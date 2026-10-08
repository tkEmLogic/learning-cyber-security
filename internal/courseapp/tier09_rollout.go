package courseapp

// Tier 9's rollout commands (#279): the manufacturer's actions on the
// operator listener, one command each, over the routes in
// services/ota/rollout.go. Each prints the request it sends, so the Learner
// can send the same one with curl and see the service answer it the same way.
//
// The actor is a stated field. Nothing on the service authenticates it, which
// is T9-W-37, and --actor is required so the record at least says who claims
// to have acted.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// rollout routes ./course rollout.
func (a *app) rollout(args []string) error {
	if len(args) == 0 {
		return errors.New("rollout requires start, advance, pause, resume, complete, or status")
	}
	switch args[0] {
	case "start":
		return a.rolloutStart(args[1:])
	case "advance", "pause", "resume", "complete":
		return a.rolloutStep(args[0], args[1:])
	case "status":
		return a.rolloutStatus()
	default:
		return fmt.Errorf("unknown rollout command %q; use start, advance, pause, resume, complete, or status", args[0])
	}
}

// rolloutOptions reads the options every rollout command shares. The tier is
// read from --tier and must be 09 or 10: both tiers offer releases through the
// same rollout routes, and #288 found that rollout start accepted only Tier 9's
// variants. It defaults to Tier 9 when omitted, so Tier 9's module examples read
// unchanged.
type rolloutOptions struct {
	tier                   string
	variant, actor, reason string
	canary                 []string
}

func parseRolloutOptions(args []string, allowed ...string) (rolloutOptions, error) {
	opts := rolloutOptions{tier: tier09}
	permitted := map[string]bool{"--tier": true, "--actor": true}
	for _, name := range allowed {
		permitted[name] = true
	}
	for i := 0; i < len(args); i++ {
		name := args[i]
		if !permitted[name] {
			return opts, fmt.Errorf("unknown option %s", name)
		}
		if i+1 >= len(args) {
			return opts, fmt.Errorf("option %s requires a value", name)
		}
		value := args[i+1]
		i++
		switch name {
		case "--tier":
			tier := normalizeTier(value)
			if tier != tier09 && tier != tier10 {
				return opts, errors.New("rollouts are Tier 9's and Tier 10's; pass --tier 09 or --tier 10")
			}
			opts.tier = tier
		case "--variant":
			opts.variant = value
		case "--actor":
			opts.actor = value
		case "--reason":
			opts.reason = value
		case "--canary":
			for _, id := range strings.Split(value, ",") {
				if id = strings.TrimSpace(id); id != "" {
					opts.canary = append(opts.canary, id)
				}
			}
		}
	}
	if strings.TrimSpace(opts.actor) == "" {
		return opts, errors.New("--actor <name> is required: the record says who claims to have acted, and nothing checks it (T9-W-37)")
	}
	return opts, nil
}

// storedManifestForTier reads a signed release manifest for whichever tier owns
// the variant, so the rollout and withdraw commands forge nothing: the release
// record comes from the release's own signed manifest.
func (a *app) storedManifestForTier(tier string, variant firmwareVariant) (releaseManifest, error) {
	switch tier {
	case tier09:
		return a.tier09StoredManifest(variant)
	case tier10:
		return a.tier10StoredManifest(variant)
	}
	return releaseManifest{}, fmt.Errorf("tier %s has no rollout releases", tier)
}

// rolloutStart offers an approved release to a named Canary group. The
// release record comes from the release's own signed manifest, as every
// earlier assign did, so the command forges nothing.
func (a *app) rolloutStart(args []string) error {
	opts, err := parseRolloutOptions(args, "--variant", "--canary")
	if err != nil {
		return err
	}
	variant, err := a.firmwareTierVariant(opts.tier, opts.variant)
	if err != nil {
		return err
	}
	if len(opts.canary) == 0 {
		return errors.New("--canary <device id>[,<device id>] is required: a rollout starts with a named Canary group")
	}
	manifest, err := a.storedManifestForTier(opts.tier, variant)
	if err != nil {
		return err
	}
	status, answer, err := a.operatorCall(http.MethodPost, "/v1/rollouts", map[string]any{
		"release":           a.assignmentFor(manifest),
		"canary_device_ids": opts.canary,
		"actor":             opts.actor,
	})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "starting the rollout", status, answer)
	}
	fmt.Fprintf(a.out, "Result: %s is offered to the Canary group: %s\n", variant.releaseID, strings.Join(opts.canary, ", "))
	fmt.Fprintln(a.out, "Every other device is still offered the Fleet baseline. Review the canary's")
	fmt.Fprintln(a.out, "records before ./course rollout advance offers it to the rest of the fleet.")
	return nil
}

var rolloutStepResults = map[string]string{
	"advance":  "the release is offered to every other claimed, active device",
	"pause":    "no new device is offered the release; a device already served keeps it, so its download can resume",
	"resume":   "the rollout offers the release again",
	"complete": "the release is the Fleet baseline now, and the rollout is closed",
}

func (a *app) rolloutStep(step string, args []string) error {
	opts, err := parseRolloutOptions(args)
	if err != nil {
		return err
	}
	status, answer, err := a.operatorCall(http.MethodPost, "/v1/rollouts/current/"+step, map[string]string{"actor": opts.actor})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "the "+step, status, answer)
	}
	var done struct {
		Result    string `json:"result"`
		ReleaseID string `json:"release_id"`
	}
	_ = json.Unmarshal(answer, &done)
	if strings.HasPrefix(done.Result, "already-") {
		fmt.Fprintf(a.out, "Result: nothing changed; the service answered %s for %s\n", done.Result, done.ReleaseID)
		return nil
	}
	fmt.Fprintf(a.out, "Result: %s: %s\n", done.ReleaseID, rolloutStepResults[step])
	return nil
}

// rolloutStatus prints what the service derives from its log.
func (a *app) rolloutStatus() error {
	status, answer, err := a.operatorCall(http.MethodGet, "/v1/rollouts/current", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "reading the rollout", status, answer)
	}
	var state struct {
		Open      bool     `json:"open"`
		ReleaseID string   `json:"release_id"`
		Stage     string   `json:"stage"`
		Paused    bool     `json:"paused"`
		Canary    []string `json:"canary_device_ids"`
		Served    []string `json:"served_device_ids"`
		StartedBy string   `json:"started_by"`
		Approved  []string `json:"approved_release_ids"`
		Withdrawn []string `json:"withdrawn_release_ids"`
	}
	if err := json.Unmarshal(answer, &state); err != nil {
		return fmt.Errorf("the rollout state is unreadable: %w", err)
	}
	if !state.Open {
		fmt.Fprintln(a.out, "No rollout is open. Every device is offered the Fleet baseline.")
	} else {
		paused := ""
		if state.Paused {
			paused = ", paused"
		}
		fmt.Fprintf(a.out, "Rollout: %s, stage %s%s, started by %s\n", state.ReleaseID, state.Stage, paused, state.StartedBy)
		fmt.Fprintf(a.out, "  Canary group: %s\n", strings.Join(state.Canary, ", "))
		fmt.Fprintf(a.out, "  served so far: %s\n", strings.Join(state.Served, ", "))
	}
	fmt.Fprintf(a.out, "Approved releases: %s\n", strings.Join(state.Approved, ", "))
	fmt.Fprintf(a.out, "Withdrawn releases: %s\n", strings.Join(state.Withdrawn, ", "))
	return nil
}

// releaseWithdrawTier09 withdraws a release: it is never served again, and an
// open rollout of it closes. The reason names the vulnerability record.
func (a *app) releaseWithdrawTier09(args []string) error {
	opts, err := parseRolloutOptions(args, "--variant", "--reason")
	if err != nil {
		return err
	}
	variant, err := tier09Variant(opts.variant)
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.reason) == "" {
		return errors.New("--reason <vulnerability record id> is required: a withdrawal says why")
	}
	status, answer, err := a.operatorCall(http.MethodPost, "/v1/releases/"+variant.releaseID+"/withdraw", map[string]string{
		"reason": opts.reason,
		"actor":  opts.actor,
	})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "the withdrawal", status, answer)
	}
	var done struct {
		Result        string `json:"result"`
		RolloutClosed bool   `json:"rollout_closed"`
	}
	_ = json.Unmarshal(answer, &done)
	if done.Result == "already-withdrawn" {
		fmt.Fprintf(a.out, "Result: nothing changed; %s was already withdrawn\n", variant.releaseID)
		return nil
	}
	fmt.Fprintf(a.out, "Result: %s is withdrawn and will never be served again\n", variant.releaseID)
	if done.RolloutClosed {
		fmt.Fprintln(a.out, "Its open rollout is closed.")
	}
	fmt.Fprintln(a.out, "A device already running it is offered the Fleet baseline, which it refuses as a")
	fmt.Fprintln(a.out, "rollback, until a rollout of a fix reaches it. That gap is the fix not yet available.")
	return nil
}
