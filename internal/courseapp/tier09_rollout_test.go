package courseapp

import (
	"strings"
	"testing"
)

// Every rollout command needs a stated actor, because the record says who
// claims to have acted and nothing on the service checks it (T9-W-37).
func TestRolloutCommandsNeedAnActor(t *testing.T) {
	for _, args := range [][]string{
		{"start", "--tier", "09", "--variant", "remediation", "--canary", "beacon-x"},
		{"advance"},
		{"pause", "--tier", "09"},
	} {
		if _, err := parseRolloutOptions(args[1:], "--variant", "--canary"); err == nil ||
			!strings.Contains(err.Error(), "--actor") {
			t.Errorf("%v without an actor = %v", args, err)
		}
	}
}

func TestRolloutOptionsParse(t *testing.T) {
	opts, err := parseRolloutOptions([]string{"--tier", "9", "--variant", "remediation",
		"--canary", "beacon-a, beacon-b,,", "--actor", "tarjei"}, "--variant", "--canary")
	if err != nil {
		t.Fatal(err)
	}
	if opts.variant != "remediation" || opts.actor != "tarjei" || strings.Join(opts.canary, "|") != "beacon-a|beacon-b" {
		t.Errorf("options = %+v", opts)
	}
	if _, err := parseRolloutOptions([]string{"--tier", "08", "--actor", "x"}); err == nil {
		t.Error("a rollout outside Tier 9 must be refused")
	}
	if _, err := parseRolloutOptions([]string{"--canary", "beacon-a", "--actor", "x"}); err == nil {
		t.Error("an option a command does not take must be refused")
	}
}

func TestRolloutStartAndWithdrawRefuseLocally(t *testing.T) {
	a, _ := provisioningApp(t)
	if err := a.rollout([]string{"start", "--tier", "09", "--variant", "remediation", "--actor", "x"}); err == nil ||
		!strings.Contains(err.Error(), "--canary") {
		t.Errorf("start without a canary = %v", err)
	}
	if err := a.release([]string{"withdraw", "--tier", "09", "--variant", "support-listener", "--actor", "x"}); err == nil ||
		!strings.Contains(err.Error(), "--reason") {
		t.Errorf("withdraw without a reason = %v", err)
	}
	if err := a.rollout([]string{"launch"}); err == nil {
		t.Error("an unknown rollout command must be refused")
	}
}
