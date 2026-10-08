package courseapp

// Tier 10's release path (#290). It is Tier 9's path, over the same operator
// listener and the same approval check, applied to Tier 10's two releases. The
// only new thing is the candidate's handover patch, which the pre-release check
// confirms the build manifest records.
//
// The candidate is published and approved by the actor "teammate", with an
// honest passing test report, because release test never boots the image: it
// proves the artifacts are consistent, not that the release behaves (T9-W-36,
// carried forward as T10-W-39). The Learner approves only their own corrected
// release.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// releaseSignTier10 signs one Tier 10 release into the release store and stops.
func (a *app) releaseSignTier10(variantName string) error {
	variant, err := tier10Variant(variantName)
	if err != nil {
		return err
	}
	if _, err := a.signTierReleaseFiles(tier10, variant, a.tier10RawImage(variant), tier10Versions[variant.label]); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: signed %s at counter %d, and published nothing\n", variant.releaseID, variant.securityCounter)
	fmt.Fprintln(a.out, "A signed release is not an offered one. It reaches a device only after it is")
	fmt.Fprintln(a.out, "described, tested and approved, and then through a rollout:")
	fmt.Fprintf(a.out, "  ./course sbom firmware --tier 10 --variant %s\n", variant.label)
	fmt.Fprintf(a.out, "  ./course release test --tier 10 --variant %s\n", variant.label)
	fmt.Fprintf(a.out, "  ./course release approve --tier 10 --variant %s --approver <your name>\n", variant.label)
	return nil
}

// releaseAssignTier10 sets the Fleet baseline through the service's own PUT, so
// the service's release-approved check applies to it, exactly as Tier 9 does.
func (a *app) releaseAssignTier10(variantName string) error {
	variant, err := tier10Variant(variantName)
	if err != nil {
		return err
	}
	manifest, err := a.tier10StoredManifest(variant)
	if err != nil {
		return err
	}
	status, answer, err := a.operatorCall(http.MethodPut, "/v1/releases/current", a.assignmentFor(manifest))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "setting the Fleet baseline", status, answer)
	}
	fmt.Fprintf(a.out, "Result: the Fleet baseline is now %s, counter %d\n", manifest.ReleaseID, manifest.SecurityCounter)
	fmt.Fprintln(a.out, "Every device outside a rollout is offered it on its next poll.")
	return nil
}

func (a *app) tier10StoredManifest(variant firmwareVariant) (releaseManifest, error) {
	var manifest releaseManifest
	data, err := os.ReadFile(a.manifestPath(variant.releaseID))
	if err != nil {
		return manifest, fmt.Errorf("no signed %s release yet; run ./course release sign --tier 10 --variant %s first",
			variant.label, variant.label)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("the stored %s manifest is unreadable: %w", variant.label, err)
	}
	return manifest, nil
}

// releaseTestTier10 runs the host-side pre-release checks, the same consistency
// checks Tier 9 runs, plus one: the build manifest's record of the handover
// patch must match the variant, so the candidate's manifest is honest that it
// was built with the patch and the corrected one is honest that it was not. The
// checks are not a test of the device: the canary is, and the report says so.
func (a *app) releaseTestTier10(variantName string) error {
	variant, err := tier10Variant(variantName)
	if err != nil {
		return err
	}
	report := tier09TestReport{
		SchemaVersion: 1,
		ReleaseID:     variant.releaseID,
		RanAt:         timeNowUTC(),
		Scope:         "host-side consistency of the release's own files; not a device test, which the canary stage is",
	}
	check := func(name string, passed bool, detail string) {
		report.Checks = append(report.Checks, tier09TestResult{name, passed, detail})
	}

	image, imageErr := os.ReadFile(filepath.Join(a.releaseDir(), variant.imageName))
	manifestBytes, manifestErr := os.ReadFile(a.manifestPath(variant.releaseID))
	signature, sigErr := os.ReadFile(a.manifestSignaturePath(variant.releaseID))
	if imageErr != nil || manifestErr != nil || sigErr != nil {
		return fmt.Errorf("the %s release is not signed yet; run ./course release sign --tier 10 --variant %s first", variant.label, variant.label)
	}
	key, err := a.releaseVerifyKey()
	if err != nil {
		return err
	}
	check("manifest-signature", manifestVerifies(key, manifestBytes, signature),
		"the stored manifest verifies against the Release signing key's public half")

	var manifest releaseManifest
	_ = json.Unmarshal(manifestBytes, &manifest)
	imageSum, _ := fileSHA256Hex(filepath.Join(a.releaseDir(), variant.imageName))
	check("manifest-digest", manifest.ImageSHA256 == imageSum && manifest.ImageSize == len(image),
		fmt.Sprintf("manifest names sha256 %s and %d bytes; the image is %s and %d bytes", manifest.ImageSHA256, manifest.ImageSize, imageSum, len(image)))
	check("manifest-counter", manifest.SecurityCounter == variant.securityCounter,
		fmt.Sprintf("manifest counter %d, variant counter %d", manifest.SecurityCounter, variant.securityCounter))
	check("manifest-release-id", manifest.ReleaseID == variant.releaseID,
		fmt.Sprintf("manifest release_id %q", manifest.ReleaseID))

	var build tier09BuildManifest
	buildErr := readJSON(filepath.Join(a.releaseDir(), variant.releaseID+".build-manifest.json"), &build)
	check("build-manifest-present", buildErr == nil, "the build manifest exists and parses; ./course sbom firmware writes it")
	if buildErr == nil {
		check("build-manifest-clean-tree", build.CleanTree,
			fmt.Sprintf("built from %s, clean_tree %v", build.SourceRevision, build.CleanTree))
		signedSum := ""
		for _, h := range build.Outputs["application_signed"] {
			if h.Alg == "SHA-256" {
				signedSum = h.Content
			}
		}
		check("build-manifest-image", signedSum == imageSum,
			"the build manifest's signed-image SHA-256 is the image in the store")
		recordsHandover := build.HandoverPatch != nil
		detail := "the build manifest records no handover patch"
		if recordsHandover {
			detail = "the build manifest records handover patch " + build.HandoverPatch.File + " sha256 " + build.HandoverPatch.SHA256
		}
		check("build-manifest-handover-matches-variant", recordsHandover == variant.handoverPatch, detail)
	}

	var bom cdxBOM
	bomErr := readJSON(filepath.Join(a.releaseDir(), variant.releaseID+".firmware.cdx.json"), &bom)
	check("sbom-present", bomErr == nil && bom.BOMFormat == "CycloneDX" && bom.SpecVersion == "1.6",
		"the firmware SBOM exists and is CycloneDX 1.6")
	if bomErr == nil {
		topSum := ""
		for _, h := range bom.Metadata.Component.Hashes {
			if h.Alg == "SHA-256" {
				topSum = h.Content
			}
		}
		check("sbom-describes-image", topSum == imageSum, "the SBOM's top component is this signed image")
		missing := []string{}
		patched := false
		for _, c := range bom.Components {
			if c.PURL == "" {
				missing = append(missing, c.Name)
			}
			if c.Name == "tf-psa-crypto" && c.Pedigree != nil {
				for _, p := range c.Pedigree.Patches {
					for _, r := range p.Resolves {
						if r.ID == "CVE-2026-50583" {
							patched = true
						}
					}
				}
			}
		}
		detail := "every component has a purl, so a VEX statement can bind to it"
		if len(missing) > 0 {
			detail = "components with no purl, which no VEX statement can bind to: " + strings.Join(missing, ", ")
		}
		check("sbom-purls", len(missing) == 0, detail)
		check("sbom-backport-matches-variant", patched == variant.westPatches,
			fmt.Sprintf("the SBOM records the CVE-2026-50583 backport: %v; this variant carries it: %v", patched, variant.westPatches))
	}

	report.Passed = true
	for _, c := range report.Checks {
		if !c.Passed {
			report.Passed = false
		}
	}
	path := filepath.Join(a.releaseDir(), variant.releaseID+".test-report.json")
	if err := writeJSON(path, report, 0o644); err != nil {
		return err
	}
	for _, c := range report.Checks {
		mark := "pass"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(a.out, "  %s  %-36s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Fprintf(a.out, "Report: %s\n", a.relative(path))
	if !report.Passed {
		return fmt.Errorf("the %s release failed its pre-release checks; approval will refuse it", variant.label)
	}
	fmt.Fprintf(a.out, "Result: %s passed every pre-release check\n", variant.releaseID)
	fmt.Fprintln(a.out, "These checks never boot the image or run the fixtures, so a release that")
	fmt.Fprintln(a.out, "regresses a control still passes here (T10-W-39). The canary and the")
	fmt.Fprintln(a.out, "regression rerun are what catch that; run them before advancing a rollout.")
	return nil
}

// releaseApproveTier10 is Tier 9's approval, applied to a Tier 10 release. The
// --approver value is the actor the service records; the candidate is approved
// as "teammate", a role, and the Learner approves the corrected release as
// themselves.
func (a *app) releaseApproveTier10(args []string) error {
	variantName, approver := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tier":
			i++
		case "--variant", "--approver":
			if i+1 >= len(args) {
				return fmt.Errorf("option %s requires a value", args[i])
			}
			if args[i] == "--variant" {
				variantName = args[i+1]
			} else {
				approver = args[i+1]
			}
			i++
		default:
			return fmt.Errorf("unknown release approve option %s", args[i])
		}
	}
	variant, err := tier10Variant(variantName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(approver) == "" {
		return errors.New("--approver <name> is required: an approval speaks for a person or role, and the record says who")
	}
	links := []struct{ label, path string }{
		{"image", filepath.Join(a.releaseDir(), variant.imageName)},
		{"manifest", a.manifestPath(variant.releaseID)},
		{"signature", a.manifestSignaturePath(variant.releaseID)},
		{"build manifest", filepath.Join(a.releaseDir(), variant.releaseID+".build-manifest.json")},
		{"firmware SBOM", filepath.Join(a.releaseDir(), variant.releaseID+".firmware.cdx.json")},
		{"test report", filepath.Join(a.releaseDir(), variant.releaseID+".test-report.json")},
	}
	for _, link := range links {
		if _, err := os.Stat(link.path); err != nil {
			return fmt.Errorf("refused locally: the %s is missing (%s); approval links every artifact, so nothing is sent", link.label, a.relative(link.path))
		}
	}
	var report tier09TestReport
	if err := readJSON(links[5].path, &report); err != nil || !report.Passed {
		return fmt.Errorf("refused locally: the test report does not record a pass; run ./course release test --tier 10 --variant %s", variant.label)
	}
	status, answer, err := a.operatorCall(http.MethodPost, "/v1/releases/"+variant.releaseID+"/approve", map[string]string{
		"image_path": variant.imageName,
		"actor":      approver,
	})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return operatorRefusal(a.out, "the approval", status, answer)
	}
	var done struct {
		Artifacts map[string]struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	_ = json.Unmarshal(answer, &done)
	for _, name := range []string{"image", "manifest", "signature", "build_manifest", "sbom", "test_report"} {
		if artifact, ok := done.Artifacts[name]; ok {
			fmt.Fprintf(a.out, "     %-15s %s  %s\n", name, artifact.SHA256, artifact.Path)
		}
	}
	fmt.Fprintf(a.out, "Result: %s is approved by %s\n", variant.releaseID, approver)
	fmt.Fprintln(a.out, "The service computed those digests from its own store. A file changed after")
	fmt.Fprintln(a.out, "this moment is refused by name when a rollout of this release starts or moves on.")
	return nil
}

// releaseWithdrawTier10 withdraws a Tier 10 release over the operator listener,
// the same action Tier 9's withdraw performs. It is used to pull the candidate
// after its failed trial, which closes the candidate's rollout (#288 recovery).
func (a *app) releaseWithdrawTier10(args []string) error {
	opts, err := parseRolloutOptions(args, "--variant", "--reason")
	if err != nil {
		return err
	}
	variant, err := tier10Variant(opts.variant)
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
