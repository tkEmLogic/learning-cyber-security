package courseapp

// Tier 9's release path (#271, #277): sign, describe, test, approve, and only
// then offer. Every earlier tier published a release by writing the service's
// current-release.json from this command. From Tier 9 nothing reaches a
// device that way: signing stores the release, and the service decides what
// is offered, through its own approval check.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

func timeNowUTC() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

// sbom routes ./course sbom. The firmware half is Tier 9's release SBOM; the
// service half describes the OTA service, which is not part of any firmware
// release.
func (a *app) sbom(args []string) error {
	if len(args) == 0 {
		return errors.New("sbom requires firmware or service")
	}
	switch args[0] {
	case "firmware":
		return a.sbomFirmware(args[1:])
	case "service":
		return a.sbomService(args[1:])
	default:
		return fmt.Errorf("unknown sbom command %q; use firmware or service", args[0])
	}
}

// releaseSignTier09 signs one Tier 9 release into the release store and stops.
func (a *app) releaseSignTier09(variantName string) error {
	variant, err := tier09Variant(variantName)
	if err != nil {
		return err
	}
	if _, err := a.signTierReleaseFiles(tier09, variant, a.tier09RawImage(variant), tier09Versions[variant.label]); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: signed %s at counter %d, and published nothing\n", variant.releaseID, variant.securityCounter)
	fmt.Fprintln(a.out, "From Tier 9 a signed release is not an offered one. It reaches a device only")
	fmt.Fprintln(a.out, "after it is described, tested and approved, and then through a rollout:")
	fmt.Fprintf(a.out, "  ./course sbom firmware --tier 09 --variant %s\n", variant.label)
	fmt.Fprintf(a.out, "  ./course release test --tier 09 --variant %s\n", variant.label)
	fmt.Fprintf(a.out, "  ./course release approve --tier 09 --variant %s --approver <your name>\n", variant.label)
	return nil
}

// releaseAssignTier09 sets the Fleet baseline through the service's own PUT,
// not by writing its state file, so the service's release-approved check
// applies to it. Started with --release-approval, the service refuses an
// unapproved release here: this is the side door the tier closes.
func (a *app) releaseAssignTier09(variantName string) error {
	variant, err := tier09Variant(variantName)
	if err != nil {
		return err
	}
	manifest, err := a.tier09StoredManifest(variant)
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

func (a *app) tier09StoredManifest(variant firmwareVariant) (releaseManifest, error) {
	var manifest releaseManifest
	data, err := os.ReadFile(a.manifestPath(variant.releaseID))
	if err != nil {
		return manifest, fmt.Errorf("no signed %s release yet; run ./course release sign --tier 09 --variant %s first",
			variant.label, variant.label)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("the stored %s manifest is unreadable: %w", variant.label, err)
	}
	return manifest, nil
}

// operatorCall sends one request to the operator listener with the Course
// environment marker, the way every manufacturer action reaches the service,
// and prints it first so the Learner can send the same request with curl.
func (a *app) operatorCall(method, path string, body any) (int, []byte, error) {
	var marker environment
	if err := readJSON(filepath.Join(a.root, a.manifest.Safety.MarkerPath), &marker); err != nil {
		return 0, nil, errors.New("no Course environment marker; run ./course setup first")
	}
	pool, err := a.trustAnchorPool()
	if err != nil {
		return 0, nil, err
	}
	port := a.manifest.Runtime.OperatorTLSPort
	address := net.JoinHostPort(hostOf(a.serviceURL()), strconv.Itoa(port))
	base := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(port)
	client := a.verifyingClient(pool, coursepki.ServiceName, address)

	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	request, err := http.NewRequest(method, base+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Course-Environment-ID", marker.EnvironmentID)

	fmt.Fprintf(a.out, "+ %s %s%s\n", method, base, path)
	fmt.Fprintf(a.out, "  X-Course-Environment-ID: %s\n", marker.EnvironmentID)
	if payload != nil {
		fmt.Fprintf(a.out, "  -> %s\n", payload)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("the operator listener could not be reached at %s: %w; start the service with ./course service start --https --mutual-tls", address, err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 256*1024))
	if err != nil {
		return 0, nil, err
	}
	fmt.Fprintf(a.out, "  <- %d %s\n", response.StatusCode, http.StatusText(response.StatusCode))
	return response.StatusCode, answer, nil
}

// operatorRefusal prints a refusal by its check name, which says which
// property did not hold, and returns it as the command's error.
func operatorRefusal(out io.Writer, doing string, status int, answer []byte) error {
	var refusal struct {
		Check  string `json:"check"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(answer, &refusal); err != nil || refusal.Check == "" {
		fmt.Fprintf(out, "     %s\n", strings.TrimSpace(string(answer)))
		return fmt.Errorf("%s was refused with status %d", doing, status)
	}
	fmt.Fprintf(out, "     refused at check %s\n", refusal.Check)
	fmt.Fprintf(out, "     reason: %s\n", refusal.Reason)
	fmt.Fprintf(out, "Result: %s was refused at %s\n", doing, refusal.Check)
	return fmt.Errorf("refused at check %s", refusal.Check)
}

// tier09TestResult is one pre-release check and what it found.
type tier09TestResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type tier09TestReport struct {
	SchemaVersion int                `json:"schema_version"`
	ReleaseID     string             `json:"release_id"`
	RanAt         string             `json:"ran_at"`
	Passed        bool               `json:"passed"`
	Scope         string             `json:"scope"`
	Checks        []tier09TestResult `json:"checks"`
}

// releaseTestTier09 runs the host-side pre-release checks the approval links
// to. They check that the release's files agree with each other and with
// what the variant is meant to be. They are not a test of the device: the
// canary is, and the report says so.
func (a *app) releaseTestTier09(variantName string) error {
	variant, err := tier09Variant(variantName)
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
		return fmt.Errorf("the %s release is not signed yet; run ./course release sign --tier 09 --variant %s first", variant.label, variant.label)
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
		check("sbom-purls", len(missing) == 0, "every component has a purl, so a VEX statement can bind to it; missing: "+strings.Join(missing, ", "))
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
		fmt.Fprintf(a.out, "  %s  %-32s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Fprintf(a.out, "Report: %s\n", a.relative(path))
	if !report.Passed {
		return fmt.Errorf("the %s release failed its pre-release checks; approval will refuse it", variant.label)
	}
	fmt.Fprintf(a.out, "Result: %s passed every pre-release check\n", variant.releaseID)
	return nil
}

// releaseApproveTier09 checks locally that every link exists and that the
// tests passed, then asks the service to record the approval. The service
// repeats every check itself and computes the digests from its own store, so
// posting the same request with curl is refused for the same reasons.
func (a *app) releaseApproveTier09(args []string) error {
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
	variant, err := tier09Variant(variantName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(approver) == "" {
		return errors.New("--approver <name> is required: an approval speaks for a person, and the record says who")
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
		return fmt.Errorf("refused locally: the test report does not record a pass; run ./course release test --tier 09 --variant %s", variant.label)
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
