package ota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tier 9's Release approval, the service's half.
//
// An approval is a `release.approved` line the service appends to records.jsonl
// when the operator listener asks for one. The service computes the digest of
// every linked artifact itself, from the files in its own release store, at the
// moment it writes the line. A caller states who approved and which image; it
// never states a digest, because a digest the caller supplies is a digest the
// caller chose.
//
// The log is append only, so an approval cannot be edited afterwards, only
// forged by a second writer. Anyone who can reach the operator listener can
// ask for one (T9-W-36): the approval does not make a release that a device
// trusts, because the Release signing key and anti-rollback still decide that
// on the device.

// The artifacts one approval links, beside the image in the release store.
//
// The image is named in the request, because the service never parses a
// Release manifest and so cannot read the image name out of one. Every other
// artifact is found by a fixed name built from the release identifier, the way
// manifest.go already finds `<release_id>.manifest.json`. `./course release
// approve` (#277) writes the three new files under these names.
//
//	<release_id>.manifest.json        the signed Release manifest (Tier 4)
//	<release_id>.manifest.sig         its detached signature (Tier 4)
//	<release_id>.build-manifest.json  the build manifest, read below
//	<release_id>.firmware.cdx.json    the firmware SBOM, CycloneDX 1.6 JSON;
//	                                  digested, never parsed
//	<release_id>.test-report.json     the pre-release test report; digested,
//	                                  never parsed
const (
	buildManifestSuffix = ".build-manifest.json"
	firmwareSBOMSuffix  = ".firmware.cdx.json"
	testReportSuffix    = ".test-report.json"
)

// approvalArtifacts is the order an approval lists its links in, and the names
// a changed-artifact refusal uses. The order is the one the design gives.
var approvalArtifacts = []string{"image", "manifest", "signature", "build_manifest", "sbom", "test_report"}

// buildManifest is the part of the build manifest the service reads, which is
// one field.
//
// The whole file is what #277 writes: at least `schema_version`, `release_id`,
// `source_revision` and `clean_tree`, and the image hashes beside them. The
// source revision and the clean-tree flag live there and are not restated in
// the approval record, which links the file by its digest instead. Everything
// else is ignored here, so a field added on the build side can never turn an
// approval into a 400.
//
// A pointer, because a missing flag is not a clean tree. A build that cannot
// say whether its tree was clean has not said that it was.
type buildManifest struct {
	CleanTree *bool `json:"clean_tree"`
}

// approvedArtifact is one link in an approval: where the file is in the release
// store, and its SHA-256 when the approval was written.
type approvedArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ReleaseApproverRole is the one role an approval states. It is a field value
// and not a credential: nothing checks who holds it, which is T9-W-36.
const ReleaseApproverRole = "release-approver"

// approvalPaths maps each link onto its file name in the release store.
func approvalPaths(releaseID, imagePath string) map[string]string {
	return map[string]string{
		"image":          imagePath,
		"manifest":       releaseID + manifestSuffix,
		"signature":      releaseID + signatureSuffix,
		"build_manifest": releaseID + buildManifestSuffix,
		"sbom":           releaseID + firmwareSBOMSuffix,
		"test_report":    releaseID + testReportSuffix,
	}
}

// digestFile is the SHA-256 of one stored file, in hex. It reads the file each
// time it is asked, because a digest remembered is a digest that cannot notice
// the file was swapped.
func (s *Server) digestFile(name string) (string, error) {
	file, err := os.Open(filepath.Join(s.cfg.ReleaseDir, name))
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// approveRelease is POST /v1/releases/{release_id}/approve on the operator
// listener. See rolloutRoutes for the request.
//
// Three refusals, in the order a Learner meets them: a release already approved
// is refused at first-approval, a missing link at release-artifacts-present,
// and a build manifest that does not say its tree was clean at build-tree-clean.
// All three answer 409, because each is the state of the store or the log
// disagreeing with the request, and none is about who is asking.
func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	releaseID := r.PathValue("release_id")
	if !validReleaseID(releaseID) {
		http.Error(w, "invalid release_id", http.StatusBadRequest)
		return
	}
	var request struct {
		ImagePath string `json:"image_path"`
		Actor     string `json:"actor"`
	}
	if err := decodeJSON(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.ImagePath == "" || filepath.Base(request.ImagePath) != request.ImagePath ||
		strings.Contains(request.ImagePath, "..") {
		http.Error(w, "image_path must be one file in the release directory", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Actor) == "" {
		http.Error(w, "actor is required: an approval says who approved", http.StatusBadRequest)
		return
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	state := s.rolloutState()
	if _, approved := state.approvals[releaseID]; approved {
		// There is no second approval and no revocation of the first.
		// Withdrawal is the act that takes a release back, and it leaves the
		// approval on the record as a fact about what was once decided.
		s.Refuse(w, r, http.StatusConflict, Refusal{
			Check:  CheckFirstApproval,
			Reason: fmt.Sprintf("release %s is already approved, and an approval is written once; withdraw the release to take it back", releaseID),
		})
		return
	}

	paths := approvalPaths(releaseID, request.ImagePath)
	artifacts := map[string]approvedArtifact{}
	var missing []string
	for _, name := range approvalArtifacts {
		digest, err := s.digestFile(paths[name])
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s (%s)", name, paths[name]))
			continue
		}
		artifacts[name] = approvedArtifact{Path: paths[name], SHA256: digest}
	}
	if len(missing) > 0 {
		s.Refuse(w, r, http.StatusConflict, Refusal{
			Check: CheckReleaseArtifactsPresent,
			Reason: fmt.Sprintf("release %s cannot be approved without every linked artifact in the release store; missing: %s",
				releaseID, strings.Join(missing, ", ")),
		})
		return
	}

	// The build manifest is read after it has been digested, so the bytes that
	// said "clean" are the bytes the approval links. Reading it first would
	// leave a moment in which the two could differ.
	if refusal := s.buildTreeClean(paths["build_manifest"]); refusal != nil {
		s.Refuse(w, r, http.StatusConflict, *refusal)
		return
	}

	record := map[string]any{
		"kind":        KindReleaseApproved,
		"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
		"station":     serviceStation,
		"release_id":  releaseID,
		"role":        ReleaseApproverRole,
		"actor":       request.Actor,
		"artifacts":   artifacts,
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		http.Error(w, "the approval could not be recorded: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":     "approved",
		"release_id": releaseID,
		"role":       ReleaseApproverRole,
		"actor":      request.Actor,
		"artifacts":  artifacts,
	})
}

// buildTreeClean refuses a build manifest that does not say, as a JSON true,
// that it was built from a clean tree. A dirty tree is a build nobody can
// reproduce from the source revision it names, so the Tier 9 release steps
// need a clean build.
func (s *Server) buildTreeClean(name string) *Refusal {
	data, err := os.ReadFile(filepath.Join(s.cfg.ReleaseDir, name))
	if err != nil {
		return &Refusal{Check: CheckBuildTreeClean, Reason: fmt.Sprintf("the build manifest %s could not be read: %v", name, err)}
	}
	var manifest buildManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return &Refusal{Check: CheckBuildTreeClean, Reason: fmt.Sprintf("the build manifest %s is not JSON: %v", name, err)}
	}
	if manifest.CleanTree == nil {
		return &Refusal{Check: CheckBuildTreeClean, Reason: fmt.Sprintf("the build manifest %s has no clean_tree flag, and a build that does not say its tree was clean has not said so", name)}
	}
	if !*manifest.CleanTree {
		return &Refusal{Check: CheckBuildTreeClean, Reason: fmt.Sprintf("the build manifest %s says clean_tree is false; build the release again from a clean tree", name)}
	}
	return nil
}

// releaseApproved is the release-approved Check. It asks two things of the
// release a request is about to offer: is there an approval for it, and is
// every artifact that approval links still the file it digested.
//
// The digests are computed again here from the store, every time. That is the
// whole point of running it at advance and resume as well as at start: an
// image swapped in the store after approval is caught at the next step, by the
// artifact's name, rather than served to the rest of the fleet.
//
// The image the request names must also be the image the approval named. A
// release record pointing at a different file under the same release
// identifier is a changed image, whatever that file's digest.
func (s *Server) releaseApproved(state rolloutState, release Release) *Refusal {
	approval, ok := state.approvals[release.ReleaseID]
	if !ok {
		return &Refusal{
			Check:  CheckReleaseApproved,
			Reason: fmt.Sprintf("release %s has no approval record; approve it on the operator listener before it is offered", release.ReleaseID),
		}
	}
	if image := approval["image"]; image.Path != release.ImagePath {
		return &Refusal{
			Check: CheckReleaseApproved,
			Reason: fmt.Sprintf("artifact image has changed since release %s was approved: the approval names %s and this release names %s",
				release.ReleaseID, image.Path, release.ImagePath),
		}
	}
	for _, name := range approvalArtifacts {
		linked, ok := approval[name]
		if !ok {
			// An approval line written by hand, or by an older writer, that
			// does not link every artifact is not an approval of the release.
			return &Refusal{
				Check:  CheckReleaseApproved,
				Reason: fmt.Sprintf("the approval of release %s does not link artifact %s", release.ReleaseID, name),
			}
		}
		digest, err := s.digestFile(linked.Path)
		if err != nil || digest != linked.SHA256 {
			return &Refusal{
				Check: CheckReleaseApproved,
				Reason: fmt.Sprintf("artifact %s (%s) has changed since release %s was approved",
					name, linked.Path, release.ReleaseID),
			}
		}
	}
	return nil
}
