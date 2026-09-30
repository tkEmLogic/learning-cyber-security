package ota

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Three claimed devices under one owner. The canary is named in every rollout
// below; the other two are the rest of the fleet.
const (
	canaryDevice = "beacon-remfg-206ef1170d64"
	fleetDevice  = "beacon-remfg-206ef1170d65"
	otherDevice  = "beacon-remfg-206ef1170d66"
)

// fleetFixture is a mutual-TLS service with three claimed devices and their
// certificates.
type fleetFixture struct {
	*mutualFixture
	certs map[string]*x509.Certificate
}

func newFleetFixture(t *testing.T) *fleetFixture {
	t.Helper()
	f := &fleetFixture{mutualFixture: newMutualFixture(t), certs: map[string]*x509.Certificate{}}
	now := time.Now()
	for i, device := range []string{canaryDevice, fleetDevice, otherDevice} {
		serial := int64(7101 + i)
		cert, _ := f.operational.issue(t, serial, device, "northwind", now.Add(-time.Hour), now.Add(OperationalLifetime))
		f.claim(t, device, "northwind", serial)
		f.certs[device] = cert
	}
	return f
}

// poll is one device's GET /v1/releases/current, as the raw bytes it receives.
func (f *fleetFixture) poll(t *testing.T, device string) []byte {
	t.Helper()
	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.operational, f.certs[device],
		http.MethodGet, "https://ota.course.example/v1/releases/current", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("assignment for %s = %d %s, want 200", device, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

// offered is the release_id a device is offered.
func (f *fleetFixture) offered(t *testing.T, device string) string {
	t.Helper()
	var release Release
	if err := json.Unmarshal(f.poll(t, device), &release); err != nil {
		t.Fatal(err)
	}
	return release.ReleaseID
}

// download is one device's GET /v1/firmware/{name}, returning the status.
func (f *fleetFixture) download(t *testing.T, device, name string) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	f.server.DeviceHandler().ServeHTTP(recorder, present(t, f.operational, f.certs[device],
		http.MethodGet, "https://ota.course.example/v1/firmware/"+name, ""))
	return recorder.Code
}

// operator sends one request to the operator listener with the marker header,
// the way ./course does.
func (f *mutualFixture) operator(t *testing.T, method, target string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, "https://ota.course.example:8444"+target, reader)
	request.Header.Set("X-Course-Environment-ID", "test-environment")
	recorder := httptest.NewRecorder()
	f.server.OperatorHandler().ServeHTTP(recorder, request)
	var answer map[string]any
	if recorder.Body.Len() > 0 && strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
			t.Fatalf("answer was not JSON: %s", recorder.Body.String())
		}
	}
	return recorder.Code, answer
}

// stageRelease writes every artifact an approval links into the release store,
// with a clean build manifest, and returns the release record that offers it.
func (f *mutualFixture) stageRelease(t *testing.T, releaseID string) Release {
	t.Helper()
	dir := f.server.cfg.ReleaseDir
	image := []byte("synthetic firmware bytes for " + releaseID)
	writeReleaseFile(t, dir, releaseID+".bin", image)
	writeReleaseFile(t, dir, releaseID+manifestSuffix, []byte(`{"release_id":"`+releaseID+`"}`))
	writeReleaseFile(t, dir, releaseID+signatureSuffix, []byte("synthetic signature"))
	writeReleaseFile(t, dir, releaseID+buildManifestSuffix,
		[]byte(`{"schema_version":1,"release_id":"`+releaseID+`","source_revision":"0123abc","clean_tree":true}`))
	writeReleaseFile(t, dir, releaseID+firmwareSBOMSuffix, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`))
	writeReleaseFile(t, dir, releaseID+testReportSuffix, []byte(`{"passed":true}`))
	sum := sha256.Sum256(image)
	return Release{
		SchemaVersion: 1,
		ReleaseID:     releaseID,
		Version:       "0.9.0",
		Board:         "esp32c6_devkitc/esp32c6/hpcore",
		ImagePath:     releaseID + ".bin",
		ImageSHA256:   hex.EncodeToString(sum[:]),
		ImageSize:     int64(len(image)),
	}
}

func (f *mutualFixture) approve(t *testing.T, release Release) (int, map[string]any) {
	t.Helper()
	return f.operator(t, http.MethodPost, "/v1/releases/"+release.ReleaseID+"/approve",
		map[string]any{"image_path": release.ImagePath, "actor": "ada"})
}

// approvedRelease stages and approves one release, failing if either step does.
func (f *mutualFixture) approvedRelease(t *testing.T, releaseID string) Release {
	t.Helper()
	release := f.stageRelease(t, releaseID)
	if status, answer := f.approve(t, release); status != http.StatusOK {
		t.Fatalf("approve %s = %d %#v, want 200", releaseID, status, answer)
	}
	return release
}

func (f *mutualFixture) startRollout(t *testing.T, release Release, canary ...string) (int, map[string]any) {
	t.Helper()
	return f.operator(t, http.MethodPost, "/v1/rollouts", map[string]any{
		"release": release, "canary_device_ids": canary, "actor": "ada",
	})
}

func (f *mutualFixture) step(t *testing.T, name string) (int, map[string]any) {
	t.Helper()
	return f.operator(t, http.MethodPost, "/v1/rollouts/current/"+name, map[string]any{"actor": "ada"})
}

func (f *mutualFixture) withdraw(t *testing.T, releaseID string) (int, map[string]any) {
	t.Helper()
	return f.operator(t, http.MethodPost, "/v1/releases/"+releaseID+"/withdraw",
		map[string]any{"reason": "T9-VULN-01", "actor": "ada"})
}

func (f *mutualFixture) putBaseline(t *testing.T, release Release) (int, map[string]any) {
	t.Helper()
	return f.operator(t, http.MethodPut, "/v1/releases/current", release)
}

func mustSucceed(t *testing.T, what string, status int, answer map[string]any) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s = %d %#v, want 200", what, status, answer)
	}
}

// succeeded takes a helper's two results straight from the call.
func succeeded(t *testing.T, what string) func(int, map[string]any) {
	t.Helper()
	return func(status int, answer map[string]any) {
		t.Helper()
		mustSucceed(t, what, status, answer)
	}
}

// assertConflict is assertRefusal for Tier 9's checks, which answer 409.
func assertConflict(t *testing.T, status int, body map[string]any, check string) {
	t.Helper()
	if status != http.StatusConflict {
		t.Fatalf("status = %d %#v, want 409", status, body)
	}
	if body["check"] != check {
		t.Fatalf("check = %v, want %q", body["check"], check)
	}
	if reason, _ := body["reason"].(string); reason == "" {
		t.Fatalf("refused at %s with no reason", check)
	}
}

// A Tier 8 board outside every rollout reads exactly the bytes it read before
// rollouts existed: the baseline record and nothing else, with no new field.
// That holds before any rollout, and while a rollout it is not in is open.
func TestATier8BoardOutsideAnyRolloutSeesTheSameBytes(t *testing.T) {
	f := newFleetFixture(t)
	stored, err := os.ReadFile(filepath.Join(f.stateDir, "current-release.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline Release
	if err := json.Unmarshal(stored, &baseline); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	before := f.poll(t, fleetDevice)
	if !bytes.Equal(before, want) {
		t.Fatalf("the Tier 8 answer changed:\n got %s\nwant %s", before, want)
	}

	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))
	during := f.poll(t, fleetDevice)
	if !bytes.Equal(during, want) {
		t.Fatalf("a device outside the rollout was told something new:\n got %s\nwant %s", during, want)
	}
	for _, row := range recordsOfKind(t, f.mutualFixture, KindRolloutServed) {
		if row["device_id"] == fleetDevice {
			t.Fatalf("the service recorded serving a release it did not serve: %#v", row)
		}
	}
}

// The canary is offered the rollout's release in the same shape, can download
// its image, and the service records that it served it. A device outside the
// rollout can download neither the rollout's image nor anything but its own.
func TestTheCanaryGroupGetsTheRolloutAndTheFleetFollowsOnAdvance(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))

	if got := f.offered(t, canaryDevice); got != candidate.ReleaseID {
		t.Fatalf("canary offered %q, want %q", got, candidate.ReleaseID)
	}
	if status := f.download(t, canaryDevice, candidate.ImagePath); status != http.StatusOK {
		t.Fatalf("canary download of its own release = %d, want 200", status)
	}
	if got := f.offered(t, fleetDevice); got != "baseline" {
		t.Fatalf("fleet device offered %q before the advance, want the baseline", got)
	}
	if status := f.download(t, fleetDevice, candidate.ImagePath); status != http.StatusNotFound {
		t.Fatalf("fleet device download of a release it was not offered = %d, want 404", status)
	}
	served := recordsOfKind(t, f.mutualFixture, KindRolloutServed)
	if len(served) != 1 || served[0]["device_id"] != canaryDevice || served[0]["stage"] != stageCanary {
		t.Fatalf("served lines = %#v, want one for the canary", served)
	}
	// A second poll is not a second fact.
	f.poll(t, canaryDevice)
	if got := len(recordsOfKind(t, f.mutualFixture, KindRolloutServed)); got != 1 {
		t.Fatalf("served lines after a second poll = %d, want 1", got)
	}

	succeeded(t, "advance")(f.step(t, "advance"))
	if got := f.offered(t, fleetDevice); got != candidate.ReleaseID {
		t.Fatalf("fleet device offered %q after the advance, want %q", got, candidate.ReleaseID)
	}
	started := recordsOfKind(t, f.mutualFixture, KindRolloutStarted)
	if len(started) != 1 || started[0]["actor"] != "ada" || started[0]["release_id"] != candidate.ReleaseID {
		t.Fatalf("rollout.started = %#v", started)
	}
	if got := recordsOfKind(t, f.mutualFixture, KindRolloutAdvanced); len(got) != 1 || got[0]["actor"] != "ada" {
		t.Fatalf("rollout.advanced = %#v", got)
	}
}

// A pause stops new devices from receiving the release, and keeps offering it
// to every device the service already served it to, so a download can resume.
func TestPauseKeepsAlreadyServedDevices(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice, otherDevice))

	if got := f.offered(t, canaryDevice); got != candidate.ReleaseID {
		t.Fatalf("canary offered %q, want %q", got, candidate.ReleaseID)
	}
	succeeded(t, "pause")(f.step(t, "pause"))

	if got := f.offered(t, canaryDevice); got != candidate.ReleaseID {
		t.Fatalf("a served device was offered %q after the pause, want %q still", got, candidate.ReleaseID)
	}
	if status := f.download(t, canaryDevice, candidate.ImagePath); status != http.StatusOK {
		t.Fatalf("a served device could not resume its download after the pause: %d", status)
	}
	if got := f.offered(t, otherDevice); got != "baseline" {
		t.Fatalf("an unserved canary device was offered %q during the pause, want the baseline", got)
	}

	status, answer := f.step(t, "advance")
	assertConflict(t, status, answer, CheckRolloutRunning)
	status, answer = f.step(t, "pause")
	if status != http.StatusOK || answer["result"] != "already-paused" {
		t.Fatalf("a second pause = %d %#v, want already-paused", status, answer)
	}
	if got := len(recordsOfKind(t, f.mutualFixture, KindRolloutPaused)); got != 1 {
		t.Fatalf("paused lines = %d, want 1", got)
	}

	succeeded(t, "resume")(f.step(t, "resume"))
	if got := f.offered(t, otherDevice); got != candidate.ReleaseID {
		t.Fatalf("an unserved canary device was offered %q after the resume, want %q", got, candidate.ReleaseID)
	}
}

// Withdrawal with no replacement closes the rollout, and the release is never
// served again: not the assignment, not the image, not by a new rollout and
// not by the baseline PUT. The device that ran it is offered the baseline.
func TestWithdrawalWithoutAReplacementNeverServesTheReleaseAgain(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))
	if got := f.offered(t, canaryDevice); got != candidate.ReleaseID {
		t.Fatalf("canary offered %q, want %q", got, candidate.ReleaseID)
	}

	status, answer := f.withdraw(t, candidate.ReleaseID)
	mustSucceed(t, "withdraw", status, answer)
	if answer["rollout_closed"] != true {
		t.Fatalf("withdrawing the open rollout's release must close it: %#v", answer)
	}
	withdrawn := recordsOfKind(t, f.mutualFixture, KindReleaseWithdrawn)
	if len(withdrawn) != 1 || withdrawn[0]["reason"] != "T9-VULN-01" || withdrawn[0]["actor"] != "ada" {
		t.Fatalf("release.withdrawn = %#v", withdrawn)
	}

	if got := f.offered(t, canaryDevice); got != "baseline" {
		t.Fatalf("the device that ran the withdrawn release was offered %q, want the baseline", got)
	}
	if status := f.download(t, canaryDevice, candidate.ImagePath); status != http.StatusNotFound {
		t.Fatalf("download of a withdrawn image = %d, want 404", status)
	}
	status, answer = f.startRollout(t, candidate, canaryDevice)
	assertConflict(t, status, answer, CheckReleaseWithdrawn)
	status, answer = f.putBaseline(t, candidate)
	assertConflict(t, status, answer, CheckReleaseWithdrawn)

	// The approval stays on the record, and withdrawal still wins.
	if got := len(recordsOfKind(t, f.mutualFixture, KindReleaseApproved)); got != 1 {
		t.Fatalf("approval lines after the withdrawal = %d, want 1", got)
	}
}

// Withdrawal with a replacement: the fix is a separate, approved rollout, and a
// device that ran the withdrawn release is offered the fix once it reaches it.
func TestWithdrawalWithAReplacementOffersTheFix(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))
	f.poll(t, canaryDevice)
	succeeded(t, "withdraw")(f.withdraw(t, candidate.ReleaseID))

	fix := f.approvedRelease(t, "tier-09-fix")
	succeeded(t, "start the fix")(f.startRollout(t, fix, canaryDevice))
	if got := f.offered(t, canaryDevice); got != fix.ReleaseID {
		t.Fatalf("the device that ran the withdrawn release was offered %q, want the fix", got)
	}
	if got := f.offered(t, fleetDevice); got != "baseline" {
		t.Fatalf("a device the fix has not reached was offered %q, want the baseline", got)
	}

	// The fix goes to the whole fleet and becomes the baseline.
	succeeded(t, "advance")(f.step(t, "advance"))
	succeeded(t, "complete")(f.step(t, "complete"))
	if got := f.offered(t, fleetDevice); got != fix.ReleaseID {
		t.Fatalf("after completion the fleet was offered %q, want the fix as baseline", got)
	}
	status, answer := f.operator(t, http.MethodGet, "/v1/rollouts/current", nil)
	if status != http.StatusOK || answer["open"] != false {
		t.Fatalf("rollout state after completion = %d %#v, want closed", status, answer)
	}
}

// Only one rollout is open at a time, and the baseline does not move under one.
func TestOneOpenRolloutAndTheBaselinePutWaitsForIt(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	other := f.approvedRelease(t, "tier-09-other")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))

	status, answer := f.startRollout(t, other, fleetDevice)
	assertConflict(t, status, answer, CheckNoOpenRollout)
	status, answer = f.putBaseline(t, other)
	assertConflict(t, status, answer, CheckNoOpenRollout)

	// Complete before the canary review is refused, then allowed after it.
	status, answer = f.step(t, "complete")
	assertConflict(t, status, answer, CheckRolloutAdvanced)
	succeeded(t, "advance")(f.step(t, "advance"))
	succeeded(t, "complete")(f.step(t, "complete"))

	succeeded(t, "baseline put after the rollout closed")(f.putBaseline(t, other))
}

// A step on no rollout, and a request without the marker header.
func TestRolloutStepsNeedAnOpenRolloutAndTheMarker(t *testing.T) {
	f := newFleetFixture(t)
	status, answer := f.step(t, "advance")
	assertConflict(t, status, answer, CheckRolloutOpen)

	candidate := f.approvedRelease(t, "tier-09-candidate")
	data, _ := json.Marshal(map[string]any{"release": candidate, "canary_device_ids": []string{canaryDevice}, "actor": "ada"})
	recorder := httptest.NewRecorder()
	f.server.OperatorHandler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/v1/rollouts", bytes.NewReader(data)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("rollout start without the marker = %d, want 403", recorder.Code)
	}

	status, _ = f.operator(t, http.MethodPost, "/v1/rollouts",
		map[string]any{"release": candidate, "canary_device_ids": []string{canaryDevice}})
	if status != http.StatusBadRequest {
		t.Fatalf("rollout start with no actor = %d, want 400", status)
	}
	status, _ = f.operator(t, http.MethodPost, "/v1/rollouts",
		map[string]any{"release": candidate, "canary_device_ids": []string{}, "actor": "ada"})
	if status != http.StatusBadRequest {
		t.Fatalf("rollout start with no Canary group = %d, want 400", status)
	}
}

// The Fleet baseline cannot be withdrawn: every device outside a rollout is
// offered it, and there is no empty answer to fall back to.
func TestTheFleetBaselineCannotBeWithdrawn(t *testing.T) {
	f := newFleetFixture(t)
	status, answer := f.withdraw(t, "baseline")
	assertConflict(t, status, answer, CheckNotFleetBaseline)
}

// The approval digests every link itself, and refuses a missing artifact, a
// dirty tree, a build manifest that does not say, and a second approval.
func TestApprovalRefusals(t *testing.T) {
	f := newFleetFixture(t)
	release := f.stageRelease(t, "tier-09-candidate")
	dir := f.server.cfg.ReleaseDir

	sbom := filepath.Join(dir, release.ReleaseID+firmwareSBOMSuffix)
	if err := os.Remove(sbom); err != nil {
		t.Fatal(err)
	}
	status, answer := f.approve(t, release)
	assertConflict(t, status, answer, CheckReleaseArtifactsPresent)
	if !strings.Contains(answer["reason"].(string), "sbom") {
		t.Fatalf("a missing-artifact refusal must name the artifact: %v", answer["reason"])
	}
	writeReleaseFile(t, dir, release.ReleaseID+firmwareSBOMSuffix, []byte(`{"bomFormat":"CycloneDX"}`))

	buildManifestFile := release.ReleaseID + buildManifestSuffix
	writeReleaseFile(t, dir, buildManifestFile, []byte(`{"source_revision":"0123abc","clean_tree":false}`))
	status, answer = f.approve(t, release)
	assertConflict(t, status, answer, CheckBuildTreeClean)
	writeReleaseFile(t, dir, buildManifestFile, []byte(`{"source_revision":"0123abc"}`))
	status, answer = f.approve(t, release)
	assertConflict(t, status, answer, CheckBuildTreeClean)
	if got := len(recordsOfKind(t, f.mutualFixture, KindReleaseApproved)); got != 0 {
		t.Fatalf("a refused approval wrote %d lines", got)
	}

	writeReleaseFile(t, dir, buildManifestFile, []byte(`{"source_revision":"0123abc","clean_tree":true}`))
	status, answer = f.approve(t, release)
	mustSucceed(t, "approve", status, answer)
	approvals := recordsOfKind(t, f.mutualFixture, KindReleaseApproved)
	if len(approvals) != 1 {
		t.Fatalf("approval lines = %d, want 1", len(approvals))
	}
	line := approvals[0]
	if line["role"] != ReleaseApproverRole || line["actor"] != "ada" || line["release_id"] != release.ReleaseID {
		t.Fatalf("release.approved = %#v", line)
	}
	artifacts := line["artifacts"].(map[string]any)
	for _, name := range approvalArtifacts {
		linked, ok := artifacts[name].(map[string]any)
		if !ok {
			t.Fatalf("the approval does not link %s: %#v", name, artifacts)
		}
		data, err := os.ReadFile(filepath.Join(dir, linked["path"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if linked["sha256"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("the %s digest is not the file's SHA-256: %#v", name, linked)
		}
	}

	status, answer = f.approve(t, release)
	assertConflict(t, status, answer, CheckFirstApproval)
}

// A rollout of an unapproved release is refused at start, and so is one whose
// release record names a different image from the one approved.
func TestRolloutStartNeedsAnApproval(t *testing.T) {
	f := newFleetFixture(t)
	release := f.stageRelease(t, "tier-09-candidate")
	status, answer := f.startRollout(t, release, canaryDevice)
	assertConflict(t, status, answer, CheckReleaseApproved)

	succeeded(t, "approve")(f.approve(t, release))
	swapped := release
	swapped.ImagePath = "baseline.bin"
	status, answer = f.startRollout(t, swapped, canaryDevice)
	assertConflict(t, status, answer, CheckReleaseApproved)
	if !strings.Contains(answer["reason"].(string), "image") {
		t.Fatalf("the refusal must name the changed artifact: %v", answer["reason"])
	}
}

// An artifact swapped in the store after approval is refused, by name, at the
// next step that offers the release to new devices.
func TestAChangedArtifactIsRefusedAtAdvanceAndResume(t *testing.T) {
	f := newFleetFixture(t)
	candidate := f.approvedRelease(t, "tier-09-candidate")
	succeeded(t, "start")(f.startRollout(t, candidate, canaryDevice))

	writeReleaseFile(t, f.server.cfg.ReleaseDir, candidate.ImagePath, []byte("a different image"))
	status, answer := f.step(t, "advance")
	assertConflict(t, status, answer, CheckReleaseApproved)
	if !strings.Contains(answer["reason"].(string), "artifact image") {
		t.Fatalf("the refusal must name the changed artifact: %v", answer["reason"])
	}
	if got := len(recordsOfKind(t, f.mutualFixture, KindRolloutAdvanced)); got != 0 {
		t.Fatalf("a refused advance wrote %d lines", got)
	}

	succeeded(t, "pause")(f.step(t, "pause"))
	status, answer = f.step(t, "resume")
	assertConflict(t, status, answer, CheckReleaseApproved)
}

// The baseline PUT asks for an approval only when the service runs with release
// approval on, which is Tier 9. Tiers 7 and 8 keep the PUT they have.
func TestTheBaselinePutNeedsAnApprovalOnlyFromTier9(t *testing.T) {
	f := newFleetFixture(t)
	unapproved := f.stageRelease(t, "tier-09-unapproved")
	succeeded(t, "Tier 8 baseline put")(f.putBaseline(t, unapproved))

	f.server.cfg.ReleaseApproval = true
	side := f.stageRelease(t, "tier-09-side-door")
	status, answer := f.putBaseline(t, side)
	assertConflict(t, status, answer, CheckReleaseApproved)

	approved := f.approvedRelease(t, "tier-09-approved")
	succeeded(t, "Tier 9 baseline put of an approved release")(f.putBaseline(t, approved))
}
