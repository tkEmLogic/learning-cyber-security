package courseapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkEmLogic/learning-cyber-security/services/ota"
)

// pointFleetAtTest rewires the fleet block at the test listeners the bypass
// harness already stood up, exactly as the harness rewires the bypass block.
// Everything else in the block is this repository's own: the owner slug, the
// bounded device list and the reset are all under test.
func (f *bypassFixture) pointFleetAtTest(t *testing.T) {
	t.Helper()
	block := f.app.manifest.Fleet
	if block.Owner == "" || len(block.DeviceIDs) == 0 {
		t.Fatal("course.yml has no fleet block with an owner and a device list")
	}
	block.Target = f.app.manifest.Bypass[tier07BypassKey].Target
	block.DevicePort = f.app.manifest.Bypass[tier07BypassKey].DevicePort
	block.OperatorPort = f.app.manifest.Bypass[tier07BypassKey].OperatorPort
	f.app.manifest.Fleet = block
}

// seedBaseline writes a Fleet baseline release the test service will offer, so a
// poll has something to report.
func (f *bypassFixture) seedBaseline(t *testing.T) {
	t.Helper()
	release := ota.Release{
		SchemaVersion: 1,
		ReleaseID:     "tier-09-remediation",
		Version:       "0.9.1+0",
		Board:         "esp32c6_devkitc/esp32c6/hpcore",
		ImagePath:     "tier-09-remediation.bin",
		Mutable:       true,
	}
	path := filepath.Join(f.root, ".course-state", "ota", "current-release.json")
	if err := writeJSON(path, release, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The fleet owner is a legitimate account, and it must not be the board's owner
// or the adversary.
func TestFleetOwnerIsNotTheBoardOwnerOrAdversary(t *testing.T) {
	f := newBypassFixture(t)
	owner := f.app.manifest.Fleet.Owner
	if owner == "" {
		t.Fatal("the fleet block names no owner")
	}
	if owner == "harbor-owner" || owner == "rival-labs" {
		t.Fatalf("the fleet owner %q is the board owner or the adversary", owner)
	}
}

// An identifier outside the bounded list is refused before any side effect.
func TestFleetRefusesUnknownDevice(t *testing.T) {
	f := newBypassFixture(t)
	if err := f.app.manifest.Fleet.fleetAllowed(f.app.manifest.Fleet.DeviceIDs[0]); err != nil {
		t.Fatalf("a listed device was refused: %v", err)
	}
	if err := f.app.manifest.Fleet.fleetAllowed("beacon-not-in-the-list"); err == nil {
		t.Fatal("an unlisted device must be refused")
	}
}

// The whole cycle: enrol the fleet with real, claimed identities, report the
// baseline so the service counts them active, poll and see the offered release
// labelled HOST, then reset and see the owner gone but the record kept.
func TestFleetEnrollBaselinePollAndReset(t *testing.T) {
	f := newBypassFixture(t)
	f.pointFleetAtTest(t)
	f.seedBaseline(t)

	f.out.Reset()
	if err := f.app.fleetEnroll(); err != nil {
		t.Fatalf("fleet enroll: %v\n%s", err, f.out.String())
	}
	enrolled := f.out.String()
	for _, id := range f.app.manifest.Fleet.DeviceIDs {
		if !strings.Contains(enrolled, id) {
			t.Fatalf("device %s was not enrolled:\n%s", id, enrolled)
		}
	}
	if strings.Count(enrolled, "HOST") < len(f.app.manifest.Fleet.DeviceIDs) {
		t.Fatalf("enrol output is not labelled HOST per device:\n%s", enrolled)
	}

	// Enrol again: idempotent, every device already claimed.
	f.out.Reset()
	if err := f.app.fleetEnroll(); err != nil {
		t.Fatalf("second fleet enroll: %v\n%s", err, f.out.String())
	}
	if !strings.Contains(f.out.String(), "already enrolled and claimed") {
		t.Fatalf("a second enrol should be idempotent:\n%s", f.out.String())
	}

	f.out.Reset()
	if err := f.app.fleetBaseline(); err != nil {
		t.Fatalf("fleet baseline: %v\n%s", err, f.out.String())
	}

	f.out.Reset()
	if err := f.app.fleetPoll(); err != nil {
		t.Fatalf("fleet poll: %v\n%s", err, f.out.String())
	}
	polled := f.out.String()
	if !strings.Contains(polled, "tier-09-remediation") {
		t.Fatalf("poll did not report the offered release:\n%s", polled)
	}
	if !strings.Contains(polled, "host result never stands in for a device result") {
		t.Fatalf("poll did not keep the HOST caveat:\n%s", polled)
	}

	// Reset removes the owner, keeps the devices and keys.
	f.out.Reset()
	if err := f.app.fleetReset(); err != nil {
		t.Fatalf("fleet reset: %v\n%s", err, f.out.String())
	}
	current, err := f.app.ownerCredentialIsCurrent(f.app.manifest.Fleet.Owner, "")
	if err != nil {
		t.Fatal(err)
	}
	if current {
		t.Fatal("the fleet owner should be gone after reset")
	}
	state, err := f.app.readFleetState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Devices) != len(f.app.manifest.Fleet.DeviceIDs) {
		t.Fatalf("reset dropped device keys: have %d, want %d", len(state.Devices), len(f.app.manifest.Fleet.DeviceIDs))
	}
	if state.OwnerCredential != "" {
		t.Fatal("reset should clear the owner credential from fleet state")
	}
}

// A rollout that names a fleet device in its canary group offers that device the
// rollout's release, and every other fleet device the baseline, which is the
// visibility the fleet exists to give.
func TestFleetPollShowsCanaryStage(t *testing.T) {
	f := newBypassFixture(t)
	f.pointFleetAtTest(t)
	f.seedBaseline(t)
	if err := f.app.fleetEnroll(); err != nil {
		t.Fatalf("fleet enroll: %v\n%s", err, f.out.String())
	}
	if err := f.app.fleetBaseline(); err != nil {
		t.Fatalf("fleet baseline: %v\n%s", err, f.out.String())
	}

	// Approve and start a rollout of a second release to one fleet device.
	canary := f.app.manifest.Fleet.DeviceIDs[0]
	f.approveAndStartRollout(t, canary)

	f.out.Reset()
	if err := f.app.fleetPoll(); err != nil {
		t.Fatalf("fleet poll: %v\n%s", err, f.out.String())
	}
	polled := f.out.String()
	if !strings.Contains(polled, canary+" is offered: tier-09-support-listener") {
		t.Fatalf("the canary device was not offered the rollout release:\n%s", polled)
	}
	other := f.app.manifest.Fleet.DeviceIDs[1]
	if !strings.Contains(polled, other+" is offered: tier-09-remediation") {
		t.Fatalf("a non-canary device was not offered the baseline:\n%s", polled)
	}
}

// approveAndStartRollout writes an approval and a rollout.started for a second
// release directly into the manufacturing record, the way the service's own
// routes would, so the poll test does not need the whole approval tooling.
func (f *bypassFixture) approveAndStartRollout(t *testing.T, canary string) {
	t.Helper()
	release := map[string]any{
		"schema_version": 1,
		"release_id":     "tier-09-support-listener",
		"version":        "0.9.0+0",
		"board":          "esp32c6_devkitc/esp32c6/hpcore",
		"image_path":     "tier-09-support-listener.bin",
		"mutable":        true,
		"signed":         false,
	}
	f.appendRecord(t, map[string]any{
		"kind":        ota.KindReleaseApproved,
		"release_id":  "tier-09-support-listener",
		"recorded_at": timeNowUTC(),
		"artifacts":   map[string]any{},
	})
	f.appendRecord(t, map[string]any{
		"kind":              ota.KindRolloutStarted,
		"release_id":        "tier-09-support-listener",
		"release":           release,
		"canary_device_ids": []string{canary},
		"actor":             "test",
		"recorded_at":       timeNowUTC(),
	})
}

func (f *bypassFixture) appendRecord(t *testing.T, record map[string]any) {
	t.Helper()
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(f.app.provisionRecordPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}
