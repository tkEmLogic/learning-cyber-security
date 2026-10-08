package courseapp

// The hosting fixtures on a mutual-TLS service (#292).
//
// Four fixtures publish something to the board through the service's Fleet
// baseline: tier-00/altered-image, tier-03/hostile-image,
// tier-04/hostile-release and tier-04/replay-release. Up to Tier 6 they do it
// with the baseline PUT and undo it with POST /v1/lab/reset. Neither works on
// the service Tier 7 to 10 run:
//
//   - the PUT goes to the TLS port, which from Tier 7 is the device listener
//     and demands a client certificate the fixture does not hold, and the
//     operator listener's PUT refuses an unapproved release from Tier 9;
//   - the lab reset reseeds the Tier 0 release and deletes events.jsonl, the
//     log every board result from Tier 7 on is read from.
//
// So when the service runs mutual TLS, these four model a compromised hosting
// side instead of a compromised operator: whoever can write the service's own
// state file is past every check the service makes, approval included. The
// fixture writes .course-state/ota/current-release.json directly, after saving
// the exact bytes it replaces, and its reset writes those bytes back and never
// calls the lab reset. What is left to refuse the release is the board, which
// is the point of every one of these fixtures. The earlier tiers' path, on a
// service without mutual TLS, is unchanged.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// hostingFixtures are the fixtures that publish through the Fleet baseline.
var hostingFixtures = map[string]bool{
	"tier-00/altered-image":   true,
	"tier-03/hostile-image":   true,
	"tier-04/hostile-release": true,
	"tier-04/replay-release":  true,
}

// hostingMode reports whether a fixture publishes by writing the state file:
// one of the four, on a service running mutual TLS.
func (a *app) hostingMode(id string) bool {
	return hostingFixtures[id] && a.serviceMode() == "mutual-tls"
}

// hostingSaved is what a hosting publish replaced, kept so its reset can put
// back exactly those bytes. Previous is the file's bytes, not a parsed record:
// a reset that re-encoded the record would restore something close to the
// baseline rather than the baseline.
type hostingSaved struct {
	SchemaVersion int       `json:"schema_version"`
	Fixture       string    `json:"fixture"`
	SavedAt       time.Time `json:"saved_at"`
	Previous      []byte    `json:"previous"`
}

func (a *app) baselinePath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "ota", "current-release.json")
}

func (a *app) hostingSavedPath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "ota", "hosting-saved-release.json")
}

// hostingPublish replaces the Fleet baseline with release by writing the
// service's state file, after saving the bytes it replaces.
//
// It refuses before writing anything when an earlier publish was never reset,
// because saving now would save that earlier hostile release as the thing to
// restore. It also refuses while a rollout is open: a device in the rollout is
// offered the rollout's release and never this one, so the board could not
// see it and the run would read silence as a refusal.
func (a *app) hostingPublish(id string, release map[string]any) error {
	var saved hostingSaved
	if readJSON(a.hostingSavedPath(), &saved) == nil {
		return fmt.Errorf("%s published a release that was never reset; run ./course attack reset %s first", saved.Fixture, saved.Fixture)
	}
	open, releaseID, err := a.rolloutOpen()
	if err != nil {
		return err
	}
	if open {
		return fmt.Errorf("the rollout of %s is open, so the board is offered that release and never the baseline this fixture writes; complete or withdraw it first", releaseID)
	}
	previous, err := os.ReadFile(a.baselinePath())
	if err != nil {
		return fmt.Errorf("cannot read the Fleet baseline to save it: %w", err)
	}
	saved = hostingSaved{SchemaVersion: 1, Fixture: id, SavedAt: time.Now().UTC(), Previous: previous}
	if err := writeJSON(a.hostingSavedPath(), saved, 0o600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		return err
	}
	a.note("This service runs mutual TLS. Its device listener serves only a device with an")
	a.note("Operational certificate, and from Tier 9 its baseline PUT refuses an unapproved")
	a.note("release. So this fixture is a compromised hosting side, not a compromised operator:")
	a.note("it writes the service's own state file, past every check the service makes.")
	a.sent("WRITE", a.relative(a.baselinePath()))
	a.sentBody("replacing the Fleet baseline with:", release)
	a.note("The bytes it replaced are saved in %s for the reset.", a.relative(a.hostingSavedPath()))
	return writeFileAtomically(a.baselinePath(), append(data, '\n'))
}

// hostingRestore puts back exactly the bytes a hosting publish replaced. It is
// idempotent: with nothing saved there is nothing to restore. It never calls
// the lab reset, which would drop the event log.
func (a *app) hostingRestore(id string) error {
	var saved hostingSaved
	if err := readJSON(a.hostingSavedPath(), &saved); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("the saved Fleet baseline is unreadable: %w", err)
	}
	if saved.Fixture != id {
		return fmt.Errorf("the saved Fleet baseline belongs to %s; run ./course attack reset %s", saved.Fixture, saved.Fixture)
	}
	if err := writeFileAtomically(a.baselinePath(), saved.Previous); err != nil {
		return err
	}
	return os.Remove(a.hostingSavedPath())
}

// writeFileAtomically writes through a temporary file and a rename, so the
// service, which reads the baseline on every poll, never reads half a file.
func writeFileAtomically(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// rolloutOpen asks the operator listener whether a rollout is open. The route
// is a read the operator listener serves to the lab bench.
func (a *app) rolloutOpen() (bool, string, error) {
	var rollout struct {
		Open      bool   `json:"open"`
		ReleaseID string `json:"release_id"`
	}
	host := hostOf(a.serviceURL())
	if err := a.operatorGet(host, a.manifest.Runtime.OperatorTLSPort, coursepki.ServiceName, "/v1/rollouts/current", &rollout); err != nil {
		return false, "", err
	}
	return rollout.Open, rollout.ReleaseID, nil
}

// hostingStoreFile reads one file out of the release store the device listener
// serves from. On a mutual-TLS service the fixture cannot fetch it the way a
// device does, because it holds no Operational certificate, so it reads what
// the listener would serve and says so.
func (a *app) hostingStoreFile(name string) ([]byte, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid release store name %q", name)
	}
	a.sent("READ", filepath.Join(a.relative(a.releaseDir()), name))
	a.note("The device listener serves only a device with an Operational certificate, so this")
	a.note("reads the release store it serves from rather than fetching it as a device would.")
	return os.ReadFile(filepath.Join(a.releaseDir(), name))
}

// hostingAssignment is the Fleet baseline as the state file holds it.
func (a *app) hostingAssignment() (releaseRecord, error) {
	var record releaseRecord
	a.sent("READ", a.relative(a.baselinePath()))
	return record, readJSON(a.baselinePath(), &record)
}

// operatorGet reads one route on the operator listener with the trust anchor
// the course generated, connecting to the literal address and checking the
// service name, as every host client in this course does.
func (a *app) operatorGet(host string, port int, serviceName, path string, value any) error {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return err
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	client := a.verifyingClient(pool, serviceName, address)
	response, err := client.Get("https://" + serviceName + ":" + strconv.Itoa(port) + path)
	if err != nil {
		return fmt.Errorf("the operator listener could not be reached at %s: %w", address, err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("GET %s on the operator listener answered %s", path, response.Status)
	}
	return json.NewDecoder(response.Body).Decode(value)
}
