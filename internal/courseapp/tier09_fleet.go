package courseapp

// The synthetic canary fleet (#279).
//
// A rollout offers a release to a Canary group first and then to the rest of
// the fleet. On the bench the board is the one real canary, so the "rest of the
// fleet" is invisible: there is nothing for the fleet stage to cover and
// nothing to watch it reach. This command supplies that fleet as host-side
// synthetic devices, each with a real Factory and a real, claimed, active
// Operational identity, obtained through the same station and claim machinery
// the Tier 7 and Tier 8 fixtures use. They poll GET /v1/releases/current over
// mutual TLS and print the release the service offers each one at each rollout
// stage.
//
// The map's settled input 8 governs the labelling: the board is the canary, the
// fleet is synthetic devices polling from the host, and a host result never
// stands in for a device result. Every line this command prints is marked HOST.
//
// It is not an attack and not an adversary, so it lives neither under `attack`
// nor under `service bypass`. It demonstrates no insecure behaviour and reads
// no refusal; it makes a legitimate fleet visible. Its owner is a legitimate
// manufacturer-and-operator account, distinct from harbor-owner (which owns the
// real board) and from the rival-labs adversary. The identities are obtained
// legitimately, as the manufacturer and an owner would: the station signs the
// Factory identity, and the service issues the Operational one through a real
// claim. The Operational CA key is never used to mint.
//
// It never downloads or installs anything. It only shows which release the
// service offers each device.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// fleetManifest is what the synthetic canary fleet may read. It is the same
// allowlist shape a bypass block has: a plain target for the marker handshake,
// a named interface, the two TLS ports and the service name, one fixed owner
// slug, a bounded device list, the declared changes and a reset.
type fleetManifest struct {
	Tier         string `yaml:"tier"`
	Target       string `yaml:"target"`
	Interface    string `yaml:"interface"`
	DevicePort   int    `yaml:"device_port"`
	OperatorPort int    `yaml:"operator_port"`
	ServiceName  string `yaml:"service_name"`

	// Owner is the one fleet owner slug: a legitimate account, minted
	// idempotently by the first command that needs it, and never harbor-owner
	// or rival-labs.
	Owner string `yaml:"owner"`

	// DeviceIDs is the bounded list of synthetic fleet devices. Names are never
	// invented at run time and never supplied on a command line.
	DeviceIDs []string `yaml:"device_ids"`

	Changes []string `yaml:"changes"`
	Reset   string   `yaml:"reset"`
}

// fleetState is what the fleet remembers between commands, so a device is not
// re-enrolled or re-claimed on every run. It holds the owner credential and
// each device's keys, so it lives under `.course-state/`, which is ignored and
// never committed, at 0600 inside a 0700 directory. Nothing prints its
// contents. Reset removes the owner entry and appends a record; the keys stay,
// for the same reason the Tier 7 fixture keeps its own: the enrollments are in
// the append-only manufacturing record and reset cannot take them back.
type fleetState struct {
	OwnerCredential string                      `json:"owner_credential"`
	Devices         map[string]*syntheticDevice `json:"devices"`
}

// fleet routes ./course fleet.
func (a *app) fleet(args []string) error {
	if len(args) == 0 {
		return errors.New("fleet requires enroll, baseline, poll, status, or reset")
	}
	switch args[0] {
	case "enroll":
		return a.fleetEnroll()
	case "baseline":
		return a.fleetBaseline()
	case "poll":
		return a.fleetPoll()
	case "status":
		return a.fleetStatus()
	case "reset":
		return a.fleetReset()
	default:
		return fmt.Errorf("unknown fleet command %q; use enroll, baseline, poll, status, or reset", args[0])
	}
}

func (a *app) fleetStateDir() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "fleet")
}

func (a *app) fleetStatePath() string {
	return filepath.Join(a.fleetStateDir(), "state.json")
}

func (a *app) readFleetState() (*fleetState, error) {
	state := &fleetState{Devices: map[string]*syntheticDevice{}}
	raw, err := os.ReadFile(a.fleetStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("fleet state is corrupt; run ./course fleet reset: %w", err)
	}
	if state.Devices == nil {
		state.Devices = map[string]*syntheticDevice{}
	}
	return state, nil
}

func (a *app) saveFleetState(state *fleetState) error {
	if err := os.MkdirAll(a.fleetStateDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.fleetStatePath(), raw, 0o600)
}

// fleetPreconditions performs the checks every fleet command that reaches the
// network shares: the manifest block, the marker handshake over plain HTTP, and
// the Learner's own mutual-TLS service being up. It returns the block and the
// loaded state.
func (a *app) fleetPreconditions() (fleetManifest, *fleetState, error) {
	block := a.manifest.Fleet
	if block.Owner == "" || len(block.DeviceIDs) == 0 {
		return block, nil, errors.New("course.yml has no fleet block with an owner and a device list")
	}
	if err := validateTarget(block.Target); err != nil {
		return block, nil, err
	}
	if err := validateSelectedInterface(block.Target, block.Interface, true); err != nil {
		return block, nil, err
	}
	// The marker handshake, over plain HTTP, before any side effect, exactly as
	// every fixture does it. It confirms which Course environment the fleet may
	// act in; it is never fetched over a TLS port.
	env, _, err := a.matchMarker(block.Target)
	if err != nil {
		return block, nil, err
	}
	if err := a.requireLearnerService(); err != nil {
		return block, nil, err
	}
	fmt.Fprintf(a.out, "Marker matched: environment_id=%s tier=%s synthetic_data=%t\n",
		env.EnvironmentID, env.Tier, env.SyntheticData)
	state, err := a.readFleetState()
	if err != nil {
		return block, nil, err
	}
	return block, state, nil
}

// fleetAllowed refuses a device identifier outside the manifest's bounded list.
func (block fleetManifest) fleetAllowed(deviceID string) error {
	for _, id := range block.DeviceIDs {
		if id == deviceID {
			return nil
		}
	}
	return fmt.Errorf("device identifier %q is not in the fleet's bounded list", deviceID)
}

// ensureFleetOwner mints the one fleet owner, once, and idempotently.
func (a *app) ensureFleetOwner(block fleetManifest, state *fleetState) error {
	if block.Owner == "harborOwner" || block.Owner == "harbor-owner" || block.Owner == "rival-labs" {
		return fmt.Errorf("the fleet owner must not be %q: it owns the real board or is the adversary", block.Owner)
	}
	if state.OwnerCredential != "" {
		current, err := a.ownerCredentialIsCurrent(block.Owner, state.OwnerCredential)
		if err != nil {
			return err
		}
		if current {
			return nil
		}
	}
	credential, record, err := a.mintOwner(block.Owner)
	if err != nil {
		return err
	}
	state.OwnerCredential = credential
	if err := a.saveFleetState(state); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "  minted the fleet owner %s, credential %s\n", record.OwnerID, record.CredentialID)
	return nil
}

// fleetEnroll gives every synthetic fleet device a real Factory identity and a
// real, claimed Operational identity, then reports it. It is idempotent: a
// device already enrolled and claimed is left alone.
func (a *app) fleetEnroll() error {
	block, state, err := a.fleetPreconditions()
	if err != nil {
		return err
	}
	if err := a.ensureFleetOwner(block, state); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Enrolling the synthetic canary fleet. Each device is enrolled through the")
	fmt.Fprintln(a.out, "real station and claimed through a real claim, as the manufacturer and the")
	fmt.Fprintln(a.out, "owner would. The Operational CA key is never used to mint.")
	for _, deviceID := range block.DeviceIDs {
		device, claimed, err := a.fleetEnrollOne(block, state, deviceID)
		if err != nil {
			return err
		}
		if claimed {
			fmt.Fprintf(a.out, "  HOST  %s: Factory and Operational identity, owner %s, serial %s\n",
				deviceID, block.Owner, device.OperationalSerial)
		} else {
			fmt.Fprintf(a.out, "  HOST  %s: already enrolled and claimed, owner %s\n", deviceID, block.Owner)
		}
	}
	fmt.Fprintln(a.out, "Result: the synthetic canary fleet holds real, claimed identities (HOST).")
	fmt.Fprintln(a.out, "Report their running release with ./course fleet baseline, then watch a")
	fmt.Fprintln(a.out, "rollout reach them with ./course fleet poll.")
	return nil
}

// fleetEnrollOne enrolls and claims one device, reusing the same station and
// claim helpers the Tier 7 fixture uses. The second result says whether this
// call did the claim.
func (a *app) fleetEnrollOne(block fleetManifest, state *fleetState, deviceID string) (*syntheticDevice, bool, error) {
	if err := block.fleetAllowed(deviceID); err != nil {
		return nil, false, err
	}
	device := state.Devices[deviceID]
	if device != nil && device.OperationalCertificate != "" {
		return device, false, nil
	}
	if device == nil || device.FactoryCertificate == "" {
		credential, _, err := a.mintCredential(deviceID)
		if err != nil {
			return nil, false, err
		}
		host, err := newHostDevice()
		if err != nil {
			return nil, false, err
		}
		csr, err := host.request(deviceID, credential)
		if err != nil {
			return nil, false, err
		}
		outcome, err := a.enrollHost(deviceID, credential, csr)
		if err != nil {
			return nil, false, err
		}
		if !outcome.Issued {
			return nil, false, fmt.Errorf("the station refused to enrol %s at %s: %s", deviceID, outcome.Check, outcome.Reason)
		}
		keyPEM, err := privateKeyPEM(host.key)
		if err != nil {
			return nil, false, err
		}
		device = &syntheticDevice{
			DeviceID:           deviceID,
			FactoryKey:         keyPEM,
			FactoryCertificate: pemCertificate(outcome.CertDER),
		}
		state.Devices[deviceID] = device
		if err := a.saveFleetState(state); err != nil {
			return nil, false, err
		}
	}
	if err := a.fleetClaim(block, state, device); err != nil {
		return nil, false, err
	}
	return device, true, nil
}

// fleetClaim drives both halves of a real claim for one synthetic device: the
// device half on its Factory identity over mutual TLS, then the owner half on
// the operator listener, then the device half again to collect the certificate.
// It is the legitimate claim a board runs, with the fixture standing in for the
// board at both ends.
func (a *app) fleetClaim(block fleetManifest, state *fleetState, device *syntheticDevice) error {
	if device.OperationalCertificate != "" {
		return nil
	}
	operationalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrPEM, err := operationalRequest(device.DeviceID, operationalKey)
	if err != nil {
		return err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return err
	}
	opened, err := a.fleetDeviceCall(block, device, http.MethodPost, "/v1/devices/"+device.DeviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csrPEM})
	if err != nil {
		return err
	}
	if opened.refused() {
		return fmt.Errorf("the device half of the claim for %s was refused at %s: %s", device.DeviceID, opened.Check, opened.Reason)
	}
	approved, err := a.fleetOwnerCall(block, state, http.MethodPost, "/v1/claim",
		map[string]any{"device_id": device.DeviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	if approved.refused() {
		return fmt.Errorf("the owner half of the claim for %s was refused at %s: %s", device.DeviceID, approved.Check, approved.Reason)
	}
	issued, err := a.fleetDeviceCall(block, device, http.MethodPost, "/v1/devices/"+device.DeviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csrPEM})
	if err != nil {
		return err
	}
	certificate, _ := issued.Body["certificate"].(string)
	if certificate == "" {
		return fmt.Errorf("the claim for %s completed with no certificate: %v", device.DeviceID, issued.Body)
	}
	keyPEM, err := privateKeyPEM(operationalKey)
	if err != nil {
		return err
	}
	device.OperationalKey = keyPEM
	device.OperationalCertificate = certificate
	device.OperationalSerial, _ = issued.Body["certificate_serial"].(string)
	device.OwnerID = block.Owner
	return a.saveFleetState(state)
}

// fleetBaseline has every claimed device report its running release, so the
// service records it as active and the rollout's fleet stage has active devices
// to cover. Run it before starting a rollout: it reports whatever the service
// currently offers, which is the Fleet baseline when no rollout is open.
func (a *app) fleetBaseline() error {
	block, state, err := a.fleetPreconditions()
	if err != nil {
		return err
	}
	claimed := a.fleetClaimedDevices(block, state)
	if len(claimed) == 0 {
		return errors.New("no fleet device is enrolled yet; run ./course fleet enroll first")
	}
	fmt.Fprintln(a.out, "Reporting each device's running release as its baseline. This is what makes")
	fmt.Fprintln(a.out, "the service count them active, so a rollout's fleet stage has devices to cover.")
	for _, device := range claimed {
		release, err := a.fleetOfferedRelease(block, device)
		if err != nil {
			return err
		}
		result, err := a.fleetDeviceCall(block, device, http.MethodPost, "/v1/devices/"+device.DeviceID+"/events",
			map[string]any{
				"device_id":          device.DeviceID,
				"event":              "status.observed",
				"machine_state":      "normal",
				"running_release_id": release,
				"detail":             "synthetic fleet device, host result",
				"transport":          "https",
				"synthetic_data":     true,
			})
		if err != nil {
			return err
		}
		if result.refused() {
			return fmt.Errorf("%s could not report its status: refused at %s: %s", device.DeviceID, result.Check, result.Reason)
		}
		fmt.Fprintf(a.out, "  HOST  %s: reported running %s, now active\n", device.DeviceID, release)
	}
	fmt.Fprintln(a.out, "Result: the synthetic fleet is active on its baseline (HOST).")
	return nil
}

// fleetPoll has every device poll GET /v1/releases/current once and prints the
// release each is offered. It downloads and installs nothing: it only shows
// which release the service offers each device at this rollout stage.
func (a *app) fleetPoll() error {
	block, state, err := a.fleetPreconditions()
	if err != nil {
		return err
	}
	claimed := a.fleetClaimedDevices(block, state)
	if len(claimed) == 0 {
		return errors.New("no fleet device is enrolled yet; run ./course fleet enroll first")
	}
	fmt.Fprintln(a.out, "Polling GET /v1/releases/current for each device, over mutual TLS. No device")
	fmt.Fprintln(a.out, "downloads or installs anything; this only shows what the service offers each.")
	for _, device := range claimed {
		release, err := a.fleetOfferedRelease(block, device)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "  HOST  %s is offered: %s\n", device.DeviceID, release)
	}
	fmt.Fprintln(a.out, "Result: the release offered to each synthetic fleet device (HOST).")
	fmt.Fprintln(a.out, "A host result never stands in for a device result: the board is the canary,")
	fmt.Fprintln(a.out, "and only the board can show a release installing or being refused.")
	return nil
}

// fleetStatus lists the enrolled fleet, its owner, and each device's lifecycle
// state as the manufacturing record derives it. It reaches no network.
func (a *app) fleetStatus() error {
	block := a.manifest.Fleet
	if block.Owner == "" {
		return errors.New("course.yml has no fleet block")
	}
	state, err := a.readFleetState()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Fleet owner: %s\n", block.Owner)
	fmt.Fprintf(a.out, "Bounded device list: %s\n", strings.Join(block.DeviceIDs, ", "))
	ids := make([]string, 0, len(state.Devices))
	for id := range state.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		fmt.Fprintln(a.out, "No device is enrolled yet. Run ./course fleet enroll.")
		return nil
	}
	for _, id := range ids {
		device := state.Devices[id]
		lifecycleState, _ := a.lifecycleStateOf(id)
		claimed := "enrolled"
		if device.OperationalCertificate != "" {
			claimed = "claimed, serial " + device.OperationalSerial
		}
		fmt.Fprintf(a.out, "  HOST  %s: %s, lifecycle %s\n", id, claimed, lifecycleState)
	}
	return nil
}

// fleetReset clears the fleet's live authorization state, the way the Tier 7
// fixture's reset does. The synthetic devices stay in the append-only
// manufacturing record forever, and the keys the fleet holds stay with them,
// because those enrollments cannot be taken back. What goes is the fleet owner's
// account, which would otherwise be a live credential after the lab is over.
func (a *app) fleetReset() error {
	block := a.manifest.Fleet
	if block.Owner == "" {
		return errors.New("course.yml has no fleet block")
	}
	state, err := a.readFleetState()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Resetting the synthetic canary fleet. This is append only wherever it can be.")
	removedOwner, err := a.removeOwnerEntries(block.Owner)
	if err != nil {
		return err
	}
	devices := make([]string, 0, len(state.Devices))
	for id := range state.Devices {
		devices = append(devices, id)
	}
	sort.Strings(devices)
	detail := fmt.Sprintf("fleet reset: removed %d owner entry for %s. The synthetic fleet devices %s stay in this record, because a store that can be edited to tidy up after a fixture is no longer the append-only store the station's claim depends on.",
		removedOwner, block.Owner, strings.Join(devices, ", "))
	if len(devices) == 0 {
		detail = fmt.Sprintf("fleet reset: removed %d owner entry for %s. No fleet devices had been enrolled.", removedOwner, block.Owner)
	}
	if err := a.writeRecord(provisionRecord{Kind: recordFixtureReset, Result: "reset", Detail: detail}); err != nil {
		return err
	}
	state.OwnerCredential = ""
	if err := a.saveFleetState(state); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "  removed:  %d owner entry for %s\n", removedOwner, block.Owner)
	fmt.Fprintf(a.out, "  appended: one fixture_reset line to %s\n", a.relative(a.provisionRecordPath()))
	fmt.Fprintf(a.out, "  kept:     the keys for the %d synthetic device(s) still in the record\n", len(devices))
	fmt.Fprintln(a.out, "  kept:     every synthetic device in the manufacturing record")
	fmt.Fprintln(a.out, "Result: the fleet holds no live authorization state")
	return nil
}

// ------------------------------------------------------------------
// Helpers that reach the Learner's own service
// ------------------------------------------------------------------

// fleetClaimedDevices returns the enrolled, claimed devices in manifest order.
func (a *app) fleetClaimedDevices(block fleetManifest, state *fleetState) []*syntheticDevice {
	var devices []*syntheticDevice
	for _, id := range block.DeviceIDs {
		if device, ok := state.Devices[id]; ok && device.OperationalCertificate != "" {
			devices = append(devices, device)
		}
	}
	return devices
}

// fleetOfferedRelease polls GET /v1/releases/current for one device and returns
// the release_id the service offers. It reads the answer; it never fetches the
// image.
func (a *app) fleetOfferedRelease(block fleetManifest, device *syntheticDevice) (string, error) {
	result, err := a.fleetDeviceCall(block, device, http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return "", err
	}
	if result.refused() {
		return "", fmt.Errorf("%s was refused at %s: %s", device.DeviceID, result.Check, result.Reason)
	}
	release, _ := result.Body["release_id"].(string)
	if release == "" {
		return "", fmt.Errorf("the service offered %s no release_id: %v", device.DeviceID, result.Body)
	}
	return release, nil
}

func (a *app) fleetServiceName(block fleetManifest) string {
	if block.ServiceName != "" {
		return block.ServiceName
	}
	return coursepki.ServiceName
}

// fleetDeviceCall sends one request to the device listener presenting the
// device's client certificate, verifying the service the way a device does.
func (a *app) fleetDeviceCall(block fleetManifest, device *syntheticDevice, method, path string, body any) (answer, error) {
	certificate, err := tls.X509KeyPair([]byte(device.OperationalOrFactory()), []byte(device.OperationalOrFactoryKey()))
	if err != nil {
		return answer{}, err
	}
	client, err := a.fleetClient(block, block.DevicePort, &certificate)
	if err != nil {
		return answer{}, err
	}
	return a.fleetSend(client, block, method, block.DevicePort, path, body, "")
}

// fleetOwnerCall sends one request to the operator listener as the fleet owner.
func (a *app) fleetOwnerCall(block fleetManifest, state *fleetState, method, path string, body any) (answer, error) {
	if state.OwnerCredential == "" {
		return answer{}, errors.New("the fleet owner has not been minted yet")
	}
	client, err := a.fleetClient(block, block.OperatorPort, nil)
	if err != nil {
		return answer{}, err
	}
	return a.fleetSend(client, block, method, block.OperatorPort, path, body, state.OwnerCredential)
}

// fleetClient dials one of the Learner's own listeners, checking the service
// certificate against the course trust anchor and required name, exactly as the
// device does. A client certificate is added for the device half.
func (a *app) fleetClient(block fleetManifest, port int, client *tls.Certificate) (*http.Client, error) {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{RootCAs: pool, ServerName: a.fleetServiceName(block), MinVersion: tls.VersionTLS12}
	if client != nil {
		config.Certificates = []tls.Certificate{*client}
	}
	address := net.JoinHostPort(hostOf(block.Target), strconv.Itoa(port))
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
			},
			TLSClientConfig: config,
		},
	}, nil
}

func (a *app) fleetSend(client *http.Client, block fleetManifest, method string, port int, path string, body any, bearer string) (answer, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return answer{}, err
		}
		reader = strings.NewReader(string(encoded))
	}
	url := "https://" + net.JoinHostPort(a.fleetServiceName(block), strconv.Itoa(port)) + path
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		return answer{}, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		return answer{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return answer{}, err
	}
	result := answer{Status: response.StatusCode}
	if err := json.Unmarshal(raw, &result.Body); err != nil {
		result.Body = map[string]any{"body": strings.TrimSpace(string(raw))}
		return result, nil
	}
	result.Check, _ = result.Body["check"].(string)
	result.Reason, _ = result.Body["reason"].(string)
	result.DeviceID, _ = result.Body["device_id"].(string)
	return result, nil
}

// OperationalOrFactory returns the certificate a device presents: its
// Operational one once claimed, or its Factory one before that.
func (d *syntheticDevice) OperationalOrFactory() string {
	if d.OperationalCertificate != "" {
		return d.OperationalCertificate
	}
	return d.FactoryCertificate
}

func (d *syntheticDevice) OperationalOrFactoryKey() string {
	if d.OperationalCertificate != "" {
		return d.OperationalKey
	}
	return d.FactoryKey
}

// pemCertificate wraps a DER certificate as PEM, the one form tls.X509KeyPair
// and the state file both want.
func pemCertificate(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
