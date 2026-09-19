package courseapp

// The Tier 7 adversary: one actor, not a bag of tricks.
//
// It holds a legitimate owner account, enrols synthetic devices through the
// real provisioning station, drives both halves of a real claim, and holds the
// Operational CA signing key. Every row in tier07_bypass.go is that one actor
// doing one more thing with what it already has, which is why there is a type
// here rather than fifteen independent functions.
//
// The power it has is not a trick the course invented. It is the Operational
// CA key having leaked, and the module names it as the threat it is. What the
// key may sign is bounded by docs/fixture-safety-contract.md to an Operational
// leaf for a device identifier this Course environment holds a record for, and
// signWithOperationalCA is the only place that calls the signing variant.
//
// It is a client. It never starts, stops or reconfigures the Learner's
// service, and it has no privileged access to the thing refusing it: every
// refusal below is read off the wire from a service the Learner started.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// tier07BypassKey is the manifest block every runner reads its inputs from.
const tier07BypassKey = "tier-07"

// tier07Adversary is the actor. One per run.
type tier07Adversary struct {
	app      *app
	manifest bypassManifest
	state    *adversaryState

	// row is the identifier being run, so narration and the CA-key disclosure
	// can name it without being passed it twice.
	row string
}

// adversaryState is what the fixture remembers between rows.
//
// It exists so that a row is rerunnable. The station refuses a second
// enrollment under an identifier that already holds a certificate, which is
// E-6-02 working exactly as Tier 6 built it, so a runner that minted fresh
// material every time would be refused by the previous run rather than by the
// check it is testing.
//
// It holds secrets: the adversary owner's credential and every synthetic
// device's private keys. It lives under `.course-state/`, which is ignored and
// never committed, at 0600 inside a 0700 directory, and nothing ever prints
// its contents. Reset deletes it.
type adversaryState struct {
	OwnerCredential string                      `json:"owner_credential"`
	Devices         map[string]*syntheticDevice `json:"devices"`

	// RevokedSerials is what this fixture marked revoked, so reset can clear
	// exactly those and nothing a Learner marked themselves.
	RevokedSerials []string `json:"revoked_serials,omitempty"`
}

// syntheticDevice is one host-side device: what the board holds in Secure
// Storage, held in a file instead.
type syntheticDevice struct {
	DeviceID           string `json:"device_id"`
	FactoryKey         string `json:"factory_key"`
	FactoryCertificate string `json:"factory_certificate"`

	// Filled once the fixture has driven a real claim for this device.
	OperationalKey         string `json:"operational_key,omitempty"`
	OperationalCertificate string `json:"operational_certificate,omitempty"`
	OperationalSerial      string `json:"operational_serial,omitempty"`
	OwnerID                string `json:"owner_id,omitempty"`
}

func (a *app) bypassStateDir() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "bypass", tier07BypassKey)
}

func (a *app) bypassStatePath() string {
	return filepath.Join(a.bypassStateDir(), "state.json")
}

// newTier07Adversary reads the manifest block and the fixture's own state.
//
// It does not reach the network and it does not check the marker. Those are
// the runner wrapper's job, and they happen before any side effect.
func (a *app) newTier07Adversary(row string) (*tier07Adversary, error) {
	block, ok := a.manifest.Bypass[tier07BypassKey]
	if !ok {
		return nil, fmt.Errorf("course.yml has no bypass entry for %s", tier07BypassKey)
	}
	state, err := a.readAdversaryState()
	if err != nil {
		return nil, err
	}
	return &tier07Adversary{app: a, manifest: block, state: state, row: row}, nil
}

func (a *app) readAdversaryState() (*adversaryState, error) {
	state := &adversaryState{Devices: map[string]*syntheticDevice{}}
	raw, err := os.ReadFile(a.bypassStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("fixture state is corrupt; run ./course service bypass reset: %w", err)
	}
	if state.Devices == nil {
		state.Devices = map[string]*syntheticDevice{}
	}
	return state, nil
}

func (x *tier07Adversary) save() error {
	return x.app.saveAdversaryState(x.state)
}

func (x *tier07Adversary) out() io.Writer { return x.app.out }

// allowedIdentifier refuses anything outside the manifest's bounded list.
//
// The list is in course.yml and never on a command line. An identifier the
// manifest does not name is refused before any side effect, which is the same
// rule that keeps a fixture from being handed a firmware path.
func (x *tier07Adversary) allowedIdentifier(deviceID string) error {
	for _, allowed := range x.manifest.SyntheticIDs {
		if allowed == deviceID {
			return nil
		}
	}
	return fmt.Errorf("device identifier %q is not in the manifest's bounded list for %s",
		deviceID, tier07BypassKey)
}

// ------------------------------------------------------------------
// The adversary owner
// ------------------------------------------------------------------

// ensureOwner mints the one adversary owner, once.
//
// It is a real entry in the Learner's own owner store, beside their own. It
// has to be: an account that could not authenticate would be refused at the
// three bearer checks and would never reach the authorization decision the
// rows exist to show. That is the whole lesson — the adversary is correctly
// authenticated, and every refusal it collects is an authorization decision.
//
// Idempotent, because a runner that minted on every run would leave a trail of
// superseded entries in a store the Learner is asked to read.
func (x *tier07Adversary) ensureOwner() (string, error) {
	slug := x.manifest.AdversaryOwner
	if slug == "" {
		return "", errors.New("course.yml names no adversary owner for the Tier 7 bypass")
	}
	if x.state.OwnerCredential != "" {
		current, err := x.app.ownerCredentialIsCurrent(slug, x.state.OwnerCredential)
		if err != nil {
			return "", err
		}
		if current {
			return slug, nil
		}
	}
	credential, record, err := x.app.mintOwner(slug)
	if err != nil {
		return "", err
	}
	x.state.OwnerCredential = credential
	if err := x.save(); err != nil {
		return "", err
	}
	fmt.Fprintf(x.out(), "  the adversary holds a legitimate owner account: %s, credential %s\n",
		record.OwnerID, record.CredentialID)
	fmt.Fprintln(x.out(), "  it is a real entry in your own owner store. Every refusal below is")
	fmt.Fprintln(x.out(), "  therefore an authorization decision and not an authentication one.")
	return slug, nil
}

// ------------------------------------------------------------------
// Synthetic devices
// ------------------------------------------------------------------

// ensureEnrolled enrols one synthetic device through the real station.
//
// In process, through the same enroll() a real board reaches, as Tier 6's
// runners do: the station has no network surface to go over the wire to, so
// anything else would mean building one. The record it writes is an ordinary
// record with no marker field, which is Tier 6's shape and a stated lesson
// rather than a gap.
func (x *tier07Adversary) ensureEnrolled(deviceID string) (*syntheticDevice, error) {
	if err := x.allowedIdentifier(deviceID); err != nil {
		return nil, err
	}
	if device, ok := x.state.Devices[deviceID]; ok && device.FactoryCertificate != "" {
		return device, nil
	}
	credential, _, err := x.app.mintCredential(deviceID)
	if err != nil {
		return nil, err
	}
	host, err := newHostDevice()
	if err != nil {
		return nil, err
	}
	csr, err := host.request(deviceID, credential)
	if err != nil {
		return nil, err
	}
	outcome, err := x.app.enrollHost(deviceID, credential, csr)
	if err != nil {
		return nil, err
	}
	if !outcome.Issued {
		return nil, fmt.Errorf("the station refused to enrol %s at %s: %s",
			deviceID, outcome.Check, outcome.Reason)
	}
	keyPEM, err := privateKeyPEM(host.key)
	if err != nil {
		return nil, err
	}
	device := &syntheticDevice{
		DeviceID:           deviceID,
		FactoryKey:         keyPEM,
		FactoryCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: outcome.CertDER})),
	}
	x.state.Devices[deviceID] = device
	if err := x.save(); err != nil {
		return nil, err
	}
	fmt.Fprintf(x.out(), "  enrolled %s through the real station, Factory certificate %s\n",
		deviceID, outcome.CertSerial)
	return device, nil
}

// claimSynthetic drives both halves of a real claim for one synthetic device.
//
// The ticket did not ask for this and the row set forced it out:
// identifier-consistent, device-claimed and ownership-context all need a
// device that is genuinely claimed, so the fixture is a full device
// impersonator and not only a credential forger.
//
// It exposes an asymmetry the module states: the nonce is only ever as good as
// the channel that carries it out of the device. For a board that channel is a
// person reading a console. Here the fixture is both ends of it, so the
// property under test is simply absent, which is the honest reason the
// claim-window rows are labelled "host, board required".
//
// The nonce it returns is the one that was spent, which E-7-11 replays.
func (x *tier07Adversary) claimSynthetic(deviceID string) (*syntheticDevice, string, error) {
	device, err := x.ensureEnrolled(deviceID)
	if err != nil {
		return nil, "", err
	}
	owner, err := x.ensureOwner()
	if err != nil {
		return nil, "", err
	}
	if device.OperationalCertificate != "" {
		return device, "", nil
	}

	operationalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	csrPEM, err := operationalRequest(deviceID, operationalKey)
	if err != nil {
		return nil, "", err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return nil, "", err
	}

	// The device half, on the Factory identity, over mutual TLS.
	opened, err := x.asDevice(device.FactoryCertificate, device.FactoryKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csrPEM})
	if err != nil {
		return nil, "", err
	}
	if opened.refused() {
		return nil, "", fmt.Errorf("the device half of the claim for %s was refused at %s: %s",
			deviceID, opened.Check, opened.Reason)
	}

	// The operator half, as the adversary owner, on the operator listener.
	approved, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return nil, "", err
	}
	if approved.refused() {
		return nil, "", fmt.Errorf("the operator half of the claim for %s was refused at %s: %s",
			deviceID, approved.Check, approved.Reason)
	}

	// The device polls once more with the same nonce and collects the
	// certificate it earned.
	issued, err := x.asDevice(device.FactoryCertificate, device.FactoryKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csrPEM})
	if err != nil {
		return nil, "", err
	}
	certificate, _ := issued.Body["certificate"].(string)
	if certificate == "" {
		return nil, "", fmt.Errorf("the claim for %s completed with no certificate: %v", deviceID, issued.Body)
	}
	keyPEM, err := privateKeyPEM(operationalKey)
	if err != nil {
		return nil, "", err
	}
	device.OperationalKey = keyPEM
	device.OperationalCertificate = certificate
	device.OperationalSerial, _ = issued.Body["certificate_serial"].(string)
	device.OwnerID = owner
	if err := x.save(); err != nil {
		return nil, "", err
	}
	fmt.Fprintf(x.out(), "  claimed %s as %s, Operational certificate %s\n",
		deviceID, owner, device.OperationalSerial)
	return device, nonce, nil
}

// ------------------------------------------------------------------
// The Operational CA signing key
// ------------------------------------------------------------------

// signWithOperationalCA forges one Operational certificate, and says so while
// it is doing it.
//
// The narration is required by the fixture safety contract, in the same words
// it requires of a Tier 4 fixture signing with the Release signing key. A
// Learner watching their own authority sign a certificate the service then
// refuses would otherwise draw the wrong conclusion twice: first that the key
// had escaped the lab, and then that the refusal proves a CA signature is
// worthless. Neither is what the row shows.
//
// The bound is the contract's and it is not widened here: an Operational leaf
// for a device identifier this Course environment holds a record for, and
// nothing else. It signs no authority, no server certificate, no Factory
// identity, no Release manifest and no firmware image, and it cannot: the
// variant it calls sets no basic constraints and no certificate-sign usage.
func (x *tier07Adversary) signWithOperationalCA(deviceID, ownerScope string,
	serial *big.Int, notBefore, notAfter time.Time) (string, *ecdsa.PrivateKey, error) {
	if !x.app.recordsName(deviceID) {
		return "", nil, fmt.Errorf("this environment holds no record for %s, so the fixture may not sign for it", deviceID)
	}
	caCert, _, err := coursepki.LoadOperationalCA(x.app.pkiDir())
	if err != nil {
		return "", nil, fmt.Errorf("no Operational Device CA; run ./course keys create operational-ca first: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	fmt.Fprintf(x.out(), "  %s signs with your own Operational Device CA key\n", x.row)
	fmt.Fprintf(x.out(), "    key fingerprint: %s\n", short(fingerprintOfBytes(caCert.RawSubjectPublicKeyInfo)))
	fmt.Fprintf(x.out(), "    signing one Operational leaf for %s, owner scope %q, serial %s\n",
		deviceID, ownerScope, serial)
	fmt.Fprintln(x.out(), "    the capability under test is a leaked CA key. This row is what an")
	fmt.Fprintln(x.out(), "    insider with the authority's private half can make, not what an")
	fmt.Fprintln(x.out(), "    outsider on the network can.")

	der, err := coursepki.IssueOperationalCertificateAs(x.app.pkiDir(), deviceID, ownerScope,
		key.Public(), serial, notBefore, notAfter)
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key, nil
}

// recordsName reports whether the device lifecycle record holds any line for
// this identifier. It is the "recorded identifier" bound, read from the
// Learner's own record rather than from the fixture's memory.
func (a *app) recordsName(deviceID string) bool {
	records, err := a.readRecords()
	if err != nil {
		return false
	}
	for _, record := range records {
		if record.DeviceID == deviceID {
			return true
		}
	}
	return false
}

// claimedDeviceNotOwnedBy finds a device the record says is claimed by
// somebody other than the adversary.
//
// In an ordinary lab that is the Learner's own board, claimed in E-7-01, which
// is why the ownership-context row is witnessed on the host but needs a board
// to exist at all. Under first-come ownership the adversary can never obtain
// such a certificate honestly, so the row forges one or it does not exist.
func (a *app) claimedDeviceNotOwnedBy(adversary string) (deviceID, owner, serial string, ok bool) {
	records, err := a.readRecords()
	if err != nil {
		return "", "", "", false
	}
	for _, record := range records {
		if record.Kind != recordClaim || record.OwnerID == adversary || record.OwnerID == "" {
			continue
		}
		deviceID, owner, serial, ok = record.DeviceID, record.OwnerID, record.CertSerial, true
	}
	return deviceID, owner, serial, ok
}

// ------------------------------------------------------------------
// Talking to the Learner's own listeners
// ------------------------------------------------------------------

// answer is what one request came back with, read the way the firmware reads
// it: the check name decides, and the status never does.
type answer struct {
	Status   int
	Check    string
	Reason   string
	DeviceID string
	Body     map[string]any
}

func (r answer) refused() bool { return r.Check != "" }

// asDevice sends one request to the device listener, presenting a client
// certificate.
//
// A host-side client that presents a client certificate did not exist
// anywhere in this repository before this ticket. verifyingClient in tier02.go
// is server authentication only, and the only mutual-TLS code in the tree was
// the #157 spike's server.
func (x *tier07Adversary) asDevice(certPEM, keyPEM, method, path string, body any) (answer, error) {
	certificate, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return answer{}, err
	}
	client, err := x.tlsClient(x.manifest.DevicePort, &certificate)
	if err != nil {
		return answer{}, err
	}
	return x.send(client, method, x.manifest.DevicePort, path, body, "")
}

// asOwner sends one request to the operator listener as the adversary owner.
//
// The credential travels only as an Authorization header and never in a body,
// so it cannot land in any log that records bodies.
func (x *tier07Adversary) asOwner(method, path string, body any) (answer, error) {
	if x.state.OwnerCredential == "" {
		return answer{}, errors.New("the adversary owner has not been minted yet")
	}
	client, err := x.tlsClient(x.manifest.OperatorPort, nil)
	if err != nil {
		return answer{}, err
	}
	return x.send(client, method, x.manifest.OperatorPort, path, body, x.state.OwnerCredential)
}

// tlsClient dials one of the Learner's own listeners, on this host, at a port
// the manifest records.
//
// It checks the service's certificate the way the device does: this trust
// anchor, this required name, no way to skip either. A fixture that skipped
// verification could be fooled by the very impersonation Tier 2 taught the
// device to refuse.
func (x *tier07Adversary) tlsClient(port int, client *tls.Certificate) (*http.Client, error) {
	pool, err := x.app.trustAnchorPool()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		RootCAs:    pool,
		ServerName: x.serviceName(),
		MinVersion: tls.VersionTLS12,
	}
	if client != nil {
		config.Certificates = []tls.Certificate{*client}
	}
	address := net.JoinHostPort(hostOf(x.manifest.Target), strconv.Itoa(port))
	return &http.Client{
		Timeout: 30 * time.Second,
		// Redirects are off for every fixture in this course, and a redirect
		// is one of the ways a target can stop being the target that was
		// checked.
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

func (x *tier07Adversary) serviceName() string {
	if x.manifest.ServiceName != "" {
		return x.manifest.ServiceName
	}
	return coursepki.ServiceName
}

func (x *tier07Adversary) send(client *http.Client, method string, port int,
	path string, body any, bearer string) (answer, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return answer{}, err
		}
		reader = strings.NewReader(string(encoded))
	}
	url := "https://" + net.JoinHostPort(x.serviceName(), strconv.Itoa(port)) + path
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
		// Not every answer is JSON: a 400 from a handler is plain text, and a
		// runner that insisted on JSON would report a parse error instead of
		// the answer the service actually gave.
		result.Body = map[string]any{"body": strings.TrimSpace(string(raw))}
		return result, nil
	}
	result.Check, _ = result.Body["check"].(string)
	result.Reason, _ = result.Body["reason"].(string)
	result.DeviceID, _ = result.Body["device_id"].(string)
	return result, nil
}

// ------------------------------------------------------------------
// Reading the refusal
// ------------------------------------------------------------------

// expectRefusal prints what the service answered and fails if it did not
// refuse, or refused at a different check than the row names.
//
// It is reportRefusal's shape, one namespace over: Tier 6 asserts a station's
// check in process, and this asserts a service's check over the wire. A bypass
// that refuses for the wrong reason has not tested what it claims to, and that
// rule does not change because the refusal now arrives over HTTP.
//
// It asserts the check and not the status. Every authorization refusal in this
// tier is 403, so the status is never the reason, and a runner that asserted
// 403 would pass on the wrong refusal.
func (x *tier07Adversary) expectRefusal(result answer, wantCheck string) error {
	if !result.refused() {
		return fmt.Errorf("%s was not refused: the service answered %d with %v",
			x.row, result.Status, result.Body)
	}
	fmt.Fprintf(x.out(), "  refused at check %s, HTTP %d\n", result.Check, result.Status)
	fmt.Fprintf(x.out(), "  %s\n", result.Reason)
	if result.DeviceID != "" {
		fmt.Fprintf(x.out(), "  the refusal names device %s, so the service had established which device it was talking to\n",
			result.DeviceID)
	}
	if result.Check != wantCheck {
		return fmt.Errorf("%s refused at %q, expected %q", x.row, result.Check, wantCheck)
	}
	fmt.Fprintf(x.out(), "\nResult: %s refused at %s, as the tier requires\n", x.row, wantCheck)
	return nil
}

// ------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------

func privateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// operationalRequest is the certification request the board's firmware builds
// for its pending Operational key: a subject naming the device, and nothing
// else. The owner is not in it, because the owner is the service's answer and
// not the device's request.
func operationalRequest(deviceID string, key *ecdsa.PrivateKey) (string, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// crockfordAlphabet is Crockford base32, the same alphabet the service
// canonicalises against: no I, no L, no O, no U.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newClaimNonce generates one nonce in the shape the board prints: fifteen
// bytes as twenty-four characters. 120 bits divides evenly by five, so there
// is no padding and the six groups of four are real rather than cosmetic.
//
// The fixture holds it in memory for the length of one run and prints none of
// them, which is the same rule the board's console cannot follow and the
// reason the claim-window rows need a board to mean anything.
func newClaimNonce() (string, error) {
	raw := make([]byte, 15)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var nonce strings.Builder
	value, bits := 0, 0
	for _, b := range raw {
		value = value<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			nonce.WriteByte(crockfordAlphabet[(value>>bits)&31])
		}
	}
	return nonce.String(), nil
}

func fingerprintOfBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
