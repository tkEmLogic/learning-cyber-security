package ota

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The two halves of the claim, and the window they meet in.
//
// The device half proves a board: it arrives on the mutually authenticated
// listener carrying a Factory certificate, an Operational certification
// request and the nonce the board printed when somebody pressed its button.
// The operator half proves a person: it arrives on the server-authenticated
// listener carrying an Owner credential, the device identifier and the same
// nonce, transcribed by hand. Neither half alone claims anything.
//
// The device half strictly precedes the operator half. Parking an operator
// half for a device that has not called would mean holding a nonce guess for a
// window that may never open, which is a free offline oracle with its own
// expiry and its own replay surface. It also inverts the sequence the tier
// exists to teach: the physical act authorizes, so it goes first.

// ClaimWindowLifetime is how long the service will accept an operator half for
// a window the device opened.
//
// The device bounds its own window with a monotonic timer from the moment of
// the press; the service starts its ten minutes when the device half arrives,
// some seconds later. The two are deliberately not the same ten minutes, and
// only one of them is an authorization input: the service alone decides that a
// claim is expired. The device's timer only ever closes the device's own
// window, by destroying the nonce and the pending Operational key, and it
// never reports a time to the service. Device time stays evidence.
const ClaimWindowLifetime = 10 * time.Minute

// claimAttemptBudget is how many times the operator half may present a nonce
// that does not match before the window closes for good.
//
// Section 8 asks for bounded backoff, and backoff is only meaningful if
// retries exist. Burning the window on the first wrong nonce would turn one
// typo into a walk back to the bench, which is a lesson about the lab rather
// than about claiming.
const claimAttemptBudget = 5

// claimPollSeconds is what the device half tells the device to wait.
const claimPollSeconds = 5

// operationalLifetime is the ninety days an Operational certificate is valid.
//
// Spelled here as well as in coursepki, because the service signs from a
// directory it is handed and nothing under services/ depends on internal/.
// Ninety days against the Factory identity's ten years: a Factory identity has
// to outlive the product, and an owner is a fact that expires.
const operationalLifetime = 90 * 24 * time.Hour

// The authority the service signs with. The file name is the host side's, and
// it is spelled here for the same reason cmd/ota/main.go spells the two CA
// certificates it loads.
const (
	operationalCACertFile = "operational-ca.crt.pem"
	operationalCAKeyFile  = "operational-ca.key.pem"
)

// claimWindow is the hot state of one open window: the part that cannot be
// replayed out of a log.
//
// It lives in memory under one mutex and it does not survive a restart. The
// nonce is not forgotten when it does — the service's own event log holds the
// verifier of every nonce ever spent — but the certification request is, and a
// Learner whose service restarted mid-window presses the button again. That
// cost is stated rather than hidden, and it is why nothing here tries to
// reconstruct a live window from the log.
type claimWindow struct {
	deviceID      string
	nonceVerifier string
	request       *x509.CertificateRequest
	opened        time.Time
	expires       time.Time
	attempts      int

	// Filled by a successful match, and read by the device's next poll. The
	// window stays in memory carrying the answer, because the poll that
	// collects the certificate presents the same nonce that earned it.
	ownerID         string
	certificate     []byte
	certSerial      string
	certFingerprint string
	certNotAfter    time.Time
}

// claimOutcome is what one pass through the state machine decided, computed
// under the lock and answered after it.
type claimOutcome struct {
	refusal *Refusal
	status  int
	body    map[string]any
	delay   time.Duration
}

// claimDeviceHandler is the device half: POST /v1/devices/{device_id}/claim.
//
// identity-factory, certificate-active and the certificate-versus-path half of
// identifier-consistent have already run. This handler owes the third source:
// the certification request's own subject must name the same device the
// Factory certificate does. A device asking to be issued a certificate for a
// neighbour is refused at the same check by the same rule.
func (s *Server) claimDeviceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := DeviceFrom(r.Context())
		if !ok {
			http.Error(w, "no verified client certificate on this connection",
				http.StatusInternalServerError)
			return
		}
		var submission struct {
			Nonce string `json:"nonce"`
			CSR   string `json:"csr"`
		}
		// 400 is the one answer that is not an authorization decision, and it
		// must not borrow an authorization check's name. A malformed body is a
		// request the service could not read, not a request it refused.
		if err := decodeJSON(r.Body, &submission); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nonce := canonicalNonce(submission.Nonce)
		if !validClaimNonce(nonce) {
			http.Error(w, "a claim nonce is 24 Crockford base32 characters, in six groups of four",
				http.StatusBadRequest)
			return
		}
		request, err := parseCertificationRequest(submission.CSR)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The request's self-signature proves the device holds the Operational
		// private key it is asking to have certified. A request that does not
		// verify is not a request.
		if err := request.CheckSignature(); err != nil {
			http.Error(w, "the certification request does not verify against its own public key",
				http.StatusBadRequest)
			return
		}
		if request.Subject.CommonName != identity.DeviceID {
			s.Refuse(w, r, http.StatusForbidden, Refusal{
				Check: CheckIdentifierConsistent,
				Reason: fmt.Sprintf("the certificate presented names %s and the certification request names %s; one request names one device",
					identity.DeviceID, request.Subject.CommonName),
				DeviceID: identity.DeviceID,
			})
			return
		}

		outcome := s.openOrPoll(identity.DeviceID, nonceVerifierFor(nonce), request)
		if outcome.refusal != nil {
			s.Refuse(w, r, outcome.status, *outcome.refusal)
			return
		}
		writeJSON(w, outcome.status, outcome.body)
	})
}

// openOrPoll runs the device half's whole state change under the claim lock.
//
// The device re-sends this identical POST every five seconds rather than
// polling a second route, so one handler answers three different questions:
// open a window, wait, and collect the certificate. The service keeps the
// certification request from the first arrival and ignores re-sent copies.
func (s *Server) openOrPoll(deviceID, verifier string, request *x509.CertificateRequest) claimOutcome {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	now := s.cfg.MutualTLS.now()
	window := s.claimWindows[deviceID]
	if window != nil && window.certificate == nil && now.After(window.expires) {
		s.recordClaimEvent(deviceID, "closed", window.nonceVerifier,
			"the claim window expired before an operator half matched it")
		delete(s.claimWindows, deviceID)
		window = nil
	}

	if window != nil && window.nonceVerifier == verifier {
		if window.certificate != nil {
			return claimOutcome{status: http.StatusOK, body: map[string]any{
				"result":                  "issued",
				"device_id":               deviceID,
				"owner_id":                window.ownerID,
				"certificate":             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: window.certificate})),
				"certificate_serial":      window.certSerial,
				"certificate_fingerprint": window.certFingerprint,
				"not_after":               window.certNotAfter.UTC().Format(time.RFC3339),
			}}
		}
		// Pending carries no check field, and that is the device's whole rule:
		// a body with a check is terminal and stops the poll dead. "Not yet"
		// is the ordinary state of a live window, and giving it a check name
		// would add a refusal that is not one.
		return claimOutcome{status: http.StatusOK, body: map[string]any{
			"result":                  "pending",
			"device_id":               deviceID,
			"claim_window_expires_at": window.expires.UTC().Format(time.RFC3339),
			"poll_after_seconds":      claimPollSeconds,
		}}
	}

	if window != nil {
		// A second physical action supersedes. Two live nonces for one device
		// is two ways in, so the old window closes before the new one opens.
		s.recordClaimEvent(deviceID, "superseded", window.nonceVerifier,
			"a second claim window opened on this device")
		delete(s.claimWindows, deviceID)
	}

	if s.spentNonces()[verifier] {
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check:    CheckNonceUnspent,
			Reason:   "the nonce presented was already spent on a successful claim",
			DeviceID: deviceID,
		}}
	}

	window = &claimWindow{
		deviceID:      deviceID,
		nonceVerifier: verifier,
		request:       request,
		opened:        now,
		expires:       now.Add(ClaimWindowLifetime),
	}
	s.claimWindows[deviceID] = window
	s.recordClaimEvent(deviceID, "opened", verifier, "")
	return claimOutcome{status: http.StatusOK, body: map[string]any{
		"result":                  "pending",
		"device_id":               deviceID,
		"claim_window_expires_at": window.expires.UTC().Format(time.RFC3339),
		"poll_after_seconds":      claimPollSeconds,
	}}
}

// claimOperatorHandler is the operator half: POST /v1/claim.
//
// The three owner-credential checks have already run, and the owner is in the
// context because it was derived from the verified credential. The body's job
// is to name a device and a nonce; it does not name an owner, because a field
// a caller fills in is not an authentication.
func (s *Server) claimOperatorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner, ok := OwnerFrom(r.Context())
		if !ok {
			http.Error(w, "no authenticated owner on this request", http.StatusInternalServerError)
			return
		}
		var approval struct {
			DeviceID string `json:"device_id"`
			Nonce    string `json:"nonce"`
		}
		if err := decodeJSON(r.Body, &approval); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if approval.DeviceID == "" || approval.Nonce == "" {
			http.Error(w, "device_id and nonce are both required", http.StatusBadRequest)
			return
		}

		outcome := s.matchAndIssue(approval.DeviceID, canonicalNonce(approval.Nonce), owner)
		// The backoff is served after the lock is released, so a device
		// polling for its certificate is never made to wait behind somebody
		// else's wrong guess.
		if outcome.delay > 0 {
			s.claimSleep(outcome.delay)
		}
		if outcome.refusal != nil {
			s.Refuse(w, r, outcome.status, *outcome.refusal)
			return
		}
		writeJSON(w, outcome.status, outcome.body)
	})
}

// matchAndIssue holds one mutex across the whole transition: check the nonce,
// check the attempt budget, mark it spent, issue the certificate, append the
// claim record, release.
//
// Tier 6's atomicity came free, because the station was a command doing one
// O_APPEND write and the whole state change was that one line. That does not
// carry to a daemon. Releasing the lock before issuance would buy throughput
// nobody needs here, while introducing a state in which the nonce is spent and
// no certificate exists.
//
// The check order is #136's, and the obvious order is wrong. nonce-unspent
// runs before anything asks whether a window is open, and before anything asks
// who owns the device. Putting device-unowned first would make a replayed
// nonce against a genuinely claimed board refuse as already-owned, which would
// put a named success criterion out of the board's reach. Only nonce-match
// spends one of the five attempts: if the other three did, an attacker could
// close a Learner's window without ever guessing.
func (s *Server) matchAndIssue(deviceID, nonce, owner string) claimOutcome {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	verifier := nonceVerifierFor(nonce)

	// 1. nonce-unspent. Read from the service's own event log, so a nonce
	// spent before a restart is still known to have been spent and `replayed`
	// never collapses into `no open claim window`. No device_id on this
	// refusal or on the next: the service has established nothing about the
	// device the caller named.
	if s.spentNonces()[verifier] {
		s.recordClaimEvent(deviceID, "refused", verifier, CheckNonceUnspent)
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check:  CheckNonceUnspent,
			Reason: "the nonce presented was already spent on a successful claim",
		}}
	}

	// 2. claim-window-open. The device half strictly precedes this one, so a
	// device that has not called has no window and nothing is parked for it.
	now := s.cfg.MutualTLS.now()
	window := s.claimWindows[deviceID]
	if window != nil && window.certificate == nil && now.After(window.expires) {
		s.recordClaimEvent(deviceID, "closed", window.nonceVerifier,
			"the claim window expired before an operator half matched it")
		delete(s.claimWindows, deviceID)
		window = nil
	}
	if window == nil {
		s.recordClaimEvent(deviceID, "refused", "", CheckClaimWindowOpen)
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check:  CheckClaimWindowOpen,
			Reason: "no claim window is open for that device; press its button to open one",
		}}
	}

	// 3. nonce-match, the only check that spends an attempt.
	if window.nonceVerifier != verifier {
		window.attempts++
		delay := claimBackoff(window.attempts)
		reason := fmt.Sprintf("the nonce presented does not match the open claim window; %d of %d attempts left",
			claimAttemptBudget-window.attempts, claimAttemptBudget)
		if window.attempts >= claimAttemptBudget {
			s.recordClaimEvent(deviceID, "closed", window.nonceVerifier,
				"the attempt budget was exhausted")
			delete(s.claimWindows, deviceID)
			reason = fmt.Sprintf("the nonce presented does not match, and %d wrong attempts have closed this claim window",
				claimAttemptBudget)
		}
		s.recordClaimEvent(deviceID, "refused", "", CheckNonceMatch)
		return claimOutcome{status: http.StatusForbidden, delay: delay, refusal: &Refusal{
			Check:    CheckNonceMatch,
			Reason:   reason,
			DeviceID: deviceID,
		}}
	}

	// 4. device-unowned. First-come ownership: the device named no owner when
	// it opened the window, so the refusal has to come from the record. The
	// reason is silent about who the owner is. The check already tells this
	// caller that the device is owned, and that oracle is decided and bounded;
	// naming whom it belongs to is the one thing the caller could not
	// otherwise obtain, and in a real fleet it maps a device to a customer.
	if claim, claimed := s.provisioningState().devices[deviceID]; claimed && claim.claimed {
		s.recordClaimEvent(deviceID, "refused", "", CheckDeviceUnowned)
		return claimOutcome{status: http.StatusForbidden, refusal: &Refusal{
			Check:    CheckDeviceUnowned,
			Reason:   "that device is already owned, and ownership is first come in this course",
			DeviceID: deviceID,
		}}
	}

	// Both halves have matched. Issue, record, and close the window by filling
	// it with its answer.
	der, certificate, err := s.issueOperational(deviceID, owner, window.request.PublicKey)
	if err != nil {
		return claimOutcome{status: http.StatusInternalServerError, body: map[string]any{
			"error": "the operational authority could not sign this claim: " + err.Error(),
		}}
	}
	fingerprint := fingerprintOf(der)
	record := map[string]any{
		"kind":            "claim",
		"recorded_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"station":         "course-ota-service",
		"device_id":       deviceID,
		"owner_id":        owner,
		"lifecycle_state": "claimed",
		// The nonce is a secret that authorized a state change, so the record
		// keeps a verifier of it and never the nonce itself.
		"claim_nonce_verifier":    verifier,
		"certificate_serial":      certificate.SerialNumber.String(),
		"certificate_fingerprint": fingerprint,
		"certificate_public_key":  fingerprintOf(certificate.RawSubjectPublicKeyInfo),
	}
	if err := s.appendProvisioningRecord(record); err != nil {
		return claimOutcome{status: http.StatusInternalServerError, body: map[string]any{
			"error": "the claim could not be recorded, so nothing was issued: " + err.Error(),
		}}
	}

	window.ownerID = owner
	window.certificate = der
	window.certSerial = certificate.SerialNumber.String()
	window.certFingerprint = fingerprint
	window.certNotAfter = certificate.NotAfter
	s.recordClaimEvent(deviceID, "nonce_spent", verifier, "")
	s.recordClaimEvent(deviceID, "issued", verifier,
		fmt.Sprintf("operational certificate %s issued to owner %s", window.certSerial, owner))

	return claimOutcome{status: http.StatusOK, body: map[string]any{
		"result":                  "claimed",
		"device_id":               deviceID,
		"owner_id":                owner,
		"lifecycle_state":         "claimed",
		"certificate_serial":      window.certSerial,
		"certificate_fingerprint": fingerprint,
		"not_after":               certificate.NotAfter.UTC().Format(time.RFC3339),
	}}
}

// claimBackoff is the bounded backoff section 8 asks for: nothing on the first
// wrong nonce, then one, two, four and eight seconds.
//
// It is bounded twice over, by the delay and by the attempt budget, and the
// second bound is what makes the first honest. A backoff with no budget is a
// slow door rather than a closed one.
func claimBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	if attempt > claimAttemptBudget {
		attempt = claimAttemptBudget
	}
	return time.Duration(1<<(attempt-2)) * time.Second
}

// issueOperational signs one Operational certificate.
//
// The service holds a CA signing key while it is running, which is recorded as
// a result rather than slipped in: in a product the operational authority
// signs for the service, it is not the service. Section 8 names protected CA
// keys as something a defensible process adds and this course does not.
//
// An Operational certificate is a Factory certificate with a different issuer
// and the owner slug in the subject organizational unit. Nothing marks it
// "operational", because the issuer is the role and a second signal is a fact
// that can disagree with the chain.
func (s *Server) issueOperational(deviceID, owner string, publicKey any) ([]byte, *x509.Certificate, error) {
	dir := s.cfg.MutualTLS.PKIDir
	if dir == "" {
		return nil, nil, errors.New("no PKI directory; the service was started without COURSE_PKI_DIR")
	}
	ca, key, err := loadOperationalCA(dir)
	if err != nil {
		return nil, nil, err
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         deviceID,
			Organization:       []string{"Learning Cyber Security course, synthetic"},
			OrganizationalUnit: []string{owner},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(operationalLifetime),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Client authentication only, and no SAN: an Operational identity is
		// never a server, and a SAN answers which server you are talking to.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, certificate, nil
}

func loadOperationalCA(dir string) (*x509.Certificate, any, error) {
	certBytes, err := os.ReadFile(filepath.Join(dir, operationalCACertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("no operational device CA to sign with: %w", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("the operational CA certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := os.ReadFile(filepath.Join(dir, operationalCAKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("no operational device CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, errors.New("the operational CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return certificate, key, nil
}

// appendProvisioningRecord writes the one line the claim adds to the device
// lifecycle record, and refuses to write private key material.
//
// The guard is the provisioning station's, kept rather than assumed. Section
// 11 makes "the backend stores the private key" a stated failure criterion,
// and a criterion with no enforcement point is a wish. The service is a second
// writer of that store, so it needs its own copy of the enforcement rather
// than inheriting the station's by proximity.
//
// This is the only line this tier adds to records.jsonl. Refusals go to the
// service's own events.jsonl, where the window's whole trail already lives, so
// the terminal store keeps holding terminal facts.
func (s *Server) appendProvisioningRecord(record map[string]any) error {
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN EC PARAMETERS", "privateKey"} {
		if strings.Contains(string(line), marker) {
			return errors.New("refusing to write a lifecycle record that contains private key material")
		}
	}
	dir := s.cfg.MutualTLS.ProvisioningDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(dir, "records.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return err
}

// recordClaimEvent appends one line of the window's trail.
//
// A refusal therefore writes two lines: this one and the one Refuse writes.
// That is deliberate rather than duplication. Refuse records what the caller
// was told, and the wire body withholds the device identifier until the
// service has established it, so the operator half's first two refusals name
// no device on the wire at all. This row records which window the refusal was
// against, which is what makes the trail readable as one device's story.
//
// Opened, every refusal, closed, superseded and spent, all in the service's
// own events.jsonl beside the refusals Refuse writes. That is what "records
// every result" means without inventing a store, and it is what keeps a
// replayed nonce distinguishable from a nonce nobody ever saw across a
// restart: the window is memory, and the fact that a nonce was spent is not.
//
// The nonce itself never appears, here or anywhere else. A verifier is what a
// record may hold of a secret.
func (s *Server) recordClaimEvent(deviceID, event, verifier, detail string) {
	row := map[string]any{
		"source":              "service",
		"claim_event":         event,
		"device_id":           deviceID,
		"service_received_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if verifier != "" {
		row["claim_nonce_verifier"] = verifier
	}
	if detail != "" {
		row["detail"] = detail
	}
	line, err := json.Marshal(row)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(filepath.Join(s.cfg.StateDir, "events.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(line, '\n'))
}

// spentNonces replays the service's event log for the verifiers of nonces that
// were spent on a successful claim.
//
// A nonce is spent on a successful match and on nothing else. A window that
// expired, or that ran out of attempts, spends nothing: its nonce is dead
// because its window is gone, and an operator presenting it afterwards is told
// that no claim window is open rather than that the nonce was used.
func (s *Server) spentNonces() map[string]bool {
	spent := map[string]bool{}
	forEachJSONLine(filepath.Join(s.cfg.StateDir, "events.jsonl"), func(line []byte) {
		var row struct {
			Source   string `json:"source"`
			Event    string `json:"claim_event"`
			Verifier string `json:"claim_nonce_verifier"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return
		}
		if row.Source == "service" && row.Event == "nonce_spent" && row.Verifier != "" {
			spent[row.Verifier] = true
		}
	})
	return spent
}

// crockfordAlphabet is Crockford base32: no I, no L, no O, no U.
//
// The nonce is transcribed by a person from a serial console into a shell,
// which is what makes the alphabet a design decision rather than a detail.
// Dropping those four letters means 0 and O, and 1 and l, never bite. Tier 6's
// 32-byte hex nonce is never read by a human, so its encoding was free; this
// one is not.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// claimNonceLength is 15 bytes as 24 characters. 120 bits divides evenly by
// five, so the encoding has no padding and the six groups of four are real
// rather than cosmetic.
const claimNonceLength = 24

// canonicalNonce is what both halves hash.
//
// A person typing a nonce may drop the grouping hyphens, use lower case, or
// type the letters Crockford deliberately left out. Canonicalising here is
// what makes the confusable-free alphabet pay: the nonce a Learner reads off a
// console and the nonce they type into a shell hash to the same verifier
// however they spaced it.
func canonicalNonce(nonce string) string {
	var canonical strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(nonce)) {
		switch r {
		case '-', ' ', '\t':
		case 'I', 'L':
			canonical.WriteRune('1')
		case 'O':
			canonical.WriteRune('0')
		case 'U':
			canonical.WriteRune('V')
		default:
			canonical.WriteRune(r)
		}
	}
	return canonical.String()
}

// validClaimNonce checks the shape of a nonce the device generated.
//
// It runs on the device half only. The device is the party that generates the
// nonce, so the service is entitled to require its own format there, and a
// wrong shape is a firmware bug rather than a refusal. On the operator half
// nothing checks the shape: a nonce of any shape that does not match simply
// does not match, and spends one of the five attempts, which is the bound that
// is supposed to stop guessing.
func validClaimNonce(nonce string) bool {
	if len(nonce) != claimNonceLength {
		return false
	}
	for _, r := range nonce {
		if !strings.ContainsRune(crockfordAlphabet, r) {
			return false
		}
	}
	return true
}

func nonceVerifierFor(nonce string) string {
	sum := sha256.Sum256([]byte(canonicalNonce(nonce)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// parseCertificationRequest accepts the request as PEM or as base64 DER.
//
// Two spellings rather than one, because the device writes what mbedTLS gives
// it and a host tool writes what is easiest to paste. Both decode to the same
// bytes, and the signature check that follows is what actually matters.
func parseCertificationRequest(value string) (*x509.CertificateRequest, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("a certification request is required")
	}
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		if block.Type != "CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("expected a certification request, got a %s block", block.Type)
		}
		return x509.ParseCertificateRequest(block.Bytes)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trimmed), ""))
	if err != nil {
		return nil, errors.New("the certification request is neither PEM nor base64 DER")
	}
	return x509.ParseCertificateRequest(der)
}
