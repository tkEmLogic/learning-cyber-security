package ota

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Tier 7's check names.
//
// A check names the property that had to hold, so "refused at check X" reads
// as "X did not hold". Tier 6's provisioning station already publishes that
// grammar; these are a second namespace in it, because which component refused
// you is half of what this tier teaches. A Learner grepping a check name must
// land in one place with one meaning, which is why the Owner credential's
// three carry an `owner-` prefix rather than reusing Tier 6's words.
//
// `reason_code` was unavailable as a field name. It has meant "the device's
// own reason for the result it is reporting" in every event body since Tier 0,
// and one JSON key may not mean two things. The wire field is `check`, and the
// firmware branches on it rather than on the status: every authorization
// refusal here is 403, so the status is never the reason.
const (
	// The device listener, all six emitted in this package.
	CheckIdentityOperational  = "identity-operational"
	CheckIdentityFactory      = "identity-factory"
	CheckCertificateActive    = "certificate-active"
	CheckIdentifierConsistent = "identifier-consistent"
	CheckDeviceClaimed        = "device-claimed"
	CheckOwnershipContext     = "ownership-context"

	// The operator listener. The three credential checks refuse 401 and the
	// four claim checks 403. Issue #146 builds the Owner credential store and
	// the claim endpoints that emit them; the listener, the refusal shape and
	// the names are here so both halves speak one vocabulary.
	CheckOwnerCredentialKnown   = "owner-credential-known"
	CheckOwnerCredentialCurrent = "owner-credential-current"
	CheckOwnerCredentialValid   = "owner-credential-valid"
	CheckNonceUnspent           = "nonce-unspent"
	CheckClaimWindowOpen        = "claim-window-open"
	CheckNonceMatch             = "nonce-match"
	CheckDeviceUnowned          = "device-unowned"
)

// The two certificate roles, which are the two authorities and nothing else.
//
// Role is which CA signed the certificate, read from VerifiedChains. A second
// signal — an extension, a common-name prefix — would be a fact that can
// disagree with the chain, and the day it does the service believes the wrong
// one. There is nothing to reconcile if there is nothing to reconcile with.
const (
	RoleFactory     = "factory"
	RoleOperational = "operational"
)

// Refusal is what every authorization refusal carries on the wire.
//
// Two fields always, and the device identifier only where the service has
// actually established which device it is talking to. The two are the same
// words the provisioning station's enrollment outcome already carries, so
// "refused at check <check>" is one sentence in both tiers.
//
// The line for device_id falls after certificate-active, which is the check
// that asks whether this service ever issued the certificate in front of it.
// Before that check passes, the subject common name is a claim the presented
// certificate makes about itself; a refusal that repeated it as device_id
// would be asserting the very thing it is refusing to accept. So
// identity-operational, identity-factory and certificate-active answer with
// two fields, and identifier-consistent, device-claimed and ownership-context
// answer with three.
//
// A reason is specific about what the caller already holds — its own serial,
// its own identifier, its own expiry — and silent about the record's contents.
// A wrong-owner refusal never names the current owner. The check already tells
// the caller that the device is owned, and that oracle is decided and bounded;
// naming whom it belongs to is the one thing the refuser could not otherwise
// obtain, and in a real fleet it maps a device to a customer.
type Refusal struct {
	Check    string `json:"check"`
	Reason   string `json:"reason"`
	DeviceID string `json:"device_id,omitempty"`
}

// MutualTLS is everything the two new listeners need that the Tier 0 service
// never had. It is nil unless the service was started with --mutual-tls, and
// nil means every byte the service emits is what Tiers 0 to 6 already see.
type MutualTLS struct {
	// ManufacturerCA signs Factory identities and OperationalCA signs
	// Operational ones. Both are self-signed roots, distinguishable at the top
	// of a verified chain, which is what makes the issuer the role.
	ManufacturerCA *x509.Certificate
	OperationalCA  *x509.Certificate

	// ProvisioningDir is the manufacturing record's directory,
	// `.course-state/provisioning`. The service reads `records.jsonl` and
	// `revoked.jsonl` out of it live, on every request that needs them: a
	// Learner who mints something and is then refused must not have to guess
	// that a restart is the fix.
	ProvisioningDir string

	// PKIDir is the one new variable the service is given, holding the four
	// authorities. Only the two CA certificates above are read here. Issue
	// #146 reads the Operational CA's signing key out of the same directory
	// when it issues a certificate at the end of a claim.
	PKIDir string

	// Now is the service clock, overridable in tests. The device cannot
	// evaluate a validity window at all, so this clock is the only enforcer of
	// certificate expiry anywhere in the course.
	Now func() time.Time
}

// ClaimHandlers is the seam issue #146 hangs the two halves of the claim
// exchange on. This ticket builds the listeners, the routes and the checks
// that run before each handler; neither handler is built here.
//
// Device reaches `POST /v1/devices/{device_id}/claim` on the device listener,
// after identity-factory, certificate-active and identifier-consistent have
// passed. It takes the Operational certification request and the nonce, and it
// still owes identifier-consistent one comparison this package cannot make:
// the request's own subject must name the same device the Factory certificate
// does. DeviceFrom gives it the certificate half of that comparison and Refuse
// writes the refusal.
//
// Operator reaches `POST /v1/claim` on the operator listener, after the three
// Owner credential checks have passed. OwnerFrom gives it the authenticated
// owner, which is derived from the verified credential and never read from the
// request body.
//
// A nil handler answers 503 rather than 404, because a route that exists and
// is not built yet is a different fact from a route that does not exist.
type ClaimHandlers struct {
	Device   http.Handler
	Operator http.Handler
}

// OwnerVerifier authenticates an operator request's bearer credential and
// returns the owner it belongs to. Issue #146 implements it over
// `.course-state/provisioning/owners.jsonl`.
//
// A refusal carries one of the three owner-credential check names and is
// answered 401, because those three are the only authentication failures in
// the tier; everything else a refusal can say here is authorization and 403.
// There is no session object: the owner is derived from the credential on the
// one request that carries it.
type OwnerVerifier interface {
	VerifyOwner(credential string) (ownerID string, refusal *Refusal)
}

// DeviceIdentity is the three facts the service reads out of a client
// certificate, each with exactly one source.
type DeviceIdentity struct {
	// DeviceID is the subject common name, which is where issue #114 settled
	// that a device's identifier lives.
	DeviceID string

	// OwnerScope is the subject organizational unit, carried by Operational
	// certificates only. It is what the certificate says; ownership context is
	// what the record says, and ownership-context is the check that they agree.
	OwnerScope string

	// Role is RoleFactory or RoleOperational, from the root of the verified
	// chain.
	Role string

	// Serial is the decimal serial number, in the same spelling the
	// manufacturing record stores, because the record joins on it.
	Serial string

	NotBefore time.Time
	NotAfter  time.Time
}

type contextKey string

const (
	deviceContextKey contextKey = "ota.device-identity"
	ownerContextKey  contextKey = "ota.authenticated-owner"
)

// DeviceFrom returns the identity the device listener derived from the client
// certificate. It is set on every request that reached a device handler, so a
// handler never has to ask a request who it is.
func DeviceFrom(ctx context.Context) (DeviceIdentity, bool) {
	identity, ok := ctx.Value(deviceContextKey).(DeviceIdentity)
	return identity, ok
}

// OwnerFrom returns the owner the operator listener derived from the verified
// bearer credential.
func OwnerFrom(ctx context.Context) (string, bool) {
	owner, ok := ctx.Value(ownerContextKey).(string)
	return owner, ok
}

// identityFrom reads the three facts out of the verified peer certificate.
//
// It cannot be reached without one: the listener is at
// tls.RequireAndVerifyClientCert, so a certificate from a genuinely foreign
// issuer fails during the handshake, before any handler runs, and the caller
// sees a closed connection with no status, no body and no check. That
// asymmetry is the tier's clearest demonstration that a refusal's usefulness
// depends on which layer refuses, and it is taught rather than worked around.
func (m *MutualTLS) identityFrom(r *http.Request) (DeviceIdentity, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return DeviceIdentity{}, false
	}
	chain := r.TLS.VerifiedChains[0]
	leaf := chain[0]
	root := chain[len(chain)-1]

	identity := DeviceIdentity{
		DeviceID:  leaf.Subject.CommonName,
		Serial:    leaf.SerialNumber.String(),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	if len(leaf.Subject.OrganizationalUnit) > 0 {
		identity.OwnerScope = leaf.Subject.OrganizationalUnit[0]
	}
	switch {
	case m.OperationalCA != nil && root.Equal(m.OperationalCA):
		identity.Role = RoleOperational
	case m.ManufacturerCA != nil && root.Equal(m.ManufacturerCA):
		identity.Role = RoleFactory
	default:
		return DeviceIdentity{}, false
	}
	return identity, true
}

// ClientCAPool is the pool the device listener verifies client certificates
// against: the two device authorities and nothing else.
//
// The Course CA is deliberately absent. It signs the service's own server
// certificate, and a pool that trusted it to authenticate clients would let a
// service certificate log in as a device.
func (m *MutualTLS) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if m.ManufacturerCA != nil {
		pool.AddCert(m.ManufacturerCA)
	}
	if m.OperationalCA != nil {
		pool.AddCert(m.OperationalCA)
	}
	return pool
}

func (m *MutualTLS) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Refuse answers one request with one refusal and records it.
//
// Both halves matter. The caller gets a body it can branch on, and the
// service's own events.jsonl gets the row that makes the tier's authorization
// tests a grep rather than a screenshot. Issue #146's operator handlers call
// this too, so one refusal never lands in two shapes.
func (s *Server) Refuse(w http.ResponseWriter, r *http.Request, status int, refusal Refusal) {
	s.recordRefusal(r, refusal)
	writeJSON(w, status, refusal)
}

// recordRefusal appends the refusal to the service's own event log.
//
// It goes in events.jsonl rather than in a second file, because one device's
// story should not split across two records a Learner has to join by hand. The
// `source` tag is what keeps a service-authored refusal from being mistaken
// for a device-authored event, and concretely from colliding with the
// device's own `reason_code` in a neighbouring line.
//
// A refusal that cannot be written is still a refusal. The caller is answered
// either way: failing the request because the log is unwritable would turn a
// 403 into a 500 and teach the wrong lesson about which one happened.
func (s *Server) recordRefusal(r *http.Request, refusal Refusal) {
	row := map[string]any{
		"source":              "service",
		"check":               refusal.Check,
		"reason":              refusal.Reason,
		"path":                r.URL.Path,
		"service_received_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if refusal.DeviceID != "" {
		row["device_id"] = refusal.DeviceID
	}
	// The service's own trail keeps what the wire body withholds: the subject
	// and serial the caller presented, recorded as presented rather than as
	// established. That is what makes the tier's authorization tests a grep,
	// and the two field names say which kind of fact each one is.
	if identity, ok := DeviceFrom(r.Context()); ok {
		if identity.DeviceID != "" {
			row["certificate_subject"] = identity.DeviceID
		}
		if identity.Serial != "" {
			row["certificate_serial"] = identity.Serial
		}
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
