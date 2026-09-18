package ota

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Tier 7 does not add authorization to the service's one listener. It splits
// the listener, because the TLS handshake precedes routing.
//
// tls.RequireAndVerifyClientCert is decided once, for a whole socket, before a
// single byte of HTTP is read, so no route on that socket can be exempted from
// it. Three of the routes the Tier 0 service serves on one listener are
// reached only by the host CLI, which will never hold a device certificate, so
// the route matrix is not a free design: the handshake sorts the routes first,
// and only then does a handler get an opinion. That is the coarsest
// authorization decision this service makes, and it is made before the request
// exists.
//
// Handler, PublicHandler and DataHandler above are untouched. They are the
// Tier 0 and Tier 2 services, they keep serving Tiers 0 to 6 exactly as they
// do today, and the --mutual-tls flag chooses which pair of constructors the
// binary mounts.

// identifierSources says what a route carries that the certificate subject can
// be compared against.
//
// identifier-consistent runs on two routes only, and that is not a weakening.
// It compares identifiers, and only /v1/devices/{device_id}/... carries one
// outside the certificate. The four Operational GETs have no device identifier
// in the path — {release_id} and {name} are not one — and no body at all, so
// there is nothing there to disagree with the certificate: the certificate is
// the identity, unaided.
type identifierSources int

const (
	identifierNone identifierSources = iota
	identifierPath
	identifierPathAndBody
)

// deviceRoute is one row of the device listener's authorization matrix.
type deviceRoute struct {
	pattern string

	// role is the one certificate role this route accepts. Every other role is
	// refused at identity-operational or identity-factory, which are a pair on
	// purpose: a certificate is a role, not a ranking, so the more privileged
	// credential is refused at the claim endpoint exactly as the less
	// privileged one is refused at the download endpoint.
	role string

	identifiers identifierSources

	// record says whether device-claimed and ownership-context run. They
	// deliberately do not run on the claim route: that route exists to create
	// the claim, and a Factory certificate carries no owner scope to check
	// against.
	record bool

	handler http.Handler
}

// deviceRoutes is the six routes a device reaches, with the checks each one
// runs, in the order it runs them: cheapest and most certificate-local first,
// which is also the disclosure order. An unclaimed device presenting its
// Factory certificate is told about its role and never learns its ownership
// state.
//
// Both manifest routes are Operational because an image download is about the
// download, not about the byte range: a manifest a device may not be assigned
// is an assignment it may not have. Refusing the image while serving the
// manifest that describes it would be a boundary drawn at the wrong noun.
func (s *Server) deviceRoutes() []deviceRoute {
	return []deviceRoute{
		{"GET /v1/releases/current", RoleOperational, identifierNone, true,
			http.HandlerFunc(s.currentRelease)},
		{"GET /v1/releases/{release_id}/manifest", RoleOperational, identifierNone, true,
			http.HandlerFunc(s.releaseManifest)},
		{"GET /v1/releases/{release_id}/manifest.sig", RoleOperational, identifierNone, true,
			http.HandlerFunc(s.releaseManifestSignature)},
		{"GET /v1/firmware/{name}", RoleOperational, identifierNone, true,
			http.HandlerFunc(s.firmware)},
		{"POST /v1/devices/{device_id}/events", RoleOperational, identifierPathAndBody, true,
			http.HandlerFunc(s.deviceEvent)},
		{"POST /v1/devices/{device_id}/claim", RoleFactory, identifierPath, false,
			s.claimHandler(s.cfg.Claim.Device, "the device half of the claim exchange")},
	}
}

// operatorRoutes is what a person reaches, on a listener that authenticates
// the server and not the client.
//
// The lab controls authorize a lab, not a person and not a device, so they
// keep the Course environment marker check they have always had and do not
// take the Owner credential. Bolting a person's credential onto a lab reset
// would teach that authorization is a quantity rather than a question about
// who is asking.
//
// GET /v1/releases/current is served here as well as on the device listener,
// because the host CLI reads back the assignment it just wrote and a PUT whose
// result cannot be read is not a usable control. It is one route answering two
// different questions — what am I assigned, from the device; what did I just
// set, from the lab bench — and the two listeners keep those questions apart.
func (s *Server) operatorRoutes() []deviceRoute {
	return []deviceRoute{
		{pattern: "GET /v1/releases/current", handler: http.HandlerFunc(s.currentRelease)},
		{pattern: "PUT /v1/releases/current", handler: http.HandlerFunc(s.updateRelease)},
		{pattern: "POST /v1/lab/seed", handler: http.HandlerFunc(s.seed)},
		{pattern: "POST /v1/lab/reset", handler: http.HandlerFunc(s.reset)},
		{pattern: "POST /v1/claim", handler: s.requireOwner(
			s.claimHandler(s.cfg.Claim.Operator, "the operator half of the claim exchange"))},
	}
}

// DeviceHandler serves the six device routes behind mutual TLS. Every refusal
// it makes is 403 carrying a check name, because settled input 7 kept role,
// ownership, record and body checks in the handler: only a genuinely foreign
// issuer fails at the handshake, where there is nothing to carry a check.
func (s *Server) DeviceHandler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range s.deviceRoutes() {
		mux.Handle(route.pattern, s.authorizeDevice(route))
	}
	return courseHeaders(mux)
}

// OperatorHandler serves the claim approval and the lab controls.
func (s *Server) OperatorHandler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range s.operatorRoutes() {
		mux.Handle(route.pattern, route.handler)
	}
	return courseHeaders(mux)
}

// SplitPublicHandler is PublicHandler for a service running with mutual TLS:
// the same two endpoints in the clear, and a refusal on every moved route that
// says which of the two TLS listeners now serves it.
//
// PublicHandler itself is not touched. The Tier 2 module quotes its refusal
// body verbatim, down to the port in moved_to, and with --mutual-tls off every
// byte this service emits is what it emits today.
func (s *Server) SplitPublicHandler(devicePort, operatorPort int, serviceName string) http.Handler {
	mux := http.NewServeMux()
	s.routePublic(mux)

	// One route is registered on both TLS listeners on purpose, and the plain
	// listener may register it only once, so the answer names both places
	// rather than picking one and being half true.
	type destination struct {
		port int
		also int
		who  string
	}
	moved := map[string]*destination{}
	var patterns []string
	add := func(pattern string, port int, who string) {
		if seen, ok := moved[pattern]; ok {
			seen.also = port
			seen.who += ", and " + who
			return
		}
		moved[pattern] = &destination{port: port, who: who}
		patterns = append(patterns, pattern)
	}
	for _, route := range s.deviceRoutes() {
		add(route.pattern, devicePort, "a device holding a client certificate")
	}
	for _, route := range s.operatorRoutes() {
		add(route.pattern, operatorPort, "an operator on the lab bench")
	}

	for _, pattern := range patterns {
		where := moved[pattern]
		mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
			answer := map[string]any{
				"error":          "this endpoint is no longer served over plain HTTP",
				"moved_to":       fmt.Sprintf("https://%s:%d", serviceName, where.port),
				"why":            "Tier 7 split the authenticated listener in two, because the TLS handshake decides who may connect before any route is matched",
				"who_may_ask":    where.who,
				"still_here":     []string{"/health", "/.well-known/course-environment"},
				"why_still_here": "the Course environment marker is a fail-closed targeting check, not a credential, and it must not depend on the control it is used to test",
			}
			if where.also != 0 {
				answer["also_on"] = fmt.Sprintf("https://%s:%d", serviceName, where.also)
			}
			writeJSON(w, http.StatusNotFound, answer)
		})
	}
	return courseHeaders(mux)
}

// authorizeDevice runs one route's checks and then, if none refused, the
// route's handler.
func (s *Server) authorizeDevice(route deviceRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutual := s.cfg.MutualTLS
		if mutual == nil {
			http.Error(w, "the device listener needs mutual TLS material", http.StatusInternalServerError)
			return
		}
		identity, ok := mutual.identityFrom(r)
		if !ok {
			// Unreachable through the real listener, which verifies against a
			// pool holding exactly the two device authorities. It is a
			// misconfiguration rather than a refusal, so it does not get a
			// check name it could be confused with.
			http.Error(w, "no verified client certificate on this connection",
				http.StatusInternalServerError)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), deviceContextKey, identity))

		// No device_id on this refusal, or on certificate-active's. Until
		// certificate-active has passed, the subject common name is only what
		// the presented certificate says about itself, and a refusal that
		// repeated it would assert the identity it is refusing.
		if identity.Role != route.role {
			s.Refuse(w, r, http.StatusForbidden, Refusal{
				Check: roleCheckFor(route.role),
				Reason: fmt.Sprintf("this endpoint accepts only %s, and the certificate presented is %s",
					roleText(route.role), roleText(identity.Role)),
			})
			return
		}

		state := s.provisioningState()
		if refusal := s.certificateActive(identity, state); refusal != nil {
			s.Refuse(w, r, http.StatusForbidden, *refusal)
			return
		}

		if route.identifiers != identifierNone {
			next, refusal := identifierConsistent(r, route, identity)
			if refusal != nil {
				s.Refuse(w, r, http.StatusForbidden, *refusal)
				return
			}
			r = next
		}

		if route.record {
			claim, claimed := state.devices[identity.DeviceID]
			if !claimed {
				s.Refuse(w, r, http.StatusForbidden, Refusal{
					Check:    CheckDeviceClaimed,
					Reason:   "this device carries no claim on record, and an unclaimed device is served nothing",
					DeviceID: identity.DeviceID,
				})
				return
			}
			if identity.OwnerScope != claim.owner {
				s.Refuse(w, r, http.StatusForbidden, Refusal{
					Check: CheckOwnershipContext,
					Reason: fmt.Sprintf("the owner scope %q in the certificate presented is not this device's current ownership context",
						identity.OwnerScope),
					DeviceID: identity.DeviceID,
				})
				return
			}
		}

		route.handler.ServeHTTP(w, r)
	})
}

// certificateActive has three clauses, and the third is the one worth arguing.
//
//  1. the certificate is not expired, by service clock. The device cannot
//     evaluate a validity window at all, which is exactly what makes a short
//     lifetime enforceable here rather than decorative.
//  2. its serial is not marked revoked.
//  3. its serial appears in a claim record. This refuses a certificate
//     genuinely signed by the Operational CA that the service has no record of
//     issuing: a CA signature is not an authorization, the record is. It is
//     strictly stronger than the CRL this course deliberately does not build,
//     because a CRL catches only what was explicitly withdrawn while the
//     record catches everything never issued.
//
// Clause 3 asks about Operational certificates only. A Factory certificate
// arriving at the claim endpoint is by definition asking to be given its first
// claim record, so requiring one of it would close the only door into the
// tier.
func (s *Server) certificateActive(identity DeviceIdentity, state provisioningState) *Refusal {
	now := s.cfg.MutualTLS.now()
	if now.After(identity.NotAfter) {
		return &Refusal{
			Check: CheckCertificateActive,
			Reason: fmt.Sprintf("the certificate presented expired at %s by service clock",
				identity.NotAfter.UTC().Format(time.RFC3339)),
		}
	}
	if now.Before(identity.NotBefore) {
		return &Refusal{
			Check: CheckCertificateActive,
			Reason: fmt.Sprintf("the certificate presented is not valid until %s by service clock",
				identity.NotBefore.UTC().Format(time.RFC3339)),
		}
	}
	if s.revokedSerials()[identity.Serial] {
		return &Refusal{
			Check:  CheckCertificateActive,
			Reason: fmt.Sprintf("certificate serial %s is marked revoked", identity.Serial),
		}
	}
	if identity.Role == RoleOperational && !state.serials[identity.Serial] {
		return &Refusal{
			Check:  CheckCertificateActive,
			Reason: fmt.Sprintf("the service has no record of issuing certificate serial %s", identity.Serial),
		}
	}
	return nil
}

// identifierConsistent compares every identifier the request carries against
// the certificate subject.
//
// The body is read here rather than in the handler so that the checks run in
// the published order, and it is put back unchanged so the handler still reads
// its own request. A body that is not JSON, or that carries no identifier at
// all, is passed through to the handler, which is the one place that answers
// 400: malformed JSON is not an authorization decision and must not borrow an
// authorization check's name.
func identifierConsistent(r *http.Request, route deviceRoute, identity DeviceIdentity) (*http.Request, *Refusal) {
	if pathID := r.PathValue("device_id"); pathID != "" && pathID != identity.DeviceID {
		return r, &Refusal{
			Check: CheckIdentifierConsistent,
			Reason: fmt.Sprintf("the certificate presented names %s and the path names %s; one request names one device",
				identity.DeviceID, pathID),
			DeviceID: identity.DeviceID,
		}
	}
	if route.identifiers != identifierPathAndBody || r.Body == nil {
		return r, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return r, nil
	}
	var fields struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(body, &fields); err != nil || fields.DeviceID == "" {
		return r, nil
	}
	if fields.DeviceID != identity.DeviceID {
		return r, &Refusal{
			Check: CheckIdentifierConsistent,
			Reason: fmt.Sprintf("the certificate presented names %s and the body names %s; one request names one device",
				identity.DeviceID, fields.DeviceID),
			DeviceID: identity.DeviceID,
		}
	}
	return r, nil
}

// requireOwner is the operator listener's half of the seam: it verifies the
// bearer credential and puts the owner it belongs to in the request context.
// Issue #146 supplies the verifier; nothing here knows what an owners file
// looks like.
func (s *Server) requireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.OwnerCredentials == nil {
			http.Error(w, "the Owner credential store is not built yet", http.StatusServiceUnavailable)
			return
		}
		credential := bearerCredential(r)
		owner, refusal := s.cfg.OwnerCredentials.VerifyOwner(credential)
		if refusal != nil {
			// 401, and only here. Not knowing who is asking is a different
			// answer from knowing and refusing, and the tier's other twelve
			// checks are all the second kind.
			s.Refuse(w, r, http.StatusUnauthorized, *refusal)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ownerContextKey, owner)))
	})
}

// bearerCredential reads the credential out of the Authorization header. It is
// never read from the body, so the secret cannot land in a request log that
// records bodies.
func bearerCredential(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return ""
	}
	return value[len(prefix):]
}

// claimHandler mounts one half of the claim exchange, or says plainly that it
// is not built yet. A route that exists and is unbuilt is a different fact
// from a route that does not exist, and a Learner meeting a 404 here would go
// looking for a typo.
func (s *Server) claimHandler(handler http.Handler, what string) http.Handler {
	if handler != nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, what+" is not built yet", http.StatusServiceUnavailable)
	})
}

func roleCheckFor(role string) string {
	if role == RoleFactory {
		return CheckIdentityFactory
	}
	return CheckIdentityOperational
}

func roleText(role string) string {
	switch role {
	case RoleFactory:
		return "a Factory identity signed by the Manufacturer Device CA"
	case RoleOperational:
		return "an Operational identity signed by the Operational Device CA"
	default:
		return "an identity from an authority this listener does not know"
	}
}
