package courseapp

// Tier 7 section 11 bypass runners.
//
// Fifteen rows, E-7-01 to E-7-15, decided in issue #142. Two of them are
// successes the board produces on the genuine path and the fixture takes no
// part in them. The other thirteen run here, and each one crafts the request
// the service is meant to refuse and reads the refusal it makes.
//
// They live under `./course service bypass`, a sibling of `./course service
// start`, and not under `./course provision bypass`. Tier 6's checks belong to
// a provisioning station on a bench and Tier 7's to a daemon on a network, and
// a Learner who typed `provision bypass` to test a mutual-TLS refusal would
// have been told the opposite of what this tier teaches. It also keeps Tier
// 6's published command strings frozen.
//
// Every runner asserts the `check` string and never the status. Every
// authorization refusal in this tier is 403, so the status is never the
// reason, and a runner that asserted 403 would pass on the wrong refusal.
//
// Every runner's output is a host result. A host result never stands in for a
// device result, and the witness column below says so for each row.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// The three values the Observed on column takes.
//
// Two would not have been enough. The four operator-listener checks are
// refusals delivered to the operator half and read on the host, while the
// board is what opens the window and prints the nonce, so a row can be
// witnessed on the host and still be impossible without hardware. The
// course-wide rule is untouched: a host result never stands in for a device
// result, and this label only records that a device made the result possible.
const (
	witnessHost   = "host"
	witnessDevice = "device"
	witnessBoth   = "host, board required"
)

// bypassRow is one row of the section 11 table, with the runner that earns it.
type bypassRow struct {
	id       string
	test     string
	expected string
	witness  string

	// forges says the row needs the Operational CA signing key. The module
	// labels these separately from the rows that need only what a real
	// outsider could plausibly hold, so a Learner can tell an insider failure
	// from an outsider attack.
	forges bool

	plan []string
	run  func(*tier07Adversary) error
}

func tier07Rows() []bypassRow {
	return []bypassRow{
		{
			id:       "e-7-01",
			test:     "Claim the board: BOOT hold, nonce, operator approval, Operational certificate stored",
			expected: "Succeeds",
			witness:  witnessDevice,
		},
		{
			id:       "e-7-02",
			test:     "Download an assignment and submit a status event on the Operational identity",
			expected: "Succeeds",
			witness:  witnessDevice,
		},
		{
			id:       "e-7-03",
			test:     "Factory certificate at the download endpoint",
			expected: "Refused at identity-operational",
			witness:  witnessHost,
			plan: []string{
				"Enrol a synthetic device through the real provisioning station.",
				"Present its genuine Factory certificate to GET /v1/releases/current.",
				"Read the refusal: a Factory identity says which board this is, not who owns it.",
			},
			run: (*tier07Adversary).rowFactoryAtDownload,
		},
		{
			id:       "e-7-04",
			test:     "Operational certificate at the claim endpoint",
			expected: "Refused at identity-factory",
			witness:  witnessHost,
			plan: []string{
				"Drive a complete claim for a synthetic device, both halves.",
				"Present the Operational certificate it earned to the claim endpoint.",
				"Read the refusal: a certificate is a role, not a ranking.",
			},
			run: (*tier07Adversary).rowOperationalAtClaim,
		},
		{
			id:       "e-7-05",
			test:     "Expired Operational certificate",
			expected: "Refused at certificate-active, clause 1",
			witness:  witnessHost,
			forges:   true,
			plan: []string{
				"Enrol a synthetic device.",
				"Forge an Operational certificate whose validity window has already closed.",
				"Present it, and read a refusal the device could not have made for itself.",
			},
			run: (*tier07Adversary).rowExpiredCertificate,
		},
		{
			id:       "e-7-06",
			test:     "Revoked Operational certificate",
			expected: "Refused at certificate-active, clause 2",
			witness:  witnessHost,
			plan: []string{
				"Drive a complete claim for a synthetic device.",
				"Mark the certificate it earned revoked with the lab control.",
				"Present the same certificate again and read the refusal.",
			},
			run: (*tier07Adversary).rowRevokedCertificate,
		},
		{
			id:       "e-7-07",
			test:     "Certificate signed by the Operational CA that the service never issued",
			expected: "Refused at certificate-active, clause 3",
			witness:  witnessHost,
			forges:   true,
			plan: []string{
				"Enrol a synthetic device.",
				"Forge a valid Operational certificate with a serial nobody issued.",
				"Read the refusal: a CA signature is not an authorization, the record is.",
			},
			run: (*tier07Adversary).rowUnissuedSerial,
		},
		{
			id:       "e-7-08",
			test:     "Forged certificate: a recorded serial, the CN of an unclaimed device",
			expected: "Refused at device-claimed",
			witness:  witnessHost,
			forges:   true,
			plan: []string{
				"Claim one synthetic device so the record holds a real serial.",
				"Enrol a second and leave it unclaimed.",
				"Forge a certificate joining the recorded serial to the unclaimed device's name.",
				"Read the refusal: the record binds a serial, and a serial is not a certificate.",
			},
			run: (*tier07Adversary).rowUnclaimedDevice,
		},
		{
			id:       "e-7-09",
			test:     "Status event whose body identifier disagrees with the path",
			expected: "Refused at identifier-consistent",
			witness:  witnessHost,
			plan: []string{
				"Drive a complete claim for a synthetic device.",
				"Submit a status event naming one device in the path and another in the body.",
				"Read the refusal: one request names one device.",
			},
			run: (*tier07Adversary).rowIdentifierMismatch,
		},
		{
			id:       "e-7-10",
			test:     "Forged certificate: the CN of a claimed device, the OU of the adversary owner",
			expected: "Refused at ownership-context",
			witness:  witnessBoth,
			forges:   true,
			plan: []string{
				"Find a device the record says somebody else has claimed. In an ordinary lab that is your own board.",
				"Forge an Operational certificate for it, carrying the adversary's owner scope.",
				"Read the refusal: the certificate says who owns it, the record decides.",
			},
			run: (*tier07Adversary).rowOwnershipContext,
		},
		{
			id:       "e-7-11",
			test:     "Replay a spent claim nonce",
			expected: "Refused at nonce-unspent",
			witness:  witnessBoth,
			plan: []string{
				"Drive a complete claim for a synthetic device, spending its nonce.",
				"Present the same nonce to the operator half a second time.",
				"Read the refusal, and note it arrives before anything asks who owns the device.",
			},
			run: (*tier07Adversary).rowReplayedNonce,
		},
		{
			id:       "e-7-12",
			test:     "Approve after the claim window has closed",
			expected: "Refused at claim-window-open",
			witness:  witnessBoth,
			plan: []string{
				"Open a claim window on a synthetic device.",
				"Spend the whole attempt budget on wrong nonces, which closes the window.",
				"Present the correct nonce to a window that is no longer there.",
			},
			run: (*tier07Adversary).rowClosedWindow,
		},
		{
			id:       "e-7-13",
			test:     "Wrong nonce inside an open window",
			expected: "Refused at nonce-match",
			witness:  witnessBoth,
			plan: []string{
				"Open a claim window on a synthetic device.",
				"Present a well-formed nonce that is not the one the window holds.",
				"Read the refusal, and the attempts it says are left.",
			},
			run: (*tier07Adversary).rowWrongNonce,
		},
		{
			id:       "e-7-14",
			test:     "The adversary approves the correct nonce on an already-claimed device",
			expected: "Refused at device-unowned",
			witness:  witnessBoth,
			plan: []string{
				"Claim a synthetic device, so it is owned.",
				"Open a second claim window on it, as a second press would.",
				"Approve with the correct nonce and read the refusal: ownership is first come.",
			},
			run: (*tier07Adversary).rowAlreadyOwned,
		},
		{
			id:       "e-7-15",
			test:     "Client certificate from a foreign issuer",
			expected: "The handshake closes. No status, no body, no check, nothing in events.jsonl",
			witness:  witnessHost,
			plan: []string{
				"Take the Untrusted CA's certificate, which means an authority nothing here trusts.",
				"Offer it to the device listener as a client certificate.",
				"Record the absence: count the service's trail before and after.",
			},
			run: (*tier07Adversary).rowForeignIssuer,
		},
	}
}

func lookupBypassRow(id string) (bypassRow, bool) {
	for _, row := range tier07Rows() {
		if row.id == id {
			return row, true
		}
	}
	return bypassRow{}, false
}

// ------------------------------------------------------------------
// The command
// ------------------------------------------------------------------

func (a *app) serviceBypass(args []string) error {
	if len(args) == 0 {
		return a.bypassList()
	}
	id := strings.ToLower(args[0])
	switch id {
	case "list":
		return a.bypassList()
	case "reset":
		return a.bypassReset()
	}
	row, ok := lookupBypassRow(id)
	if !ok {
		return fmt.Errorf("unknown bypass %q; run ./course service bypass list", args[0])
	}
	if row.run == nil {
		return fmt.Errorf("%s is a board row, not a host runner: %s. Run it on the device, following the module",
			strings.ToUpper(row.id), row.test)
	}
	executeID, err := flagValue(args[1:], "--execute")
	if err != nil {
		executeID = ""
	}
	return a.runBypassRow(row, executeID)
}

func (a *app) bypassList() error {
	block, ok := a.manifest.Bypass[tier07BypassKey]
	if !ok {
		return fmt.Errorf("course.yml has no bypass entry for %s", tier07BypassKey)
	}
	fmt.Fprintln(a.out, "Tier 7 section 11 rows. One adversary drives every host row: it holds a")
	fmt.Fprintln(a.out, "legitimate owner account, enrols synthetic devices through the real")
	fmt.Fprintln(a.out, "station, drives both halves of a real claim, and holds your Operational")
	fmt.Fprintln(a.out, "Device CA signing key.")
	fmt.Fprintln(a.out)
	fmt.Fprintf(a.out, "%-8s  %-20s  %-8s  %s\n", "Row", "Observed on", "CA key", "Test")
	for _, row := range tier07Rows() {
		key := ""
		if row.forges {
			key = "needed"
		}
		fmt.Fprintf(a.out, "%-8s  %-20s  %-8s  %s\n",
			strings.ToUpper(row.id), row.witness, key, row.test)
	}
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "A host result never stands in for a device result. \"host, board required\"")
	fmt.Fprintln(a.out, "means a board opened the claim window and printed the nonce, and the")
	fmt.Fprintln(a.out, "refusal was then read here. It never lets this command claim that a")
	fmt.Fprintln(a.out, "device refused anything.")
	fmt.Fprintf(a.out, "\nReset: %s\n", block.Reset)
	return nil
}

// runBypassRow is the wrapper every row goes through: the Tier 0 guarantees,
// then the row, then the evidence record.
//
// Dry run first, an exact row identifier to execute, a marker handshake over
// plain HTTP, manifest-owned inputs and a machine-readable evidence record.
// Tier 6's extraction command was exempted from the handshake because it had
// no target and opened no socket. Nothing in Tier 7 is in that position.
func (a *app) runBypassRow(row bypassRow, executeID string) error {
	adversary, err := a.newTier07Adversary(strings.ToUpper(row.id))
	if err != nil {
		return err
	}
	block := adversary.manifest

	if err := validateTarget(block.Target); err != nil {
		return err
	}
	if err := validateSelectedInterface(block.Target, block.Interface, true); err != nil {
		return err
	}
	// The marker handshake, over plain HTTP, before any side effect. It is
	// never fetched over either TLS port, and this is the tier where that rule
	// earns its keep: the adversary holds a CA key that would let a
	// mutual-TLS marker fetch succeed, and a check the adversary can satisfy
	// with its own forged credential is not a check.
	env, fingerprint, err := a.matchMarker(block.Target)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "Bypass: %s\nTarget: %s\nInterface: %s\n",
		strings.ToUpper(row.id), block.Target, block.Interface)
	fmt.Fprintf(a.out, "Marker matched: course_id=%s environment_id=%s tier=%s synthetic_data=%t\n",
		env.CourseID, env.EnvironmentID, env.Tier, env.SyntheticData)
	fmt.Fprintf(a.out, "Device listener: https://%s:%d, mutual TLS\n", adversary.serviceName(), block.DevicePort)
	fmt.Fprintf(a.out, "Operator listener: https://%s:%d, server authenticated\n", adversary.serviceName(), block.OperatorPort)
	fmt.Fprintf(a.out, "Test: %s\nExpected result: %s\nObserved on: %s\n", row.test, row.expected, row.witness)
	if row.forges {
		fmt.Fprintln(a.out, "Capability under test: a leaked Operational Device CA key. This row")
		fmt.Fprintln(a.out, "  is what an insider holding the authority's private half can make.")
	} else {
		fmt.Fprintln(a.out, "Capability under test: what an outsider on the network could plausibly hold.")
	}
	fmt.Fprintf(a.out, "Changes: %s\nReset: %s\n", strings.Join(block.Changes, ", "), block.Reset)
	if len(row.plan) > 0 {
		fmt.Fprintln(a.out, "Plan:")
		for i, line := range row.plan {
			fmt.Fprintf(a.out, "  %d. %s\n", i+1, line)
		}
	}
	if executeID == "" {
		fmt.Fprintln(a.out, "Result: dry run only")
		fmt.Fprintf(a.out, "Execute: ./course service bypass %s --execute %s\n", row.id, row.id)
		return nil
	}
	if strings.ToLower(executeID) != row.id {
		return errors.New("--execute value must exactly match the row identifier")
	}
	if err := a.requireLearnerService(); err != nil {
		return err
	}

	fmt.Fprintln(a.out)
	start := time.Now().UTC()
	runErr := row.run(adversary)
	result := "passed"
	if runErr != nil {
		result = "failed"
	}
	record := map[string]any{
		"schema_version":          1,
		"bypass_id":               row.id,
		"marker_fingerprint":      fingerprint,
		"target":                  block.Target,
		"selected_interface":      block.Interface,
		"started_at":              start,
		"ended_at":                time.Now().UTC(),
		"command":                 fmt.Sprintf("./course service bypass %s --execute %s", row.id, row.id),
		"test":                    row.test,
		"expected_effect":         row.expected,
		"observed_on":             row.witness,
		"operational_ca_key_used": row.forges,
		"result":                  result,
		// Reset is a separate command for this fixture, so the evidence says
		// what state the run left behind rather than claiming it was cleaned.
		"reset_command": block.Reset,
	}
	if runErr != nil {
		record["failure"] = runErr.Error()
	}
	evidencePath, evidenceErr := a.writeAttackEvidence(filepath.Join("tier-07", row.id), record)
	if evidenceErr != nil {
		return evidenceErr
	}
	fmt.Fprintf(a.out, "Evidence: %s\n", evidencePath)
	fmt.Fprintf(a.out, "Observed on: %s. This is a host result; a host result never stands in for a device result.\n",
		row.witness)
	return runErr
}

// requireLearnerService refuses to run against anything but the Learner's own
// service, started by the Learner, with mutual TLS on.
//
// The fixture never starts a service of its own. An ephemeral one per run
// would throw away the refusal trail in the service's own events.jsonl, and
// that trail is the lab artifact this tier produces. It also keeps the runner
// honest: it is a client, with no privileged access to the thing refusing it.
func (a *app) requireLearnerService() error {
	if _, running := a.runningService(); !running {
		return errors.New("no course service is running; start your own with ./course service start --https --mutual-tls")
	}
	if mode := a.serviceMode(); mode != "mutual-tls" {
		return fmt.Errorf("the running service is in %s mode; Tier 7's rows need mutual TLS. Stop it and run ./course service start --https --mutual-tls", mode)
	}
	return nil
}

// ------------------------------------------------------------------
// The thirteen host rows
// ------------------------------------------------------------------

// E-7-03. A Factory identity at an endpoint that serves owners.
func (x *tier07Adversary) rowFactoryAtDownload() error {
	device, err := x.ensureEnrolled("beacon-bypass-e7-03")
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the certificate is genuine, unexpired and signed by the Manufacturer")
	fmt.Fprintln(x.out(), "  Device CA. Nothing about it is forged. It is simply the wrong role.")
	result, err := x.asDevice(device.FactoryCertificate, device.FactoryKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "identity-operational")
}

// E-7-04. An Operational identity at the claim endpoint.
//
// Section 8's restriction runs both ways, and this is the half a ranking would
// have missed: the more privileged credential is refused here exactly as the
// less privileged one is refused at the download endpoint.
func (x *tier07Adversary) rowOperationalAtClaim() error {
	const deviceID = "beacon-bypass-e7-04"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return err
	}
	csr, err := x.freshRequest(deviceID)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the device now holds a valid Operational certificate, and offers it")
	fmt.Fprintln(x.out(), "  at the one endpoint that exists to hand out Operational certificates.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "identity-factory")
}

// E-7-05. A certificate whose validity window has already closed.
//
// The row the specification's success criteria never ask for, kept because it
// is the only place a Learner sees the consequence of the device's blindness
// to wall-clock time: the service refuses on its own clock, and the device
// could not have caught this for itself in any tier of this course.
func (x *tier07Adversary) rowExpiredCertificate() error {
	const deviceID = "beacon-bypass-e7-05"
	if _, err := x.ensureEnrolled(deviceID); err != nil {
		return err
	}
	owner, err := x.ensureOwner()
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	certificate, key, err := x.signWithOperationalCA(deviceID, owner, serial,
		now.Add(-coursepki.OperationalLifetime-24*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the window opened ninety-one days ago and closed yesterday. A device")
	fmt.Fprintln(x.out(), "  cannot read that: CONFIG_MBEDTLS_HAVE_TIME_DATE is off in every tier,")
	fmt.Fprintln(x.out(), "  and device time is evidence rather than an authorization input.")
	result, err := x.asDevice(certificate, keyPEM, http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return fmt.Errorf("the handshake refused this before any check could name it, which is the E-7-15 outcome and not this row: %w", err)
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-7-06. A certificate the service issued and then withdrew.
func (x *tier07Adversary) rowRevokedCertificate() error {
	const deviceID = "beacon-bypass-e7-06"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	if device.OperationalSerial == "" {
		return errors.New("the claim recorded no certificate serial, so there is nothing to revoke")
	}
	revoked, err := x.app.revokedSerials()
	if err != nil {
		return err
	}
	if !revoked[device.OperationalSerial] {
		fmt.Fprintln(x.out(), "  marking it revoked with the lab control, which writes the file the")
		fmt.Fprintln(x.out(), "  service reads live:")
		if err := x.app.claimRevoke([]string{"--serial", device.OperationalSerial}); err != nil {
			return err
		}
		x.state.RevokedSerials = append(x.state.RevokedSerials, device.OperationalSerial)
		if err := x.save(); err != nil {
			return err
		}
	}
	fmt.Fprintln(x.out(), "  the certificate is unexpired and correctly signed. Only the record changed.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-7-07. A certificate the Operational CA really signed, that the service
// never issued.
//
// This is the clause that is strictly stronger than the revocation list this
// course deliberately does not build: a list catches only what was explicitly
// withdrawn, and the record catches everything that was never issued.
func (x *tier07Adversary) rowUnissuedSerial() error {
	const deviceID = "beacon-bypass-e7-07"
	if _, err := x.ensureEnrolled(deviceID); err != nil {
		return err
	}
	owner, err := x.ensureOwner()
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	certificate, key, err := x.signWithOperationalCA(deviceID, owner, serial,
		now.Add(-time.Hour), now.Add(coursepki.OperationalLifetime))
	if err != nil {
		return err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  this certificate verifies against the trust anchor perfectly. It is")
	fmt.Fprintln(x.out(), "  unexpired, correctly signed, and names a device that really exists.")
	result, err := x.asDevice(certificate, keyPEM, http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-7-08. A recorded serial joined to the name of an unclaimed device.
//
// The row that makes device-claimed reachable. Clause 3 of certificate-active
// asks only that the serial appear in a claim record, not in this device's
// claim record, and issue #142 narrowed it by that one word precisely so this
// artifact exists. The tier's second lesson about serial joins: the record
// binds a serial, and a serial is not a certificate.
func (x *tier07Adversary) rowUnclaimedDevice() error {
	const donorID = "beacon-bypass-e7-08-donor"
	const unclaimedID = "beacon-bypass-e7-08"
	donor, _, err := x.claimSynthetic(donorID)
	if err != nil {
		return err
	}
	if donor.OperationalSerial == "" {
		return errors.New("the donor claim recorded no certificate serial")
	}
	if _, err := x.ensureEnrolled(unclaimedID); err != nil {
		return err
	}
	owner, err := x.ensureOwner()
	if err != nil {
		return err
	}
	serial, ok := new(big.Int).SetString(donor.OperationalSerial, 10)
	if !ok {
		return fmt.Errorf("the donor serial %q is not a decimal number", donor.OperationalSerial)
	}
	now := time.Now().UTC()
	certificate, key, err := x.signWithOperationalCA(unclaimedID, owner, serial,
		now.Add(-time.Hour), now.Add(coursepki.OperationalLifetime))
	if err != nil {
		return err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  serial %s belongs to %s, which really is claimed, so the serial really\n",
		donor.OperationalSerial, donorID)
	fmt.Fprintf(x.out(), "  is in a claim record and certificate-active is satisfied. The name on\n")
	fmt.Fprintf(x.out(), "  the certificate is %s, which is not.\n", unclaimedID)
	result, err := x.asDevice(certificate, keyPEM, http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "device-claimed")
}

// E-7-09. Two identifiers in one request that do not agree.
func (x *tier07Adversary) rowIdentifierMismatch() error {
	const deviceID = "beacon-bypass-e7-09"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	const impersonated = "beacon-bypass-e7-03"
	fmt.Fprintf(x.out(), "  the path names %s and the body names %s. In Tier 0 the service believed\n",
		deviceID, impersonated)
	fmt.Fprintln(x.out(), "  the body, because nothing else was on offer. Now the certificate decides.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/events", map[string]any{
			"device_id":      impersonated,
			"schema_version": 1,
			"event":          "status",
			"reason_code":    "normal",
		})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "identifier-consistent")
}

// E-7-10. A certificate whose owner scope disagrees with the record.
//
// Under first-come ownership the adversary can never obtain such a certificate
// honestly, so it is forged here or it does not exist. The device it targets
// has to be one somebody else claimed, and in an ordinary lab that is the
// Learner's own board: the refusal is read on the host, and a board is what
// makes the row possible.
func (x *tier07Adversary) rowOwnershipContext() error {
	owner, err := x.ensureOwner()
	if err != nil {
		return err
	}
	deviceID, holder, serialText, ok := x.app.claimedDeviceNotOwnedBy(owner)
	if !ok {
		return fmt.Errorf("no device in %s is claimed by an owner other than %s. Claim your board first, which is E-7-01; this row forges a certificate against somebody else's device and there is nobody else yet",
			x.app.relative(x.app.provisionRecordPath()), owner)
	}
	serial, ok := new(big.Int).SetString(serialText, 10)
	if !ok {
		return fmt.Errorf("the claim record for %s carries no usable certificate serial", deviceID)
	}
	now := time.Now().UTC()
	certificate, key, err := x.signWithOperationalCA(deviceID, owner, serial,
		now.Add(-time.Hour), now.Add(coursepki.OperationalLifetime))
	if err != nil {
		return err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  %s is claimed, and not by the adversary. The forged certificate names\n", deviceID)
	fmt.Fprintf(x.out(), "  the device correctly and carries owner scope %q in its subject.\n", owner)
	result, err := x.asDevice(certificate, keyPEM, http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	if strings.Contains(result.Reason, holder) {
		return fmt.Errorf("the refusal named the current owner %q; in a real fleet that maps a device to a customer", holder)
	}
	if err := x.expectRefusal(result, "ownership-context"); err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "Note what the reason does not say: it never names who does own the device.")
	return nil
}

// E-7-11. A nonce that was already spent on a successful claim.
//
// nonce-unspent runs before anything asks whether a window is open and before
// anything asks who owns the device. That order is load bearing: device-unowned
// first would make a replayed nonce refuse as already-owned and put a named
// success criterion out of the board's reach.
func (x *tier07Adversary) rowReplayedNonce() error {
	const deviceID = "beacon-bypass-e7-11"
	if _, ok := x.state.Devices[deviceID]; ok {
		// The spent nonce is held only for the length of the run that spent
		// it, so a rerun needs a device whose claim happens here.
		return errors.New("this row spends a nonce and cannot replay one it did not see; run ./course service bypass reset first")
	}
	_, nonce, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the same nonce is presented to the operator half a second time.")
	fmt.Fprintln(x.out(), "  The device is now owned, so two checks could refuse this. Watch which one does.")
	result, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "nonce-unspent")
}

// E-7-12. A window that is no longer open.
//
// The row says ten minutes and this runner closes the window with the attempt
// budget instead, which is a substitution the output states rather than hides.
// A runner may not move the service's clock: the fixture is a client with no
// privileged access to the thing refusing it, which is the rule that makes
// every other row here worth anything. Waiting ten real minutes inside a lab
// step is the other option and it teaches nothing the fourth wrong nonce does
// not. Both close the same window, and the refusal is the same refusal.
func (x *tier07Adversary) rowClosedWindow() error {
	const deviceID = "beacon-bypass-e7-12"
	nonce, err := x.openWindow(deviceID)
	if err != nil {
		return err
	}
	if _, err := x.ensureOwner(); err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  a window is open. It closes after ten minutes, or after four wrong")
	fmt.Fprintln(x.out(), "  nonces, and this runner spends the budget because it may not move the")
	fmt.Fprintln(x.out(), "  service's clock and will not hold a lab step for ten minutes.")
	fmt.Fprintln(x.out(), "  The backoff is real, so this takes about fourteen seconds.")
	for attempt := 1; attempt <= 4; attempt++ {
		wrong, err := newClaimNonce()
		if err != nil {
			return err
		}
		result, err := x.asOwner(http.MethodPost, "/v1/claim",
			map[string]any{"device_id": deviceID, "nonce": wrong})
		if err != nil {
			return err
		}
		if result.Check != "nonce-match" {
			return fmt.Errorf("wrong nonce %d refused at %q, expected nonce-match", attempt, result.Check)
		}
		fmt.Fprintf(x.out(), "    attempt %d: %s\n", attempt, result.Reason)
	}
	fmt.Fprintln(x.out(), "  the window is gone. Now the correct nonce is presented to it.")
	result, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "claim-window-open")
}

// E-7-13. A wrong nonce while the window is still open.
func (x *tier07Adversary) rowWrongNonce() error {
	const deviceID = "beacon-bypass-e7-13"
	if _, err := x.openWindow(deviceID); err != nil {
		return err
	}
	if _, err := x.ensureOwner(); err != nil {
		return err
	}
	wrong, err := newClaimNonce()
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  a well-formed nonce that is not the one the window holds. Nothing")
	fmt.Fprintln(x.out(), "  checks its shape on this half: a nonce that does not match simply does")
	fmt.Fprintln(x.out(), "  not match, and spends one of the four attempts.")
	result, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": wrong})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "nonce-match")
}

// E-7-14. A correct nonce on a device that already has an owner.
func (x *tier07Adversary) rowAlreadyOwned() error {
	const deviceID = "beacon-bypass-e7-14"
	if _, _, err := x.claimSynthetic(deviceID); err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the device is owned. A second press still opens a window, because the")
	fmt.Fprintln(x.out(), "  device does not know it is owned: the record does, and the record is")
	fmt.Fprintln(x.out(), "  what refuses.")
	nonce, err := x.openWindow(deviceID)
	if err != nil {
		return err
	}
	result, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "device-unowned")
}

// E-7-15. The row whose evidence is that there is no evidence.
//
// It may not report a refusal it did not see, and it may not invent a reason
// code for a layer that emits none. So it counts the service's trail before
// and after, and records the absence as an absence.
func (x *tier07Adversary) rowForeignIssuer() error {
	certificate, err := os.ReadFile(filepath.Join(x.app.pkiDir(), coursepki.UntrustedCert))
	if err != nil {
		return fmt.Errorf("no Untrusted CA material; run ./course setup first: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(x.app.pkiDir(), coursepki.UntrustedKey))
	if err != nil {
		return err
	}
	before, err := x.app.serviceTrailLines()
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the Untrusted CA means, in this course's vocabulary, an authority")
	fmt.Fprintln(x.out(), "  nothing here trusts. Tier 7 adds no fifth authority to say it again.")
	result, err := x.asDevice(string(certificate), string(key),
		http.MethodGet, "/v1/releases/current", nil)
	if err == nil {
		return fmt.Errorf("the handshake accepted a foreign issuer and answered %d: %v", result.Status, result.Body)
	}
	after, trailErr := x.app.serviceTrailLines()
	if trailErr != nil {
		return trailErr
	}
	fmt.Fprintf(x.out(), "  the connection closed: %v\n", err)
	fmt.Fprintln(x.out(), "  There is no status. There is no body. There is no check name, because")
	fmt.Fprintln(x.out(), "  the layer that refused has nowhere to put one.")
	fmt.Fprintf(x.out(), "  the service's trail held %d lines before and %d after\n", before, after)
	if after != before {
		return fmt.Errorf("a handshake failure left %d new lines in the service's trail; the row's whole claim is that it leaves none", after-before)
	}
	fmt.Fprintln(x.out(), "\nResult: E-7-15 closed the handshake and left nothing behind, as the tier requires")
	fmt.Fprintln(x.out(), "Compare this with E-7-05. Both refusals are correct. Only one of them")
	fmt.Fprintln(x.out(), "can tell the device what went wrong.")
	return nil
}

// openWindow runs the device half alone, which is what a button press
// followed by one submission does.
func (x *tier07Adversary) openWindow(deviceID string) (string, error) {
	device, err := x.ensureEnrolled(deviceID)
	if err != nil {
		return "", err
	}
	csr, err := x.freshRequest(deviceID)
	if err != nil {
		return "", err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return "", err
	}
	result, err := x.asDevice(device.FactoryCertificate, device.FactoryKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/claim",
		map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		return "", err
	}
	if result.refused() {
		return "", fmt.Errorf("opening a claim window on %s was refused at %s: %s",
			deviceID, result.Check, result.Reason)
	}
	if answer, _ := result.Body["result"].(string); answer != "pending" {
		return "", fmt.Errorf("opening a claim window on %s answered %q, expected pending", deviceID, answer)
	}
	fmt.Fprintf(x.out(), "  a claim window is open on %s\n", deviceID)
	return nonce, nil
}

// freshRequest builds a throwaway Operational certification request. The key
// it proves possession of is discarded: these rows never collect a
// certificate, and a key nobody keeps is one fewer secret in fixture state.
func (x *tier07Adversary) freshRequest(deviceID string) (string, error) {
	key, err := newHostDevice()
	if err != nil {
		return "", err
	}
	return operationalRequest(deviceID, key.key)
}

// serviceTrailLines counts the service's own events.jsonl, which is what
// E-7-15 measures the absence against.
func (a *app) serviceTrailLines() (int, error) {
	raw, err := os.ReadFile(filepath.Join(a.root, a.manifest.Paths.State, "ota", "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return 0, nil
	}
	return len(strings.Split(trimmed, "\n")), nil
}

// ------------------------------------------------------------------
// Reset
// ------------------------------------------------------------------

// bypassReset clears live authorization state and rewinds no history.
//
// The distinction is the lesson and it fits in one sentence: a record of what
// happened is never rewound, and a store that decides what happens next is.
//
// So the synthetic devices stay in the manufacturing record forever, and every
// line the service wrote to its own events.jsonl stays too. What goes is the
// adversary owner's account, which would otherwise be a live credential after
// the lab is over, and the serials this fixture marked revoked, which would
// otherwise change how the service answers a later honest request.
//
// It is a separate command rather than something every row runs at the end.
// Thirteen rows sharing one adversary is the tier's shape, and a reset between
// them would re-mint the owner thirteen times, leaving twelve superseded
// entries in a store the Learner is asked to read.
func (a *app) bypassReset() error {
	block, ok := a.manifest.Bypass[tier07BypassKey]
	if !ok {
		return fmt.Errorf("course.yml has no bypass entry for %s", tier07BypassKey)
	}
	state, err := a.readAdversaryState()
	if err != nil {
		return err
	}
	owner := block.AdversaryOwner

	fmt.Fprintln(a.out, "Resetting the Tier 7 adversary. This is append only wherever it can be.")

	removedOwner, err := a.removeOwnerEntries(owner)
	if err != nil {
		return err
	}
	removedSerials, err := a.removeRevokedSerials(state.RevokedSerials)
	if err != nil {
		return err
	}

	devices := make([]string, 0, len(state.Devices))
	for id := range state.Devices {
		devices = append(devices, id)
	}
	sort.Strings(devices)

	detail := fmt.Sprintf(
		"tier-07 service bypass reset: removed %d owner entry for %s and %d revoked serial(s). The synthetic devices %s stay in this record, because a store that can be edited to tidy up after a fixture is no longer the append-only store the station's claim depends on.",
		removedOwner, owner, removedSerials, strings.Join(devices, ", "))
	if len(devices) == 0 {
		detail = fmt.Sprintf(
			"tier-07 service bypass reset: removed %d owner entry for %s and %d revoked serial(s). No synthetic devices had been enrolled.",
			removedOwner, owner, removedSerials)
	}
	if err := a.writeRecord(provisionRecord{
		Kind:   recordFixtureReset,
		Result: "reset",
		Detail: detail,
	}); err != nil {
		return err
	}

	if err := os.RemoveAll(a.bypassStateDir()); err != nil {
		return err
	}

	fmt.Fprintf(a.out, "  removed:  %d owner entry for %s from %s\n",
		removedOwner, owner, a.relative(a.ownerStorePath()))
	fmt.Fprintf(a.out, "  removed:  %d serial(s) this fixture marked revoked from %s\n",
		removedSerials, a.relative(a.revokedPath()))
	fmt.Fprintf(a.out, "  removed:  the fixture's own state under %s\n", a.relative(a.bypassStateDir()))
	fmt.Fprintf(a.out, "  appended: one fixture_reset line to %s\n", a.relative(a.provisionRecordPath()))
	fmt.Fprintln(a.out, "  kept:     every synthetic device in the manufacturing record")
	fmt.Fprintln(a.out, "  kept:     every line the service wrote to its own events.jsonl")
	fmt.Fprintln(a.out, "  kept:     your own owner, your own claims, and any serial you marked yourself")
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "A record of what happened is never rewound. A store that decides what")
	fmt.Fprintln(a.out, "happens next is. That is the whole difference between the two lists above.")
	fmt.Fprintf(a.out, "Result: the Tier 7 adversary holds no live authorization state\n")
	return nil
}

// removeOwnerEntries rewrites the owner store without one owner.
//
// The store is append only in ordinary use and ownerList says so. This is the
// one exception the fixture safety contract writes down, and it is bounded to
// the single manifest-named adversary slug: it may not remove the Learner's
// own owner, and it cannot, because the slug comes from course.yml.
func (a *app) removeOwnerEntries(owner string) (int, error) {
	if owner == "" {
		return 0, nil
	}
	records, err := a.readOwnerRecords()
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		return 0, nil
	}
	kept := make([]ownerRecord, 0, len(records))
	removed := 0
	for _, record := range records {
		if record.OwnerID == owner {
			removed++
			continue
		}
		kept = append(kept, record)
	}
	if removed == 0 {
		return 0, nil
	}
	var lines strings.Builder
	for _, record := range kept {
		line, err := json.Marshal(record)
		if err != nil {
			return 0, err
		}
		lines.Write(line)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(a.ownerStorePath(), []byte(lines.String()), 0o600); err != nil {
		return 0, err
	}
	return removed, nil
}

// removeRevokedSerials rewrites the revoked-serial store without the serials
// this fixture marked, and touches no serial it did not.
func (a *app) removeRevokedSerials(serials []string) (int, error) {
	if len(serials) == 0 {
		return 0, nil
	}
	mine := map[string]bool{}
	for _, serial := range serials {
		mine[serial] = true
	}
	raw, err := os.ReadFile(a.revokedPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var lines strings.Builder
	removed := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record revocationRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return 0, fmt.Errorf("revocation file is corrupt: %w", err)
		}
		if mine[record.CertSerial] {
			removed++
			continue
		}
		lines.WriteString(line)
		lines.WriteByte('\n')
	}
	if removed == 0 {
		return 0, nil
	}
	if err := os.WriteFile(a.revokedPath(), []byte(lines.String()), 0o600); err != nil {
		return 0, err
	}
	return removed, nil
}
