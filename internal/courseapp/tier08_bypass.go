package courseapp

// Tier 8 bypass runners.
//
// Ten host rows, E-8-01 to E-8-10, from issue #257. Each one withdraws an
// authority through a real Tier 8 operation, or reaches for a universal
// secret, and then shows that the credential it left behind no longer works.
// Each row reads the check that refused it, off the wire from the Learner's
// own service, or from the real station in process for the one station row.
//
// The actor is the Tier 7 adversary, one tier on. It holds the same single
// owner account, keeps its keys in the same fixture state, and runs under the
// same wrapper: dry run first, the exact row to execute, the marker handshake
// over plain HTTP, manifest-owned inputs and an evidence record. What changes
// is what it does with that account. In Tier 7 it tried to take what was not
// its own. In Tier 8 it is the owner of its own synthetic devices, it
// withdraws their authority, and it shows that a copy of the old credential
// is refused. That is SC-08: a credential stops authorizing a device when the
// authority behind it is withdrawn.
//
// No row signs anything with the Operational CA key. Every certificate a row
// presents was issued by the service or the station on the genuine path.
//
// Every runner's output is a host result. A host result never stands in for a
// device result. The Time floor is a device-side control. The one row about
// it, E-8-11, runs the firmware's own floor code in a native_sim build on the
// host (tier08_time_floor.go), and it too claims nothing about a board.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
	"github.com/tkEmLogic/learning-cyber-security/internal/lifecycle"
)

// tier08BypassKey is the manifest block the Tier 8 rows read their inputs
// from.
const tier08BypassKey = "tier-08"

// Two identifiers on one synthetic board, for E-8-10. The suffix is a
// locally administered MAC (the 02 prefix), so no real board can carry it,
// and boardOf keys both names to the same hardware.
const (
	tier08OldBoardID = "beacon-bypass-e8-10-02000000e810"
	tier08NewBoardID = "beacon-bypass-e8-10b-02000000e810"
)

// What the Tier 8 adversary holds, for the Capability line. None of these
// is the Operational CA key.
const (
	holdsOwnerAccount   = "the owner account of its own synthetic devices, and a copy of the credential it later withdraws."
	holdsOwnerAndKey    = "the owner account of its own synthetic devices, and each device's current Operational key."
	holdsSharedIdentity = "Tier 6's shared-image identity, which anyone who has the shared image holds."
	holdsManufacturer   = "the manufacturer's station, and a copy of the credential the manufacturer later withdraws."
	holdsReleaseKey     = "a release signing key. Here it is a throwaway one, made for this run and trusted only by a host build, never your Release signing key."
)

func tier08Rows() []bypassRow {
	return []bypassRow{
		{
			id:       "e-8-01",
			test:     "Recovery with the Owner credential alone, and no press",
			expected: "Refused at claim-window-open",
			witness:  witnessHost,
			holds:    holdsOwnerAndKey,
			plan: []string{
				"Claim a synthetic device as the adversary owner.",
				"Authorize its recovery on the operator listener, as the owner of record may.",
				"Approve a recovery claim without a device half: a remote \"recover my device\".",
				"Read the refusal: the authorization is live, and there is still no window to spend it on.",
			},
			run: (*tier07Adversary).rowRecoverWithoutPress,
		},
		{
			id:       "e-8-02",
			test:     "Tier 6's shared-image identity as the device half of a recovery",
			expected: "Refused at identifier-consistent",
			witness:  witnessHost,
			holds:    holdsSharedIdentity,
			plan: []string{
				"Claim a synthetic device and authorize its recovery.",
				"Present the shared development identity at that device's claim endpoint.",
				"Read the refusal: the universal secret is a real Factory identity, and it names one device that is not this one.",
			},
			run: (*tier07Adversary).rowSharedIdentityRecovery,
		},
		{
			id:       "e-8-03",
			test:     "Renewal onto the key that is already certified",
			expected: "Refused at key-unused",
			witness:  witnessHost,
			holds:    holdsOwnerAndKey,
			plan: []string{
				"Claim a synthetic device.",
				"Ask for its renewal as the owner, so renewal is due now.",
				"Renew with a certification request over the key the device already holds.",
				"Read the refusal: a renewal that keeps the key renews nothing.",
			},
			run: (*tier07Adversary).rowRenewSameKey,
		},
		{
			id:       "e-8-04",
			test:     "Renewal that nobody asked for, early in the certificate's life",
			expected: "Refused at renewal-due",
			witness:  witnessHost,
			holds:    holdsOwnerAndKey,
			plan: []string{
				"Claim a synthetic device. Its certificate has almost all of its life left.",
				"Renew with a fresh key, with no request from the owner.",
				"Read the refusal: the service decides when renewal is due, not the device.",
			},
			run: (*tier07Adversary).rowUnsolicitedRenewal,
		},
		{
			id:       "e-8-05",
			test:     "Operational certificate the owner revoked",
			expected: "Refused at certificate-active, clause 2",
			witness:  witnessHost,
			holds:    holdsOwnerAccount,
			plan: []string{
				"Claim a synthetic device.",
				"Revoke its certificate on the operator listener, as its owner.",
				"Present the same certificate again and read the refusal.",
			},
			run: (*tier07Adversary).rowOwnerRevokedCertificate,
		},
		{
			id:       "e-8-06",
			test:     "Factory certificate the manufacturer blocked, at the claim endpoint",
			expected: "Refused at certificate-active, clause 2",
			witness:  witnessHost,
			holds:    holdsManufacturer,
			plan: []string{
				"Enrol a synthetic device through the real station.",
				"Block its Factory serial from the station, as the manufacturer.",
				"Open a claim window with that Factory certificate and read the refusal.",
			},
			run: (*tier07Adversary).rowBlockedFactorySerial,
		},
		{
			id:       "e-8-07",
			test:     "Revoked device presenting its own unrevoked certificate",
			expected: "Refused at device-unrevoked",
			witness:  witnessHost,
			holds:    holdsOwnerAccount,
			plan: []string{
				"Claim a synthetic device.",
				"Revoke the device, not the certificate, as its owner.",
				"Present the certificate, which is not revoked, and read the refusal.",
			},
			run: (*tier07Adversary).rowRevokedDevice,
		},
		{
			id:       "e-8-08",
			test:     "Transferred device presenting its old certificate before a new claim",
			expected: "Refused at certificate-active, clause 2",
			witness:  witnessHost,
			holds:    holdsOwnerAccount,
			plan: []string{
				"Claim a synthetic device.",
				"Give it up with an Ownership transfer, as its owner.",
				"Present the old certificate before anyone claims the device again.",
			},
			run: (*tier07Adversary).rowTransferredDevice,
		},
		{
			id:       "e-8-09",
			test:     "Decommissioned board presenting its own certificate",
			expected: "Refused at device-in-service",
			witness:  witnessHost,
			holds:    holdsManufacturer,
			plan: []string{
				"Claim a synthetic device.",
				"Decommission its board at the station, as the manufacturer.",
				"Present its certificate, which no one revoked, and read the refusal.",
			},
			run: (*tier07Adversary).rowDecommissionedAtService,
		},
		{
			id:       "e-8-10",
			test:     "Decommissioned board enrolling again under a new identifier",
			expected: "Refused at hardware-in-service",
			witness:  witnessHost,
			holds:    holdsManufacturer,
			plan: []string{
				"Enrol a synthetic board and decommission it.",
				"Enrol the same board under a new identifier, with a new Bootstrap credential.",
				"Read the station's refusal: the board is the unit, not the name.",
			},
			run: (*tier07Adversary).rowDecommissionedAtStation,
		},
		{
			id:       "e-8-11",
			test:     "A release dated far in the future ends the device's own Operational certificate",
			expected: "Refused by the Time floor, on the host",
			witness:  witnessHost,
			holds:    holdsReleaseKey,
			plan: []string{
				"Generate a throwaway release key, two synthetic 90-day Operational certificates, and two manifests: one dated twenty years ahead, and one dated now.",
				"Build the Tier 8 firmware's own time_floor.c, release_policy.c and recovery_state.c for native_sim, with the throwaway public key compiled in.",
				"First boot: the far-future manifest under a key the build does not trust moves nothing; the same manifest under the release key raises the Time floor past the certificate's valid_to, and the certificate stops being presented.",
				"Second boot, on the same simulated flash: the floor is read back, a fresh certificate is refused at once, and an ordinary manifest cannot lower it.",
			},
			local: (*app).rowTimeFloorFarFuture,
		},
	}
}

// newTier08Adversary is the Tier 7 adversary reading the Tier 8 block.
//
// It keeps the Tier 7 fixture state, because it is the same actor: one owner
// account and one set of keys. A second state file would hold a second copy
// of the owner credential, and the two copies would supersede each other in
// the owner store every time the Learner moved between tiers.
func (a *app) newTier08Adversary(row string) (*tier07Adversary, error) {
	block, ok := a.manifest.Bypass[tier08BypassKey]
	if !ok {
		return nil, fmt.Errorf("course.yml has no bypass entry for %s", tier08BypassKey)
	}
	if tier07, ok := a.manifest.Bypass[tier07BypassKey]; ok && tier07.AdversaryOwner != block.AdversaryOwner {
		return nil, fmt.Errorf("course.yml names %q as the Tier 8 adversary owner and %q as the Tier 7 one; the fixture has exactly one adversary owner",
			block.AdversaryOwner, tier07.AdversaryOwner)
	}
	if block.AdversaryOwner == "" {
		return nil, errors.New("course.yml names no adversary owner for the Tier 8 bypass")
	}
	state, err := a.readAdversaryState()
	if err != nil {
		return nil, err
	}
	return &tier07Adversary{app: a, manifest: block, state: state, row: row}, nil
}

func (a *app) bypassListTier08() error {
	block, ok := a.manifest.Bypass[tier08BypassKey]
	if !ok {
		return fmt.Errorf("course.yml has no bypass entry for %s", tier08BypassKey)
	}
	fmt.Fprintln(a.out, "Tier 8 rows. The Tier 7 adversary drives E-8-01 to E-8-10. Here it is the")
	fmt.Fprintln(a.out, "owner, or the manufacturer, of its own synthetic devices. It withdraws an")
	fmt.Fprintln(a.out, "authority and then shows that the credential it kept is refused. No row")
	fmt.Fprintln(a.out, "signs anything with your Operational Device CA key or your Release signing key.")
	fmt.Fprintln(a.out)
	fmt.Fprintf(a.out, "%-8s  %-12s  %-40s  %s\n", "Row", "Observed on", "Expected result", "Test")
	for _, row := range tier08Rows() {
		fmt.Fprintf(a.out, "%-8s  %-12s  %-40s  %s\n",
			strings.ToUpper(row.id), row.witness, row.expected, row.test)
	}
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "A host result never stands in for a device result. E-8-11 is the one row about")
	fmt.Fprintln(a.out, "the Time floor, a device-side control. It builds the firmware's own floor code")
	fmt.Fprintln(a.out, "for native_sim on this computer, and it never reaches the service or a board.")
	fmt.Fprintf(a.out, "\nReset: %s\n", block.Reset)
	return nil
}

// ------------------------------------------------------------------
// The ten host rows
// ------------------------------------------------------------------

// E-8-01. A remote "recover my device".
//
// Recovery is the Tier 7 claim with step 4 replaced, so it still needs a
// device half, and a device half needs a press. The owner's authority is real
// and it is not enough: the press is the second party.
func (x *tier07Adversary) rowRecoverWithoutPress() error {
	const deviceID = "beacon-bypass-e8-01"
	if _, _, err := x.claimSynthetic(deviceID); err != nil {
		return err
	}
	if err := x.authorizeRecovery(deviceID); err != nil {
		return err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the owner of record holds a live Recovery authorization. It now approves a")
	fmt.Fprintln(x.out(), "  claim with a well-formed nonce, and no device has pressed its button.")
	result, err := x.asOwner(http.MethodPost, "/v1/claim",
		map[string]any{"device_id": deviceID, "nonce": nonce})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "claim-window-open")
}

// E-8-02. The course's own universal secret, offered as the device half of a
// recovery.
//
// Issue #214 expected identity-factory or certificate-active here, and the
// wire says neither. The shared identity is a genuine Factory certificate,
// signed by the Manufacturer Device CA and never revoked, so it passes both.
// What refuses it is the rule that one request names one device: the
// certificate names beacon-development-shared, and the path names the device
// being recovered.
func (x *tier07Adversary) rowSharedIdentityRecovery() error {
	const deviceID = "beacon-bypass-e8-02"
	if _, _, err := x.claimSynthetic(deviceID); err != nil {
		return err
	}
	if err := x.authorizeRecovery(deviceID); err != nil {
		return err
	}
	pki := x.app.pkiDir()
	if !coursepki.SharedIdentityExists(pki) {
		return errors.New("no shared development identity; run ./course keys create shared-identity first, which is the credential Tier 6's shared image carries")
	}
	certificate, err := os.ReadFile(filepath.Join(pki, coursepki.SharedIdentityCert))
	if err != nil {
		return err
	}
	key, err := os.ReadFile(filepath.Join(pki, coursepki.SharedIdentityKey))
	if err != nil {
		return err
	}
	csr, err := x.freshRequest(deviceID)
	if err != nil {
		return err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  the shared development identity, %s, is the credential every Tier 6\n",
		coursepki.SharedIdentityName)
	fmt.Fprintln(x.out(), "  shared image carries. E-6-07 extracted it from the image. It is offered")
	fmt.Fprintf(x.out(), "  here as the device half of the recovery of %s.\n", deviceID)
	result, err := x.asDevice(string(certificate), string(key), http.MethodPost,
		"/v1/devices/"+deviceID+"/claim", map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "identifier-consistent")
}

// E-8-03. A renewal that keeps the key it is meant to replace.
func (x *tier07Adversary) rowRenewSameKey() error {
	const deviceID = "beacon-bypass-e8-03"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  asking for renewal as the owner, so that renewal is due now and")
	fmt.Fprintln(x.out(), "  renewal-due cannot be the check that refuses this row:")
	if err := x.ownerAct("/v1/devices/"+deviceID+"/renewal-request", nil); err != nil {
		return err
	}
	key, err := parsePrivateKeyPEM(device.OperationalKey)
	if err != nil {
		return err
	}
	csr, err := operationalRequest(deviceID, key)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the certification request is signed by the key the device already holds,")
	fmt.Fprintln(x.out(), "  so it proves possession of a key the service has already certified.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/renewal", map[string]any{"csr": csr})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "key-unused")
}

// E-8-04. A renewal the service did not offer.
//
// Nothing in this row ever asks for a renewal of this device. If a row did,
// the request would apply to this certificate for the rest of its life and
// the row could not be run again.
func (x *tier07Adversary) rowUnsolicitedRenewal() error {
	const deviceID = "beacon-bypass-e8-04"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	csr, err := x.freshRequest(deviceID)
	if err != nil {
		return err
	}
	fmt.Fprintln(x.out(), "  the device offers a fresh key it has never used. Only the timing is wrong:")
	fmt.Fprintln(x.out(), "  renewal is due when a third of the certificate's life is left, or when")
	fmt.Fprintln(x.out(), "  the owner asks, and neither has happened.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodPost, "/v1/devices/"+deviceID+"/renewal", map[string]any{"csr": csr})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "renewal-due")
}

// E-8-05. A certificate its owner revoked through the service.
//
// E-7-06 marked a serial revoked by writing the file. This row reaches the
// same file through the Owner's operation over the operator listener, which is
// the only way Tier 8 gives an owner.
func (x *tier07Adversary) rowOwnerRevokedCertificate() error {
	const deviceID = "beacon-bypass-e8-05"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	revoked, err := x.app.revokedSerials()
	if err != nil {
		return err
	}
	if !revoked[device.OperationalSerial] {
		fmt.Fprintf(x.out(), "  revoking certificate %s as its owner, on the operator listener:\n",
			device.OperationalSerial)
		if err := x.ownerAct("/v1/certificates/"+device.OperationalSerial+"/revoke",
			map[string]any{"reason": crlReasonKeyCompromise}); err != nil {
			return err
		}
	}
	fmt.Fprintln(x.out(), "  the certificate is unexpired and correctly signed, and the device still")
	fmt.Fprintln(x.out(), "  holds its key. Only the service's status for the serial changed.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-8-06. The manufacturer's block on a Factory identity.
//
// Recovery rests on the Factory identity, so this is the block that closes
// recovery for a hostile device. Clause 2 does not ask which authority signed
// the certificate, so it refuses a Factory serial on the claim endpoint as it
// refuses an Operational one anywhere else.
func (x *tier07Adversary) rowBlockedFactorySerial() error {
	const deviceID = "beacon-bypass-e8-06"
	device, err := x.ensureEnrolled(deviceID)
	if err != nil {
		return err
	}
	serial, err := certificateSerial(device.FactoryCertificate)
	if err != nil {
		return err
	}
	revoked, err := x.app.revokedSerials()
	if err != nil {
		return err
	}
	if !revoked[serial] {
		fmt.Fprintln(x.out(), "  the adversary acts as the manufacturer here, at the station, because")
		fmt.Fprintln(x.out(), "  blocking a Factory identity is the manufacturer's power and no owner's:")
		if err := x.app.provisionRevoke([]string{"--serial", serial, "--reason", crlReasonKeyCompromise}); err != nil {
			return err
		}
	}
	csr, err := x.freshRequest(deviceID)
	if err != nil {
		return err
	}
	nonce, err := newClaimNonce()
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  Factory certificate %s opens a claim window, as a press would.\n", serial)
	result, err := x.asDevice(device.FactoryCertificate, device.FactoryKey, http.MethodPost,
		"/v1/devices/"+deviceID+"/claim", map[string]any{"nonce": nonce, "csr": csr})
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-8-07. A revoked device, and a certificate nobody revoked.
//
// Device revocation writes a revocation record and revokes no serial, so
// certificate-active passes and device-unrevoked is the check that names the
// reason. That is the difference between stopping a credential and stopping a
// device.
func (x *tier07Adversary) rowRevokedDevice() error {
	const deviceID = "beacon-bypass-e8-07"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	state, err := x.app.lifecycleStateOf(deviceID)
	if err != nil {
		return err
	}
	if state != lifecycle.Revoked {
		fmt.Fprintln(x.out(), "  revoking the device as its owner, on the operator listener:")
		if err := x.ownerAct("/v1/devices/"+deviceID+"/revoke",
			map[string]any{"reason": crlReasonKeyCompromise}); err != nil {
			return err
		}
	}
	fmt.Fprintf(x.out(), "  certificate %s is not revoked.\n", device.OperationalSerial)
	fmt.Fprintln(x.out(), "  The device is revoked, and the record says so.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "device-unrevoked")
}

// E-8-08. The first act of an Ownership transfer, and the credential left
// over from before it.
//
// The second act, a new owner's claim, is the unchanged Tier 7 press. This row
// stops before it, because the gap between the two acts is where the old
// credential would still work if the transfer had not revoked it.
func (x *tier07Adversary) rowTransferredDevice() error {
	const deviceID = "beacon-bypass-e8-08"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	state, err := x.app.lifecycleStateOf(deviceID)
	if err != nil {
		return err
	}
	if state != lifecycle.Transferred {
		fmt.Fprintln(x.out(), "  giving the device up as its owner, on the operator listener:")
		if err := x.ownerAct("/v1/devices/"+deviceID+"/transfer", nil); err != nil {
			return err
		}
	}
	fmt.Fprintln(x.out(), "  the device rests in transferred, owned by no one, until somebody presses")
	fmt.Fprintln(x.out(), "  its button and claims it. The old owner's certificate is presented now.")
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "certificate-active")
}

// E-8-09. A retired board on the service.
//
// Decommissioning revokes no serial, on purpose: certificate-active runs
// first, so revoking the serials would refuse the certificate before
// device-in-service could name the real reason.
func (x *tier07Adversary) rowDecommissionedAtService() error {
	const deviceID = "beacon-bypass-e8-09"
	device, _, err := x.claimSynthetic(deviceID)
	if err != nil {
		return err
	}
	if err := x.decommission(deviceID); err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  certificate %s is not revoked, and the device still holds its key.\n",
		device.OperationalSerial)
	result, err := x.asDevice(device.OperationalCertificate, device.OperationalKey,
		http.MethodGet, "/v1/releases/current", nil)
	if err != nil {
		return err
	}
	return x.expectRefusal(result, "device-in-service")
}

// E-8-10. A retired board at the station, under a name it never had.
//
// Tier 6's identifier-unused already refuses the old name. A new name is the
// cheap way round that, and it is why the board, keyed by its MAC suffix, is
// the unit of decommissioning and not the identifier.
func (x *tier07Adversary) rowDecommissionedAtStation() error {
	if err := x.allowedIdentifier(tier08NewBoardID); err != nil {
		return err
	}
	if _, err := x.ensureEnrolled(tier08OldBoardID); err != nil {
		return err
	}
	if err := x.decommission(tier08OldBoardID); err != nil {
		return err
	}
	credential, _, err := x.app.mintCredential(tier08NewBoardID)
	if err != nil {
		return err
	}
	host, err := newHostDevice()
	if err != nil {
		return err
	}
	csr, err := host.request(tier08NewBoardID, credential)
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out(), "  %s is a new name with a new Bootstrap credential. Its MAC\n", tier08NewBoardID)
	fmt.Fprintf(x.out(), "  suffix is %s, the same board as %s.\n", boardOf(tier08NewBoardID), tier08OldBoardID)
	outcome, err := x.app.enrollHost(tier08NewBoardID, credential, csr)
	if err != nil {
		return err
	}
	if outcome.Issued {
		return fmt.Errorf("%s was not refused: the station issued Factory certificate %s", x.row, outcome.CertSerial)
	}
	// The station has no network surface, so this refusal has no status. It
	// is read from the real station in process, as Tier 6's rows read theirs.
	fmt.Fprintf(x.out(), "  refused at check %s, by the station\n", outcome.Check)
	fmt.Fprintf(x.out(), "  %s\n", outcome.Reason)
	if outcome.Check != "hardware-in-service" {
		return fmt.Errorf("%s refused at %q, expected %q", x.row, outcome.Check, "hardware-in-service")
	}
	fmt.Fprintf(x.out(), "\nResult: %s refused at hardware-in-service, as the tier requires\n", x.row)
	return nil
}

// ------------------------------------------------------------------
// The operations the rows withdraw authority with
// ------------------------------------------------------------------

// authorizeRecovery runs the owner's half of a recovery on the operator
// listener. A live authorization is answered with the same one, so a rerun
// writes nothing new.
func (x *tier07Adversary) authorizeRecovery(deviceID string) error {
	fmt.Fprintf(x.out(), "  authorizing the recovery of %s as its owner of record:\n", deviceID)
	return x.ownerAct("/v1/devices/"+deviceID+"/recover", nil)
}

// ownerAct sends one owner operation and fails if the service refused it.
func (x *tier07Adversary) ownerAct(path string, body any) error {
	result, err := x.asOwner(http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if result.refused() {
		return fmt.Errorf("POST %s was refused at %s: %s", path, result.Check, result.Reason)
	}
	if result.Status != http.StatusOK {
		return fmt.Errorf("POST %s answered %d: %v", path, result.Status, result.Body)
	}
	fmt.Fprintf(x.out(), "    POST %s: %s\n", path, resultOf(result))
	return nil
}

// decommission retires a synthetic board at the station, once. A second
// decommission is refused by the station, so a rerun checks the record first.
func (x *tier07Adversary) decommission(deviceID string) error {
	records, err := x.app.readRecords()
	if err != nil {
		return err
	}
	if boardDecommissioned(records, boardOf(deviceID)) {
		fmt.Fprintf(x.out(), "  the board of %s is already decommissioned in this environment.\n", deviceID)
		return nil
	}
	fmt.Fprintln(x.out(), "  the adversary acts as the manufacturer here, at the station, because")
	fmt.Fprintln(x.out(), "  decommissioning is the manufacturer's act:")
	return x.app.provisionDecommission([]string{"--device", deviceID})
}

// lifecycleStateOf derives one device's state from the record, the same way
// the service does.
func (a *app) lifecycleStateOf(deviceID string) (string, error) {
	records, err := a.readRecords()
	if err != nil {
		return "", err
	}
	return lifecycle.Derive(lifecycleRecords(records))[deviceID].State, nil
}

func resultOf(result answer) string {
	if value, _ := result.Body["result"].(string); value != "" {
		return value
	}
	return http.StatusText(result.Status)
}

func certificateSerial(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("the fixture's certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return certificate.SerialNumber.String(), nil
}

// parsePrivateKeyPEM reads back a synthetic device's key from fixture state,
// which privateKeyPEM wrote as PKCS #8.
func parsePrivateKeyPEM(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("the fixture's private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the fixture's private key is not an ECDSA key")
	}
	return key, nil
}
