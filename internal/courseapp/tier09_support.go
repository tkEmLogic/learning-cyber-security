package courseapp

// Tier 9's support-listener attack fixture (#269, #279), the host half of the
// planted flaw T9-W-34.
//
// The counter-5 release added an unauthenticated UDP support listener on the
// board, on the port CONFIG_COURSE_SUPPORT_LISTENER_PORT names. It answers two
// one-word requests: `inventory`, with the device id, running release and
// security counter, and `reboot`, which resets the chip. Nothing authenticates
// either, and nothing on the device or in the service records who asked. This
// fixture is the "small UDP sender on the lab network" the design calls for: it
// sends one request and prints exactly what it sent and what came back.
//
// It is a registered fixture, so it inherits the whole safety runner: the dry
// run, the exact `--execute` identifier, the marker handshake over plain HTTP,
// the machine-readable evidence record, and the block-after-failed-reset. The
// marker handshake goes to the loopback OTA service, exactly as Tier 6's clone
// does: the handshake is about which Course environment a fixture may act in,
// not about which socket it opens, and the board serves no marker of its own.
//
// The reboot request is destructive, so it is one of two allowlisted values
// behind --request, the same shape Tier 3's images use. It can never be reached
// without naming it, and the runner already forces --execute on top of that.

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// supportListenerFixtureID is the one manifest key this file owns.
const supportListenerFixtureID = "tier-09/support-listener"

// supportListenerPortDefault matches the Kconfig default the counter-5 image
// carries, so a manifest that omits the port still reaches the board.
const supportListenerPortDefault = 7700

// supportReplyTimeout bounds how long the fixture waits for the board's answer.
// A lost datagram and an absent listener look the same over UDP, which is the
// whole reason the timeout message calls itself weak evidence.
const supportReplyTimeout = 3 * time.Second

// fixtureReplyTimeout is the fixture's wait for one answer. Only the Tier 10
// scenario shortens it, for Event 8's dense series inside a trial window of
// about ten seconds (#293); an ordinary run always waits the full 3 s.
func (a *app) fixtureReplyTimeout() time.Duration {
	if a.supportTimeout > 0 && a.supportTimeout < supportReplyTimeout {
		return a.supportTimeout
	}
	return supportReplyTimeout
}

// boardAddressRecord is the one allowlisted target this fixture reaches over
// the network. The board serves no Course environment marker, so its address
// cannot come from the marker handshake, and the contract keeps endpoints off
// the fixture command line. So a separate lab-control step records it here,
// validated as a literal private or loopback address, and the fixture reads it
// from generated state rather than from its own arguments. See
// docs/fixture-safety-contract.md, "Tier 9 fixtures".
type boardAddressRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Address       string `json:"address"`
	RecordedAt    string `json:"recorded_at"`
}

func (a *app) boardAddressPath() string {
	return filepath.Join(a.root, a.manifest.Paths.State, "support", "board-address.json")
}

// deviceAddress is `./course device address [<ip>]`: a lab control, not a
// fixture. With an address it validates and records the board's LAN address;
// with none it prints the one on record.
//
// It is a lab control for the same reason Tier 7's revoke command is: it opens
// no socket, has no target and changes no service state, so a marker handshake
// and a reset would guard nothing while implying a check had happened. The
// address a Learner passes is the one the board prints on its own console,
// `wifi.address <ip> assigned by DHCP`, and it is validated to the same literal
// private or loopback set every target in this course is held to.
func (a *app) deviceAddress(args []string) error {
	if len(args) == 0 {
		var record boardAddressRecord
		if err := readJSON(a.boardAddressPath(), &record); err != nil || record.Address == "" {
			fmt.Fprintln(a.out, "No board address on record.")
			fmt.Fprintln(a.out, "Read it from the board's console, the wifi.address line, and record it with")
			fmt.Fprintln(a.out, "./course device address <ip>")
			return nil
		}
		fmt.Fprintf(a.out, "Board address on record: %s (recorded %s)\n", record.Address, record.RecordedAt)
		return nil
	}
	if len(args) != 1 {
		return errors.New("device address takes one literal address, or none to show the one on record")
	}
	address := args[0]
	// The same literal private or loopback rule every target obeys: no DNS
	// name, no range, no wildcard. A board on the lab network carries a private
	// address; loopback is allowed for a host build that has no board.
	if err := validateBind(address); err != nil {
		return fmt.Errorf("a board address must be loopback or a literal private or link-local address, not %q: %w", address, err)
	}
	record := boardAddressRecord{
		SchemaVersion: 1,
		Address:       address,
		RecordedAt:    timeNowUTC(),
	}
	if err := writeJSON(a.boardAddressPath(), record, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: recorded the board's address as %s\n", address)
	fmt.Fprintf(a.out, "The support-listener fixture reads it from %s, never from its own command line.\n",
		a.relative(a.boardAddressPath()))
	return nil
}

// boardAddress returns the recorded board address, refusing before any side
// effect if none is on record. It re-validates what it reads, so a hand-edited
// state file cannot widen the target past the rule the setup step enforced.
func (a *app) boardAddress() (string, error) {
	var record boardAddressRecord
	if err := readJSON(a.boardAddressPath(), &record); err != nil || record.Address == "" {
		return "", errors.New("no board address on record; record it with ./course device address <ip> first")
	}
	if err := validateBind(record.Address); err != nil {
		return "", fmt.Errorf("the recorded board address %q is not a literal private or loopback address: %w", record.Address, err)
	}
	return record.Address, nil
}

// supportListenerFixture sends one request to the board's support listener and
// prints exactly what it sent and what came back.
func (a *app) supportListenerFixture(id string) (string, string, map[string]string, error) {
	request, ok := a.manifest.Fixtures[id].Requests[a.selector]
	if !ok || request == "" {
		return "", "", nil, fmt.Errorf("%s has no request for selector %q", id, a.selector)
	}
	port := a.manifest.Fixtures[id].Port
	if port == 0 {
		port = supportListenerPortDefault
	}
	address, err := a.boardAddress()
	if err != nil {
		return "", "", nil, err
	}
	target := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	a.step(1, "Send one line to the board's support listener over UDP.")
	a.note("The listener is unauthenticated (T9-W-34). Anything that can send a")
	a.note("datagram to the board can take its inventory and can restart it.")
	a.sent("UDP", target)
	a.note("payload: %q", request)
	if a.selector == "reboot" {
		a.note("This asks the board to restart. It is why reboot is a named request")
		a.note("and not the default: the runner will not send it unless you name it.")
	}

	timeout := a.fixtureReplyTimeout()
	reply, err := sendSupportRequest(target, request, timeout)
	seconds := int(timeout / time.Second)
	hashes := map[string]string{}
	if errors.Is(err, errSupportTimeout) {
		// A timeout is weak evidence and the fixture says so plainly. After the
		// remediation release the listener is gone and this is exactly what a
		// Learner sees, but a lost datagram looks the same, so the board's boot
		// log is the strong evidence.
		message := fmt.Sprintf("no reply within %d s", seconds)
		a.got("%s", message)
		a.note("weak evidence: a lost datagram looks the same; read the boot log")
		observed := fmt.Sprintf("no reply within %d s from the support listener; weak evidence, read the boot log", seconds)
		return observed, "the board's own boot log is the strong evidence, not this timeout", hashes, nil
	}
	if errors.Is(err, errSupportRefused) {
		// Stronger than a timeout: the board's own network stack answered
		// that nothing listens on the port. It still says nothing about
		// what the image contains, so the boot log remains the record.
		a.got("port unreachable: the board's network stack says nothing listens on UDP %d", port)
		a.note("That is the board's answer, not a lost datagram. The boot log says why.")
		observed := fmt.Sprintf("the board answered that nothing listens on UDP %d (ICMP port unreachable)", port)
		return observed, "", hashes, nil
	}
	if err != nil {
		return "", "", hashes, err
	}
	a.got("%q", reply)
	if request == "inventory" {
		a.note("The listener named the device id, its running release and its security")
		a.note("counter, to a sender that proved nothing about who it was.")
	}
	if request == "reboot" {
		a.note("The listener acknowledged, then reset the board. Watch ./course device")
		a.note("logs for the boot banner and the fresh boot the service will see.")
	}
	observed := fmt.Sprintf("the unauthenticated support listener answered %q with %q", request, strings.TrimSpace(reply))
	return observed, "", hashes, nil
}

// resetSupportListener is the fixture's honest no-op reset. It touches no
// service state, so there is nothing to seed back; a reboot it may have caused
// is the board's and cannot be rewound from the host.
func (a *app) resetSupportListener() error {
	return nil
}

// errSupportTimeout is the sentinel that separates "no reply" from a real
// send or receive error, so the caller can word the two differently.
var errSupportTimeout = errors.New("support listener did not reply")

// errSupportRefused is the board's ICMP port unreachable, which a connected
// UDP socket reports as a refused read.
var errSupportRefused = errors.New("nothing listens on the support port")

// sendSupportRequest sends one UDP datagram and reads at most one reply. It is
// deliberately tiny: one datagram out, one datagram in or a timeout, and no
// retry, so what the Learner sees is exactly one exchange on the wire.
func sendSupportRequest(target, request string, timeout time.Duration) (string, error) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s over UDP: %w", target, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(request + "\n")); err != nil {
		return "", fmt.Errorf("could not send to %s: %w", target, err)
	}
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", errSupportTimeout
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "", errSupportRefused
		}
		return "", err
	}
	return string(buffer[:n]), nil
}

// tier09Plan and tier09Proves are what the dry run shows for the Tier 9
// fixture, the same shape the earlier tiers use.
var tier09Plan = map[string][]string{
	supportListenerFixtureID: {
		"Read the board's recorded address, and refuse if none is on record.",
		"Send one line, the named request, to the board's support-listener UDP port.",
		"Print exactly what was sent and what came back, or report no reply as weak evidence.",
	},
}

var tier09Proves = map[string][]string{
	supportListenerFixtureID: {
		"T9-W-34  The support listener answers unauthenticated requests and accepts reboot. Closed for a device on counter 6, which compiles the listener out.",
	},
}
