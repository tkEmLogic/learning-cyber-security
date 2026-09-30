package courseapp

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// supportApp builds a small app rooted in a temp dir, enough for the
// support-listener fixture's own helpers: it does not need a service.
func supportApp(t *testing.T) (*app, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	a := &app{root: t.TempDir(), out: out, errOut: out}
	a.manifest.Paths.State = ".course-state"
	return a, out
}

// The board address is a lab-control input, validated to the same literal
// private or loopback set every target obeys, and read from state rather than
// from the fixture command line.
func TestDeviceAddressValidatesAndRoundTrips(t *testing.T) {
	a, _ := supportApp(t)
	for _, bad := range []string{"example.com", "8.8.8.8", "0.0.0.0", "not-an-ip"} {
		if err := a.deviceAddress([]string{bad}); err == nil {
			t.Errorf("device address %q was accepted, want a refusal", bad)
		}
	}
	if _, err := a.boardAddress(); err == nil {
		t.Error("boardAddress must refuse before any address is recorded")
	}
	if err := a.deviceAddress([]string{"192.168.7.42"}); err != nil {
		t.Fatal(err)
	}
	got, err := a.boardAddress()
	if err != nil || got != "192.168.7.42" {
		t.Fatalf("boardAddress() = %q, %v; want 192.168.7.42", got, err)
	}
}

// The two requests are the only ones the fixture may send, and reboot is one of
// them so it can never be reached without naming it.
func TestSupportFixtureRequestsAreBounded(t *testing.T) {
	f := fixture{Requests: map[string]string{"inventory": "inventory", "reboot": "reboot"}}
	allowed, option := f.selectors()
	if option != "--request" {
		t.Fatalf("selector option = %q, want --request", option)
	}
	if allowed["inventory"] != "inventory" || allowed["reboot"] != "reboot" {
		t.Fatalf("unexpected allowlist: %v", allowed)
	}
	if _, ok := allowed["shutdown"]; ok {
		t.Fatal("an unlisted request must not be in the allowlist")
	}
}

// An unknown selector is refused before any datagram leaves the host.
func TestSupportFixtureRefusesUnknownRequest(t *testing.T) {
	a, _ := supportApp(t)
	a.manifest.Fixtures = map[string]fixture{
		supportListenerFixtureID: {Requests: map[string]string{"inventory": "inventory", "reboot": "reboot"}, Port: 7700},
	}
	if err := a.deviceAddress([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	a.selector = "shutdown"
	if _, _, _, err := a.supportListenerFixture(supportListenerFixtureID); err == nil {
		t.Fatal("an unknown request must be refused")
	}
}

// The fixture sends exactly one datagram and prints what it sent and what came
// back. A tiny UDP echo stands in for the board.
func TestSupportFixtureSendsAndPrintsTheAnswer(t *testing.T) {
	reply := "device_id=beacon-test release_id=tier-09-support-listener security_counter=5\n"
	port := startUDPEcho(t, reply)

	a, out := supportApp(t)
	a.manifest.Fixtures = map[string]fixture{
		supportListenerFixtureID: {Requests: map[string]string{"inventory": "inventory", "reboot": "reboot"}, Port: port},
	}
	if err := a.deviceAddress([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	a.selector = "inventory"
	observed, _, _, err := a.supportListenerFixture(supportListenerFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	if !strings.Contains(printed, "inventory") || !strings.Contains(printed, "security_counter=5") {
		t.Fatalf("the exchange was not printed:\n%s", printed)
	}
	if !strings.Contains(observed, "answered") {
		t.Fatalf("observed effect = %q", observed)
	}
}

// A timeout is reported honestly as weak evidence, because a lost datagram and
// an absent listener look the same over UDP.
func TestSupportFixtureReportsTimeoutAsWeakEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("this waits out the real UDP reply timeout, a few seconds")
	}
	// A socket that receives but never answers, so the read times out rather
	// than failing fast. A closed port would return an ICMP refusal instead,
	// which is a different case from the lost datagram this row is about.
	silent := silentUDPPort(t)

	a, out := supportApp(t)
	a.manifest.Fixtures = map[string]fixture{
		supportListenerFixtureID: {Requests: map[string]string{"inventory": "inventory"}, Port: silent},
	}
	if err := a.deviceAddress([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	a.selector = "inventory"
	observed, limitation, _, err := a.supportListenerFixture(supportListenerFixtureID)
	if err != nil {
		t.Fatalf("a timeout must not be an error: %v", err)
	}
	if !strings.Contains(observed, "no reply") || !strings.Contains(observed, "weak evidence") {
		t.Fatalf("observed = %q, want a weak-evidence timeout", observed)
	}
	if !strings.Contains(out.String(), "read the boot log") {
		t.Fatalf("the timeout did not point at the boot log:\n%s", out.String())
	}
	if limitation == "" {
		t.Fatal("a timeout must record a hardware limitation")
	}
}

// startUDPEcho listens on loopback and answers one datagram with reply. It
// returns the port it bound.
func startUDPEcho(t *testing.T, reply string) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP([]byte(reply), addr)
		_ = n
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// silentUDPPort binds a loopback UDP socket that receives but never answers, so
// a send to it succeeds and the read times out, which is the lost-datagram case
// the row is about. A closed port would fail fast with an ICMP refusal instead.
func silentUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			if _, _, err := conn.ReadFromUDP(buffer); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
