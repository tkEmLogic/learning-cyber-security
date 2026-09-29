package courseapp

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// transcriptConsole is a console whose board side is a fixed transcript. What
// the station sends is written to a pipe and thrown away, so the whole console
// path runs without a serial device.
func transcriptConsole(t *testing.T, transcript string) *console {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, read)
	t.Cleanup(func() {
		write.Close()
		read.Close()
	})
	return &console{port: write, reader: bufio.NewReader(strings.NewReader(transcript))}
}

// requestTranscript is what a board prints for "provision request": a Tier 8
// board prints provision.mac first, a Tier 6 or Tier 7 board does not. The
// shell prompt and a stray printk line are left in, as on the real console.
func requestTranscript(mac string, csr []byte) string {
	var b strings.Builder
	b.WriteString("uart:~$ provision request <credential>\r\n")
	if mac != "" {
		fmt.Fprintf(&b, "provision.mac %s\r\n", mac)
	}
	b.WriteString("[00:00:05.120,000] <inf> wifi: still connected\r\n")
	fmt.Fprintf(&b, "provision.csr begin %d\r\n", len(csr))
	encoded := hex.EncodeToString(csr)
	for len(encoded) > 0 {
		n := 64
		if n > len(encoded) {
			n = len(encoded)
		}
		fmt.Fprintf(&b, "provision.csr data %s\r\n", encoded[:n])
		encoded = encoded[n:]
	}
	b.WriteString("provision.csr end\r\n")
	return b.String()
}

// certificateTranscript is the board accepting the certificate the station
// returns, so an issued enrolment runs to its end.
func certificateTranscript(deviceID string) string {
	return "provision.certificate expecting 600 bytes\r\n" +
		"provision.certificate stored, device_id=" + deviceID + "\r\n"
}

func TestReadProvisionRequestReadsTheTier08MAC(t *testing.T) {
	csr := []byte{0x30, 0x82, 0x01, 0x02, 0xaa}
	mac, got, err := readProvisionRequest(transcriptConsole(t, requestTranscript("206ef1170d64", csr)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if mac != "206ef1170d64" {
		t.Fatalf("mac = %q, want the reported one", mac)
	}
	if !bytes.Equal(got, csr) {
		t.Fatalf("csr = %x, want %x", got, csr)
	}
}

func TestReadProvisionRequestAcceptsATier07BoardWithoutAMAC(t *testing.T) {
	csr := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	mac, got, err := readProvisionRequest(transcriptConsole(t, requestTranscript("", csr)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if mac != "" || !bytes.Equal(got, csr) {
		t.Fatalf("mac = %q csr = %x, want no MAC and the request", mac, got)
	}
}

func TestReadProvisionRequestRejectsAMalformedMAC(t *testing.T) {
	for _, bad := range []string{"20:6e:f1:17:0d:64", "206EF1170D64", "206ef1170d"} {
		_, _, err := readProvisionRequest(transcriptConsole(t, requestTranscript(bad, []byte{0x01})), 2*time.Second)
		if err == nil || !strings.Contains(err.Error(), "not twelve lower-case hex") {
			t.Fatalf("mac %q: err = %v, want a malformed-MAC error", bad, err)
		}
	}
}

// A Tier 8 board whose MAC matches its identifier enrols, and the enrolment
// record carries the MAC the board reported.
func TestEnrollOverConsoleKeysTheBoardByTheReportedMAC(t *testing.T) {
	a, out := provisioningApp(t)
	const id = "beacon-t08-206ef1170d64"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, id)
	transcript := requestTranscript("206ef1170d64", device.request(t, id, credential)) + certificateTranscript(id)

	if err := a.enrollOverConsole(transcriptConsole(t, transcript), id, credential); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "board reported its factory MAC: 206ef1170d64") {
		t.Fatalf("output does not show the reported MAC:\n%s", text)
	}
	if !strings.Contains(text, "Result: "+id+" holds a Factory identity") {
		t.Fatalf("enrolment did not complete:\n%s", text)
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Kind == recordEnrollment && record.Result == "issued" && record.DeviceID == id {
			found = record.Board == "206ef1170d64"
		}
	}
	if !found {
		t.Fatalf("the issued enrolment record does not carry the reported MAC: %+v", records)
	}
}

// identifier-matches-hardware: a Tier 8 board may not enrol under another
// board's name. The refusal is recorded and nothing is issued.
func TestIdentifierMatchesHardwareRefusesAMismatchedSuffix(t *testing.T) {
	a, out := provisioningApp(t)
	const id = "beacon-aabbccddeeff"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, id)
	transcript := requestTranscript("206ef1170d64", device.request(t, id, credential))

	if err := a.enrollOverConsole(transcriptConsole(t, transcript), id, credential); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Refused at check identifier-matches-hardware") {
		t.Fatalf("mismatch was not refused at identifier-matches-hardware:\n%s", out.String())
	}
	if n := countIssued(t, a); n != 0 {
		t.Fatalf("%d certificates issued, want none", n)
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	last := records[len(records)-1]
	if last.Result != "refused" || !strings.HasPrefix(last.Detail, "identifier-matches-hardware: ") || last.Board != "206ef1170d64" {
		t.Fatalf("refusal record = %+v, want identifier-matches-hardware on the reported board", last)
	}
}

// A name that is not a MAC at all does not match a reported MAC either.
func TestIdentifierMatchesHardwareRefusesANonMACName(t *testing.T) {
	a, out := provisioningApp(t)
	const id = "beacon-development-shared"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, id)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID:    id,
		CSRDer:      device.request(t, id, credential),
		ReportedMAC: "206ef1170d64",
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued || outcome.Check != "identifier-matches-hardware" {
		t.Fatalf("outcome = issued:%v check:%s, want identifier-matches-hardware", outcome.Issued, outcome.Check)
	}
}

// The attack the check closes: a decommissioned board enrolling under a name
// whose suffix is some other board's MAC. Before Tier 8 the station would have
// keyed that name to the other board and issued; with the MAC reported, the
// name is refused because it does not match the hardware.
func TestADecommissionedBoardCannotBorrowAnotherBoardsName(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}

	const borrowed = "beacon-aabbccddeeff"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, borrowed)
	outcome, err := a.enroll(enrollmentRequest{
		DeviceID:    borrowed,
		CSRDer:      device.request(t, borrowed, credential),
		ReportedMAC: "206ef1170d64",
	}, credential)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Issued || outcome.Check != "identifier-matches-hardware" {
		t.Fatalf("borrowed name = issued:%v check:%s, want identifier-matches-hardware", outcome.Issued, outcome.Check)
	}
}

// hardware-in-service is keyed on the reported MAC: a Tier 8 board that was
// decommissioned is refused there under a new, correctly suffixed identifier.
func TestHardwareInServiceUsesTheReportedMAC(t *testing.T) {
	a, out := provisioningApp(t)
	if outcome := enrollDevice(t, a, out, "beacon-206ef1170d64"); !outcome.Issued {
		t.Fatalf("first enrolment refused at %s: %s", outcome.Check, outcome.Reason)
	}
	if err := a.provisionDecommission([]string{"--device", "beacon-206ef1170d64"}); err != nil {
		t.Fatal(err)
	}

	const id = "beacon-t08-206ef1170d64"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, id)
	transcript := requestTranscript("206ef1170d64", device.request(t, id, credential))
	if err := a.enrollOverConsole(transcriptConsole(t, transcript), id, credential); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Refused at check hardware-in-service") {
		t.Fatalf("decommissioned board was not refused at hardware-in-service:\n%s", out.String())
	}
}

// A Tier 6 or Tier 7 board prints no MAC. It still enrols, keyed by its
// identifier's suffix as before, and the output says the suffix is unchecked.
func TestEnrollOverConsoleKeepsSuffixKeyingForATier07Board(t *testing.T) {
	a, out := provisioningApp(t)
	const id = "beacon-206ef1170d64"
	device := newFakeDevice(t)
	credential := credentialFor(t, a, out, id)
	transcript := requestTranscript("", device.request(t, id, credential)) + certificateTranscript(id)

	if err := a.enrollOverConsole(transcriptConsole(t, transcript), id, credential); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"board printed no provision.mac line, so it runs a Tier 6 or Tier 7 image",
		"the station keys the board by the identifier's suffix, 206ef1170d64",
		"Result: " + id + " holds a Factory identity",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output lacks %q:\n%s", want, text)
		}
	}
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Kind == recordEnrollment && record.Board != "" {
			t.Fatalf("a board with no MAC report left a board key on its record: %+v", record)
		}
	}
}

func countIssued(t *testing.T, a *app) int {
	t.Helper()
	records, err := a.readRecords()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, record := range records {
		if record.Kind == recordEnrollment && record.Result == "issued" {
			n++
		}
	}
	return n
}
