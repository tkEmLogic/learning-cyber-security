package courseapp

// Tier 8 firmware prints its factory MAC before its certification request, as
// "provision.mac <12 hex>" (decision #216, built in #256). The station reads
// that line and keys the board by it, so the MAC suffix of an identifier stops
// being only a naming convention: an identifier whose suffix is not the MAC
// the board reported is refused at identifier-matches-hardware.
//
// The station trusts this report and does not prove it. It is the firmware's
// own line, and a modified image can print any MAC. esptool read-mac, a ROM
// read of the eFuse, is the stronger source, and decommission and remanufacture
// use that one in the procedure.
//
// A Tier 6 or Tier 7 board prints no MAC line. The station then keys the board
// by the identifier's suffix, exactly as before Tier 8, and says so.

import (
	"fmt"
	"strings"
	"time"
)

const provisionMACPrefix = "provision.mac "

// readProvisionRequest reads the board's answer to "provision request": an
// optional provision.mac line, then the chunked provision.csr transfer. The
// MAC is empty when the board printed none.
func readProvisionRequest(c *console, timeout time.Duration) (string, []byte, error) {
	var mac, malformed string
	csrDER, err := c.readChunkedObserving("provision.csr", timeout, func(line string) {
		if !strings.HasPrefix(line, provisionMACPrefix) {
			return
		}
		reported := strings.TrimSpace(strings.TrimPrefix(line, provisionMACPrefix))
		if validMAC(reported) {
			mac = reported
		} else {
			malformed = reported
		}
	})
	if err != nil {
		return "", nil, fmt.Errorf("the board did not return a certification request: %w", err)
	}
	if malformed != "" {
		return "", nil, fmt.Errorf("the board reported the MAC %q, which is not twelve lower-case hex characters", malformed)
	}
	return mac, csrDER, nil
}

// validMAC is the form Tier 8 firmware prints: six bytes as twelve lower-case
// hex characters, with no separators.
func validMAC(mac string) bool {
	if len(mac) != 12 {
		return false
	}
	for i := 0; i < len(mac); i++ {
		if !isLowerHex(mac[i]) {
			return false
		}
	}
	return true
}

// enrollingBoard is the hardware key for one enrolment: the MAC the board
// reported, or the identifier's MAC suffix when it reported none.
func enrollingBoard(request enrollmentRequest) string {
	if request.ReportedMAC != "" {
		return request.ReportedMAC
	}
	return boardOf(request.DeviceID)
}

// reportBoardKey tells the Learner which key the station uses for the board,
// and how much that key is worth.
func (a *app) reportBoardKey(deviceID, mac string) {
	if mac != "" {
		fmt.Fprintf(a.out, "  board reported its factory MAC: %s\n", mac)
		fmt.Fprintln(a.out, "  the station keys the board by this MAC, and the identifier's suffix")
		fmt.Fprintln(a.out, "  must match it. The station trusts this report but cannot prove it:")
		fmt.Fprintln(a.out, "  the firmware printed it, and esptool read-mac is the stronger source")
		return
	}
	fmt.Fprintln(a.out, "  board printed no provision.mac line, so it runs a Tier 6 or Tier 7 image")
	fmt.Fprintf(a.out, "  the station keys the board by the identifier's suffix, %s, as before\n", boardOf(deviceID))
	fmt.Fprintln(a.out, "  Tier 8, and cannot check that this suffix is the board's MAC")
}
