package courseapp

// Tier 8's renewal, the host half.
//
// There is one command, and it is the Owner's: ./course claim renew makes
// renewal due now instead of when a third of the certificate's lifetime is
// left. It does not renew anything. The device renews on its own Operational
// identity the next time it polls and reads `renew`, with no person in the
// renewal itself, and the service retires the old certificate once it sees
// the new one used. This command only moves the schedule, which is why it is
// safe to give the Owner: it can make a renewal happen sooner, and it can never
// make one happen for a device whose identity would be refused anyway.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// claimRenew asks the service to set `renew` for one device the caller owns.
func (a *app) claimRenew(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return err
	}
	credential, err := flagValue(args, "--credential")
	if err != nil {
		return errors.New("--credential is required; it is the Owner credential ./course owner new printed once")
	}
	if strings.TrimSpace(credential) == "" {
		return errors.New("--credential is empty")
	}

	pool, err := a.trustAnchorPool()
	if err != nil {
		return err
	}
	port := a.manifest.Runtime.OperatorTLSPort
	address := net.JoinHostPort(hostOf(a.serviceURL()), strconv.Itoa(port))
	base := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(port)
	client := a.verifyingClient(pool, coursepki.ServiceName, address)
	path := "/v1/devices/" + deviceID + "/renewal-request"

	fmt.Fprintln(a.out, "Asking for a renewal now, as the owner of this device.")
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The service normally asks a device to renew when a third of its")
	fmt.Fprintln(a.out, "certificate's lifetime is left. This moves that moment to now. It does not")
	fmt.Fprintln(a.out, "renew anything: the device renews on its own Operational identity when it")
	fmt.Fprintln(a.out, "next reads its assignment, and no person takes part in that.")
	fmt.Fprintf(a.out, "  operator listener: %s\n", base)
	fmt.Fprintf(a.out, "  device named:      %s\n", deviceID)
	fmt.Fprintln(a.out)

	request, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	fmt.Fprintf(a.out, "+ POST %s%s\n", base, path)
	fmt.Fprintln(a.out, "  Authorization: Bearer <the credential, not printed>")

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("the operator listener could not be reached at %s: %w; start the service with ./course service start --https --mutual-tls", address, err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "  <- %d %s\n", response.StatusCode, http.StatusText(response.StatusCode))
	return a.narrateRenewalRequest(response.StatusCode, answer)
}

// narrateRenewalRequest explains the service's answer. It is apart from the
// request so the narration can be tested without a listener.
func (a *app) narrateRenewalRequest(status int, answer []byte) error {
	if status != http.StatusOK {
		var refusal struct {
			Check  string `json:"check"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(answer, &refusal); err != nil || refusal.Check == "" {
			fmt.Fprintf(a.out, "     %s\n", strings.TrimSpace(string(answer)))
			return fmt.Errorf("the renewal request was refused with status %d", status)
		}
		fmt.Fprintf(a.out, "     refused at check %s\n", refusal.Check)
		fmt.Fprintf(a.out, "     reason: %s\n", refusal.Reason)
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "The check name says which property did not hold, and the status does not.")
		fmt.Fprintf(a.out, "Result: the renewal request was refused at %s\n", refusal.Check)
		return fmt.Errorf("refused at check %s", refusal.Check)
	}
	var done struct {
		Result   string `json:"result"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(answer, &done); err != nil {
		return fmt.Errorf("the operator listener answered 200 with a body this command cannot read: %w", err)
	}
	fmt.Fprintf(a.out, "     result: %s\n", done.Result)
	fmt.Fprintf(a.out, "     device: %s\n", done.DeviceID)
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The device's next assignment carries renew: true. When it renews, both")
	fmt.Fprintln(a.out, "certificates are accepted until the service sees the new one used. Then the")
	fmt.Fprintf(a.out, "old one is revoked as superseded in %s.\n", a.relative(a.revokedPath()))
	fmt.Fprintf(a.out, "Result: renewal is due now for %s\n", done.DeviceID)
	return nil
}
