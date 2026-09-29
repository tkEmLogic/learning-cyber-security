package courseapp

// Tier 8's recovery command, the host half.
//
// Recovery is the Tier 7 claim with one check replaced. This command is the
// only new act in it: the owner of record tells the service the device's
// Operational identity is lost. The service revokes the current Operational
// certificate and, for one hour, lets the owner's next claim of that device
// through where a first claim would require an unowned device. After that the
// Learner presses the button and runs ./course claim approve exactly as in
// Tier 7. The firmware does not know it is recovering.

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

// crlReasonSuperseded is what a recovery revokes the old certificate with
// unless the owner says the board was stolen.
const crlReasonSuperseded = "superseded"

// claimRecover is ./course claim recover --device <id> --credential <hex>
// [--reason keyCompromise].
func (a *app) claimRecover(args []string) error {
	deviceID, err := flagValue(args, "--device")
	if err != nil {
		return err
	}
	reason := crlReasonSuperseded
	if given, err := flagValue(args, "--reason"); err == nil {
		reason = given
	}
	if reason != crlReasonSuperseded && reason != crlReasonKeyCompromise {
		return fmt.Errorf("reason %q is not accepted for a recovery; use %s, or %s for a board you think was stolen",
			reason, crlReasonSuperseded, crlReasonKeyCompromise)
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
	path := "/v1/devices/" + deviceID + "/recover"

	fmt.Fprintln(a.out, "Authorizing the recovery of a lost Operational identity, as the owner of")
	fmt.Fprintln(a.out, "record. The service revokes the device's current Operational certificate and")
	fmt.Fprintln(a.out, "allows one claim of this device by you within the next hour. Nothing is sent")
	fmt.Fprintln(a.out, "to the device: you still press its button and approve the claim.")
	fmt.Fprintf(a.out, "  device: %s\n", deviceID)
	fmt.Fprintf(a.out, "  reason: %s\n", reason)
	fmt.Fprintln(a.out)

	body, err := json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)

	fmt.Fprintf(a.out, "+ POST %s%s\n", base, path)
	fmt.Fprintln(a.out, "  Authorization: Bearer <the credential, not printed>")
	fmt.Fprintf(a.out, "  -> %s\n", body)

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

	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Check  string `json:"check"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(answer, &refusal); err != nil || refusal.Check == "" {
			fmt.Fprintf(a.out, "     %s\n", strings.TrimSpace(string(answer)))
			return fmt.Errorf("the recovery authorization was refused with status %d", response.StatusCode)
		}
		fmt.Fprintf(a.out, "     refused at check %s\n", refusal.Check)
		fmt.Fprintf(a.out, "     reason: %s\n", refusal.Reason)
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "The check name says which property did not hold, and the status does not.")
		fmt.Fprintf(a.out, "Result: the recovery authorization was refused at %s\n", refusal.Check)
		return fmt.Errorf("refused at check %s", refusal.Check)
	}

	var done struct {
		Result        string   `json:"result"`
		DeviceID      string   `json:"device_id"`
		Authorization string   `json:"recovery_authorization"`
		Revoked       []string `json:"revoked_certificate_serials"`
		Expires       string   `json:"expires_at"`
	}
	if err := json.Unmarshal(answer, &done); err != nil {
		return fmt.Errorf("the operator listener answered 200 with a body this command cannot read: %w", err)
	}
	revoked := "nothing new"
	if len(done.Revoked) > 0 {
		revoked = strings.Join(done.Revoked, ", ")
	}
	fmt.Fprintf(a.out, "     result:        %s\n", done.Result)
	fmt.Fprintf(a.out, "     authorization: %s\n", done.Authorization)
	fmt.Fprintf(a.out, "     revoked:       %s\n", revoked)
	fmt.Fprintf(a.out, "     expires at:    %s, by the service clock\n", done.Expires)
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "Now press the device's button and approve the claim with the nonce it prints:")
	fmt.Fprintf(a.out, "  ./course claim approve --device %s --nonce <nonce> --credential <your credential>\n", done.DeviceID)
	fmt.Fprintln(a.out, "The device generates a new Operational key for the claim. The old key is")
	fmt.Fprintln(a.out, "never certified again.")
	fmt.Fprintf(a.out, "Result: recovery of %s is %s until %s\n", done.DeviceID, done.Result, done.Expires)
	return nil
}
