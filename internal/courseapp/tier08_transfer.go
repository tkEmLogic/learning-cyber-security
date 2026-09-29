package courseapp

// Tier 8's Ownership transfer command, the host half.
//
// A transfer is two acts, and this command is the first: the owner of record
// gives the device up. The service revokes the device's Operational
// certificate as privilegeWithdrawn, voids any open Recovery authorization and
// leaves the device transferred, owned by no one. The second act is the
// unchanged Tier 7 claim: whoever holds the device presses its button and runs
// ./course claim approve with their own Owner credential. The transfer names
// no recipient, because the press is what binds the device to its new owner.

import (
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

// ownerTransfer is ./course owner transfer --device <id> --credential <hex>.
//
// It takes no --reason. A transfer always revokes as privilegeWithdrawn: the
// old owner's privilege is withdrawn, and nothing is said about the key.
func (a *app) ownerTransfer(args []string) error {
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
	path := "/v1/devices/" + deviceID + "/transfer"

	fmt.Fprintln(a.out, "Giving a device up, as its owner of record. This is the first of the two")
	fmt.Fprintln(a.out, "acts of an ownership transfer. The service revokes the device's Operational")
	fmt.Fprintln(a.out, "certificate, and the device is then owned by no one. It cannot reach the")
	fmt.Fprintln(a.out, "service until a new owner claims it. You cannot undo this yourself.")
	fmt.Fprintf(a.out, "  device: %s\n", deviceID)
	fmt.Fprintf(a.out, "  reason: %s\n", crlReasonPrivilegeWithdrawn)
	fmt.Fprintln(a.out)

	request, err := http.NewRequest(http.MethodPost, base+path, nil)
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

	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Check  string `json:"check"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(answer, &refusal); err != nil || refusal.Check == "" {
			fmt.Fprintf(a.out, "     %s\n", strings.TrimSpace(string(answer)))
			return fmt.Errorf("the transfer was refused with status %d", response.StatusCode)
		}
		fmt.Fprintf(a.out, "     refused at check %s\n", refusal.Check)
		fmt.Fprintf(a.out, "     reason: %s\n", refusal.Reason)
		fmt.Fprintln(a.out)
		fmt.Fprintln(a.out, "The check name says which property did not hold, and the status does not.")
		fmt.Fprintf(a.out, "Result: the transfer was refused at %s\n", refusal.Check)
		return fmt.Errorf("refused at check %s", refusal.Check)
	}

	var done struct {
		Result   string   `json:"result"`
		DeviceID string   `json:"device_id"`
		Revoked  []string `json:"revoked_certificate_serials"`
		Voided   string   `json:"voided_recovery_authorization"`
		State    string   `json:"lifecycle_state"`
	}
	if err := json.Unmarshal(answer, &done); err != nil {
		return fmt.Errorf("the operator listener answered 200 with a body this command cannot read: %w", err)
	}
	revoked := "nothing new"
	if len(done.Revoked) > 0 {
		revoked = strings.Join(done.Revoked, ", ")
	}
	voided := "none was open"
	if done.Voided != "" {
		voided = done.Voided
	}
	fmt.Fprintf(a.out, "     result:                 %s\n", done.Result)
	fmt.Fprintf(a.out, "     revoked:                %s\n", revoked)
	fmt.Fprintf(a.out, "     recovery authorization: %s\n", voided)
	fmt.Fprintf(a.out, "     lifecycle state:        %s\n", done.State)
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "The second act belongs to the new owner. They press the device's button and")
	fmt.Fprintln(a.out, "approve the claim with the nonce it prints and their own credential:")
	fmt.Fprintf(a.out, "  ./course claim approve --device %s --nonce <nonce> --credential <their credential>\n", done.DeviceID)
	fmt.Fprintln(a.out, "The transfer names no new owner. The person who presses the button becomes it.")
	fmt.Fprintf(a.out, "Result: device %s is %s\n", done.DeviceID, done.State)
	return nil
}
