package courseapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/tkEmLogic/learning-cyber-security/internal/coursepki"
)

// The Tier 2 fixtures replay the Tier 0 attacks against a service the device
// now verifies, and try two ways around that check.
//
// Every one of them runs on the host. A host client checking a certificate
// runs exactly the checks the device runs, so the mechanism is the same, but
// the refusal that matters is the device's and it is read from the board's
// serial console. Each fixture says so rather than letting a host result stand
// in for a hardware one.

// trustAnchorPool is the same material the firmware compiles in.
func (a *app) trustAnchorPool() (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Join(a.pkiDir(), coursepki.CourseCACert))
	if err != nil {
		return nil, errors.New("no Course certificate authority exists; run ./course setup first")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("the Course certificate authority is unreadable")
	}
	return pool, nil
}

// verifyingClient is a client configured the way the device is: this trust
// anchor, this required name, and no way to skip either. It connects to a
// literal address and checks the name, which is what the device does.
func (a *app) verifyingClient(pool *x509.CertPool, requireName, dialAddress string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, dialAddress)
			},
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: requireName,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

func (a *app) tlsAddress(target string) string {
	return net.JoinHostPort(hostOf(target), strconv.Itoa(a.manifest.Runtime.TLSPort))
}

func hostOf(target string) string {
	host := stripScheme(target)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if host == "localhost" {
		return "127.0.0.1"
	}
	return host
}

func stripScheme(value string) string {
	for _, prefix := range []string{"http://", "https://"} {
		if len(value) > len(prefix) && value[:len(prefix)] == prefix {
			return value[len(prefix):]
		}
	}
	return value
}

// runTier02PlaintextInspection replays the Tier 0 reconnaissance attack.
func (a *app) runTier02PlaintextInspection(env environment, target string) (string, string, map[string]string, error) {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return "", "", nil, err
	}

	a.step(1, "Ask the plain HTTP port for the release record, exactly as Tier 0 did.")
	a.sent(http.MethodGet, target+"/v1/releases/current")
	response, err := a.client.Get(target + "/v1/releases/current")
	if err != nil {
		return "", "", nil, err
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return "", "", nil, fmt.Errorf("the plain HTTP port still serves release records: %s", response.Status)
	}
	a.got("%d Not Found. The same request that worked in Tier 0 returns nothing readable:", response.StatusCode)
	var moved map[string]any
	if json.Unmarshal(body, &moved) == nil {
		a.showJSON(moved)
	}
	a.note("The release record, the firmware bytes, and the status events left this port.")
	a.note("The Course environment marker did not, and that is deliberate. It is a targeting check, not a credential.")

	a.step(2, "Ask the TLS port, checking the certificate the way the device does.")
	a.note("Trust anchor: the Course certificate authority in .course-secrets/pki.")
	a.note("Required name: %s. The connection still goes to the literal address %s.", coursepki.ServiceName, a.tlsAddress(target))
	client := a.verifyingClient(pool, coursepki.ServiceName, a.tlsAddress(target))
	url := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(a.manifest.Runtime.TLSPort) + "/v1/releases/current"
	a.sent(http.MethodGet, url)
	response, err = client.Get(url)
	if err != nil {
		return "", "", nil, fmt.Errorf("the verified connection failed: %w", err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	var release map[string]any
	if json.Unmarshal(body, &release) != nil {
		return "", "", nil, errors.New("the verified connection returned no release record")
	}
	a.got("%d OK. The record is still there, and now only a verified client can read it:", response.StatusCode)
	a.showJSON(release)
	a.note("An observer on this network sees the handshake and then encrypted bytes. The fields above never cross in the clear.")

	a.step(3, "Ask the same TLS port by address, without stating the name.")
	a.note("This is the mistake the tier is about, so it is worth watching fail.")
	byAddress := a.verifyingClient(pool, hostOf(target), a.tlsAddress(target))
	a.sent(http.MethodGet, "https://"+a.tlsAddress(target)+"/v1/releases/current")
	if _, err := byAddress.Get("https://" + a.tlsAddress(target) + "/v1/releases/current"); err == nil {
		return "", "", nil, errors.New("a connection that named no service was accepted; the certificate should not allow that")
	} else {
		a.got("refused: %v", err)
	}
	a.note("The certificate carries the name %s and no address at all, so an address can never match it.", coursepki.ServiceName)

	captured := a.captureExchange(target, "tier-02/plaintext-inspection")

	return "release records left the plain HTTP port and are readable only over a verified connection",
		"this is the host's check, not the device's; read the board's serial console for the device's own refusal",
		captured, nil
}

// captureExchange records the bytes on the wire, when the container allows it.
//
// Capture is bounded by the contract: one interface, only the manifest-owned
// ports, a filter the course builds, a fixed duration, and no promiscuous mode.
// The filter is printed, so the bound is visible rather than promised.
func (a *app) captureExchange(target, fixture string) map[string]string {
	dir := filepath.Join(a.root, a.manifest.Paths.GeneratedArtifacts, "attacks", filepath.FromSlash(fixture))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	path := filepath.Join(dir, "wire.pcap")
	filter := fmt.Sprintf("tcp port %d or tcp port %d", a.manifest.Runtime.OTAPort, a.manifest.Runtime.TLSPort)

	a.step(4, "Record what an observer on this network would actually see.")
	if _, err := exec.LookPath("tcpdump"); err != nil {
		a.note("No capture tool is installed, so this step is skipped and no packet evidence is produced.")
		a.note("Rebuild the dev container to get it, and see docs/fixture-safety-contract.md for the bounds a capture must keep.")
		return nil
	}
	a.note("Interface: loopback. Filter: %s. Duration: 5 seconds. No promiscuous mode.", filter)
	command := exec.Command("tcpdump", "-i", "lo", "-s", "0", "-w", path, "-G", "5", "-W", "1", filter)
	if err := command.Start(); err != nil {
		a.note("Capture could not start: %v", err)
		return nil
	}
	time.Sleep(500 * time.Millisecond)
	pool, err := a.trustAnchorPool()
	if err == nil {
		client := a.verifyingClient(pool, coursepki.ServiceName, a.tlsAddress(target))
		url := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(a.manifest.Runtime.TLSPort) + "/v1/releases/current"
		if response, err := client.Get(url); err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}
	if response, err := a.client.Get(target + "/.well-known/course-environment"); err == nil {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	_ = command.Wait()
	info, err := os.Stat(path)
	if err != nil {
		a.note("Capture produced no file. The container may lack NET_RAW; see docs/fixture-safety-contract.md.")
		return nil
	}
	a.got("Wrote %s, %d bytes.", path, info.Size())
	a.note("Open it and look for the release fields. They are not there. The marker exchange is, in the clear, as designed.")
	return map[string]string{"wire.pcap": fmt.Sprintf("%d bytes", info.Size())}
}

// serveWith starts a manifest-owned TLS service on one port with one
// certificate, and returns a stop function. It answers the marker in the clear
// on the plain port, the same way the real service does, so a fixture's safety
// check never depends on the certificate under test.
func (a *app) serveWith(env environment, host string, plainPort, tlsPort int, certFile, keyFile string) (func(), error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(a.pkiDir(), certFile), filepath.Join(a.pkiDir(), keyFile))
	if err != nil {
		return nil, err
	}
	marker := http.NewServeMux()
	marker.HandleFunc("/.well-known/course-environment", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	})
	data := http.NewServeMux()
	data.HandleFunc("/v1/releases/current", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"release_id": "impersonated", "version": "0.0.0-hostile", "signed": false,
		})
	})

	plain, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(plainPort)))
	if err != nil {
		return nil, fmt.Errorf("start manifest-owned marker listener: %w", err)
	}
	secure, err := tls.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(tlsPort)),
		&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		plain.Close()
		return nil, fmt.Errorf("start manifest-owned TLS listener: %w", err)
	}
	// The imposter's own handshake failures are the expected result here, so
	// its error log is discarded. Leaving it on interleaves Go's internal
	// message with the narration and makes the refusal look like a crash.
	quiet := log.New(io.Discard, "", 0)
	plainServer := &http.Server{Handler: marker, ReadHeaderTimeout: 2 * time.Second, ErrorLog: quiet}
	dataServer := &http.Server{Handler: data, ReadHeaderTimeout: 2 * time.Second, ErrorLog: quiet}
	go func() { _ = plainServer.Serve(plain) }()
	go func() { _ = dataServer.Serve(secure) }()
	return func() {
		plainServer.Shutdown(context.Background())
		dataServer.Shutdown(context.Background())
	}, nil
}

// runTier02Impersonation replays the Tier 0 impersonation attack against a
// device that now checks who answered.
func (a *app) runTier02Impersonation(env environment, target string) (string, string, map[string]string, error) {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return "", "", nil, err
	}
	host := hostOf(target)
	plainPort := a.manifest.Runtime.ImpersonationPort
	tlsPort := a.manifest.Runtime.ImpersonationTLSPort

	a.step(1, "Start a second service that pretends to be the update service.")
	a.note("It answers on %s:%d in the clear for the marker, and serves data over TLS on port %d.", host, plainPort, tlsPort)
	a.note("Its certificate carries the correct name, %s. Only its issuer is wrong.", coursepki.ServiceName)
	stop, err := a.serveWith(env, host, plainPort, tlsPort, coursepki.UntrustedCert, coursepki.UntrustedKey)
	if err != nil {
		return "", "", nil, err
	}
	defer stop()
	impersonationURL := fmt.Sprintf("http://%s:%d", host, plainPort)
	if _, _, err := a.matchMarker(impersonationURL); err != nil {
		return "", "", nil, err
	}
	a.got("The imposter answers the marker check, in the clear, exactly as the contract expects.")
	a.note("That check never depended on the certificate, which is why it still works here.")

	a.step(2, "Point the device configuration at the imposter.")
	configPath := filepath.Join(a.root, a.manifest.Paths.State, "device-config.json")
	var config map[string]any
	if err := readJSON(configPath, &config); err != nil {
		return "", "", nil, err
	}
	a.note("Was: ota_url = %v", config["ota_url"])
	config["ota_url"] = impersonationURL
	if err := writeJSON(configPath, config, 0o600); err != nil {
		return "", "", nil, err
	}
	a.note("Now: ota_url = %v", impersonationURL)
	a.note("In Tier 0 this address was the entire basis for trust, and the imposter won here.")

	a.step(3, "Ask the imposter for a release, checking the certificate the way the device does.")
	client := a.verifyingClient(pool, coursepki.ServiceName, net.JoinHostPort(host, strconv.Itoa(tlsPort)))
	url := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(tlsPort) + "/v1/releases/current"
	a.sent(http.MethodGet, url)
	_, err = client.Get(url)
	if err == nil {
		return "", "", nil, errors.New("the imposter was accepted; the trust anchor should have refused it")
	}
	a.got("refused: %v", err)
	a.note("The check that ran: does a chain lead from this certificate to the trust anchor in this image.")
	a.note("What it compared: the issuer of the presented certificate against the Course certificate authority.")
	a.note("What it rejected: a certificate signed by an authority nobody told the device to trust.")
	a.note("The name was right. The address was right. Neither was enough, and that is the whole point.")

	a.step(4, "Confirm what the imposter was holding.")
	description, err := coursepki.Describe(filepath.Join(a.pkiDir(), coursepki.UntrustedCert))
	if err != nil {
		return "", "", nil, err
	}
	fmt.Fprint(a.out, description)
	a.note("A well-formed certificate for the right name. Nothing about it is malformed, and it still fails.")
	a.note("No release data was read, so nothing the imposter said reached the device.")

	return "the impersonation service was refused because its certificate does not chain to the trust anchor",
		"this is the host's refusal; the device's own refusal is on the board's serial console",
		nil, nil
}

// runTier02NameMismatch isolates the name check from the chain check.
func (a *app) runTier02NameMismatch(env environment, target string) (string, string, map[string]string, error) {
	pool, err := a.trustAnchorPool()
	if err != nil {
		return "", "", nil, err
	}
	host := hostOf(target)
	plainPort := a.manifest.Runtime.ImpersonationPort
	tlsPort := a.manifest.Runtime.ImpersonationTLSPort

	a.step(1, "Serve a certificate issued by the authority the device does trust.")
	a.note("Everything about this certificate is genuine except the name it carries.")
	stop, err := a.serveWith(env, host, plainPort, tlsPort, coursepki.WrongNameCert, coursepki.WrongNameKey)
	if err != nil {
		return "", "", nil, err
	}
	defer stop()
	if _, _, err := a.matchMarker(fmt.Sprintf("http://%s:%d", host, plainPort)); err != nil {
		return "", "", nil, err
	}
	description, err := coursepki.Describe(filepath.Join(a.pkiDir(), coursepki.WrongNameCert))
	if err != nil {
		return "", "", nil, err
	}
	fmt.Fprint(a.out, description)

	a.step(2, "Connect requiring the name the device requires.")
	a.note("Required: %s. Presented: %s.", coursepki.ServiceName, coursepki.MismatchName)
	client := a.verifyingClient(pool, coursepki.ServiceName, net.JoinHostPort(host, strconv.Itoa(tlsPort)))
	url := "https://" + coursepki.ServiceName + ":" + strconv.Itoa(tlsPort) + "/v1/releases/current"
	a.sent(http.MethodGet, url)
	if _, err := client.Get(url); err == nil {
		return "", "", nil, errors.New("a certificate for the wrong name was accepted")
	} else {
		a.got("refused: %v", err)
	}
	a.note("The check that ran: does the certificate carry the name this device was told to require.")
	a.note("What it compared: the certificate's dNSName entries against %s.", coursepki.ServiceName)
	a.note("What it rejected: a certificate the trusted authority really did issue, for something else.")

	a.step(3, "Notice which check did not fail.")
	a.note("The chain was fine. The authority was the right one. Only the name was wrong.")
	a.note("Both checks have to pass. A control that verified the issuer and skipped the name would have accepted this.")

	return "a certificate issued by the trusted authority for another name was refused",
		"this is the host's refusal; the device's own refusal is on the board's serial console",
		nil, nil
}
