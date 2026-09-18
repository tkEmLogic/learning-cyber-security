package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tkEmLogic/learning-cyber-security/services/ota"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		response, err := http.Get("http://127.0.0.1:8080/health")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		response.Body.Close()
		return
	}
	https := false
	mutualTLS := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--https":
			https = true
		case "--mutual-tls":
			mutualTLS = true
		default:
			log.Fatalf("unknown option %q", arg)
		}
	}
	if mutualTLS && !https {
		log.Fatal("--mutual-tls applies only with --https")
	}

	bind := env("COURSE_BIND", "127.0.0.1")
	if !safeBind(bind, os.Getenv("COURSE_ALLOW_CONTAINER_WILDCARD") == "1") {
		log.Fatalf("COURSE_BIND must be loopback or a private IP address, got %q", bind)
	}
	port := env("COURSE_PORT", "8080")
	// The two device authorities and the manufacturing record, or nothing at
	// all. Nothing at all is what every tier before this one runs with, and it
	// is what keeps their bytes unchanged.
	var mutual *ota.MutualTLS
	if mutualTLS {
		mutual = loadMutualTLS()
	}
	server, err := ota.New(ota.Config{
		CourseID:      env("COURSE_ID", "learning-cyber-security"),
		EnvironmentID: os.Getenv("COURSE_ENVIRONMENT_ID"),
		Tier:          env("COURSE_TIER", "00"),
		StateDir:      env("COURSE_STATE_DIR", ".course-state/ota"),
		ReleaseDir:    env("COURSE_RELEASE_DIR", "artifacts/generated/releases"),
		// Empty unless a Learner deliberately started a misbehaving service.
		// Tier 5 is the only tier that sets it.
		RangeBehaviour: os.Getenv("COURSE_RANGE_BEHAVIOUR"),
		MutualTLS:      mutual,
	})
	if err != nil {
		log.Fatal(err)
	}
	address := net.JoinHostPort(bind, port)

	if !https {
		log.Printf("UNSAFE COURSE SERVICE: HTTP only, synthetic data, listening on %s", address)
		log.Printf("course marker: http://%s/.well-known/course-environment", address)
		if err := http.ListenAndServe(address, server.Handler()); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Two listeners with different jobs.
	//
	// Release records, firmware bytes, and status events move to TLS. Health
	// and the Course environment marker stay in the clear, because a safety
	// check must not depend on the control it is used to test, and because the
	// marker is a fail-closed targeting check rather than a credential.
	//
	// The plain listener still answers on the data paths, with a message
	// saying where they went. A Learner replaying the Tier 0 attack needs to
	// be told, not left guessing.
	tlsPort := env("COURSE_TLS_PORT", "8443")
	certFile := os.Getenv("COURSE_TLS_CERT")
	keyFile := os.Getenv("COURSE_TLS_KEY")
	if certFile == "" || keyFile == "" {
		log.Fatal("--https needs COURSE_TLS_CERT and COURSE_TLS_KEY")
	}
	serviceName := env("COURSE_SERVICE_NAME", "ota.course.example")
	tlsAddress := net.JoinHostPort(bind, tlsPort)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	if !mutualTLS {
		log.Printf("COURSE SERVICE: data on https://%s, presenting %s", tlsAddress, serviceName)
		log.Printf("COURSE SERVICE: health and course marker stay on http://%s", address)
		log.Printf("course marker: http://%s/.well-known/course-environment", address)

		go func() {
			if err := http.ListenAndServe(address, server.PublicHandler(mustPort(tlsPort), serviceName)); err != nil {
				log.Fatal(err)
			}
		}()
		// One listener that authenticates only itself, which is what Tiers 2
		// to 6 run and what their published modules quote.
		serveTLS(tlsAddress, server.DataHandler(), &tls.Config{
			Certificates: []tls.Certificate{certificate},
		})
		return
	}

	// Three listeners with three different answers to "who may connect".
	//
	// The device listener demands a client certificate for the whole socket,
	// because tls.RequireAndVerifyClientCert is decided before a byte of HTTP
	// is read and therefore before any route is matched. The operator listener
	// authenticates only the server, because a person has no device
	// certificate and a bearer token on a socket that rejects the handshake
	// never reaches a handler. The plain listener keeps health and the Course
	// environment marker, un-redirected: a mutual-TLS marker fetch is exactly
	// what an attack fixture holding a CA key could satisfy, so a marker
	// behind the control would be a safety check the adversary can forge.
	operatorPort := env("COURSE_OPERATOR_TLS_PORT", "8444")
	operatorAddress := net.JoinHostPort(bind, operatorPort)

	log.Printf("COURSE SERVICE: devices on https://%s, mutual TLS, presenting %s", tlsAddress, serviceName)
	log.Printf("COURSE SERVICE: operators on https://%s, server authenticated only", operatorAddress)
	log.Printf("COURSE SERVICE: health and course marker stay on http://%s", address)
	log.Printf("course marker: http://%s/.well-known/course-environment", address)

	go func() {
		if err := http.ListenAndServe(address,
			server.SplitPublicHandler(mustPort(tlsPort), mustPort(operatorPort), serviceName)); err != nil {
			log.Fatal(err)
		}
	}()
	go serveTLS(operatorAddress, server.OperatorHandler(), &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	serveTLS(tlsAddress, server.DeviceHandler(), &tls.Config{
		Certificates: []tls.Certificate{certificate},
		// The whole socket, one decision. A certificate from an authority
		// outside this pool fails here, with no status, no body and no check
		// name, and that asymmetry is taught rather than worked around.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  mutual.ClientCAPool(),
	})
}

// serveTLS runs one listener from an explicit server, and never returns.
//
// An explicit *http.Server rather than http.ListenAndServeTLS, because the
// client-certificate decision lives in the tls.Config and that function has
// nowhere to put one.
func serveTLS(address string, handler http.Handler, config *tls.Config) {
	server := &http.Server{
		Addr:      address,
		Handler:   handler,
		TLSConfig: config,
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

// loadMutualTLS reads the two device authorities out of COURSE_PKI_DIR.
//
// One directory rather than a variable per file: coursepki owns the file names
// already, and five variables naming five files is five ways to be told the
// wrong thing. COURSE_TLS_CERT and COURSE_TLS_KEY stay as they are, because
// --present untrusted deliberately points them outside the normal set.
// The two authority file names the host side writes. They are spelled here
// rather than imported from coursepki, because nothing under services/ depends
// on internal/: the service is handed a directory and reads it.
const (
	manufacturerCAFile = "device-ca.crt.pem"
	operationalCAFile  = "operational-ca.crt.pem"
)

func loadMutualTLS() *ota.MutualTLS {
	pkiDir := os.Getenv("COURSE_PKI_DIR")
	if pkiDir == "" {
		log.Fatal("--mutual-tls needs COURSE_PKI_DIR, holding the device authorities")
	}
	return &ota.MutualTLS{
		ManufacturerCA:  loadCA(filepath.Join(pkiDir, manufacturerCAFile)),
		OperationalCA:   loadCA(filepath.Join(pkiDir, operationalCAFile)),
		ProvisioningDir: env("COURSE_PROVISIONING_DIR", ".course-state/provisioning"),
		PKIDir:          pkiDir,
	}
}

func loadCA(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("--mutual-tls needs %s: %v", filepath.Base(path), err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("%s is not PEM", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return certificate
}

func mustPort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("COURSE_TLS_PORT must be a number, got %q", value)
	}
	return port
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func safeBind(value string, allowContainerWildcard bool) bool {
	if allowContainerWildcard && value == "0.0.0.0" {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return value == "localhost"
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.SetPrefix(fmt.Sprintf("[%s] ", "course-ota"))
}
