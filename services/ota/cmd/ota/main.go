package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
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
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--https":
			https = true
		default:
			log.Fatalf("unknown option %q", arg)
		}
	}

	bind := env("COURSE_BIND", "127.0.0.1")
	if !safeBind(bind, os.Getenv("COURSE_ALLOW_CONTAINER_WILDCARD") == "1") {
		log.Fatalf("COURSE_BIND must be loopback or a private IP address, got %q", bind)
	}
	port := env("COURSE_PORT", "8080")
	server, err := ota.New(ota.Config{
		CourseID:      env("COURSE_ID", "learning-cyber-security"),
		EnvironmentID: os.Getenv("COURSE_ENVIRONMENT_ID"),
		Tier:          env("COURSE_TIER", "00"),
		StateDir:      env("COURSE_STATE_DIR", ".course-state/ota"),
		ReleaseDir:    env("COURSE_RELEASE_DIR", "artifacts/generated/releases"),
		// Empty unless a Learner deliberately started a misbehaving service.
		// Tier 5 is the only tier that sets it.
		RangeBehaviour: os.Getenv("COURSE_RANGE_BEHAVIOUR"),
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

	log.Printf("COURSE SERVICE: data on https://%s, presenting %s", tlsAddress, serviceName)
	log.Printf("COURSE SERVICE: health and course marker stay on http://%s", address)
	log.Printf("course marker: http://%s/.well-known/course-environment", address)

	go func() {
		if err := http.ListenAndServe(address, server.PublicHandler(mustPort(tlsPort), serviceName)); err != nil {
			log.Fatal(err)
		}
	}()
	if err := http.ListenAndServeTLS(tlsAddress, certFile, keyFile, server.DataHandler()); err != nil {
		log.Fatal(err)
	}
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
