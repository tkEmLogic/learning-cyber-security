package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
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
	})
	if err != nil {
		log.Fatal(err)
	}
	address := net.JoinHostPort(bind, port)
	log.Printf("UNSAFE COURSE SERVICE: HTTP only, synthetic data, listening on %s", address)
	log.Printf("course marker: http://%s/.well-known/course-environment", address)
	if err := http.ListenAndServe(address, server.Handler()); err != nil {
		log.Fatal(err)
	}
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
	log.SetPrefix(fmt.Sprintf("[%s] ", "tier-00-ota"))
}
