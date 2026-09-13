package ota

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	CourseID      string
	EnvironmentID string
	Tier          string
	StateDir      string
	ReleaseDir    string
}

type Release struct {
	SchemaVersion int    `json:"schema_version"`
	ReleaseID     string `json:"release_id"`
	Version       string `json:"version"`
	Board         string `json:"board"`
	ImagePath     string `json:"image_path"`
	ImageSHA256   string `json:"image_sha256"`
	ImageSize     int64  `json:"image_size"`
	Mutable       bool   `json:"mutable"`
	Signed        bool   `json:"signed"`
}

type Server struct {
	cfg Config
	mu  sync.Mutex
}

func New(cfg Config) (*Server, error) {
	if cfg.CourseID == "" || cfg.EnvironmentID == "" || cfg.Tier == "" {
		return nil, errors.New("course marker fields are required")
	}
	if cfg.StateDir == "" || cfg.ReleaseDir == "" {
		return nil, errors.New("state and release directories are required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

// Handler serves every endpoint on one listener. This is the Tier 0 service,
// and it does not change, because the Tier 0 module is published and describes
// it exactly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routePublic(mux)
	s.routeData(mux)
	return courseHeaders(mux)
}

// PublicHandler serves the two endpoints that stay in the clear in every tier:
// health, and the Course environment marker.
//
// The marker is plain HTTP on purpose. A safety check must not depend on the
// control it is being used to test. Over TLS a fixture would either have to
// verify a certificate before being allowed to find out whether it is pointed
// at the lab, which makes the control a precondition for testing the control,
// or skip verification, which is the one example this course tells Learners
// never to write. The impersonation fixture settles it: its imposter presents
// a deliberately untrusted certificate, so a TLS marker check would refuse the
// very fixture it is meant to guard.
//
// The marker carries only synthetic identifiers and is not a credential.
//
// Data routes are registered here too, and refuse with a message that says
// where they went. A bare 404 would leave a Learner guessing.
func (s *Server) PublicHandler(tlsPort int, serviceName string) http.Handler {
	mux := http.NewServeMux()
	s.routePublic(mux)
	moved := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":          "this endpoint is no longer served over plain HTTP",
			"moved_to":       fmt.Sprintf("https://%s:%d", serviceName, tlsPort),
			"why":            "Tier 2 moved release records, firmware, and events to an authenticated, encrypted connection",
			"still_here":     []string{"/health", "/.well-known/course-environment"},
			"why_still_here": "the Course environment marker is a fail-closed targeting check, not a credential, and it must not depend on the control it is used to test",
		})
	}
	for _, route := range dataRoutes {
		mux.HandleFunc(route, moved)
	}
	return courseHeaders(mux)
}

// DataHandler serves release records, firmware bytes, and status events. In
// Tier 2 it runs behind TLS.
func (s *Server) DataHandler() http.Handler {
	mux := http.NewServeMux()
	s.routeData(mux)
	return courseHeaders(mux)
}

// dataRoutes is the single list both handlers work from, so the two can never
// drift apart.
var dataRoutes = []string{
	"GET /v1/releases/current",
	"PUT /v1/releases/current",
	"GET /v1/releases/{release_id}/manifest",
	"GET /v1/firmware/{name}",
	"POST /v1/devices/{device_id}/events",
	"POST /v1/lab/seed",
	"POST /v1/lab/reset",
}

func (s *Server) routePublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /.well-known/course-environment", s.marker)
}

func (s *Server) routeData(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/releases/current", s.currentRelease)
	mux.HandleFunc("PUT /v1/releases/current", s.updateRelease)
	mux.HandleFunc("GET /v1/releases/{release_id}/manifest", s.releaseManifest)
	mux.HandleFunc("GET /v1/firmware/{name}", s.firmware)
	mux.HandleFunc("POST /v1/devices/{device_id}/events", s.deviceEvent)
	mux.HandleFunc("POST /v1/lab/seed", s.seed)
	mux.HandleFunc("POST /v1/lab/reset", s.reset)
}

func courseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Course-Environment", "unsafe-tier-00")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "tier": s.cfg.Tier, "synthetic_data": true})
}

func (s *Server) marker(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": 1,
		"course_id":      s.cfg.CourseID,
		"environment_id": s.cfg.EnvironmentID,
		"tier":           s.cfg.Tier,
		"synthetic_data": true,
	})
}

func (s *Server) currentRelease(w http.ResponseWriter, _ *http.Request) {
	release, err := s.loadRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, release)
}

func (s *Server) updateRelease(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	var release Release
	if err := decodeJSON(r.Body, &release); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.validateRelease(release); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	release.Mutable = true
	release.Signed = false
	if err := s.saveRelease(release); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, release)
}

func (s *Server) releaseManifest(w http.ResponseWriter, r *http.Request) {
	release, err := s.loadRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if r.PathValue("release_id") != release.ReleaseID {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, release)
}

func (s *Server) firmware(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || filepath.Base(name) != name {
		http.Error(w, "invalid firmware name", http.StatusBadRequest)
		return
	}
	release, err := s.loadRelease()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if filepath.Base(release.ImagePath) != name {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.cfg.ReleaseDir, name)
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) deviceEvent(w http.ResponseWriter, r *http.Request) {
	var event map[string]any
	if err := decodeJSON(r.Body, &event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bodyID, _ := event["device_id"].(string)
	if bodyID == "" {
		http.Error(w, "body device_id is required", http.StatusBadRequest)
		return
	}
	event["path_device_id"] = r.PathValue("device_id")
	event["accepted_device_id"] = bodyID
	event["service_received_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	event["tier_00_trust"] = "body_device_id"
	line, err := json.Marshal(event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.cfg.StateDir, "events.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":           true,
		"accepted_device_id": bodyID,
		"warning":            "Tier 0 trusts the JSON body device_id",
	})
}

func (s *Server) seed(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	seedPath := filepath.Join(s.cfg.StateDir, "seed-release.json")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("seed record unavailable: %v", err), http.StatusServiceUnavailable)
		return
	}
	var release Release
	if err := json.Unmarshal(data, &release); err != nil {
		http.Error(w, "seed record malformed", http.StatusInternalServerError)
		return
	}
	if err := s.saveRelease(release); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"seeded": true, "release_id": release.ReleaseID})
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	if !s.markerHeaderMatches(r) {
		http.Error(w, "course environment marker mismatch", http.StatusForbidden)
		return
	}
	_ = os.Remove(filepath.Join(s.cfg.StateDir, "events.jsonl"))
	s.seed(w, r)
}

func (s *Server) markerHeaderMatches(r *http.Request) bool {
	return r.Header.Get("X-Course-Environment-ID") == s.cfg.EnvironmentID
}

func (s *Server) loadRelease() (Release, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var release Release
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "current-release.json"))
	if err != nil {
		return release, fmt.Errorf("current release unavailable: %w", err)
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return release, fmt.Errorf("current release malformed: %w", err)
	}
	return release, nil
}

func (s *Server) saveRelease(release Release) error {
	if err := s.validateRelease(release); err != nil {
		return err
	}
	data, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(filepath.Join(s.cfg.StateDir, "current-release.json"), data, 0o600)
}

func (s *Server) validateRelease(release Release) error {
	if release.SchemaVersion != 1 || release.ReleaseID == "" || release.Version == "" {
		return errors.New("release schema_version, release_id, and version are required")
	}
	if release.ImagePath == "" || filepath.Base(release.ImagePath) != release.ImagePath || strings.Contains(release.ImagePath, "..") {
		return errors.New("image_path must be one file in the release directory")
	}
	info, err := os.Stat(filepath.Join(s.cfg.ReleaseDir, release.ImagePath))
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("manifest-owned firmware image is unavailable")
	}
	return nil
}

func decodeJSON(r io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
