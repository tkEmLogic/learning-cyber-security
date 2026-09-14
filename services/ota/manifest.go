package ota

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The Release manifest is a separate object from the Update assignment, and
// this file is deliberately the only place that touches it.
//
// CONTEXT.md already draws the line. An Update assignment is "the OTA service's
// choice of which release, if any, a specific device should install. It refers
// to a release manifest but does not change the signed release." A Release
// manifest is "immutable, manufacturer-signed metadata that describes one
// firmware release". Until now the service had one mutable record doing both
// jobs, and `/v1/releases/{release_id}/manifest` re-marshalled that record from
// a Go struct.
//
// Re-marshalling is the bug. The signature covers the exact bytes that were
// signed, so reformatting the JSON without changing a single value breaks
// verification. That is not a flaw to engineer around with a canonicalization
// scheme, it is the reason the manifest is treated as bytes end to end: the
// build signs bytes, the service stores and serves those same bytes, and the
// device verifies them before it parses them.
//
// So nothing here unmarshals a manifest. The service never parses one, never
// validates one, and never holds the Release signing key, exactly as CONTEXT.md
// says of the OTA service. A manifest the service cannot read is a manifest the
// service cannot quietly corrupt.

// manifestSuffix and signatureSuffix name the two files that make up one
// stored release manifest. They live beside the firmware image in the release
// directory, because they are release artifacts in the same sense the image is.
const (
	manifestSuffix  = ".manifest.json"
	signatureSuffix = ".manifest.sig"
)

// manifestPath and signaturePath map a release identifier onto stored files.
// Both go through validReleaseID first, so no request can walk out of the
// release directory.
func (s *Server) manifestPath(releaseID string) string {
	return filepath.Join(s.cfg.ReleaseDir, releaseID+manifestSuffix)
}

func (s *Server) signaturePath(releaseID string) string {
	return filepath.Join(s.cfg.ReleaseDir, releaseID+signatureSuffix)
}

// validReleaseID keeps a path parameter from becoming a path. Go's router will
// not match a `/` inside one segment, but `..` is a perfectly ordinary segment,
// so the allowlist is spelled out rather than assumed.
func validReleaseID(id string) bool {
	if id == "" || len(id) > 128 || strings.Contains(id, "..") {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// releaseManifest serves the stored manifest bytes verbatim.
//
// Any stored manifest is served, not only the one the current assignment points
// at. A release is immutable and the assignment is a pointer at one of them, so
// asking for an older release's manifest is a reasonable question with a
// truthful answer. It is also the question the downgrade lab asks.
func (s *Server) releaseManifest(w http.ResponseWriter, r *http.Request) {
	releaseID := r.PathValue("release_id")
	if !validReleaseID(releaseID) {
		http.Error(w, "invalid release_id", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Course-Manifest-Signature", "/v1/releases/"+releaseID+"/manifest.sig")
	s.serveStoredBytes(w, r, s.manifestPath(releaseID), "application/json", releaseID,
		"no signed release manifest is stored for this release")
}

// releaseManifestSignature serves the detached signature alongside the bytes it
// covers. It is raw ASN.1 DER over SHA-256 of the manifest bytes, produced by
// the offline Release signing key, and it is served as opaque bytes for the
// same reason the manifest is.
func (s *Server) releaseManifestSignature(w http.ResponseWriter, r *http.Request) {
	releaseID := r.PathValue("release_id")
	if !validReleaseID(releaseID) {
		http.Error(w, "invalid release_id", http.StatusBadRequest)
		return
	}
	s.serveStoredBytes(w, r, s.signaturePath(releaseID), "application/octet-stream", releaseID,
		"no detached manifest signature is stored for this release")
}

// serveStoredBytes hands the open file to http.ServeContent, which is what
// makes this byte-exact: nothing decodes, re-encodes, pretty-prints, or reorders
// anything between the stored file and the socket. Range requests come along
// for free, on the same code path the firmware download already uses.
func (s *Server) serveStoredBytes(w http.ResponseWriter, r *http.Request, path, contentType, releaseID, missing string) {
	file, err := os.Open(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":      missing,
			"release_id": releaseID,
			"why": "the Release manifest is published by whoever holds the Release signing key, " +
				"not by this service; the service stores the signed bytes and serves them unchanged",
		})
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, fmt.Sprintf("stored release artifact unavailable: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, "", info.ModTime(), file)
}
