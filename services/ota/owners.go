package ota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

// The Owner credential store, read live on every operator request.
//
// Live rather than loaded at startup, because the alternative produces the
// worst failure a lab can have: the Learner mints an owner, the claim is
// refused, and nothing in the refusal hints that restarting the service is the
// fix. It also matches the replay discipline the record store already uses,
// and the file holds two lines.
//
// The store is the host CLI's to write and the service's to read, so the shape
// is spelled here as well as there. That is the same boundary provisioning.go
// crosses, and for the same reason: nothing under services/ depends on
// internal/.

// ownerEntry is the subset of one owners.jsonl line the service reads.
type ownerEntry struct {
	Kind               string `json:"kind"`
	OwnerID            string `json:"owner_id"`
	CredentialID       string `json:"credential_id"`
	CredentialVerifier string `json:"credential_verifier"`
	CredentialExpires  string `json:"credential_expires"`
}

const ownerEntryKind = "owner_credential_issued"

// ownerStore answers the three owner-credential checks out of
// `.course-state/provisioning/owners.jsonl`.
type ownerStore struct {
	dir string
	now func() time.Time
}

// VerifyOwner authenticates a bearer credential and returns the owner it
// belongs to.
//
// There is no session and no login exchange. A single credential presentation
// on the one request that needs it delivers an authenticated owner, and the
// handler derives the owner from the credential rather than from a field in
// the body, exactly as the device listener derives the device from the client
// certificate rather than from a JSON key.
//
// The three checks run in one order and each answers 401, because not knowing
// who is asking is a different answer from knowing and refusing. Everything
// else in this tier is the second kind.
func (s ownerStore) VerifyOwner(credential string) (string, *Refusal) {
	if credential == "" {
		return "", &Refusal{
			Check:  CheckOwnerCredentialKnown,
			Reason: "this endpoint needs an Owner credential in an Authorization: Bearer header",
		}
	}
	presented := ownerVerifierFor(credential)
	entries := s.read()

	var matched *ownerEntry
	for i := range entries {
		if entries[i].CredentialVerifier == presented {
			matched = &entries[i]
		}
	}
	if matched == nil {
		// Silent about how many owners exist and about which one was close.
		return "", &Refusal{
			Check:  CheckOwnerCredentialKnown,
			Reason: "no owner in this environment holds the credential presented",
		}
	}

	// Re-minting supersedes rather than resets: the store is append only and
	// the last credential for an owner is the one that authenticates. That is
	// replacement, and it is deliberately not revocation, which is Tier 8.
	current := matched
	for i := range entries {
		if entries[i].OwnerID == matched.OwnerID {
			current = &entries[i]
		}
	}
	if current.CredentialID != matched.CredentialID {
		return "", &Refusal{
			Check: CheckOwnerCredentialCurrent,
			Reason: fmt.Sprintf("the credential presented for owner %s was superseded by a later one",
				matched.OwnerID),
		}
	}

	expires, err := time.Parse(time.RFC3339, matched.CredentialExpires)
	if err != nil {
		return "", &Refusal{
			Check: CheckOwnerCredentialValid,
			Reason: fmt.Sprintf("the credential presented for owner %s carries no readable expiry",
				matched.OwnerID),
		}
	}
	if s.clock().After(expires) {
		// Nothing consumes an Owner credential, so a lifetime is the only
		// bound it has. Ninety days, checked here, and the module says that a
		// credential with no expiry is the standing secret this tier argues
		// against.
		return "", &Refusal{
			Check: CheckOwnerCredentialValid,
			Reason: fmt.Sprintf("the credential presented for owner %s expired at %s",
				matched.OwnerID, expires.UTC().Format(time.RFC3339)),
		}
	}
	return matched.OwnerID, nil
}

func (s ownerStore) read() []ownerEntry {
	var entries []ownerEntry
	forEachJSONLine(filepath.Join(s.dir, "owners.jsonl"), func(line []byte) {
		var entry ownerEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return
		}
		if entry.Kind != ownerEntryKind || entry.OwnerID == "" {
			return
		}
		entries = append(entries, entry)
	})
	return entries
}

func (s ownerStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// ownerVerifierFor is the host side's verifierFor, spelled again on this side
// of the boundary. A hash, not an HMAC: a symmetric construction would put a
// live secret in a store whose whole purpose is to hold none.
//
// The comparison is over a hash rather than over the secret, which is why an
// ordinary string comparison is enough here.
func ownerVerifierFor(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return "sha256:" + hex.EncodeToString(sum[:])
}
