package courseapp

// The build half of Tier 10 (#290): the two releases this tier publishes from
// one source tree, and the teammate's handover patch that only the candidate
// carries.
//
// The firmware is firmware/tier-10-integrated-defense, which is Tier 9's
// remediation behaviour as a committed tree: the support listener is compiled
// out and the TF-PSA-Crypto backport for CVE-2026-50583 is carried. Tier 10
// adds no new control on the device. It is the integration tier, where the
// whole defense is exercised at once by the mixed campaign.
//
// The corrected release at counter 8 builds that tree. The candidate release at
// counter 7 builds a throwaway copy of it with handover/teammate-candidate.patch
// applied, which plants two defects (T10-W-38): the support listener is brought
// back and started before the health gate, and the beacon period is lengthened
// past the health window so the trial times out. The patch is never applied to
// the repository tree, and its sha256 is recorded in the candidate's build
// manifest so the record is honest about what built the image.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// tier10 is the tier's identifier as the CLI spells it after normalizeTier.
const tier10 = "10"

// The two counters. The failed trial at 7 reverts cleanly to Tier 9's 6, and
// because the corrected release is strictly higher, once 8 is primary the
// anti-rollback check refuses the approved-but-bad candidate if it is offered
// again (#287).
const (
	tier10CandidateCounter = 7
	tier10CorrectedCounter = 8
)

// tier10Versions are what imgtool stamps into each image header. They differ so
// a header never says the same for two images that are not the same.
var tier10Versions = map[string]string{
	"candidate": "0.10.0+0",
	"corrected": "0.10.1+0",
}

// tier10Variants are the two releases. Both carry the TF-PSA-Crypto backport.
// Only the candidate carries the handover patch, and only the candidate sits at
// the lower counter: the corrected release is the one that stays on the fleet.
var tier10Variants = map[string]firmwareVariant{
	"candidate": {
		releaseID:       "tier-10-candidate",
		label:           "candidate",
		beaconState:     "steady",
		version:         "0.10.0-candidate",
		imageName:       "tier-10-candidate.bin",
		securityCounter: tier10CandidateCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
		westPatches:     true,
		handoverPatch:   true,
	},
	"corrected": {
		releaseID:       "tier-10-corrected",
		label:           "corrected",
		beaconState:     "steady",
		version:         "0.10.1-corrected",
		imageName:       "tier-10-corrected.bin",
		securityCounter: tier10CorrectedCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
		westPatches:     true,
	},
}

func tier10Variant(name string) (firmwareVariant, error) {
	variant, ok := tier10Variants[name]
	if !ok {
		return firmwareVariant{}, fmt.Errorf("unknown Tier 10 release %q; use candidate or corrected", name)
	}
	return variant, nil
}

// firmwareTierVariant resolves a variant for the tiers that share the Tier 9
// release, SBOM and scan machinery. It keeps each tier's own "unknown release"
// wording.
func (a *app) firmwareTierVariant(tier, name string) (firmwareVariant, error) {
	switch tier {
	case tier09:
		return tier09Variant(name)
	case tier10:
		return tier10Variant(name)
	}
	return firmwareVariant{}, fmt.Errorf("tier %s has no SBOM-bearing releases", tier)
}

func (a *app) tier10BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-10-integrated-defense-"+variant.label)
}

func (a *app) tier10RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier10BuildDir(variant), "tier-10-integrated-defense", "zephyr", "zephyr.bin")
}

// tier10HandoverPatch is the readable patch the teammate handed over, inside the
// application so the Learner reads it next to the code, never a tree-wide search.
func (a *app) tier10HandoverPatch() string {
	return filepath.Join(a.root, firmwareApps[tier10], "handover", "teammate-candidate.patch")
}

// tier10CandidateAppRoot is the throwaway directory the candidate is built from.
// It is under build/, which is gitignored, so the copy is never committed.
func (a *app) tier10CandidateAppRoot() string {
	return filepath.Join(a.root, "build", "tier-10-candidate-app")
}

// tier10AppTree returns the application directory the build uses for this
// variant, repo-relative, and a cleanup function.
//
// The corrected variant builds the committed tree. The candidate copies that
// tree, and firmware/common beside it so the application's ../common reference
// still resolves, applies the handover patch to the copy, and builds that. The
// repository tree is never modified: the two defects live only in the image the
// candidate publishes.
func (a *app) tier10AppTree(variant firmwareVariant) (string, func(), error) {
	committed := firmwareApps[tier10]
	if !variant.handoverPatch {
		return committed, func() {}, nil
	}

	root := a.tier10CandidateAppRoot()
	cleanup := func() { _ = os.RemoveAll(root) }
	if err := os.RemoveAll(root); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", nil, err
	}
	// cp -r keeps the leaf directory names, so the app lands at
	// <root>/tier-10-integrated-defense and ../common resolves to <root>/common.
	appDest := filepath.Join(root, "tier-10-integrated-defense")
	if err := runAttached(a.root, a.out, a.errOut, "cp", "-r",
		filepath.Join(a.root, committed), appDest); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("could not copy the application for the candidate build: %w", err)
	}
	if err := runAttached(a.root, a.out, a.errOut, "cp", "-r",
		filepath.Join(a.root, "firmware", "common"), filepath.Join(root, "common")); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("could not copy the shared module for the candidate build: %w", err)
	}

	patch := a.tier10HandoverPatch()
	fmt.Fprintf(a.out, "+ patch -p1 -d %s -i %s\n", a.relative(appDest), a.relative(patch))
	fmt.Fprintln(a.out, "The candidate is the corrected tree plus the teammate's handover patch. The")
	fmt.Fprintln(a.out, "patch is applied to this copy only; the repository tree is untouched.")
	if err := runAttached(a.root, a.out, a.errOut, "patch", "-p1", "-d", appDest, "-i", patch); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("the handover patch did not apply to the candidate copy: %w", err)
	}

	rel, err := filepath.Rel(a.root, appDest)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return rel, cleanup, nil
}

// writeTier10BuildRecord records the build, the same facts Tier 9 records, plus
// the handover patch for the candidate. The record is what nothing after the
// build can recover: whether the tree was clean, which commits the modules were
// at, and which patches were on the source while it compiled. The candidate's
// source revision names the committed corrected tree, so without the handover
// patch digest the record would misrepresent the candidate as that tree; the
// digest is what keeps it honest (#290).
func (a *app) writeTier10BuildRecord(variant firmwareVariant, buildDir, confPath string, clean bool, revision string) error {
	fragment, err := fileSHA256Hex(confPath)
	if err != nil {
		return err
	}
	record := tier09BuildRecord{
		SchemaVersion:        1,
		ReleaseID:            variant.releaseID,
		Variant:              variant.label,
		BuiltAt:              timeNowUTC(),
		SourceRevision:       revision,
		CleanTree:            clean,
		Application:          firmwareApps[tier10],
		Board:                a.manifest.Devices["reference_beacon"].Board,
		ConfigFragmentSHA256: fragment,
	}
	for _, project := range tier09Projects {
		out, err := exec.Command("git", "-C", filepath.Join(a.zephyrWorkspace(), project.path), "rev-parse", "HEAD").Output()
		if err != nil {
			return fmt.Errorf("cannot read the commit of %s: %w", project.path, err)
		}
		record.Projects = append(record.Projects, tier09Project{project.name, project.path, strings.TrimSpace(string(out))})
	}
	if variant.westPatches {
		patch := filepath.Join(a.root, firmwareApps[tier10], "patches", "tf-psa-crypto", "cve-2026-50583.patch")
		sum, err := fileSHA256Hex(patch)
		if err != nil {
			return err
		}
		record.WestPatches = append(record.WestPatches, tier09AppliedPatch{
			Module: tier09PatchedModule,
			File:   filepath.ToSlash(filepath.Join(firmwareApps[tier10], "patches", "tf-psa-crypto", "cve-2026-50583.patch")),
			SHA256: sum,
			Fixes:  "CVE-2026-50583",
		})
	}
	if variant.handoverPatch {
		sum, err := fileSHA256Hex(a.tier10HandoverPatch())
		if err != nil {
			return err
		}
		record.HandoverPatch = &tier10HandoverRecord{
			File:        filepath.ToSlash(filepath.Join(firmwareApps[tier10], "handover", "teammate-candidate.patch")),
			SHA256:      sum,
			AppliedTo:   "a build-time copy of " + firmwareApps[tier10] + ", not the repository tree",
			Description: "the teammate's handover change (T10-W-38): the support listener returns and starts before the health gate, and the beacon period is lengthened past the health window",
		}
	}
	return writeJSON(filepath.Join(buildDir, "course-build.json"), record, 0o644)
}
