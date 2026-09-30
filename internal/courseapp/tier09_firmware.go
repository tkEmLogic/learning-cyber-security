package courseapp

// The build half of Tier 9: the two releases this tier publishes, and the
// West patch that only the second one carries (#278).
//
// The firmware is firmware/tier-09-vulnerability-support, Tier 8's
// application with one addition and one removal. The support-listener release
// at counter 5 adds an unauthenticated UDP support listener (#269, T9-W-34).
// The remediation release at counter 6 compiles it out, and carries the
// TF-PSA-Crypto fix for CVE-2026-50583 (#275). It reads a Tier 8 board's
// storage unchanged, so an update from Tier 8 keeps both identities.

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// tier09 is the tier's identifier as the CLI spells it after normalizeTier.
const tier09 = "09"

// The two counters. Section 7 moves a device off a vulnerable version by a
// signed release at a higher counter, so the remediation is one above the
// release it replaces, and a device that installs it refuses that release.
const (
	tier09SupportCounter     = 5
	tier09RemediationCounter = 6
)

// tier09Versions are what imgtool stamps into each image header. Tier 8 had
// one version for all its releases; Tier 9's two differ in what they contain,
// and a header that said the same for both would hide it.
var tier09Versions = map[string]string{
	"support-listener": "0.9.0+0",
	"remediation":      "0.9.1+0",
}

// tier09Variants are the two releases, from one source tree. Neither is a
// lab image: the first is what the manufacturer shipped without knowing, and
// the second is what it ships once it does.
var tier09Variants = map[string]firmwareVariant{
	"support-listener": {
		releaseID:       "tier-09-support-listener",
		label:           "support-listener",
		beaconState:     "steady",
		version:         "0.9.0-support-listener",
		imageName:       "tier-09-support-listener.bin",
		securityCounter: tier09SupportCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
		supportListener: true,
	},
	"remediation": {
		releaseID:       "tier-09-remediation",
		label:           "remediation",
		beaconState:     "steady",
		version:         "0.9.1-remediation",
		imageName:       "tier-09-remediation.bin",
		securityCounter: tier09RemediationCounter,
		trialBehaviour:  "healthy",
		identityModel:   "factory",
		westPatches:     true,
	},
}

func tier09Variant(name string) (firmwareVariant, error) {
	variant, ok := tier09Variants[name]
	if !ok {
		return firmwareVariant{}, fmt.Errorf("unknown Tier 9 release %q; use support-listener or remediation", name)
	}
	return variant, nil
}

func (a *app) tier09BuildDir(variant firmwareVariant) string {
	return filepath.Join(a.zephyrWorkspace(), "build", "tier-09-vulnerability-support-"+variant.label)
}

func (a *app) tier09RawImage(variant firmwareVariant) string {
	return filepath.Join(a.tier09BuildDir(variant), "tier-09-vulnerability-support", "zephyr", "zephyr.bin")
}

// tier09PatchedModule is the one module the remediation build patches,
// relative to the Zephyr workspace, as patches.yml names it.
const tier09PatchedModule = "modules/crypto/tf-psa-crypto"

// tier09PatchArgs are the west patch options every call shares: the patch
// files and their list live in the Tier 9 application, not in Zephyr, and
// only the one module is touched.
func (a *app) tier09PatchArgs() []string {
	appDir := filepath.Join(a.root, firmwareApps[tier09])
	return []string{"patch",
		"-b", filepath.Join(appDir, "patches"),
		"-l", filepath.Join(appDir, "patches.yml"),
		"-dm", tier09PatchedModule}
}

// tier09ModuleClean refuses to build either Tier 9 release on a patched
// module. A remediation build that died between apply and clean would
// otherwise leave the fix in place, and the next support-listener build would
// silently carry it: the vulnerable release would not be the vulnerable
// release, and nothing would say so.
func (a *app) tier09ModuleClean() error {
	dir := filepath.Join(a.zephyrWorkspace(), tier09PatchedModule)
	out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return fmt.Errorf("cannot read the state of %s: %w", dir, err)
	}
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("%s has local changes, so it is not the tree Zephyr pins; "+
			"run west %s clean in %s and build again",
			tier09PatchedModule, strings.Join(a.tier09PatchArgs(), " "), a.zephyrWorkspace())
	}
	return nil
}

// withTier09Patches runs build with the West patch applied, when the variant
// carries one, and always cleans it afterwards, including when the build
// fails. The shared workspace is patched only while this one image builds.
func (a *app) withTier09Patches(variant firmwareVariant, build func() error) error {
	if err := a.tier09ModuleClean(); err != nil {
		return err
	}
	if !variant.westPatches {
		return build()
	}
	workspace := a.zephyrWorkspace()
	west := filepath.Join(workspace, ".venv", "bin", "west")
	args := a.tier09PatchArgs()
	fmt.Fprintf(a.out, "+ west %s apply\n", strings.Join(args, " "))
	if err := runAttachedFrom(a.root, workspace, a.out, a.errOut, nil, west, append(args, "apply")...); err != nil {
		return fmt.Errorf("the CVE-2026-50583 patch did not apply: %w", err)
	}
	buildErr := build()
	fmt.Fprintf(a.out, "+ west %s clean\n", strings.Join(args, " "))
	if err := runAttachedFrom(a.root, workspace, a.out, a.errOut, nil, west, append(args, "clean")...); err != nil {
		if buildErr != nil {
			return buildErr
		}
		return fmt.Errorf("the image built, but the patch was not cleaned from %s: %w", tier09PatchedModule, err)
	}
	return buildErr
}

// releaseSignTier09 signs one Tier 9 release and publishes it, by Tier 7's
// sequence unchanged.
func (a *app) releaseSignTier09(variantName string) error {
	variant, err := tier09Variant(variantName)
	if err != nil {
		return err
	}
	release, err := a.signTierRelease(tier09, variant, a.tier09RawImage(variant), tier09Versions[variant.label])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Result: published %s, %d bytes\n", variant.releaseID, release["image_size"])
	fmt.Fprintf(a.out, "Its counter is %d. A device running it refuses every release below that.\n",
		variant.securityCounter)
	return nil
}

// releaseAssignTier09 points the service at a Tier 9 release that is already
// signed.
func (a *app) releaseAssignTier09(variantName string) error {
	variant, err := tier09Variant(variantName)
	if err != nil {
		return err
	}
	return a.assignTierRelease(tier09, variant)
}

// kconfigBool spells a Go bool the way a Kconfig fragment does.
func kconfigBool(on bool) string {
	if on {
		return "y"
	}
	return "n"
}
