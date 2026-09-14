package courseapp

import (
	"fmt"
	"os/exec"
	"strings"
)

// Tier 5 makes an install recoverable, and its five releases differ only in
// what happens between the trial boot and the confirmation.
//
// Tier 3 and Tier 4 requested a permanent upgrade on purpose: the swap
// happened, the image ran, and nothing ever asked whether it worked. Section 6
// fixes that from Tier 5 the application requests BOOT_UPGRADE_TEST and never
// a permanent upgrade, so every install is on trial until the device itself
// decides otherwise.
//
// The fallback path has physically existed since Tier 0, because the course
// pins swap-using-offset in every tier. No tier has ever taken it. T0-W-07 has
// been open since Tier 0 saying exactly that, and this is the tier that closes
// it.
// tier05Version is deliberately absent until the signing path needs it.
//
// Tier 4 declared tier04Version, never wired it to imgtool, and shipped an
// image whose --version was wrong. An unused Go constant does not fail a
// build, so the only protection is not to write one down before the code that
// consumes it exists. It arrives with ./course release sign for this tier.

const (
	// Every Tier 5 release carries the same security counter, and that is a
	// decision rather than an oversight.
	//
	// These five images exist to test the trial path. A differing counter
	// would let the bootloader's downgrade prevention refuse one of them
	// before its trial ever started, and the tier would be demonstrating
	// Tier 4's control by accident instead of its own. Section 6 allows an
	// equal counter for an ordinary feature release in as many words.
	//
	// It is one above Tier 4's security-fix release, because a device running
	// that release must be able to accept these.
	tier05SecurityCounter = tier04SecurityCounter + 2

	// How long the device has to prove itself healthy. Section 6 fixes 60
	// seconds. It reaches the build as CONFIG_COURSE_HEALTH_GATE_SECONDS,
	// which defaults to the same value, so a build that never sets it is
	// still correct.
	tier05HealthGateSeconds = 60
)

// tier05Variants are the five releases Tier 5 produces.
//
// Four of them do not work, and none of them is hostile. Nobody without the
// Release signing key can produce any of these, so an unhealthy release is the
// manufacturer publishing something broken, which section 11 names beside the
// attacks in its threat list. The device cannot tell a broken release from a
// leaked key, and it recovers from either the same way.
//
// Each needs its own release_id. A prepared release that reuses one the device
// has already seen is shrugged off, and a device carrying on unchanged looks
// exactly like a control working.
var tier05Variants = map[string]firmwareVariant{
	"healthy": {
		releaseID:       "tier-05-healthy",
		label:           "healthy",
		beaconState:     "steady",
		version:         "0.5.0-recoverable",
		imageName:       "tier-05-healthy.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "healthy",
	},
	"crash": {
		releaseID:       "tier-05-crash",
		label:           "crash",
		beaconState:     "steady",
		version:         "0.5.1-crash",
		imageName:       "tier-05-crash.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "crash",
	},
	"hang": {
		releaseID:       "tier-05-hang",
		label:           "hang",
		beaconState:     "steady",
		version:         "0.5.2-hang",
		imageName:       "tier-05-hang.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "hang",
	},
	"fail-health": {
		releaseID:       "tier-05-fail-health",
		label:           "fail-health",
		beaconState:     "steady",
		version:         "0.5.3-fail-health",
		imageName:       "tier-05-fail-health.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "fail-health",
	},
	"timeout-health": {
		releaseID:       "tier-05-timeout-health",
		label:           "timeout-health",
		beaconState:     "steady",
		version:         "0.5.4-timeout-health",
		imageName:       "tier-05-timeout-health.bin",
		securityCounter: tier05SecurityCounter,
		trialBehaviour:  "timeout-health",
	},
}

// trialBehaviourSymbols maps a variant's trial behaviour to the Kconfig symbol
// that selects it.
//
// The map is the single place the two vocabularies meet. A behaviour with no
// symbol is a build error rather than a silently healthy image, which is the
// failure that would be hardest to notice: an image that was meant to crash
// and instead confirms looks like the recovery path working.
var trialBehaviourSymbols = map[string]string{
	"healthy":        "CONFIG_COURSE_TRIAL_HEALTHY",
	"crash":          "CONFIG_COURSE_TRIAL_CRASH",
	"hang":           "CONFIG_COURSE_TRIAL_HANG",
	"fail-health":    "CONFIG_COURSE_TRIAL_FAIL_HEALTH",
	"timeout-health": "CONFIG_COURSE_TRIAL_TIMEOUT_HEALTH",
}

func trialBehaviourSymbol(behaviour string) (string, error) {
	if behaviour == "" {
		return "", fmt.Errorf("a Tier 5 variant must name a trial behaviour")
	}
	symbol, ok := trialBehaviourSymbols[behaviour]
	if !ok {
		return "", fmt.Errorf("unknown Tier 5 trial behaviour %q", behaviour)
	}
	return symbol, nil
}

// sourceRevision reports the git revision this build came from, with -dirty
// appended when the working tree has uncommitted changes, exactly as
// git describe --dirty reports it.
//
// A dirty tree gets the suffix rather than a refusal to build. The Learner's
// forked repository will be dirty almost all the time, because editing it is
// the exercise, and refusing to build until they commit is a rule the course
// has no business imposing. The value degrades honestly instead: it says it
// does not identify a commit.
//
// Failure to run git at all is not an error either. A Learner may have
// unpacked the course rather than cloned it, and an image that will not build
// without a git checkout would be a worse outcome than one that says it does
// not know where it came from.
func (a *app) sourceRevision() string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = a.root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	revision := strings.TrimSpace(string(out))
	if revision == "" {
		return "unknown"
	}

	// --quiet exits non-zero when there is a difference, which is the
	// question being asked, so a non-nil error here is the answer and not a
	// failure.
	dirty := exec.Command("git", "diff", "--quiet", "HEAD")
	dirty.Dir = a.root
	if dirty.Run() != nil {
		revision += "-dirty"
	}
	return revision
}
