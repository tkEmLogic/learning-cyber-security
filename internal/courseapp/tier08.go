package courseapp

import "errors"

// Tier 8 manages a device's life after its first claim: renewal, recovery,
// revocation, transfer and decommissioning, all written to the one lifecycle
// log that internal/lifecycle derives state from.
//
// This file is the scaffolding the tier's later tickets hang off. The service
// half of the log is built, and the tier has no firmware yet. So every
// firmware command answers --tier 08 with a refusal that says so, rather than
// falling through to an older tier's image: offering a Tier 7 image as a Tier
// 8 one is the shortcut this course does not take.
//
// When the firmware lands, firmwareApps gains its directory, tier08Variants
// its releases, and the tier joins the conditions in writeFirmwareConfig and
// buildFirmware that list Tier 7. Then tier08NoFirmware and its four callers
// go.

// tier08 is the tier's identifier as the CLI spells it after normalizeTier.
const tier08 = "08"

// tier08Variants is empty until the Tier 8 firmware exists.
var tier08Variants = map[string]firmwareVariant{}

var tier08NoFirmware = errors.New("tier 08 has no firmware yet, so there is no Tier 8 image to build, sign, assign or flash")
