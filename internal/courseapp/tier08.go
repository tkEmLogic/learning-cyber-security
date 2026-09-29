package courseapp

// Tier 8 manages a device's life after its first claim: renewal, recovery,
// revocation, transfer and decommissioning, all written to the one lifecycle
// log that internal/lifecycle derives state from.
//
// This file is the scaffolding the tier's other files hang off. The firmware
// half is tier08_firmware.go.

// tier08 is the tier's identifier as the CLI spells it after normalizeTier.
const tier08 = "08"
