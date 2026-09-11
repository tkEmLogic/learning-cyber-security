# Altered-image fixture

Identifier: `tier-00/altered-image`.

Weakness: The release record is mutable and MCUboot is configured for unsigned images.

Permitted input: The fixture creates only `artifacts/generated/releases/tier-00-altered.bin`.

Precondition: The target marker must match.

Expected host effect: The service publishes and returns the generated altered image, then reset restores the baseline release.

Hardware limit: Device acceptance, execution, LED behavior, and serial output remain pending without a physical ESP32-C6.

Execution: `./course attack run tier-00/altered-image --execute tier-00/altered-image`.

Reset: `./course attack reset tier-00/altered-image`.

Evidence: `artifacts/generated/attacks/tier-00/altered-image/`.
