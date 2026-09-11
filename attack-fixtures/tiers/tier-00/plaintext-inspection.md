# Plaintext inspection fixture

Identifier: `tier-00/plaintext-inspection`.

Weakness: The OTA path uses HTTP without confidentiality.

Permitted target: The one literal OTA service origin from generated Course state.

Precondition: The target marker must exactly match `.course-state/environment.json`.

Expected effect: Release fields and manifest-owned synthetic firmware bytes are readable.

Execution: `./course attack run tier-00/plaintext-inspection --execute tier-00/plaintext-inspection`.

Reset: `./course attack reset tier-00/plaintext-inspection`.

Evidence: `artifacts/generated/attacks/tier-00/plaintext-inspection/`.
