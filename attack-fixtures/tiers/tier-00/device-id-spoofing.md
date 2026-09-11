# Device-ID spoofing fixture

Identifier: `tier-00/device-id-spoofing`.

Weakness: The Tier 0 event endpoint trusts the JSON body `device_id`.

Permitted target: The one literal OTA service origin from generated Course state.

Precondition: The target marker must match and the spoofed identifier must come from `course.yml`.

Expected effect: The service accepts the manifest-owned clone identifier even when the path names the shared development identifier.

Execution: `./course attack run tier-00/device-id-spoofing --execute tier-00/device-id-spoofing`.

Reset: `./course attack reset tier-00/device-id-spoofing`.

Evidence: `artifacts/generated/attacks/tier-00/device-id-spoofing/`.
