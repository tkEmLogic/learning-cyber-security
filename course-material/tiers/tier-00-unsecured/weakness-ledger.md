# Tier 0 Weakness ledger

| Identifier | Weakness | Fixture | Result | Status | Planned tier |
| --- | --- | --- | --- | --- | --- |
| T0-W-01 | HTTP reveals metadata and firmware | `tier-00/plaintext-inspection` | Insecure effect observed on host | Open | Tier 2 |
| T0-W-02 | Service trusts the body device identifier | `tier-00/device-id-spoofing` | Insecure effect observed on host | Open | Tier 7 |
| T0-W-03 | Device configuration trusts an unauthenticated service | `tier-00/service-impersonation` | Insecure effect observed on host | Open | Tier 2 |
| T0-W-04 | Unsigned altered image is delivered | `tier-00/altered-image` | Host delivery observed, device execution pending | Open | Tier 3 |
| T0-W-05 | Release record is mutable | `tier-00/altered-image` | Insecure effect observed on host | Open | Tier 4 |
| T0-W-06 | No anti-rollback policy exists | Not executed in Tier 0 | Not tested | Open | Tier 4 |
| T0-W-07 | No test-boot confirmation or recovery proof exists | Hardware required | Pending | Open | Tier 5 |
