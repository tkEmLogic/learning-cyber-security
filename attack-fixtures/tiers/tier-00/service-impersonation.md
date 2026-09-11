# Service impersonation fixture

Identifier: `tier-00/service-impersonation`.

Weakness: Generated device configuration uses HTTP and has no server authentication.

Permitted target: The manifest-owned local impersonation port on the selected local interface.

Precondition: The real service marker must match before the fixture starts its marker-matching imitation.

Expected effect: Generated device configuration reads the hostile mutable release record.

Refused behavior: The fixture does not change ARP, DNS, gateways, privileged ports, or unrelated services.

Execution: `./course attack run tier-00/service-impersonation --execute tier-00/service-impersonation`.

Reset: `./course attack reset tier-00/service-impersonation`.

Evidence: `artifacts/generated/attacks/tier-00/service-impersonation/`.
