# SBOM review

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-SBOM-<your initials> |
| artifact_type | sbom-review |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | An SBOM describes what the build says it used. It is not proof of what runs on the board, and it cannot name code that has no identity in any database. |

## The two SBOMs and the build manifest

The firmware SBOM belongs to one release. The service SBOM describes the OTA service, which is not part of any firmware release.

| Field | Firmware, counter 5 | Firmware, counter 6 | OTA service |
| --- | --- | --- | --- |
| Command you ran |  |  |  |
| File it wrote |  |  |  |
| Format and version |  |  |  |
| sha256 of the file |  |  |  |
| Number of components |  |  |  |

| Field | Value |
| --- | --- |
| Build manifest file for counter 6 |  |
| Source revision it records |  |
| Does that revision match your `git rev-parse --short HEAD` |  |
| Its `clean_tree` value |  |
| Image digest it records |  |
| Image digest of the file in the release store |  |

## The components

One row per component. Read each value out of the SBOM, not out of the course text. Write `none` where the SBOM gives no value.

| Component | Version in the SBOM | purl | CPE | Component type | In the image, and how you know |
| --- | --- | --- | --- | --- | --- |
| Zephyr |  |  |  |  |  |
| MCUboot |  |  |  |  |  |
| Mbed TLS |  |  |  |  |  |
| TF-PSA-Crypto |  |  |  |  |  |
| hal_espressif |  |  |  |  |  |
| wpa_supplicant, Espressif fork |  |  |  |  |  |
| TinyCrypt |  |  |  |  |  |
| Espressif precompiled Wi-Fi libraries |  |  |  |  |  |
| Go standard library |  |  |  |  |  |
| gopkg.in/yaml.v3 |  |  |  |  |  |

Add a row for every component the SBOM lists that is not here. Delete no row, even when the SBOM does not list that component, because a missing component is a finding.

## What the SBOM does and does not tell a scanner

A scanner links a C component to an advisory only through a CPE. A VEX statement binds to a component only through its purl. Answer each question from the file.

| Question | Your answer |
| --- | --- |
| Does every C component carry a purl |  |
| Does every C component carry a CPE |  |
| Which component type does Zephyr have, and why does it matter to grype |  |
| How does the service SBOM spell the Go standard library's version |  |
| What differs between the counter 5 and counter 6 SBOMs |  |

## Listed but not in the image

Name one component an SBOM lists that the image does not contain. Say how you proved it from the build, for example from the `.config`, the compile commands or the link map.

| Component | Where it is listed | Why it is not in the image | Evidence you used |
| --- | --- | --- | --- |
|  |  |  |  |

## What no scanner can see

Give one example from this build for each kind. These are the places where a clean scan is not a clean product.

| Kind | Example in this build | How you would find it without a scanner |
| --- | --- | --- |
| The manufacturer's own code |  |  |
| A component with no identity in any vulnerability database |  |  |
| An advisory that the database has not processed yet |  |  |

## Record state

| Field | Value |
| --- | --- |
| Build you generated them from |  |
| Record state | pending until you have generated both firmware SBOMs from your own build |
