# Support statement

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-SUPPORT-<your initials> |
| artifact_type | support-statement |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | The Support period here belongs to a fictional product. Whether five years matches how long a real product is expected to be in use is for product-specific legal review. Neither the device nor the service refuses anything on a date. |

## The facts the course has fixed

| Fact | Value |
| --- | --- |
| Manufacturer | Harbor Devices Ltd, Cork, Ireland (fictional) |
| Product first placed on the market | March 2027 |
| End of the Support period | end of March 2032 |
| Security updates | free of charge |
| How long each issued security update stays available | at least ten years after it is issued, or the rest of the Support period, whichever is longer |

## The statement

Write the statement a customer reads at the time of purchase. Use plain words. It must say, at least:

- the end of the Support period, as a month and a year;
- that security updates are free of charge;
- how long each security update stays available after it is issued;
- how a device receives updates, and what the customer must do for that to happen;
- what happens to a device that never contacts the update service.

Your text:

## Why five years

Write how the Support period was set. Name what Harbor Devices considered, such as how long customers expect to use the product and the support periods of the components it depends on. Article 13(8) of the CRA lists what a manufacturer considers.

| Consideration | What you took into account |
| --- | --- |
| How long customers expect to use the product |  |
| Support periods of the components with core functions |  |
| Comparable products |  |
| Anything that argues for a longer period |  |

## The unsupported component you found

| Field | Value |
| --- | --- |
| Component |  |
| Why its supplier no longer fixes the version in use |  |
| Vulnerability record that covers it |  |
| What moves the product to a supported version |  |

## The open finding: `supported_until`

Every signed release manifest carries a `supported_until` field. Read it in the manifests for counter 5 and counter 6, then compare it with the Support period above.

| Field | Value |
| --- | --- |
| `supported_until` in the counter 5 manifest |  |
| `supported_until` in the counter 6 manifest |  |
| How the value is computed, and where in the source |  |
| Does the device check it |  |
| How it differs from the Support period |  |
| What a customer could wrongly believe from it |  |

Record this as an open finding. The course does not change it in code.

## Devices that never poll

A device that never contacts the update service stays on the version it has, including a vulnerable one. Write what the statement tells users about this, and name the residual risk it matches.

Your text:
