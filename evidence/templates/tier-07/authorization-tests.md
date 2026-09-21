# Authorization tests

Copy this file into `evidence/learner/tier-07/` and write in the copy.

| Field | Value |
| --- | --- |
| artifact_id | T7-TESTS-<your initials> |
| artifact_type | verification-evidence |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-07 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 07, synthetic_data true |
| limitations | Thirteen of these rows are host results and they stay host results. They are evidence about your service. `E-7-01` and `E-7-02` are the evidence about your device. |

## Results

The `Observed on` column has three values rather than two. `device` means your board produced it. `host` means the fixture produced it on this machine. `host, board required` means the refusal was read here and a board is what made the row possible at all. That third value narrows nothing: it only records that hardware was needed for the result to exist.

| Evidence ID | Test | Expected result | Observed on | CA key | Actual result | Record state |
| --- | --- | --- | --- | --- | --- | --- |
| E-7-01 | Claim the board: BOOT hold, nonce, operator approval, Operational certificate stored | Succeeds | device | | | pending |
| E-7-02 | Download an assignment and submit a status event on the Operational identity | Succeeds | device | | | pending |
| E-7-03 | Factory certificate at the download endpoint | Refused at `identity-operational` | host | | | pending |
| E-7-04 | Operational certificate at the claim endpoint | Refused at `identity-factory` | host | | | pending |
| E-7-05 | Expired Operational certificate | Refused at `certificate-active`, clause 1 | host | needed | | pending |
| E-7-06 | Revoked Operational certificate | Refused at `certificate-active`, clause 2 | host | | | pending |
| E-7-07 | Certificate signed by the Operational CA that the service never issued | Refused at `certificate-active`, clause 3 | host | needed | | pending |
| E-7-08 | Forged certificate: a recorded serial, the common name of an unclaimed device | Refused at `device-claimed` | host | needed | | pending |
| E-7-09 | Status event whose body identifier disagrees with the path | Refused at `identifier-consistent` | host | | | pending |
| E-7-10 | Forged certificate: the common name of a claimed device, the owner scope of the adversary | Refused at `ownership-context` | host, board required | needed | | pending |
| E-7-11 | Replay a spent claim nonce | Refused at `nonce-unspent` | host, board required | | | pending |
| E-7-12 | Approve after the claim window has closed | Refused at `claim-window-open` | host, board required | | | pending |
| E-7-13 | Wrong nonce inside an open window | Refused at `nonce-match` | host, board required | | | pending |
| E-7-14 | The adversary approves the correct nonce on an already-claimed device | Refused at `device-unowned` | host, board required | | | pending |
| E-7-15 | Client certificate from a foreign issuer | The handshake closes. No status, no body, no check, nothing in the trail | host | | | pending |

Fill in the actual result from your own run. A row becomes `observed` when you have run it, and `E-7-01` and `E-7-02` become `observed` only from the board.

## Where the runners wrote their records

| Field | Value |
| --- | --- |
| Evidence records written by the runners |  |
| The service's own trail |  |
| Lines in the trail before `E-7-15` |  |
| Lines in the trail after `E-7-15` |  |

The evidence for `E-7-15` is that there is no evidence, which is why the row counts the trail before and after. Record both numbers even when they are the same, because that is the result.

## The four rows signed with your own authority key

Four rows sign with your own Operational Device CA key. They show what an insider with the authority's private half can make, which is a different threat from what an outsider on your network can make.

| Evidence ID | What the insider made | What the service still refused | Why |
| --- | --- | --- | --- |
|  |  |  |  |

## The pair to sit with

Both `E-7-05` and `E-7-15` are correct refusals of a certificate. Only one of them can tell anybody what went wrong.

| Field | E-7-05 | E-7-15 |
| --- | --- | --- |
| Layer that refused |  |  |
| Check name |  |  |
| What the service recorded |  |  |
| What a fleet operator learns |  |  |
