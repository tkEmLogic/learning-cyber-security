# Tier 1 answers

This page holds the finished answers to the four Tier 1 Predict questions and to the two Tier 1 exercises.

Do not read it before you have written your own answer. A partial answer that you wrote is worth more than a complete one that you read, because the difference between the two is the only thing this tier can teach you.

When you have written your answer, read the matching section here and mark every place the two differ. Do not copy this page into your worksheet. Write down the differences instead.

This is one worked model. It is not the only correct one. If you think something here is wrong, write down why and take it to your Mentor review gate.

## Predict answers

The Tier 1 page asks four questions before the exercises begin. They are answered here, and the answers use the finished model further down this page, so read this section only after your own model is written.

**1. Noticed first, and never noticed at all.** A factory customer notices `T0-W-07` first. It is the only weakness in the ledger whose scenario has no attacker in it: `MS-06` is power lost during an overwrite install, or an installed image that crashes on start, and `R-06` records the result as a device that no longer starts and cannot be recovered remotely. A beacon that has stopped working is visible from across the floor. The customer never notices `T0-W-01`. Reading the release record and downloading the image is one ordinary request that the service is happy to answer, it changes nothing on the device, and `MS-01` harms no protected asset, so there is nothing for anyone to see afterwards.

**2. Least effort for the attacker.** `T0-W-01` again. It costs one unauthenticated request from anywhere on the same network, with no exploit, no credential and no device. That is why `R-01` records what the actor achieves as full knowledge of the update path before attacking it, and why `MS-01` is written down although it harms no asset: it lowers the cost of every other scenario in the register.

**3. Closed on its own, removes the most attacker outcomes.** `T0-W-04`, that MCUboot accepts unsigned images. It is one of only two weaknesses that appear in more than one misuse scenario, `MS-04` and `MS-08`, and those two carry the worst outcomes in the register: `R-04` is permanent attacker-chosen code execution on every device from one request, and `R-08` is fleet-wide code execution from a compromised server. The register treats `R-08` in Tier 3 alone, which is the tier that closes this weakness. Close it and an attacker who rewrites the release record, or who owns the service host outright, can still make a device install an older release that you published yourself, which is `R-05`. They can no longer choose the code that runs. The boundary table on the Tier 1 page says why one control carries that much: boundary 3 belongs to MCUboot and to nothing else, because MCUboot is the last component that can refuse.

**4. The asset no Tier 0 attack touched.** `A-02`, the firmware signing key, because the Reference product has no signing key in Tier 0 and no scenario can name an asset that does not exist. The section [The asset no scenario touches](#the-asset-no-scenario-touches) below holds the answer and the reason it matters, and it is worth reading there rather than here.

The wrong answer engineers give most often is to question 3, and it is `T0-W-03`, that the device trusts an unauthenticated service. It is the weakness that feels most like the attack, because an imposter answering at the address is the Tier 0 attack people remember. Closing it authenticates the sender and says nothing about what was sent. `R-08` is the row that shows the difference: a hosting attacker publishes from the genuine service, over a connection the device verifies, and an authenticated transport hands them the fleet rather than stopping them.

## Exercise 1 answer: one observation, one threat

The observation was the second step of the altered-image fixture. The attacker overwrote the record that decides which firmware every device installs, and the service accepted the change without asking who sent it.

Each hop below shows a wrong version first. The wrong versions are not strawmen. They are the answers that engineers write most often, and each one fails for a reason worth knowing.

### Hop 1: the asset

Wrong: the OTA service.

Right: firmware authenticity and integrity.

The service is a component, not an asset. An asset is something of value that an attacker can harm. Naming a component tells you where the attack happened. Naming the asset tells you what it cost. Only the second one can be traded off, insured, or accepted as a risk.

### Hop 2: the actor

Wrong: a hacker.

Right: a local attacker who can reach the update service on the factory network, or a hosting attacker who has compromised the machine that runs it. Neither needs a credential, because the service asks for none. The local attacker needs a route to port 8080. The hosting attacker already has one.

"A hacker" names no access, so it cannot be designed against. Every useful actor statement names what the actor can already reach, because that is what a control has to take away.

### Hop 3: the misuse scenario

Wrong: the release record is mutable.

Right: a local attacker who can reach the update service replaces the current release record with one that names their own image, so that every beacon in the factory downloads and runs firmware the attacker wrote.

The wrong version is the weakness, which you already knew. A misuse scenario adds the three things the weakness does not carry: who does it, what they have to reach, and what happens to the customer at the end. Write it in one sentence in the form "a given actor with given access does something so that some outcome follows". If you cannot finish that sentence, you do not yet have a scenario.

### Hop 4: the risk

Wrong: HTTP is insecure.

Right: an attacker who can reach the update service for one minute gains permanent code execution on every device in the fleet, including devices they cannot reach directly, and the fleet installs their code as a normal update with no error and no record that anything unusual happened.

"HTTP is insecure" is a missing control wearing a risk costume. A control is what you add. A risk is what happens while you have not added it. The test is whether your sentence would still make sense to the factory manager who pays for the fix. "HTTP is insecure" would not. "Anyone on your network can choose what your machines run" would.

Note what makes this risk large. It is not the difficulty of the attack, which is one HTTP request. It is the reach: one request affects every device, and the effect survives a reboot.

### Hop 5: the Security claim

Wrong: the device is secure against firmware tampering.

Right: only firmware authored by the manufacturer runs on the Reference product.

The wrong version cannot be challenged, because "secure" has no test. The right version can be challenged by one person with one altered image, which is exactly what makes it useful. A claim a reviewer cannot attack is a claim that proves nothing when it survives.

This claim is `unsupported` today. You watched it fail in Tier 0.

### Hop 6: the requirement

Wrong: the device shall use MCUboot with ECDSA-P256 signatures.

Right: the device shall refuse to install or start a firmware image whose signature does not verify against the trust anchor held on the device. Acceptance criterion: when a modified image is published as the current release, the device records a verification failure, does not overwrite the running image, and continues to run the release it was already running.

The wrong version names a technology and stops. It cannot be tested, only inspected, and it is satisfied by a device that has MCUboot and ECDSA and checks nothing. A requirement states a security property and a way to see it happen. The technology is a later decision, and naming it too early hides the property behind a product name.

This is the failure the course specification warns about by name. Requirements that name technologies without a security property or an observable acceptance criterion are the most common defect in a first threat model.

### Hop 7: the planned control

Wrong: add security to the OTA service.

Right: MCUboot verifies an image signature against a trust anchor built into the bootloader, and the matching private key never exists on the OTA service host. Added in Tier 3. Lifecycle state today: `planned`.

Notice where the control landed. The attack happened at the service, and the control goes on the device. That is the whole lesson of this hop. A check placed where the attacker already stands is not a check. The device is the only party that can decide what the device runs.

### The chain end to end

| Hop | Answer |
| --- | --- |
| Observation | The service accepted a `PUT` to the current release record from an unauthenticated caller, and then served the altered image to anyone who asked |
| Asset | A-01, firmware authenticity and integrity |
| Actor | Local attacker with network reach to the service, or hosting attacker on the service host |
| Misuse scenario | MS-04 |
| Risk | R-04, permanent attacker-chosen code execution across the fleet from one request |
| Claim | SC-01, only firmware authored by the manufacturer runs on the Reference product, status `unsupported` |
| Requirement | REQ-01, refuse an image whose signature does not verify, with a stated acceptance criterion |
| Planned control | CTL-01, signed images with an offline key, Tier 3 |
| Residual risk after the control | RES-02, the signing key becomes the most valuable asset in the product the moment it exists |

Read the last row again. A finished chain does not end at the control. It ends at what the control leaves behind, because every control moves the risk somewhere rather than deleting it.

## Exercise 2 answer: the complete threat model

### The misuse scenarios

| ID | Weakness | Misuse scenario | Asset |
| --- | --- | --- | --- |
| MS-01 | T0-W-01 | A local attacker on the factory network reads the release record and downloads the firmware image, learning the version, the exact size, the digest, and that images are unsigned | None directly |
| MS-02 | T0-W-02 | A local attacker sends a status report that names a beacon they do not own, so the operator sees a healthy machine as failing and sends maintenance to the wrong floor | A-06 |
| MS-03 | T0-W-03 | A local attacker answers at the address the device was built to trust, using a rogue access point or a spoofed address, so the device takes its update instructions from the attacker | A-04 |
| MS-04 | T0-W-04, T0-W-05 | A local attacker replaces the current release record with one naming their own unsigned image, so every beacon downloads and runs firmware the attacker wrote | A-01 |
| MS-05 | T0-W-06 | An attacker, or an operator making a mistake, assigns a release older than the one installed, so a device returns to a version whose defects are already published | A-05 |
| MS-06 | T0-W-07 | Power is lost during an overwrite install, or the installed image crashes on start, so the device is left with no working image and no way back | A-07 |
| MS-07 | T1-W-08 | A physical opportunist with brief access, or a thief with a stolen unit, reads the shared device identifier from flash or from the serial console, and can then produce status reports for every device in the fleet | A-03 |
| MS-08 | T0-W-04, T0-W-05 | A hosting attacker who has compromised the update service host publishes a release of their choosing, without ever holding a signing key, because no signing key exists | A-01, A-04 |

MS-01 is the one worth pausing on. It harms no protected asset, because firmware confidentiality is deliberately not a core requirement of this product. It is still a finding, because it lowers the cost of every other scenario on this list. An attacker who has read the release record knows the exact image size to match and knows in advance that nothing will check a signature.

An observation that maps to no asset is not a mistake in your model. Record it as reconnaissance, say which scenarios it makes cheaper, and move on.

### The risk register

| ID | Scenario | Asset | Actor | What the actor achieves | Treatment | Tier |
| --- | --- | --- | --- | --- | --- | --- |
| R-01 | MS-01 | None directly | Local attacker | Full knowledge of the update path before attacking it | Encrypt the transport so the record is not readable in passing | Tier 2 |
| R-02 | MS-02 | A-06 | Local attacker, remote attacker, operational failure | Control of what the operator believes about any machine | Bind each report to a per-device identity proven on the connection | Tier 6, Tier 7 |
| R-03 | MS-03 | A-04 | Local attacker | The device takes its update instructions from the attacker | The device checks who answered before it believes the answer | Tier 2 |
| R-04 | MS-04 | A-01 | Local attacker, OTA service, Device | Permanent attacker-chosen code execution on every device, from one request | The device verifies the image publisher, and the release record is signed | Tier 3, Tier 4 |
| R-05 | MS-05 | A-05 | Local attacker, operational failure | A fleet returned to a version with published defects | Signed release metadata and a security counter the device refuses to go below | Tier 4 |
| R-06 | MS-06 | A-07 | Operational failure | A device that no longer starts and cannot be recovered remotely | Test boot, confirmation, and revert to the last confirmed image | Tier 5 |
| R-07 | MS-07 | A-03 | Physical opportunist, thief | One extracted secret that impersonates the whole fleet | A per-device key generated on the device and never shared | Tier 6 |
| R-08 | MS-08 | A-01, A-04 | Hosting attacker | Fleet-wide code execution from a compromised server | The service cannot create a newly trusted release, because the signing key is never on it | Tier 3 |

Likelihood is not scored in this register, and it is not an oversight. Every one of these succeeded on the first attempt in Tier 0, against a product with no control at all. A likelihood column here would record only that nothing was stopping any of them. Likelihood becomes meaningful from Tier 2 onward, when a control exists that an attacker has to beat.

### The asset no scenario touches

| Asset | Covered by | Why |
| --- | --- | --- |
| A-01 Firmware authenticity and integrity | R-04, R-08 | |
| A-02 The firmware signing key | Nothing | The product has no signing key, so there is nothing to steal |
| A-03 The device private identity key | R-07 | In Tier 0 the shared identifier stands in for it |
| A-04 Trust anchors and update policy | R-03, R-08 | |
| A-05 Installed version and anti-rollback state | R-05 | |
| A-06 Configuration and reported status integrity | R-02 | |
| A-07 Device availability and recovery access | R-06 | |

A-02 is the most important row in this table, and it is the empty one.

The Reference product has no firmware signing key today, so no scenario can name it. The moment Tier 3 creates one, it becomes the most valuable asset in the product: whoever holds it can author firmware that every device in the fleet will accept forever, and no later control can take that back. The control you are about to add creates the asset you will then have to protect for the life of the product.

That is why an asset with no risk is recorded rather than deleted. "Not present yet" and "not at risk" look identical in a risk register and mean opposite things.

### The actors no scenario names

| Actor | Named in | If not named, why |
| --- | --- | --- |
| Manufacturer | Owner column and Residual risks | A role that owns risks rather than a source of them |
| Provisioning operator | Nothing | The product has no provisioning step at all in Tier 0, which is itself the finding that Tier 6 answers |
| Customer operator | R-02 indirectly, as the person deceived | Owner of the availability risk in RES-04 |
| Mentor | Nothing | A course role with no function in the product |
| OTA service | R-04 | Named as an actor because Tier 0 trusts it without it having earned anything |
| Device | R-04 | Named as an actor because it accepts firmware without checking anything |
| Remote attacker | R-02 | Reach depends on whether the service is exposed beyond the local network. Recorded as an assumption, not a fact |
| Local attacker | R-01 to R-05 | |
| Physical opportunist | R-07 | |
| Thief | R-07 | |
| Hosting attacker | R-08 | |
| Operational failure | R-02, R-05, R-06 | Not an attacker, and the register is wrong without it |

Two of these rows are the ones most first models get wrong.

The OTA service and the Device are listed as actors, not only as components. In Tier 0 both of them make trust decisions that nobody checks, so both can be made to act against the product's interest without being compromised in any interesting way. An actor list that contains only attackers will miss every risk that comes from a trusted party behaving exactly as designed.

Operational failure is not an attacker and belongs in the register anyway. R-06 has no attacker at all, and it is the risk most likely to actually happen to a real fleet.

### The Security claims

Every claim below is `unsupported` at the end of Tier 1. Tier 1 produced no control and ran no test, so no other status is available.

| ID | Claim | Asset | Status | What contradicts it today | Requirements | Tier that can change it |
| --- | --- | --- | --- | --- | --- | --- |
| SC-01 | Only firmware authored by the manufacturer runs on the Reference product | A-01 | unsupported | The altered-image fixture installed and ran an unsigned image | REQ-01, REQ-06 | Tier 3 |
| SC-02 | The device installs only the release the manufacturer currently approves, and never an earlier one | A-05 | unsupported | The device installed an older release during the Tier 0 reset | REQ-02, REQ-06 | Tier 4 |
| SC-03 | The device exchanges updates and status only with the genuine update service, and the network can neither read nor change what they exchange | A-04, A-06 | unsupported | The impersonation fixture answered in place of the service and was believed | REQ-03 | Tier 2 |
| SC-04 | A status report can only be produced by the device it names | A-06, A-03 | unsupported | The spoofing fixture reported as a device it was not | REQ-04 | Tier 6, Tier 7 |
| SC-05 | An interrupted or failed update never leaves the device without a working image | A-07 | unsupported | The install is a permanent swap with no test boot and no revert | REQ-05 | Tier 5 |

### The requirements

| ID | Requirement | Acceptance criterion | Supports |
| --- | --- | --- | --- |
| REQ-01 | The device refuses to install or start a firmware image whose signature does not verify against the trust anchor held on the device | A modified image published as the current release produces a recorded verification failure, the running image is not overwritten, and the device continues to run the release it was already running | SC-01 |
| REQ-02 | The device refuses a release whose version state is lower than the one it has already installed | An older release assigned after a newer one is rejected with a recorded reason, and the installed release does not change | SC-02 |
| REQ-03 | The device opens an update or status connection only to a service whose identity it can verify, and refuses one it cannot | A service presenting no identity, or an identity that does not match the expected name, is refused before any release data is read | SC-03 |
| REQ-04 | The service accepts a status report only when the identity proven on the connection matches the device named in the report | A report naming a device other than the one on the connection is rejected and recorded as rejected | SC-04 |
| REQ-05 | After an interrupted or failed install, the device starts the last image that was confirmed to work | Power removed during an install, and an image that fails to start, both end with the device running the previously confirmed release | SC-05 |
| REQ-06 | The update service cannot create a release that devices will trust, and the signing key is never present on the service host | An operator with full control of the service host cannot produce a release that a device accepts | SC-01, SC-02 |

Every requirement names a property and a way to see it. None of them names a protocol, a library, an algorithm, or a key length. Those belong to the control, which is the next table, and they belong there because they are the part most likely to change without the requirement changing.

REQ-06 is the requirement that teams forget. It is the only one that says what an attacker who wins gets, rather than what a defender does.

### The planned controls

Every control is `planned`. No control exists at the end of Tier 1. A later tier changes the same record to `implemented` and then to `verified`. The record is revised in place, so the plan and the result stay in one history rather than two.

| ID | Control | Meets | Lifecycle state | Tier |
| --- | --- | --- | --- | --- |
| CTL-01 | MCUboot verifies an image signature against a trust anchor in the bootloader, with the private key held offline | REQ-01 | planned | Tier 3 |
| CTL-02 | Signed release metadata and a security counter the device refuses to move backwards | REQ-02 | planned | Tier 4 |
| CTL-03 | HTTPS with a course-local service certificate authority, certificate validation, and hostname validation on the device | REQ-03 | planned | Tier 2 |
| CTL-04 | A per-device identity generated on the device, then mutual TLS binding every report to the connection that carried it | REQ-04 | planned | Tier 6, Tier 7 |
| CTL-05 | Two image slots with test boot, explicit confirmation, and automatic revert | REQ-05 | planned | Tier 5 |
| CTL-06 | Release signing on a separate offline workstation, with the service holding only public material | REQ-06 | planned | Tier 3 |

### The Residual risks

Every Residual risk has an owner and either a treatment or a recorded acceptance. A Residual risk with neither is an open finding pretending to be a decision.

| ID | Residual risk | Owner | Treatment or acceptance |
| --- | --- | --- | --- |
| RES-01 | Physical access to the board allows flash readout and serial access, and no core tier treats it | Manufacturer | Treated in Advanced Tier A. Accepted for the core course, because the core scope excludes invasive hardware attacks and the lab uses disposable boards |
| RES-02 | The firmware signing key becomes the highest-value asset in the product the moment Tier 3 creates it, and its compromise cannot be undone by any later control | Manufacturer | Treated in Tier 3 by keeping the key off every network-reachable host. A fully compromised signing system is outside the course scope by a fixed decision |
| RES-03 | Firmware contents are readable by anyone who obtains an image | Manufacturer | Accepted. Firmware confidentiality is not a core requirement of this product. Taught with its operational cost in Advanced Tier A |
| RES-04 | The update path must keep working for a five-year support period, and nothing in the course models that | Manufacturer with the customer operator | Accepted for the course. Revisited in Tier 9 with support and vulnerability handling |

### What this model is still missing

A finished Tier 1 model is not a complete one, and saying so is part of the result.

This model covers one device, not a fleet. It assumes the factory network is the only network that can reach the service. It treats the manufacturer's own build process as trustworthy, which is a large assumption that Tier 9 examines and no tier proves. It says nothing about what the customer is told when a device is compromised, which is a Tier 9 topic. It scores no likelihood, because with no controls in place there is nothing to score.

Write your own version of this paragraph. A model that knows its own edges is worth more at a review than one that claims not to have any.

## What to do with this page

Go back to **[Tier 1](index.md)** and finish the tier.

Your worksheet should now hold your answers, the differences you found, and anything here you disagree with. Those three things are what you bring to the Mentor review gate. The gate is a conversation about your reasoning, not a check that your tables match these ones.
