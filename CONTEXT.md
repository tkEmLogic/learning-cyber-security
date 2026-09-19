# Learning Cyber Security

This context defines the language used to design and teach the embedded and IoT
cybersecurity course.

## Language

**Course specification**:
The implementation-ready description of the course audience, architecture,
modules, labs, assessment, and supporting repository.
_Avoid_: Course plan, curriculum notes

**Learner**:
An embedded software engineer who has little or no experience applying
cybersecurity in an embedded product-development context.
_Avoid_: Student, beginner, new graduate

**Mentor**:
An experienced engineer who reviews the learner's work at defined points.
_Avoid_: Teacher, lecturer

**Mentor review gate**:
A scheduled review where the learner demonstrates a result, explains the
security reasoning, and responds to a prepared failure or challenge.
_Avoid_: Instructor checkpoint, lesson review

**Reference product**:
An industrial equipment status beacon built around an ESP32-C6. It shows a
simulated machine state with one monochrome LED. On means normal operation. Off
means the device is off. Fast and slow blinking show two fictional error states.
The device reports status over Wi-Fi and receives software updates over Wi-Fi.
_Avoid_: Demo app, blinky, access controller

**Lab artifact**:
A reviewable result that shows what the learner designed, implemented,
observed, or concluded during a lab.
_Avoid_: Homework, deliverable

**Release manifest**:
Immutable, manufacturer-signed metadata that describes one firmware release,
including its compatible hardware, version, security counter, image size, and
image digest.
_Avoid_: Update file, version record

**Update assignment**:
The OTA service's choice of which release, if any, a specific device should
install. It refers to a release manifest but does not change the signed release.
_Avoid_: Manifest, deployment

**OTA service**:
The service that provides update assignments, release manifests, firmware
images, and update event records. It does not hold firmware release-signing
keys.
_Avoid_: Signing server, firmware authority

**Factory identity**:
A persistent, manufacturer-issued identity that identifies one physical device.
It is issued by Bootstrap-authorized enrollment and is then used only for
claiming and controlled recovery, not for routine owner access.
_Avoid_: Device password, owner identity

**Operational identity**:
A rotatable, per-device identity used for normal mutual TLS access to services.
It belongs to the device's current ownership context. It is issued by the
Operational Device CA when a claim succeeds, it names its owner in its owner
scope, and it lives ninety days. The device cannot tell that it has expired,
because the device has no trusted clock, so the service alone enforces the end
of its life. A device holding no Operational identity does not fall back to its
Factory identity. It stays unable to download.
_Avoid_: Factory identity, user account

**Bootstrap credential**:
A unique, short-lived or one-time credential that permits only initial
enrollment. It cannot authorize normal device operation or firmware download.
_Avoid_: Default password, device identity

**Claim window**:
A ten-minute period opened by a physical action, a ten-second hold of the BOOT
button, during which a device may be assigned to a new owner and receive a new
operational identity. The same press generates the Claim nonce and the Pending
Operational key.

Two parties bound the window and they do not time the same ten minutes. The
device times its own window from the press and closes it by destroying the
nonce and the pending key. The service times the claimable period on its own
clock and is the only party that decides a claim is expired. A reset ends the
window, and neither party resumes it.
_Avoid_: Pairing mode, maintenance mode

**Provisioning station**:
The host-side authority that enrolls a device over its physical connection. It
consumes a Bootstrap credential, checks proof of possession, issues the Factory
certificate, and appends the provisioning record, all before anything is sent
back to the device. It stores no private-key material.
_Avoid_: OTA service, server

**Provisioning record**:
The append-only device lifecycle record. The provisioning station is its first
writer rather than its only one. The station records credential issuance and
enrollment, including the certificate fingerprint and which credential was
consumed, and from Tier 7 the OTA service appends the claim that binds a device
to an owner. It never holds a private key, and a secret it refers to is kept
only as a hash. An entry is never edited or removed, including one a clone put
there.
_Avoid_: Database, key store

**Proof of possession**:
Evidence, carried inside the signed certification request, that the requester
holds the private key whose public half the request presents. The station
refuses a request whose proof does not verify.
_Avoid_: Authentication, password check

**Clone**:
A copy of a shared credential used to act as the fleet it was taken from. In
Tier 6 the Learner extracts the shared key from a firmware image and registers
devices that were never manufactured, all under one certificate fingerprint.
_Avoid_: Fork, duplicate device

**Secure element**:
A separate security component that generates or stores private keys and
performs cryptographic operations without exporting those private keys. In this
course, the selected secure element is STSAFE-A120.
_Avoid_: Hardware root of trust, key vault

**Security evidence pack**:
The versioned set of engineering artifacts that connects security claims,
requirements, controls, tests, results, residual risks, and source references
for the reference product.
_Avoid_: Compliance pack, final report

**Security claim**:
A specific, reviewable statement about a security property or lifecycle
behavior of the reference product. A claim is supported, partly supported,
unsupported, or not applicable based on linked evidence.
_Avoid_: Guarantee, compliance claim

**Security requirement**:
A statement of what the reference product must do and how someone else would
see it happen, identified as `REQ-<nn>` and carrying an acceptance criterion. It
names no product, library, protocol, or algorithm.
_Avoid_: Spec item, feature, user story

**Security control**:
The technical or procedural measure that meets one or more security
requirements, identified as `CTL-<nn>` and carrying a lifecycle state of
`planned`, `implemented`, or `verified`. A control names the technology a
requirement must not.
_Avoid_: Mitigation, countermeasure, safeguard

**Residual risk**:
A known security risk that remains after the selected controls are applied,
including its rationale, owner, and planned treatment or acceptance.
_Avoid_: Accepted vulnerability, limitation

**Hardening tier**:
A runnable state of the reference product created by adding one focused
security control or lifecycle capability to the preceding state. Each tier
preserves the earlier behavior, demonstrates the new boundary, and adds
evidence to the security evidence pack.
_Avoid_: Course level, release version

**Control tier**:
A Hardening tier that reproduces an attack, adds one focused control, replays
the attack against it, and tests bypasses. Every tier from Tier 2 to Tier 9 and
both Advanced Tiers are control tiers, including the ones `course.yml` marks
`kind: lifecycle`, because the kind says where a tier sits in the course arc and
not how its module is shaped.
_Avoid_: Lifecycle tier, hardening module

**Baseline tier**:
The single Hardening tier that builds the unsecured reference product. It has no
control to add and no attack to defeat, and it records the successful attack as
its result. Tier 0 is the only one.
_Avoid_: Tier zero, starting tier

**Analysis tier**:
The single Hardening tier that produces analysis artifacts, changes no code and
adds no control. It reclassifies an earlier observation against threats,
requirements, and planned controls, and claims no technical rejection. Tier 1 is
the only one.
_Avoid_: Threat model tier, paper tier

**Weakness ledger**:
The per-tier record of known weaknesses, demonstrated attack vectors, controls
that close or reduce them, evidence of the changed behavior, and weaknesses
that remain for later tiers.
_Avoid_: Bug list, vulnerability scan

**Tier checkpoint**:
An immutable, annotated Git tag that identifies a tested runnable state at the
start or completion of a hardening tier.
_Avoid_: Tier branch, solution folder

**Course workspace**:
A learner-owned Git branch or worktree created from a tier checkpoint. It holds
the learner's code and evidence without changing the published checkpoint.
_Avoid_: Tier checkpoint, shared working directory

**Course environment**:
The disposable local setup that `./course setup` creates for one Learner: the
generated state, secrets, service configuration, and keys that belong to one
run of the course on one machine. It is thrown away and recreated, and nothing
in it is a production asset.
_Avoid_: Test environment, deployment

**Attack fixture**:
One named, scripted attack a Learner runs against their own Course environment
through `./course attack run`. It states its target, the weaknesses it
demonstrates, the files it changes and its reset command before it does
anything, and it acts only after matching the Course environment marker and
being given its own identifier a second time. It performs an attack the course
has already explained, so it is a teaching instrument rather than a tool for
finding new ones, and `docs/fixture-safety-contract.md` binds every one of them.

Not every piece of attack machinery is a fixture. A command that reads
something the Learner already has, changes nothing and reaches no service is an
ordinary `./course` command, because wrapping it in this apparatus would report
a safety check that was guarding nothing.

Nor is every fixture registered in `course.yml`. Tier 7's is one adversary
under `./course service bypass`, driving thirteen rows, so it is bound by
written rules in `docs/fixture-safety-contract.md` rather than by a manifest
entry. It keeps every guarantee above: the disclosure, the marker match, the
second naming of its own identifier, and the reset.
_Avoid_: Exploit, payload, penetration test, security scanner

**Course environment marker**:
A disposable, setup-generated identifier shared by the local course service,
fixtures, and Course workspace. An attack fixture must match it before causing
the intended insecure effect.
_Avoid_: Authentication token, production environment flag

**Course certificate authority**:
The disposable authority generated for one Course environment that signs the
Service certificate. It exists to teach certificate validation and is never a
production certificate authority.
_Avoid_: Root CA, company CA

**Service certificate**:
The certificate the OTA service presents to the Reference product, naming the
course-local service name. It proves which service answered, and it proves
nothing about who published a firmware image.
_Avoid_: SSL certificate, device certificate

**Release signing key**:
The private key that signs a firmware image so a device can tell that the
manufacturer published it, and from Tier 4 also the exact bytes of a Release
manifest so a device can tell what the release claims about itself. One key,
two signatures over different bytes, checked by two independent verifiers. It is
held offline, away from the OTA service and from version control, and it is
separate from every device identity key and from the Course certificate
authority.
_Avoid_: Firmware key, code signing certificate

**Security counter**:
A number carried in both the signed MCUboot image and the signed Release
manifest, which only increases when a release closes a security boundary that
must not be reopened. It is separate from the human-readable version, which
never overrides it. It is compared, never remembered: the bootloader reads the
counter of the image in the primary slot and compares it with the candidate's.
_Avoid_: Version, build number, rollback index

**Trial image**:
An image MCUboot has swapped into the primary slot but not been told to keep.
It is running, and it is one reboot away from being replaced by the image it
displaced. Every install from Tier 5 onwards begins as one.
_Avoid_: Test image, candidate image, pending image

**Confirmed image**:
The image the device falls back to. It became confirmed because something
asserted that it works, and it stays confirmed until a later image does the
same. A device always has exactly one.
_Avoid_: Current image, active image, good image

**Health gate**:
The local checks a trial image must pass, and keep passing, before it is
confirmed. Every check is local by construction: the gate runs before the
device has a network, so backend reachability cannot be one of its inputs.
_Avoid_: Health check, self test, smoke test

**Revert**:
MCUboot restoring the confirmed image because a trial image never asserted it
worked. It is what happens by default; confirming is the exception that
prevents it.
_Avoid_: Rollback, downgrade, restore

**Resume state**:
The record of how far a download got and which release it belonged to, kept in
flash so an interruption does not cost the bytes already written. It says where
to resume and never what to trust: a resumed download re-verifies the Release
manifest before the record is allowed to matter.
_Avoid_: Download cache, checkpoint, partial image

**Image signature**:
The signature over a firmware image, made with the Release signing key and
checked by the bootloader before the image is allowed to run. It proves who
published the image. It proves nothing about which service delivered it.
_Avoid_: Checksum, image hash, firmware signature

**Trust anchor**:
The public material a device checks something against, compiled into the
Reference product rather than fetched over the network. From Tier 3 the
Reference product holds two, and they are unrelated. The Course certificate
authority is the anchor for a presented Service certificate. The
image-verification public key is the anchor for an Image signature. Always
name which one is meant.

From Tier 4 that second key is held in two places: the bootloader checks the
Image signature with it and the application checks the Release manifest
signature with it. Same key material, two independent verifiers, and a pass by
one is never evidence about the other.

Tier 7 adds no third anchor. The device presents an Operational certificate and
never verifies one, so it holds nothing for the Operational Device CA. It
checks an issued certificate against its own key and its own identifier
instead.
_Avoid_: Root certificate store, trusted key

**Customer operator**:
The person who installs and manages a device on the customer side. They work
for an owner, they are not the manufacturer, and they hold no device identity.
In Tier 7 they run the operator half of a claim: they present an Owner
credential and submit the device identifier with the Claim nonce that the
device showed them.
_Avoid_: User, administrator, owner

**Owner**:
The party a device belongs to once it has been claimed. An owner is named by a
short slug, such as `northwind`, written in lower-case letters, digits and
hyphens. That slug is what an Operational certificate carries and what the
device record stores. An owner is not a person. A Customer operator acts for an
owner.
_Avoid_: User, account, tenant

**Owner credential**:
A credential that authorizes a person rather than a device. It is thirty-two
random bytes, minted by the course and printed once, and only a hash of it is
kept. The holder presents it as a bearer token on every operator request. It is
reusable for ninety days, and minting a new credential for the same owner
replaces the previous one. It is never a device identity and it is never stored
as the device's private key.
_Avoid_: Password, API key, device identity

**Authenticated owner**:
The owner that the service works out from the Owner credential presented on one
operator request. The service never trusts an owner name carried in the request
body, and it keeps nothing about the caller between requests. The course
specification calls this an owner session. The course has no session object,
and the word session does not appear in the code.
_Avoid_: Owner session, login, signed-in user

**Claim nonce**:
A one-use secret that the device generates when its Claim window opens. It is
printed on the device console as twenty-four characters in six groups, in an
alphabet chosen so that a person can copy it without confusing similar
characters. That person gives it to the service, which is how the claim proves
that someone is physically at that device. The service keeps only a hash of it
and spends it on the first successful match.
_Avoid_: Pairing code, password, activation key

**Pending Operational key**:
The Operational key a device generates when its Claim window opens, before any
certificate for it exists. It is held only in memory, so the end of the window
and a reset both destroy it, and a flash dump taken during an open window does
not contain it. It becomes the device's stored Operational key only when the
issued certificate arrives.
_Avoid_: Provisional certificate, temporary key, pending Operational identity

**Mutual TLS**:
A TLS connection on which both ends present a certificate, so the service
identifies the device while the device identifies the service. The service
reads three facts from the certificate it receives, and each fact has one
source. The device identifier is the subject common name. The role is which
certificate authority signed the certificate, taken from the verified chain,
because a second signal could disagree with the chain. The owner scope is the
subject organizational unit. Nothing else in the certificate names a role.
_Avoid_: Two-way SSL, client authentication, certificate pinning

**Device listener**:
The service port that accepts only mutual TLS connections and serves the routes
a device uses: its update assignment, release manifests, image downloads,
status events, and the device half of a claim. A caller holding no device
certificate never reaches a handler here, because the handshake happens before
the request is read. The listener boundary is therefore the coarsest
authorization decision the service makes.
_Avoid_: HTTPS endpoint, API server, secure port

**Operator listener**:
The service port a person reaches. It authenticates the service to the caller
and asks for no client certificate, which is what lets an Owner credential be
presented on it at all. It serves the operator half of a claim and the lab
controls.
_Avoid_: Admin port, management API, operator session

**Owner scope**:
The owner slug that an Operational certificate carries, in the subject
organizational unit. It states which owner the certificate was issued for. It
is a statement the certificate makes about itself, so on its own it is not
evidence that the owner is still the current one.
_Avoid_: Ownership context, tenant identifier, subject name

**Ownership context**:
The property a connection is checked against: the owner scope in the presented
certificate must equal the owner that the device record names now. The
certificate states an owner and the record holds the current one, and the
record decides. A certificate that is genuine and unexpired is still refused
when the device has moved out of its ownership context.
_Avoid_: Owner scope, owner session, ownership claim

**Operational Device CA**:
The certificate authority that signs Operational certificates. It is a
self-signed root, separate from the manufacturer authority that signs Factory
certificates, so operational trust does not descend from manufacturing trust.
The Learner creates it, and the OTA service holds its signing key while mutual
TLS is on. The device never holds it as a Trust anchor, because a device
presents an Operational certificate and never verifies one.
_Avoid_: Operational certificate authority, intermediate CA

**Certificate-role inventory**:
The single listing of every trust relationship the course has built: each
authority and what it signs, each leaf role with its issuer and where it lives,
and the signing keys that have no certificate at all. It is one part of Tier
7's lab artifact. It is not the same listing as the signing keys on their own,
which answer the narrower Tier 3 question of which key is which.
_Avoid_: Key list, certificate list, PKI dump

**Check**:
The named property that had to hold, which a refusal reports. The provisioning
station started this grammar in Tier 6, and the OTA service continues it in
Tier 7 with its own separate set of names, because which component refused a
request is part of what the refusal says. A refusal body carries the name in a
field called `check` and one sentence in a field called `reason`. Every
authorization refusal returns the same HTTP status, so the check is the reason
and the status never is.

A refusal at the TLS handshake carries no check at all. Nothing has read the
request yet, so the caller sees only a closed connection. Which layer refuses
decides how useful a refusal can be.
_Avoid_: Error code, reason code, failure type

**Reason code**:
The device's own reason for the result it is reporting, carried in the status
event the device sends. It has meant that since Tier 0 and Tier 7 does not
change it. The course specification also uses the words "distinct reason codes"
for the refusals the service must keep apart, and those refusals are named by a
Check instead. Always say which of the two is meant.
_Avoid_: Check, HTTP status

**Synthetic device**:
A device that exists only on the host: a key pair and a Factory certificate in
a file, enrolled through the real provisioning station by an Attack fixture.
It lands in the device lifecycle record as an ordinary entry, because the
station genuinely cannot tell one from a board, and that inability is the
lesson rather than a gap. The course names them `beacon-bypass-*` and
`beacon-phantom-*`, and that convention is the only tell: the record carries
no field saying which entries a fixture wrote, and anyone who can write the
record can pick any name.
_Avoid_: Fake device, virtual device, phantom device

**Adversary owner**:
The single Owner the Tier 7 fixture holds, slug `rival-labs`, minted into the
Learner's own owner store and cleared by the fixture's reset. It is a fully
legitimate account and that is the point: it passes every credential check, so
each refusal it collects is an authorization decision rather than an
authentication one. `./course setup` does not create it, because the Learner
mints their own Owner as a lab step and the adversary's belongs with the rest
of the adversary's material. There is exactly one, named in the manifest and
never supplied on a command line.
_Avoid_: Second owner, attacker account, rogue owner

**Host, board required**:
The witness value for a Tier 7 result that is read on the host but that only a
board can make possible: the board opens the Claim window and prints the
Claim nonce, and the refusal then arrives on the operator half. It is a third
value beside `host` and `device`, and it narrows nothing. A host result still
never stands in for a device result; this label only records that a device was
needed for the result to exist at all.
_Avoid_: Host, hybrid, partly device
