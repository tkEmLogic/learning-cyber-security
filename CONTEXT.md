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
It belongs to the device's current ownership context.
_Avoid_: Factory identity, user account

**Bootstrap credential**:
A unique, short-lived or one-time credential that permits only initial
enrollment. It cannot authorize normal device operation or firmware download.
_Avoid_: Default password, device identity

**Claim window**:
A short period opened by physical action during which a device may be assigned
to a new owner and receive a new operational identity.
_Avoid_: Pairing mode, maintenance mode

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
_Avoid_: Root certificate store, trusted key
