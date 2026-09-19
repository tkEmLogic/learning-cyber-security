# Prototype: outline of the cryptography primer

**This is a prototype, not course material.** It answers ticket [#184](https://github.com/tkEmLogic/learning-cyber-security/issues/184): what shape the cryptography primer takes, where it lives, and what it covers. The prose below is sketch text to react to. None of it is written to the course writing rules, and none of it should be copied into the course. Ticket [#191](https://github.com/tkEmLogic/learning-cyber-security/issues/191) writes the real page.

## The shape this outline proposes

One companion page, `course-material/cryptography-primer.md`, sitting beside the landing page rather than inside any tier. Eleven short sections. Around 1,400 to 1,800 words, which is roughly 20 minutes of reading and about a third of the length of Tier 2.

It is prerequisite reading for Tier 2, met once, and linked back into from Tiers 3, 4, 6 and 7 on first use of a term it owns.

## The rule the page is written under

**Define the nouns. Do not spend the tier's insight.**

Every section names a term, gives one plain sentence of definition, says what the course uses it for, and says where the reader first meets it. No section explains which attack a control stops, because that is what the tier the reader is about to work is for.

This matters most at Tier 2. Its Predict questions 3 and 4 ask the reader to hold an opinion about the difference between encryption and authentication before the tier teaches it. The primer must give the reader those two words, and must not answer those two questions. A primer that says "encryption without authentication leaves impersonation open" has spent Tier 2's best moment on a page the reader skims in a canteen.

## The outline

### 1. What this page is

Two paragraphs. This page defines the words the course uses from Tier 2 onward. It is not a cryptography course, and it teaches nothing you will be asked to implement. Read it once before Tier 2, and come back to it when a tier links here.

One sentence naming what is deliberately absent: no mathematics, no algorithm internals, no advice about choosing algorithms for a product of your own.

### 2. Bytes, hashes and digests

A digest is a short fixed-length fingerprint of any amount of bytes. The same bytes always give the same digest. Different bytes give a different one, and you cannot work backwards from a digest to the bytes.

Course use: the release record has carried a digest since Tier 0, and Tier 3's signature is computed over a digest rather than over the image.

First met: Tier 0.

### 3. A key pair

Two keys generated together. One is kept secret, the private half. One is handed out freely, the public half. What one does, only the other can undo.

The sentence that has to land: publishing the public half costs you nothing, and that is the entire trick.

First met: Tier 2, and it is the tier's central object from Tier 3 onward.

### 4. Signing and verifying

Signing takes bytes and a private key and produces a signature. Verifying takes the bytes, the signature and the matching public key, and answers one question with yes or no: were these exact bytes signed by the holder of that private key?

What a signature proves: origin and integrity. What it does not prove: that the bytes are secret, that they are current, or that they are the ones you wanted. One line only, pointing forward without elaborating, because Tier 3 and Tier 4 are each built on one half of that sentence.

First met: Tier 3, and used in Tiers 4, 6 and 7.

### 5. Encrypting and authenticating

Encryption makes bytes unreadable to anyone without the key. Authentication proves who you are speaking to. They are separate properties, and a connection can have either one without the other.

Two or three sentences, and it stops there. Tier 2's Predict questions are left standing.

First met: Tier 2.

### 6. A certificate

A public key and a name, signed by someone else. The course's own best sentence already exists at `tier-07:309` and arrives five tiers late: "It adds a signed statement about who the key belongs to and until when."

Also here: X.509 expanded as the format that every certificate in this course uses, the name field the device actually checks, and why a certificate is public rather than secret.

First met: Tier 2, at `index.md:43` and `tier-02:161`.

### 7. Certificate authorities, chains and trust anchors

A certificate authority is whoever signed the certificate. A chain is a certificate signed by another certificate, repeated. A trust anchor is where the reader decides to stop asking, because it is a copy they already hold.

One Mermaid diagram: Course certificate authority signs the service certificate, the device holds the authority, the device checks the chain. The same meaning is in the text beside it, per the Markdown rules.

The sentence Tier 2 needs: your device carries the authority and not the service key, which is why the service can be reissued without reflashing every board.

First met: Tier 2. Used again at every identity tier.

### 8. Asking for a certificate

A certification request, abbreviated CSR, is a public key plus the name you are asking for, signed by the matching private key. That self-signature is the proof that you hold the private half of the key you just sent.

Course use: Tier 6 generates a key on the device and asks for a Factory identity. Tier 7 asks for an Operational identity.

First met: Tier 6 at `tier-06:188`, again at `tier-07:409`.

### 9. Freshness, and the nonce

A nonce is a number used once. It exists because a signature that was valid last year is still valid today, so the receiver has to supply something new and unpredictable and require it back.

The course uses the word 47 times without ever defining it, which makes this section one of the two that pay for the page on their own.

First met: Tier 4 in the replay work, Tier 7 in the Claim nonce.

### 10. Names you will meet

A table, one line each, of the names the course uses where the reader needs to know only what kind of thing it is. The table does not explain any of them.

| Name | What it is |
| --- | --- |
| SHA-256 | The digest function this course uses |
| ECDSA, P-256 | The signature scheme and the curve this course signs with |
| AES-GCM, AEAD | The encryption this course's TLS uses, and the word for encryption that also detects tampering |
| TLS, HTTPS | The protocol that authenticates and encrypts a connection, and HTTP carried over it |
| OTA | Over the air, the update path this whole course hardens |
| X.509, DER, ASN.1 | The certificate format, and the two names for how it is encoded on the wire |
| PKCS#8, SEC1 | Two file formats a private key is stored in |
| SAN | The field in a certificate that holds the name the device checks |

### 11. Where each idea is used

A closing table mapping each concept to the tier that first needs it, so a reader who arrives from a link in Tier 6 can see what they were meant to have read.

Two or three further readings under it, marked optional, in the shape section 19 uses: the reading, its level, its type, the learning question, and the exact section. RFC 5280 section 1 is the obvious first, and it already sits in `research/course-readings.md:81` as Recommended, reaching no module today.

## What this page does not own

The boundary against ticket [#192](https://github.com/tkEmLogic/learning-cyber-security/issues/192), which defines the remaining terms tier by tier.

The primer owns the vocabulary that four or more tiers share. Everything tied to one tier, one platform or one storage location stays in that tier, defined in passing on first use: NVS, ITS, PSA, TLV, eFuse, bearer token, SBOM, OCSP, secure element, and the Tier 6 and 7 course roles that `CONTEXT.md` already defines.

The test: a reader in Tier 6 should not be sent to the primer to look up where a key is stored on an ESP32-C6.

## Where the reader meets it

| Where | What it says |
| --- | --- |
| Landing page, in "Where to go next", before the Tier 2 paragraph | One sentence and a link: read this before Tier 2, it takes 20 minutes |
| Landing page, above the "Words this course uses" table | One sentence separating the two: course roles here, security concepts there |
| Tier 2, in "Starting state" | Listed with the other things the reader needs before starting, with its time |
| Tiers 3, 4, 6 and 7, on first use of a term | A relative link to the section, nothing more |
| `README.md` | No change. It states which tiers are published, and this is not a tier |

The landing page's tier table gains no row, because the primer is not a tier and cannot be given a number without amending section 11 of the specification. Its 20 minutes are stated where the reader meets it instead of in the 43-hour total.

## Sizing

One writing session. Eleven sections, two tables, one Mermaid diagram, no new commands, no firmware, no fixtures, and nothing to validate on a board.

It does not graduate to its own map, and #183 does not block on it.

The one thing that could change that is the further reading. If the primer is expected to carry worked examples, `openssl` commands the reader runs, or an exercise, it stops being a primer and becomes a tier, and that is the version that would need its own map.

## The forks a reviewer should push on

1. **Eleven sections or six.** The page could stop after certificates and authorities and leave nonces and the names table to their tiers. The nonce section is the one this outline would fight hardest for.
2. **Whether the encryption and authentication section survives at all.** It is the section closest to spending Tier 2's insight. Cutting it means the reader meets both words for the first time inside the Predict questions that turn on them.
3. **One page or two.** Sections 2 to 9 are concepts, section 10 is a lookup table. The table could be a glossary that grows through the course instead, which is really ticket #192's landing-page glossary in another shape.
4. **Prerequisite or reference.** This outline makes it prerequisite reading for Tier 2. The lighter alternative is to link it only on first use and never tell the reader to read it up front.
