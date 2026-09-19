# Course content review, Tiers 0 to 7

Reviewed on 2026-09-19, against the published state of `course-material/` at `4aaf230`.

This is a review of learner-facing written content only. The firmware, the services and the `./course` command were not reviewed, except where a module quotes a string one of them prints.

It is the input to the Wayfinder map that repairs these findings. Tickets cite findings by their identifier here rather than restating them.

## What was reviewed

`course-material/index.md`, the eight tier modules under `course-material/tiers/`, and the two companion answers pages. Supporting rules read for context: `docs/agents/course-writing.md`, `docs/agents/course-module-template.md`, `docs/course-specification.md` sections 1, 11, 13, 14, 19 and 20, and `CONTEXT.md`.

## The five questions asked

1. Would this course be understandable to a firmware engineer with little knowledge of cybersecurity?
2. Is the course comprehensive, with no logical gaps?
3. Are acronyms and concepts properly explained throughout?
4. Is the language easy for a Learner whose first language is not English?
5. Is the course overly concerned with bugs that are not directly related to cybersecurity?

## Summary

| Question | Verdict |
| --- | --- |
| Understandable to a security newcomer | The reasoning yes, the vocabulary no. The largest single gap. |
| Comprehensive, no logical gaps | The tier arc is sound. The identifier chains and the evidence pack break in checkable places. |
| Acronyms and concepts explained | No. Around 25 terms are used undefined, including CA and CSR. |
| Language for a non-native speaker | Good mechanically. Around 12 idioms, mixed spelling, and sentences that lengthen in Tiers 6 and 7. |
| Overly concerned with non-security bugs | Yes, and the share is growing tier by tier. |

Nothing found here is a rewrite. Two items are substantial: a cryptography primer between Tier 1 and Tier 2, and the Security evidence pack from Tier 4 onward. The rest is editing.

## F-01: the course never teaches public-key cryptography

The course assumes public-key cryptography as prior knowledge and never teaches it. None of the following is defined in learner-facing text.

| Term | First used |
| --- | --- |
| What a certificate is: a public key and a name, signed by someone else | `index.md:43` |
| What a certificate authority is. "CA" is never expanded | `index.md:43`, `tier-02:161` |
| Key pair, public half and private half, what signing and verifying do | Tiers 2 and 3 throughout |
| Certification request, and the abbreviation CSR | `tier-06:188`, `tier-07:409` |
| TLS, HTTPS and OTA, none of them expanded | Tier 2 onward |
| TLV, PSA, AEAD, AES-GCM, ECDSA, P-256, SHA-256, NVS, ITS, SAN, DER, ASN.1, PKCS#8, SEC1, eFuse, X.509, OCSP, SBOM | Tiers 3 to 7 |
| nonce, used 47 times; bearer token; trust anchor, used 18 times; chain | Tiers 2, 6 and 7 |

Two things make this sharper than a missing glossary.

`docs/agents/course-writing.md` already requires the opposite: "Define a necessary technical term before using it without explanation." The course breaks its own rule from Tier 2 onward.

The course's best definition of a certificate arrives five tiers after the first use, at `tier-07:309`: "It adds a signed statement about who the key belongs to and until when." That sentence belongs in Tier 2.

The cliff is between Tier 1 and Tier 2. Tier 1 needs no cryptography. Tier 2 opens with an authority, a chain, a trust anchor, ECDSA and `zsock_setsockopt(SOL_TLS, ...)` within twenty lines, and its Predict questions 3 and 4 at `tier-02:98` ask the reader to hold an opinion about the difference between encryption and authentication before the tier has taught it.

There is no existing home to extend. Section 19 of the specification contains no cryptography fundamentals entry. Tier 2's required reading is Zephyr's TLS API documentation, which teaches API use rather than concepts. RFC 5280 sits in `research/course-readings.md:81` as Recommended and reaches no module.

## F-02: the Security evidence pack breaks at Tier 4

The Security evidence pack is the course's central artifact. It is carried through every tier and examined at three Mentor review gates. It has no working support past Tier 3.

- `evidence/templates/` holds directories for `tier-00` to `tier-03` only.
- `tier-04:510` instructs `./course evidence init --tier 04`. That subcommand does not exist. `./course evidence` accepts only `context` and `check`, and refuses anything else.
- Tiers 5, 6 and 7 give the "Update the Security evidence pack" section as a bullet list with no command at all, because there is nothing to copy.
- `evidence check` validates Tier 0 only. `evidence/schemas/` holds `tier-00-evidence.schema.json` and nothing later.

A Learner following Tier 4 as written runs a command that refuses, and from Tier 5 onward is told what to record with no instruction on where.

## F-03: the control and requirement chains break

`CTL-05` is orphaned and `CTL-07` is unintroduced. Tier 1 plans `CTL-05`, "Two image slots with test boot, explicit confirmation, and automatic revert", meeting `REQ-05` in Tier 5, at `tier-01/answers.md:207`. Tier 5 then states at `:459` that `CTL-07` supports `REQ-05`. A Learner carrying their own control records is left with `CTL-05` permanently `planned` and a `CTL-07` that nothing introduces.

This sits badly beside `tier-07:825`, which spends a paragraph celebrating `CTL-04` surviving intact from Tier 1 to Tier 7.

`REQ-07` and `REQ-08` are never stated. They appear only as identifiers in the control tables at `tier-06:300` and `tier-07:822`. Tier 7 quotes `REQ-04` in full in the same section, which makes the omission conspicuous.

None of these identifiers appears in `course.yml`, so the repair is confined to Markdown.

## F-04: Predict questions promised an answer that never arrives

Tier 6's own Reveal section diagnoses this defect at `:269`: "The three questions were always here and nothing answered them, which meant a Learner was asked to commit to an answer and then left holding it." It was repaired in Tier 5 and Tier 6 only.

| Tier | The promise | Closing section |
| --- | --- | --- |
| Tier 1 | "You will check them against your own finished model at the end of the tier" (`:98`) | none |
| Tier 3 | "You will compare them at the end" (`:79`) | none |
| Tier 4 | "You will compare them at the end" (`:80`) | none |
| Tier 7 | four questions asked (`:89`) | none |

`docs/agents/course-module-template.md` states the rule: "A lifted Predict with no close leaves the Learner holding written answers that nothing ever checks, which is worse than not asking."

## F-05: Section 14 has become a bug diary

The "What this tier found in the earlier tiers" section grows tier by tier: 175 words in Tier 5, 290 in Tier 6, 641 in Tier 7.

Of Tier 7's five findings, two carry a security lesson: the control that passed seventeen tests and could not fire over the wire (`:841`), and the ledger row that silently fell off four tiers earlier (`:845`). The other three are firmware defects with no security content: a JSON unescape bug, a PSA key permission intersection, and Tier 5's stale trial record.

One sizing bug is documented in six places. `CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN` and `err=-113` occupy a 130-word aside in the middle of Tier 2's core teaching section at `:227`, plus troubleshooting rows in Tiers 2, 3 and 4 and a disambiguation row in Tier 6.

The structural instance is `T5-W-26`. It is a Weakness ledger row created entirely by a non-security defect, it receives around 230 words of explanation at `tier-05:436`, and it is inherited into the ledgers of Tiers 6 and 7, so every later tier carries it forward. `T5-W-15`, a Zephyr watchdog driver quirk, is the same shape and smaller.

## F-06: Tiers 2, 3 and 4 omit Section 14 silently

The module template requires the section, or one line stating that the tier found nothing. Tiers 2, 3 and 4 have neither. They did find things: `tier-05:463` says "four out of four have now found something" and `tier-06:315` says "five out of five". Tier 3's discovery of Tier 2's TLS buffer limit is written into Tier 2's body rather than Tier 3's own module.

## F-07: Tier 5 is unreachable by navigation

`tier-04:546` is the only Continue section in the course that names the next tier without linking it. `../tier-05-recovery/index.md` is referenced from nowhere in `course-material/`.

## F-08: Tier 5's Primary references departs from the format

`tier-05:520` is a bullet list rather than the five-column table every other tier uses, and it points only at specification sections and function names. It is the only tier with no external reading.

## F-09: the landing-page glossary is incomplete and covers the wrong things

`course-material/index.md` defines eighteen terms. `CONTEXT.md` also defines `Bootstrap credential`, `Claim window`, `Claim nonce`, `Owner credential`, `Update assignment` and `Secure element`, all of which Tiers 6 and 7 use constantly and none of which reach the Learner's glossary.

Separately, every entry in that glossary is a course role or artifact. Not one is a security concept a newcomer would need to look up.

## F-10: the Wi-Fi passphrase in every image is never named as a weakness

The Wi-Fi passphrase is compiled into every image from Tier 0, at `tier-00:157`. Tier 6 then teaches at length that anything inside a firmware image is public, and never applies that lesson to the credential the course itself placed there.

It surfaces only as a safety note on `./course device dump` at `tier-06:37`, and as one aside at `tier-07:561` calling build-time credentials a teaching simplification. There is no Weakness ledger row for it.

## F-11: idiom and culture-bound phrasing

Against the rule in `docs/agents/course-writing.md` to avoid idioms and culture-specific references.

| Phrase | Location |
| --- | --- |
| "a stranger who found it in a skip" | `tier-07:549` |
| "the factory canteen" | `tier-02:5` |
| "the table a careful engineer writes on a Friday" | `tier-04/answers.md:44` |
| "Sit with that", "Sit with step 2", "the pair to sit with" | `tier-03:291`, `tier-04:119`, `tier-06:237`, `tier-07:676` |
| "the check that ran out of patience with you" | `tier-02:459` |
| "an availability problem wearing a security badge" | `tier-02:470` |
| "a missing control wearing a risk costume" | `tier-01/answers.md:47` |
| "you are in good company" | `tier-05:415` |
| "the distinction has teeth" | `tier-04:521` |
| "a more useful result than a victory lap" | `tier-07:802` |
| "repay attention", "repays attention" | `tier-05:317`, `tier-05:396` |
| "has already cost an afternoon" | `tier-02:227` |

## F-12: mixed British and American spelling

`behavior` appears 10 times and `behaviour` 3. Also `recognise` at `tier-03:381`, `sceptical` at `tier-05:15`, and `labelled` twice. This undermines the rule to use the same word for a concept in every module.

## F-13: sentence length drifts upward in Tiers 6 and 7

Several sentences exceed 50 words with two or three colon-joined clauses. `tier-06:251`, the key-derivation sentence, and `tier-07:672` are the clearest examples. Tiers 0 to 3 do not do this.

## F-14: Tier 7 is disproportionate

13,418 words against 6,720 for the next largest module, at the same 4-hour budget as Tiers 4 and 6. Either the estimate or the module is wrong.

## What was found to be sound

These are recorded so that a later pass does not mistake them for oversights.

The tier arc has no conceptual gaps. Every tier names what the previous one did not buy, at `tier-02:15`, `tier-03:13` and `tier-04:15` among others, and the "claims you must not make" block appears in every control tier.

The fixed heading spine holds string for string across all eight modules. No em dash appears anywhere in `course-material/`. Every relative link resolves. One paragraph per source line is observed throughout.

The honesty discipline is the course's strongest feature and no finding above asks for less of it: Tier 6 refusing to let per-device keys look like a complete fix, Tier 4 naming the bootloader rather than the application as the security boundary, and the consistent refusal to let a host result stand in for a device result.

The out-of-sequence `T5-W-26`, appearing numerically after `T7-W-25`, is correct under the numbering rule in the module template. It is not a defect, though no learner-facing text explains why the number jumps.
