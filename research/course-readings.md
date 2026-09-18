# Course readings for the hardening tiers

**Research question:** [GitHub issue #18](https://github.com/tkEmLogic/learning-cyber-security/issues/18), part of map [#1](https://github.com/tkEmLogic/learning-cyber-security/issues/1)

**Access and review date:** 11 September 2026

**Status:** Research and reading guidance. This is not legal advice. The course must not claim CRA conformity.

## Short answer

This report lists the external readings that support each course module. The course is organized as cumulative hardening tiers, from T0 to T10, plus two advanced modules. Each tier introduces one control or lifecycle capability. A reading is placed at the first tier where the learner needs it. A reading should answer the decision or observation for that tier without asking the learner to understand a later control.

Each reading is marked required, recommended, or optional. Each reading also shows whether it is normative (a law, standard, or protocol specification that states rules) or explanatory (a vendor guide, project document, or article that explains a topic). For a large source, the tables give the exact section or page to read. Licensing and access notes are collected in the source register at the end.

## How to use this list

**Required** means the learner reads it to make or understand the tier decision. Aim for one to three required readings per tier.

**Recommended** means the reading adds useful depth. Read it if time allows.

**Optional** means the reading is for a learner who wants background or a wider view.

**Normative** means the source states rules or a formal specification. Treat its statements as binding for the object it governs. Laws, standards-track RFCs, IEEE and ISO standards, and the SUIT and TUF specifications are normative. **Explanatory** means the source teaches or describes. Vendor documents, project guides, ENISA guidance, and blog posts are explanatory. Use explanatory sources to learn, not as proof of a legal or protocol rule.

Read the exact section named in the "Where to read" column. Do not read a whole large specification unless the tier needs it.

## Baseline versions

The course pins these versions. Keep readings aligned to them.

| Component | Version | Note |
| --- | --- | --- |
| Board | ESP32-C6 | Reference product target. |
| Zephyr | 4.4.2 | Use the 4.4.2 documentation set. |
| MCUboot | 2.4.0 | Use the 2.4.0 release notes and pinned docs. |
| ESP-IDF security docs | v6.1 | Used for ESP32-C6 hardware security features in the advanced module. |

If the course later moves to a newer stable version, restate the compatibility impact and update the pinned links in this list.

## Cross-cutting readings

These readings support the whole course. Introduce them early and return to them.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 9019, A Firmware Update Architecture for Internet of Things](https://www.rfc-editor.org/rfc/rfc9019) | Recommended | Normative (informational) | What are the standard parts and threats of an IoT firmware update system? | Sections 2 to 3, and Section 3.5 on security requirements. |
| [CRA, Regulation (EU) 2024/2847, Annex I](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I) | Recommended | Normative and legal | Which security properties and vulnerability-handling duties does EU law expect? | Annex I, Part I for product properties and Part II for vulnerability handling. |
| [Latacora, Cryptographic Right Answers: Post-Quantum Edition](https://www.latacora.com/blog/post-quantum-cryptographic-right-answers/) | Optional | Explanatory | Why should signature and key choices stay replaceable across a five-year product life? | Whole post. Use only as a discussion of cryptographic agility and product lifetime. Do not use it to add post-quantum cryptography to the course. |

The cumulative weakness ledger, the security evidence pack, the attack-and-retest cycle, and the residual-risk review are course-owned processes defined by the course itself, so they need no external reading.

## T0. Unsecured reference product

The learner runs the insecure baseline and observes weaknesses. The baseline has HTTP OTA, an unsigned MCUboot, and no TLS, device authentication, metadata signing, anti-rollback, or security event records.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [Zephyr device management, OTA overview](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/ota.html) | Required | Explanatory | What are the parts of an OTA update path, and where can it fail when nothing is secured? | The OTA overview page. |
| [MCUboot, readme for Zephyr](https://docs.mcuboot.com/readme-zephyr.html) | Required | Explanatory | How does MCUboot pick and run an image, and what does an unsigned configuration allow? | The "Building" and "Signing the application" sections. |
| [Zephyr device firmware upgrade with MCUboot](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/dfu.html) | Optional | Explanatory | How does Zephyr hand a downloaded image to MCUboot? | The MCUboot and image management sections. |

## T1. Product and threat modeling

The learner describes the product, its assets, and its threats before adding any control.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | Required | Explanatory | How do I structure a threat model and record assets, threats, and mitigations? | Whole page. |
| [Microsoft, Threats and the STRIDE model](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) | Recommended | Explanatory | Which threat categories should I check for each part of the data flow? | The STRIDE category table. |
| [ENISA, Baseline Security Recommendations for IoT](https://www.enisa.europa.eu/publications/baseline-security-recommendations-for-iot) | Recommended | Explanatory | Which baseline security areas apply to a connected device? | The security measures and gap sections. |
| [ETSI EN 303 645, Cyber Security for Consumer IoT](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) | Optional | Normative | Which baseline provisions describe good practice for connected devices? | Clause 5 provisions. Version 3.1.3. |

## T2. HTTPS server authentication and confidentiality

The learner replaces HTTP with HTTPS so the device can authenticate the server and protect the transfer.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) | Required | Normative | What does TLS provide, and what does server authentication actually verify? | Section 1 for the overview and Appendix E.1 for the security properties. |
| [Zephyr networking, BSD sockets and TLS](https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html) | Required | Explanatory | How do I open a TLS client socket and supply trust anchors in Zephyr? | The "TLS credentials" and secure socket option sections. |
| [RFC 5280, Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) | Recommended | Normative | How is a server certificate structured and checked against a trust anchor? | Section 4 for the certificate fields and Section 6 for path validation. |

## T3. Offline-signed MCUboot application images

The learner signs application images offline and MCUboot verifies them. This builds a software-rooted trust chain.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [MCUboot design document](https://docs.mcuboot.com/design.html) | Required | Explanatory | How does MCUboot verify an image signature before it runs the image? | The "Image format" and image verification sections. |
| [MCUboot imgtool](https://docs.mcuboot.com/imgtool.html) | Required | Explanatory | How do I sign an image offline and keep the signing key off the device? | The key generation and "sign" command sections. |
| [MCUboot, readme for Zephyr](https://docs.mcuboot.com/readme-zephyr.html) | Recommended | Explanatory | How do I sign a Zephyr application by hand? | The "Signing the application manually" section. |
| [Latacora, Cryptographic Right Answers: Post-Quantum Edition](https://www.latacora.com/blog/post-quantum-cryptographic-right-answers/) | Optional | Explanatory | Why keep the signature algorithm replaceable over the product life? | Whole post. Discussion of agility only. Do not add post-quantum cryptography. |

## T4. Signed immutable release metadata and downgrade policy

The learner signs release metadata, makes releases immutable, and adds a downgrade policy with security counters.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 9124, A Manifest Information Model for Firmware Updates in IoT Devices](https://www.rfc-editor.org/rfc/rfc9124) | Required | Normative (informational) | Which fields must signed update metadata carry to resist tampering and downgrade? | The threat sections and the required manifest elements. |
| [MCUboot design document, security counter](https://docs.mcuboot.com/design.html) | Required | Explanatory | How does MCUboot use a monotonic security counter to block a downgrade? | The "Security counter" and rollback protection sections. |
| [The Update Framework (TUF) specification](https://theupdateframework.github.io/specification/latest/) | Recommended | Normative | How does a repository sign and expire metadata to resist rollback and mix-and-match? | Sections 1 to 4 on roles and metadata. |
| [RFC 9019, firmware update architecture](https://www.rfc-editor.org/rfc/rfc9019) | Recommended | Normative (informational) | Which security requirements apply to update metadata? | Section 3.5. |

## T5. Resumable download, test boot, health confirmation, revert, and serial recovery

The learner adds a resumable download, a MCUboot test boot, a health confirmation, an automatic revert, and a serial recovery path.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [MCUboot design document, swap and revert](https://docs.mcuboot.com/design.html) | Required | Explanatory | How do test boot, confirm, and automatic revert work? | The "Swap" and "High-level operation" sections on swap types and confirmation. |
| [MCUboot serial recovery](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/serial_recovery.md) | Required | Explanatory | How can a device recover when a new image fails to confirm? | Whole document. Pinned to v2.4.0. |
| [Zephyr device management, mcumgr](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/mcumgr.html) | Recommended | Explanatory | How does the device receive and manage images over the SMP protocol? | The image management and transport sections. |

### Comparison: Eclipse hawkBit, Mender MCU, and Golioth

The resolved OTA architecture decision uses the course-owned HTTPS pull service for every lab in this course. These three readings are comparison references only, so the learner can see where a maintained fleet platform adds operational capability that the small course service intentionally omits. No lab in this course requires an account with, or a deployment to, any of these three services.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [Eclipse hawkBit, Rollout management](https://hawkbit.eclipse.dev/#/rollout-management) | Recommended | Explanatory | How does a self-hosted fleet platform stage a rollout across groups and stop it automatically on errors, compared with the course's single canary-then-remaining-devices step? | The "Cascading Deployment Group Execution" section. |
| [Mender, Microcontroller tutorial](https://docs.mender.io/get-started/microcontroller-preview) | Recommended | Explanatory | How does a self-hosted or hosted fleet client support MCU devices, and which guarantees does it still leave to MCUboot rather than provide itself? | The paragraph on the MCU device tier and its unsupported features, including artifact signing. |
| [Golioth, Over-the-Air (OTA) updates](https://docs.golioth.io/device-management/ota/) | Recommended | Explanatory | How does a managed free-usage OTA service model packages, artifacts, deployments, and cohorts, compared with the course's single signed release manifest? | The "Concepts" section, covering packages, artifacts, deployments, and cohorts. |

## T6. Unique per-device factory identity and provisioning

The learner gives each device a unique factory identity that cannot be cloned.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [IEEE Std 802.1AR, Secure Device Identity](https://grouper.ieee.org/groups/802/1/pages/802.1ar.html) | Required | Normative | What is an initial device identity, and how is it bound to the device? | The scope and overview page. The full standard defines IDevID and LDevID. |
| [Espressif, ESP32-C6 eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html) | Required | Explanatory | Where can a device store a unique key so it cannot be copied? | The eFuse blocks and key purpose sections. |
| [Espressif, esp_secure_cert_mgr](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md) | Recommended | Explanatory | How is a per-device certificate and key stored securely at the factory? | Whole readme. |
| [Espressif, ESP32-C6 mass manufacturing utility](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/mass_mfg.html) | Recommended | Explanatory | How do I provision unique data to many devices at the factory? | Whole page. |

## T7. Owner-scoped operational identity and mutual TLS

The learner enrolls an owner-scoped operational identity and uses mutual TLS between the device and the service.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 7030, Enrollment over Secure Transport (EST)](https://www.rfc-editor.org/rfc/rfc7030.html) | Required | Normative | How does a device enroll and obtain an operational certificate? | Sections 2 and 4 on enrollment. |
| [RFC 8446, TLS 1.3, client authentication](https://www.rfc-editor.org/rfc/rfc8446) | Required | Normative | How does a server request and verify a client certificate for mutual TLS? | Section 4.3.2 on CertificateRequest and Section 4.4.2 on Certificate. |
| [RFC 8995, Bootstrapping Remote Secure Key Infrastructure (BRSKI)](https://www.rfc-editor.org/rfc/rfc8995.html) | Recommended | Normative | How can a device use its factory identity to bootstrap trust with an owner? | The architecture and voucher sections. |
| [RFC 5280, X.509 certificate profile](https://www.rfc-editor.org/rfc/rfc5280) | Recommended | Normative | How is the operational certificate structured and validated? | Section 4 and Section 6. |

### Note: why the device has no authenticated time

Tier 7 issues an Operational certificate that is valid for a limited period, and the device cannot check that period. The course build leaves `CONFIG_MBEDTLS_HAVE_TIME_DATE` off, so the device has no trusted wall-clock time, and the OTA service enforces expiry on its behalf. This note explains why getting the time is harder than it looks, and why section 7 of the course specification says that device time is evidence and not an authorization input.

The device cannot simply be handed the time by the service it talks to. Section 6 of the course specification treats the OTA service as untrusted. It may deny an update or replay an old signed release, and it is trusted only to carry bytes that the device verifies for itself against a key it already holds. A plain timestamp is not such a byte string, because nothing on the device can check it. Taking the time from the party whose certificate you are about to validate is also circular. An attacker who controls that party sets the clock to a moment when the certificate they hold is still valid, and the check then passes every time.

Plain SNTP does not solve it either. SNTP carries no authentication, so any attacker who can answer on the local network can return whatever time suits them. That is the same attacker Tier 0 and Tier 2 already teach, the one who reads and rewrites traffic on the classroom network. A device that trusts an SNTP answer has moved the decision from the service to whoever replies first.

Two protocols do answer the problem. Network Time Security, RFC 8915, authenticates NTP using TLS key establishment, so the client knows which server answered and that the answer was not changed in transit. Roughtime takes a different route and lets a client collect signed answers from several servers, so a server that reports a false time can be shown to have lied. Both are out of scope for this course. Tier 7 records the device's blindness to time as a weakness-ledger row instead, and the service stays the single authority on whether a certificate has expired.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 8915, Network Time Security for the Network Time Protocol](https://www.rfc-editor.org/rfc/rfc8915.html) | Optional | Normative | How does a device get the time from a server it can authenticate? | Section 1.3 for the two protocols, then Section 8 for the attacks that remain, including the delay attack in Section 8.6 and NTS stripping in Section 8.7. |
| [Roughtime, draft-ietf-ntp-roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) | Optional | Explanatory | How can a client prove that a time server gave it a false answer? | Read it as a design sketch, not as a course requirement. Check the datatracker page first for the current status. |

## T8. Renewal, rotation, revocation, recovery, ownership transfer, and decommission

The learner runs the full identity lifecycle: renew, rotate, revoke, recover, transfer ownership, and decommission.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [NIST SP 800-57 Part 1 Revision 5, Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Required | Normative | How long should keys live, and how do I plan rotation and retirement? | Section 5 on the key lifecycle and Section 8 on transitions. |
| [RFC 6960, X.509 Online Certificate Status Protocol (OCSP)](https://www.rfc-editor.org/rfc/rfc6960) | Required | Normative | How is a certificate revoked and its status checked? | Sections 2 and 4 on request and response. |
| [RFC 5280, certificate revocation lists](https://www.rfc-editor.org/rfc/rfc5280) | Recommended | Normative | How does a CRL record revoked certificates? | Section 5. |
| [RFC 8995, BRSKI, ownership](https://www.rfc-editor.org/rfc/rfc8995.html) | Recommended | Normative | How is device ownership established and transferred with a voucher? | The voucher and ownership sections. |

## T9. SBOM, vulnerability handling, remediation, rollout, support policy, and CRA Article 14

The learner builds an SBOM, handles a vulnerability, ships a remediation release, and runs the CRA Article 14 reporting exercise with traceability.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [CRA, Regulation (EU) 2024/2847, Article 14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14) | Required | Normative and legal | What must a manufacturer report about actively exploited vulnerabilities and severe incidents, to whom, and by when? | Article 14, with the reporting timelines. |
| [CRA, Article 13 and Annex I Part II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13) | Required | Normative and legal | Which ongoing vulnerability-handling, SBOM, and support-period duties apply? | Article 13 and Annex I Part II on vulnerability handling. |
| [NTIA, The Minimum Elements for a Software Bill of Materials (SBOM)](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf) | Required | Explanatory | What must an SBOM contain at a minimum? | The "Data Fields" and minimum-elements sections. |
| [CISA, Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom) | Recommended | Explanatory | How is an SBOM used across the supply chain? | The overview page. |
| [CycloneDX specification overview](https://cyclonedx.org/specification/overview/) | Recommended | Explanatory | Which machine-readable SBOM format can the build produce? | The overview page. |
| [FIRST, Common Vulnerability Scoring System (CVSS) v4.0](https://www.first.org/cvss/v4-0/) | Recommended | Normative | How do I score the severity of a vulnerability? | The specification document. |
| [SPDX specifications](https://spdx.dev/use/specifications/) | Optional | Explanatory | Which alternative SBOM format is available? | The current specification page. |
| [ISO/IEC 29147:2018, Vulnerability disclosure](https://www.iso.org/standard/72311.html) | Optional | Normative | How should a manufacturer receive and disclose vulnerability reports? | Whole standard. Paywalled. |
| [ISO/IEC 30111:2019, Vulnerability handling processes](https://www.iso.org/standard/69725.html) | Optional | Normative | How should a manufacturer investigate and remediate a report? | Whole standard. Paywalled. |

## T10. Integrated attack and failure

The learner defends against a combined attack and failure scenario that spans earlier tiers. No new external reading is required. The learner reviews the readings for the tiers under test and the weakness ledger.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [RFC 9019, firmware update architecture](https://www.rfc-editor.org/rfc/rfc9019) | Recommended | Normative (informational) | How do the update controls fit together against a realistic attacker? | Read the whole document as a system review. |
| [CRA, Annex I](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I) | Recommended | Normative and legal | Do the combined controls cover the expected product properties? | Annex I, Part I and Part II, as a checklist. |

## Advanced A. ESP32-C6 hardware-rooted security

The learner manually integrates ESP32-C6 Secure Boot v2, flash encryption, eFuses, debug and download restrictions, and signed recovery, then validates on a physical board. Several steps burn eFuses and are irreversible.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [Espressif, ESP32-C6 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/secure-boot-v2.html) | Required | Explanatory | How does hardware-rooted secure boot verify the bootloader and image? | Whole page. ESP-IDF v6.1. |
| [Espressif, ESP32-C6 flash encryption](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/flash-encryption.html) | Required | Explanatory | How is flash content protected, and which steps are irreversible? | Whole page, with the release-mode warnings. |
| [Espressif, ESP32-C6 eFuse Manager](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/system/efuse.html) | Required | Explanatory | How are eFuses read and burned, and why is burning permanent? | The key blocks and burning sections. |
| [Espressif, security feature enablement workflows](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/security-features-enablement-workflows.html) | Recommended | Explanatory | In which order do I enable the irreversible security features safely? | Whole page. |
| [Espressif, espefuse tool for ESP32-C6](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/index.html) | Recommended | Explanatory | How do I inspect and burn eFuses from the host? | The command reference. |
| [MCUboot, readme for Espressif](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/readme-espressif.md) | Recommended | Explanatory | How does MCUboot use the Espressif secure boot and flash encryption? | Whole document. Pinned to v2.4.0. |

## Advanced B. STSAFE-A120 private-key isolation and mutual TLS

The learner uses the STSAFE-A120 secure element to hold a non-exportable private key and runs mutual TLS. If the pinned integration does not pass hardware validation, the learner runs a guided comparison instead.

| Reading | Level | Type | Learning question it answers | Where to read |
| --- | --- | --- | --- | --- |
| [STMicroelectronics, STSAFE-A120 datasheet](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf) | Required | Explanatory | What does the secure element do, and how does it isolate a private key? | The features and cryptographic services sections. |
| [ST, AN6206, online certificate distribution for STSAFE-A](https://www.st.com/resource/en/application_note/an6206-online-certificate-distribution-for-stsafea-products-stmicroelectronics.pdf) | Recommended | Explanatory | How is a device certificate provisioned for the secure element? | Whole application note. |
| [catie-aq, Zephyr STSAFE-A1xx driver](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/tree/5b7f1243db53506ae9c50ffc4eecda0224512c12) | Recommended | Explanatory | How does a community Zephyr driver expose STSAFE-A120, and where are its limits? | The readme and sample readmes. This is the scaffold used for the comparison fallback. Not an ST product. |
| [STMicroelectronics, STSELib](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/README.md) | Optional | Explanatory | Which official library exposes STSAFE cryptographic operations? | The readme. Pinned to v1.1.9. |

## Maintenance policy

Re-check this list on each course release and at least every six months. The next scheduled review is by 11 March 2027.

On each review, confirm the pinned versions still match the course. Watch Zephyr 4.4.2, MCUboot 2.4.0, and ESP-IDF v6.1. Replace any "latest" or "stable" link with a pinned version link when the course pins a new version, and record the compatibility impact.

Re-validate every URL on the review date. Some sources block automated checks. ST.com PDFs and ISO.org pages returned blocks or timeouts from an automated client on the access date. Verify these by hand in a browser.

Watch the sources that change without a version number. These are living web pages: the Espressif Zephyr support page, the CISA SBOM page, the ENISA publication page, and the Commission CRA pages. Re-read them and update the notes if they change.

Watch for new normative releases. Track updates to the CRA and its Commission guidance, ETSI EN 303 645, the ISO/IEC 29147 and 30111 standards, CVSS, and the SUIT RFCs. Update the "Where to read" pointers if section numbers move.

## Uncertain or unavailable sources

These sources need manual attention at each review.

| Source | Reason | Action |
| --- | --- | --- |
| ST STSAFE-A120 datasheet and AN6206 | ST.com blocked or timed out from an automated client. The links were confirmed by the sibling STSAFE research on the same access date. | Open each link in a browser and confirm it still resolves. |
| ISO/IEC 29147:2018 and ISO/IEC 30111:2019 | The ISO catalogue pages return 403 to an automated client, and the standards are paywalled. | Confirm the catalogue numbers by hand. Buy or access through a library if the content is needed. |
| IEEE Std 802.1AR | The standard is paywalled, although IEEE 802 standards are often free through the IEEE GET Program after a delay. | Check current free availability, or purchase, before relying on the full text. |
| catie-aq Zephyr STSAFE-A1xx driver | Community project, not an ST product, and pinned to one commit. It is the comparison fallback and may not pass hardware validation. | Re-check the commit and the project status. Prefer an official ST integration if one becomes available. |
| Roughtime, draft-ietf-ntp-roughtime | An Internet-Draft, not yet an RFC. It was in final review at the RFC Editor on 19 September 2026, so it may gain an RFC number and a new URL. | Check the datatracker page and replace the draft link with the RFC link once one is assigned. |
| Latacora post-quantum article | A vendor blog post, used only as discussion of cryptographic agility and product lifetime. | Keep it optional. Do not use it to add post-quantum cryptography to the course. |

## Source register

All sources were accessed and reviewed on 11 September 2026.

| Source | Version or date | Type | Licence and access |
| --- | --- | --- | --- |
| [CRA, Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) | Official Journal L 2024/2847, 20 November 2024. CELEX 32024R2847. | Normative and legal | European Union copyright. Reuse permitted under the Commission reuse policy. Free to read on EUR-Lex. |
| [ETSI EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) | Version 3.1.3. | Normative | ETSI copyright. Free PDF download. |
| [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) | August 2018, standards track. | Normative | IETF Trust. Free to read. |
| [RFC 5280, X.509 and CRL profile](https://www.rfc-editor.org/rfc/rfc5280) | May 2008, standards track. | Normative | IETF Trust. Free to read. |
| [RFC 6960, OCSP](https://www.rfc-editor.org/rfc/rfc6960) | June 2013, standards track. | Normative | IETF Trust. Free to read. |
| [RFC 7030, EST](https://www.rfc-editor.org/rfc/rfc7030.html) | October 2013, standards track. | Normative | IETF Trust. Free to read. |
| [RFC 8995, BRSKI](https://www.rfc-editor.org/rfc/rfc8995.html) | May 2021, standards track. | Normative | IETF Trust. Free to read. |
| [RFC 8915, Network Time Security](https://www.rfc-editor.org/rfc/rfc8915.html) | September 2020, standards track. | Normative | IETF Trust. Free to read. Added for the Tier 7 authenticated-time note and checked on 19 September 2026, after this register's access date. |
| [Roughtime, draft-ietf-ntp-roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) | Revision 19, 17 March 2026. Internet-Draft with intended status Experimental, in final review at the RFC Editor on the check date. | Explanatory | IETF Trust. Free to read. Added for the Tier 7 authenticated-time note and checked on 19 September 2026, after this register's access date. |
| [RFC 9019, IoT firmware update architecture](https://www.rfc-editor.org/rfc/rfc9019) | April 2021, informational. | Normative (informational) | IETF Trust. Free to read. |
| [RFC 9124, SUIT manifest information model](https://www.rfc-editor.org/rfc/rfc9124) | January 2022, informational. | Normative (informational) | IETF Trust. Free to read. |
| [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) | Living specification, current on access date. | Normative | Cloud Native Computing Foundation project. Free to read. |
| [IEEE Std 802.1AR](https://grouper.ieee.org/groups/802/1/pages/802.1ar.html) | 2018 edition. | Normative | IEEE copyright. Full text paywalled. Abstract page is free. |
| [NIST SP 800-57 Part 1 Rev 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Revision 5, May 2020. | Normative | United States Government work, public domain. Free to read. |
| [NTIA SBOM minimum elements](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf) | July 2021. | Explanatory | United States Government work, public domain. Free to read. |
| [CISA SBOM page](https://www.cisa.gov/sbom) | Web page current on access date. | Explanatory | United States Government work, public domain. Free to read. |
| [CycloneDX specification overview](https://cyclonedx.org/specification/overview/) | Current on access date. | Explanatory | OWASP Foundation project. Open specification. |
| [SPDX specifications](https://spdx.dev/use/specifications/) | Current on access date. | Explanatory | Linux Foundation project. Open specification. |
| [FIRST CVSS v4.0](https://www.first.org/cvss/v4-0/) | Version 4.0. | Normative | FIRST.Org. Free to use. |
| [ISO/IEC 29147:2018](https://www.iso.org/standard/72311.html) | 2018 edition. | Normative | ISO copyright. Paywalled. |
| [ISO/IEC 30111:2019](https://www.iso.org/standard/69725.html) | 2019 edition. | Normative | ISO copyright. Paywalled. |
| [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | Current on access date. | Explanatory | OWASP, Creative Commons. Free to read. |
| [Microsoft STRIDE threats](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) | Current on access date. | Explanatory | Microsoft documentation. Free to read. |
| [ENISA Baseline Security Recommendations for IoT](https://www.enisa.europa.eu/publications/baseline-security-recommendations-for-iot) | 2017 publication. | Explanatory | ENISA. Free to read. |
| [Zephyr OTA overview](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/ota.html) | 4.4.2 docs. | Explanatory | Zephyr Project, Apache-2.0 documentation. Free to read. |
| [Zephyr DFU with MCUboot](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/dfu.html) | 4.4.2 docs. | Explanatory | Zephyr Project, Apache-2.0. Free to read. |
| [Zephyr mcumgr](https://docs.zephyrproject.org/4.4.2/services/device_mgmt/mcumgr.html) | 4.4.2 docs. | Explanatory | Zephyr Project, Apache-2.0. Free to read. |
| [Eclipse hawkBit, Rollout management](https://hawkbit.eclipse.dev/#/rollout-management) | Living documentation. Server release 1.1.0 current on access date. | Explanatory | Eclipse Foundation project, EPL-2.0. Free to read. Comparison reference only. |
| [Mender, Microcontroller tutorial](https://docs.mender.io/get-started/microcontroller-preview) | Mender MCU 1.0.0, stable release, 20 April 2026. | Explanatory | Northern.tech AS documentation. Free to read. Comparison reference only. |
| [Golioth, Over-the-Air (OTA) updates](https://docs.golioth.io/device-management/ota/) | Web page current on access date. | Explanatory | Golioth, Inc. documentation. Free to read. Comparison reference only. |
| [Zephyr sockets and TLS](https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html) | 4.4.2 docs. | Explanatory | Zephyr Project, Apache-2.0. Free to read. |
| [MCUboot design](https://docs.mcuboot.com/design.html) | 2.4.0. | Explanatory | MCUboot project, Apache-2.0. Free to read. |
| [MCUboot imgtool](https://docs.mcuboot.com/imgtool.html) | 2.4.0. | Explanatory | MCUboot project, Apache-2.0. Free to read. |
| [MCUboot readme for Zephyr](https://docs.mcuboot.com/readme-zephyr.html) | 2.4.0. | Explanatory | MCUboot project, Apache-2.0. Free to read. |
| [MCUboot serial recovery](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/serial_recovery.md) | v2.4.0. | Explanatory | MCUboot project, Apache-2.0. Free to read. |
| [MCUboot readme for Espressif](https://github.com/mcu-tools/mcuboot/blob/v2.4.0/docs/readme-espressif.md) | v2.4.0. | Explanatory | MCUboot project, Apache-2.0. Free to read. |
| [Espressif ESP32-C6 Secure Boot v2](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/secure-boot-v2.html) | ESP-IDF v6.1. | Explanatory | Espressif documentation. Free to read. |
| [Espressif ESP32-C6 flash encryption](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/flash-encryption.html) | ESP-IDF v6.1. | Explanatory | Espressif documentation. Free to read. |
| [Espressif ESP32-C6 eFuse Manager (v6.1)](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/api-reference/system/efuse.html) | ESP-IDF v6.1. | Explanatory | Espressif documentation. Free to read. |
| [Espressif security enablement workflows](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c6/security/security-features-enablement-workflows.html) | ESP-IDF v6.1. | Explanatory | Espressif documentation. Free to read. |
| [Espressif espefuse tool](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/espefuse/index.html) | Current on access date. | Explanatory | Espressif documentation. Free to read. |
| [Espressif ESP32-C6 eFuse Manager (stable)](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/efuse.html) | ESP-IDF stable. | Explanatory | Espressif documentation. Free to read. |
| [Espressif mass manufacturing utility](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/storage/mass_mfg.html) | ESP-IDF stable. | Explanatory | Espressif documentation. Free to read. |
| [Espressif esp_secure_cert_mgr](https://github.com/espressif/esp_secure_cert_mgr/blob/main/README.md) | main branch on access date. | Explanatory | Espressif project, Apache-2.0. Free to read. |
| [STMicroelectronics STSAFE-A120 datasheet](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf) | Current on access date. | Explanatory | ST copyright. Free to read. Automated access blocked. |
| [ST AN6206 online certificate distribution](https://www.st.com/resource/en/application_note/an6206-online-certificate-distribution-for-stsafea-products-stmicroelectronics.pdf) | Current on access date. | Explanatory | ST copyright. Free to read. Automated access blocked. |
| [STMicroelectronics STSELib](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/README.md) | v1.1.9. | Explanatory | ST project licence, see repository. Free to read. |
| [catie-aq Zephyr STSAFE-A1xx driver](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/tree/5b7f1243db53506ae9c50ffc4eecda0224512c12) | Pinned commit 5b7f124. | Explanatory | Community project, Apache-2.0. Free to read. Not an ST product. |
| [Latacora post-quantum article](https://www.latacora.com/blog/post-quantum-cryptographic-right-answers/) | Blog post, current on access date. | Explanatory | Latacora, all rights reserved. Link only, do not copy. |
