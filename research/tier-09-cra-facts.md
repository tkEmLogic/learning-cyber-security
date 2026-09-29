# CRA reporting and product facts for Tier 9, as of September 2026

**Research question:** [GitHub issue #268](https://github.com/tkEmLogic/learning-cyber-security/issues/268), under the Tier 9 map [#265](https://github.com/tkEmLogic/learning-cyber-security/issues/265).

**Builds on:** [#3](https://github.com/tkEmLogic/learning-cyber-security/issues/3) and its report, [`research/cra-obligations.md` on branch `research/cra-obligations`](https://github.com/tkEmLogic/learning-cyber-security/blob/research/cra-obligations/research/cra-obligations.md), accessed 11 September 2026. This report updates that one. It does not repeat what is still correct there.

**Access date for every source below:** 30 September 2026, unless a row says otherwise.

**Status:** Research, not legal advice. The course never makes a legal determination for the Learner (specification section 4).

## Short answer

Article 14 reporting has applied since 11 September 2026. ENISA's Single Reporting Platform (SRP) is live at `https://portal.cra-srp.enisa.europa.eu/`. ENISA publishes a field glossary for it. No implementing act under Article 14(10) fixes the format or procedure of the notifications. The only new binding act on reporting is Delegated Regulation (EU) 2026/881, which governs when a CSIRT may delay passing a notification on to other CSIRTs. It places no new duty on the manufacturer.

The Commission's July 2026 guidance says the clock starts when the manufacturer, after a prompt initial assessment, has "a reasonable degree of certainty" that a vulnerability is being actively exploited or that a severe incident has compromised the product.

Section 4 of the specification is correct on all four deadlines. One phrase is worth tightening: the severe-incident final report runs from when the incident notification is *submitted*, not from the 72-hour deadline.

ENISA lists a coordinating CSIRT for all 27 member states. For the fictional manufacturer, this report recommends **Ireland**, with the NCSC (CSIRT-IE) as coordinator. It publishes English national guidelines, a helpdesk address and an outage procedure. Its guidelines also contain one timing statement stricter than the Regulation, which the scenarios must handle (see "The recommended member state").

The CRA has **not** been incorporated into the EEA Agreement. EFTA lists it as "under scrutiny".

## What changed since #3

| Topic | #3 said (11 September 2026) | Now (30 September 2026) |
| --- | --- | --- |
| SRP | The Commission page described it. | Live since 11 September 2026. It has a portal, a user manual, a field glossary (v1.3, 25 September 2026) and an FAQ (17 September 2026). |
| Coordinating CSIRTs | Not researched. | ENISA list covers all 27 member states (page dated 10 September 2026). |
| Delegated act on delayed dissemination | Not mentioned. | Delegated Regulation (EU) 2026/881, adopted 11 December 2025, in the OJ 20 April 2026, in force 10 May 2026. |
| Implementing act on notification format (Article 14(10)) | Not mentioned. | None found. |
| Implementing act on SBOM format (Article 13(24)) | Not mentioned. | None found. |
| Commission FAQ | Not cited. | Version 1.4, 4 September 2026, has a section on reporting. |
| Annex I Part I list | Twelve outcomes. | The Annex has thirteen points, (2)(a) to (2)(m), plus point (1). #3 left out (2)(i). The full list is below. |
| EEA | Not researched. | Not incorporated. |

## 1. Article 14 as it now operates

### The law

These points are quoted or closely paraphrased from [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng), Articles 14 and 16. The text was read from the Publications Office copy of OJ L 2024/2847 (CELEX 32024R2847). No amending act was found.

- **Who and where.** The manufacturer notifies "simultaneously to the CSIRT designated as coordinator ... and to ENISA", via the single reporting platform (Article 14(1) and (3)). It uses the electronic notification end-point of the coordinating CSIRT of the member state where it has its main establishment in the Union (Article 14(7)).
- **Main establishment.** This is the member state "where the decisions related to the cybersecurity of its products with digital elements are predominantly taken". If that cannot be determined, it is the member state with the establishment that has the most employees in the Union (Article 14(7), second subparagraph). A manufacturer with no EU establishment follows a fallback order: authorised representative, then importer, then distributor, then where most users are (Article 14(7), third subparagraph).
- **Intermediate report.** The coordinating CSIRT that first receives the notification "may request" an intermediate report on status updates (Article 14(6)).
- **Users.** After becoming aware, the manufacturer informs impacted users, and where appropriate all users. Where necessary, it tells them which mitigation and corrective measures they can take, "where appropriate in a structured, machine-readable format" (Article 14(8)).
- **Format act.** "The Commission may, by means of implementing acts, specify further the format and procedures of the notifications" (Article 14(10)). This is a power, not a duty. See "What is not confirmed".
- **Delay act.** Article 14(9) required a delegated act by 11 December 2025 on the grounds for delaying dissemination under Article 16(2). That act is Delegated Regulation (EU) 2026/881 (below).
- **Voluntary reports.** Anyone may report other vulnerabilities, cyber threats, incidents and near misses voluntarily (Article 15).

### The Single Reporting Platform

These are ENISA's operating facts. They are not law.

- **Live.** ENISA says the SRP launched on 11 September 2026. The portal is `https://portal.cra-srp.enisa.europa.eu/`. [ENISA, SRP page](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp). The Commission's reporting page says the same, updated 11 September 2026. [Commission, CRA reporting](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- **Access.** An EU Login account with multi-factor authentication is required. One primary "authorised representative" (AR) user registers per manufacturer and can invite up to 20 secondary AR users. The coordinating CSIRT validates the AR-to-manufacturer link in parallel, and a pending validation does not block a submission. [ENISA, SRP FAQ, updated 17 September 2026](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions)
- **Stages.** An SRP notification moves through Early Warning, then 72-hour Notification, then Final Report. ENISA's guidance says the stages follow in order and a later stage needs the earlier one. A notification cannot be edited after the Final Report, and every update alerts the coordinating CSIRT and the concerned CSIRTs. [ENISA, AR notification submission and update guidance, updated 12 September 2026](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-guidance-ar-notification-submission-and-update)
- **Field glossary.** ENISA says the glossary explains "SRP data fields, completion instructions, examples, expected formats, timeline, and applicability". [ENISA, CRA SRP Glossary, version 1.3, 25 September 2026](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2)

### SRP fields, by stage

This table was read from the glossary page, version 1.3. "Req" means the glossary marks the field as required at that stage. "Opt" means optional. "–" means the field is not shown at that stage. Field names are ENISA's own. The course should re-read the glossary before it publishes a template, because ENISA versions it.

**Fields for both event types**

| Field | Early warning | 72-hour | Final |
| --- | --- | --- | --- |
| Notification type (Vulnerability or Incident) | Req | Req | Req |
| Title | Req | Req | Req |
| Summary | Req | Req | Req |
| Manufacturer name (filled by the system) | Req | Req | Req |
| Member States where product available (concerned CSIRTs) | Req | Req | Req |
| Product name | Req | Req | Req |
| Product version | Req | Req | Req |
| Product type (default, important, critical), class, category | Opt | Opt | Opt |
| End of support indicator (yes or no) | Opt | Opt | Opt |
| Component name | Opt | Opt | Opt |
| Mitigating measure expected shortly (yes or no) | Opt | Opt | Opt |
| User action able to reduce impact | Opt | Opt | Opt |
| Considered sensitivity of information | Opt | Opt | Req |
| Corrective or mitigating measures taken | Opt | Opt | Req |
| Corrective or mitigating measures that users can take | Opt | Opt | Req |
| Attack vector | – | Opt | Opt |

**Extra fields for an actively exploited vulnerability**

| Field | Early warning | 72-hour | Final |
| --- | --- | --- | --- |
| Date and time you became aware (UTC) | Req | Req | Req |
| Date and time the exploitation occurred (UTC) | Opt | Req | Opt |
| General information | Opt | Req | Opt |
| CVE ID, EUVD ID | Opt | Opt | Opt |
| Date when a corrective or mitigating measure became available (UTC) | Opt | Opt | Req |
| Details about the security update or corrective measure | Opt | Opt | Req |
| Full description of the severity | Opt | Opt | Req |
| Full description of the impact | Opt | Opt | Req |
| Malicious actor | Opt | Opt | Req if available |
| Particular exceptional circumstances (PEC) and PEC delay reason | – | Opt | – |
| Further information | Opt | Opt | Opt |

**Extra fields for a severe incident**

| Field | Early warning | 72-hour | Final |
| --- | --- | --- | --- |
| Suspected of unlawful or malicious acts (yes, no, unknown) | Req | Req | Req |
| Date and time you became aware (UTC) | Req | Req | Opt |
| Date and time the incident occurred (UTC) | Opt | Req | Opt |
| General information about the nature of the incident | Opt | Req | Opt |
| Initial assessment of the incident | Opt | Req | Opt |
| Applied and ongoing mitigation measures | Opt | Opt | Req |
| Detailed description of the severity | Opt | Opt | Req |
| Detailed description of the impact | Opt | Opt | Req |
| Type of threat or root cause | Opt | Opt | Req |

These fields follow Article 14(2) and (4) closely. The awareness time is a field of its own, recorded in UTC. That supports settled input 10, where the Learner records awareness on a scenario clock.

### When the clock starts

The Regulation says "becoming aware" and does not define it. The Commission's guidance defines it this way. It is non-binding, and it aligns the term with the NIS2 implementing regulation and the EDPB's GDPR breach guidelines.

> "The manufacturer is therefore to be regarded as having become aware when, after such an initial assessment, it has a reasonable degree of certainty that: (i) a vulnerability contained in its product with digital elements is being actively exploited; or (ii) a severe incident has occurred and has led to the security of its product with digital elements being compromised."

The manufacturer "should assess the suspicious event immediately", and "the emphasis should be on prompt action to carry out the initial assessment". [Commission guidance, annex to C(2026) 5252 final, 27 July 2026, section 9.1, paragraphs 211 to 214](https://ec.europa.eu/newsroom/dae/redirection/document/131456)

The same section adds four points the scenarios can use:

- **No retroactive reporting.** Exploitation the manufacturer already knew about before 11 September 2026 is not reportable. A vulnerability known before that date becomes reportable if the manufacturer learns of active exploitation after it (paragraph 217).
- **Component vulnerabilities.** A vulnerability in a third-party component that is unreachable in the product, or has not been exploited in it, is not "an actively exploited vulnerability contained in its product". It is still subject to Annex I Part II handling and to upstream reporting under Article 13(6) (paragraph 218). This matches settled input 2's "not affected" triage.
- **Old and unsupported products.** Article 14 applies from 11 September 2026 to all in-scope products, including those placed on the market before 11 December 2027. It continues after the support period ends. The Annex I Part II handling duties do not apply to products placed before 11 December 2027, or after support ends (paragraph 210).
- **Informing users.** Article 14(8) is applied in a risk-based way and does not require public disclosure. Broader disclosure may follow once the issue is fixed (paragraphs 220 and 221).

The [Commission CRA FAQ, version 1.4, 4 September 2026](https://ec.europa.eu/newsroom/dae/redirection/document/123307), section "Reporting obligations of manufacturers", lists ways a manufacturer becomes aware: a customer report, threat intelligence, a government agency, an ethical hacker, telemetry or a honeypot. It also says that a zero-day found by an ethical hacker or a test lab, with no evidence of malicious exploitation, is not an actively exploited vulnerability. The FAQ is a Commission services document and says it is not authoritative.

The Regulation's definition, Article 3(42), is: "a vulnerability for which there is reliable evidence that a malicious actor has exploited it in a system without permission of the system owner". Recital 68 excludes good-faith testing.

### Delegated Regulation (EU) 2026/881

[Commission Delegated Regulation (EU) 2026/881 of 11 December 2025](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R0881) was published in the OJ on 20 April 2026 and entered into force on 10 May 2026 (Publications Office metadata). It lets the CSIRT that first receives a notification delay passing it on to other CSIRTs. It may do so when the manufacturer has said an effective mitigation "is expected to be made available within 72 hours". If none comes in that time, the CSIRT disseminates. It may also delay while it acts as trusted intermediary in a CVD, or when the SRP or a CSIRT is compromised (Articles 3 to 5).

It adds no duty and no deadline for the manufacturer. For the scenarios, it matters only because the SRP has a "Mitigating measure expected shortly" field. That field is the manufacturer's way to ask for the delay.

## 2. The two event types and section 4 of the specification

| Stage | Actively exploited vulnerability | Severe incident | Source |
| --- | --- | --- | --- |
| Early warning | Within 24 hours of becoming aware. Indicates, where applicable, the member states where the product is available. | Within 24 hours of becoming aware. Says at least whether the incident is suspected of being caused by unlawful or malicious acts, and the member states. | Article 14(2)(a), 14(4)(a) |
| Notification | Within 72 hours of becoming aware. General information about the product, the nature of the exploit and of the vulnerability, measures taken, measures users can take, and how sensitive the information is. | Within 72 hours of becoming aware. The nature of the incident, an initial assessment, measures taken, measures users can take, and sensitivity. | Article 14(2)(b), 14(4)(b) |
| Final report | No later than 14 days after a corrective or mitigating measure is available. At least: (i) description, severity and impact; (ii) where available, the malicious actor; (iii) details of the update or other corrective measures. | Within one month after the submission of the incident notification under point (b). At least: (i) detailed description, severity and impact; (ii) type of threat or likely root cause; (iii) applied and ongoing mitigation measures. | Article 14(2)(c), 14(4)(c) |

Every stage after the early warning starts with "unless the relevant information has already been provided". So an early warning that already contains everything can satisfy the later content. ENISA's SRP still moves through three stages.

**When an incident is severe** (Article 14(5)): it negatively affects, or can affect, the product's ability to protect the availability, authenticity, integrity or confidentiality of sensitive or important data or functions. Or it has led, or can lead, to malicious code being introduced or executed in the product or in a user's network and information systems.

### Is section 4 still accurate?

Yes. All four deadlines in the section 4 table match Article 14. Two notes follow. Neither is a correction of fact.

1. **The severe-incident anchor.** Section 4 says "within one month after the 72-hour incident notification". The Regulation says "within one month after the submission of the incident notification". The Commission guidance uses the same shorthand as section 4 (paragraph 215). The two readings differ when the notification is sent early. If awareness is at T and the notification is submitted at T+30h, the final report is due one month after T+30h, not one month after T+72h. A scenario clock should anchor to the submission timestamp. A future specification amendment could say "one month after the incident notification is submitted". This report does not edit the specification.
2. **The vulnerability anchor.** The 14 days run from when a corrective or mitigating measure is *available*, not from awareness. If no measure exists yet, the Regulation sets no outer date. The intermediate report on the CSIRT's request (Article 14(6)) covers that gap. A scenario should say when the fix becomes available. In Tier 9, that is when the signed remediation release at counter 6 is approved and assigned.

## 3. The coordinating CSIRT for the fictional manufacturer

ENISA publishes the list of CSIRTs designated as coordinators for all 27 member states, with a website for each (page dated 10 September 2026). [ENISA, List of CSIRTs designated as coordinators](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/list-of-csirts-designated-as-coordinators). This list is the source used here for "what each state has designated". The national legal instrument behind each designation was not found for any of the three candidates. See "What is not confirmed".

### Candidates

| Member state | Coordinator and what it publishes | For the course |
| --- | --- | --- |
| **Ireland** | NCSC, which includes CSIRT-IE. ENISA lists `https://www.ncsc.gov.ie/cra/`. The NCSC publishes a CRA page (updated 11 September 2026) and English *Guidelines on reporting obligations under Article 14 of the CRA*, dated 31 August 2026. These give a helpdesk address, `cra_helpdesk@ncsc.gov.ie`, and an outage-only fallback address, `cra_fallback@ncsc.gov.ie`. It says: "Submissions via email will ONLY be accepted when the SRP is officially declared offline by ENISA." Reporting is through the SRP. | English sources. Plain SRP path. A national guidance document the Learner can read. |
| **Sweden** | CERT-SE at the Swedish National Cybersecurity Centre (NCSC). The NCSC page says "CERT-SE vid Nationellt cybersäkerhetscenter (NCSC) är Sveriges nationella CSIRT" and that reporting is done in ENISA's platform. It gives `ncsc@ncsc.se` and a phone number for support. | Nordic neighbour of the Norwegian employer. The sources are in Swedish. |
| **Netherlands** | NCSC-NL. Its CRA reporting page says that if you are based in the Netherlands, you report to the NCSC. It offers MijnNCSC (with eHerkenning) or a CRA web form, and says the NCSC forwards the report to ENISA and to other member states' CSIRTs. | Dutch sources. A national intake channel sits beside the SRP. How this maps to Article 14(7)'s SRP end-point was not confirmed, so it would add a question the course cannot answer. |

Sources: [NCSC Ireland, CRA page](https://www.ncsc.gov.ie/cra/). [NCSC Ireland, National CRA Guidelines v1, 31 August 2026](https://www.ncsc.gov.ie/pdfs/National_CRA_Guidelines_v1.pdf). [CERT-SE, Rapportering och anmälan](https://www.cert.se/rapportera/). [NCSC Sweden, cyberresiliensförordningen](https://www.ncsc.se/sv/radgivning-och-stod/krav-och-regler-inom-informationssakerhet-och-cybersakerhet/cyberresiliensforordningen/). [NCSC-NL, Melden onder de Cyber Resilience Act](https://www.ncsc.nl/wet-en-regelgeving/cyber-resilience-act-cra/melden). The Irish government press release on the guidelines (gov.ie) returned HTTP 403 and was not read.

### The recommended member state

**Ireland**, with the NCSC (CSIRT-IE) as the CSIRT designated as coordinator. It is the only candidate whose national material is in English, which suits a course written for non-native English speakers. It also publishes a guidance document the Learner can cite, and it reports only through the SRP.

**One trap for #273.** The Irish guidelines say: "on submission of the 24hrs Early Warning (EW) report to the SRP, the Detailed Notification must be submitted within 48hrs of the EW submission." The Regulation sets 72 hours from awareness and says nothing about a gap after the early warning. The two agree only when the early warning is sent at exactly 24 hours. If it is sent sooner, the Irish statement is stricter. The same guidelines say that on the final report for a severe incident, it is due "no later than 1 month after submission of the Detailed Notification", which matches the Regulation.

A scenario set in Ireland should compute the Regulation's deadline. It can also show the national guidance deadline and have the Learner meet the earlier of the two, labelled as national guidance, not law. Whether to teach this or avoid it is a decision for #273.

### The legal-review boundary line

Main establishment is a factual test about where cybersecurity decisions are predominantly taken (Article 14(7)). The course can state it for the fictional manufacturer. It cannot decide it for a real one.

## 4. The EEA position

The CRA has not been incorporated into the EEA Agreement. EFTA's EEA-Lex factsheet says the act is "marked as EEA relevant by the EU and under scrutiny for incorporation into the EEA Agreement by Iceland, Liechtenstein and Norway". It lists no EEA Joint Committee decision. [EFTA, EEA-Lex factsheet 32024R2847](https://www.efta.int/eea-lex/32024r2847). The factsheet shows no page-update date. ENISA's SRP FAQ does not address EEA states.

For the boundary line: *"The CRA is marked as EEA relevant but, as of 30 September 2026, has not been incorporated into the EEA Agreement. Whether and when it applies to a Norwegian manufacturer, and where a real manufacturer's main establishment is, are matters for product-specific legal review."*

## 5. Annex I, one row per requirement

This is the Regulation's own numbering, for one control-map row each. Wording is shortened. Part I point (2) applies "on the basis of the cybersecurity risk assessment ... and where applicable" (Article 13(3) and (4)). A row marked not applicable needs a justification in the technical documentation (Article 13(4)).

**Part I, cybersecurity requirements for product properties**

| Ref | Requirement |
| --- | --- |
| I.1 | Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks. |
| I.2(a) | Made available on the market without known exploitable vulnerabilities. |
| I.2(b) | Secure by default configuration, including the possibility to reset the product to its original state (unless agreed otherwise for a tailor-made business product). |
| I.2(c) | Vulnerabilities can be addressed through security updates. Where applicable, automatic security updates are on by default, with a clear and easy opt-out, notification of available updates, and the option to postpone them for a time. |
| I.2(d) | Protection from unauthorised access by appropriate control mechanisms (authentication, identity or access management), and reporting of possible unauthorised access. |
| I.2(e) | Confidentiality of stored, transmitted or otherwise processed data, for example by state-of-the-art encryption at rest or in transit. |
| I.2(f) | Integrity of stored, transmitted or processed data, commands, programs and configuration against unauthorised manipulation, and reporting of corruptions. |
| I.2(g) | Data minimisation. |
| I.2(h) | Availability of essential and basic functions, also after an incident, including resilience against denial-of-service attacks. |
| I.2(i) | Minimise the negative impact of the product, or connected devices, on the availability of services provided by other devices or networks. |
| I.2(j) | Limit attack surfaces, including external interfaces. |
| I.2(k) | Reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques. |
| I.2(l) | Security-related information by recording and monitoring relevant internal activity, including access to or modification of data, services or functions, with an opt-out for the user. |
| I.2(m) | Users can securely and easily remove all data and settings permanently, and any transfer of that data to other products is secure. |

**Part II, vulnerability handling requirements**

| Ref | Requirement |
| --- | --- |
| II.1 | Identify and document vulnerabilities and components, including an SBOM in a commonly used, machine-readable format, covering at least the top-level dependencies. |
| II.2 | Address and remediate vulnerabilities without delay, including by security updates. Where technically feasible, security updates are separate from functionality updates. |
| II.3 | Effective and regular tests and reviews of the product's security. |
| II.4 | Once a security update is available, share and publicly disclose information about fixed vulnerabilities: description, how to identify affected products, impact, severity and remediation help. Publication may be delayed in duly justified cases until users could apply the patch. |
| II.5 | Put in place and enforce a policy on coordinated vulnerability disclosure. |
| II.6 | Facilitate the sharing of information about potential vulnerabilities in the product and its third-party components, including a contact address for reporting vulnerabilities. |
| II.7 | Mechanisms to securely distribute updates so that vulnerabilities are fixed or mitigated in a timely manner, and automatically where applicable for security updates. |
| II.8 | Security updates disseminated without delay, free of charge (unless agreed otherwise for a tailor-made business product), with advisory messages that tell users what they may need to do. |

Source: [CRA, Annex I](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I).

The Commission guidance says that "regular" tests in II.3 does not mean repeating an unchanged campaign at fixed intervals. It means reviewing whether new threats or vulnerabilities require the tests to change, then testing (paragraph 238). A vulnerability is "known" for I.2(a) when it is listed in public vulnerability databases such as the EUVD. It may also be known from non-public sources, such as CVD, internal testing or prominent media, once the manufacturer has confirmed that it applies (paragraphs 233 to 235).

## 6. Article 13 support-period rules

All from [CRA, Article 13](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13):

- **13(8), setting it.** The support period reflects how long the product is expected to be in use. The manufacturer considers reasonable user expectations, the nature and intended purpose of the product, and relevant Union law. It may also consider comparable products, the operating environment, the support periods of third-party components that provide core functions, and ADCO and Commission guidance.
- **13(8), minimum.** At least five years. If the product is expected to be in use for less than five years, the period matches the expected use time. The Commission may set category minimums by delegated act. None was found.
- **13(8), documentation.** The information used to set the period goes into the Annex VII technical documentation.
- **13(8), policies.** The manufacturer has appropriate policies and procedures, including CVD policies under Annex I Part II point (5), to process and remediate reported vulnerabilities.
- **13(9), update availability.** Each security update made available during the support period stays available for at least 10 years after issue, or for the rest of the support period, whichever is longer.
- **13(10), software versions.** For substantially modified software versions, the manufacturer may meet II.2 only for the latest version, if users of earlier versions can get it free and without extra hardware or software costs.
- **13(11), archives.** Public archives of old versions are allowed. Users must be told clearly about the risks of unsupported software.
- **13(19), end date and notice.** The end date, at least month and year, is stated clearly at the time of purchase, and where applicable on the product, its packaging or by digital means. Where technically feasible, the product displays a notice to the user when support has ended.

The Commission guidance says five years "is therefore not to be considered as the default for all products". Products expected to be used for longer should have longer support periods (paragraph 126, citing recital 60). If a manufacturer relies on 13(10) and stops fixing older versions, it is expected to tell users who have not upgraded, where technically feasible (footnote 18).

For Tier 9's "unsupported devices" fog item: 13(19) is the only rule that points at the device itself. The product shows an end-of-support notice "where technically feasible". The SRP also has an "End of support indicator" field. Both are facts for the map. Neither decides whether Tier 9's device or service expresses an end-of-support date.

## 7. Annex II user information

At minimum the product comes with the following. Source: [CRA, Annex II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_II).

| Ref | Information |
| --- | --- |
| II-1 | Manufacturer name, registered trade name or trademark, postal address, email or other digital contact, and website where available. |
| II-2 | The single point of contact for reporting and receiving information about vulnerabilities, and where the CVD policy can be found. |
| II-3 | Name, type and any other information that uniquely identifies the product. |
| II-4 | Intended purpose, including the security environment provided by the manufacturer, essential functions and security properties. |
| II-5 | Known or foreseeable circumstances of intended use or reasonably foreseeable misuse that may lead to significant cybersecurity risks. |
| II-6 | Where applicable, the internet address of the EU declaration of conformity. |
| II-7 | The type of technical security support offered, and the end date of the support period. |
| II-8(a) | Detailed instructions, or an internet address for them, on the measures needed at commissioning and through the product's lifetime for secure use. |
| II-8(b) | How changes to the product can affect the security of data. |
| II-8(c) | How security-relevant updates can be installed. |
| II-8(d) | Secure decommissioning, including how user data can be securely removed. |
| II-8(e) | How to turn off the default automatic installation of security updates. |
| II-8(f) | For products meant for integration into other products, what the integrator needs to meet Annex I and Annex VII. |
| II-9 | If the manufacturer makes the SBOM available to users, where to find it. |

Related duties: 13(16) puts the manufacturer's contact details in Annex II. 13(17) requires a single point of contact that lets users choose their preferred means of communication, "not limit[ed] ... to automated tools". 13(18) requires clear, understandable information, kept available for at least 10 years or for the support period, whichever is longer.

## 8. What the CRA and the Commission expect of a CVD policy

The CRA requires a CVD policy but gives it no content list. What the sources say:

- **Law.** Put in place and enforce a CVD policy (Annex I II.5). Provide a contact address for reporting vulnerabilities, and facilitate sharing about the product's and its components' vulnerabilities (II.6). Have policies and procedures, including CVD policies, to process and remediate vulnerabilities from internal or external sources (13(8)). Annex II-2 tells users where the policy is. Annex VII 2(b) puts the CVD policy, the SBOM, evidence of the reporting contact address and the secure update distribution solution into the technical documentation. [CRA, Annexes I, II and VII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_VII)
- **Recital 76.** This is not binding, but it explains the intent. The policy "should specify a structured process through which vulnerabilities are reported to a manufacturer in a manner allowing the manufacturer to diagnose and remedy such vulnerabilities before detailed vulnerability information is disclosed to third parties or to the public". Reporting may be direct, or indirect and anonymous via a CSIRT. Manufacturers "should also consider publishing their security policies in machine-readable format". Bug bounties may be part of the policy.
- **Component vulnerabilities (13(6)).** Report a component vulnerability to its maintainer and share any fix. The Commission guidance says to report through the maintainer's own CVD channel, and only for the integrated version. There is no need to report if the maintainer is already aware, or if the component has no maintainer (paragraphs 222 to 229).
- **After the support period, or for older versions.** The guidance says the CVD policy and information-sharing duties continue for all later substantially modified versions (paragraph 131 and examples 52 and 53).
- **ENISA.** No ENISA guidance on a manufacturer's CRA CVD policy was found. ENISA's vulnerability pages point to the EUVD and to its role as a CVE root, and list older material aimed at member-state CVD policies. [ENISA, Vulnerability services](https://www.enisa.europa.eu/topics/vulnerability-disclosure)
- **Standards.** The Commission FAQ says the harmonised standard on vulnerability handling was due to be adopted by the European standardisation organisations by 30 August 2026. Whether it was adopted, and whether its reference is in the OJ, was not confirmed.

**Engineering interpretation, not law.** The course's CVD policy should cover a contact address and a choice of channel, the scope (products and versions), what reporters can expect (acknowledgement, triage, updates), a coordinated disclosure timeline, and safe-harbour wording, marked as a policy choice. It should also say where the SBOM and the advisories are published, and link to the Annex II single point of contact. None of these items beyond the contact, the process and enforcement are named by the CRA.

## 9. What is not confirmed

- **A format act under Article 14(10).** None was found on EUR-Lex, the Commission reporting page, ENISA's SRP pages or the Commission FAQ. The ENISA glossary is the only field-level format, and it is not a legal act. If an act exists that post-dates these sources, this report does not know it.
- **An SBOM act under Article 13(24).** None was found. A secondary source says none exists. That source is not a primary one.
- **National legal designation instruments.** For Ireland, Sweden and the Netherlands, the national law or order behind the coordinator designation was not found. ENISA's list is the source used here.
- **The Netherlands' intake channels.** How MijnNCSC and the web form relate to the SRP end-point in Article 14(7) was not confirmed.
- **The Irish government press release** (gov.ie) returned HTTP 403.
- **The SRP glossary table** was read through a page renderer. Field names and the stage markers should be re-checked against the page, or the SRP user manual PDF, before a template is published.
- **Harmonised standards.** Whether any CRA harmonised standard is cited in the OJ as of 30 September 2026 was not confirmed.
- **The EFTA factsheet** has no update date. "Not incorporated" is what the page says on the access date.
- **Amendments to the CRA.** No amending act was found. EUR-Lex's HTML front end refused automated access, so the text was read from the Publications Office copy of the OJ publication. A consolidated version was not checked.

## 10. Consequences for other tickets

- **#273, Article 14 scenarios.**
  - Use Ireland and the NCSC (CSIRT-IE).
  - Anchor the severe-incident final report to the notification's submission time.
  - Anchor the vulnerability final report to the time the fix is available, which is the remediation release at counter 6.
  - Record awareness in UTC, as the SRP does.
  - Decide whether to show the Irish "48 hours after the early warning" statement as a national-guidance deadline.
  - State the scenario date. Guidance paragraph 210 says Annex I Part II handling does not legally apply before 11 December 2027 for products placed before then, although Article 14 does. A scenario set in 2026 is legally a reporting-only scenario.
  - The component-triage rule in paragraph 218 matches "not affected" scanner matches. Such matches are not reportable, but upstream reporting may be due.
- **#274, CRA evidence set.**
  - The control map should have 22 rows: 14 in Part I (I.1 and I.2(a) to (m)) and 8 in Part II. #3's list missed I.2(i).
  - User information has 14 Annex II rows.
  - The CVD policy should link to the Annex II single point of contact. Annex VII 2(b) names the CVD policy, the SBOM, the contact address and the update distribution solution as technical-documentation content.
  - The support statement should give the end month and year (13(19)) and the 10-year update availability (13(9)).
- **Specification section 4.** No factual correction is needed. An optional wording change: "one month after the incident notification is submitted". This belongs to the map's publication ticket, not to this research.

## Source register

| Source | Date or version | Role |
| --- | --- | --- |
| [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) | OJ L 2024/2847, 20 November 2024. Read from the Publications Office copy (CELEX 32024R2847). | Binding text: Articles 3, 13 to 17, 71; Annexes I, II, VII; recitals 60, 68, 76. |
| [Delegated Regulation (EU) 2026/881](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R0881) | Adopted 11 December 2025. OJ 20 April 2026. In force 10 May 2026. | Binding. Grounds for a CSIRT to delay dissemination. |
| [Commission guidance, annex to C(2026) 5252 final](https://ec.europa.eu/newsroom/dae/redirection/document/131456) | 27 July 2026. | Non-binding. Awareness, reporting, support period, known vulnerabilities, upstream reporting. |
| [Commission CRA FAQ](https://ec.europa.eu/newsroom/dae/redirection/document/123307) | Version 1.4, 4 September 2026. | Non-authoritative Commission services FAQ. |
| [Commission, CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | Updated 11 September 2026. | First-party. SRP operational. |
| [ENISA, Single Reporting Platform](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp) | September 2026. | SRP launch, portal, documents. |
| [ENISA, SRP glossary](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2) | Version 1.3, 25 September 2026. | SRP fields by stage. |
| [ENISA, SRP FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions) | Updated 17 September 2026. | Access, roles, CSIRT selection. |
| [ENISA, SRP submission and update guidance](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-guidance-ar-notification-submission-and-update) | Updated 12 September 2026. | Stage order and edit rules. |
| [ENISA, List of CSIRTs designated as coordinators](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/list-of-csirts-designated-as-coordinators) | 10 September 2026. | All 27 member states. |
| [NCSC Ireland, CRA page](https://www.ncsc.gov.ie/cra/) | Updated 11 September 2026. | Irish coordinator, fallback address. |
| [NCSC Ireland, National CRA Guidelines v1](https://www.ncsc.gov.ie/pdfs/National_CRA_Guidelines_v1.pdf) | 31 August 2026. | National guidance, helpdesk, the 48-hour statement. |
| [NCSC Sweden, cyberresiliensförordningen](https://www.ncsc.se/sv/radgivning-och-stod/krav-och-regler-inom-informationssakerhet-och-cybersakerhet/cyberresiliensforordningen/) | No date shown. | Swedish coordinator. |
| [CERT-SE, Rapportering och anmälan](https://www.cert.se/rapportera/) | No date shown. | Swedish reporting page. |
| [NCSC-NL, Melden onder de CRA](https://www.ncsc.nl/wet-en-regelgeving/cyber-resilience-act-cra/melden) | No date shown. | Dutch coordinator and channels. |
| [EFTA, EEA-Lex 32024R2847](https://www.efta.int/eea-lex/32024r2847) | No date shown. | EEA status: under scrutiny. |
| [ENISA, Vulnerability services](https://www.enisa.europa.eu/topics/vulnerability-disclosure) | Current on the access date. | EUVD, CVE root. No CRA CVD guidance found. |
