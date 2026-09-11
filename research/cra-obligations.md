# Cyber Resilience Act obligations for the reference product

**Research question:** [GitHub issue #3](https://github.com/tkEmLogic/learning-cyber-security/issues/3)

**Research date and access date:** 11 September 2026

**Status:** Research, not legal advice

## Short answer

The EU Cyber Resilience Act, or CRA, is Regulation (EU) 2024/2847. It can
apply to a hardware or software product with digital elements that is made
available on the EU market. Its main product rules apply from 11 December
2027. Its manufacturer reporting rules apply earlier, from 11 September
2026.

For a covered reference product, the course should teach a lifecycle rather
than only a secure-development checklist. The lifecycle starts with a
documented cybersecurity risk assessment. It continues through secure design,
testing, release, CE marking, user information, vulnerability handling,
security updates, incident reporting, and retained evidence.

The Regulation states legal outcomes and required records. It does not
prescribe one development process, tool, test suite, update architecture, or
SBOM tool. Recommendations in the sections named **Engineering
interpretation** are reasonable ways to create evidence. They are not
themselves CRA requirements.

## Authority, version, and reading method

The binding source used here is **Regulation (EU) 2024/2847 of the European
Parliament and of the Council of 23 October 2024 on horizontal cybersecurity
requirements for products with digital elements**, Official Journal of the
European Union **L 2024/2847, 20 November 2024**. It is cited below as
**CRA**. The official English EUR-Lex ELI version is dated 20 November 2024
and was checked on 11 September 2026.

- [CRA, official EUR-Lex text, CELEX 32024R2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
- [CRA, EUR-Lex legal notice and official-language access](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847)
- [European Commission CRA policy page](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [European Commission manufacturer page](https://digital-strategy.ec.europa.eu/en/policies/cra-manufacturers)
- [European Commission reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [European Commission conformity-assessment page](https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment)
- [Commission Implementing Regulation (EU) 2025/2392 of 28 November 2025](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025R2392)
- [Commission Communication C(2026) 5252 final, 27 July 2026](https://ec.europa.eu/newsroom/dae/redirection/document/131455)
- [Commission guidance on the application of the CRA, annex to C(2026) 5252 final, 27 July 2026](https://ec.europa.eu/newsroom/dae/redirection/document/131456)

The Regulation is the source for statements labelled **Law**. Commission
pages are useful first-party implementation information, but they do not
replace the Regulation. The Commission describes its 27 July 2026 practical
guidance as non-binding. It should therefore help implementation, not be
treated as the legal text.

## Terms and scope to confirm before teaching compliance

**Product with digital elements** is the CRA term for a software or hardware
product, including its remote data processing solutions, that falls within
the Article 3 definition. A component can be a product with digital elements.
[CRA, Article 3(1), (2), and (3)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_3)

**Law:** The CRA applies when such a product is made available on the EU
market and its intended or reasonably foreseeable use includes a direct or
indirect data connection to a device or network. A Wi-Fi product normally
meets the connection part of this test. The other scope facts still need
review. [CRA, Article
2(1)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_2)

**Manufacturer** is the person or entity that develops or manufactures the
product, or has it designed, developed, manufactured, and markets it under
its name or trade mark. The manufacturer carries the core duties in Articles
13 and 14. [CRA, Article 3(13), Article
13](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13), and [Article
14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14)

**Support period** is the period in which the manufacturer ensures effective
vulnerability handling for the product. [CRA, Article
3(20)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_3)

**SBOM** means software bill of materials. It is a formal record containing
details and supply-chain relationships of the components used to build
software. [CRA, Article 3(39)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_3)

**CVD** means coordinated vulnerability disclosure. In this report, it means
a managed process for receiving, assessing, fixing, and disclosing
vulnerability information. The CRA requires a CVD policy. It does not define
this short form in Article 3. [CRA, Annex I, Part II, point
5](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

For this course, the reference product is a small Wi-Fi-connected product
using an ESP32-C6, Zephyr, MCUboot, and secure Wi-Fi over-the-air, or OTA,
updates. This is the scenario in the parent course issue. It is a useful
working example, but it does not itself establish a legal conclusion.
[Course issue #1](https://github.com/tkEmLogic/learning-cyber-security/issues/1)

The available course context does not state the product's precise functions,
operator, EU market, component suppliers, or sector rules. Therefore this
research does not decide that the product is in CRA scope, assign its legal
manufacturer, or assign an Annex III or IV category. Those facts must be
stated and reviewed for a real product. See [the project
definition](../CONTEXT.md).

**Law:** Article 2 contains exclusions and interactions with other EU
legislation. A product may be excluded or subject to sector-specific rules,
including rules for some medical devices, in-vitro diagnostic medical
devices, aviation products, motor vehicles, and certain national-security or
defence products. [CRA, Article 2](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_2)

## Dates and phasing

| Date | Legal effect | Source |
| --- | --- | --- |
| 20 November 2024 | Publication in the Official Journal. | [CRA heading and publication data](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) |
| 10 December 2024 | Entry into force, 20 days after publication. | [CRA, Article 71(1)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_71) |
| 11 June 2026 | Chapter IV, Articles 35 to 51, applies. It covers notification and control of conformity assessment bodies. | [CRA, Article 71(2)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_71) |
| 11 September 2026 | Article 14 applies. This is the manufacturer reporting duty. It applies on the research date. | [CRA, Article 71(2)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_71) |
| 11 December 2027 | The rest of the Regulation applies, unless Article 71 says otherwise. This includes the main product, conformity, information, and support obligations. | [CRA, Article 71(2)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_71) |

**Law:** Do not describe the CRA as fully applicable today. Reporting has an
earlier application date. The main product obligations have the later date
above. [CRA, Article 71](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_71)

**Law:** Article 14 reporting also applies to covered products placed on the
market before 11 December 2027. Other CRA duties apply to an older product
only if it is substantially modified from that date, subject to the exact
transition rules. [CRA, Article
69(2)-(3)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_69)

## 1. Product cybersecurity requirements

### Binding requirements

**Law:** Before placing a covered product on the market, the manufacturer
must ensure that it was designed, developed, and manufactured in accordance
with the essential cybersecurity requirements in Annex I, Part I. It must
also handle vulnerabilities effectively during the support period under Annex
I, Part II. [CRA, Article 13(1) and
(8)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** The manufacturer must carry out and document a cybersecurity risk
assessment. It must take account of the result during planning, design,
development, production, delivery, and maintenance. The assessment must be
updated as appropriate during the support period. The manufacturer must also
record relevant cybersecurity matters systematically. [CRA, Article
13(2), (3), and (7)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** Annex I, Part I requires the following outcomes, where relevant to
the product and its risk assessment:

- no known exploitable vulnerabilities when the product is placed on the
  market;
- secure configuration by default;
- protection from unauthorised access through appropriate control mechanisms;
- protection of confidentiality, including data stored, transmitted, or
  otherwise processed;
- protection of integrity for stored, transmitted, and processed data,
  commands, programs, and configuration;
- data minimisation;
- protection of availability and resilience against denial-of-service
  attacks;
- limitation of the attack surface, including external interfaces;
- mitigation of the impact of incidents;
- security-relevant recording and monitoring, with a user opt-out;
- the ability to remove user data and settings securely; and
- appropriate security updates. Where applicable, automatic installation is
  enabled by default, with a clear opt-out and temporary postponement.

[CRA, Annex I, Part I, points
1-2](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

The list is not a claim that every control is needed in every product. The
Annex and the Article 13 risk assessment determine relevance and
proportionality.

### Engineering interpretation

For the course, ask a learner to produce a risk register that identifies
assets, interfaces, attackers, misuse that is reasonably foreseeable, chosen
security controls, residual risk, and a review date. Map each chosen control
to one or more Annex I outcomes. Keep test results and design decisions with
the map. This is a practical evidence pattern, not a prescribed CRA template.

A suitable reference-product exercise is to list its debug port, update
channel, local network service, cloud API, mobile application, credentials,
and stored data. The learner can then show how default configuration,
authentication, access control, encryption, integrity checking, logging, and
availability controls reduce the stated risks.

**Law:** A manufacturer must use due care when it integrates third-party
components. It must make sure that these components do not weaken the
product's compliance. If it finds a vulnerability in an integrated
component, it must report it to the component maker or maintainer and fix it
in its own product. It must share a developed fix with that party where
appropriate. [CRA, Article
13(5)-(7)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

This matters for the ESP32-C6, Zephyr, MCUboot, radio stack, and other
libraries. The Commission guidance uses a similar example. A company that
combines an off-the-shelf microcontroller, connectivity parts, firmware, and
sensors into a connected product is the manufacturer of the whole product.
[Commission guidance C(2026) 5252 final, example 51, 27 July
2026](https://ec.europa.eu/newsroom/dae/redirection/document/131456)

## 2. Manufacturer identification and non-conformity response

### Binding requirements

**Law:** A covered product must carry a type, batch, serial number, or other
element that allows its identification. If that is not possible, the
identifier goes on its packaging or an accompanying document. The
manufacturer must also show its name, registered trade name or trade mark,
and postal and electronic address on the product, its packaging, or an
accompanying document. These details help users and authorities identify the
responsible manufacturer. [CRA, Article
13(15)-(17)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** If the manufacturer considers, or has reason to believe, that a
product already placed on the market is not in conformity, it must
immediately take the corrective measures needed to bring it into conformity,
withdraw it, or recall it. The manufacturer must also cooperate with market
surveillance authorities that request information or action to remove risk.
Separate Article 14 reporting rules apply to actively exploited
vulnerabilities and severe incidents. [CRA, Article
13(21)-(22)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

### Engineering interpretation

Give every released firmware image and physical device a clear version or
identifier. Keep a record that links it to the SBOM, test results, support
period, and user instructions. Create a simple decision record for a patch,
withdrawal, or recall. This makes the Article 13 duties easier to perform.
It is an evidence practice, not a prescribed CRA record format.

## 3. Vulnerability handling and the support period

### Binding requirements

**Law:** The support period must be at least five years, unless the expected
product lifetime is shorter. In the shorter case, it must correspond to that
expected lifetime. The manufacturer must determine the expected product
lifetime by considering the intended purpose, reasonably foreseeable use, and
other relevant circumstances. It must state the end date, at least the month
and year, clearly at the time of purchase. [CRA, Article
13(8) and (19)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

Five years is not the default for every product. The support period must
reflect the expected use time. A product expected to remain in use for more
than five years should have a longer support period. A period below five
years needs evidence that expected use is genuinely shorter. [Commission
guidance C(2026) 5252 final, section 5, paragraphs 125 to 127, 27 July
2026](https://ec.europa.eu/newsroom/dae/redirection/document/131456)

**Law:** During the support period, Annex I, Part II requires the
manufacturer to identify and document vulnerabilities and components,
including by drawing up an SBOM in a commonly used and machine-readable
format. The SBOM must cover at least the top-level dependencies. It must
regularly test and review the security of the product, remedy vulnerabilities
without delay, and publish information about fixed vulnerabilities.
[CRA, Annex I, Part II, point
1](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

**Law:** A security update issued during the support period must remain
available for at least 10 years after issue, or for the rest of the support
period if that is longer. [CRA, Article
13(9)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** The manufacturer must put in place and enforce a CVD policy. The
policy must provide a contact point and a process for receiving, handling,
and disclosing vulnerability information. [CRA, Annex I, Part II, point
5 and
6](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

### Engineering interpretation

Keep an SBOM for every released build and firmware image. Store the SBOM
identifier with the release version. Track each component's supplier,
version, licence, known vulnerabilities, and remediation decision. This
makes the Annex I requirement auditable. The CRA does not mandate a named
SBOM format, database, scanner, or ticket system.

Publish a security contact, security policy, supported versions, disclosure
workflow, acknowledgement target, and a way to send sensitive reports. Run
an exercise from report receipt through triage, fix, update, advisory, and
closure. These are sensible ways to operate CVD. The legal requirement is
the policy and effective handling, not these exact service levels.

## 4. Security updates and end-user information

### Binding requirements

**Law:** Security updates, including security patches, must be made available
without delay and free of charge. A tailored product for a business user can
be covered by a different agreement. Where technically feasible, new
security updates must be separate from functionality updates. [CRA, Annex I,
Part II, points 2 and
8](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

**Law:** At placement on the market, the manufacturer must provide the
information and instructions in Annex II in a clear, understandable,
intelligible, and legible form. They include the manufacturer and
vulnerability contact information, product identification, intended use and
security environment, support period, and instructions for secure
installation, operation, updates, decommissioning, and removal of user data.
[CRA, Article 13(18)-(20) and Annex
II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** The manufacturer must provide users with a secure way to obtain
security updates and the information needed for secure use. It must inform
impacted users after becoming aware of a reportable vulnerability or
incident. Where needed, it must explain risk reduction and corrective
measures. [CRA, Annex I, Part II and Article
14(8)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_I)

### Engineering interpretation

Treat an update as a security feature. Design authenticated updates,
integrity verification, rollback or recovery where appropriate, clear version
identification, and a user-visible update path. Test a failed update and a
power loss. Keep the test record. These design choices are not individually
specified by the CRA.

For the course, a concise end-user instruction can state the supported
version, end date of support, default credentials or setup steps, network
assumptions, how to check and install an update, and how to reset or dispose
of the product safely.

## 5. Reporting duties

### Binding requirements that apply now

**Law:** A manufacturer must notify an actively exploited vulnerability
contained in a product with digital elements, and a severe incident having an
impact on the product's security. It must send an early warning without undue
delay and in any event within 24 hours after becoming aware. It must submit a
vulnerability notification or incident notification without undue delay and
in any event within 72 hours after becoming aware. [CRA, Article
14(1)-(4)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14)

An actively exploited vulnerability needs reliable evidence of malicious
use without the system owner's permission. A severe incident harms, or can
harm, protection of important data or functions, or can introduce malicious
code. [CRA, Article
3(42)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_3) and [Article
14(5)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14)

**Law:** For an actively exploited vulnerability, the final report is due no
later than 14 days after a corrective or mitigating measure is available. For
a severe incident, it is due within one month after the incident
notification. Article 14 also provides for intermediate reports when
requested. [CRA, Article
14(2)(c), (4)(c), and
(6)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14)

**Law:** After becoming aware, the manufacturer must inform impacted users
about the actively exploited vulnerability or severe incident. It must
inform all users where appropriate. Where needed, the notice must explain
measures that users can take. [CRA, Article
14(8)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_14)

The Commission's current implementation page says the report is submitted
once through the CRA Single Reporting Platform. It identifies the CSIRT of
the manufacturer's main establishment as the receiving CSIRT and describes
simultaneous availability to ENISA except in exceptional circumstances.
This is Commission implementation information. The binding reporting duty is
Article 14. [Commission, “CRA reporting”, accessed 11 September
2026](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)

### Engineering interpretation

Maintain a 24-hour reporting playbook now, not only before the 2027 product
deadline. Assign an incident owner and back-up. Record the time the
manufacturer became aware, the evidence supporting the classification, the
24-hour warning, the 72-hour notification, user communication, mitigation,
and final report. A rehearsal is a strong course lab artifact. The CRA does
not prescribe a particular incident-management tool or organisation chart.

## 6. Engineering evidence and formal conformity records

### Engineering evidence

The following is a useful distinction for the course.

**Law:** The technical documentation must contain the information in Annex
VII. It must show the product's conformity with the essential cybersecurity
requirements. It includes a general product description, the documented
cybersecurity risk assessment, relevant design and development information,
the standards or common specifications applied, test reports, the SBOM,
vulnerability-handling information, and information relevant to production
and maintenance. It must be ready before market placement and kept current,
where appropriate, at least during the support period. [CRA, Article 31 and Annex
VII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_VII)

**Engineering interpretation:** Maintain a traceable evidence set:

1. Product boundary, intended use, security assumptions, and architecture.
2. Risk assessment and decisions that link each important risk to a control.
3. Requirements-to-design-to-test traceability.
4. Threat-model and abuse-case results.
5. Software, firmware, and SBOM release records.
6. Security test, code-review, penetration-test, and update-test results.
7. Vulnerability, CVD, advisory, patch, and incident-report records.
8. Release approval, support-period decision, user instruction, and
   decommissioning material.

This list is an evidence organisation method. Annex VII, not this list, is
the legal record requirement.

### Formal conformity records

**Law:** The manufacturer must apply the appropriate conformity-assessment
procedure before placing the product on the market. The normal procedure is
internal production control. The category can require a notified body:

- default-category products may use self-assessment;
- important class I products in Annex III may use self-assessment only when
  the required standards, specifications, or certification routes are fully
  used;
- important class II products in Annex III require a notified body or an
  applicable certification route; and
- critical products in Annex IV require certification where the Commission
  has required it, or otherwise one of the class II procedures.

[CRA, Articles 7, 8, and 32 and Annexes III, IV, and
VIII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_32)

The Commission gives examples, not a substitute for classification: ordinary
products include mobile apps and smart speakers; important products include
operating systems, anti-virus software, routers, and firewalls; critical
products include smart cards, secure elements, and smart-meter gateways.
[Commission, “CRA conformity assessment”, accessed 11 September
2026](https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment)

The ESP32-C6 is a microcontroller and may have security-related functions.
Annex III lists microcontrollers with security-related functions as
important class I products. This does not automatically classify the
finished reference product as class I. Classification is based on the core
function of the product placed on the market. Check the technical
descriptions in Implementing Regulation (EU) 2025/2392 and the product facts.
[Commission Implementing Regulation (EU) 2025/2392, 28 November
2025](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025R2392)

**Law:** After conformity has been demonstrated, the manufacturer draws up
the EU declaration of conformity, or DoC, using Annex V. The DoC identifies
the product and manufacturer, states that it is issued under the
manufacturer's sole responsibility, identifies the applicable Union
legislation and standards or specifications, records notified-body details
where applicable, and is signed. [CRA, Article 28 and Annex
V](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_28)

**Law:** The manufacturer keeps the technical documentation and the EU DoC
available for at least 10 years after the product is placed on the market, or
for the support period if that is longer. [CRA, Article
13(13)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_13)

**Law:** CE marking is affixed visibly, legibly, and indelibly to the
product before it is placed on the market. If that is not possible because of
the nature of the product, it is affixed to the packaging and the EU DoC.
For software, it is put on the DoC or the product website. The notified
body's number follows the CE marking for the full quality assurance procedure.
[CRA, Article
30](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_30)

CE marking is the manufacturer's declaration of conformity. It is not an EU
or national authority's product safety approval. [Commission, “CE marking”,
accessed 11 September
2026](https://single-market-economy.ec.europa.eu/single-market/goods/ce-marking_en)

## 7. Suggested course boundary

For a small connected reference product, learners can produce these
reviewable lab artifacts:

| Lifecycle point | Lab artifact | Why it helps |
| --- | --- | --- |
| Plan | Product boundary and CRA scope assumptions | Makes the legal facts explicit. |
| Design | Risk assessment and Annex I control map | Links threats and controls to legal outcomes. |
| Build | Versioned SBOM and secure build/release record | Supports component and vulnerability handling. |
| Test | Security test report, including failed-update recovery | Supplies evidence for the technical documentation. |
| Release | Draft user instructions, support-period statement, DoC data sheet, and CE-marking decision | Separates user-facing material from formal conformity records. |
| Operate | CVD policy, advisory template, update record, and 24-hour reporting exercise | Connects support to reporting and free fixes. |
| Retire | Secure decommissioning and user-data removal instructions | Supports Annex II information duties. |

These are teaching artifacts. They do not make the course provider,
reference-product author, or learner the legal manufacturer.

## 8. Legal-review areas

Obtain product-specific legal and regulatory review before representing a
real product as CRA compliant. In particular, decide:

1. **Scope and economic operator.** Is there a product with digital elements
   made available in the EU? Who is the legal manufacturer? Is software,
   firmware, a component, and a remote data-processing service one product
   or separate products for these duties? [CRA, Articles 2 and
   3](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#art_2)
2. **Other regimes and exclusions.** Does sector-specific EU law apply, and
   how does its cybersecurity treatment interact with Article 2? A Wi-Fi
   product also needs review under the Radio Equipment Directive and other
   applicable product laws.
3. **Classification and assessment.** Does Annex III or IV apply? Does the
   product use a harmonised standard, common specification, or a notified
   body? Check the current Annex text, Implementing Regulation (EU)
   2025/2392, and later Commission acts. Classify the finished product and
   separately supplied components by their own core functions. [CRA,
   Articles 7, 8, and 32 and Annexes
   III-IV](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng#anx_III)
4. **Support period.** Record the facts used to determine expected product
   lifetime. Review any decision to set it below five years.
5. **Vulnerability and incident threshold.** Decide whether an event is an
   actively exploited vulnerability or severe incident, when awareness
   occurred, which CSIRT is competent, and whether a notification is due.
   The reporting clock is short.
6. **Evidence and representation.** Confirm that technical documentation,
   DoC, translations, CE marking, user information, retention, and
   market-surveillance cooperation meet the applicable requirements.
7. **Open-source and supply chain roles.** Determine whether a party is a
   manufacturer, a steward, or another actor for the actual distribution
   model. Do not infer this only from a public repository.

## Source register

All sources below were accessed on 11 September 2026.

| Source | Date or version | Role |
| --- | --- | --- |
| [Regulation (EU) 2024/2847, official EUR-Lex text](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) | Adopted 23 October 2024. Official Journal L 2024/2847, 20 November 2024. CELEX 32024R2847. | Binding CRA text. |
| [Commission Implementing Regulation (EU) 2025/2392](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32025R2392) | 28 November 2025. | Binding technical descriptions for Annex III and IV product categories. |
| [Commission Communication C(2026) 5252 final](https://ec.europa.eu/newsroom/dae/redirection/document/131455) | 27 July 2026. | Approves the draft CRA guidance. |
| [Commission guidance on the application of the CRA](https://ec.europa.eu/newsroom/dae/redirection/document/131456) | Annex to C(2026) 5252 final, 27 July 2026. | Non-binding implementation guidance. |
| [Commission CRA manufacturer page](https://digital-strategy.ec.europa.eu/en/policies/cra-manufacturers) | Web page current on access date. | First-party overview of the manufacturer lifecycle. |
| [Commission CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | Web page current on access date. | First-party information about the Single Reporting Platform. |
| [Commission CRA conformity-assessment page](https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment) | Web page current on access date. | First-party overview of categories and assessment routes. |
| [Commission CE marking page](https://single-market-economy.ec.europa.eu/single-market/goods/ce-marking_en) | Web page current on access date. | First-party explanation of CE marking. |

The Commission guidance is non-binding. It helps explain product boundaries,
support periods, risk assessment, and reporting. It does not amend Regulation
(EU) 2024/2847.
