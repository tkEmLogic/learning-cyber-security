# Annex I control map

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-ANNEX-I-<your initials> |
| artifact_type | control-map |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true |
| limitations | The map shows where the Reference product stands against each Annex I requirement, not that it meets one. The product is first placed on the market in March 2027, and before 11 December 2027 only Article 14 applies to it. The map is engineering practice for that date. |

## How to fill it in

The course has written the requirement text in every row, shortened from Annex I. Where a control from Tier 2 to Tier 9 plainly addresses a requirement, the course has named it too, and the last column says `course`. A row marked `you` or `judgment` is yours to map. Your Mentor reads the four `judgment` rows closely at the gate.

Set a status and an evidence link in every row. The status is one of the four values in section 10 of the course specification: `supported`, `partly_supported`, `unsupported` or `not_applicable`. A `not_applicable` row needs a written reason, because the technical documentation must justify it.

A named control is not the same as a supported row. A row is `supported` only when the evidence exists and passed.

## Part I: Cybersecurity requirements for the product

| Ref | Requirement | Controls | Evidence | Status | Gap or reason | Mapped by |
| --- | --- | --- | --- | --- | --- | --- |
| I.1 | Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks | The Tier 1 risk register and threat model, carried through every later tier |  |  |  | course |
| I.2(a) | Made available on the market without known exploitable vulnerabilities | The Tier 9 vulnerability records and the Remediation release |  |  |  | course |
| I.2(b) | Secure by default configuration, including the possibility to reset the product to its original state |  |  |  |  | you |
| I.2(c) | Vulnerabilities can be addressed through security updates, with automatic updates on by default where applicable, a clear opt-out, notification, and the option to postpone | CTL-01, CTL-02, CTL-05 |  |  |  | course |
| I.2(d) | Protection from unauthorized access by control mechanisms such as authentication and identity management, and reporting of possible unauthorized access | CTL-03, CTL-04, CTL-10, CTL-11, CTL-12 |  |  |  | course |
| I.2(e) | Confidentiality of stored, transmitted or processed data, for example by encryption at rest or in transit | CTL-03, CTL-08 |  |  |  | course |
| I.2(f) | Integrity of stored, transmitted or processed data, commands, programs and configuration against unauthorized manipulation, and reporting of corruptions | CTL-01, CTL-02, CTL-06 |  |  |  | course |
| I.2(g) | Data minimization |  |  |  |  | judgment |
| I.2(h) | Availability of essential and basic functions, also after an incident, including resilience against denial-of-service attacks | CTL-05 |  |  |  | course |
| I.2(i) | Minimize the negative impact of the product, or connected devices, on the availability of services provided by other devices or networks |  |  |  |  | judgment |
| I.2(j) | Limit attack surfaces, including external interfaces |  |  |  |  | judgment |
| I.2(k) | Reduce the impact of an incident using exploitation mitigation mechanisms and techniques |  |  |  |  | you |
| I.2(l) | Security-related information by recording and monitoring relevant internal activity, including access to or change of data, services or functions, with an opt-out for the user | The service's append-only `records.jsonl` and `events.jsonl` |  |  |  | course |
| I.2(m) | Users can securely and easily remove all data and settings permanently, and any transfer of that data to other products is secure |  |  |  |  | judgment |

## Part II: Vulnerability handling requirements

| Ref | Requirement | Controls | Evidence | Status | Gap or reason | Mapped by |
| --- | --- | --- | --- | --- | --- | --- |
| II.1 | Identify and document vulnerabilities and components, including an SBOM in a commonly used, machine-readable format, covering at least the top-level dependencies | The Tier 9 firmware and service SBOMs |  |  |  | course |
| II.2 | Address and remediate vulnerabilities without delay, including by security updates, kept separate from functionality updates where technically feasible | The Tier 9 Remediation release |  |  |  | course |
| II.3 | Effective and regular tests and reviews of the product's security | The attack fixtures and bypass tests of Tiers 2 to 9 |  |  |  | course |
| II.4 | Once a security update is available, share and publicly disclose information about fixed vulnerabilities, unless a delay is duly justified |  |  |  |  | you |
| II.5 | Put in place and enforce a policy on coordinated vulnerability disclosure | The Tier 9 Coordinated vulnerability disclosure policy |  |  |  | course |
| II.6 | Facilitate the sharing of information about potential vulnerabilities in the product and its third-party components, including a contact address for reporting vulnerabilities | The Tier 9 Coordinated vulnerability disclosure policy and user security information |  |  |  | course |
| II.7 | Mechanisms to securely distribute updates so that vulnerabilities are fixed or mitigated in a timely manner, and automatically where applicable | CTL-01, CTL-02, CTL-03, CTL-06, and CTL-?? for the Tier 9 Rollout and Release approval |  |  |  | course |
| II.8 | Security updates disseminated without delay and free of charge, with advisory messages that tell users what they may need to do | The Tier 9 support statement and Rollout |  |  |  | course |

## The four judgment rows

For each `judgment` row, write in one short paragraph which control or behavior of the Reference product addresses the requirement, where it falls short, and why. `I.2(j)` has a live failure in this tier: say what it is and what removed it.

| Ref | Your reasoning |
| --- | --- |
| I.2(g) |  |
| I.2(i) |  |
| I.2(j) |  |
| I.2(m) |  |

## Source

| Source | Version or date | Accessed |
| --- | --- | --- |
| Regulation (EU) 2024/2847, Annex I |  |  |
