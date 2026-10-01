# What a Tier 10 incident record and timeline should hold

**Research question:** [GitHub issue #285](https://github.com/tkEmLogic/learning-cyber-security/issues/285), under the Tier 10 map [#284](https://github.com/tkEmLogic/learning-cyber-security/issues/284). It feeds the incident timeline template in the Tier 10 lab artifact (specification section 11, Tier 10 block).

**Access date for every source below:** 1 October 2026.

**Status:** Research. It proposes a field list. It does not write the template, and it settles no course term.

## Short answer

NIST SP 800-61 Revision 3 (April 2025) is the current NIST guidance, and it no longer contains a field list. It is a CSF 2.0 Community Profile: a set of outcomes with recommendations. It still says what an incident record must track, in a few places: the status, a summary, the indicators of compromise, the status and expected time frame of every assigned action, and the next steps (RS.MA, R3). It asks for the sequence of events and the assets in each event (RS.AN-03, R1), a record of facts found and actions taken whose integrity is kept (RS.AN-06), and an after-action report at the end (RC.RP-06, R1).

The detailed field lists live in Revision 2 (2012), which NIST withdrew on 3 April 2025 and replaced "in its entirety" with Revision 3. Revision 2 section 3.2.5 lists eleven items for an incident tracking record, and Appendix B lists the data elements to collect. This report uses those lists as the only published NIST field list, and marks every field that has no basis in Revision 3.

ISO/IEC 27035 is paywalled. Its public abstracts confirm a five-phase model (plan and prepare, detection and reporting, assessment and decision, responses, learn lessons), but not any field list. ENISA's 2010 Good Practice Guide for Incident Management adds one idea the NIST texts do not stress: an incident is classified more than once, and the classification can change. The ENISA-hosted Reference Security Incident Taxonomy has explicit classes for causes that are not attacks (Misconfiguration, Outage, Data Loss) and a class for "Undetermined".

For Tier 10, the proposal is one incident record per Learner, with four parts: a record header, a timeline of facts and actions, an event table where each scenario event is classified twice (first sight and final), and a closing part for recovery and lessons learned. The field list is in "The proposed field list" below. About half of Revision 2's fields are left out, because they serve a team, a court or a cost estimate, and a single Learner on one board has none of those.

All three bodies separate detection and classification from containment, and containment from recovery. All three treat lessons learned as its own phase. Revision 3 adds that lessons should be recorded as soon as they are found, not only at the end. For telling attacks from operational failures, the useful points are that NIST counts power failures and other non-attack causes as "adverse events", that an incident is declared only when an event meets defined criteria, and that ENISA expects the classification to change as the facts arrive.

## 1. The sources and what each can carry

| Source | Status on 1 October 2026 | What it gives this template |
| --- | --- | --- |
| [NIST SP 800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3), April 2025 | Current. Supersedes Revision 2. | Outcomes and recommendations by CSF 2.0 identifier. A few named record items. The phase model. |
| [NIST SP 800-61r2](https://doi.org/10.6028/NIST.SP.800-61r2), August 2012 | Withdrawn 3 April 2025. The PDF carries a withdrawal notice. | The only NIST field lists: section 3.2.5, section 3.3.2 (evidence log), section 3.4.1 (lessons-learned questions), Appendix B. |
| ISO/IEC 27035-1:2023, 27035-2:2023, 27035-3:2020 | Published. Paywalled. | Only what the public abstracts say: the phase names and what each part covers. |
| [ENISA Good Practice Guide for Incident Management](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf), 2010 | ENISA publication, still on the ENISA site. Written for CERTs. | The handling workflow, the triage sub-phases, and the rule that classification happens up to three times. |
| [Reference Security Incident Taxonomy](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force/blob/master/working_copy/humanv1.md), version 1003 | Maintained by the TF-CSIRT working group in ENISA's GitHub organization. Last change to the file 12 May 2026. ENISA's [publication page](https://www.enisa.europa.eu/publications/reference-incident-classification-taxonomy) (26 January 2018) points to it. | Classes that are not attacks, and "Undetermined". |

### What Revision 3 says about its own scope

Revision 3's change log says it "performed a full rewrite", "shifted the focus of the document from guidelines on detecting, analyzing, prioritizing, and handling incidents to recommendations and considerations", and reorganized the content as a CSF 2.0 Community Profile (Appendix C). Section 1.1 says it is "no longer feasible" to keep the details of how to perform incident response in one static publication. So the absence of a field list in Revision 3 is a choice, not a gap in this research.

### What is public about ISO/IEC 27035

ISO's own page for [ISO/IEC 27035-1:2023](https://www.iso.org/standard/78973.html) says the part "presents basic concepts, principles and process with key activities of information security incident management, which provide a structured approach to preparing for, detecting, reporting, assessing, and responding to incidents, and applying lessons learned". ISO's pages for parts 2 and 3 refused automated access (HTTP 403), so their abstracts were read from the IEC webstore, which co-publishes ISO/IEC standards.

The [IEC page for ISO/IEC 27035-2:2023](https://webstore.iec.ch/publication/83156) says part 2 is based on "the 'plan and prepare' and 'learn lessons' phases of the information security incident management phases model presented in ISO/IEC 27035-1:2023, 5.2 and 5.6". It lists the "learn lessons" phase as identifying areas for improvement, making the improvements, and evaluating the incident response team.

The [IEC page for ISO/IEC 27035-3:2020](https://webstore.iec.ch/publication/67659) says part 3 covers "incident detection, reporting, triage, analysis, response, containment, eradication, recovery and conclusion", and is based on the "Detection and reporting", "Assessment and decision" and "Responses" phases of the 27035-1:2016 model.

Nothing public was found that lists the fields of an ISO/IEC 27035 event report or incident report. This report therefore cites ISO/IEC 27035 only for the phase model and never for a field. The phase names of 5.3 to 5.5 in the 2023 edition were not confirmed from a public source; the names above come from the 27035-3 abstract, which cites the 2016 edition.

## 2. What the guidance says a record should hold

### NIST SP 800-61r3 (current)

| Identifier | What it asks for |
| --- | --- |
| RS.MA, R3 | "The incident response status should be tracked for each incident along with pertinent information, such as an incident summary, indicators of compromise related to the incident, the status and expected time frame for each assigned action, and next steps to be taken." |
| RS.MA, N2 | Risk evaluation factors for prioritizing: "asset criticality, functional impact of the incident, data impact of the incident, stage of observed activity, threat actor characterization, and recoverability". |
| RS.MA-01, C1 | "Consider designating an incident lead for each incident." |
| RS.MA-02, R1 | A preliminary review "to verify that a cybersecurity incident has occurred, then estimate the severity of the incident and the level of urgency". |
| RS.MA-03, R1 | A more detailed review to "categorize them by incident type". |
| RS.MA-05, R1 | Apply recovery criteria "to determine when an incident's recovery processes should be initiated". |
| RS.AN-03, R1 to R3 | "Determine the sequence of events that have occurred during the incident and which assets and resources were involved in each of those events." Determine the vulnerabilities, threats and threat actors involved. Find "the underlying or systemic root causes". |
| RS.AN-06 | "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved." |
| RS.AN-07 | Incident data is "still considered evidence", even when no formal chain of custody is kept. |
| RS.AN-08, R1 | Estimate magnitude: look for indicators "on both the assets known to be targeted and other potential targets". |
| RS.MI, N1 | Record the duration of a containment measure: "an emergency workaround that must be removed within hours, a temporary workaround to be removed within two weeks, or a permanent solution". |
| RS.MI-01, RS.MI-02 | Containment "refers to preventing the expansion of an incident". Eradication "refers to mitigating an incident's effects". |
| RC.RP-03, R1 | "Check restoration assets for indicators of compromise, file corruption, and other integrity issues before use." |
| RC.RP-04, R2 and R3 | Confirm "the return to normal operations" and "monitor the performance of restored systems". |
| RC.RP-05, R1 | "Remediate the root causes of the incident before production use." |
| RC.RP-06, R1 | "Prepare an after-action report that documents the incident itself, the response and recovery actions taken, and lessons learned." |
| RS.CO-02, R2 | Procedures "that include what must be reported to whom and at what times". |

### NIST SP 800-61r2 (withdrawn): the tracking record

Section 3.2.5 says the issue tracking system "should contain information on the following":

- the current status of the incident (new, in progress, forwarded for investigation, resolved)
- a summary of the incident
- indicators related to the incident
- other incidents related to this incident
- actions taken by all incident handlers on this incident
- chain of custody, if applicable
- impact assessments related to the incident
- contact information for other involved parties
- a list of evidence gathered during the incident investigation
- comments from incident handlers
- next steps to be taken

The same section says "every step taken from the time the incident was detected to its final resolution should be documented and timestamped". A footnote adds: "Incident handlers should log only the facts regarding the incident, not personal opinions or conclusions. Subjective material should be presented in incident reports, not recorded as evidence."

Appendix B.1 adds, under incident details: status-change timestamps "including time zone" (when the incident started, was detected, was reported, and was resolved), current status, source or cause, a description including how it was detected, the affected resources, the incident category and indicators, the prioritization factors (functional impact, information impact, recoverability), mitigating factors, the response actions performed, and other organizations contacted. Appendix B.2 adds the cause of the incident, the cost, and the business impact.

Section 3.2.6 gives example scales. Functional impact: None, Low, Medium, High. Information impact: None, Privacy Breach, Proprietary Breach, Integrity Loss. Recoverability: Regular, Supplemented, Extended, Not Recoverable.

Section 3.2.4 says "Keep All Host Clocks Synchronized", because "event correlation will be more complicated if the devices reporting events have inconsistent clock settings".

Section 3.4.1 lists the lessons-learned questions: what exactly happened, and at what times; whether procedures were followed and were adequate; what information was needed sooner; whether any step "might have inhibited the recovery"; what to do differently; how information sharing could improve; what corrective actions prevent recurrence; what precursors or indicators to watch for; and what tools or resources are needed. The same section calls for "a formal chronology of events (including timestamped information such as log data from systems)".

### ENISA

The Good Practice Guide (section 8) sets the workflow as report, registration, triage, resolution, closure and post-analysis. Triage has three sub-phases: "verification, initial classification and assignment" (8.3). Registration links a report to an existing incident when they are related (8.2). For the incident report form, it says "there is no standardised form used by CERTs", and points to IODEF.

On classification, section 8.5.2 says: "you can classify an incident three times, each time changing the classification": when the report arrives, during resolution, and at the end. It then recommends a simple repeatable rule over a sophisticated one, and does not recommend classifying only at the end. Section 8.3.2 admits that at first sight "you usually do not have enough data to do it properly. Nevertheless it is important to classify your incidents at this stage."

Section 8.5.1 lists what a closing note holds: a short description including the classification, whether the incident was resolved, and the main findings and recommendations.

The Reference Security Incident Taxonomy has, under "Availability", the class "Misconfiguration" ("Software misconfiguration resulting in service availability issues") and "Outage" ("caused, for example, by air conditioning failure or natural disaster"), next to "Sabotage" and "Denial of Service". Under "Information Content Security" it has "Data Loss" ("caused by, for example, hard disk failure or physical theft"). Under "Other" it has "Undetermined": "The categorisation of the incident is unknown/undetermined."

## 3. How the guidance separates the phases

| Phase | NIST SP 800-61r3 | NIST SP 800-61r2 (withdrawn) | ISO/IEC 27035 (public abstracts) | ENISA guide (2010) |
| --- | --- | --- | --- | --- |
| Detection | Detect (DE): DE.CM monitoring, DE.AE analysis | Detection and Analysis | Detection and reporting | Report and registration |
| Classification | DE.AE-08 declares an incident; RS.MA-02 triages; RS.MA-03 categorizes and prioritizes | Detection and Analysis (3.2.4 to 3.2.6) | Assessment and decision | Triage: verification, initial classification, assignment |
| Containment | Respond (RS): RS.MI-01 | Containment, Eradication and Recovery (3.3.1) | Responses (27035-3 lists containment) | Resolution cycle |
| Eradication | RS.MI-02 | Same phase (3.3.4) | Responses | Resolution cycle, "eradication and recovery" |
| Recovery | Recover (RC): RC.RP, RC.CO; RS.MA-05 starts it | Same phase (3.3.4) | Responses (27035-3 lists recovery and conclusion) | Resolution cycle, then closure |
| Lessons learned | ID.IM (Improvement), fed from every function | Post-Incident Activity (3.4) | Learn lessons | Post-analysis |

Revision 3, Table 1, maps the old phases to the CSF functions. Detection and Analysis maps to Detect and to the Improvement category. Containment, Eradication and Recovery maps to Respond, Recover and Improvement. Post-Incident Activity maps to Improvement only. Section 2.1 explains why: incidents now take "weeks or months", and "the lessons learned during incident response should often be shared as soon as they are identified, not delayed until after recovery concludes".

Three boundaries are drawn the same way by every source:

1. **Detection is not classification.** NIST Revision 3 defines an event as any observable occurrence, an adverse event as any event "associated with a negative consequence regardless of cause, including natural disasters, power failures, or cybersecurity attacks", and says "additional analysis is often needed to determine whether adverse cybersecurity events indicate that a cybersecurity incident has occurred" (section 1). An incident is declared only "when adverse events meet the defined incident criteria", considering "known false positives" (DE.AE-08). ENISA puts verification before classification in triage.
2. **Containment is not recovery.** Containment stops the incident from growing. Eradication removes its cause. Recovery restores normal operation and confirms it (RS.MI-01, RS.MI-02, RC). ENISA's resolution cycle keeps the same order, and repeats it until the result is reached.
3. **Lessons learned is its own phase,** but Revision 3 lets lessons enter at any time through ID.IM.

### What this means for telling attacks from operational failures

The sources give four points that the Tier 10 scenario can use directly.

- **A symptom does not name its cause.** Revision 2 says some indicators, "such as a server crash or modification of critical files, could happen for several reasons other than a security incident, including human error" (3.2.4). It also says that "in many instances, a situation should be handled the same way regardless of whether it is security related". So the Learner's first response to a symptom does not have to wait for the classification. The template should let the Learner record a containment step before the classification is final.
- **Declaring an incident needs a criterion.** DE.AE-08 asks the handler to apply incident criteria and consider known false positives. In Tier 10, the criterion is the trust boundary: an event is an attack when something crossed, or tried to cross, a boundary from the specification's section 2 list. A failure is an event where no actor crossed a boundary. The template should ask for the boundary and the evidence for that judgment, not for a label alone.
- **The classification is expected to change.** ENISA classifies up to three times. The template should hold a first-sight classification and a final one, with the fact that changed it. This makes the course's failure criterion ("treats all failures as TLS problems") visible in the record instead of hidden by a corrected final answer.
- **"Undetermined" is a legitimate value.** The taxonomy has it, and Revision 2's status list allows "forwarded for investigation". A Learner who cannot yet tell should say so, not guess.

One more point bears on the Tier 10 recovery. RS.MA-03, R3 asks the handler to balance "the need to quickly recover from an incident with the need to observe the attacker or conduct a more thorough investigation", and Revision 2 lists the "need for evidence preservation" among the containment criteria (3.3.1). For Tier 10 this is the reason to capture the serial and service logs of the failed test boot before recovering the board. RC.RP-03 ("check restoration assets ... before use") is the external source for checking the teammate's candidate release before it goes anywhere near recovery.

## 4. The proposed field list

The source column names the strongest source. "r3" is SP 800-61r3, "r2" is the withdrawn SP 800-61r2, "ENISA" is the 2010 guide, "RSIT" is the taxonomy, and "spec" is the course specification. A field marked "r2 only" has no basis in Revision 3, and is kept because it serves the exercise.

### Part 1: Record header

One per Learner, for the whole scenario. It sits under the metadata block every evidence template already uses (`artifact_id`, `artifact_type`, `owner`, and the rest, as in `evidence/templates/tier-09/report-severe-incident.md`).

| Field | What the Learner writes | Source |
| --- | --- | --- |
| Incident lead | The Learner. One line, no contact details. | r3 RS.MA-01 C1 |
| Status | One of: open, contained, recovering, closed. | r3 RS.MA R3; r2 3.2.5 |
| Summary | Three sentences at most, written last. | r3 RS.MA R3; r2 3.2.5 |
| Assets in scope | The board identifier, the four synthetic fleet devices, the OTA service, the release under test. | r3 RS.AN-03 R1; r2 B.1 |
| Clock sources | Which clock each kind of timestamp comes from (see "The clocks" below). | r2 3.2.4 and B.1 (r2 only) |
| Related records | Weakness ledger rows, earlier-tier evidence, and any Tier 9 report the scenario touches. | r2 3.2.5; ENISA 8.2 |

### Part 2: Timeline

One row for every fact observed and every action taken, in order. Facts only: an opinion goes in Part 3.

| Field | What the Learner writes | Source |
| --- | --- | --- |
| Row | A sequence number. Rows are never deleted. A correction is a new row that names the row it corrects. | r3 RS.AN-06 (integrity of records); r2 3.2.5 footnote on logbooks |
| Time (UTC) | The time, with its clock source. A board line with no time is ordered by the service or host time next to it, and says so. | r2 3.2.5 ("documented and timestamped"), B.1 ("including time zone"); r3 RS.AN-03 R1 |
| Kind | One of: observation, action, decision, communication. | r2 3.2.5 ("system events, conversations, and observed changes"); r3 RS.AN-06 ("facts discovered and actions taken") |
| Source | Serial console, service log, fleet status, or command output. | r3 RS.AN-07; r2 3.2.4 (event correlation) |
| What happened | The fact, quoted or closely copied. No interpretation. | r2 3.2.5 footnote 36 (r2 only) |
| Asset | Which asset the row is about. | r3 RS.AN-03 R1 |
| Event | The scenario event this row belongs to, once known. Empty is allowed. | r2 3.2.5 ("other incidents related"); r3 DE.AE-03 (correlation) |
| Evidence | The path of the captured file under `evidence/learner/tier-10/`. | r3 RS.AN-07; r2 3.2.5 ("list of evidence gathered") |

### Part 3: Events

One row per scenario event. This is where the Learner tells attacks from failures.

| Field | What the Learner writes | Source |
| --- | --- | --- |
| Event | A short identifier and name. | ENISA 8.2 (registration reference) |
| First observed (UTC) | The timeline row where the first symptom appears. | r2 B.1 ("when the incident was discovered/detected") |
| First classification | Attack, operational failure, or undetermined, with the reason. Written before the next event is read. | ENISA 8.3.2 and 8.5.2; RSIT "Undetermined" |
| Final classification | Attack, operational failure, or undetermined. | ENISA 8.5.2 |
| What changed it | The timeline row that moved the classification, or "unchanged". | ENISA 8.5.2; r3 DE.AE-04 R1 ("review and refine the estimates") |
| Actor | One role from specification section 2 (for example Hosting attacker, Remote attacker, Operational failure). | r3 RS.AN-03 R2 (threat actors); r3 RS.MA-03 R1 (categorize by type); spec section 2 |
| Trust boundary | The boundary crossed or tried, from specification section 2, or "none" for a failure. | spec section 11, Tier 10 success criteria |
| Predicted control | The control the Learner expects to act, written before the evidence is checked. | spec section 11, Tier 10 success criteria |
| Control result | What the control did, with the timeline row that shows it. | r3 RS.AN-03 R1; spec section 11 |
| Indicators | The specific log lines or records that mark the event. | r3 RS.MA R3; r2 B.1 |
| Scope checked | Which other devices in the synthetic fleet were checked for the same indicators, and the result. | r3 RS.AN-08 R1 ("other potential targets") |
| Impact | Functional impact (None, Low, Medium, High) and recoverability (Regular, Supplemented, Extended, Not Recoverable). | r3 RS.MA N2; r2 3.2.6 tables |
| Root cause | One sentence, or "not yet known". | r3 RS.AN-03 R3; r2 B.2 |

### Part 4: Response, recovery and lessons

| Field | What the Learner writes | Source |
| --- | --- | --- |
| Containment step | The action, the event it contains, and whether it is an emergency, temporary or permanent measure. | r3 RS.MI-01 and RS.MI N1; r2 3.3.1 |
| Evidence kept before acting | What was captured before the containment or recovery step changed the board. | r3 RS.MA-03 R3; r2 3.3.1 ("need for evidence preservation") |
| Eradication | What removed the cause, for example the corrected release. | r3 RS.MI-02 |
| Recovery start criterion | Why recovery could start at that point. | r3 RS.MA-05 R1 |
| Restoration asset checked | How the candidate release, or any image used to recover, was checked before use. | r3 RC.RP-03 R1 |
| Root cause remediated before rollout | The defect each change fixes, and the evidence it was fixed before the canary. | r3 RC.RP-05 R1 |
| Normal operation confirmed | The canary result and fleet health that show it. | r3 RC.RP-04 R2 and R3 |
| Unsafe bypass refused | Each shortcut considered and why it was not taken. | spec section 11, Tier 10 failure criteria; spec section 21 (never bypass a security boundary) |
| End of recovery | The criterion for declaring the end, and its time. | r3 RC.RP-06 |
| Communications | Who was told what, and when: at least the teammate who prepared the candidate. | r3 RS.CO-02 R2, RC.CO-03 |
| Reportability | Whether any event looks like a severe incident or an actively exploited vulnerability under CRA Article 14, and if so a pointer to the Tier 9 template. No report is redone. | spec section 4; see "Overlap with Tier 9" |
| Lessons, as found | A dated line each time a lesson appears during the work. | r3 section 2.1 and ID.IM-03 |
| Lessons-learned questions | Answers to: what was needed sooner, what step could have hurt recovery, which indicators to watch, which corrective action becomes a weakness ledger row. | r2 3.4.1 (r2 only, as a list); r3 ID.IM-03 N3; ISO/IEC 27035-2 "learn lessons" abstract |

### What is left out, and why

| Field in the guidance | Source | Why it does not fit a single-Learner exercise |
| --- | --- | --- |
| Contact details: phone, email, location, organizational unit | r2 B.1 | One Learner, no team to reach. The incident lead line is enough. |
| Chain of custody, evidence handler names, storage locations | r2 3.2.5 and 3.3.2 | No prosecution. r3 RS.AN-07 N1 says formal chain of custody "might not be performed for every incident". The evidence path column keeps provenance. |
| Cost and monetary damage | r2 B.2 and 3.4.1 | Synthetic fleet and fictional company. No real cost exists. |
| Information impact scale (Privacy Breach, Proprietary Breach) | r2 3.2.6 | The course holds no personal or proprietary data. Integrity loss is caught by the root cause and the indicators. Could return if a scenario event alters records. |
| Physical location | r2 B.1 | One board on one desk. |
| Escalation and elevation times | r3 RS.MA-04; r2 3.2.6 | No management chain. The Mentor gate is a coaching review, not an escalation path (specification section 13). |
| Law enforcement, human resources, media, information-sharing bodies | r3 RS.CO-02 R5, RS.CO-03; r2 3.2.7 | No such parties exist in the course. |
| Assignment to a handler | ENISA 8.3.4 | One handler. |
| Incident taxonomy class, such as an RSIT type | RSIT; r3 RS.MA-03 R1 | The specification's actor list (section 2) does the same work in the course's own words. The taxonomy's value here is as precedent for non-attack classes and "Undetermined". See open question 2. |

## 5. Points specific to this course

### The clocks

Revision 2 asks for synchronized clocks. The course cannot have them. The board has no wall clock: the Time floor is "not the current time, only a lower bound on it" (CONTEXT.md). The Tier 9 application firmware prints every console line with `printk` and has no `LOG_` calls in `firmware/tier-09-vulnerability-support/src` or `firmware/common/src`, so serial lines carry no timestamp at all. MCUboot is built with `CONFIG_LOG_MODE_MINIMAL=y`. The OTA service writes its own times. Lifecycle records in Tier 8 already note that their times "come from the service's own clock".

So the template should make the clock source a stated field rather than assume one clock. A board line is placed by the host capture time, or by the service event next to it, and the row says which. This is the honest replacement for Revision 2's synchronized clocks, and it is also a small lesson in itself: correlating a device with no clock against a service that has one.

### Words to keep apart

The course glossary defines Awareness time for CRA reporting and tells writers to avoid "Discovery time, detection time" as synonyms for it. NIST Revision 2's timestamps include "when the incident was discovered/detected". The template therefore uses "First observed" for the time a symptom first appears, and does not use "Awareness time" unless the reportability field sends the Learner to Tier 9. Whether "Incident timeline" or "First observed" needs a glossary entry is a domain-modeling decision for the template ticket, not for this research.

The specification already lists "Operational failure" as an actor: "Operator error, failed download, power loss, or a wrong release, treated as a failure case rather than an attacker" (section 2). That fits the Actor column directly, and matches NIST's "regardless of cause" wording for adverse events.

### Overlap with Tier 9

Tier 9 already teaches incident reporting. Its two Article 14 scenarios run on paper on a Scenario clock, and its template (`evidence/templates/tier-09/report-severe-incident.md`) follows the ENISA Single Reporting Platform glossary. It records awareness time, classification rationale, the date and time the incident occurred, mitigation, "type of threat or root cause", and the three deadlines. Issue #273 designed those scenarios.

The Tier 10 record should not repeat that. It differs in three ways: it is the internal handling record, not a regulator submission; it runs on the board and the live service, not on paper; and it records many events, some of which are not incidents at all. The two meet at one field: the reportability pointer in Part 4. If a Tier 10 event would be a severe incident (for example a hosting attack that reached the fleet), the Learner names it and points to the Tier 9 template, and the Mentor key decides whether the scenario wants that link drawn.

Fields that look alike in both templates should use the same words, so the Learner sees that the internal record feeds the external report. The Tier 9 template's "Type of threat or root cause" and "Corrective or mitigating measures taken" correspond to this record's root cause and eradication fields.

## 6. Open questions for the dev

1. **One record or one per event.** This report proposes one record with an event table, because the scenario is one campaign and correlation is part of the lesson (r3 DE.AE-03). The alternative, one record per event as in Revision 2's per-incident tracking, is closer to how a team works but makes the Learner repeat the header and hides the links between events.
2. **A taxonomy column.** The proposal uses the specification's actor list instead of the Reference Security Incident Taxonomy. Adding an optional RSIT class column would teach a real CSIRT vocabulary at the cost of one more column. The taxonomy is written for internet-facing CSIRT work, and most of its classes (spam, phishing, copyright) never occur in the scenario.
3. **When the first classification is fixed.** ENISA's three-point classification works only if the Learner writes the first one before reading on. Tier 9 enforces this with "Stop" lines on its scenario page. Tier 10's events are staged by a runner, so the stop has to come from the runner or the module text. That belongs to the campaign design.

## 7. What was not confirmed

- The section titles of ISO/IEC 27035-1:2023 clauses 5.3 to 5.5. The public 27035-2 abstract confirms 5.2 and 5.6 only. The phase names used above come from the 27035-3 abstract, which cites the 2016 edition.
- Whether ISO/IEC 27035 defines the content of an event report or incident report. A secondary site paraphrases the standard as saying the event report "should contain all that is necessary to understand the event and make a decision", but that could not be traced to a public primary text, so it is not used.
- ENISA's [Reference Incident Classification Taxonomy](https://www.enisa.europa.eu/publications/reference-incident-classification-taxonomy) PDF itself. The publication page loaded, but its download link returned HTTP 404. The working group's current version on GitHub was read instead.
- Whether NIST's [Incident Response project page](https://csrc.nist.gov/projects/incident-response), which Revision 3 points to for supplemental resources, now links a record template. It was not read.
- Whether MCUboot's minimal log mode prints a timestamp. This matters only for the few bootloader lines; the template's clock-source rule covers either answer.

## Sources

- Nelson A, Rekhi S, Souppaya M, Scarfone K (2025), *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, NIST SP 800-61r3, [doi:10.6028/NIST.SP.800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3), PDF from nvlpubs.nist.gov.
- Cichonski P, Millar T, Grance T, Scarfone K (2012), *Computer Security Incident Handling Guide*, NIST SP 800-61r2, [doi:10.6028/NIST.SP.800-61r2](https://doi.org/10.6028/NIST.SP.800-61r2), withdrawn 3 April 2025, PDF from nvlpubs.nist.gov with the withdrawal notice.
- ISO, [ISO/IEC 27035-1:2023 product page](https://www.iso.org/standard/78973.html).
- IEC webstore, [ISO/IEC 27035-1:2023](https://webstore.iec.ch/publication/83157), [ISO/IEC 27035-2:2023](https://webstore.iec.ch/publication/83156), [ISO/IEC 27035-3:2020](https://webstore.iec.ch/publication/67659).
- ENISA (2010), [Good Practice Guide for Incident Management](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf).
- TF-CSIRT Reference Security Incident Taxonomy Working Group, [Reference Security Incident Taxonomy, human-readable version 1003](https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force/blob/master/working_copy/humanv1.md), commit `901c69c124`, 12 May 2026.
- ENISA, [Reference Incident Classification Taxonomy publication page](https://www.enisa.europa.eu/publications/reference-incident-classification-taxonomy), 26 January 2018.
- Course sources: `docs/course-specification.md` sections 2, 4, 11 and 13; `CONTEXT.md`; `evidence/templates/tier-09/report-severe-incident.md`; `evidence/templates/tier-08/lifecycle-event-records.md`; `course-material/tiers/tier-09-vulnerability-support/article-14-severe-incident.md`.
