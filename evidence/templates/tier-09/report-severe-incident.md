# Article 14 report: severe incident

Copy this file into `evidence/learner/tier-09/` and write in the copy.

This is course evidence. It does not show CRA conformity, and it is not a legal determination.

| Field | Value |
| --- | --- |
| artifact_id | T9-REPORT-INC-<your initials> |
| artifact_type | reporting-exercise |
| owner | Learner |
| reviewer | (empty until a Mentor reviews it) |
| scope | tier-09 |
| revision | 1 |
| status | draft |
| created_at | (date) |
| last_reviewed_at |  |
| source_revision | (output of `git rev-parse --short HEAD`) |
| environment | course_id learning-cyber-security, tier 09, synthetic_data true, scenario clock |
| limitations | Every time here is a time on a Scenario clock, in UTC. Harbor Devices Ltd is fictional. Nothing in this record is sent to ENISA or to any CSIRT, and nothing in it decides whether a real event is reportable. |

Work through [the severe incident scenario](../../../course-material/tiers/tier-09-vulnerability-support/article-14-severe-incident.md) stage by stage. Write each submission when the scenario tells you to stop, before you read on.

**About this template.** The SRP field lists below follow ENISA's CRA Single Reporting Platform glossary, version 1.3, dated 25 September 2026, and read on 30 September 2026. ENISA changes the glossary between versions. This template is a course exercise, not the official SRP format, and no act of law fixes that format. Course maintainers re-read the glossary, and correct these tables, before each publication of this template.

## Part 1: What section 4 of the course specification asks you to record

| Field | Value |
| --- | --- |
| Awareness time (UTC) |  |
| The scenario event that set it |  |
| Why not an earlier event, and why not a later one |  |
| Classification |  |
| Classification rationale |  |
| Competent CSIRT assumption, and the main establishment it rests on |  |
| Member states where the product is available |  |
| Mitigation |  |
| User communication, in the words you would send |  |
| Final-report deadline, and the event it counts from |  |
| Points that require legal review |  |

Name at least two points that require legal review. For each one, say what a lawyer would have to decide and why this course cannot decide it for you.

## Part 2: The three SRP stages

The stages follow in order, and a later stage needs the earlier one. A field marked `optional` may still be worth filling in. Leave a field empty only when you have nothing true to write.

### Stage 1: Early warning

Due within 24 hours of the awareness time. For a severe incident, these are the fields glossary version 1.3 shows at this stage.

| SRP field | At this stage | Your entry |
| --- | --- | --- |
| Notification type (Vulnerability or Incident) | required |  |
| Title | required |  |
| Summary | required |  |
| Manufacturer name (filled by the system) | required |  |
| Member States where product available (concerned CSIRTs) | required |  |
| Product name | required |  |
| Product version | required |  |
| Product type (default, important, critical), class, category | optional |  |
| End of support indicator (yes or no) | optional |  |
| Component name | optional |  |
| Mitigating measure expected shortly (yes or no) | optional |  |
| User action able to reduce impact | optional |  |
| Considered sensitivity of information | optional |  |
| Corrective or mitigating measures taken | optional |  |
| Corrective or mitigating measures that users can take | optional |  |
| Suspected of unlawful or malicious acts (yes, no, unknown) | required |  |
| Date and time you became aware (UTC) | required |  |
| Date and time the incident occurred (UTC) | optional |  |
| General information about the nature of the incident | optional |  |
| Initial assessment of the incident | optional |  |
| Applied and ongoing mitigation measures | optional |  |
| Detailed description of the severity | optional |  |
| Detailed description of the impact | optional |  |
| Type of threat or root cause | optional |  |

### Stage 2: 72-hour notification

Due within 72 hours of the awareness time, under Article 14.

| SRP field | At this stage | Your entry |
| --- | --- | --- |
| Notification type (Vulnerability or Incident) | required |  |
| Title | required |  |
| Summary | required |  |
| Manufacturer name (filled by the system) | required |  |
| Member States where product available (concerned CSIRTs) | required |  |
| Product name | required |  |
| Product version | required |  |
| Product type (default, important, critical), class, category | optional |  |
| End of support indicator (yes or no) | optional |  |
| Component name | optional |  |
| Mitigating measure expected shortly (yes or no) | optional |  |
| User action able to reduce impact | optional |  |
| Considered sensitivity of information | optional |  |
| Corrective or mitigating measures taken | optional |  |
| Corrective or mitigating measures that users can take | optional |  |
| Attack vector | optional |  |
| Suspected of unlawful or malicious acts (yes, no, unknown) | required |  |
| Date and time you became aware (UTC) | required |  |
| Date and time the incident occurred (UTC) | required |  |
| General information about the nature of the incident | required |  |
| Initial assessment of the incident | required |  |
| Applied and ongoing mitigation measures | optional |  |
| Detailed description of the severity | optional |  |
| Detailed description of the impact | optional |  |
| Type of threat or root cause | optional |  |

### Stage 3: Final report

Due within one month after the 72-hour notification was submitted. Count from the submission, not from the deadline.

| SRP field | At this stage | Your entry |
| --- | --- | --- |
| Notification type (Vulnerability or Incident) | required |  |
| Title | required |  |
| Summary | required |  |
| Manufacturer name (filled by the system) | required |  |
| Member States where product available (concerned CSIRTs) | required |  |
| Product name | required |  |
| Product version | required |  |
| Product type (default, important, critical), class, category | optional |  |
| End of support indicator (yes or no) | optional |  |
| Component name | optional |  |
| Mitigating measure expected shortly (yes or no) | optional |  |
| User action able to reduce impact | optional |  |
| Considered sensitivity of information | required |  |
| Corrective or mitigating measures taken | required |  |
| Corrective or mitigating measures that users can take | required |  |
| Attack vector | optional |  |
| Suspected of unlawful or malicious acts (yes, no, unknown) | required |  |
| Date and time you became aware (UTC) | optional |  |
| Date and time the incident occurred (UTC) | optional |  |
| General information about the nature of the incident | optional |  |
| Initial assessment of the incident | optional |  |
| Applied and ongoing mitigation measures | required |  |
| Detailed description of the severity | required |  |
| Detailed description of the impact | required |  |
| Type of threat or root cause | required |  |

## Part 3: The deadlines

Name the anchor event in every row: the scenario event the deadline counts from. A deadline without its anchor cannot be checked.

| Submission | Rule | Anchor event | Anchor time (UTC) | Due (UTC) | Submitted (UTC) |
| --- | --- | --- | --- | --- | --- |
| Early warning | Article 14 of Regulation (EU) 2024/2847 |  |  |  |  |
| 72-hour notification | Article 14 of Regulation (EU) 2024/2847 |  |  |  |  |
| Final report | Article 14 of Regulation (EU) 2024/2847 |  |  |  |  |

Say in one sentence why the final report does not count from the 72-hour deadline.

## Record state

| Field | Value |
| --- | --- |
| Were the submissions written before you read on |  |
| Record state | pending until you have worked the whole scenario |
