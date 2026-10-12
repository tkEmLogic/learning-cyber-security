# Tier 10 Mentor key

This page is for the Mentor at the core-course completion gate. It holds the answer key to the integration scenario, the boundary and control each event belongs to, the unsafe shortcuts a Learner reaches for, and the things in the lab's own records that a Learner should not read too much into.

The course is public, so a Learner can read this page. That is acceptable. The gate tests reasoning, not recall: a Learner who repeats a row from here without being able to say why it holds has not done the work, and one follow-up question shows it. If you are a Learner, do not open this page before you have written the first-pass row for all eight events. Then finish your own final table first, compare, and record the differences rather than copying the answers.

Every time on this page is UTC and comes from the Tier 10 board campaign of 12 October 2026 on an ESP32-C6-DevKitC-1, the same capture [the module](index.md) quotes. Serial times come from the capture tool, because the board's console prints none.

## The answer key

| Event | Mechanism | Where | Class | Boundary | Control that answers |
| --- | --- | --- | --- | --- | --- |
| 1 | The runner restarts the service with `--present wrong-name`, so it presents a certificate for another name | board | attack: service impersonation | The device and the OTA service | `CTL-03`, the device's server name check (Tier 2). The board refused with verification flags `0x00000004` |
| 2 | `tier-04/hostile-release --release wrong-key`, written into the Fleet baseline as a compromised hosting side | board | attack: malicious hosting | The release signing workstation and the OTA service | `CTL-02`, the manifest signature (Tier 4). Refused at `manifest-signature`, `status=-149` |
| 3 | `tier-04/replay-release` offers `tier-05-crash`, a genuine older release at counter 4, unedited | board | attack: replay | The release signing workstation and the OTA service | `CTL-02`, the security counter (Tier 4), with `CTL-01` in MCUboot behind it. Refused at `security-counter`, 4 against 6 |
| 4 | `service bypass e-8-07`: a revoked device presents its own unrevoked certificate | host, labeled as a host result | attack: credential misuse | The device and the OTA service, decided at the service | `CTL-12`, revocation (Tier 8). Refused at `device-unrevoked` |
| 5 | The runner, as `teammate`, starts the candidate rollout with a misspelled canary, `beacon-t08c-206ef1170d46`, reads that nothing was served, and advances | service | operational failure: operator error | `none` is right. The customer operator and the manufacturer service is acceptable if the Learner says the operator here is the manufacturer's own | Nothing. `CTL-18` checks only that the group is well formed, which is `T10-W-40` |
| 6 | The service runs with `--range interrupt:500439`, 0.6 of the candidate's size, so the download is cut once and resumed | board | operational failure, and the scenario's one decoy | `none`, or the device and the OTA service | Tier 5's resumable download, with the signed digest checked over the whole image |
| 7 | The candidate's beacon period is 90 s, so `beacon-advancing` fails at the gate's second sample | board | operational failure: bad release health | MCUboot and the Zephyr application | `CTL-05`, the health gate and automatic revert (Tier 5) |
| 8 | `tier-09/support-listener --request inventory`, sent in a series until one lands inside the trial window | board | attack | The device and the local Wi-Fi network | Nothing on the board. It is `T10-W-38`, the planted regression of `T9-W-34`. The release process should have caught it: a canary that waits, and the support-listener regression before the advance |

The staged times on the capture were 19:01:59, 19:02:45, 19:03:28, 19:04:30, 19:04:39, 19:06:48, 19:07:58 and 19:10:24.

### What to accept as a first classification

`undetermined` is a good first answer for Event 1 and Event 2, if the Learner can say what would settle it. A certificate with the wrong name can be a misconfigured service, and a signature that does not verify can be a key rotation mistake. Both were attacks here, and the evidence that settles it is that nobody on the team changed a certificate or a key.

Push back on `attack` for Event 6. The download resumed, the image hashed to its signed digest, and the board installed it. A Learner who calls it an attack has usually reasoned from "something cut my connection" to "someone cut my connection".

Push back hard on any network or TLS explanation for Event 7. The specification names "treats all failures as TLS problems" as this tier's failure criterion, and Event 6 exists to set that trap. The board printed that no health check asks whether the service is reachable, and the check that failed, `beacon-advancing`, is local.

Event 5 is the one most Learners call `undetermined` or miss. The symptom is quiet: three records with the right release and a Canary group one character pair away from the board's identifier. A Learner who compared the group with the board's `identity.state` line has done the right thing. A Learner who did not should be asked what `served so far` showed before the advance.

Event 8's sender address, `192.168.68.77`, is the lab host, because the fixture runs there. In a real network it would be any device that can reach the board. A Learner who concludes "it was my own machine, so it was harmless" has read the lab layout, not the event.

### When a real operator should have acted

The first safe moment to stop the rollout was Event 5: a canary that served nobody was advanced. The latest was Event 7, when the candidate failed its trial on the only real device. The scenario asks the Learner to watch until Event 8 because it needs the trial windows. Ask the Learner when they would have paused in a real shift, and why.

## What an attacker could have done with `reboot`

The scenario sends `inventory` so that each revert keeps a single cause. The listener answers `reboot` as well, from anyone.

A reset during a trial is a failed trial. An attacker who sends `reboot` in every trial window makes every candidate that carries the listener revert, whatever else it gets right. A release with only the beacon fixed would never confirm on any device the attacker can reach. With three attempts per release, three datagrams spend a release's whole trial budget, and the board then refuses it at `trial-limit`. That is a veto over the fleet's updates for anyone on the local network, and the same window gave them the device's identity and release with `inventory`.

## The unsafe shortcuts

Each of these makes the board look healthy, or the scenario move faster, and each goes around a control. A Learner who considered one and recorded it in the incident record has done well. A Learner who ran one needs a recovery plan, as section 13 of the specification describes.

**Flashing the board over USB.** It works on a desk and proves nothing about a fleet. It also discards the evidence: the revert, the trial count and the confirmed image MCUboot kept. The recovery proof is that nobody touched the board.

**Dropping `--release-approval`.** It turns off the one check that stops an unapproved release from becoming the Fleet baseline. A Learner who restarts the service without it "to get the corrected release out faster" has removed `CTL-17` during an incident. The scenario's start check reads the running service's own flags for exactly this reason, and `E-10-05` shows the check is still on.

**`./course release assign --tier 05` to `--tier 08`, or writing `.course-state/ota/current-release.json` by hand.** Those earlier commands write the state file directly, past approval and past `no-open-rollout`. For a hosting attacker that is the threat itself, which is why the hosting fixtures do it. For an operator in an incident it is a side door around the release path. Tier 9's "What the attacker still controls" names it.

**Waiting out the trial limit.** It is not a bypass. The board would refuse the candidate at `check=trial-limit` after its third failure and stay on counter 6 without anyone acting. It is unsafe by omission: the listener stays live for about ten seconds of every retry, and the release stays on offer to every device in the fleet. The capture withdrew after two attempts, four seconds after Event 8.

## Things a Learner should not read too much into

These are artifacts of the lab and of the runner, not of the events. A Learner who builds a theory on one of them should be asked which event it belongs to.

**The service restarts in `ota.log`.** Each block of `COURSE SERVICE:` lines is the runner restarting the service, either to stage an event or to undo the last one. The restart before Event 1 is part of Event 1. The others are bookkeeping.

**The `err=-0x004c` line at Event 1.** Restarting the service while the board is in the middle of a poll cuts that poll. The capture showed `tls.poll data check err=-0x004c` and an `err=-113` request failure at 19:01:55, before the real name refusal, `err=-0x2700`, at 19:02:27. The first pair is the restart, not the impersonation.

**Later downloads are cut and resumed too.** The interruption behind Event 6 stays in force until Event 8 ends, because switching it off mid-download broke an earlier version of the runner. The capture's second trial download was cut at 19:08:27 and resumed at 19:09:41. To the Learner it looks like an unreliable network, and it is not a ninth event.

**The candidate's boot banner.** It says `Trial behaviour compiled into this image: healthy` and "the support listener is compiled out", and then it starts the listener. That is the teammate's summary line, never updated after the change. It is a lesson rather than noise: believe what the device does, `support.listener listening on UDP 7700`, over what its summary says. The corrected release prints the same banner, and on that image the banner is true.

**An extra answer in the first trial.** The capture's serial log has `support.inventory answered 192.168.68.77:43247, unauthenticated` at 19:07:21, during the first trial. That was the campaign running the support-listener regression against the candidate. A Learner's console has it only if they ran the regression during that trial.

**`recovery.state trial release_id=tier-10-candidate attempts=2 of 3` on the corrected release's boot.** The record of the last trial survives until another release is tried. It describes the past, not a problem with counter 8.

**`"signed":false` in the `rollout.started` records.** The service sets `signed` to `false` on every release record it stores, whichever route offered the release. It is not a statement about the release or its signature.

**The TLS handshake errors from `127.0.0.1` at the end of `ota.log`.** They are the regression's host probes, run from the lab host on purpose.

**The candidate's build manifest and the staging log.** The build manifest's `handover_patch` entry describes both defects and names `T10-W-38`, and the `release test` output the runner wrote to the staging log names `T10-W-39`. `.course-state/scenario/staging.log` holds every mechanism above. A Learner who read either during the scenario has read the answers, and the first-pass table loses its value.

## The candidate's two defects

The handover patch has two hunks. The first sets `CONFIG_COURSE_SUPPORT_LISTENER=y` in `prj.conf` and moves `bring_up_network_and_listener()` before `confirm_or_revert()` in `main.c`, so the listener is live during every trial. That is `T10-W-38`, and it does not fail the boot. The second sets `BEACON_PERIOD_SECONDS` from 1 to 90. The gate samples every 5 s and expects the beacon to advance, so it fails at the second sample, about ten seconds into the window, and the board reverts.

The corrected release is the committed tree, which carries neither hunk. A Learner should be able to point to the file and line for each in the tree, and to say why fixing the beacon alone would ship the listener. The two hunks are separate on purpose.

The planning assumed the listener would be live for the whole 60 s window. On the board it is live for about 9 to 10 s, from the gate's start to its second sample. That is why the scenario sends a series of single datagrams for Event 8.

## Diagnose: a pass that came from the wrong place

**Preparation.** Before the session, record the lab host's own loopback address as the board's address:

```text
./course device address 127.0.0.1
```

Then ask the Learner to run the support-listener regression against the corrected release. Nothing listens on UDP 7700 on the lab host either, so the host's own network stack refuses the datagram, and the run reports `pass`, `observed absent`. Run it once yourself before the session to confirm your host answers that way. Put the board's real address back at the end.

**The symptom.** A pass, on the release that should pass. Everything points to "the listener is gone, the evidence is good".

**The cause.** The datagram never reached the board. A port-unreachable answer says only that something at that address has no socket open on that port. It does not say which device answered.

**A good diagnostic path.** The Learner asks what answered the datagram, prints the address on record with `./course device address`, and compares it with the board's latest `wifi.address` line. Then they reach for the evidence that does name the device: the board's own boot log, `support.listener absent`, which no other host can print. Tier 9 already called port unreachable weak evidence. This failure shows why it is weak in a second way.

**What it teaches.** A regression line is only as good as its target. The board's real reports reach the course through `events.jsonl` under the board's device identifier, read over mutual TLS. The support-listener line is the one board result that is not, and it trusts an address a person typed.

## Explain: what the attacker can still do

Good answers for the three the module asks for:

- **Through the operator listener:** approve any release in any name (`T9-W-36`), pause or withdraw a fix (`T9-W-37`), or start a rollout with a canary of nobody and advance it at once (`T10-W-40`). None of these makes the board accept a release it would otherwise refuse.
- **Through the service's state directory:** offer any release past approval and past the rollout, as the hosting fixtures do. The board's signature, counter and hardware checks still apply.
- **With the Release signing key:** sign anything at any counter, which the board accepts, which is `T3-W-11`. Or date a manifest far ahead and end every Operational credential, which is `T8-W-29`.

A Learner who answers "nothing, the regression passed" has read the regression as a proof of absence. Ask them what the regression did not run.
