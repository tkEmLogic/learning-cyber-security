# Tier 5: Make installation recoverable

## Scenario

Your device is careful about what it installs. It verifies the service it talks to, the key that signed the image, and a manifest that says which release the image is and whether that release is newer than the one already running. Four tiers of work, and every one of them asks the same kind of question: should I accept this?

None of them asks whether it works.

Last Tuesday you published a release that verified perfectly. Correct key, correct manifest, correct counter, correct hardware range. It also had a null dereference in the startup path, on a board configuration you do not have on your desk. Every device that took it swapped it into the primary slot, overwrote the working image with it, rebooted, and crashed. They are still crashing. The working firmware was sitting in the secondary slot right up until the swap, and the swap was permanent, so it is not there any more.

Nothing was forged, nothing was replayed, and every control you have built worked exactly as designed. You shipped a broken release with your own key and your fleet installed it, because installing it is all your fleet knows how to do.

`T0-W-07` has been open since Tier 0 saying precisely this. The fallback path physically exists: the course has used MCUboot's swap-using-offset mode in every tier, so the displaced image is written into the secondary slot on every install. No tier has ever taken that path. Tier 0 said a path you never take is not a recovery mechanism, and four tiers later it still is not one.

This tier makes the device sceptical about its own success. It will install on trial rather than permanently, judge itself for sixty seconds, and put the old image back on its own if it cannot prove it works. It will also learn to survive being interrupted: a download that stops halfway will resume rather than start again, which matters because the thing most likely to interrupt an update is not an attacker.

By the end you will have reverted a device four different ways, and you will be able to say which of those four the device could explain and which it could not.

## Learning result

After this tier, you can:

- Explain why update availability is a security property, and why a device that cannot be updated is a device you cannot fix.
- Request a test boot rather than a permanent upgrade, and say what changes about the failure you are now protected from.
- Design a health gate that cannot be failed by the network, and say why that constraint is structural rather than a matter of care.
- Distinguish a failed check from a stalled one, and say why the tier ships two broken releases to make that distinction observable.
- Resume an interrupted download safely, and explain which of the two orderings of a progress record and a flash write is the safe one and why.
- Say which failures a device can explain afterwards and which it cannot, and why that is a property of the failure rather than a gap in the code.
- Name the new attack surface this tier creates, which is the first tier where hardening adds one.

## Safety boundary

Everything in this tier runs against the disposable Course environment on your own machine and the board on your desk.

This tier publishes four releases that do not work. They are signed with your own Release signing key, because nobody without it can produce a release this device will install, and a release that is refused at the signature never reaches the trial boot that is the whole subject here. Your key has not leaked. The commands say so as they run.

None of these four is an attack. A release that crashes is the manufacturer publishing something broken, which section 11 of the specification names beside the attacks in its threat list. The device cannot tell a broken release from a leaked key, and it recovers from either the same way.

Nothing here is irreversible. Every revert restores an image that is already on the flash, and the worst outcome of a mistake in this tier is a board that needs reflashing over USB, which you have done in every tier so far.

Both signing keys still live in `.course-secrets/signing`. Git ignores that directory.

## Starting state

You have finished Tier 4. Your device refuses seven hostile releases for distinguishable reasons and installs the current one.

```text
./course service start --https
./course device logs
```

You should see the Tier 4 banner and a verified connection.

One note about the device output quoted in this module. Every serial line in it was recorded on the board the course used before, a nanoESP32-C6 1.0, and no tier has yet been run on the ESP32-C6-DevKitC-1 this course now targets. Treat the quoted lines as what to expect rather than as a result on your board, record what you actually see, and raise any difference with a Mentor instead of editing your observation to match the page.

One thing to carry in clearly. Every install you have made so far was permanent, requested as `BOOT_UPGRADE_PERMANENT`, and the device has never once asked whether the result works. That is still true when you start, and it is what this tier closes.

## Weakness ledger before the work

Inherited from Tier 4. Not your own work yet.

| Weakness | What it means today | How you would see it | Where it is addressed |
| --- | --- | --- | --- |
| T0-W-07 | An installed image is permanent and the fallback path is unused | Install an image that does not work. The device has no way back | This tier |
| T0-W-02 | The service trusts the device identifier in the request body | Any device can claim another's name | Tier 6 and Tier 7 |
| T2-W-09 | The device has no clock and checks no dates | An expired certificate is accepted | Tier 8 |
| T3-W-10 | The bootloader itself is unverified | Nothing checks MCUboot before it runs | Advanced Tier A |
| T3-W-11 | One key signs the image and the manifest, so taking it defeats both | Sign anything with the release key | Tier 8 for lifecycle |
| T4-W-12 | Downgrade prevention does not protect the first install | Install onto a device whose primary image carries no counter | Accepted for the core course |
| T4-W-13 | The security counter is compared, never remembered | Rewrite the primary slot and the device forgets what it was running | Advanced Tier A |

## Predict

Before you change anything, write down what you expect. You will check these at the end.

1. Your device is running a release you confirmed. You assign it a release that crashes on startup. What is the device running ten minutes later?
2. You interrupt a download halfway through, by any means you like. What happens to the bytes already in the slot?
3. The device is sixty seconds into judging a new image and you unplug the network. Does the image confirm?
4. A release fails its trial. You leave the service assigning it. What does the device do for the next hour?

## Reproduce the failure that has no attacker

Start where Tier 4 left off, and install something broken.

```text
./course build firmware --tier 05 --variant crash
./course release sign --tier 05 --variant crash
```

Your Tier 4 device will take it. Every check passes, because there is nothing wrong with the image as an image: it is signed with your key, its manifest verifies, its counter is not lower, its hardware range matches, its digest is right. It is simply a program that does not run.

Watch it install and watch what you are left with. The device swaps the broken image into the primary slot, reboots, and faults. The image that worked is gone, because the swap was permanent.

This is `T0-W-07`, and it is worth sitting with for a moment. You did not make a mistake here that any of your existing controls could have caught. Tier 3 asks who signed it. Tier 4 asks whether it is the right release. Neither has an opinion about whether it works, and neither should: that is not a question a signature can answer.

Reflash a working image before you continue.

```text
./course device flash --tier 04 --variant security-fix
```

## Investigate the missing boundary

Read the specification's section 6 on image installation and confirmation, and notice how much of it is about what happens *after* an image is accepted. Then look at what your application currently does at the end of an install:

```c
boot_request_upgrade(BOOT_UPGRADE_PERMANENT);
```

MCUboot has a second mode. `BOOT_UPGRADE_TEST` swaps the image in the same way and then waits to be told the result was acceptable. If nobody tells it, it swaps back.

The question this tier has to answer is who tells it, and on what evidence. "The image booted" is not enough: a crashing image boots. Section 6 fixes the answer as a local health gate of sixty seconds, and it fixes one constraint on that gate which is easy to read past:

> Loss of network service alone must not fail the local health gate or cause an endless revert loop, because local application health is separated from optional backend reachability.

That constraint is the interesting part of the design. A device that treated "cannot reach the service" as unhealthy would revert every time your service restarted, and would then be offered the same release again, and would revert again. The endless loop the specification names is not hypothetical; it is the obvious thing to build if you are not careful.

## Install on trial and judge the result

Build and publish the five releases this tier uses. They come from one source tree and differ only in what they do during the trial, which is the whole subject, so the difference you have to understand is a single Kconfig choice rather than a diff between five directories.

```text
./course build firmware --tier 05 --variant healthy
./course release sign --tier 05 --variant healthy
```

Read `firmware/tier-05-recovery/src/main.c` and `health_gate.c` before you run anything. Four things in them are worth finding yourself.

**The upgrade is a test.** `boot_request_upgrade(BOOT_UPGRADE_TEST)`, and the application calls `boot_write_img_confirmed()` only after the gate passes. From this tier on, the device never requests a permanent upgrade again.

**The gate runs before the network comes up.** `confirm_or_revert()` is called before `net_link_connect()`. That is not an accident of ordering: it makes the specification's constraint structurally true rather than merely intended. A gate that has not connected cannot be failed by a connection.

**The watchdog is fed by the thread it vouches for, and nothing else.** The beacon reports that it is alive; `main` feeds the watchdog. Feeding from a timer would have been easier and would have guarded nothing, because a timer keeps running in interrupt context while the thread it describes is dead.

**The progress record is written after the bytes it describes.** The record may lag the flash. It may never lead it. There is one rule underneath the whole download path and it is worth memorising: *the record may never describe more than the flash holds.*

Now install a release that works, onto a device running something else.

```text
./course release assign --tier 05 --variant healthy
./course device logs
```

```text
ota.upgrade requested a TEST swap, not a permanent one
I: Image index: 0, Swap type: test
boot.state running image is on trial, not yet confirmed
trial.begin attempt 1 of 3 for release tier-05-healthy
health.check image-integrity      pass
health.check credentials-loaded   pass
health.check beacon-running       pass
health.check update-client-ready  pass
health.gate every check passed, holding for 60 seconds
health.gate passed
trial.confirm this image is now the one the device falls back to
```

Every check runs and every result prints, even when the first one fails. That is the same choice Tier 4 made with its eight refusal reasons, for the same reason: you cannot diagnose a failure whose siblings you cannot see.

## Watch it revert, four different ways

Four releases fail, and they are four releases rather than one because they fail differently and a device that could not tell them apart would be teaching you less than it knows.

```text
./course release assign --tier 05 --variant crash
./course release assign --tier 05 --variant hang
./course release assign --tier 05 --variant fail-health
./course release assign --tier 05 --variant timeout-health
```

Run them one at a time and read the device between each.

**`crash` faults before the gate starts.**

```text
trial.crash faulting deliberately before the health gate starts

 mcause: 3, Breakpoint
  mtval: 9002
...
rst:0x7 (TG0_WDT_HPSYS)
I: Image index: 0, Swap type: revert
```

The exception is printed, and then nothing happens for twenty seconds until the watchdog resets the board. Zephyr's fault handler halts rather than rebooting, so the watchdog is what actually recovers the device. That is worth noticing: the watchdog is not only for hangs.

**`hang` stops, quietly.**

```text
trial.hang stopping here, in the thread that feeds the watchdog
rst:0x7 (TG0_WDT_HPSYS)
I: Image index: 0, Swap type: revert
```

An ordinary loop in `main`. Interrupts keep being serviced and the beacon thread keeps running; what stops is the feed, because `main` is the only thing that performs one. This is the least informative failure in the whole course, and that is the point of it.

**`fail-health` fails one named check, before the window.**

```text
health.check image-integrity      pass
health.check credentials-loaded   pass
health.check beacon-running       pass
health.check update-client-ready  FAIL
health.gate refused by update-client-ready before the window started
trial.revert a health check failed at check update-client-ready
```

**`timeout-health` passes everything and then stops.**

```text
health.gate every check passed, holding for 60 seconds
health.gate holding, 54 seconds left
health.check beacon-advancing     FAIL with 49 seconds left
health.gate the window did not complete: the beacon stopped
trial.revert the health window expired at check beacon-advancing
```

Those last two are the pair the specification's wording demands: section 6 distinguishes "a failed check" from "an expired health timer", and one image cannot show you both.

In every case the next boot brings back the image you confirmed, and the device says what happened:

```text
I: Image index: 0, Swap type: revert
boot.state running image is confirmed
boot.state the previous boot gave up on release tier-05-fail-health at check update-client-ready
boot.state and MCUboot has put this image back. That is a revert.
```

## Prove the revert is not blocked by the counter

Section 6 says a failed trial can revert to the previously confirmed image
without a newer counter making that image ineligible. That is a claim worth
testing rather than believing, because Tier 4 spent a whole tier teaching the
bootloader to refuse an image whose counter went backwards, and a revert is an
image whose counter goes backwards.

The `crash` release is the one that raises the security counter, and it is the
only one of the five that does. Every other release carries the same counter so
that the trial path is what is being tested. This one is deliberately different:

```text
release.admitted release_id=tier-05-crash version=0.5.1-crash counter=4 channel=stable
I: course: slot=secondary header=ok tlv=ok signature=present key=match counter=4
I: Image index: 0, Swap type: test
Security counter of the running image: 4
```

It fails, and the revert takes the device backwards:

```text
I: Image index: 0, Swap type: revert
I: course: slot=secondary header=ok tlv=ok signature=present key=match counter=3
I: course: slot=primary header=ok tlv=ok signature=present key=match counter=3
Security counter of the running image: 3
```

No refusal, and no `Image 0 in slot 1 erased due to downgrade prevention`.

Why this needed a counter of 4 to mean anything is worth understanding.
MCUboot's `check_downgrade_prevention()` refuses when the primary slot's
counter is **strictly greater** than the candidate's. With every release at the
same counter, the check would not fire even if a revert did pass through it, so
a revert between equal counters proves nothing at all. Only a revert that would
otherwise be refused can demonstrate the exemption.

The exemption is structural rather than lucky. In `loader.c`,
`check_downgrade_prevention()` is called under `case BOOT_SWAP_TYPE_TEST` and
`case BOOT_SWAP_TYPE_PERM` only, and `BOOT_SWAP_TYPE_REVERT` is a separate case
reached after both of those break out.

## What the device cannot tell you

Two of those four leave no reason behind.

| Release | What the next boot can say |
| --- | --- |
| `fail-health` | The named check that failed |
| `timeout-health` | That the beacon stopped, and when |
| `crash` | Nothing. Reset cause only |
| `hang` | Nothing. Reset cause only |

The application writes its reason to flash before its controlled reboot. A crashing image never reaches that code, and a hung one is reset from an interrupt handler where writing to flash is not safe. So the device can tell you why it gave up only if it was still alive enough to write it down.

This is not a gap to engineer around. It is the honest description of what a watchdog reset is, and a tier that hid it behind a uniform-looking report would be teaching you to trust a verdict.

Note also that reset cause does not separate `crash` from `hang` on this board: both end as `rst:0x7 (TG0_WDT_HPSYS)`, because the fault handler halts and the watchdog recovers. What separates them is the exception dump.

## Resume an interrupted download

The other half of availability. Section 7 requires the device to stream the image to the slot using range requests, store its progress, and resume safely.

Make the service answer badly on purpose:

```text
./course service start --https --range interrupt:200000
./course release assign --tier 05 --variant timeout-health
```

The service begins answering correctly and drops the connection after 200000 bytes. The device keeps what it has:

```text
ota.progress 196608 of 740041 bytes are in the slot
ota.request failed url=/v1/firmware/tier-05-timeout-health.bin err=-113
ota.install interrupted with 200000 bytes in the slot; the record
ota.install survives and the next poll resumes from there
```

and picks up where it left off:

```text
ota.resume 196608 of 740041 bytes are already in the slot
ota.resume the manifest was fetched and verified again before this record
ota.resume was allowed to matter. The record says where to resume, never what to believe.
ota.resume requesting Range: bytes=196608-
```

Two details in that output repay attention.

**It resumed from 196608, not 200000.** The record is written after the bytes it describes, at 64 KiB checkpoints, so it lagged the flash by 3392 bytes and those bytes were downloaded twice. That is the safe direction. A record that led the flash would have resumed into a gap and built an image that only the digest would catch.

**The manifest was fetched and verified again.** The stored record is a hint about where to resume. It is never a thing to trust. This is the only tier that puts application state in flash, and a device that treated its own flash as a trust anchor would be learning the wrong habit in exactly the wrong place.

Now try it with a reset instead of a dropped connection, which loses RAM as well:

```text
./course device reset
```

during a transfer. The device comes back, re-verifies the manifest, and resumes from the recorded offset. Nothing in the course before this tier had state that needed to survive a reset at all.

## Test bypass attempts

Three things can be defeated separately here, so there are three attempts.

**Make the service ignore the range request.**

```text
./course service start --https --range ignore
```

A server that ignores `Range` and answers `200` with the whole body is the failure most likely to be got wrong, because it looks like success while restarting the image from byte zero underneath a device that believes it is appending.

```text
ota.resume requesting Range: bytes=393216-
ota.resume refused status=200, expected 206 Partial Content
ota.discard the response was refused before any write
ota.discard the progress record was cleared before the slot was erased
```

Note the discard order: record first, then slot. That is the mirror of the write order, and for the same reason. Writing lags so the record can only under-claim; discarding leads so a power cut in the middle leaves no record rather than one pointing into an erased slot.

**Change the release underneath a partial download.** Assign a different release while one is half-downloaded. The device discards rather than splicing two images together.

```text
ota.discard the release changed since this download started
```

**Keep offering a release that fails.** This is the loop the specification warns about, and the device bounds it:

```text
trial.begin attempt 1 of 3 for release tier-05-crash
trial.begin attempt 2 of 3 for release tier-05-crash
trial.begin attempt 3 of 3 for release tier-05-crash
ota.refused check=trial-limit release_id=tier-05-crash attempts=3 of 3
ota.refused this release has already been given every trial it gets.
ota.refused The beacon carries on; the device is healthy and has simply
ota.refused stopped accepting one release.
```

The count is incremented when a trial *begins*, not when one fails. A crashing image never reaches code that could record a failure and a hung one cannot write from an interrupt handler, so counting failures would have missed the two failures that most need counting.

Finally, the case the specification names by name. Stop the service entirely while an image is being judged:

```text
health.gate every check passed, holding for 60 seconds
health.gate passed
trial.confirm this image is now the one the device falls back to
event.queued update.confirmed release_id=tier-05-healthy detail=health gate passed
ota.tls refused the connection to 192.168.68.81:8443 errno=104
```

The image confirms. The device then reports a failed connection every poll and carries on running. Network loss alone did not fail the gate and did not cause a revert loop, which is what section 6 requires.

## Say what happened, once there is somewhere to say it

That `event.queued` line is worth following, because it is a consequence of the ordering you read earlier.

The health gate runs before `net_link_connect()`. That is what makes the constraint you just tested structural: a gate that has not connected cannot be failed by a connection. It also means the device reaches its verdict with no way to tell anyone, and the verdicts are exactly the events section 7 asks it to report.

So the device writes the event down and sends it when there is a link:

```text
event.queued update.reverted release_id=tier-05-healthy detail=tier-05-fail-health update-client-ready
```

Three things about that line repay attention.

**The reporting image is not the image that failed.** A failed trial reboots, so the image that reports the revert is the one that came back. It reads the reason out of flash, which is why the reason had to be written before the reboot rather than sent over a network that was not up.

**The running release and the failed release are different fields.** The service stores an event's identifier as `running_release_id`, and for a revert the release that failed is precisely the one not running. An earlier version of this tier put the failed release in that field, which produced records saying the device was running an image it had just thrown away. A fleet view built on those would show a broken release spreading.

**A crash and a hang still report something.** They leave no reason, but they leave a trial record naming a release the device is not running, which is enough to report `reason-unrecorded`. The failures hardest to diagnose are the ones a fleet most needs to hear about, and a device that stayed silent about them would have inverted this tier's whole lesson.

That report happens once. The record is marked as reported rather than cleared, because the count in it is also what bounds the retries, and you can watch both facts in one line: `recovery.state trial` prints the release, the attempt count, and whether the fleet has been told. `T5-W-26` is what marking it costs.

## Reveal

Compare against what you predicted.

1. Ten minutes later the device is running the release you confirmed before the broken one, and has refused the broken one on its trial count.
2. The bytes stay. The download resumes from the last recorded checkpoint, re-verifying the manifest first.
3. It confirms. No health check asks whether the service is reachable.
4. Three trials, three reverts, and then it stops accepting that release and carries on beaconing.

If you predicted that the network loss would fail the gate, you are in good company: it is the intuitive answer and it is the one the specification forbids.

## Weakness ledger after the work

| Weakness | Result after this tier | Status | Evidence or next action |
| --- | --- | --- | --- |
| T0-W-07 | Closed. Every install is a trial, the device judges itself, and the fallback path that has existed since Tier 0 is finally used | Closed | The four reverts, observed on hardware, on the earlier nanoESP32-C6 1.0 |
| T0-W-02 | Unchanged | Open | Tier 6 and Tier 7 |
| T2-W-09 | Unchanged | Open | Tier 8 |
| T3-W-10 | Unchanged | Open | Advanced Tier A |
| T3-W-11 | Unchanged | Open | Tier 8 for lifecycle |
| T4-W-12 | Unchanged, and now reachable more than once. A revert restores the previously confirmed image, and if that image predates the security counter the device returns to the state this row describes | Open | Advanced Tier A, with `T4-W-13` |
| T4-W-13 | Unchanged | Open | Advanced Tier A |
| T5-W-14 | New. Anyone who can power-cycle the board during the sixty second health window forces a revert, with no key, no network and no credential. The device can never complete an update while someone keeps doing it | Open | Residual availability risk. Named in the lab artifact |
| T5-W-15 | New. The watchdog catches a hung thread only because the driver's stage 0 handler fails to feed it, which it does because `wdt_esp32_isr()` does not disable write protection first. An upstream fix would change this silently | Open | Recorded limit. Recheck on any Zephyr upgrade |
| T5-W-26 | New. A revert is reported once, to nobody in particular. The event is held in RAM and sent when the link returns, and nothing acknowledges it, so a board that reverts and never reaches the service does not tell the fleet it reverted | Open | Recorded limit. Tier 8 revisits delivery |

Three of the four changes are limits rather than achievements, which by now should be the expected shape of a control tier's ledger.

`T5-W-14` deserves attention because it is the first time in this course that adding a control has created new attack surface. Before this tier an install either completed or it did not. Now there is a sixty second window in which a physically present attacker can guarantee it does not, indefinitely, using nothing but the power switch.

`T5-W-26` is a limit this tier chose on purpose, and it is worth seeing why, because the honest version looks worse than the broken one.

The device records that a release was put on trial, and a board that reverted reads that record on the next boot and reports the revert. Nothing clears the record on that path, and nothing may: the same count is what stops the device installing a failing release forever, so forgetting it to tidy up would trade a duplicate message for a revert loop. The device marks the record as reported instead.

Marking it means the report happens once. The event is queued in RAM, sent when the link returns, and nobody acknowledges it, so if that boot cannot reach the service the revert is never reported at all. Before the mark existed, the report fired on every boot until something got through, which looks like a retry and is not one: it was the device unable to tell that it had already spoken, and left running long enough it would name a release it had never tried. A message repeated until it is wrong is not more reliable than a message sent once. It is less honest about what the device actually knows.

Delivery that survives a device being offline needs the service to acknowledge what it received and the device to keep what has not been acknowledged. That is a queue with durable state on both ends, and it belongs with the other lifecycle operations in Tier 8.

## Security claim and evidence status

**SC-05: An interrupted or failed update never leaves the device without a working image.**

It becomes **partly supported**.

Supported against the failures this tier can demonstrate: a release that crashes, hangs, fails a health check or stalls during the window is reverted to the last confirmed image, and a download interrupted by a dropped connection or a reset resumes and completes. All of this was observed on the board the course used before, a nanoESP32-C6 1.0, and none of it has been repeated yet on the ESP32-C6-DevKitC-1 this course now targets.

The revert path itself is not blocked by the anti-rollback control, observed
with a trial image at counter 4 reverting to a confirmed image at counter 3.

Not supported against a power cut at every transition. Three of section 6's transitions were not reached during validation: the trailer update, the confirmation write, and the first reboot after confirmation. Each is a window of a few milliseconds. They are recorded as `not_reached` in `course.yml` rather than as passes, because a skipped check never supports a claim.

Not supported against sustained physical interference, which is `T5-W-14`.

One control supports it. Unlike `SC-01` and `SC-02`, this claim needs no second control for key custody, because nothing in it is about who signed anything.

| Control | What it does | Requirement | Status after this tier |
| --- | --- | --- | --- |
| CTL-05 | Two image slots with test boot, explicit confirmation, and automatic revert | REQ-05 | Implemented, and not exercised against a power cut at three of the transitions |

`CTL-05` is the control Tier 1 planned for this tier, in the words Tier 1 used. Your own control record for it has been sitting at `planned` since Tier 1, and this is the tier that moves it.

## What this tier found in Tier 4

A control tier is the first thing to exercise the previous tier's work in a new way, and four out of four have now found something.

Tier 4 returns the transport's error before it looks at the refusal that caused it. When a response callback refuses, the HTTP client aborts the connection and reports the abort, so a size refusal comes back as `-113`, which is what a dropped connection looks like.

In Tier 4 this is harmless: nothing branches on that value, the refusal is printed where it is decided, and you still read `check=image-size`. In Tier 5 it was not harmless, because Tier 5 decides whether to discard a partial download based on that value, and a refused range response kept its bytes.

Tier 4 is not being changed. Every behaviour its module describes is correct and its validated outcomes stand, and a published tier changing underneath a Learner is its own problem. The finding is recorded here instead.

## Update the Security evidence pack

Add to your pack:

- The update state diagram: download, verify, test boot, judge, confirm or revert.
- The interruption matrix: what happens when each transition is interrupted, including the three that were not reached and why.
- Confirmation and revert logs for all five releases.
- A recovery record: how you would restore a device whose primary image no longer works, using the serial recovery procedure below.
- Your `control` records for `CTL-05`, moved from `planned` to `implemented`.
- Residual availability risks, which for this tier are `T5-W-14` and `T5-W-15`.

## Serial recovery

The last confirmed image is your normal recovery path, and everything above is about keeping it available. When there is no valid image left, recovery is physical.

This tier does not build MCUboot's serial recovery mode. Section 6 specifies it on a dedicated UART, and on this board the console already occupies the USB serial path, so a dedicated recovery UART means physical pins and a second adapter that no core tier requires. The procedure is documented here and the build belongs to Advanced Tier A, where physical access and disposable hardware are already prerequisites.

Until then, recovery on this board is reflashing over USB:

```text
./course device flash --tier 05 --variant healthy
```

Two things about that command are worth knowing before you need them. Flashing writes the primary slot and does **not** clear MCUboot's trailer, so a pending trial survives a reflash and the fresh image can come up reporting itself unconfirmed. And `esptool`'s own reset leaves this chip in ROM download mode, `boot:0x4`, where the application never runs and the console is silent, which looks exactly like a board you have broken.

Section 18's core boot matrix lists signed serial recovery as a row it verifies. That row is **not satisfied by this tier** and is recorded as such. Leaving it silently absent would be the same error as claiming a hardware result you did not observe.

## Troubleshooting

| What you see | What it means |
| --- | --- |
| The device reverts immediately and `beacon-running` failed | The beacon thread had not produced its first tick. The gate waits three seconds for it; if you have modified the beacon, check it still ticks |
| A healthy image reboots every half minute on `rst:0x7` | The watchdog is not being fed often enough for your poll interval. `main` feeds in slices between polls and on every response fragment |
| `ota.resume refused status=200` | The service ignored your range request. Expected if you started it with `--range ignore`; otherwise your service is not the one this course ships |
| The board is silent after a reset and the console shows nothing | Check the boot line for `boot:0x4 DOWNLOAD`. Pulse RTS alone to reset; `esptool` leaves the chip in the ROM loader |
| A release is refused with `check=trial-limit` | It has already failed three trials. Assign a different release, which clears the count |
| A release is refused with `check=already-confirmed` | You are offering the device the image it is already running and has confirmed |

## Informal Mentor conversation

This tier has a **required Mentor review gate**, the update-recovery gate, and the first since Tier 3. Section 13 sets the four headings.

Come prepared to show one success and one failure, to explain which trust boundary changed and which did not, and to diagnose a prepared failure the Mentor chooses. Be ready for the question this gate always asks: what can the attacker still do? The answer for this tier is unusually interesting, because hardening it added surface rather than only removing it.

## Continue

**[Tier 6: Replace shared identity with per-device factory identity](../tier-06-factory-identity/index.md)** replaces the shared development identity with a per-device factory identity. Your device can now recover from a bad release; it still claims the same name as every other device you own, and that name travels inside every image anyone can copy. Tier 6 has you clone the shared credential to prove the point, then generate a key on the device itself.

Start it from a device running a confirmed image.

## Primary references

- Specification sections 6, 7, 11, 13 and 18.
- MCUboot: `boot_request_upgrade()`, `boot_write_img_confirmed()`, `boot_is_img_confirmed()`.
- Zephyr: `stream_flash`, NVS, and the watchdog API.
- `docs/fixture-safety-contract.md`, Tier 5 section.
