# Tier 4 answers: the version policy decision table

This page holds one worked model of the decision table from [Tier 4](index.md). It is not a marking scheme.

Fill in your own table before you read it. Then record the differences and the reasoning behind them, rather than copying this one. The value of the exercise is in the case where two careful engineers disagree, and you will not find that by agreeing with a page.

The rule the table applies is fixed by section 6 of the specification: **a security counter is increased only when a release closes a security boundary that must not be reopened.** A candidate counter may equal the confirmed one for an ordinary release, but never be lower. Section 11 names the failure criterion: a human readable version must never override the security counter.

## The scenarios

Your device is running `0.4.0-release-policy` at security counter 1.

1. A log message says `recieved`. Someone fixes the spelling.
2. The beacon gains a second blink pattern, requested by the product owner.
3. A malformed status response from the service makes the device reboot. No data is exposed and nothing is bypassed, but a hostile service can keep a fleet rebooting indefinitely.
4. The service name comparison is skipped when the configured name is the empty string, so a certificate for any name is accepted. Fixed.
5. An Mbed TLS advisory is published. The vulnerable code path is not reachable in this product, and the dependency is updated anyway.
6. A second Mbed TLS advisory. This path is reachable and can leak private key material. The dependency is updated.

## The table, worked

| # | Release | Version | Counter | Why |
| --- | --- | --- | --- | --- |
| 1 | Spelling fix | `0.4.1` | 1, unchanged | Nothing was closed, so nothing must stay closed. |
| 2 | Second blink pattern | `0.5.0` | 1, unchanged | A feature. The version moves because humans need to talk about it. The counter has no opinion about features. |
| 3 | Reboot on malformed response | `0.5.1` | 1, unchanged | Arguable, and worth arguing. It is a real availability fault, but reinstalling the old image reopens no boundary an attacker can cross to reach anything. If you raised the counter here, say what boundary you are protecting. |
| 4 | Name check bypass | `0.5.2` | **2** | This is the case the counter exists for. The old image accepts a certificate for any name, and a fleet that can be put back onto it has not been fixed. |
| 5 | Unreachable advisory | `0.5.3` | 1, unchanged | The dependency moved. The product's boundary did not. Raising the counter would claim a fix for a hole this product never had. |
| 6 | Reachable advisory, key material | `0.5.4` | **3** | Key material. The old image must never run again. |

Two of six. That ratio is the lesson.

## Wrong version 1: raise it every time

| # | Version | Counter |
| --- | --- | --- |
| 1 | `0.4.1` | 2 |
| 2 | `0.5.0` | 3 |
| 3 | `0.5.1` | 4 |
| 4 | `0.5.2` | 5 |
| 5 | `0.5.3` | 6 |
| 6 | `0.5.4` | 7 |

This is the table a careful engineer writes on a Friday, and it is the opposite of careful.

Every release permanently destroys the ability to install every release before it. Six months later a device fails in the field, and the one diagnostic step that would answer it, putting the previous image back to see whether the fault follows, is now impossible on every device you own. The counter has been spent on a spelling fix.

It also empties the field of meaning. A counter that increments on everything records how many releases there have been, which is what the version already said.

## Wrong version 2: tie it to the version

`security_counter = minor version`, so scenario 2 takes it to 5 and everything after inherits that.

This is the failure criterion section 11 names in as many words, and it is seductive because it removes a judgement call. It fails in both directions at once. A patch release that closes a real hole cannot raise the counter without an artificial minor bump, and a feature release raises it for nothing.

The two numbers answer different questions. The version answers "which release is this", and humans need it to be readable and ordered. The counter answers "may a device ever go back to before this", and nothing except a security judgement should move it.

## What to record

Not the table. Record where you disagreed with this page and why, and in particular what you decided about scenario 3. That decision is the artifact.

Back to [Tier 4](index.md).
