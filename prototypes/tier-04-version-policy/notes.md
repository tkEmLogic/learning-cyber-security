# Version policy decision table prototype

Throwaway prototype for [#69](https://github.com/tkEmLogic/learning-cyber-security/issues/69). Not course material. Something to react to.

The rule is fixed by section 6: **a security counter is increased only when a release closes a security boundary that must not be reopened.** A candidate counter may equal the confirmed one for an ordinary release, but never be lower. Section 11 names the failure criterion: the human-readable version must never override the security counter.

## The six scenarios the Learner classifies

The device is running `0.4.0-release-policy` at security counter 1.

1. A log message says `recieved`. Someone fixes the spelling.
2. The beacon gains a second blink pattern, requested by the product owner.
3. A malformed status response from the service makes the device reboot. No data is exposed and nothing is bypassed, but a hostile service can keep a fleet rebooting indefinitely.
4. The service name comparison is skipped when the configured name is the empty string, so a certificate for any name is accepted. Fixed.
5. An Mbed TLS advisory is published. The vulnerable code path is not reachable in this product, and the dependency is updated anyway.
6. A second Mbed TLS advisory. This path **is** reachable and can leak private key material. The dependency is updated.

## The table as it should be filled in

| # | Release | Version | Counter | Why |
| --- | --- | --- | --- | --- |
| 1 | Spelling fix | `0.4.1` | 1, unchanged | Nothing was closed, so nothing must stay closed. |
| 2 | Second blink pattern | `0.5.0` | 1, unchanged | A feature. The version moves because humans need to talk about it; the counter has no opinion about features. |
| 3 | Reboot on malformed response | `0.5.1` | 1, unchanged | Arguable, and worth arguing. It is a real availability fault, but reinstalling the old image reopens no boundary an attacker can cross to reach anything. Record the reasoning; a Learner who raises the counter here should be able to say what boundary they are protecting. |
| 4 | Name check bypass | `0.5.2` | **2** | This is the case the counter exists for. The old image accepts a certificate for any name, and a fleet that can be put back onto it has not been fixed. |
| 5 | Unreachable advisory | `0.5.3` | 1, unchanged | The dependency moved; the product's boundary did not. Updating is right. Raising the counter would claim a fix that was never a hole here. |
| 6 | Reachable advisory, key material | `0.5.4` | **3** | Key material. The old image must never run again. |

Two of six. That ratio is the lesson.

## The wrong tables, which are the ones engineers actually write

### Wrong 1: raise it every time

| # | Version | Counter |
| --- | --- | --- |
| 1 | `0.4.1` | 2 |
| 2 | `0.5.0` | 3 |
| 3 | `0.5.1` | 4 |
| 4 | `0.5.2` | 5 |
| 5 | `0.5.3` | 6 |
| 6 | `0.5.4` | 7 |

It looks careful and it is the opposite. Every release permanently destroys the ability to install every release before it. Six months in, a device fails in the field, and the one diagnostic step that would answer it — put the previous image back and see whether the fault follows — is now impossible on every device in the fleet. The counter has been spent on spelling.

It also empties the field of meaning. A counter that increments on everything says only how many releases there have been, which is what the version already said.

### Wrong 2: tie it to the version

`security_counter = minor version`, so scenario 2 takes it to 5 and everything after inherits that.

This is the failure criterion section 11 names in as many words, and it is seductive because it removes a judgement call. It fails in both directions at once: a patch release that closes a real hole cannot raise the counter without an artificial minor bump, and a feature release raises it for nothing.

## What the module has to make the Learner do

Classify before seeing any answer, then compare. The value is not in getting six right; it is in scenario 3, where two careful engineers can disagree and both have to say what boundary they think they are protecting.

## Open question for the answers page

The module template says control tiers do not publish answers pages, with one exception: "unless the tier asks the Learner to design something." This qualifies. But Tier 4 would be the first control tier to have one, and that is a template change as well as a tier decision. Worth confirming the exception is being read as intended rather than stretched.
