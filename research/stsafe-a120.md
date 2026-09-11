# STSAFE-A120 with an ESP32-C6 and Zephyr

**Research date:** 2026-09-11  
**Question:** What security properties can an STSAFE-A120 add to the reference product, and what does integration with ESP32-C6 and Zephyr require?  
**Recommendation:** Advanced module. It is a valuable comparison with protected on-chip keys, but it is not a core-course requirement.

## Summary

The STSAFE-A120 is an external secure element. A secure element is a separate chip designed to hold secrets and perform security operations. It can give the product a per-device identity, keep a device private key out of normal ESP32-C6 software and flash, sign data, and support a TLS client certificate flow. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf)

It does not replace secure boot, flash encryption, a TLS library, or a secure update design. The ESP32-C6 still handles the network, TLS protocol, certificate checks, and most application security decisions. A compromised application can still ask the secure element to sign data. [Zephyr secure sockets, v4.4.2](https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html)

There is no upstream Zephyr STSAFE driver. A search of the upstream Zephyr source for `STSAFE` returned no results on the research date. A separate CATIE module does provide an A110/A120 Zephyr I2C driver. It is not an upstream Zephyr component and its samples target an nRF5340 board, not ESP32-C6. Treat it as a useful starting point, not as a supported ESP32-C6 product integration. [Upstream Zephyr search](https://github.com/search?q=STSAFE+repo%3Azephyrproject-rtos%2Fzephyr&type=code) [CATIE driver README, commit 5b7f1243db53506ae9c50ffc4eecda0224512c12](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/README.md)

## What the A120 can add

### Device identity

The A120 can hold a device identifier and a device certificate chain. STSELib has functions to read an 11-byte device ID, the certificate size, and a certificate from a selected certificate zone. This supports a per-device X.509 identity. X.509 is the common certificate format used by TLS. [STSELib device authentication API, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_device_authentication.h)

For product use, the backend should bind the certificate public key and device ID to the product serial number and owner record. Do not make the device ID alone an authorization decision. An attacker can often read an identifier even when they cannot copy the private key.

### Private-key isolation and signing

The A120 has internal elliptic curve cryptography, or ECC, private-key slots. ECC is a public-key method that uses small keys. The A120 can generate an ECC key pair in a selected slot and apply a usage limit to that pair. The host receives the public key. The intended design is that the private key stays in the secure element and the host requests a cryptographic operation. [STSELib asymmetric-key API, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_asymmetric_keys_management.h)

This is stronger separation than storing a normal private-key file in external flash. It reduces accidental copying into source control, build logs, debug output, non-volatile storage, or a factory database. It also gives a separate hardware boundary if flash encryption or the main MCU is attacked.

The same boundary can sign a digest or participate in elliptic-curve key agreement. These operations can support an application signature, challenge-response authentication, and the private-key operation in TLS. The exact curves, slots, access conditions, and command permissions depend on the ordered A120 profile. Confirm them before choosing certificate algorithms. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf) [STSELib library configuration, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/doc/resources/Markdown/03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md)

### TLS client authentication

TLS client authentication is often called mutual TLS, or mTLS. In mTLS, the server checks the device certificate and asks the device to prove that it owns the matching private key.

The A120 can supply the device certificate and perform the private-key operation. The ESP32-C6 must still run the TLS state machine, receive and parse certificates, validate the server, manage network errors, and protect TLS session data in RAM. Zephyr secure sockets use Mbed TLS. They require credentials to be registered as certificate authority, or CA, certificates, public certificates, private keys, or pre-shared keys. There is no documented A120 credential provider in that API. [Zephyr secure sockets, v4.4.2](https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html)

This makes mTLS the largest integration task. The product needs either:

1. A maintained Mbed TLS private-key callback or driver that sends the sign or key-agreement operation to the A120.
2. A TLS stack and middleware combination that already has an A120 integration.

STSELib links to a wolfSSL example project. Its A120 tests cover random number generation, ECC key generation, ECC signing, and ECC key agreement on a Raspberry Pi 5. This shows a middleware path, but it is not evidence of a Zephyr TLS integration. [wolfSSL A120 test README, commit 407922b](https://github.com/wolfSSL/wolfssl-examples/blob/407922b85fcb44787c44d34762ae31e88b981bd1/stsafe/README.md)

### Certificate and trust-anchor storage

The A120 has 16 KB of configurable non-volatile memory. It can store public data such as a device certificate chain, subject to the selected profile and access conditions. STSELib explicitly reads a device certificate from a certificate zone. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf) [STSELib device authentication API, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_device_authentication.h)

Do not assume that A120 certificate storage is a ready-made TLS server trust store. In STSELib, the function that verifies a device certificate receives the root CA certificate as a host buffer. This shows that the library can use a host-held root certificate. It does not prove that Zephyr TLS will obtain server trust anchors from the A120. [STSELib device authentication API, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_device_authentication.h)

For a first product, keep the server root CA or pinned public key in the signed application image or another protected host store. Keep this set small. Design and test its update and rollback path. Store server trust anchors in the A120 only after confirming the profile, access controls, memory budget, and TLS integration.

## Provisioning choices

Provisioning means loading the device key, certificate, and access rules before the product is shipped.

1. **SPL05 generic sample profile.** `STSAFA120S8SPL05` is an orderable public sample-profile part. It is suitable for learning and prototypes. Read its profile document before use because data zones and access rules are already chosen. [ST store listing for STSAFA120S8SPL05](https://estore.st.com/en/stsafa120s8spl05-cpn.html) [AN6053, STSAFE-A120 SPL05 generic sample profile description](https://www.st.com/resource/en/application_note/an6053-stsafea120-spl05-generic-sample-profile-description-stmicroelectronics.pdf)
2. **ST or approved production personalization.** Use a custom profile or personalization service when the product needs unique keys and certificates at scale. This can avoid giving a contract manufacturer a long-lived device private key. Before an order, get the profile definition, certificate format, issuing CA owner, key ownership, and recovery terms in writing.
3. **Product-controlled injection.** The product owner can create keys and certificates and load them through an approved secure process. This gives more control but makes the factory process and key-handling system part of the security boundary. Use a hardware security module or an equivalent controlled signing system for the CA key.
4. **Online Certificate Distribution, or OCD.** ST documents OCD for STSAFE-A products. It can help a backend obtain certificate information for provisioned devices. Treat it as one part of backend registration, not as the complete fleet inventory or revocation process. [AN6206, Online certificate distribution for STSAFE-A products](https://www.st.com/resource/en/application_note/an6206-online-certificate-distribution-for-stsafea-products-stmicroelectronics.pdf)

Before irreversible provisioning, run a pilot that proves all of these items: production-to-backend serial mapping, certificate-chain validation, lost-device revocation, certificate renewal, CA rollover, device replacement, and failed-line recovery.

## Hardware and physical interface

The A120 is an I2C slave. Its data sheet specifies I2C Fast-mode operation up to 400 kbit/s. The host must budget I2C transfer time, command time, and response polling time. Do not use cryptographic engine time alone as the TLS latency estimate. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf)

The direct board work is small but important:

- Connect the A120 to an ESP32-C6 I2C controller with correct pull-up resistors and voltage levels.
- Connect and control reset if the selected design requires it.
- Keep I2C exposed only where needed. Test bus probing, clock stretching, a stuck bus, missing pull-ups, brownout, and a device held in reset.
- Consider physical access. An external chip improves key isolation, but its I2C wires are accessible to an attacker with board access. A bus attacker can observe public traffic, replay permitted requests, alter traffic when no protected host session is in use, or deny service.

The third-party Zephyr driver makes reset GPIO mandatory in its DeviceTree hardware description. It creates an I2C device, toggles reset, and serializes multi-threaded use with a mutex. These details are useful design checks for an ESP32-C6 port. [CATIE A120 DeviceTree binding, commit 5b7f1243db53506ae9c50ffc4eecda0224512c12](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/dts/bindings/crypto/st,stsafe-common.yaml) [CATIE driver source, commit 5b7f1243db53506ae9c50ffc4eecda0224512c12](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/drivers/stsafe/stsafe.c)

ST's documented development hardware is the X-NUCLEO-ESE01A1 expansion board with the NUCLEO-L452RE STM32 board. This is a good way to learn the part. It is not an ESP32-C6 development kit. For ESP32-C6 work, plan a breakout board or a product PCB with an A120 and suitable I2C wiring. [STSAFE-A SDK README, v1.0.4](https://github.com/STMicroelectronics/stsafe-a-sdk/blob/v1.0.4/ReadMe.md) [UM3531, how to use the A120 Nucleo expansion board](https://www.st.com/resource/en/user_manual/um3531-how-to-use-stm32-nucleo-expansion-board-based-on-the-stsafea120-secure-element-stmicroelectronics.pdf)

## Software, middleware, and licensing

STSELib is ST's middleware library. It has API, service, and core layers. It requires a project configuration file and a platform file. The generic platform example includes STM32 headers, so a Zephyr port must provide Zephyr types and callbacks instead. It also exposes settings for response polling and protected host sessions. [STSELib README, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/README.md) [STSELib configuration guide, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/doc/resources/Markdown/03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md) [STSELib generic platform guide, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/doc/resources/Markdown/04_PORTING_GUIDE/PAL_files/stse_platform_generic.h.md)

At the research date, STSAFE-A SDK release note **v1.0.4** listed STSELib **v1.1.9**. The SDK describes STM32 reference hardware and requires X-CUBE-CRYPTOLIB **v4.5.0**. Do not add that STM32 dependency to an ESP32-C6 Zephyr build without a separate porting decision. [STSAFE-A SDK release note, v1.0.4](https://github.com/STMicroelectronics/stsafe-a-sdk/blob/v1.0.4/release_note.md) [STSAFE-A SDK README, v1.0.4](https://github.com/STMicroelectronics/stsafe-a-sdk/blob/v1.0.4/ReadMe.md)

STSELib has a BSD 3-Clause license. The separate CATIE Zephyr module has an Apache-2.0 license. Its Zephyr West dependency manifest pulls a development revision of STSELib **v1.2.0**, commit `dc93a1c`. The two licenses are generally compatible, but the product must preserve their notices and review every imported dependency. [STSELib license, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/LICENSE.txt) [CATIE license](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/LICENSE) [CATIE West manifest](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/west.yml)

## Zephyr and ESP32-C6 status

Zephyr v4.4.2 documents the ESP32-C6 DevKitC board and its MCUboot option. The board page says simple boot has neither security features nor OTA updates. This makes a boot and update design necessary even when an A120 is added. [ESP32-C6 DevKitC board documentation, Zephyr v4.4.2](https://docs.zephyrproject.org/4.4.2/boards/espressif/esp32c6_devkitc/doc/index.html)

Upstream Zephyr did not contain `STSAFE` code in the searched source. The CATIE module is the only directly found Zephyr driver in this research. At commit `5b7f1243db53506ae9c50ffc4eecda0224512c12`, it provides `st,stsafe-a120` DeviceTree support, I2C transport, reset control, STSELib platform callbacks, and thread-safe handle access. Its supplied tester covers echo, personalization information, and host-key state. Its multi-thread sample demonstrates serialized echo operations. Neither sample demonstrates a TLS client certificate connection. [CATIE driver README](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/README.md) [CATIE tester sample](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/samples/zephyr_st-stsafe-a1xx-tester/README.md) [CATIE multi-thread sample](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/blob/5b7f1243db53506ae9c50ffc4eecda0224512c12/samples/zephyr_st-stsafe-a1xx-example/README.md)

The practical path is:

1. Start from the CATIE driver only after pinning its commit and reviewing its maintenance status.
2. Create an ESP32-C6 overlay and validate electrical I2C and reset behavior.
3. Prove basic A120 commands and concurrent access.
4. Add and test a TLS private-key bridge. Do not register an empty or copied software private key merely to satisfy the Zephyr credential API.
5. Test mutual TLS, server validation, certificate rotation, timeout, reset, I2C failure, and retry behavior against the real backend.
6. Keep a documented update plan for the driver, STSELib, Zephyr, A120 profile, certificates, and backend CA.

## Performance and lifecycle limits

The public data sheet establishes a 400 kbit/s I2C ceiling, 500,000 erase/write cycles, and 25-year data retention at 25 C for A120 non-volatile memory. These are part limits, not a complete product benchmark. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf)

The wolfSSL Raspberry Pi 5 example reports about 40 ms for P-256 key generation, 51 ms for a P-256 signature, and 38 ms for a P-256 shared secret. These are example results from another host. They are not A120 product limits or an ESP32-C6 result. [wolfSSL A120 test README, commit 407922b](https://github.com/wolfSSL/wolfssl-examples/blob/407922b85fcb44787c44d34762ae31e88b981bd1/stsafe/README.md)

Do not put an unmeasured signature time in a product requirement. Measure the median, 95th percentile, and 99th percentile handshake latency. Test the selected profile, PCB, I2C speed, Zephyr driver, certificate size, power mode, and temperature range. Include reconnects and server certificate validation.

Avoid writing a secure counter or record for every boot, packet, or handshake. Such writes consume finite non-volatile-memory life. Also review every access-condition change before production. STSELib documents configuration for response polling and protected host sessions, and its release history mentions non-reversible access-condition downgrade documentation. Irreversible profile choices need a signed manufacturing review. [STSELib configuration guide, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/doc/resources/Markdown/03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md) [STSELib releases](https://github.com/STMicroelectronics/STSELib/releases)

## Comparison with protected ESP32-C6 on-chip keys

The ESP32-C6 already has meaningful on-chip protections when configured through a supported Espressif workflow:

| Area | ESP32-C6 protected on-chip option | What the A120 adds |
| --- | --- | --- |
| Firmware authenticity | Secure Boot v2 verifies bootloader and application signatures. The signing private key stays off-device. | Nothing required here. Keep secure boot even with A120. |
| Flash confidentiality | Release-mode flash encryption encrypts external flash. The eFuse flash key is protected from software. | A separate chip boundary for the device identity key. |
| Client signing key | The DS peripheral uses RSA private parameters encrypted in flash. An eFuse HMAC key derives the decryption key inside hardware. ESP-TLS has an mTLS DS example. | ECC-focused secure-element functions, certificate zones, separate hardware, and ST personalization options. |
| Secret material | HMAC eFuse keys can be inaccessible outside crypto hardware. | An independently managed device identity and a security boundary outside the MCU. |

[ESP32-C6 Secure Boot v2, ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/security/secure-boot-v2.html) [ESP32-C6 flash encryption, ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/security/flash-encryption.html) [ESP32-C6 DS peripheral, ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/api-reference/peripherals/ds.html) [ESP32-C6 HMAC, ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/api-reference/peripherals/hmac.html)

The Espressif material is an ESP-IDF baseline. It does not prove that every feature, eFuse workflow, or ESP-TLS DS integration is available unchanged in Zephyr. Validate the actual Zephyr and Espressif hardware abstraction layer support before using those protections in this product.

## Threats

### Threats reduced by the A120

- Simple cloning from a copied flash image or a copied software private key.
- Accidental private-key exposure in normal host software, flash, logs, build files, and many factory workflows.
- Some physical extraction attacks against the MCU and external flash, because the long-lived key and operation are in a separate secure element.
- Supply-chain identity problems when a controlled personalization process creates a unique device identity.

### Threats not removed by the A120

- Malicious but correctly signed firmware. Secure boot and secure update rules must handle this.
- A runtime-compromised ESP32-C6 application asking the A120 to sign attacker-chosen data.
- A compromised backend, CA, enrollment service, or product authorization rule.
- I2C denial of service, power removal, reset abuse, or destruction of the external chip.
- A physical attacker who can modify the I2C path, unless the selected profile and host-session design protect the relevant commands.
- Certificate expiry, CA rollover, revocation failure, wrong fleet records, and loss of manufacturing traceability.
- Debug interfaces left open, weak passwords, unsafe APIs, memory bugs, or data leaked by application code.

## Course placement

Put the A120 in an **advanced hardware root of trust lab**. It should come after the learner has built a secure boot and signed-update flow, used protected storage, validated a TLS server certificate, and understood mTLS.

The lab should compare two designs:

1. An ESP32-C6 design using its supported secure boot, flash encryption, and protected on-chip key functions.
2. An A120-backed device identity with a private-key operation outside the MCU.

The lab artifact should include a threat table, a provisioning diagram, a certificate lifecycle plan, an mTLS test result, measured reconnect latency, and I2C fault results. The mentor review gate should ask why an external secure element is worth its bill-of-materials cost and maintenance work for the stated threat model.

Do not make the A120 a core-course dependency. It adds hardware cost, board work, manufacturing decisions, and a non-trivial Zephyr TLS integration. It is better used to teach when a stronger hardware boundary is justified, and when it is not.

## Sources

All sources below were accessed on **2026-09-11**.

1. STMicroelectronics. [STSAFE-A120 data sheet, DS14164 Rev. 2](https://www.st.com/resource/en/datasheet/stsafe-a120.pdf).
2. STMicroelectronics. [AN6053, STSAFE-A120 SPL05 generic sample profile description](https://www.st.com/resource/en/application_note/an6053-stsafea120-spl05-generic-sample-profile-description-stmicroelectronics.pdf).
3. STMicroelectronics. [AN6206, Online certificate distribution for STSAFE-A products](https://www.st.com/resource/en/application_note/an6206-online-certificate-distribution-for-stsafea-products-stmicroelectronics.pdf).
4. STMicroelectronics. [UM3531, how to use the STM32 Nucleo expansion board based on STSAFE-A120](https://www.st.com/resource/en/user_manual/um3531-how-to-use-stm32-nucleo-expansion-board-based-on-the-stsafea120-secure-element-stmicroelectronics.pdf).
5. STMicroelectronics. [STSAFE-A SDK release note, v1.0.4](https://github.com/STMicroelectronics/stsafe-a-sdk/blob/v1.0.4/release_note.md) and [SDK README, v1.0.4](https://github.com/STMicroelectronics/stsafe-a-sdk/blob/v1.0.4/ReadMe.md).
6. STMicroelectronics. [STSELib README, v1.1.9](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/README.md), [device authentication API](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_device_authentication.h), [asymmetric-key API](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/api/stse_asymmetric_keys_management.h), and [BSD 3-Clause license](https://github.com/STMicroelectronics/STSELib/blob/v1.1.9/LICENSE.txt).
7. Zephyr Project. [BSD sockets and secure sockets, v4.4.2](https://docs.zephyrproject.org/4.4.2/connectivity/networking/api/sockets.html) and [ESP32-C6 DevKitC board documentation, v4.4.2](https://docs.zephyrproject.org/4.4.2/boards/espressif/esp32c6_devkitc/doc/index.html).
8. CATIE. [Zephyr STSAFE-A1xx driver at commit 5b7f1243db53506ae9c50ffc4eecda0224512c12](https://github.com/catie-aq/zephyr_st-stsafe-a1xx/tree/5b7f1243db53506ae9c50ffc4eecda0224512c12).
9. Espressif. [ESP32-C6 Secure Boot v2, ESP-IDF v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/security/secure-boot-v2.html), [flash encryption, v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/security/flash-encryption.html), [DS peripheral, v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/api-reference/peripherals/ds.html), and [HMAC, v5.5.2](https://docs.espressif.com/projects/esp-idf/en/v5.5.2/esp32c6/api-reference/peripherals/hmac.html).
10. wolfSSL. [STSAFE-A120 test suite, commit 407922b](https://github.com/wolfSSL/wolfssl-examples/tree/407922b85fcb44787c44d34762ae31e88b981bd1/stsafe).

## Uncertainties and follow-up checks

- ST pages and PDFs were primary sources, but several ST PDF pages timed out during automated retrieval. The exact data-sheet and application-note URLs were recorded. Confirm the current revision and the ordered profile with ST before a purchase decision.
- The CATIE module was active at the cited commit, but its repository is third-party. Its visible samples target nRF5340 hardware. No ESP32-C6 build, hardware test, or mTLS test was found.
- No upstream Zephyr `STSAFE` source was found. This is a source-search result for the research date, not a promise that no later upstream support will appear.
- A120 profile contents, certificate hierarchy, access conditions, secure-channel setup, pricing, availability, and production personalization terms are order-specific. Obtain them from ST or the distributor before design freeze.
- The public documents give device limits, not an ESP32-C6 Zephyr handshake benchmark. Measure the final hardware and software combination.
