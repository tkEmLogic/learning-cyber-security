# Scanning the pinned dependencies offline

**Research question:** [GitHub issue #267](https://github.com/tkEmLogic/learning-cyber-security/issues/267), part of map [#265](https://github.com/tkEmLogic/learning-cyber-security/issues/265)

**Access and run date:** 30 September 2026. Every scanner run below was made on that date, on the dev host, in a scratch directory. Read-only facts about the Zephyr workspace were read inside the `tier2-validate` container. The board was not touched.

**Status:** Research. This is raw material for the triage exercise ticket (#272), not its answer. It is not legal advice and it makes no CRA conformity claim.

## Short answer

No single scanner gives a correct match list for this course. Use two scanners and one vendor cross-check, each with a pinned and dated database.

1. **grype** with an imported, checksummed database snapshot scans the firmware SBOM. It is the only tool tested that matched Zephyr at all. It matches C components only through NVD CPE data, so it raises many false matches and misses many true ones.
2. **govulncheck** with a local copy of the Go vulnerability database scans the OTA service and the course helper. It is the only tool that separates reachable Go matches from unreachable ones.
3. **A dated snapshot of the vendor advisories** (Zephyr GitHub security advisories and the Mbed TLS advisory pages) is the answer key. Without it, the Learner cannot tell a false match from a true one, and cannot see the true matches that no scanner reported.

osv-scanner is not recommended for the firmware. It returned zero matches for every pinned C component, both online and offline, and its offline mode does not support commit-level scanning. It works for Go, with one version-string trap described below.

Three premises of the map turned out to be false or incomplete. First, the Go matches are mostly real: the OTA service is built with Go 1.24.0, an unsupported toolchain, and 32 standard-library vulnerabilities are reachable from course code. Second, the most important true firmware matches are the ones no scanner raised: Mbed TLS 4.1.0 and TF-PSA-Crypto 1.1.0 are affected by July 2026 advisories, and Zephyr 4.4.2 is affected by at least one advisory whose code is in the Tier 8 image. Third, a CycloneDX SBOM that marks Zephyr as an `operating-system` component makes grype silently skip it.

## What was pinned and scanned

| Component | Pinned version | How the version was found |
| --- | --- | --- |
| Zephyr | 4.4.2, commit `dccb0959` | `course.yml`, `zephyr/VERSION` and `zephyr/.git/HEAD` in the container workspace |
| MCUboot | 2.4.0, commit `6d3b3d2c` | `course.yml`, `bootloader/mcuboot/boot/zephyr/VERSION`, and the `mcuboot` revision in Zephyr's `west.yml`. The commit is the upstream `v2.4.0` tag commit. |
| Mbed TLS | 4.1.0, Zephyr fork commit `a3e190fe` | `mbedtls` revision in Zephyr's `west.yml` and `MBEDTLS_VERSION_STRING` in `include/mbedtls/build_info.h`. The fork adds only build and packaging commits on top of the upstream `mbedtls-4.1.0` tag (`0fe989b6`), dated 2 April 2026. It carries no later security fixes. |
| TF-PSA-Crypto | 1.1.0, Zephyr fork commit `dc575a2d` | `tf-psa-crypto` revision in `west.yml` and `TF_PSA_CRYPTO_VERSION_STRING`. Mbed TLS 4.x takes its cryptography from this separate module. |
| Mbed TLS 3.6 | commit `a00e23de` | Also in `west.yml`, but the manifest comment says it is only for TF-M builds. The ESP32-C6 image does not use TF-M. Out of scope. |
| hal_espressif | commit `f0746505` | `west.yml`. It carries ESP-IDF 6.1.0 components, including a `wpa_supplicant` fork that `sbom.yml` names as version 2.10. The Wi-Fi build compiles it in when `CONFIG_WIFI_ESP32=y`, which Tier 8 sets. |
| Go toolchain | go1.24.0 | `go.mod` says `go 1.24` with no `toolchain` line. The dev container installs Go 1.23.4 (`.devcontainer/Dockerfile`), and `GOTOOLCHAIN=auto` makes it download go1.24.0. `go version` in the container repository prints `go1.24.0`. |
| Go modules | `gopkg.in/yaml.v3` v3.0.1 | `go.mod`. It has no known vulnerabilities in either database. |

The Tier 8 build configuration used for first-pass triage is `/opt/zephyr-workspace/build/tier-08-credential-lifecycle-baseline/tier-08-credential-lifecycle/zephyr/.config` in the container. It has `CONFIG_NET_IPV4`, `CONFIG_NET_TCP`, `CONFIG_NET_DHCPV4`, `CONFIG_SETTINGS_NVS`, `CONFIG_MBEDTLS_X509_CRT_PARSE_C` and TLS 1.2 only. It does not set `CONFIG_BT`, `CONFIG_USERSPACE`, `CONFIG_NET_IPV6`, `CONFIG_NET_STATISTICS`, `CONFIG_NET_IPV4_IGMP` or `CONFIG_NET_SHELL`. The SoC is RISC-V.

### SBOM format assumption

The sibling ticket #266 settles SBOM generation. This research assumed two shapes, and tested both.

- Firmware: a hand-written CycloneDX 1.6 JSON SBOM with one component per pinned C component, each with a CPE and a `pkg:github` purl, and a hand-written SPDX 2.3 tag-value file in the shape Zephyr's own `west spdx` writes. `west spdx` in Zephyr 4.4.2 supports SPDX 2.2 and 2.3 only (`scripts/west_commands/zspdx/version.py`). It gives Zephyr the CPE `cpe:2.3:o:zephyrproject:zephyr:<version>:-:*:*:*:*:*:*` (`zspdx/walker.py`) and takes other CPEs and purls from each module's `zephyr/module.yml` `security: external-references`. In this workspace only Mbed TLS and TF-PSA-Crypto declare them. MCUboot and hal_espressif declare nothing.
- OTA service: a CycloneDX 1.7 JSON SBOM made by syft 1.52.0 from a `services/ota/cmd/ota` binary built with go1.24.0.

## Tools and their pinned databases

| Tool and version | Database pinning | Snapshot size | Offline run |
| --- | --- | --- | --- |
| grype 0.119.0 | Download one archive named in `https://grype.anchore.io/databases/v6/latest.json`, check its sha256, then `grype db import`. The snapshot used here is `vulnerability-db_v6.1.9_2026-09-29T00:34:00Z_1790663551.tar.zst`, built 2026-09-29T06:32:31Z, sha256 `1e88821121dd3ec9bef68b4eb7c5524997f62da37215113ec256179d4e6da8cf`. | 182,413,359 bytes compressed. 3,128,655,872 bytes (about 3.1 GB) as the imported SQLite file. | Works with `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_CHECK_FOR_APP_UPDATE=false` and `GRYPE_DB_VALIDATE_AGE=false`. |
| govulncheck v1.8.0 | Download `https://vuln.go.dev/vulndb.zip`, check its sha256, unpack, pass `-db file:///path`. The snapshot used here has `index/db.json` modified 2026-09-28T16:43:40Z, sha256 `faa8c45538d259ae1fd3c34ae20632ee738d1190836c84ac95d5f2bc604d85bc`. | 3,351,093 bytes compressed, about 19 MB unpacked, 4,514 entries. | Works. The JSON output records `db_last_modified` and `go_version`, which is useful evidence. |
| osv-scanner 2.6.0 | `--download-offline-databases` fetches one zip per ecosystem into `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`. `--offline-vulnerabilities` then uses only that cache. The Go zip was 11,906,977 bytes, last modified 2026-09-29T21:32:56Z. The GIT ecosystem zip, which holds the C and C++ records, is 198,378,857 bytes. | 12 MB for Go. About 198 MB more for GIT. | Works for Go. The offline documentation says "Commit level scanning is not supported", so offline mode cannot match C components by commit. |

**The grype age check breaks a pinned database.** grype refuses a database older than `db.max-allowed-built-age`, which defaults to 120 hours, when `db.validate-age` is true, which is the default (grype configuration reference). This was reproduced by setting the limit to one hour: grype exited with status 1 and printed "the vulnerability database was built 16 hours ago (max allowed age is 1 hour)". With `GRYPE_DB_VALIDATE_AGE=false` the same run succeeded. The exercise must set that variable, or every Learner's scan fails five days after the snapshot was built.

**Where the snapshots live.** The govulncheck database is small enough to commit to the repository or bake into the dev container image. The grype archive is too large to commit and unpacks to 3.1 GB, so baking it into the image would roughly double a large pull. The practical choice is to publish the grype archive once as a course release asset or an OCI artifact on the GitHub Container Registry, record its sha256 in `course.yml`, and have setup fetch and import it once, after which scans need no network. This research did not confirm how long Anchore keeps old archives at their original URLs, so the course should not rely on re-downloading the snapshot from Anchore later.

**Tool versions matter as much as database dates.** The same database gives different matches with a different scanner version, because matching rules change. Pin the scanner binaries by version and checksum next to the database.

## How each tool matches embedded C components

### grype

grype matches C components only by CPE against NVD data. The configuration reference lists `match.stock.using-cpes: true` by default, and package types with no ecosystem fall to the stock matcher. A `pkg:github` purl alone produced zero matches for Zephyr and for Mbed TLS 4.0.0. Five results from controlled SBOM variants:

1. **Component type hides Zephyr.** With Zephyr as a CycloneDX `operating-system` component, grype returned 0 Zephyr matches. The same component as `library` or `firmware` returned 26. The same CPE in an SPDX 2.3 package with `PrimaryPackagePurpose: SOURCE`, which is what `west spdx` writes, also returned 26. The CPE part (`o`) and the update field (`-` or `*`) made no difference.
2. **CPE vendor splits Mbed TLS.** NVD files Mbed TLS records under `arm:mbed_tls`, `trustedfirmware:mbed_tls` and `mbed-tls:mbedtls`, and TF-PSA-Crypto under `arm:tf-psa-crypto` and `trustedfirmware:tf-psa-crypto` (all five exist in the grype database). For Mbed TLS 4.0.0, the `arm` CPE gave 1 match and the `trustedfirmware` CPE gave 6. grype did not merge the vendors. `west spdx` emits only the `arm` form from `module.yml`.
3. **MCUboot is invisible.** The grype database has no CPE product for MCUboot. MCUboot 2.4.0 and a deliberately old 1.0.0 both gave 0 matches. MCUboot's three GitHub advisories (CVE-2021-3399, CVE-2021-3890, CVE-2024-32883) are all fixed long before 2.4.0, so today this costs nothing, but a future MCUboot advisory would not be seen.
4. **The NVD backlog is invisible.** Several Zephyr advisories that name 4.4.2 are in the database only as NVD records with status `analyzing` and no CPE configuration, so no scanner that relies on NVD CPEs can match them. Examples: CVE-2026-12634, CVE-2026-12365, CVE-2026-12366, CVE-2026-12363, CVE-2026-12232. CVE-2026-18746, published by Zephyr on 2026-09-28, had no CPE either.
5. **NVD ranges ignore backports.** NVD records for many Zephyr CVEs say "affected before 4.5.0". Zephyr's own advisories say the fix was backported to 4.4.1 or 4.4.2. grype follows NVD, so it reports these as matches on 4.4.2.

### osv-scanner and the OSV database

OSV stores Zephyr and Mbed TLS records in the GIT ecosystem, as commit ranges on the upstream repository, and lists the tags it has resolved as affected (checked for CVE-2026-10639 and CVE-2026-12634). Four results:

1. The firmware CycloneDX SBOM produced 6 packages and 0 vulnerabilities, online. `pkg:github` purls are not an OSV ecosystem.
2. Querying the OSV API by commit returned 0 for all six pinned commits: Zephyr `dccb0959`, MCUboot `6d3b3d2c`, the Mbed TLS fork `a3e190fe`, upstream Mbed TLS 4.1.0 `0fe989b6`, TF-PSA-Crypto `dc575a2d` and hal_espressif `f0746505`.
3. Querying by tag works only for some tags. Zephyr `v4.3.0` gave 124, `v4.4.0` 98, `v4.4.1` 61, `v4.4.2` 0, `v3.7.1` 1. The CVE-2026-10639 record lists `v4.4.0-rc3` but not `v4.4.0`, `v4.4.1` or `v4.4.2`, although Zephyr says 4.4.2 is affected. Patch releases on release branches are not reliably resolved.
4. The repository name is case-sensitive. `https://github.com/Mbed-TLS/mbedtls` gave 0 for every tag. `https://github.com/mbed-tls/mbedtls`, the form used in OSV records, gave 5 for `v4.0.0` and 0 for `v4.1.0`.

osv-scanner has no VEX input. It suppresses findings through `[[IgnoredVulns]]` entries in `osv-scanner.toml`, with `id`, optional `ignoreUntil` and optional `reason` (osv-scanner configuration documentation).

### Zephyr-specific options

Zephyr offers no scanner and no machine-readable feed on its vulnerabilities page. It publishes GitHub security advisories on the `zephyrproject-rtos/zephyr` repository and CVE records, and documents backports per release branch on its vulnerabilities page. The GitHub advisories API (`gh api repos/zephyrproject-rtos/zephyr/security-advisories`) returned 249 advisories with machine-readable vulnerable ranges and patched versions, and that is the best available answer key. Espressif's `esp-idf-sbom` tool can check an ESP-IDF build against NVD or a local NVD mirror and honours `cve-exclude-list` entries in `sbom.yml`, but it targets ESP-IDF builds, not Zephyr builds. The one such entry in this workspace records that CVE-2023-52160 is patched in the `wpa_supplicant` fork, which is a ready-made example of a vendor triage record.

### govulncheck and Go matching

Go matching is precise in all three tools because the Go database carries package and symbol data. The one trap is the version string. syft writes the standard library as component version `go1.24.0` with purl `pkg:golang/stdlib@1.24.0`. osv-scanner reads the component version, and returned 149 matches, including 2021 and 2022 advisories fixed long before Go 1.24. Changing only the version field to `1.24.0` gave 53 matches, which agrees with grype and govulncheck. osv-scanner on `go.mod` directly reported only `gopkg.in/yaml.v3` and dropped the standard library, so it missed the toolchain entirely.

govulncheck needs the right toolchain to be right. On the dev host, whose Go is 1.26.8, it said "No vulnerabilities found". With `GOTOOLCHAIN=go1.24.0`, the toolchain the dev container actually uses, it reported the matches below. The scan must run inside the dev container, or pin the toolchain explicitly.

## The real match list

### OTA service and course helper (Go)

| Tool | Matches | Notes |
| --- | --- | --- |
| grype on the syft SBOM of the OTA binary | 53, all `stdlib` | 2 Critical, 25 High, 24 Medium, 2 Low |
| osv-scanner offline, syft SBOM as produced | 149 | 96 are false matches from the `go1.24.0` version string |
| osv-scanner offline, version field corrected | 53 | Same set as grype |
| govulncheck, source mode, offline database | 53 known, 32 reachable | "Your code is affected by 32 vulnerabilities from the Go standard library", 7 more in imported packages but not called, 14 more in required modules but not imported |

First-pass guess: **affected**, for most of the 32 reachable ones. They are reachable from `services/ota/cmd/ota.main`, `internal/courseapp.Run` and `internal/coursepki`. Examples: GO-2025-3563 (request smuggling through invalid chunked data in `net/http`, fixed in go1.24.2), GO-2026-4870 (TLS 1.3 KeyUpdate denial of service, fixed in go1.25.9), GO-2025-4175 and GO-2026-4947 in `crypto/x509.Verify`. The impact is limited because the service binds to the lab network, but the finding is real. Several fixes exist only in the Go 1.25 and 1.26 lines (for example GO-2026-6218, fixed in go1.25.13), which means Go 1.24 no longer receives fixes. GO-2026-4971 is Windows-only and is **not affected** on the Linux container.

This is a course infrastructure defect, not exercise material only. The fix is a `toolchain` line in `go.mod`, or a newer `go` directive and container Go, followed by a rescan. It is a clean example of an unsupported component, which section 7 names as a threat.

### Firmware: what grype reported

With Zephyr as a `library` component, grype reported 28 matches: 26 for Zephyr and 2 for `wpa_supplicant`. It reported none for MCUboot, Mbed TLS 4.1.0, TF-PSA-Crypto 1.1.0 or hal_espressif. The "Zephyr says" column comes from the Zephyr GitHub advisory for the same CVE.

| CVE | Area | NVD range used by grype | Zephyr says | First-pass guess and why |
| --- | --- | --- | --- | --- |
| CVE-2026-10634 | TCP connection list | < 4.5.0 | <= 4.4.0 | Not affected by version. Vendor range excludes 4.4.2. |
| CVE-2026-10636 | IPv4 IGMP | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and IGMP is not built. |
| CVE-2026-10637 | IPv6 MLD | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and IPv6 is not built. |
| CVE-2026-10638 | ICMPv6 | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and IPv6 is not built. |
| CVE-2026-10639 | ICMPv4 echo reply | < 4.5.0 | < 4.5.0 | Not affected. The version is in range, but the faulty statistics call compiles to nothing without `CONFIG_NET_STATISTICS_ICMP` (`subsys/net/ip/net_stats.h`), and Tier 8 does not set `CONFIG_NET_STATISTICS`. A good "in range, code not present" case. |
| CVE-2026-10640 | IPv6 neighbour discovery | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and IPv6 is not built. |
| CVE-2026-10642 | PL011 UART driver | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not this SoC's UART. |
| CVE-2026-10647 | USB CDC-NCM | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and USB device stack not used. |
| CVE-2026-10663 | USB host stack | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2026-10664 | nRF70 Wi-Fi driver | < 4.5.0 | >= 4.0.0, no fix listed | Not affected. The version may be in range, but the driver is for a different chip. |
| CVE-2026-10669 | Xtensa MPU | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and the SoC is RISC-V. |
| CVE-2026-10670 | `k_thread_name_copy` syscall | < 4.5.0 | < 4.5.0 | Not affected. In range, but it needs `CONFIG_USERSPACE`, which is not set. |
| CVE-2026-10671 | Kernel pipe syscall | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and userspace is not built. |
| CVE-2026-10673 | ADIN2111 Ethernet | < 4.5.0 | fixed 4.4.1 | Not affected. Fixed, and not this hardware. |
| CVE-2026-10681 | Userspace dynamic objects | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and userspace is not built. |
| CVE-2026-10682 | Log filter syscall | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and userspace is not built. |
| CVE-2026-10683 | DesignWare I2C target | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not used. |
| CVE-2026-10685 | Bluetooth GATT client | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and Bluetooth is not built. |
| CVE-2026-10686 | IPv6 forwarding | < 4.5.0 | <= 4.4.1 | Not affected. Vendor range excludes 4.4.2, and IPv6 is not built. |
| CVE-2026-10773 | DHCPv4 message name table | < 4.5.0 | fixed 4.4.2 | Not affected by version. DHCPv4 is built, so this is the one where a Learner who skips the vendor advisory could wrongly write "affected". A good misleading-match candidate. |
| CVE-2026-10774 | Bluetooth Mesh keys | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2026-10848 | OCPP client | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2026-10849 | hawkBit client | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. It is an update client, so it looks relevant to an OTA product at first glance. Another misleading-match candidate. |
| CVE-2026-11368 | Bluetooth ATT | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2026-2411 | Bluetooth GATT permissions | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2026-7007 | ext2 file system | < 4.5.0 | fixed 4.4.2 | Not affected. Fixed, and not built. |
| CVE-2023-52160 | wpa_supplicant PEAP | <= 2.10 | Espressif `sbom.yml` says patched | Not affected. Vendor patched it, and the device does not use PEAP. |
| CVE-2024-5290 | wpa_supplicant (Ubuntu packaging) | any version | Not applicable | Not affected. NVD describes it as an issue in Ubuntu's wpa_supplicant that loads arbitrary shared objects. The embedded fork has no shared objects to load. A pure CPE false match. |

Of the 26 Zephyr matches, 21 are fixed in 4.4.1 or 4.4.2 by Zephyr's own advisories, and 2 more have a vendor range that ends before 4.4.2. All 28 firmware matches are first-pass "not affected".

### Firmware: true matches that no scanner reported

These come from the vendor advisories, not from any scanner. They are the most useful part of the list for the exercise, because they show that a clean scan is not a clean product.

| Advisory | Component | Vendor range | First-pass guess and why |
| --- | --- | --- | --- |
| CVE-2026-50583, zero-length ECC public key out-of-bounds read, 7 July 2026 | TF-PSA-Crypto up to 1.1.0, Mbed TLS 4.0.0 to 4.1.0 | Fixed in TF-PSA-Crypto 1.1.1 and Mbed TLS 4.1.1 | **Likely affected.** The advisory says Mbed TLS 4.x is affected "through their TF-PSA-Crypto submodule by default". The device parses ECC public keys from the server certificate in every TLS handshake, before it knows the peer is trusted. Impact is a crash. Needs confirmation that the parse path reaches the flawed code. |
| CVE-2026-12634, settings NVS backend out-of-bounds stack write | Zephyr >= 2.0.0, <= 4.4.2 | Fixed on `main`, projected 4.5.0 | **Affected, low impact.** `CONFIG_SETTINGS_NVS=y` in Tier 8, so the code is present. It needs an attacker who can write the settings flash, which is the physical attacker the course already models. Impact is a crash at `settings_load()`. |
| CVE-2026-49300, X.509 CA bit forgery | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | **Not affected, by analysis.** The advisory says only applications that "accept certificates directly from untrusted users" are affected. The device accepts only chains from the course CA, and the course CA builds extensions itself: `internal/courseapp/tier06.go` reads only the credential from a CSR and copies no CSR extension into the issued certificate. |
| CVE-2026-50586, TLS 1.2 NewSessionTicket leak | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | Not affected. Server side only. The device is a TLS client. |
| CVE-2026-50579, PKCS7 use-after-free | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | Not affected. Needs `MBEDTLS_PKCS7_C`. Tier 8's `.config` sets no PKCS7 option and the firmware parses no PKCS7 data. Confirm in the generated Mbed TLS configuration. |
| CVE-2026-50588, EC J-PAKE out-of-bounds read | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | Not affected. EC J-PAKE is not enabled. |
| CVE-2026-50580, ECDHE-PSK client overflow | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | Not affected. Only ECDHE-ECDSA is enabled, and no PSK identity is set. |
| CVE-2026-25832, TLS 1.3 HelloRetryRequest group | Mbed TLS up to 4.1.1 | Fixed in 4.1.2 | Not affected. TLS 1.3 is not enabled. |
| CVE-2026-73096, TLS 1.3 early data | Mbed TLS 4.0.0 to 4.1.0 | Fixed in 4.1.1 | Not affected. TLS 1.3 and server early data are not enabled. |

The grype database knows these Mbed TLS CVEs only through non-NVD records with no CPE, and CVE-2026-73096 is not in it at all. OSV returned nothing for Mbed TLS 4.1.0.

Zephyr advisories that name 4.4.2 in their range and that grype missed, beyond CVE-2026-12634, include CVE-2026-12365 (work-queue cancellation under SMP), CVE-2026-12366 (userspace k_timer), CVE-2026-12363 (LoRaWAN), CVE-2026-12232 (Intel ALH DAI), CVE-2026-18746 (LwM2M), CVE-2026-10678 (MCTP I2C), CVE-2026-10666 (`parse_ipv4` in the networking utilities) and CVE-2026-8023 (a path traversal with no fix listed). Most are not built into Tier 8. CVE-2026-10666 and CVE-2026-8023 need a closer look at which Zephyr code they touch before they are ruled out. This list is from a script that checks each advisory's range string against 4.4.2. Some older advisories have badly written ranges (for example ">=2.4.0" with a patched version of 2.5.0), so the script's raw output needs a human read.

## VEX: recording triage so a rerun suppresses it

| Format | Consumed by | Produced by |
| --- | --- | --- |
| OpenVEX | grype (`--vex` or `vex-documents`) | govulncheck `-format openvex` |
| CSAF VEX | grype (documented) | none of the tools tested |
| CycloneDX VEX | none of the tools tested as input. grype lists `embedded-cyclonedx-vex-json` only as a deprecated output format. | grype (deprecated) |
| `osv-scanner.toml` `[[IgnoredVulns]]` | osv-scanner | written by hand |

grype's VEX guide says it supports OpenVEX and CSAF VEX as input, moves `not_affected` and `fixed` statements to the ignored list by default, and adds `affected` and `under_investigation` only when `vex-add` asks for them. It matches a VEX product to a package by purl, or by container image.

This was tested. An OpenVEX document with two `not_affected` statements and one `under_investigation` statement, against the CycloneDX firmware SBOM, moved exactly the two `not_affected` matches to `ignoredMatches` with rule `{"namespace": "vex", "vex-status": "not_affected"}`, and left the `under_investigation` one in the results. Against the SPDX file in `west spdx` shape, where Zephyr has a CPE but no purl, the same VEX suppressed nothing, whether the product was named by purl or by CPE.

So VEX works for this course only if every SBOM component that can be triaged carries a purl, and the VEX product identifier is exactly that purl. A tool-agnostic alternative for a CPE-only package is grype's own ignore rules in its configuration file, but that was not tested here.

## What later tickets inherit

- **#266, SBOM generation.** Do not give Zephyr the CycloneDX type `operating-system`, or grype will skip it. Give every C component a CPE, because grype matches C only by CPE. Give Zephyr a purl, because VEX binds only by purl, and `west spdx` does not write one for Zephyr. Consider adding the `trustedfirmware` CPE for Mbed TLS and TF-PSA-Crypto beside the `arm` one. Add MCUboot, hal_espressif and the `wpa_supplicant` fork by hand, because `west spdx` gets no identifiers for them. Name the precompiled Espressif Wi-Fi libraries as a known gap. For the Go SBOM, check the standard library version string before osv-scanner reads it.
- **#272, triage exercise.** The pinned set is grype 0.119.0 with database `v6.1.9` built 2026-09-29T06:32:31Z, govulncheck v1.8.0 with Go database modified 2026-09-28T16:43:40Z, and a dated export of the Zephyr advisories API and the Mbed TLS advisory pages. The answer key has three kinds of rows: scanner matches that are false (most of the 26 Zephyr rows, and the Ubuntu `wpa_supplicant` row), scanner matches that are true but not exploitable in this image (CVE-2026-10639, CVE-2026-10670), and true matches that no scanner raised (CVE-2026-50583, CVE-2026-12634). Good candidates for the Mentor's "misleading vulnerability scan match" are CVE-2026-10849 (hawkBit, looks like an update-path flaw), CVE-2026-10773 (DHCPv4, the code is built but the version is fixed) and the 149 versus 53 osv-scanner result for Go.
- **Settled input 2 needs a note.** "Most will be not affected" holds for the firmware scanner rows. It does not hold for the Go rows, and it hides the true firmware matches that scanners miss.
- **A course fix may be needed outside the exercise.** The OTA service's Go toolchain is unsupported, with 32 reachable standard-library vulnerabilities. The dev should decide whether to pin a supported toolchain now, as course housekeeping, or to keep go1.24.0 on purpose as a Tier 9 "unsupported component" finding that the Learner triages. The second choice must be written down, or it looks like an unnoticed defect. If the Mbed TLS or Zephyr pins move, the firmware match list above changes and must be rerun.
- **Setup.** The grype snapshot is about 182 MB to fetch and 3.1 GB on disk. The setup step must set `GRYPE_DB_VALIDATE_AGE=false`, `GRYPE_DB_AUTO_UPDATE=false` and `GRYPE_CHECK_FOR_APP_UPDATE=false`, and must verify the archive's sha256.

## Sources

All accessed 30 September 2026.

- grype configuration reference, `https://oss.anchore.com/docs/reference/grype/configuration/`, for `db.auto-update`, `db.validate-age`, `db.max-allowed-built-age` (120h), `check-for-app-update`, `match.*.using-cpes` defaults, `vex-documents` and `vex-add`.
- grype VEX guide, `https://oss.anchore.com/docs/guides/vulnerability/filter-results/`, for OpenVEX and CSAF VEX input, default suppression statuses and purl product matching.
- grype database listing, `https://grype.anchore.io/databases/v6/latest.json`, for the snapshot name, build time and checksum.
- osv-scanner offline mode, `https://google.github.io/osv-scanner/usage/offline-mode/`, for the offline flags, `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` and "Commit level scanning is not supported".
- osv-scanner configuration, `https://google.github.io/osv-scanner/configuration/`, for `[[IgnoredVulns]]`.
- OSV query API, `https://google.github.io/osv.dev/post-v1-query/`, for commit and GIT tag queries. OSV records fetched from `https://api.osv.dev/v1/vulns/<id>`.
- OSV ecosystem downloads, `https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip` and `.../GIT/all.zip`, for sizes and dates.
- govulncheck documentation, `https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck`, for `-db`, `-mode binary`, `-format openvex` and the rule that source mode uses the `go` command on the PATH. Go vulnerability database, `https://vuln.go.dev/vulndb.zip` and `https://vuln.go.dev/index/db.json`.
- Zephyr vulnerabilities page, `https://docs.zephyrproject.org/latest/security/vulnerabilities.html`, and Zephyr GitHub security advisories through `gh api repos/zephyrproject-rtos/zephyr/security-advisories`, including GHSA-q7c8-m2qg-385c for CVE-2026-12634.
- MCUboot GitHub security advisories through `gh api repos/mcu-tools/mcuboot/security-advisories`.
- Mbed TLS security advisories index, `https://mbed-tls.readthedocs.io/en/latest/security-advisories/`, and the eight July 2026 advisory pages linked from it.
- Zephyr's `west.yml`, `scripts/west_commands/zspdx/`, module `zephyr/module.yml` files, `subsys/net/ip/net_stats.h` and the Tier 8 `.config`, read in the `tier2-validate` container. Zephyr's Mbed TLS and TF-PSA-Crypto fork histories through `gh api repos/zephyrproject-rtos/mbedtls/commits` and `.../tf-psa-crypto/commits`.
- esp-idf-sbom, `https://github.com/espressif/esp-idf-sbom`, and `hal_espressif/components/wpa_supplicant/sbom.yml` in the workspace.
