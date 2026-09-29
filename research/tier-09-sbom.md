# Generating SBOMs for the firmware and the OTA service

**Research question:** [GitHub issue #266](https://github.com/tkEmLogic/learning-cyber-security/issues/266), part of map [#265](https://github.com/tkEmLogic/learning-cyber-security/issues/265)

**Access and review date:** 30 September 2026

**Status:** Research. This report establishes facts. It designs nothing and it decides nothing. Where it names an option, the choice is for the tickets that build.

**How to read the evidence marks.** **Source** means the claim was read out of a pinned source file or an official document, and the file or document is named. **Observed** means something was run and its result is reported. **Not established** means the question was asked and no answer was found. Everything marked Observed was run on 30 September 2026, either inside the long-lived `tier2-validate` container (Zephyr 4.4.2 at `/opt/zephyr-workspace`, West 1.5.0) in throwaway build directories under `/tmp`, or on the host in a scratch directory. Nothing touched the board. Nothing in the repository or the Zephyr workspace was changed.

## Short answer

`west spdx` works for this build, but not by following the Zephyr page, and not with the workspace as the course sets it up. Three things have to be true first: the CMake file API query must exist in each image's own build directory (not the sysbuild top directory), `CONFIG_BUILD_OUTPUT_META=y` must be set for each image, and every active West project must be cloned. The course fetches only four projects (`hal_espressif`, `mcuboot`, `mbedtls`, `tf-psa-crypto`), so the meta step crashes on the first missing one. A West project filter fixes it, and it can be applied without touching the workspace through `WEST_CONFIG_LOCAL`.

What it writes is four SPDX 2.3 tag-value documents per image. Only three components carry identifiers a scanner can match: Zephyr 4.4.2, Mbed TLS 4.1.0 and TF-PSA-Crypto 1.1.0. MCUboot appears only as a commit hash, the Espressif HAL only as a commit hash, and the precompiled Espressif Wi-Fi libraries that are linked into the application do not appear at all. The shipping bootloader verifies signatures with TinyCrypt, which is vendored inside MCUboot and has no identity of its own in the output, while the same output lists Mbed TLS 4.1.0 as a bootloader dependency although no Mbed TLS file is compiled into it.

The OTA service has no third-party Go module at all. Its only dependency is the Go standard library, and the version of that library is whatever toolchain happened to build it. In the dev container that is Go 1.24.0, which the Go vulnerability database says is affected by 30 standard-library vulnerabilities reachable from the service's code. The course helper adds one module, `gopkg.in/yaml.v3` v3.0.1. `go version -m` gives this inventory for free. `cyclonedx-gomod` and `syft` turn it into CycloneDX or SPDX JSON.

On format, BSI TR-03183-2 version 2.1.0 accepts only CycloneDX 1.6 or later and SPDX 3.0.1 or later, as JSON or XML. Zephyr writes SPDX 2.3 tag-value, which meets neither. The Go tools write CycloneDX 1.6 natively. The CRA itself names no format: it asks for "a commonly used and machine-readable format covering at the very least the top-level dependencies", and the implementing act that would fix a format under Article 13(24) has not been adopted.

## 1. `west spdx` on this build

### What the tool says it needs

The Zephyr 4.4 page lists four steps: `west spdx --init -d BUILD_DIR`, enable `CONFIG_BUILD_OUTPUT_META`, `west build -d BUILD_DIR`, then `west spdx -d BUILD_DIR`. For sysbuild it says only to "target the actual application which you want to generate the SBOM for", that is `BUILD_DIR/<app>`. **Source:** [Zephyr 4.4.0 documentation, "Software bill of materials: west spdx"](https://docs.zephyrproject.org/4.4.0/develop/west/zephyr-cmds.html).

The command in the pinned tree offers SPDX 2.2 or 2.3, defaulting to 2.3, and writes tag-value only. Its options are `--init`, `--build-dir`, `--namespace-prefix`, `--spdx-dir`, `--spdx-version {2.2,2.3}`, `--analyze-includes` and `--include-sdk`. **Observed:** `west spdx --help` in the container.

`--init` does one thing: it creates an empty file at `BUILD_DIR/.cmake/api/v1/query/codemodel-v2`. **Source:** `zephyr/scripts/west_commands/spdx.py`, `do_run_init()`.

Without `CONFIG_BUILD_OUTPUT_META`, Zephyr deletes the meta file "to prevent spdx to use invalid data", and `west spdx` refuses. **Source:** `zephyr/CMakeLists.txt:1931-1948`. **Observed:** `ERROR: CONFIG_BUILD_OUTPUT_META must be enabled to generate spdx files; bailing`.

### What happened when the documented steps were followed

**Attempt A: `--init` on the sysbuild directory.** The query file was created at the top of the build directory and survived `west build --sysbuild --pristine=always` (the course's own build flag, from `scripts/build-zephyr-baseline.sh`). The build succeeded. But the CMake file API reply was written only for the sysbuild project. The image directory `tier-08-credential-lifecycle/` had no `.cmake` directory, and `west spdx -d BUILD_DIR/tier-08-credential-lifecycle` failed with `cmake api reply directory ... does not exist`. **Observed.** So in a sysbuild build, `--init` must name each image directory, not the top one. The Zephyr page does not say this.

**Attempt B: `--init` on each image directory, META on, pristine build.** Initialising `BUILD_DIR/tier-08-credential-lifecycle` and `BUILD_DIR/mcuboot` before the build worked, and the query survived the pristine build. `CONFIG_BUILD_OUTPUT_META=y` was passed per image as `-Dtier-08-credential-lifecycle_CONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y` and reached both `.config` files. The build then failed in the post-build meta step: `FileNotFoundError: [Errno 2] No such file or directory: '/opt/zephyr-workspace/modules/lib/acpica'`. **Observed.**

The cause is in `scripts/zephyr_module.py`. The meta writer walks every West project that the manifest marks active and runs `git rev-parse` in each one. It does not check whether the project is cloned. **Source:** `zephyr/scripts/zephyr_module.py:709-742` (`west_projects()` keeps projects where `manifest.is_active(p)`) and `:600-660` (`process_meta()` calls `_create_meta_project()` on each).

The course's workspace clones four of the 67 projects the manifest lists besides Zephyr itself. `docs/esp32c6-build-baseline.md:54` runs `west update hal_espressif mcuboot mbedtls` and `.devcontainer/post-create.sh:34` adds `tf-psa-crypto`. **Source.** `west list` shows every other project as `not-cloned` and none of them inactive. **Observed.** So `CONFIG_BUILD_OUTPUT_META` cannot build in the course's workspace as it stands.

**Attempt C: the same, with a project filter.** West reads its local configuration from the file named by `WEST_CONFIG_LOCAL` when that variable is set. **Source:** `west/configuration.py:617-618` in the container's venv. A copy of `.west/config` in `/tmp` with one extra line, `project-filter = -.*,+hal_espressif,+mcuboot,+mbedtls,+tf-psa-crypto`, made only the four cloned projects active. With that variable exported, the build completed, both `zephyr.meta` files were written, and `west spdx` wrote four documents for each image. **Observed.** The real `.west/config` was not touched. Writing the same filter into the workspace with `west config manifest.project-filter` would do the same job permanently; that is a decision for the build ticket.

The documents parse: `pyspdxtools -i` (spdx-tools 0.8.5, already in the Zephyr venv) exited 0 on `zephyr.spdx` and `modules-deps.spdx`, and converted `modules-deps.spdx` to SPDX JSON. **Observed.**

The same method works for the separately built shipping bootloader: `--init` on its build directory and `-DCONFIG_BUILD_OUTPUT_META=y` on its command line. It was built for this test with MCUboot's bundled sample key, because the public release key is not needed to see what the SBOM contains. **Observed.**

### What the output contains

Four files per image, all SPDX 2.3 tag-value. For the Tier 8 application: `app.spdx` (4 KB, 11 files), `zephyr.spdx` (217 KB, 539 files), `build.spdx` (189 KB, 128 files) and `modules-deps.spdx` (3 KB). **Observed.** Each file entry has SHA1 and SHA256 checksums, and licences come from `SPDX-License-Identifier` lines. **Source:** Zephyr 4.4.0 page above. **Observed:** `FileChecksum: SHA1:` and `FileChecksum: SHA256:` lines.

Identifiers per component, as written for the Tier 8 application:

| Component | Version written | CPE | PURL | Where |
| --- | --- | --- | --- | --- |
| Zephyr | 4.4.2 | `cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*` | `pkg:github/zephyrproject-rtos/zephyr@v4.4.2` | `zephyr.spdx`, `modules-deps.spdx` |
| Mbed TLS | 4.1.0 (deps), commit `a3e190fe` (sources) | `cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*` | `pkg:github/Mbed-TLS/mbedtls@v4.1.0` | `modules-deps.spdx` only |
| TF-PSA-Crypto | 1.1.0 (deps), commit `dc575a2d` (sources) | `cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*` | `pkg:github/Mbed-TLS/TF-PSA-Crypto@v1.1.0` | `modules-deps.spdx` only |
| MCUboot | commit `6d3b3d2c` only | none | none | `zephyr.spdx` |
| Espressif HAL | commit `f0746505` only | none | none | `zephyr.spdx` |
| Espressif Wi-Fi libraries | absent | absent | absent | nowhere |
| Course application and `firmware/common` | none, or the course commit with `-dirty` | none | none | `app.spdx`, `zephyr.spdx` |

**Observed** in the four documents. The supplier is written as `Organization: zephyrproject` for Zephyr and `Organization: arm` for the two Arm modules, and is absent for the rest. **Observed.**

Where the identifiers come from explains the gaps. Zephyr's CPE and PURL are built from its Git tag. A module's CPE and PURL come only from a `security: external-references:` list in its `zephyr/module.yml`. **Source:** `zephyr/scripts/west_commands/zspdx/walker.py:276-340` and `:420-450`. Of the four cloned projects, only `mbedtls` and `tf-psa-crypto` have such a list. **Observed:** a search of every `zephyr/module.yml` under `modules/` and `bootloader/`.

MCUboot's version is known to the build and thrown away. `zephyr.meta` records MCUboot with `tags: [v2.4.0]`, but the walker uses tags only for Zephyr itself, so MCUboot is written with its commit as the version. **Observed:** `tier-08-credential-lifecycle/zephyr/zephyr.meta` against `zephyr.spdx`.

Mbed TLS and TF-PSA-Crypto are named by the upstream project in their PURL (`Mbed-TLS/...`) but downloaded from Zephyr's forks (`zephyrproject-rtos/mbedtls@a3e190fe...`). **Observed.** Whether the forks carry patches that change which upstream advisories apply is **Not established**; it is a triage question for #272.

### The Espressif Wi-Fi libraries are linked and not listed

The application links `-lnet80211`, `-lpp`, `-lphy` and `-lcore` from `modules/hal/espressif/zephyr/blobs/lib/esp32c6/`. **Observed:** `build.ninja` of the Tier 8 image. No SPDX document names any of them. **Observed:** zero matches for `blobs/lib` in all four files.

The information exists. `hal_espressif`'s `zephyr/module.yml` lists each blob with a SHA-256, a URL pinned to commit `b9bc45aa8e98d53f8999f220a92286d9a57d4c1b` of `espressif/esp32-wifi-lib`, and `version: '1.0'`. **Source:** `modules/hal/espressif/zephyr/module.yml:194-209`. The version field is the same placeholder for every blob, so the commit in the URL is the only real version.

These are closed-source binaries holding the 802.11 stack. For vulnerability handling they are the component a Learner can least inspect, and they are the one `west spdx` leaves out.

### The bootloader's SBOM describes the wrong crypto

The shipping bootloader is built with `CONFIG_BOOT_ECDSA_TINYCRYPT=y` and `CONFIG_BOOT_USE_TINYCRYPT=y`. **Observed:** `zephyr/.config` of the standalone bootloader build, from `firmware/tier-08-credential-lifecycle/bootloader/mcuboot.conf`. The files it compiles include `ext/tinycrypt/lib/source/ecc.c`, `ecc_dsa.c` and `sha256.c`, and a vendored `ext/mbedtls-asn1/` subset. **Observed:** `zephyr.spdx` of that build.

In the same build, `mbedtls-sources` and `tf-psa-crypto-sources` are written with `FilesAnalyzed: false` (nothing compiled), yet `modules-deps.spdx` lists `mbed_tls` 4.1.0 and `tf-psa-crypto` 1.1.0, each with a CPE, as dependencies. **Observed.** `modules-deps.spdx` lists every module the build could see, not the ones it used.

This has two consequences. A scanner fed `modules-deps.spdx` will report Mbed TLS advisories against a bootloader that contains no Mbed TLS. And TinyCrypt, the library that actually checks every image signature, appears only as files inside `mcuboot-sources`, with no name, version or identifier a scanner could match.

### Which binary the SBOM hashes

`build.spdx` hashes `./zephyr/zephyr.elf`. It does not list `zephyr.bin` or `zephyr.signed.bin`. **Observed:** zero `FileName: ./zephyr/zephyr.bin` entries in the application's and the bootloader's `build.spdx`, while both files exist in the build directory. The image that is signed, published and flashed is therefore not hashed by any SBOM. Linking the SBOM to the release has to happen in the build manifest (section 5).

### Stability of the output

Each run writes a new random document namespace (`http://spdx.org/spdxdocs/zephyr-<uuid4>`) and the current time. **Source:** `spdx.py`, `do_run_spdx()`. `--namespace-prefix` sets the namespace. The course repository appears in the output as `ccd1d654...-dirty`, because the repository mounted in the container has uncommitted changes, and `zephyr.meta` records `workspace: dirty: true, extra: true`. **Observed.** An SBOM made from a dirty tree names a revision nobody can check out.

### Can scanners match these identifiers?

A short check of the NVD CPE dictionary, not a scan. **Observed** through the NVD CPE API 2.0 on 30 September 2026:

- `cpe:2.3:a:arm:mbed_tls:4.1.0` is in the dictionary.
- `cpe:2.3:o:zephyrproject:zephyr` has 185 dictionary entries, but 4.4.2 itself is not one. CVE match criteria use version ranges, so a missing dictionary entry does not by itself stop a match.
- `cpe:2.3:a:arm:tf-psa-crypto` has no dictionary entry.
- No MCUboot CPE was found under `mcuboot:mcuboot`, `mcu-tools:mcuboot` or a keyword search.
- `cpe:2.3:a:espressif:esp-idf` has 173 entries. The Espressif HAL is derived from ESP-IDF, but nothing in the SBOM says which ESP-IDF version, so ESP-IDF advisories cannot be matched.

What each scanner does with `pkg:github` PURLs and with these CPEs is #267's question.

## 2. The Go side

### What the programs actually depend on

`go.mod` declares `go 1.24` and one requirement, `gopkg.in/yaml.v3 v3.0.1`. **Source.**

The container has Go 1.23.4 installed (`.devcontainer/Dockerfile:62`) and `GOTOOLCHAIN=auto`. Because `go.mod` asks for 1.24, the `go` command fetched and used `go1.24.0`, which is now in the module cache as `golang.org/toolchain@v0.0.1-go1.24.0.linux-amd64`. **Observed.** The host builds with its own Go, 1.26.8. **Observed.** So the standard library inside the OTA service depends on the machine that built it, and nothing in the repository pins it. A `toolchain` line in `go.mod` would pin it; that is a choice for the build ticket.

`go version -m` on binaries built in the container:

- `services/ota/cmd/ota`: built with `go1.24.0`, `mod github.com/tkEmLogic/learning-cyber-security v0.0.0-20260929224417-ccd1d65422e4+dirty`, **no `dep` lines**, and `vcs.revision=ccd1d654...`, `vcs.modified=true`, `CGO_ENABLED=1`, `GOOS=linux`, `GOARCH=amd64`.
- `tools/course`: the same, plus `dep gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=`.

**Observed.** The OTA service's whole third-party inventory is the Go standard library.

`go list -m all` also names `gopkg.in/check.v1`, a test dependency of `yaml.v3` that is in no binary. **Observed.** A tool that reads `go.mod` or `go.sum` rather than a binary lists it.

### What each tool writes

| Tool and mode | Input | Format written | Standard library | Main module version | Hashes |
| --- | --- | --- | --- | --- | --- |
| `go version -m` | built binary | plain text | as the Go version | pseudo-version with `+dirty` | `h1:` module hash per dependency |
| `cyclonedx-gomod app -std` v1.12.0 | source and `go list` | CycloneDX 1.6 JSON (1.0 to 1.7 selectable) | `pkg:golang/std@go1.24.0` | pseudo-version, no `+dirty` | SHA-256 per module, none for the main module or std |
| `cyclonedx-gomod mod` | `go.mod` | CycloneDX 1.6 JSON | not listed | pseudo-version | SHA-256 per module |
| `cyclonedx-gomod bin` | built binary | CycloneDX 1.6 JSON | not listed without `-std` | `+dirty` kept | none |
| `syft scan file:` v1.52.0 | built binary | SPDX 2.3 JSON, SPDX tag-value, CycloneDX JSON (1.7 by default) | `pkg:golang/stdlib@1.24.0` and `cpe:2.3:a:golang:go:1.24.0` | `+dirty` kept | SHA-1 and SHA-256 of the binary |
| `syft scan file:go.mod` | `go.mod` | same | not listed | `UNKNOWN` | none |

**Observed**, on the container-built binaries and the repository, except `syft`, which was run on the host against copies of those binaries. The `cyclonedx-gomod` module hash is the `go.sum` `h1:` directory hash decoded to hexadecimal, not a hash of any file that is shipped. **Observed:** `7f1566fc...` is the base64 `fxVm/Gz...` value. `syft` built with `go install` reports itself as `Tool: syft-[not provided]`, because its version is set by release linker flags. **Observed.** A pinned release binary would record its version.

The two tools name the standard library differently, `pkg:golang/std@go1.24.0` against `pkg:golang/stdlib@1.24.0`. **Observed.** Which spelling each scanner matches is for #267.

`cyclonedx-gomod app` and `mod` failed in this agent's Git worktree with `git: reference not found`, and worked in the ordinary clone mounted in the container. **Observed.** A Learner working in a Git worktree would hit the same error.

### Offline use

None of `cyclonedx-gomod`, `syft`, `grype`, `osv-scanner`, `trivy` or `govulncheck` is installed in the container. **Observed.** The container reached `proxy.golang.org` (HTTP 200), so `go install` works there. **Observed.** `go version -m` needs nothing but the Go toolchain. `cyclonedx-gomod` needs the module cache, which `post-create.sh` fills with `go mod download`. `syft` on a binary reads only the binary; its update check was turned off with `SYFT_CHECK_FOR_APP_UPDATE=false`. Whether any of them tries the network when the network is cut was **Not established**; no run was made with networking disabled.

`osv-scanner` v2.6.0, the current release, needs Go 1.27 to build from source, so `go install` fails with the host's 1.26.8 and the container's 1.24.0. **Observed.** A prebuilt release binary avoids that.

### A first look at the real matches

`govulncheck` v1.8.0 in binary mode on the container-built OTA service, against the live Go vulnerability database on 30 September 2026, reported: "Your code is affected by 30 vulnerabilities from the Go standard library", plus 7 in imported packages and 15 in required modules that the code "doesn't appear to call". One example is `GO-2025-3503` in `net/http`, found in go1.24 and fixed in go1.24.1, with `http.ProxyFromEnvironment` as the reachable symbol. **Observed.** This is not the pinned, dated scan that #267 will define. It is recorded here because it changes what the service side of the exercise looks like.

## 3. Which format

### What each authority asks for

**The CRA.** Annex I, Part II, point (1): manufacturers shall "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products". **Source:** [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847), accessed 30 September 2026. It names no format.

Article 13(24): "The Commission may, by means of implementing acts taking into account European or international standards and best practices, specify the format and elements of the software bill of materials referred to in Part II, point (1), of Annex I." **Source:** same text. No such implementing act has been adopted as of the access date, according to secondary reports; the Commission's own register was not checked. **Not established** from a primary source.

Other SBOM points in the same text: Article 3(39) defines an SBOM as "a formal record containing details and supply chain relationships of components included in the software elements of a product with digital elements"; Annex VII point 2(b) puts the SBOM in the technical documentation; Annex VII point 8 makes it available to a market surveillance authority on reasoned request; Annex II point 9 says user information states where the SBOM can be accessed "if the manufacturer decides to make available the software bill of materials to the user"; and recital 77 says manufacturers "should not be obliged to make the SBOM public". **Source:** same text.

**BSI TR-03183-2, version 2.1.0, 20 August 2025.** **Source:** [BSI-TR-03183-2 v2.1.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf), accessed 30 September 2026.

- Format (section 4): JSON or XML, valid against CycloneDX 1.6 or higher or SPDX 3.0.1 or higher, officially released versions only. Version 2.1.0 raised these from CycloneDX 1.5 and SPDX 2.2.1 (document history, table 1).
- Depth (section 5.1): "recursive dependency resolution MUST be performed at least for each component included in the scope of delivery", down to and including the first component outside it. That is stricter than the CRA's "top-level dependencies".
- Build information (section 5.1): the SBOM "MUST contain the same information as available during the build process".
- Required for the SBOM (table 2): creator (an email address, or a URL if none) and timestamp.
- Required for each component (table 3): creator, name, version, filename, dependencies with completeness "clearly indicated", distribution licences, a SHA-512 hash of the deployable component, and the executable, archive and structured properties.
- Required where they exist (tables 4 and 5): the SBOM's URI, and per component the source code URI, the URI of the deployable form, other identifiers "such as Common Platform Enumeration (CPE) or Package URL (purl)", and the original licences.
- Licences (section 6.1): SPDX identifiers or expressions; licence text is not a substitute.
- One SBOM per software version (section 3.1).
- No vulnerability information inside an SBOM (sections 3.1 and 8.1.14). A document that contains both "does not conform". CSAF, with VEX as a profile, is the recommended format for vulnerability information.
- The version rule (section 7): only the most recent version, or the one before it for six months after a new one.

**The NTIA minimum elements**, which section 19 of the specification lists as the Tier 9 reading, were not re-read for this report. **Not established** here.

### Where the course's output falls short

| Requirement | Zephyr `west spdx` | Go tools |
| --- | --- | --- |
| Format (TR 2.1.0) | SPDX 2.3 tag-value: fails both the version and the serialisation rule | `cyclonedx-gomod` CycloneDX 1.6 JSON passes; `syft` CycloneDX 1.7 passes; `syft` SPDX 2.3 JSON fails |
| Creator email or URL | `Tool: Zephyr SPDX builder` only | tool only |
| Component creator | missing for all but Zephyr and the two Arm modules | missing |
| Component version | commit hashes for MCUboot and the HAL; placeholder `1.0` for blobs, not even written | present |
| SHA-512 of deployable component | none; SHA-1 and SHA-256 of source files and `zephyr.elf` only | none; `syft` gives SHA-256 of the binary |
| Recursive dependencies, completeness stated | modules listed as "could see", not "used"; the Wi-Fi blobs and TinyCrypt missing | complete for Go, since Go records linked modules |
| Licences | detected from file headers; `NOASSERTION` at package level | not requested in these runs |
| CPE or PURL where they exist | three components only | present |
| Top-level dependencies (CRA) | met for Zephyr, Mbed TLS and TF-PSA-Crypto; not for MCUboot, the HAL or the Wi-Fi libraries | met |

**Source** for the requirements; **Observed** for the tool columns.

The honest reading is that raw tool output meets the CRA's floor for the Go service, and does not meet it for the firmware until MCUboot, the Espressif HAL, the Wi-Fi libraries and TinyCrypt are named with a version. Neither side meets TR-03183-2 without course-written additions, chiefly SHA-512 hashes of what is shipped and a named creator. None of this is a conformity statement.

### Mixing formats

Mixing SPDX for the firmware and CycloneDX for the service is not a technical problem for scanning, because common scanners read both. It is a problem for the evidence chain. A vulnerability record or VEX statement has to point at a component in an SBOM, and CycloneDX VEX and CSAF VEX refer to components differently from SPDX. With two formats, the Learner writes two kinds of reference for one process.

The facts point one way without deciding it. TR-03183-2 2.1.0 accepts CycloneDX 1.6. The Go tools write CycloneDX 1.6. Zephyr writes neither format TR accepts, so the firmware needs a course-owned step in any case. The firmware facts that step would need are all in files the build already writes: `zephyr.meta` (every project, commit and tag), `modules/hal/espressif/zephyr/module.yml` (blob hashes and pinned URLs), the `west spdx` documents (which module sources were compiled, with file hashes), and the output images. Keeping the raw `west spdx` documents as build evidence next to whatever the course derives from them loses nothing.

## 4. What a build manifest needs to hold

Section 10 of the specification says every release links to "its exact source revision, build manifest, SBOM, release manifest, signature evidence, test results, and approval record". The Release manifest already carries the image SHA-256, size, security counter and support information (section 7). **Source:** `docs/course-specification.md:437` and `:254`. The build manifest is the record that ties the rest together. From what this research found to be missing or unstable:

- **Course source revision:** the full commit, and a clean-tree flag. Both `zephyr.meta` and Go build info mark the tree dirty today, so the manifest has to either refuse a dirty tree or record it as a finding.
- **Firmware inputs:** the tier's application path, the board target `esp32c6_devkitc/esp32c6/hpcore`, the Zephyr and West manifest revisions, and the commit and tag of every West project. `zephyr.meta` already holds these.
- **Configuration:** a hash of each Kconfig fragment, including the generated one. The generated fragment holds the course Wi-Fi network (`scripts/build-zephyr-baseline.sh`, the `COURSE_FIRMWARE_CONF` comment), so the manifest records its hash and never its content.
- **The two builds:** the sysbuild application build and the separate bootloader build, each with its own inputs, because the bootloader that ships is not the one sysbuild makes (`sysbuild.conf`).
- **Keys:** the fingerprint of the public signing key the bootloader was built against, never a private-key path.
- **Toolchain:** Zephyr SDK 1.0.1 and the compiler path from `CMakeCache.txt`; for Go, the exact Go version, `GOOS`, `GOARCH` and `CGO_ENABLED` from `go version -m`.
- **Tools that made the evidence:** West 1.5.0, the Zephyr tree `west spdx` came from, and the versions of `cyclonedx-gomod`, `syft` or whatever is chosen.
- **Environment:** the dev container image identity.
- **Outputs:** SHA-256 and SHA-512 of `zephyr.elf`, `zephyr.bin`, the signed image, the bootloader binary, and the OTA service and helper binaries. SHA-256 matches the Release manifest's digest. SHA-512 is what TR-03183-2 asks for. No SBOM tool hashes the signed image, so this is the only place that ties an SBOM to what is flashed.
- **SBOM files:** their paths and hashes, so the release links to one fixed SBOM.

Reproducible builds are not claimed. Nothing here was rebuilt twice and compared.

## What the rest of the map should inherit

1. `west spdx` needs three things the course does not do today: `--init` on each image directory, `CONFIG_BUILD_OUTPUT_META=y` on each image, and a West project filter limited to the four cloned projects. `WEST_CONFIG_LOCAL` applies the filter without changing the workspace.
2. `modules-deps.spdx` is the wrong scanner input for the bootloader. It lists Mbed TLS 4.1.0 against a bootloader that compiles no Mbed TLS. `zephyr.spdx` shows what was compiled.
3. The Espressif Wi-Fi libraries and TinyCrypt are real components with no identity in any tool output. They are the two most instructive gaps for the SBOM review.
4. The OTA service's only dependency is the Go standard library, and its version follows the building machine. In the container that is Go 1.24.0, with 30 reachable standard-library vulnerabilities on the live database today.
5. TR-03183-2 2.1.0 rejects SPDX 2.3. The CRA names no format and no implementing act fixes one yet.
6. No SBOM tool hashes the signed image. The build manifest has to.

## Premises in the ticket that did not hold

- The ticket asks whether `west spdx` "names modules with versions and PURLs or CPEs that a scanner can match". It does for three of them: Zephyr, Mbed TLS and TF-PSA-Crypto. MCUboot and the Espressif HAL get only a commit hash, and the Wi-Fi libraries are not named.
- The ticket treats "the Go modules" as the OTA service's dependencies. The service has none. Its whole inventory is the Go standard library.
- The ticket's "(the `esp32c6_devkitc/esp32c6/hpcore` target, sysbuild with MCUboot)" implies one build. The course makes two, and the sysbuild bootloader is discarded. An SBOM of the sysbuild `mcuboot/` image describes a bootloader that is not shipped.
- The map's settled input 2 expects that most real scanner matches will be "not affected". That may hold for the firmware. For the service on Go 1.24.0 it does not: `govulncheck` finds the vulnerable symbols reachable.

## Sources

- Zephyr Project, "Software bill of materials: west spdx", Zephyr 4.4.0 documentation, <https://docs.zephyrproject.org/4.4.0/develop/west/zephyr-cmds.html>, accessed 30 September 2026.
- Zephyr 4.4.2 source at commit `dccb09599635`, in `/opt/zephyr-workspace/zephyr`: `scripts/west_commands/spdx.py`, `scripts/west_commands/zspdx/walker.py`, `scripts/west_commands/zspdx/writer.py`, `scripts/zephyr_module.py`, `CMakeLists.txt`, `Kconfig.zephyr`.
- `modules/hal/espressif/zephyr/module.yml` at `f07465053c0f`; `modules/crypto/mbedtls/zephyr/module.yml` at `a3e190fe44c7`; `modules/crypto/tf-psa-crypto/zephyr/module.yml` at `dc575a2ddcc8`.
- West 1.5.0, `west/configuration.py`, in the Zephyr venv.
- Regulation (EU) 2024/2847 (Cyber Resilience Act), Official Journal L, 20 November 2024, <https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847>, accessed 30 September 2026: Article 3(39), Article 13(24), Annex I Part II (1), Annex II (9), Annex VII (2)(b) and (8), recitals 22 and 77.
- BSI, Technical Guideline TR-03183-2, version 2.1.0, 20 August 2025, <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf>, accessed 30 September 2026: sections 3.1, 4, 5.1, 5.2, 6.1, 7, 8.1.14.
- NVD CPE API 2.0, <https://services.nvd.nist.gov/rest/json/cpes/2.0>, queried 30 September 2026.
- CycloneDX `cyclonedx-gomod` v1.12.0, Anchore `syft` v1.52.0, `golang.org/x/vuln` `govulncheck` v1.8.0, installed with `go install` into a scratch directory on 30 September 2026.
- Repository: `go.mod`, `course.yml`, `scripts/build-zephyr-baseline.sh`, `firmware/tier-08-credential-lifecycle/sysbuild.conf` and `bootloader/mcuboot.conf`, `docs/esp32c6-build-baseline.md`, `.devcontainer/Dockerfile`, `.devcontainer/post-create.sh`, `docs/course-specification.md` sections 7 and 10, all at `ccd1d65`.
