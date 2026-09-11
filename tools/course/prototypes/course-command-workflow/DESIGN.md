# Throwaway design proposal: `course.yml` and `./course`

This artifact supports issue 23. It is a prototype input, not a production contract. The interactive prototype is [`index.html`](index.html).

## Proposed decisions

1. `course.yml` is declarative. It names capabilities, checkpoints, paths, requirements, safety rules, and underlying commands. It does not contain workflow state.
2. `.course-state/` holds local workflow state. A passing tier verification writes a receipt tied to the tier start checkpoint and the exact Learner Git revision.
3. `./course tier start <id>` creates a new Git worktree and Learner branch from the published start checkpoint. Later commands run inside that Course workspace.
4. Starting Tier 1 does not continue from the Tier 0 Learner branch. It starts from the published Tier 0 completion checkpoint and preserves the Tier 0 worktree.
5. Planned tiers stay in the manifest with `status: planned`. `tier list` shows them as planned. No command may treat them as runnable.
6. `doctor` only inspects. `setup` writes disposable state and secrets only under manifest-declared untracked paths.
7. Every wrapper command prints the ecosystem commands and configuration paths it uses.
8. `clean` reads an exact allowlist from the manifest, shows it, and requires the typed phrase `REMOVE COURSE GENERATED STATE`.

## Proposed `course.yml` shape

The example is intentionally concrete for Tier 0 and Tier 1. Tier 2 shows the placeholder shape used through Tier 10 and Advanced Tiers A and B.

```yaml
schema_version: 1

course:
  id: learning-cyber-security
  version: "1.0"
  minimum_wrapper_version: "1.0.0"

paths:
  state: .course-state
  secrets: .course-secrets
  build: build
  generated_artifacts: artifacts/generated
  cleanup_allowlist:
    - .course-state
    - .course-secrets
    - build
    - artifacts/generated

runtimes:
  compose:
    choices:
      docker:
        probe: [docker, compose, version]
        command: [docker, compose]
      podman:
        probe: [podman, compose, version]
        command: [podman, compose]
    selection: explicit_if_ambiguous

toolchains:
  zephyr:
    required_tools:
      git: {probe: [git, --version]}
      python: {probe: [python3, --version]}
      cmake: {probe: [cmake, --version]}
      ninja: {probe: [ninja, --version]}
      west: {probe: [west, --version]}
    environment:
      required: [ZEPHYR_WORKSPACE]
    versions:
      zephyr: 4.4.2
      mcuboot: 2.4.0
      zephyr_sdk: 1.0.1

components:
  firmware:
    build:
      command:
        - west
        - build
        - --sysbuild
        - -b
        - esp32c6_devkitc/esp32c6/hpcore
        - firmware/reference-product-baseline
        - -d
        - "{paths.build}/tier-{tier.id}"
      outputs:
        - "{paths.build}/tier-{tier.id}/zephyr/zephyr.bin"
    required_tools: [west, cmake, ninja]

services:
  ota:
    runtime: compose
    compose_file: services/ota/compose.yml
    profiles:
      "00": tier-00
      "01": tier-00
    healthcheck:
      command: [curl, --fail, "http://127.0.0.1:8080/health"]
    safety:
      bind: 127.0.0.1
      course_environment_marker: required

devices:
  esp32c6_devkitc:
    board: esp32c6_devkitc/esp32c6/hpcore
    selector:
      stable_serial_path_required: true
      path_prefix: /dev/serial/by-id/
    commands:
      flash:
        command: [west, flash, -d, "{build.directory}", --dev-id, "{device.path}"]
        destructive: true
        irreversible: false
      logs:
        command: [python3, -m, serial.tools.miniterm, "{device.path}", "115200"]
      update:
        command: [python3, tools/course/device.py, update, --device, "{device.id}"]
      recover:
        command: [python3, tools/course/device.py, recover, --device, "{device.id}"]

attack_fixtures:
  tier-00/plaintext-inspection:
    tier: "00"
    command:
      - python3
      - attack-fixtures/tiers/tier-00/run.py
      - --fixture
      - plaintext-inspection
      - --target
      - "{service.ota.url}"
      - --require-course-marker
    requires:
      services: [ota]
      isolated_lab_network: true
      course_environment_marker: true
    expected:
      "00": insecure_effect_observed
      "01": observation_linked_to_analysis
    evidence:
      - captured-http-exchange

  tier-00/altered-image:
    tier: "00"
    command:
      - python3
      - attack-fixtures/tiers/tier-00/run.py
      - --fixture
      - altered-image
      - --target
      - "{service.ota.url}"
      - --require-course-marker
    requires:
      services: [ota]
      hardware: [esp32c6_devkitc]
      isolated_lab_network: true
      course_environment_marker: true
    expected:
      "00": insecure_effect_observed
    evidence:
      - accepted-image-record

tiers:
  "00":
    title: Build the unsecured reference product
    kind: baseline
    track: core
    status: implemented
    checkpoints:
      start: course-v1.0-tier-00-start
      complete: course-v1.0-tier-00-complete
    module: course/tiers/tier-00-unsecured/index.md
    prerequisites: []
    requires:
      toolchains: [zephyr]
      components: [firmware]
      services: [ota]
      hardware: [esp32c6_devkitc]
    commands:
      build: [firmware]
      verify:
        - python3
        - tools/course/verify.py
        - --tier
        - "00"
    attacks:
      - tier-00/plaintext-inspection
      - tier-00/altered-image
    evidence:
      - id: baseline-architecture
        path: evidence/learner/tier-00/baseline-architecture.md
        schema: evidence/schemas/architecture.schema.json
      - id: captured-http-exchange
        path: evidence/learner/tier-00/http-exchange.yml
        schema: evidence/schemas/observation.schema.json
      - id: accepted-image-record
        path: evidence/learner/tier-00/accepted-image.yml
        schema: evidence/schemas/observation.schema.json
      - id: absent-controls-list
        path: evidence/learner/tier-00/absent-controls.md
        schema: evidence/schemas/absent-controls.schema.json
    mentor_review: not_required
    safety:
      isolated_lab_network: required
      disposable_credentials: required
      irreversible_operations: forbidden

  "01":
    title: Model the product and its risks
    kind: analysis
    track: core
    status: implemented
    checkpoints:
      start: course-v1.0-tier-00-complete
      complete: course-v1.0-tier-01-complete
    module: course/tiers/tier-01-threat-model/index.md
    prerequisites:
      - tier: "00"
        completion: verified_receipt
    requires:
      toolchains: []
      components: []
      services: []
      hardware: []
    commands:
      verify:
        - python3
        - tools/course/verify.py
        - --tier
        - "01"
    attacks:
      - tier-00/plaintext-inspection
    evidence:
      - {id: product-definition, path: evidence/learner/tier-01/product-definition.md}
      - {id: threat-model, path: evidence/learner/tier-01/threat-model.yml}
      - {id: risk-register, path: evidence/learner/tier-01/risks.yml}
      - {id: claims, path: evidence/learner/tier-01/claims.yml}
      - {id: requirements, path: evidence/learner/tier-01/requirements.yml}
    mentor_review: required
    safety:
      irreversible_operations: forbidden

  "02":
    title: Authenticate and encrypt the server connection
    kind: control
    track: core
    status: planned
    checkpoints:
      start: course-v1.0-tier-01-complete
      complete: course-v1.0-tier-02-complete
    module: course/tiers/tier-02-authenticated-https/index.md
    prerequisites:
      - tier: "01"
        completion: verified_receipt
    requires: null
    commands: null
    attacks: []
    evidence: []
    mentor_review: not_required
    safety:
      irreversible_operations: forbidden
```

The initial production manifest should contain equivalent `status: planned` entries for `03` through `10`, `A`, and `B`. A planned entry must keep its title, track, prerequisite, checkpoint names, and module path stable. Its runnable capabilities remain `null` or empty until implementation and validation are complete.

## Local state shape

`course.yml` stays immutable during normal use. The wrapper may write this untracked receipt after verification:

```json
{
  "schema_version": 1,
  "course_version": "1.0",
  "tier": "00",
  "start_checkpoint": "course-v1.0-tier-00-start",
  "verified_revision": "a1b2c3d4",
  "manifest_digest": "sha256:...",
  "result": "passed",
  "completed_at": "2026-09-11T20:00:00Z"
}
```

The receipt becomes stale when the current revision, course version, start checkpoint, or manifest digest changes. `tier start 01` requires a current Tier 0 receipt. It does not require the Learner to tag or publish their branch.

## Command behavior

| Command | Main behavior | Refusal or safety behavior |
| --- | --- | --- |
| `./course doctor` | Inspect versions, workspace configuration, compose runtimes, device paths, and generated state. Print every probe. | Return nonzero with all found problems. Do not write state or install tools. Hardware absence is a warning unless the requested operation needs hardware. |
| `./course setup` | Select one compose runtime and create disposable configuration and secrets in the four declared untracked paths. | Refuse when required tools or a runtime are missing. If Docker and Podman are both present, require `--runtime`. Do not change tracked files. |
| `./course tier list` | Show every manifest tier with `Implemented`, `Planned`, or `Experimental` status and its prerequisites. | Never present `planned` as runnable. |
| `./course tier start <id>` | Validate the tier, receipt prerequisites, repository version, tools, and clean invoking worktree. Create a worktree and Learner branch from the start checkpoint. Print the module and first command. | Refuse dirty work, missing tags, stale or missing receipts, existing path or branch collisions, missing requirements, and any non-runnable tier. Never stash, reset, delete, or reuse a worktree silently. |
| `./course tier status` | Show current tier, checkpoint, Git revision, dirty state, services, device, last build, evidence status, and receipt status. | Report that the current directory is not a Course workspace when no workspace metadata matches. |
| `./course tier diff <id>` | Show Learner changes from the start checkpoint. Reveal the reference checkpoint diff only after explicit `--reveal-reference`. | Refuse a mismatched tier. Never merge or apply the reference delta. |
| `./course build [component]` | Expand the component's manifest command and run it. Print the exact command and output paths. | Refuse unavailable components, missing tools, or use outside a Course workspace. |
| `./course service start\|stop\|status` | Operate only manifest-owned compose services and profiles. Print the compose file, profile, and health check. | Refuse an unselected runtime. `stop` names services and does not terminate unrelated processes. |
| `./course device flash\|logs\|update\|recover` | Require an exact device selected by stable serial path. Print the underlying West, serial, or helper command. | Refuse ambiguous devices and unmet build or service preconditions. Normal commands cannot call irreversible hardware operations. |
| `./course attack list\|run <fixture>` | Resolve a manifest fixture, check tier, network, service, hardware, and course target marker, then run it and store the result under generated artifacts. | Fail closed outside the isolated lab network or when the target marker is absent. Never accept an unrestricted target. |
| `./course verify <tier-id>` | Run manifest-declared build, test, fixture-result, and evidence checks. Write a revision-bound local receipt only after all pass. | Refuse mismatched tiers and dirty or unnamed revisions. On failure, write no passing receipt. |
| `./course evidence check` | Validate required paths, schemas, links, metadata, and secret policy for the current tier. | List every missing or invalid artifact. Do not create Learner evidence. |
| `./course clean` | Show the exact existing paths from `cleanup_allowlist`, then require `REMOVE COURSE GENERATED STATE`. | Never run a Git reset, Git clean, broad process kill, wildcard deletion, parent-directory deletion, or deletion outside the repository or current Course workspace. |

## Output contract

Every command should use the same output order:

1. Context: course version, current Tier, Course workspace, and relevant target.
2. Preconditions checked.
3. Underlying command or configuration path.
4. Result.
5. State files or artifacts changed.
6. One safe next command.

Refusals should use the same order, stop before side effects, and name the action the Learner must take. The wrapper should not repair Git state automatically.

## Human decision questions

1. Should `verify` write an untracked, revision-bound completion receipt, or should prerequisites be inferred from Git and evidence every time?
2. Should Tier 1 always start in a fresh worktree from `course-v1.0-tier-00-complete`, or should it continue from the Learner's Tier 0 branch?
3. After `tier start`, should normal commands run inside the new Course workspace, or from the controller repository with a required `--workspace` argument?
4. If both Docker Compose and Podman Compose are present, should setup require an explicit choice, or use a documented preference order?
5. Should `tier list` show planned tiers as unavailable, or hide them until implemented?
6. Is the typed cleanup phrase plus an exact allowlist sufficient, or should cleanup also require a `--workspace <path>` argument?
