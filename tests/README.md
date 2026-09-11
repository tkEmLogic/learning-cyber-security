# Tests

Go service and helper tests are colocated with their packages.

`scripts/verify-tier-00.sh` runs host tests, Go vet, shell syntax checks, JSON Schema validation, Markdown checks, secret checks, and repository cross-reference checks.

Container integration uses the real compose service and the four `./course attack run` commands.

The pinned firmware build uses `scripts/build-zephyr-baseline.sh`.

Hardware flash, serial, LED, Wi-Fi, OTA installation, recovery, and altered-image execution stay pending when no physical ESP32-C6 is available.
