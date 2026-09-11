# Course setup

Use a current Linux distribution with Go, Git, curl, Python 3 with virtual environment support, and either Docker Compose or Podman Compose.

Ubuntu 24.04 is the CI reference environment. Other current Linux distributions are supported when the same tools qualify.

Run:

```text
python3 -m venv build/python
build/python/bin/pip install -r requirements.txt
./course doctor
./course setup --runtime docker
./course service start
./course service status
```

Use `--runtime podman` instead when Podman is your selected runtime.

If both runtimes qualify, setup requires an explicit choice.

The Python packages are required by the Tier 0 verification command. The virtual environment is generated state and the cleanup command removes it.

Setup creates only `.course-state/`, `.course-secrets/`, `build/`, and `artifacts/generated/`.

The service binds to `127.0.0.1` by default.

Use `./course setup --runtime docker --bind 192.168.1.20` only when that literal private address is the selected classroom interface.

Clean generated state with:

```text
./course service stop
./course clean --confirm "REMOVE COURSE GENERATED STATE"
```

The clean command removes only the exact allowlist from `course.yml`.
