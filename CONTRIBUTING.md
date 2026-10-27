# Contributing

Keep the workflow agent-guided, auditable, and conservative about model support. Read AGENTS.md and docs/COMPATIBILITY.md. Do not commit raw reports, credentials, backups, screenshots, streaming APKs, or malware samples. Security concerns can be raised without posting owner-specific diagnostics; no private disclosure channel is configured here.

Use synthetic fixtures. New device support needs explicit compatibility gates and actual separately recorded hardware acceptance; don't infer support from a successful ADB connection. An unknown hash is not automatically malicious.

Before a commit:

```sh
python3 -m unittest discover -s tests -v
for script in runtime/*.sh; do sh -n "$script" || exit; done
python3 host/check_release.py --write
python3 host/check_release.py
```

Review the diff and checksum changes. `SHA256SUMS` detects changed checked-out content but does not authenticate the repository author; use a trusted source/revision. CI uses pinned upstream action commits and runs Python tests/checks on Linux/macOS. It does not connect to real hardware or install malware.

The first release is an agent runbook plus CLI/runtime helpers, not a desktop installer or a universally validated cleaner. Keep the readme/runbook/compatibility/reference evidence aligned with the actual code. Do not embed a user's source address, hardware serial, public key, app inventory, or private-state path as a default. User-specific data stays outside this repo even when ignored by Git.
