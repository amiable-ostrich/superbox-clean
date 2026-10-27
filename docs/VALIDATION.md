# Validation record — 2026-10-27

## Repository checks

- 25 synthetic unit/regression tests passed locally with Python 3.14.
- Coverage includes explicit private-network inputs, shell/argument injection rejection, exact firmware/hash gates, missing/unknown artifacts, explicit boot-file opt-in, changed device identity, changed saved evidence, corrupted/symlink backup rejection, repeat/no-op behavior, private/symlink-safe state files, unsigned ADB challenge parsing, single-port firewall construction, partial-match failure before attachment, and an unconfirmed-watchdog rollback simulation.
- All included runtime shell files pass `sh -n`.
- Publication text/artifact checks and SHA256SUMS validation pass. Device addresses, MAC, hardware serial, public/private key material, personal paths, APKs, native payloads, archives, captures, and private audit output were excluded from publication.
- GitHub Actions is configured for Linux/macOS and Python 3.10/3.14. Check the workflow result for a particular commit; configured CI is not itself a passing run.

## Reference hardware

The earlier manually executed cleanup procedure was exercised on one S2 Pro using the exact firmware in COMPATIBILITY.md. Known persistence stayed absent through software reboots; authenticated ADB, targeted firewall rules, install restrictions, and app-root daemon removal were checked. Both Blue TV and Blue VOD played video. The initial firewall compatibility failure and its recovery are described in REFERENCE.md.

The new repository's **inspection and offline-plan helpers** were subsequently run against that already-cleaned box: they recognized the reference profile, found zero matching artifacts at active paths, and read secure ADB enabled. Output remained in private state outside the checkout. No new quarantine, lockdown, root, or firewall mutation from this repository was applied merely to test publication.

The new automated quarantine wrapper has synthetic tests; the original-policy restore helpers have shell syntax checks but no dedicated device-level restore trial. Neither has a new destructive hardware trial. Other models, wall-power cold boot, and every physical remote-control button remain unvalidated. The reference evidence is not a clean-firmware attestation or certification of retained streaming code.
