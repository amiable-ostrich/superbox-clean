# Validation record

The initial repository and hardware record below is from 2026-10-27. A separately identified follow-up is recorded at the end.

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

## Follow-up hardware finding — 2026-11-11

A separate `qw` root broker was identified, investigated and manually quarantined on the same reference firmware. A paired application-UID diagnostic demonstrated unsafe authorization based on a caller-controlled process name. The diagnostic inherited supplementary ADB groups and its initial SELinux domain; it was not an installed-app exploit test. See [the detailed qw record](QW.md) for hashes and limitations.

The owner-authorized remediation used verified private backups and exact firmware/hash checks. A new boot ID, absent active executable/init/socket, no registered qw service, matching quarantined bytes, authenticated root maintenance, AUTH challenge behavior, existing firewall/install protections, sampled video playback in both streaming apps, and launcher/Settings behavior were verified. Physical handset controls, audible sound and wall-power cold boot remain unverified.

This was a separate one-time operation, not a device trial of a newly added repository mutation helper. The automatic malware profile and existing root-tool removal script remain unchanged and do not remove qw. No binaries, reproduction payloads or owner-specific diagnostics are published.
