# Agent instructions

Follow SETUP.md. This is an agent-guided defensive maintenance project, not a universal firmware cleaner.

- Inspect before changing. Confirm the user's target and permissions; existing session authorization persists. Do not repeatedly ask for already-authorized steps.
- Use explicit private-network discovery. An open ADB port is not device identification. Do not scan the internet, unrelated networks, or log into unrelated devices.
- Read docs/COMPATIBILITY.md. Quarantine/mutation helpers support only the exact reference firmware. On other versions, perform an audit and explain what needs adaptation. Do not bypass the profile gate by renaming a model or weakening checks.
- A path, package name, packed executable, or unfamiliar domain alone does not prove malware. The automatic quarantine tool requires exact reference hashes, a matching firmware profile, a device-bound audit, and a verified local backup. Unknown hashes need separate analysis.
- Keep state, backups, keys, inventories, screenshots, and packet captures outside the checkout. Never commit device output or upload binaries, credentials, diagnostics, or personal screenshots to GitHub. Only synthetic tests and manually redacted evidence summaries belong here.
- Do not download or execute a random cleanup/rooting script. Root is a prerequisite, not an exploit supplied by this project. Preserve a working management connection and backups.
- Test firewall rules live with a detached rollback watchdog and a NEW connection before persistence. Use single TCP-port matches; never add a generic INPUT DROP policy. Seed an authorized laptop PUBLIC key before enabling ADB auth; never copy its private key to the box.
- Do not remove the only WebView provider, launcher, Settings, keyboard, package manager, or playback dependencies. Extra app removal is optional and must match the user's keep list. The runtime does not automatically remove every package.
- Installation lockdown also blocks ordinary updates. Explain the maintenance restore/relock process. It cannot prevent root exploits, firmware malware, or unwanted code already inside retained streaming apps.
- Remove app-accessible root only after authenticated `adb root` and persistent management access survive reboot. Chmod on su alone did not persist on the reference device. Do not restore quarantined payloads as routine recovery.
- Do not flash firmware, factory-reset, change router configuration, enable bootloader unlocking, or perform USB-A host-to-host connections as an inferred recovery procedure.
- Verify boot completion, exact policies, authentication, firewall rules, absence of identified persistence, playback, and remote control. Separate observed hardware evidence from new wrapper/unit tests. Do not certify the whole device clean or claim support from a successful package install.
- For development, use Python's standard library. Run `python3 -m unittest discover -s tests -v`, `python3 host/check_release.py`, and `sh -n runtime/*.sh` (one file at a time). New high-impact behavior needs meaningful failure/recovery tests. Do not test new mutations on the maintainer's TV merely to publish this repository.
- Publication is authorized when requested by the user. Do not include the upstream LG project's unrelated code or apply its release/issue workflow to this independent repository.
