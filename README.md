# Superbox Clean

Use a coding agent to investigate a Superbox Android TV box, quarantine identified malware, preserve the streaming apps you choose, and reduce the chance of reinfection.

## Get started

1. Download this repository using **Code → Download ZIP** and extract it, or clone it.
2. Open the folder in a coding agent that can run terminal commands on your computer.
3. Paste this:

   > Help me inspect and clean my Superbox. Read AGENTS.md and follow SETUP.md. Discover candidates on my local network, verify which device is the Superbox, and check its exact model and firmware before changing it. I want to keep Blue TV and Blue VOD plus required system components. Save private backups outside the repo, quarantine only evidence-backed files, preserve recovery access, and explain installation lockdown. Verify authentication, boot persistence, playback, and remote control. If my model or files differ from the reference, audit them and explain the limits rather than forcing the reference cleanup.

Keep the box on, with its remote nearby, and put the computer on the same local network. **Python 3.10+ and Google's Android Platform Tools (`adb`)** are required. Linux, macOS, or WSL with working LAN access are the supported host environments. There are no Python package dependencies. ADB/root availability depends on the box; this project does not exploit or root devices.

This follows the agent-guided approach of [LG TV Clean](https://github.com/amiable-ostrich/lg-tv-clean). It is a procedure with focused helpers, not a universal one-click cleaner.

## Compatibility

| Device/version | What is supported |
| --- | --- |
| **SuperBOX S2 Pro**, Android 9/API 28, **`SuperBOX_S2PRO.20211214.V1.2.0`** | Reference procedure; exact-hash quarantine profile and gated install-lockdown helpers. The manual procedure was exercised on one device. |
| Other S2 Pro firmware | Discovery and inspection where ADB works. No automatic quarantine or lockdown profile. |
| Other Superbox models, including S3–S8 | Discovery and inspection where ADB works. **Not hardware-validated; no mutation support claimed.** |

Only byte-identical artifacts from the reference investigation qualify for automatic quarantine. A matching model, unfamiliar package name, or open port is insufficient. Unknown hashes are reported and left alone. Even another S2 Pro may have entirely different infections. See [compatibility and adding models](docs/COMPATIBILITY.md).

## What it includes

- Network discovery, private inspection reports, offline plans, backup-verified quarantine, installation-policy lockdown, and readback helpers.
- Narrow firewall rules, an automatic firewall rollback watchdog, ADB key-authentication checks, and optional removal of the app-accessible root daemon.
- [SETUP.md](SETUP.md): agent runbook, app preservation, reboot/playback checks, and recovery.
- [Reference evidence](docs/REFERENCE.md), synthetic regression tests, CI, and `SHA256SUMS` for the included helpers.

A typical inspection starts with:

```sh
python3 host/superbox.py discover --network 192.168.50.0/24
python3 host/superbox.py audit --device 192.168.50.8:5555 --state "$HOME/.local/state/superbox-clean/first-audit"
python3 host/superbox.py plan --audit "$HOME/.local/state/superbox-clean/first-audit/before.json"
```

Replace the example subnet and address with your own. Discovery probes a few ports; it does not identify devices or log in to every host. Inspect the plan before using the mutation commands in SETUP.md.

## Limits and recovery

**Install lockdown also blocks normal app updates.** Use the documented maintenance restore/relock process. It does not prevent firmware exploits, privileged malware, or unwanted behavior already inside an app you retain. Native/P2P streaming libraries may upload data as part of playback. Keeping these apps does not establish that all spying or third-party traffic has stopped.

The reference box had severely outdated security patches and modified system files. A targeted cleanup cannot establish trusted firmware integrity. No firmware flashing, factory reset, or copyrighted streaming APKs are included. Malware samples, personal diagnostics, credentials, and device addresses are excluded.

Keep backups and an authenticated management connection. The runbook includes a detached firewall rollback before persistence. **Do not connect ordinary USB-A host ports together**, and do not assume a port marked USB1 is a debug/OTG port. If access is lost, follow [recovery](SETUP.md#recovery-and-maintenance); never automatically restore the quarantined payloads.
