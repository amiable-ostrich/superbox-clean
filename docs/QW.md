# Additional root broker: qw

## Finding and scope

A follow-up investigation on 2026-11-11 found another root broker on the reference **SuperBOX S2 Pro, Android 9/API 28, firmware `SuperBOX_S2PRO.20211214.V1.2.0`**. Removing `su` and `daemonsu` had not removed this separate service, defined in `/system/etc/init/qw.rc`:

```text
service qw /system/bin/qw --daemon
    user root
    group root
    class core
```

Its Unix socket at `/dev/com.koushikdutta.superuser.daemon/server` was world-connectable. Socket permissions alone were not the basis for the finding: a controlled test demonstrated unsafe authorization.

| Artifact | Size (bytes) | SHA-256 |
| --- | --- | --- |
| `/system/bin/qw` | 317856 | `088bd9d22edd091a2c4045363221e335bf34388c5287490e0cb2811e1289e8a2` |
| `/system/etc/init/qw.rc` | 79 | `b80e1d9759cb0c9f84ef05b03d7952d9200e8bc4cda6baf793a2cf415ea4b73f` |

These hashes identify the investigated artifacts. A filename or different hash does not establish identical behavior or justify automatic removal. No binary, raw device output, or owner-specific identifier is distributed here.

## Identification and authorization weakness

The statically linked ARM executable retained compressed debug symbols. Symbols, disassembly, and strings identified a modified implementation of [Koush's Superuser command](https://github.com/koush/Superuser/blob/master/Superuser/jni/su/su.c) and [daemon](https://github.com/koush/Superuser/blob/master/Superuser/jni/su/daemon.c). This identifies a source family, not a reproducible-build match or verified vendor provenance.

The client inspected its parent's process name and accepted names associated with factory-test apps. A normal shell invocation failed before reaching the root-command path. That failure initially concealed the weakness: accepted process names were caller-controlled, and the broker's command path did not enforce the upstream interactive authorization sequence.

A diagnostic launched through authenticated maintenance ADB dropped its UID and primary GID to an existing application identity. With an ordinary process name, its request was rejected. With a factory-test process name, the same process requested only an identity-printing command and received UID/GID 0. No persistence or arbitrary command payload was installed.

The diagnostic inherited supplementary ADB groups and its initial SELinux domain; it was not an installed application exploit. SELinux was permissive. The paired test held these conditions constant and changed the process name. It demonstrates unsafe authorization, but does not independently establish exploitability from every app sandbox or on enforcing firmware.

Exact DEX string-table inspection found direct qw references in the factory Aging and Box APKs, already uninstalled for the active user. The inspected launcher, Blue TV, Blue VOD and SettingsAssist APKs had no direct qw string references. This supports a factory-test-helper explanation, not a guarantee that every indirect dependency was found.

**Classification:** an unsafe privileged factory-test root broker, recommended for disabling on the investigated streaming setup. The investigation did not establish that qw was Kimwolf, another malware family, or the original infection source. No direct network connection from its daemon was observed in the snapshot.

## Manual remediation performed

Following owner authorization, a separate operation on the reference box:

1. Confirmed exact firmware, device-bound identity, authenticated root maintenance, and current artifact hashes.
2. Created a private backup archive, pulled it to the host, and verified both archive members and checksums before mutation.
3. Stopped the service for a reversible dependency check. Streaming apps opened and the VOD catalog loaded.
4. Used a one-time script with firmware/hash/process checks to move the executable and startup definition out of active paths into root-owned quarantine. The directory was mode 0700 and both files mode 0600, with execution bits removed.
5. Removed the stale socket after confirming no live listener remained, remounted the root filesystem read-only, and rebooted.
6. Verified a changed boot ID, boot completion, absent active paths/socket, no registered qw service, matching quarantine hashes, and no inspected executable links to qw or quarantine.

After reboot, authenticated root maintenance still worked and an unsigned ADB handshake returned AUTH. Existing IPv4/IPv6 firewall rules, installation restrictions and streaming install appops remained effective. ADB was returned to its normal shell UID after verification.

Blue TV displayed advancing video. Blue VOD loaded its catalog and title details, then displayed advancing opening video. Settings and the launcher worked with synthetic Back/Home input. Physical remote buttons, audible sound, wall-power cold boot, every channel/title and a complete movie were **not** independently verified.

Backups, scripts and diagnostics stayed private. The root broker was not restored as routine recovery. This closes the observed qw route; it does not establish trusted firmware integrity or eliminate every privileged vendor component.

## Repository support boundary

**The automatic malware-quarantine profile and `runtime/remove-app-root.sh` do not remove qw.** The manual operation above is a hardware observation, not newly supported automation. No profile gate was weakened and no reusable qw mutation helper is included in this documentation update.

Agents should inspect for additional privileged services after removing familiar root tools. If this exact qw pair is found, review the evidence, backup/recovery path, dependencies and owner authorization before separate, hash-bound remediation. Unknown versions require fresh analysis. Do not rename a profile, blindly delete a similarly named program, merely change permissions, or restore known malware to regain access. Preserve the boot/playback/authentication checks in SETUP.md.
