# Agent setup runbook

Read AGENTS.md and docs/COMPATIBILITY.md first. Work from the repository root. All example addresses are fictional; substitute the owner's actual private subnet/device. The owner need not type terminal commands: a capable coding agent runs the computer steps and guides the physical checks.

This is a staged maintenance workflow, not `curl | sh`. Commands after inspection require authorization to change the identified box. Existing authorization in the session applies; don't repeatedly ask for it. Different firmware or new payload hashes require investigation, not bypassing checks.

## 1. Prepare the computer and private workspace

Use Linux, macOS, or WSL with Python 3.10+ and working LAN access. Install `adb` from [Google's Platform Tools](https://developer.android.com/tools/releases/platform-tools). Inspect downloads from their official source; do not run a random “Superbox cleaner.” Do not install a rooting exploit merely to use this procedure.

```sh
python3 --version
adb version
python3 host/check_release.py
python3 -m unittest discover -s tests -v
umask 077
mkdir -p "$HOME/.local/state/superbox-clean"
SBC_STATE=$(mktemp -d "$HOME/.local/state/superbox-clean/setup-XXXXXXXX")
```

Keep `$SBC_STATE` outside the checkout. It can contain private inventories, hardware-identity hashes, authorized public keys, backups, and policy snapshots. Do not upload it as a GitHub issue attachment. Each helper's `--state` must be a new empty directory; this prevents overwriting previous evidence. On macOS, Python 3 may need installation; Windows users should use WSL rather than native Python for the POSIX state-permission checks.

## 2. Discover and identify

Determine the computer's current route/address first (`ip route` on Linux, `route -n get default` and `ifconfig` on macOS). Use only the owner's LAN. Don't assume a remembered address is still assigned to the box.

```sh
python3 host/superbox.py discover --network 192.168.50.0/24
```

The helper probes TCP 5555, 5858, and 63002 with bounded concurrency. To check a different owner-specified ADB port, use `--ports PORT`. Only small RFC1918 IPv4 networks are accepted. An open port is only a candidate; do not connect to unrelated devices to “see what they are.” Correlate the router's device list, box's network screen, MAC/ARP entry, or observed device identity. Router logins/configuration are not automated here.

```sh
SBC_DEVICE=192.168.50.8:5555
adb connect "$SBC_DEVICE"
adb -s "$SBC_DEVICE" shell getprop ro.product.model
adb -s "$SBC_DEVICE" shell getprop ro.build.display.id
python3 host/superbox.py audit --device "$SBC_DEVICE" --state "$SBC_STATE/audit"
python3 host/superbox.py plan --audit "$SBC_STATE/audit/before.json"
```

The audit stages/deletes a temporary text script but makes no persistent configuration changes. It collects selected properties, file hashes, installed-package paths, process names, install restrictions, and the WebView provider. It does not capture screen, packet payloads, accounts, or app data. These diagnostics still belong in private state. A hardware serial is hashed with the build fingerprint to bind a plan to the device; its raw value is not saved in the audit.

If root is needed to read paths, add `--root` only when you have an existing authorized root shell or `su`. The tool never attempts a new rooting exploit. If `adb` is unavailable, the device requires pairing, or diagnostics fail, resolve that access prerequisite; don't interpret failure as a clean result.

## 3. Check compatibility, dependencies, and recovery

For the exact reference model/firmware, inspect:

```sh
adb -s "$SBC_DEVICE" shell cat /proc/mounts
adb -s "$SBC_DEVICE" shell dumpsys webviewupdate
adb -s "$SBC_DEVICE" shell id
```

Confirm Android 9/API 28, system-as-root ext4 `/`, expected init paths, usable `sha256sum`, `tar`, `pm`, and both firewall tools. Mutations require existing root. On the reference build, `adb root` worked without an exploit:

```sh
adb -s "$SBC_DEVICE" root
adb -s "$SBC_DEVICE" wait-for-device
adb -s "$SBC_DEVICE" shell id
```

Do not continue with direct-root commands unless UID is 0. `--root` can use an already installed `su` for quarantine/lockdown if direct ADB root isn't available; optional root-tool removal specifically requires a working authenticated ADB root channel.

Save the current package inventory, selected app data/activation if authorized and needed, relevant system files, existing ADB authorized-key file, and exact policy/configuration snapshots outside the repo. The quarantine helper backs up **only selected matching files**, not the entire device or streaming activation. Before auth/firewall/root changes, make a separate root-only tar backup of all files being changed; pull it, check its members/checksums, and preserve it privately. Use a device-side temporary archive and `adb pull`, not binary output through `su`/a terminal, which can corrupt backups. Never extract an untrusted archive into the checkout or a privileged filesystem.

Keep the remote nearby. Confirm Home/Settings work. Do not assume USB1/USB2 labels indicate OTG/debugging. A USB-C-to-A cable fitting the sockets does not establish compatible host/device roles. Do not connect two ordinary USB-A host ports.

On a different build, stop the mutation workflow and report audit findings and missing evidence. Do not pass `--apply` just because the hardware says Superbox.

## 4. Quarantine identified artifacts

Read the plan. `match` means the exact reference bytes; `unknown` is left alone; `missing` is not proof of safety. Preserve system services such as Android's real `netd`.

```sh
python3 host/superbox.py quarantine \
  --device "$SBC_DEVICE" --root --apply \
  --audit "$SBC_STATE/audit/before.json" \
  --state "$SBC_STATE/quarantine"
```

To include the two **exact-hash suspicious boot-animation replacements**, explicitly add `--include-suspicious-boot-files` after reviewing the evidence. Their separate classification avoids calling all packed boot programs confirmed Kimwolf.

The helper refreshes the audit, checks device identity and firmware, verifies selected hashes against the saved audit, creates/pulls a tar backup, checks each member's type/size/hash, rechecks all live hashes, stops the matched respawner/packages, and kills only native executables matching the captured payload hash. It then remounts `/`, moves the selected files to a private system quarantine, removes their executable permissions, remounts read-only, and records readback. It never restores malware automatically.

Unknown files are not modified. If known and unknown variants coexist, the known files can be quarantined but the unknown components remain unresolved. Do not label that a complete cleanup. A subsequent fresh audit/plan is required if newly appeared files need action. A rerun with no matching active files is a no-op.

Do not run multiple maintenance operations concurrently against one box. If a step fails, stop and inspect the local backup and partial state. Reboot only after understanding the result; don't automatically undo quarantine by putting executable payloads back.

## 5. Keep streaming dependencies; optionally remove extras

Ask for or honor the owner's keep list. Defaults are `com.bluetv.live2` (Blue TV) and `com.vodblue.vod2` (Blue VOD). Other versions may use different IDs. Keep their activation/data unless removal was requested.

Keep the launcher, Settings, keyboard, input/Bluetooth, networking, media/DRM, package manager, and required system/Google components. Chrome was the reference box's **only WebView provider**. Do not disable/uninstall its entire package. With root, its standalone browser entry activities can be disabled without disabling WebView:

```sh
adb -s "$SBC_DEVICE" shell pm disable --user 0 com.android.chrome/com.google.android.apps.chrome.Main
adb -s "$SBC_DEVICE" shell pm disable --user 0 com.android.chrome/com.google.android.apps.chrome.IntentDispatcher
```

Use `pm disable`, not `disable-user`, for these components; verify the result is `disabled` and the WebView provider remains valid.

If the owner wants a minimal setup, review candidates individually: vendor app store (`com.blue.store2`), voice/search assistant, Play Store, vendor updaters, network remote control (`com.supercontrol.remoteservice`), factory/aging apps, Camera, Gallery, Music, stock video/file manager, and Miracast. Save their original installation/enabled state and APK paths. Then use `pm uninstall --user 0 PACKAGE` only for agreed nonessential apps. That removes a factory app for this user, not its firmware image; a factory reset can restore it. Don't remove or quarantine an updater solely because its name is unfamiliar. Disabling firmware update paths has an ongoing security tradeoff; review actual trustworthy update options first.

The reference store's system APK directory was separately quarantined after backup because it was a reinstall path. The new exact-hash payload quarantine helper does **not** automatically move a legitimate store or all optional apps. Do not broadly copy the reference inventory to another model.

A retained streaming app may contain analytics, native/P2P code, or proxy functionality. A short string scan is not an audit. Removing malware wrappers does not establish that the rest is trustworthy. Don't block generic cloud/CDN hosts solely because they appear in a connection list.

## 6. Enable authenticated ADB

Do this before removing app-accessible root. Confirm the exact reference layout and back up `/system/etc/prop.default` and `/data/misc/adb/adb_keys` if present. Never overwrite existing authorized keys.

Use the computer's **public** Android key (`~/.android/adbkey.pub`, generated when adb first starts). Validate that its first field decodes to an Android RSA public key, not an SSH key or private key. Stage it, with the helper, then run using the working root channel:

```sh
adb -s "$SBC_DEVICE" push "$HOME/.android/adbkey.pub" /data/local/tmp/sbc-management.pub
adb -s "$SBC_DEVICE" push runtime/enable-adb-auth.sh /data/local/tmp/sbc-enable-auth.sh
adb -s "$SBC_DEVICE" shell sh /data/local/tmp/sbc-enable-auth.sh /data/local/tmp/sbc-management.pub
adb -s "$SBC_DEVICE" reboot
```

Reconnect with the same computer/key after boot. If a pairing prompt appears, authorize it using the handset. Check boot completion and `ro.adb.secure=1`, then test actual unsigned protocol behavior:

```sh
adb connect "$SBC_DEVICE"
adb -s "$SBC_DEVICE" shell getprop sys.boot_completed
python3 host/auth_probe.py --device "$SBC_DEVICE"
```

Expected reply: **AUTH**. CNXN means unauthenticated access was accepted. A timeout alone doesn't prove auth. Secure ADB still permits the authorized key to request privileged maintenance on this userdebug build; protect that private key on the computer.

If adb is stuck on an old offline transport after reboot, disconnect/reconnect or restart its local server. Avoid killing another task's server blindly. A separate `adb -P 5039` server with the same host key can diagnose a stale transport without changing device authentication; helper commands expect the default server unless `ADB_SERVER_SOCKET` is configured. Don't weaken auth to fix a stale computer-side connection.

## 7. Protect management ports with tested narrow rules

Determine the IPv4 source address the computer actually uses to reach this device. Do not paste a maintainer/example address. Prefer a router DHCP reservation if maintenance access should persist. If the address changes, these rules must be updated from an already authorized channel.

The included guard restricts TCP 5555/5858/63002 to that address, blocks IPv6 access to those ports, and blocks the root-capable remote-control interfaces TCP 12104/UDP 12305. It leaves unrelated traffic policies unchanged. Some models use different ports; this list is **reference-specific**. Loopback access to the debugging ports is blocked as well, reducing local-proxy access paths.

First obtain UID 0 via the authenticated ADB channel. Set an address the agent has verified belongs to the computer:

```sh
SBC_MGMT_IP=192.168.50.20
SBC_TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
SBC_CONFIRM=/data/local/tmp/sbc-confirm-$SBC_TOKEN
adb -s "$SBC_DEVICE" push runtime/access-guard.sh /data/local/tmp/sbc-access.sh
adb -s "$SBC_DEVICE" push runtime/access-rollback.sh /data/local/tmp/sbc-access-rollback.sh
```

Start the detached rollback **before** adding rules. Check that it is running. These commands must run under an existing direct root ADB shell, not a non-root shell with a failed `su` prefix:

```sh
adb -s "$SBC_DEVICE" shell "nohup sh /data/local/tmp/sbc-access-rollback.sh '$SBC_CONFIRM' >/data/local/tmp/sbc-rollback.log 2>&1 </dev/null &"
adb -s "$SBC_DEVICE" shell "sh /data/local/tmp/sbc-access.sh '$SBC_MGMT_IP'"
adb disconnect "$SBC_DEVICE"
adb connect "$SBC_DEVICE"
adb -s "$SBC_DEVICE" shell id
```

Within 90 seconds, a **new successful connection** must confirm the rules. Read them back with `iptables -S SBC_ACCESS` and `ip6tables -S SBC_ACCESS`, confirm the expected source and that normal internet/playback works, then create the exact marker through that fresh connection. If it can't connect, **do not confirm or persist anything**; wait for the detached watchdog to remove the INPUT hooks, then reconnect and diagnose. It removes only this project's hooks, not the device's other firewall configuration.

```sh
adb -s "$SBC_DEVICE" root
adb -s "$SBC_DEVICE" wait-for-device
adb -s "$SBC_DEVICE" shell "touch '$SBC_CONFIRM'"
```

Only after these checks, back up any existing project guard and persist the already-tested script in `/system/etc/sbc-access.sh`, mode 0700, while `/` is briefly writable. Create `/system/etc/init/sbc-access.rc`, mode 0644, with the **verified real address** in place of `<MANAGEMENT_IPV4>`:

```text
service sbc_access /system/bin/sh /system/etc/sbc-access.sh <MANAGEMENT_IPV4>
    class late_start
    user root
    group root
    seclabel u:r:su:s0
    disabled
    oneshot

on property:sys.boot_completed=1
    start sbc_access
```

Use `restorecon` on the new files, remount `/` read-only, reboot, and verify the rules exist and both an authorized connection and playback work. The guard begins after boot completion; ADB key auth must already protect earlier boot. **Do not persist a broad INPUT DROP rule or depend on the multiport extension.**

## 8. Optional installation lockdown

Explain that this blocks ordinary new installs **and updates**, including those requested by the two streaming apps. It is useful for a fixed setup; it is not an antivirus or a substitute for trustworthy patched firmware.

```sh
python3 host/superbox.py lockdown --device "$SBC_DEVICE" --root --apply --state "$SBC_STATE/lockdown"
```

This records original restrictions/appops in a root-only device file without overwriting that snapshot on repeat execution, denies the two streaming apps' `REQUEST_INSTALL_PACKAGES` operation, and sets `no_install_apps`/`no_install_unknown_sources`. Inspect the saved after-state. Test a normal install with a known, trusted test APK if available; the expected error is `User restriction prevents installing`. Don't download an arbitrary APK just to test a block.

## 9. Optional removal of app-accessible root

Only on the exact reference layout, **after** key auth, the persistent firewall, a fresh authenticated `adb root`, and reboot/recovery checks have passed. Save separate verified private backups of `/system/xbin/su`, `/system/xbin/daemonsu`, and `/system/bin/rootsudaemon.sh` first. If privileged services or retained apps depend on these tools, investigate before removal.

```sh
adb -s "$SBC_DEVICE" root
adb -s "$SBC_DEVICE" wait-for-device
adb -s "$SBC_DEVICE" push runtime/remove-app-root.sh /data/local/tmp/sbc-remove-app-root.sh
adb -s "$SBC_DEVICE" shell sh /data/local/tmp/sbc-remove-app-root.sh
adb -s "$SBC_DEVICE" reboot
```

It moves the tools into a separate root-only directory, replaces their startup script with a no-op, and kills existing daemons. It refuses to overwrite an earlier root-tools quarantine. Authenticate again, verify no `su`/`daemonsu` reappeared, no daemon is running, playback still works, and authenticated `adb root` still works. `chmod su` alone was undone by the reference firmware. This procedure does not remove every privileged service or make SELinux enforcing. Do not enable enforcing blindly on this vendor build.

Return ADB to its normal shell UID with `adb unroot` when privileged verification is finished. The authorized key can still request root maintenance later, so protect it.

## 10. Final acceptance

Reboot, then make a fresh private audit/verification (use root diagnostics only through the authenticated maintenance channel if required):

```sh
python3 host/superbox.py verify --device "$SBC_DEVICE" --state "$SBC_STATE/final"
```

Check all of the following; the helper's JSON is not a blanket pass/fail certificate:

- Actual boot completion and matching device identity/firmware; root filesystem read-only after maintenance.
- No identified active files/process executables or respawn services. Scan executable links/hashes, not only names; root malware can disguise names or lie about results.
- Effective install restrictions and appops if requested, including after reboot. Verify a known installer is blocked where feasible.
- An unsigned ADB connection returns AUTH; authorized laptop reconnects; exact IPv4/IPv6 firewall source/port rules survived reboot.
- Both streaming apps open and play video; required WebView remains valid; handset Home/Back/arrows/OK, power/standby/wake, and Settings still work. Distinguish catalog loading from playback.
- Remove any temporary repair app, public-key staging file, temporary archives/scripts, and installation-test APK. Keep private host backups. Do not remove the final runtime scripts or authorized-key store.
- Record what was physically tested versus inferred. A software reboot is not a witnessed wall-power cold boot. No clean firmware attestation is provided.

## Recovery and maintenance

**Firewall rollback before persistence:** the detached watchdog removes this project's INPUT hooks after 90 seconds unless confirmed. Don't disable its timer until a new connection works.

**Persistent access rollback:** from an existing authorized root channel, remove only the `SBC_ACCESS` INPUT jumps for IPv4/IPv6, remove/disable `/system/etc/init/sbc-access.rc` and `/system/etc/sbc-access.sh` while `/` is briefly writable, and remount read-only. Use `iptables -D INPUT -j SBC_ACCESS`/`ip6tables -D INPUT -j SBC_ACCESS` rather than flushing the device firewall. This restores access exposure; retain key auth and correct the policy before ordinary use.

**If all network access is lost:** do not factory-reset or flash unknown firmware. Inspect physical on-screen settings. A local repair application/terminal can undo only the known project firewall changes if an existing authorized root path remains; installation lockdown must be considered. A genuinely documented USB debug/OTG port may provide another authorized channel. Do not promise this on USB1/USB2 labels alone or use unsafe host-to-host cabling. There is no included universal USB or malware-removal APK. If there is no remaining channel, physical/model-specific recovery is required; stop rather than inventing access.

**Maintenance installs:** while authenticated as root, run:

```sh
python3 host/superbox.py allow-installs --device "$SBC_DEVICE" --root --apply --state "$SBC_STATE/restore-install-policy"
```

This restores the recorded prior restrictions/appops; if they were already blocked, it preserves that. It refuses to guess if the snapshot is absent. Keep Play Store/vendor update removals in mind: lifting restrictions doesn't reinstall them. Review and verify any new APK/update, then run `lockdown` again with a fresh state directory and recheck playback. This does not fetch or patch streaming apps.

**App removal rollback:** use the saved installation/enabled-state record. A removed factory package can usually be restored with `cmd package install-existing --user 0 PACKAGE`; a disabled Chrome activity with `pm enable --user 0 COMPONENT`. Don't blanket-enable all packages; that can restart unwanted vendor code. No automatic bulk restore is included.

**Quarantine:** backups are for forensic review and expert recovery, not an automatic “restore malware” button. Inspect and validate a specific legitimate file before restoration. Do not return the identified payloads, Door/Notes wrappers, or their startup scripts to service. Preserve original quarantine/backup metadata after partial failures.

**App-root tools:** removing app root is separate from quarantine. If genuinely needed later, an authorized ADB root channel can restore the previously backed-up legitimate tools after review. This reintroduces an attack surface; don't restore them to resolve a cosmetic launcher issue.
