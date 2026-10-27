# Compatibility

## Reference boundary

Automatic mutations require all four properties below, checked on the live device:

| Property | Reference value |
| --- | --- |
| `ro.product.model` | `SuperBOX_S2PRO` |
| `ro.build.display.id` | `SuperBOX_S2PRO.20211214.V1.2.0` |
| `ro.build.version.release` | `9` |
| `ro.build.version.sdk` | `28` |

The reference firmware reported security patch `2019-02-05`. Those version fields are reported by the device; a compromised OS can lie. They are compatibility checks, not attestation.

`profiles/s2pro-20211214.json` contains SHA-256 hashes and sizes, never payload bytes. Quarantine also requires a device-bound saved audit, a fresh matching artifact hash, a verified local archive, and a final hash recheck immediately before mutation. The two packed boot-animation replacements are classified separately and require `--include-suspicious-boot-files`; their individual malware family was not established.

Reference mutations assume a writable/remountable **system-as-root ext4 `/`** layout, Android init `.rc` files, and the Android 9 command set. A successful `adb connect` or matching product name does not validate these assumptions. The agent must inspect mounts/tools before any mutation.

## Other versions

Discovery and inspection are intended to work with other Android-based boxes that expose an authorized ADB connection. They have not been tested on other Superbox hardware. The included diagnostic parser expects Android `getprop`, `pm`, `ps`, `sha256sum`, `dumpsys user`, and `dumpsys webviewupdate`. If these are unavailable, the helper stops and the agent must adapt the **read-only** audit. It must not silently continue with an empty inventory.

Different devices can use ADB 5555, 5858, 63002, another port, USB-only debugging, or no accessible debugging. An unavailable port is not a clean result. This project does not bypass pairing, exploit a device, unlock a bootloader, or supply replacement firmware.

No automatic mutations are claimed for other S2 builds or S3/S4/S5/S6/S7/S8 models. Keep the gate intact. Use an isolated guest network/VLAN that denies access to the rest of the LAN while investigating, where your router supports it. Such isolation alone does not stop internet proxy traffic. Router changes are outside the included helpers.

## Adding support

1. Get the owner's authorization and collect a private, redacted-by-hand hardware/firmware/mount/tool report. Do not publish raw audits or samples.
2. Establish root/management prerequisites without weakening authentication. Determine the actual persistent partition/init layout and WebView/launcher/playback dependencies.
3. Identify files by evidence and content hashes. Do not blacklist generic names such as Notes across devices. Verify provenance and avoid treating all vendor code as confirmed malware.
4. Add a separate profile and regression fixtures. Include mismatch, unknown-file, backup failure, interruption, rerun, firewall rollback, and preservation cases.
5. Add the new profile to explicit selection/gating logic; do not edit the S2 profile's expected model to get past a refusal. Update its documentation and checksums.
6. Record actual reboot, playback, handset, auth, and recovery results separately from unit tests. Mark untested steps clearly.

## Verified vs unverified

One S2 Pro was manually cleaned and rebooted multiple times. Blue TV and Blue VOD video playback was observed; known persistence and root-daemon removal, authenticated ADB, narrow IPv4/IPv6 rules, and installation restrictions were checked. Physical wall-power cold boot and every handset button were not independently exercised.

The reusable wrapper and snapshot/restore implementation in this repository have automated synthetic tests. They have **not** been rerun destructively on additional boxes or used to recreate an infection on the already-cleaned reference box. Tests validate the tool's control flow and failure handling, not the trustworthiness of an infected OS.
