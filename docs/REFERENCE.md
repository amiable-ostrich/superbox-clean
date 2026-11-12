# Reference investigation

A single SuperBOX S2 Pro on the firmware listed in COMPATIBILITY.md exposed unauthenticated network ADB and an app-accessible root utility. SELinux was permissive. The investigation found:

- Two processes named `netd_service` running executables from deleted memory-file objects. A saved executable contained a Kimwolf v7 version marker, blockchain RPC endpoints, an onion address, and network-attack identifiers. The profile includes its SHA-256 hash without redistributing it.
- `/system/etc/init/turbovpn.rc` launched `.netd_helper`, which enabled `com.android.door`, attempted administrator enrollment, disabled SELinux enforcement, altered ADB settings, started a service, and executed `.w`.
- Door and Notes APKs containing native executables and restart services, plus a separate `lolz.rc`/`bootington.sh` startup path.
- Recent, packed static replacements at the boot-animation paths. Those files were quarantined as suspicious replacements, not independently attributed to a malware family.

The observed artifacts were stopped and moved into a root-only quarantine, with local backups. Normal streaming packages and app data were preserved. The scan does not prove the original infection source or that personal data was stolen. No active DDoS attack was demonstrated during the observed snapshot.

## Operational lessons carried into this repository

The first broad firewall used an unsupported multiport extension. Its intended management exceptions were omitted while a final inbound drop remained; network access was lost. A locally built repair app, downloaded through the box's browser, restored access. That app was removed afterward; neither it nor its signing key is distributed here.

The reusable firewall protects only selected debugging/network-control ports, uses single-port matches, and has a detached rollback watchdog. It must pass a new connection before persistence. A property value alone is insufficient to prove auth: an unsigned ADB probe must return AUTH, and the authorized laptop must reconnect.

Changing `su` permissions alone did not persist. The final manual setup quarantined `su`/`daemonsu`, replaced their startup script with a no-op, killed existing daemons, and verified reboot. Authenticated ADB root remained available for maintenance. The project does not claim that removing these tools eliminates all privileged attack paths.

Chrome was the only WebView provider. Its package was retained, with browser entry activities disabled. Removing it outright could break retained apps. Both streaming apps include native components; Blue VOD includes P2P libraries. Those were not fully reverse engineered or certified free of unwanted traffic.

## Follow-up: additional qw root broker

On 2026-11-11, another root broker named `qw` was investigated on the same reference firmware. A controlled application-UID diagnostic demonstrated that a caller-controlled factory-test process name could obtain root. This was classified as an unsafe privileged helper, not attributed to the quarantined bot malware. It was subsequently stopped and quarantined with its startup file; absence, maintenance access, existing protections and sampled streaming playback were verified after reboot.

See [qw findings and manual remediation](QW.md) for exact artifact hashes, test limitations, dependency evidence and the automation boundary. The existing malware profile and root-tool removal script do not handle qw.

## External primary research

- [Plume: When Your TV Box Becomes Someone Else's Gateway](https://www.plume.com/newsroom/when-your-tv-box-becomes-someone-elses-gateway) — Superbox proxy behavior and insecure local interfaces.
- [Plume: Residential Proxy Networks as Malware Delivery Platforms](https://www.plume.com/newsroom/superproxy-how-residential-proxy-networks-have-become-malware-delivery-platforms) — follow-on malware delivery research.
- [Palo Alto Networks Unit 42: Kimwolf v7](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/) — independent Kimwolf technical analysis.
- [Nokia Deepfield: Aisuru ecosystem research](https://github.com/deepfield/public-research/blob/main/reports/2026-03-20-aisuru-ecosystem.md) — Door-wrapper/bot ecosystem analysis.
- [Google: Android Debug Bridge](https://developer.android.com/tools/adb) — official management tooling and authentication documentation.
- [REA](https://github.com/morluto/rea) — optional reverse engineering tooling. It is not a cleaner or required dependency; installing it does not make an unknown APK safe.

External reports support investigation; they do not establish that every Superbox model is infected or that all files sharing a name are malicious. No commercial streaming applications, firmware images, malware samples, keys, screenshots, IP addresses, or raw reports from the owner are included.
