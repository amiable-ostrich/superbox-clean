#!/system/bin/sh
# Last-stage optional hardening, after backups, key authentication, and reboot checks.
set -eu
[ "$(id -u)" = 0 ] && [ "$(getprop service.adb.root)" = 1 ] || { echo 'Use authenticated adb root first' >&2; exit 1; }
[ "$(getprop ro.product.model)" = SuperBOX_S2PRO ] &&
[ "$(getprop ro.build.display.id)" = SuperBOX_S2PRO.20211214.V1.2.0 ] || exit 2
[ "$(getprop ro.adb.secure)" = 1 ] && [ -s /data/misc/adb/adb_keys ] || exit 3
iptables -C INPUT -j SBC_ACCESS
ip6tables -C INPUT -j SBC_ACCESS
# This script is intentionally not called automatically by the host CLI.
Q=/system/superbox-clean-root-tools
[ ! -e "$Q" ] || { echo 'Already staged: inspect previous result; do not overwrite backups' >&2; exit 4; }
mount -o remount,rw /
trap 'mount -o remount,ro /' EXIT HUP INT TERM
mkdir "$Q"
chmod 700 "$Q"
for file in /system/xbin/su /system/xbin/daemonsu /system/bin/rootsudaemon.sh; do
 if [ -f "$file" ]; then mv "$file" "$Q/"; fi
done
printf '#!/system/bin/sh\n# App-accessible root daemon disabled by Superbox Clean.\nexit 0\n' > /system/bin/rootsudaemon.sh
chmod 755 /system/bin/rootsudaemon.sh
restorecon /system/bin/rootsudaemon.sh
chmod -R go-rwx "$Q"
mount -o remount,ro /
trap - EXIT HUP INT TERM
stop rootservice
for pid in $(ps -A -o PID,NAME | awk '/daemonsu/ {print $1}'); do kill -9 "$pid" 2>/dev/null || true; done
sync
echo 'APP_ROOT_REMOVED: reboot and verify before ending maintenance'
