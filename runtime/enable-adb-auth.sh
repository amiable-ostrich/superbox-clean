#!/system/bin/sh
# Optional reference-firmware helper. Adds a public key; never copies a private key.
# Usage: sh enable-adb-auth.sh /data/local/tmp/<your-staged-public-key>
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$(getprop ro.product.model)" = SuperBOX_S2PRO ] &&
[ "$(getprop ro.build.display.id)" = SuperBOX_S2PRO.20211214.V1.2.0 ] || exit 2
[ "$#" = 1 ] && [ -f "$1" ] && [ ! -L "$1" ] || exit 3
case "$1" in /data/local/tmp/*.pub) ;; *) exit 3;; esac
# ADB public-key field is base64, followed by an optional non-secret comment.
key=$(head -n 1 "$1" | cut -d ' ' -f1)
case "$key" in ''|*[!A-Za-z0-9+/=]*) echo 'Invalid public key field' >&2; exit 3;; esac
[ "${#key}" -eq 700 ] || { echo 'Expected an Android 2048-bit ADB public key, not a private key' >&2; exit 3; }
D=/data/local/superbox-clean
[ ! -L "$D" ] || exit 3
mkdir -p "$D"
chmod 700 "$D"
[ -e "$D/prop.default.before" ] || cp /system/etc/prop.default "$D/prop.default.before"
if [ -f /data/misc/adb/adb_keys ] && [ ! -e "$D/adb_keys.before" ]; then cp /data/misc/adb/adb_keys "$D/adb_keys.before"; fi
mount -o remount,rw /
trap 'mount -o remount,ro /' EXIT HUP INT TERM
grep -q '^ro.adb.secure=[01]$' /system/etc/prop.default || exit 4
sed -i 's/^ro.adb.secure=0$/ro.adb.secure=1/' /system/etc/prop.default
restorecon /system/etc/prop.default
mount -o remount,ro /
trap - EXIT HUP INT TERM
mkdir -p /data/misc/adb
# Preserve existing authorized keys. A duplicate is harmless on repeat execution.
printf '\n%s superbox-clean-management\n' "$key" >> /data/misc/adb/adb_keys
chown 1000:2000 /data/misc/adb /data/misc/adb/adb_keys
chmod 2750 /data/misc/adb
chmod 640 /data/misc/adb/adb_keys
restorecon -R /data/misc/adb
sync
echo 'AUTH_STAGED: reboot, reconnect using this key, and run auth_probe.py'
