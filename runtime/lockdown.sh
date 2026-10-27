#!/system/bin/sh
# Install restrictions only. Does not remove apps, root, or update firmware.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Existing root required' >&2; exit 1; }
[ "$(getprop ro.product.model)" = SuperBOX_S2PRO ] &&
[ "$(getprop ro.build.display.id)" = SuperBOX_S2PRO.20211214.V1.2.0 ] || exit 2
D=/data/local/superbox-clean
[ ! -L "$D" ] || exit 3
mkdir -p "$D"
chown 0:0 "$D"
chmod 700 "$D"
# Save the original base/effective policy conservatively; do not erase it on rerun.
if [ ! -e "$D/install-policy.before" ]; then
 policy=$(dumpsys user)
 : > "$D/install-policy.tmp"
 for flag in no_install_apps no_install_unknown_sources; do
  value=0
  if printf '%s\n' "$policy" | grep -q "^[[:space:]]*$flag[[:space:]]*$"; then value=1; fi
  printf '%s=%s\n' "$flag" "$value" >> "$D/install-policy.tmp"
 done
 for pkg in com.bluetv.live2 com.vodblue.vod2; do
  mode=$(cmd appops get "$pkg" REQUEST_INSTALL_PACKAGES | sed -n 's/^REQUEST_INSTALL_PACKAGES: \([a-z]*\).*$/\1/p' | head -n 1)
  case "$mode" in allow|deny|ignore|default|foreground) ;; *) mode=default;; esac
  printf '%s=%s\n' "$pkg" "$mode" >> "$D/install-policy.tmp"
 done
 chmod 600 "$D/install-policy.tmp"
 mv "$D/install-policy.tmp" "$D/install-policy.before"
fi
[ ! -L "$D/install-policy.before" ] || exit 3
for pkg in com.bluetv.live2 com.vodblue.vod2; do
 if pm list packages "$pkg" | grep -qx "package:$pkg"; then
  cmd appops set "$pkg" REQUEST_INSTALL_PACKAGES deny
 fi
done
pm set-user-restriction --user 0 no_install_unknown_sources 1
pm set-user-restriction --user 0 no_install_apps 1
# Device snapshots saved by the host include policy readback.
dumpsys user
echo 'INSTALL_LOCKDOWN_COMPLETE (normal app installation and updates are blocked)'
