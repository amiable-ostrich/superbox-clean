#!/system/bin/sh
# Restore the recorded original install policy, not an unconditional unlock.
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$(getprop ro.product.model)" = SuperBOX_S2PRO ] &&
[ "$(getprop ro.build.display.id)" = SuperBOX_S2PRO.20211214.V1.2.0 ] || exit 2
D=/data/local/superbox-clean
F=$D/install-policy.before
[ ! -L "$D" ] && [ ! -L "$F" ] && [ -f "$F" ] || { echo 'No recorded policy; do not guess' >&2; exit 3; }
# Validate all four records before changing any policy. Never source a device file.
[ "$(wc -l < "$F")" -eq 4 ] || exit 3
for flag in no_install_apps no_install_unknown_sources; do
 value=$(sed -n "s/^$flag=//p" "$F")
 case "$value" in 0|1) ;; *) exit 3;; esac
done
for pkg in com.bluetv.live2 com.vodblue.vod2; do
 mode=$(grep -F "$pkg=" "$F" | cut -d= -f2)
 case "$mode" in allow|deny|ignore|default|foreground) ;; *) exit 3;; esac
done
for flag in no_install_apps no_install_unknown_sources; do
 value=$(sed -n "s/^$flag=//p" "$F")
 pm set-user-restriction --user 0 "$flag" "$value"
done
for pkg in com.bluetv.live2 com.vodblue.vod2; do
 mode=$(grep -F "$pkg=" "$F" | cut -d= -f2)
 if pm list packages "$pkg" | grep -qx "package:$pkg"; then
  cmd appops set "$pkg" REQUEST_INSTALL_PACKAGES "$mode"
 fi
done
mv "$F" "$D/install-policy.restored"
dumpsys user
echo ORIGINAL_INSTALL_POLICY_RESTORED
