#!/system/bin/sh
# Start detached BEFORE access-guard.sh. A fresh connection must create the marker.
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$#" = 1 ] || exit 2
case "$1" in /data/local/tmp/sbc-confirm-[a-f0-9]*) ;; *) exit 2;; esac
marker=$1
sleep 90
if [ ! -f "$marker" ]; then
 for fw in iptables ip6tables; do
  while $fw -C INPUT -j SBC_ACCESS 2>/dev/null; do $fw -D INPUT -j SBC_ACCESS || break; done
 done
fi
