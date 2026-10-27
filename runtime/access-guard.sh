#!/system/bin/sh
# Usage: sh access-guard.sh <management computer's private IPv4>
# Stage and test live before installing a boot hook. No general network blocking.
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$#" = 1 ] || { echo 'Management IPv4 required' >&2; exit 2; }
management=$1
case "$management" in *[!0-9.]*|'') exit 2;; esac
oldifs=$IFS
IFS=.
set -- $management
IFS=$oldifs
[ "$#" = 4 ] || exit 2
for octet in "$@"; do
 case "$octet" in ''|0[0-9]*) exit 2;; esac
 [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || exit 2
done
case "$management" in
 10.*|192.168.*) ;;
 172.*) [ "$2" -ge 16 ] && [ "$2" -le 31 ] || exit 2;;
 *) exit 2;;
esac
for fw in iptables ip6tables; do
 $fw -N SBC_ACCESS 2>/dev/null || true
 $fw -F SBC_ACCESS
 if [ "$fw" = iptables ]; then
  for port in 5555 5858 63002; do
   $fw -A SBC_ACCESS -p tcp --dport "$port" -s "$management" -j ACCEPT
  done
 fi
 for port in 5555 5858 63002 12104; do
  $fw -A SBC_ACCESS -p tcp --dport "$port" -j DROP
 done
 $fw -A SBC_ACCESS -p udp --dport 12305 -j DROP
 $fw -A SBC_ACCESS -j RETURN
 $fw -C INPUT -j SBC_ACCESS 2>/dev/null || $fw -I INPUT 1 -j SBC_ACCESS
done
