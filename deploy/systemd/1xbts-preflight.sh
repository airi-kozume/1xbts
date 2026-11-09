#!/usr/bin/env bash
set -euo pipefail

# Docker starts the femtocell stack independently. Wait until its fixed edge
# network exists before adding the host route that depends on it.
for _ in $(seq 1 60); do
    if /usr/sbin/ip route show 172.31.0.0/24 | /usr/bin/grep -q ' dev '; then
        break
    fi
    sleep 1
done

if ! /usr/sbin/ip route show 172.31.0.0/24 | /usr/bin/grep -q ' dev '; then
    echo "1xBTS: femto-edge network did not appear within 60 seconds" >&2
    exit 1
fi

/usr/sbin/modprobe fou
/usr/sbin/modprobe ipip
exec /home/airi/1xbts/docker/femto/host-route.sh add
