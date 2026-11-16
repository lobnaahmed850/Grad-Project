#!/bin/sh
# Route lab traffic through the local router, then start ordinary services.
set -e
ip route replace 10.10.0.0/16 via "$GATEWAY"
/usr/sbin/sshd
# Naming the interface lets dnsmasq answer hosts on the other lab subnet.
dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --interface=eth0 \
    --address=/files.lab/10.10.3.10 --address=/www.lab/10.10.1.10
exec nginx -g 'daemon off;'
