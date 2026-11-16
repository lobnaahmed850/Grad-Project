#!/bin/sh
# Route lab traffic through the local router, then idle. The attacks are launched from the host
# with docker compose exec, so nothing runs here on its own.
set -e
ip route replace 10.10.0.0/16 via "$GATEWAY"
exec sleep infinity
