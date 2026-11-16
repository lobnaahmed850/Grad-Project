#!/usr/bin/env bash
# Make the lab's links behave like real ones. Run this after every "docker compose up".
#   1. Turn off segmentation offload everywhere. Otherwise virtual interfaces merge packets,
#      and captures show "packets" of 50 KB that would never appear on a real network.
#   2. Give the r1-r2 link a realistic delay and speed.
# Usage: lab/set_link.sh [delay] [rate]     Default: 250us each way, 100mbit
set -euo pipefail
cd "$(dirname "$0")"
delay="${1:-250us}"
rate="${2:-100mbit}"

for service in server-a server-b server-c attacker client-a1 client-a2 client-b1 client-c1 capture r2-tools; do
  docker compose exec -T "$service" sh -c '
    for iface in $(ip -o link show | awk -F": " "\$2 != \"lo\" {print \$2}" | cut -d@ -f1); do
      ethtool -K "$iface" tso off gso off gro off 2>/dev/null || true
    done'
done

for pair in capture:10.10.2.2 r2-tools:10.10.2.3; do
  service="${pair%%:*}"
  address="${pair##*:}"
  iface=$(docker compose exec -T "$service" sh -c "ip -o -4 addr show | awk '/$address/ {print \$2}'")
  docker compose exec -T "$service" tc qdisc replace dev "$iface" root netem delay "$delay" rate "$rate"
  docker compose exec -T "$service" tc qdisc show dev "$iface"
done
