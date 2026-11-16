#!/usr/bin/env bash
# Generate normal traffic from several clients across both subnets and capture it from the r1-r2
# link. lan_a sources talk to server-b, lan_b sources talk to server-a, so every flow crosses the
# monitored link. More sources and workers than capture_benign.sh, for a large, diverse normal set.
# Usage: lab/capture_benign_multi.sh <name> [activities per worker] [workers per source]
# Writes lab/captures/<name>.pcap
set -euo pipefail
cd "$(dirname "$0")"
name="$1"
activities="${2:-300}"
workers="${3:-2}"
compose="docker compose"
# Keep only traffic between the lab subnets (drops core and host-bridge multicast).
filter='(tcp or udp) and (src net 10.10.1.0/24 or src net 10.10.3.0/24 or src net 10.10.4.0/24) and (dst net 10.10.1.0/24 or dst net 10.10.3.0/24 or dst net 10.10.4.0/24)'

iface=$($compose exec -T capture sh -c "ip -o -4 addr show | awk '/10\.10\.2\.2/ {print \$2}'")
$compose exec -d -T capture tcpdump -i "$iface" -U -s 128 -w "/captures/$name.pcap" "$filter"
sleep 1

# Sources on each subnet reach servers on the other two, so flows cross the monitored link.
for _ in $(seq "$workers"); do
  for src in server-a client-a1 client-a2; do
    $compose exec -T "$src" benign_traffic.sh 10.10.3.10 "$activities" &
    $compose exec -T "$src" benign_traffic.sh 10.10.4.10 "$activities" &
  done
  for src in server-b client-b1; do
    $compose exec -T "$src" benign_traffic.sh 10.10.1.10 "$activities" &
  done
  for src in server-c client-c1; do
    $compose exec -T "$src" benign_traffic.sh 10.10.1.10 "$activities" &
  done
done
wait

sleep 1
$compose exec -T capture pkill -INT tcpdump
sleep 1
$compose exec -T capture chown "$(id -u):$(id -g)" "/captures/$name.pcap"
ls -la "captures/$name.pcap"
