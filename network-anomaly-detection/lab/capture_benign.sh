#!/usr/bin/env bash
# Generate normal traffic in both directions and save it from the r1-r2 link.
# The filter keeps only traffic between the two lab subnets, which excludes
# multicast that the host computer sends onto the Docker bridge.
# Usage: lab/capture_benign.sh <name> [activities per worker] [workers per direction]
# Writes lab/captures/<name>.pcap
set -euo pipefail
cd "$(dirname "$0")"
name="$1"
activities="${2:-20}"
workers="${3:-2}"
compose="docker compose"

iface=$($compose exec -T capture sh -c "ip -o -4 addr show | awk '/10\.10\.2\.2/ {print \$2}'")
$compose exec -d -T capture tcpdump -i "$iface" -U -s 128 -w "/captures/$name.pcap" \
  '(tcp or udp) and ((src net 10.10.1.0/24 and dst net 10.10.3.0/24) or (src net 10.10.3.0/24 and dst net 10.10.1.0/24))'
sleep 1

for _ in $(seq "$workers"); do
  $compose exec -T server-a benign_traffic.sh 10.10.3.10 "$activities" &
  $compose exec -T server-b benign_traffic.sh 10.10.1.10 "$activities" &
done
wait

sleep 1
$compose exec -T capture pkill -INT tcpdump
sleep 1
$compose exec -T capture chown "$(id -u):$(id -g)" "/captures/$name.pcap"
ls -la "captures/$name.pcap"
