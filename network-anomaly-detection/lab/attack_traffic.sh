#!/usr/bin/env bash
# Generate ATTACK traffic from server-a (10.10.1.10) against server-b (10.10.3.10) and save it
# from the r1-r2 link, the same link the benign capture uses. This gives attack and normal
# traffic measured on ONE network, which is what the detector needs to be trained and tested on.
#
# Isolated lab only: every network in docker-compose.yml is `internal: true`, the only target is
# our own container, and each attack is bounded (fixed packet/request counts, no open-ended flood).
# The tools are standard and published -- nmap, nping (ships with nmap) and curl -- and this is how
# the CICIDS2017 training set itself was generated, so the test matches what the model was trained on.
#
# Each attack is written to its own pcap so every flow in a file has a known label.
# Usage: lab/attack_traffic.sh <prefix>
#   writes lab/captures/<prefix>_scan.pcap, <prefix>_httpflood.pcap, <prefix>_synflood.pcap
set -euo pipefail
cd "$(dirname "$0")"
prefix="$1"
compose="docker compose"
victim=10.10.3.10
# Keep only traffic between the two lab subnets (drops host-bridge multicast), same as the benign capture.
filter='(tcp or udp) and ((src net 10.10.1.0/24 and dst net 10.10.3.0/24) or (src net 10.10.3.0/24 and dst net 10.10.1.0/24))'

iface=$($compose exec -T capture sh -c "ip -o -4 addr show | awk '/10\.10\.2\.2/ {print \$2}'")

start_capture() {
  $compose exec -d -T capture tcpdump -i "$iface" -U -s 128 -w "/captures/$1.pcap" "$filter"
  sleep 1
}
stop_capture() {
  sleep 1
  $compose exec -T capture pkill -INT tcpdump || true
  sleep 1
  $compose exec -T capture chown "$(id -u):$(id -g)" "/captures/$1.pcap"
  ls -la "captures/$1.pcap"
}

echo "== PortScan: nmap SYN scan over 10,000 ports =="
start_capture "${prefix}_scan"
$compose exec -T server-a nmap -sS -T4 -n --max-retries 1 --host-timeout 120s -p 1-10000 "$victim" >/dev/null || true
stop_capture "${prefix}_scan"

echo "== HTTP flood: 20 workers x 200 GETs against nginx =="
start_capture "${prefix}_httpflood"
$compose exec -T server-a sh -c '
  for w in $(seq 20); do
    ( for i in $(seq 200); do curl -s -o /dev/null --max-time 5 "http://'"$victim"':8080/"; done ) &
  done
  wait' || true
stop_capture "${prefix}_httpflood"

echo "== SYN flood: nping half-open SYNs across 800 source ports (bounded) =="
# Spread the SYNs over many source ports so the extractor sees many short flood flows,
# the way a real multi-source SYN flood looks, instead of one giant flow.
start_capture "${prefix}_synflood"
$compose exec -T server-a sh -c '
  for w in $(seq 20); do
    ( base=$((20000 + w * 40))
      for off in $(seq 0 39); do
        nping --tcp -p 8080 --flags syn -g $((base + off)) -c 15 --rate 1500 -N -q "'"$victim"'" >/dev/null 2>&1
      done ) &
  done
  wait' || true
stop_capture "${prefix}_synflood"

echo "done: lab/captures/${prefix}_{scan,httpflood,synflood}.pcap"
