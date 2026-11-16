#!/usr/bin/env bash
# Capture normal traffic at three link speeds, to see how much results depend on the network.
# Usage: lab/capture_profiles.sh [activities per worker]
# Writes lab/captures/benign_lan.pcap, benign_wan.pcap and benign_slow.pcap
set -euo pipefail
cd "$(dirname "$0")"
activities="${1:-200}"

./set_link.sh 250us 100mbit
./capture_benign.sh benign_lan "$activities" 2

./set_link.sh 2ms 50mbit
./capture_benign.sh benign_wan "$activities" 2

./set_link.sh 10ms 10mbit
./capture_benign.sh benign_slow "$activities" 2

./set_link.sh 250us 100mbit
