# Validation command ledger

Executed in `/home/mahmoud/dev/isd/mentorship/ai-netguard` on November 16, 2026.
Tokens are intentionally omitted. Paths below identify the actual environments
and artifacts; raw shell debug output is not an exhaustive terminal transcript.
The result files and technical report distinguish successful and failed attempts.

## Environment and baseline

The first baseline used the preserved sibling's Python:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  /home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/demos/.venv/bin/python \
  -B -m pytest network-anomaly-detection/tests -q -p no:cacheprovider
```

The original local-CSV evaluation was reproduced with:

```bash
/home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/demos/.venv/bin/python \
  -B network-anomaly-detection/tools/eval_lab.py \
  --lab 'network-anomaly-detection/localdata/*.csv' \
  --if-model network-anomaly-detection/models/iforest_v0.1.0.joblib \
  --rf-model network-anomaly-detection/models/random_forest_final.joblib \
  --out network-anomaly-detection/reports/integration/legacy-reproduced.json
```

A dedicated repository environment was subsequently created:

```bash
/home/mahmoud/.local/share/uv/python/cpython-3.11.17-linux-x86_64-gnu/bin/python3.11 \
  -m venv .venv
.venv/bin/pip install -r network-anomaly-detection/requirements.txt
```

## Captures and frozen model selection

The initial collection used the sibling Python executable above:

```bash
python -B network-anomaly-detection/tools/collect_sessions.py \
  --manifest artifacts/sessions/release-v1.json \
  --normal-runs 3 --attack-runs 2 --seconds 5
python -B network-anomaly-detection/tools/train_release.py \
  --manifest artifacts/sessions/release-v1.json
```

The `python` shorthand in that block denotes the sibling executable, not an
unrecorded system interpreter. An initial calibration attempt failed the latency
gate. Numeric conversion was optimized before final-test feature access; the
failed calibration is retained.

After a fresh concurrent workload exposed 6.0% benign false alarms, a new
dataset was captured. It does not reuse the first release's final captures:

```bash
/home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/demos/.venv/bin/python \
  -B network-anomaly-detection/tools/collect_sessions.py \
  --manifest artifacts/sessions/release-v2.json \
  --normal-runs 4 --mixed-runs 2 --attack-runs 2 --seconds 12
```

## Container builds

Registry access initially failed. Offline contexts were prepared with:

```bash
/home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/demos/.venv/bin/python \
  -B network-anomaly-detection/tools/prepare_offline_runtime.py /tmp/netguard-runtime-build-v3
docker build --builder default --pull=false --network none \
  -t netguard-runtime:integration /tmp/netguard-runtime-build-v3
```

The same preparation/build sequence was used for contexts ending in `v1` and
`v2` while fixing startup and capture behavior. Existing contexts were preserved.
Standard networked builds subsequently succeeded:

```bash
docker build --builder default -f Dockerfile -t netguard-runtime:standard-verified .
docker build --builder default \
  -f network-anomaly-detection/lab/host.Dockerfile \
  -t netguard-lab-host:standard-verified network-anomaly-detection/lab
```

## Live validation

All Compose commands inherit the local `NETGUARD_TOKEN`.

```bash
docker compose -f network-anomaly-detection/lab/integration/compose.yml \
  --profile serving up -d --no-build ingest sensor
python -B network-anomaly-detection/tools/demo_integration.py
python -B network-anomaly-detection/tools/load_check.py --seconds 10
```

These runs initially used the sibling Python; later release-specific evidence
uses `.venv/bin/python`. The live-demo tool itself executes bounded client
traffic, UDP fixture messages, ingestion stop/start and sensor stop/start, then
asserts durable recovery and actual postrestart model verdicts.

## Benchmarks and UI

The initial CPU comparison used the preserved sibling Python:

```bash
python -B network-anomaly-detection/tools/benchmark_system.py \
  --pcap artifacts/sessions/test-benign-3000-1794843667025731908.pcap \
  --out network-anomaly-detection/reports/integration/benchmark.json \
  --legacy-if network-anomaly-detection/models/iforest_v0.1.0.joblib \
  --legacy-rf network-anomaly-detection/models/random_forest_final.joblib
```

Authenticated Chromium checks exercised both source filters, expandable evidence
and desktop/mobile viewport bounds:

```bash
CHROMIUM_PATH=/home/mahmoud/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome \
  node --experimental-websocket network-anomaly-detection/tools/check_dashboard.mjs
```

The topology SVG was also rendered in headless Chromium and inspected visually.
Screenshots are local artifacts, not public traffic or production evidence.

## Full regression suite

```bash
PYTHONDONTWRITEBYTECODE=1 \
IF_MODEL_PATH=/home/mahmoud/dev/isd/mentorship/ai-netguard/network-anomaly-detection/models/iforest_v0.1.0.joblib \
LEGACY_CANDIDATE_DIR=/home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/models/candidates \
.venv/bin/python -B -m pytest network-anomaly-detection/tests \
  -q -p no:cacheprovider --basetemp=/tmp/netguard-final-118 \
  --junitxml=network-anomaly-detection/reports/lab-v2/tests.xml
```

Final result: 118 passed, 0 failed, 0 skipped.

## Public Friday parity and saved-model diagnostic

```bash
PCAP=/home/mahmoud/dev/isd/mentorship/ai-netguard-ml-fix/network-anomaly-detection/data/raw/pcap/Friday-WorkingHours.pcap
ZIP=artifacts/public-validation/GeneratedLabelledFlows.zip
.venv/bin/python network-anomaly-detection/tools/parity_check.py "$PCAP" "$ZIP" \
  --day Friday --profile training \
  --out artifacts/public-validation/friday-full
.venv/bin/python network-anomaly-detection/tools/e2e_real_traffic.py "$PCAP" "$ZIP" \
  --day Friday \
  --if-model network-anomaly-detection/models/iforest_v0.1.0.joblib \
  --rf-model network-anomaly-detection/models/random_forest_final.joblib \
  --heldout-if <cached holdout_if.parquet> --heldout-rf <cached holdout_rf.parquet> \
  --cache artifacts/public-validation/e2e-cache \
  --out network-anomaly-detection/reports/integration/friday-e2e-reproduced.json
```

Exact arguments and input hashes are recorded in
`network-anomaly-detection/reports/integration/friday-provenance.json`.

Python modules were parsed with `ast`, notebook files with `json`, and the SVG
with `xml.etree.ElementTree`. Git ignore rules were checked explicitly for raw
captures, original models and the intentionally included release artifact.
