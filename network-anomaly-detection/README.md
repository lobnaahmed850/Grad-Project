# ML release and isolated laboratory

Run the following from the repository root with Python 3.11 and dependencies
pinned in `network-anomaly-detection/requirements.txt`.

## Start and demonstrate

```bash
export NETGUARD_TOKEN="$(openssl rand -hex 24)"
BUILDX_BUILDER=default docker compose \
  -f network-anomaly-detection/lab/integration/compose.yml \
  --profile serving up -d --build
.venv/bin/python network-anomaly-detection/tools/demo_integration.py
```

The console is at <http://127.0.0.1:8090>. The demo report is
`reports/integration/live-demo.json`. The lab captures only its own server-facing
traffic, not the host's network. Stop without deleting data:

```bash
docker compose -f network-anomaly-detection/lab/integration/compose.yml \
  --profile serving down
```

The older router lab in `lab/compose.yml` remains historical. The recommended
integration lab does not require its router images or broad privileges.

## Collect a new dataset

Do not overwrite the original release manifest. Choose fresh paths and preserve
the raw PCAPs, which are deliberately ignored by Git.

```bash
.venv/bin/python network-anomaly-detection/tools/collect_sessions.py \
  --manifest artifacts/sessions/next-release.json \
  --normal-runs 4 --mixed-runs 2 --attack-runs 2 --seconds 12
```

This creates 36 role-assigned independent runs, including per-actor labels in
concurrent normal/flood captures. The tool rejects kernel capture loss and can
resume a verified manifest prefix with the same arguments plus `--resume`.
These runs are a demonstration minimum, not sufficient production-normal coverage. Capture more
days, hosts, legitimate high-rate workloads and attack families for real claims.

## Train, calibrate, evaluate and export

```bash
.venv/bin/python network-anomaly-detection/tools/train_release.py \
  --manifest artifacts/sessions/next-release.json \
  --release network-anomaly-detection/models/releases/lab-v3 \
  --reports network-anomaly-detection/reports/lab-v3
```

The tool refuses to overwrite release directories. It freezes calibration
selection before opening the final test, serializes fitted preprocessing with
the model, verifies reloaded prediction equality and promotes only on acceptance.
After inspecting test results, do not reuse those captures for another model
selection claim. The point-estimate acceptance gate is not a confidence-bound
guarantee or production-readiness decision.

`src.release.ReleaseModel.load_default()` and
`src.pipeline.TwoStagePipeline.load_chosen()` load the same active artifact.
Feature ordering, classes, units, source hashes, runtime versions, flow
configuration, thresholds and dataset provenance are stored alongside it.
Joblib is executable serialization; only load trusted artifacts.

## Replay and serve the same features

```bash
PYTHONPATH=network-anomaly-detection .venv/bin/python -c \
  "from src.release import ReleaseModel; from src.streaming import replay_capture; m=ReleaseModel.load_default(); f=replay_capture('capture.pcap',m.flow_config); print(m.predict(f))"
```

The flow engine supports Ethernet IPv4 TCP/UDP, bounded bidirectional state,
idle/active timeouts, FIN/RST/shutdown emission and causal source-start rate.
It drops/counts late timestamps. The default model serves server-ingress flows.
See the architecture guide for exact definitions, unsupported protocols and
the distinction from the legacy `extract_flows()` lifecycle.

Outside the isolated lab, interface and network scope must be explicit:

```bash
PYTHONPATH=.:network-anomaly-detection .venv/bin/python -m netguard.sensor \
  --interface lab0 --include-net 10.77.0.0/24 --server-ip 10.77.0.10 \
  --endpoint http://127.0.0.1:8090 --outbox runtime/outbox.sqlite
```

This requires an authorized observation interface and `NET_RAW`; the example
names the lab interface and will fail when that interface is absent.

## Tests and benchmarks

```bash
.venv/bin/python -m pytest network-anomaly-detection/tests -q -p no:cacheprovider
.venv/bin/python network-anomaly-detection/tools/benchmark_system.py \
  --pcap artifacts/sessions/your-benign-capture.pcap \
  --out network-anomaly-detection/reports/benchmark-new.json
```

Optional `--legacy-if` and `--legacy-rf` compare preserved original artifacts.
The live demo records actual packet-to-storage latency and diagnostics;
offline batch amortization does not include waiting for flows or a batch.

## Offline build fallback

If registry/package access is unavailable but a trusted Python 3.11 environment
and `ubuntu:26.04` are already cached:

```bash
.venv/bin/python network-anomaly-detection/tools/prepare_offline_runtime.py \
  /tmp/netguard-runtime-context
docker build --builder default --pull=false --network none \
  -t netguard-runtime:integration /tmp/netguard-runtime-context
docker compose -f network-anomaly-detection/lab/integration/compose.yml \
  --profile serving up -d --no-build
```

The host lab image `netguard-lab-host:1` must also exist or be built with network
access. The fallback copies the selected environment and records its packages;
it is not a universal hermetic build from an empty machine.

## Evidence and historical workflows

Current `lab-v2` results are in `reports/lab-v2/`; `reports/integration/` preserves
the baseline and first release, including its later concurrent-load failure.
The release-validation notebook
reads those files; older notebooks display historical warnings.
The original model files, raw public data and captures remain local and ignored.
[Historical repair/extractor workflow](../docs/legacy-ml-workflow.md) retains
known-answer checks and legacy CSV evaluation commands.
