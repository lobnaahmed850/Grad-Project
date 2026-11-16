# AI-NetGuard engineering and validation report

Date: November 16, 2026. Branch: `engineering/integrated-netguard`, originally
based on `origin/AI` at `0c4d86c`. Scope: an integrated, reproducible Linux Docker
laboratory with actual packet capture, model inference, syslog ingestion,
persistent events and a browser console. Production readiness is not established.

## What was broken and what changed

| Finding | Root cause | Implemented change | Evidence |
|---|---|---|---|
| Main collector and ML were disconnected | Separate branches/notebooks had no runtime integration boundary | Independent syslog and ML inputs converge on a common event API/store | Actual UDP + HTTP tests and live demo |
| Chosen defaults differed from successful experiments | Named candidate files were selected instead of a reproducible release | Immutable release bundle, frozen evaluation, checksum/schema/version checks and current pointer | Default-loader tests and live sensor checksum assertion |
| Source rate contained future information | Entire-capture first/last timestamp calculation | Bounded causal rolling source-start count, sampled at flow start | Prefix-invariance, expiry, ordering and capacity tests |
| Attack evaluation leaked runs | Randomly split flows from the same captures | Separate whole training/calibration/test runs; duplicate screening | Capture manifest, selection/evaluation files and leakage tests |
| Offline extraction could not serve packets | No active-flow lifecycle or durable delivery | Shared streaming engine, bounded Linux packet ring, inference queue and SQLite outbox | Actual live traffic and replay/compatibility tests |
| Direction and flag meanings were wrong | Legacy CICFlowMeter first-packet behavior and training flag ordering | Preserved verified compatibility extractor, contract and CSV repairs | Known-answer tests and reproduced legacy CSV evaluation |
| Cisco/Linux/Windows parsing was unreliable | Timestamp fallbacks, content substring attribution and missing formats | Structured parsers, configured timezone, rollover rules and quarantine | Regression fixtures and real UDP ingestion |
| Initial live capture dropped bursts | Small per-packet socket receive buffering | Bounded 32 MiB TPACKET_V2 capture ring | Live kernel-drop/truncation counters |
| Durable delivery created avoidable delay | Per-event SQLite transactions and HTTP requests | Atomic outbox/ingestion batches and batched acknowledgments | Preserved before/after load measurements |
| No common observable application existed | JSONL output and notebook-only decisions | Authenticated API, WAL storage, diagnostics and responsive dashboard | Browser checks with actual stored ML and syslog events |

The existing sibling `ml-pipeline-fix` worktree and original serialized IF/RF
artifacts were preserved. Its earlier extraction/repair work was imported before
integration changes. The original public-data model files were not overwritten.
The release's intentional API and four-class scope changes are documented in
[the architecture guide](architecture-and-validation.md).

## Baseline and the failed first release

The imported baseline initially produced 43 passing tests and one optional-model
skip. Supplying the preserved legacy artifacts enabled full coverage later.

Reproducing the older local-CSV evaluation found **99 usable benign flows** in
this checkout, compared with the earlier report's 108. They are different
inventories. The saved models flagged 100% of the uncorrected benign rows and
53.54% after both CSV repairs. Correct attack typing after repair was about
91.86%, dominated by port scans. Repair is not a substitute for recapturing
unrecoverable fields.

The first integrated model, `lab-v1`, used 27 independent five-second captures.
Its novel-flow test had 1.90% FPR, but a new concurrent benign/flood workload
exposed **6.01% FPR** (11/183 benign flows). This failed the 3% quality target
despite successful processing. The failure is retained in
`reports/integration/load-lab-v1.json`; it was not removed by threshold tuning.

The response was to collect a **new dataset**, with longer runs and concurrent
normal/flood sessions labeled by actor. The new final captures were not reused
from the inspected first-release test. The classifier/threshold recipe was
selected on the new calibration sessions before opening final-test features.

## Active model and independent evaluation

The application default is **`lab-v2`**, selected as
`causal-rf64-confidence-0.5`: 64 trees, maximum depth 12, minimum leaf size 2,
balanced subsample class weights and fixed seed 42. The imputer is fitted only
on training sessions. The bundle has 41 ordered features, including causal source
flow rate, and occupies 244,543 bytes for `model.joblib`.

An RF-only recipe won the declared calibration policy. The historical parallel
confidence-0.9 design remains available explicitly for research, but is not
silently substituted for this evaluated default. Vote confidence is not a
guaranteed calibrated probability.

The new dataset contains **36 independent capture sessions**, 12 per role:
four benign, two mixed benign/flood, two scan, two flood and two slow-HTTP runs.
Collection used 12-second scenarios, with scans allowed to finish their bounded
port list earlier. There are 38,873 training rows, 29,205 primary calibration
rows, and 26,097 primary final-test rows.

Final metrics exclude 14,421 feature fingerprints matching earlier roles from
40,518 total independently captured test rows. Secondary metrics on all rows
and metrics for each session are retained. Fingerprints use signed-log1p values
rounded to three decimals; they are not an exhaustive nearest-neighbor leakage
proof. All admitted captures have verified hashes and zero reported capture
loss. One lossy attempt was rejected and rerun with a larger capture buffer;
the valid prefix was preserved through checked resume.

| Final novel-flow measure | Measured result |
|---|---:|
| Binary confusion matrix, `[[TN, FP], [FN, TP]]` | `[[977, 4], [48, 25068]]` |
| False positive rate | 0.4077% |
| Descriptive 95% Wilson interval | 0.1587–1.0437% |
| Binary precision | 99.9840% |
| Binary recall | 99.8089% |
| Binary F1 | 99.8964% |
| False negative rate | 0.1911% |
| Mean attack-category detection rate | 99.9352% |
| Category macro F1, including benign | 99.2407% |

| True class | Flows | Precision | Type recall | F1 |
|---|---:|---:|---:|---:|
| BENIGN | 981 | 95.3171% | 99.5923% | 97.4078% |
| HTTP_FLOOD | 24,704 | 99.9838% | 99.7976% | 99.8906% |
| PORT_SCAN | 297 | 99.3311% | 100% | 99.6644% |
| SLOW_HTTP | 115 | 100% | 100% | 100% |

HTTP-flood detection recall is 99.8057%; two detected flows received a different
attack type, explaining its slightly lower type recall. Whole-session results
are available in the evaluation file. Serialization/reload predictions were
identical. The loader and live demonstration both verify the selected version
and exact model SHA-256.

These intervals describe flow proportions. Correlated flows within the same
run violate independent-trial assumptions, and all runs occurred on one host on
one day. This is laboratory evidence, not a production confidence guarantee.

## Live system and reliability

The Compose environment includes two normal clients, a controlled simulator,
HTTP/DNS/SSH server, capture container, live ML sensor, ingestion service,
SQLite volumes and dashboard. Traffic and management networks are internal.
Only ingestion joins the separate dashboard bridge, with the published port
bound to `127.0.0.1:8090`. That service can have an outbound route; traffic
generators do not. There is no Cisco router, Windows VM or external attack target.

The sensor observes the server namespace; it is not an inline network gateway.
It uses explicit interface/subnet/server configuration. Flows terminate on RST,
both FIN directions, idle/active timeout, capacity eviction or shutdown.
Memory bounds cover active flows, source context, queues and capture buffers.
Late timestamps are rejected and counted rather than silently reordered.

The live demonstration uses new actual HTTP/DNS/SSH, scan, HTTP-flood and
slow-header traffic. Its network alerts come from extracted packets and the
real released classifier. Three Linux/Cisco/Windows-format syslog datagrams are
separate format fixtures; an unsupported datagram is quarantined. Both input
types reach the same persistent store and console.

Reliability validation stops ingestion while producing traffic, observes durable
pending events, restarts ingestion and verifies drain without losing stored
records. It then gracefully restarts the sensor and requires fresh captured
traffic to produce new stored verdicts. The outbox survives restart; in-memory
partial packet flows do not survive a crash. UDP logs are inherently
unacknowledged.

Local automated coverage includes malformed frames/captures/logs, invalid
timestamps, queue overflow, flow/source capacity, source expiry and ordering,
model corruption/schema/version failures, empty evaluation, batch atomicity,
idempotency, retention and durable acknowledgments. The final local regression
suite produced **118 passed, zero failed, zero skipped** with original artifacts
supplied; JUnit evidence is retained in
`network-anomaly-detection/reports/lab-v2/tests.xml`.

### Fresh live outcomes

After durable-outbox batching, the sequential demonstration observed 59 benign
flows with no false alarms, 400 scan flows with 100% detection, 3,253 flood flows
with 99.4159% detection, and 38 slow-HTTP flows with 100% detection. It stored
both event sources, verified 200 pending events during ingestion outage and
successful replay, then verified actual verdicts after sensor restart. The
small per-scenario normal sample is not a population FPR guarantee.

The final concurrent ten-second normal/flood workload produced **7,095 stored
verdicts**: `[[174,3],[20,6898]]`, **1.6949% normal false alarms** (3/177) and
**99.7109% flood detection** (6,898/6,918). Its descriptive FPR Wilson interval is
0.5781–4.8641%, so this short additional run does not statistically establish a
true rate below 3%. The point-estimate quality gate passed.

The workload reported zero kernel drops, ring truncations, inference errors,
queue drops and outbox drops. It also counted **71 late packets**, which the
declared event-time policy rejected; zero kernel loss must not be described as
lossless packet processing. The sequential demo counted 34 late packets.
Source/flow capacity evictions were zero under the measured concurrent load.

## Performance definition and CPU benchmark

Hardware: Intel Core i7-13650HX, 20 logical CPUs; Linux 6.12.107 Debian host.
Python 3.11.17, sklearn 1.9.1, numpy 2.4.6, pandas 3.0.6, joblib 1.5.3.
The runtime container and lab services have explicit CPU/memory/PID limits.

The CPU benchmark uses actual extracted capture rows, warm loaded models and
100 single-flow repetitions. Its single-flow definition includes release
preprocessing and prediction, excluding packet arrival, flow completion, queue,
network delivery and database storage.

| Inference path | Mean | Median | P95 | P99 | Maximum |
|---|---:|---:|---:|---:|---:|
| Preserved legacy serial pipeline | 32.098 ms | 30.914 ms | 36.340 ms | 60.586 ms | 61.332 ms |
| Active release, one flow | 4.161 ms | 4.133 ms | 4.369 ms | 4.500 ms | 4.623 ms |

Both models were loaded once. The original large Isolation Forest and
per-flow processing are expensive; model loading per request was not used to
inflate the baseline. The new model has a narrower class scope and architecture,
so this is not a claim of equal full-vocabulary coverage at lower cost.

Batch 32 averaged 4.289 ms total (0.1340 ms/flow; theoretical prediction-only
throughput 7,460 flows/s). Batch 256 averaged 4.805 ms total (0.01877 ms/flow;
53,279 flows/s). These are CPU prediction measurements, not complete-system
throughput or a latency guarantee for a flow waiting for its batch.

The 5 ms gate passed for this warm, quiet single-flow CPU definition. It does
**not** pass as a general live packet-to-alert guarantee. Idle timeout alone is
one second, and live queueing, durable delivery and service contention add time.
The JSON reports provide mean, median, P95, P99, maximum, throughput, CPU, RSS,
queue depth, drop counters and accuracy under concurrent workload.

### Live latency under concurrent load

Transactional outbox enqueue/acknowledgment batches reduced observed mean
last-packet-to-delivery latency from **1,838 ms to 439 ms**, and its P95 from
2,808 ms to 1,120 ms. These are different fresh realizations of the same
bounded workload, with the same model and thresholds, not a paired packet-by-
packet speed experiment. Pre-optimization measurements are retained.

| Final live stage | Mean | Median | P95 | P99 | Maximum in retained samples |
|---|---:|---:|---:|---:|---:|
| Queue wait | 8.003 ms | 6.664 ms | 16.658 ms | 23.514 ms | 43.905 ms |
| Inference batch | 8.600 ms | 7.167 ms | 15.053 ms | 25.154 ms | 47.610 ms |
| Flow completion wait | 361.883 ms | 0 ms | 1,020.009 ms | 1,046.255 ms | 1,052.209 ms |
| HTTP batch delivery | 19.554 ms | 18.110 ms | 28.510 ms | 39.809 ms | 55.558 ms |
| Last packet to acknowledged delivery | 438.614 ms | 105.297 ms | 1,120.154 ms | 1,146.762 ms | 1,195.638 ms |

Live percentiles retain at most the last 4,096 samples per stage. Inference
batch measurements had 497 samples; the larger event-level stages retain the
last 4,096 of 7,095 verdicts. Delivery measurements cover a transaction batch,
not independent per-event CPU cost. Capture-row extraction timings include the
enclosing flow update; the offline benchmark isolates row construction.

The sensor's observed peak RSS was 233.99 MiB under a 768 MiB limit; CPU time
averaged 57.61% of one core over 14.21 seconds of uptime. Docker's sampled
sensor CPU percentages during generation ranged from 62.91% to 70.37%.
The inference queue peaked at 41/2,048 rows. Processing throughput over this
uptime, including startup and drain, was 499.44 verdicts/s. This is an observed
bounded-workload rate, not a maximum sustainable-capacity claim.

Idle flow completion and durable storage dominate parts of end-to-end latency.
Even after optimization, the measured deployment does not provide a 5 ms
packet-to-alert SLO; under-load classifier P95 alone was 7.224 ms.

## Public Friday packet parity, reproduced

The full CICIDS2017 Friday capture (9 GB) was re-extracted with the current
extractor in 58 s: 702,803 flows against 703,245 published rows, of which
702,651 (99.92%) paired. All 76 compared features agreed on at least 99.891%
of paired rows. This is 98 fewer pairs than the earlier 702,749; the cause is
not attributed. Inputs and hashes: `reports/integration/friday-provenance.json`;
per-feature agreement: `reports/integration/experiments/friday-parity-reproduced.csv`.

The preserved original models were then scored on freshly extracted features
for the earlier cached held-out cohort (100,428 benign, 43,257 attack flows).
That cohort comes from the original random flow split, so it is a diagnostic of
extraction effects, not independent-session validation.

| Extraction path | IF false alarms | IF AUC | RF correct type | RF confidence |
|---|---|---|---|---|
| Training-correct | 1.807% | 0.9896 | 99.958% | 0.9995 |
| Lab tool defect | 96.890% | 0.8245 | 99.864% | 0.5270 |
| Defect, then repaired | 14.356% | 0.9674 | 99.947% | 0.9482 |

62 of 78 RF features were recovered to at least 99% accuracy by the CSV repair.
Results: `reports/integration/friday-e2e-reproduced.json`. Other days and the
team's exact Java build remain unverified.

## Reproducibility and review artifacts

- Actual default: `network-anomaly-detection/models/releases/current.json`.
- Immutable evaluated artifact: `models/releases/lab-v2/{manifest.json,model.joblib}`.
- Final evidence: `network-anomaly-detection/reports/lab-v2/`.
- Baseline, first-release failures and rejected capture:
  `network-anomaly-detection/reports/integration/`.
- Raw captures/manifests remain locally under `artifacts/sessions/`, ignored by
  Git; capture provenance is also embedded in the release manifest.
- [Exact principal commands and interpreter paths](validation-commands.md).
- [Architecture, causal features, schema and migration](architecture-and-validation.md).
- [Run, collect, train, evaluate and benchmark](../network-anomaly-detection/README.md).
- [Topology](network-topology.svg).

The standard networked runtime and host images built successfully. Early DNS
failures were worked around with an explicitly recorded offline environment;
that fallback is no longer the only verified build. Runtime dependencies are
pinned, including transitive dependencies, and the Python base image is pinned
by digest. Lab OS packages and random file content are not a bit-for-bit
hermetic build; image identities are recorded for actual captures.

GitHub CI configuration is provided, but no remote CI run, push or merge is
claimed. Historical notebooks are labeled as research; the release-validation
notebook reads the actual default manifest and evaluation rather than
recreating a random-flow split.

## Failures encountered and retained limitations

Failures were corrected at their source rather than suppressed: early capture
volume permissions, missing SSH chroot capability, capture-process reaping,
nonroot raw-socket capability behavior, internal-only bridge port publishing,
per-packet receive-buffer loss, per-event durable delivery, an empty-array metrics
exception, dashboard browser-profile cleanup and a Compose-stats CLI mismatch.
The first release's concurrent FPR failure and a capture with 12,734 dropped
packets remain explicit evidence. No dropped capture entered training.

Remaining production work:

1. Capture real normal and attack runs across days, machines, operating systems,
   subnets, rates and network conditions; retain PCAPs. This lab has no real
   Windows or Cisco devices and no production workload distribution.
2. Broaden and independently validate attack coverage. The active model does
   not cover the original Bot, credential attacks, SYN-flood family, Heartbleed,
   SQL injection or other original CICIDS classes. Preserve/reassess those
   legacy models separately; do not infer their performance from this release.
3. Validate unknown attacks and legitimate high-rate workloads. RF-only
   classification is not an open-set anomaly guarantee. Short GETs can represent
   legitimate or malicious activity; labels reflect bounded scenario provenance,
   not proof of service denial for each flow.
4. Extend or explicitly scope IPv6, ICMP, IP fragments, jumbo frames, VLAN
   offload metadata and capture points beyond this server. Current extraction
   supports complete Ethernet IPv4 TCP/UDP frames.
5. Decide and test operational latency SLOs, retention, disk capacity, TLS,
   credentials, authorization, high availability, monitoring, crash recovery and
   sustained-load capacity on deployment hardware. Counts and bounded buffers
   do not imply lossless operation at arbitrary load.
6. Extend public-data packet parity beyond Friday and obtain the team's exact
   Java extractor build before accepting tool-specific claims. The reproduced
   Friday check and known-answer tests do not validate every day, historical
   report, attack label or original tool build.

The original team pcaps/extractor build and production-like traffic are still
external evidence requirements. A successful Docker demonstration does not
remove them.
