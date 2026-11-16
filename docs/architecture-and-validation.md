# Architecture and validation contract

## Data flow

The sensor attaches to an explicitly named Linux Ethernet interface. A bounded
32 MiB TPACKET_V2 receive ring retains kernel packet timestamps; frames larger
than its 2048-byte slots are rejected and counted rather than silently treated as
complete packets. The present lab has ordinary MTU-sized frames with offload
disabled. Jumbo frames require a different ring configuration and validation.
Capture has no promiscuous enterprise mirror or inline forwarding role.

`decode_frame` accepts complete IPv4 TCP/UDP Ethernet frames. Unsupported
protocols, fragments and incomplete headers are rejected. IPv6, ICMP flow
classification, VLAN reconstruction from stripped hardware metadata and IP
fragment reassembly are not implemented. Counters expose capture loss,
truncation, malformed/unsupported input and late timestamps.

The sensor feeds decoded packets to `StreamingFlows`, queues emitted rows, runs
the loaded release in microbatches, normalizes verdicts and writes a durable
outbox. HTTP delivery acknowledges each event only after the ingestion API has
stored it. Retried UUIDs are idempotent. SQLite/WAL bounds event retention and
quarantine. The dashboard reads the same storage APIs for both syslog and ML.
UDP syslog has no acknowledgment or guaranteed delivery.

## Flow and feature definitions

A bidirectional key consists of protocol and the unordered endpoint pairs. The
first observed packet defines forward direction. The release uses idle timeout
1 second and active timeout 8 seconds, as recorded in its manifest. A reset,
FIN observed in both directions, timeout, capacity eviction or graceful shutdown
emits a segment. Single-packet flows are included. Active-timeout segments may
start mid-connection. A crash starts fresh segments and loses active partial
flows; no claim of lossless crash recovery is made for packet state.

The engine bounds active flows (10,000), sources (4,096), source-start events
(100,000) and stale expiration entries. Capacity evictions are counted. Packets
older than the event-time watermark are dropped and counted; replay follows the
same observation-order policy. Timestamp ties preserve observation order.

Source flow rate is:

```
rate(source, t) = observed new flow starts from source in (t-W, t] / W
```

It is sampled when the current flow starts, includes that start, and remains
fixed for the emitted segment. W is 1 second in the release. Idle sources expire
globally. Capacity eviction can reduce retained context and is diagnostic.
There is no future capture duration or count in this feature.

Feature values otherwise share the verified `Flow` calculations used for
CICIDS2017 compatibility, including its historically shuffled training flag
columns. The ordered selected subset and units are in `manifest.json`; full
feature meanings live in `src/feature_contract.py`. Ports, IP identities and
several unreliable/constant public-data features are excluded from release
selection. Nonfinite numeric values are replaced with missing values and
imputed by the training-fitted serialized pipeline. Nonnumeric malformed values
are rejected.

`extract()` remains available for legacy CICFlowMeter parity and repair. It is
not interchangeable with release replay: termination, singleton and timeout
policies differ. Release training and inference both use `StreamingFlows`.
Tests compare identical replay/live feed sequences and eligible legacy feature
rows within numeric tolerances; this does not claim every historical CSV row
has the same lifecycle as a live flow.

## Dataset provenance and leakage control

`tools/collect_sessions.py` creates uniquely named PCAPs before any training.
Capture manifests record role, scenario, actor/server addresses, start/end time,
seed, operations/errors, tool Python, image identity, capture SHA-256 and kernel
loss statistics. Zero-operation, failed-operation or lossy runs are rejected.
Each run receives its training/calibration/test role before collection.

The active `lab-v2` dataset has 36 sessions: 12 per role, each with four benign,
two concurrent benign/flood, two scan, two HTTP-flood and two slow-HTTP runs.
Concurrent runs label each source actor explicitly. The prior `lab-v1` had 27
shorter sessions and failed a later concurrent-workload check. Its results and
bundle remain preserved. The new final captures are independent of that first
release's already inspected test data. Runs vary client, seed and intensity;
they are still short sessions on one host on one day.

Capture hashes, IDs and role disjointness are enforced. The primary calibration
and final test additionally exclude flow fingerprints seen in preceding roles:
signed-log1p transformed features rounded to three decimals. Both complete and
novel-flow metrics are retained. This is a conservative repeat-pattern screen,
not an exhaustive nearest-neighbor proof against all possible near duplicates.
Some genuine attack patterns are naturally identical across independent runs.
Wilson intervals describe flow proportions assuming independent trials; real
flows within a run are correlated. Session metrics are reported separately.
Neither interval calculations nor these same-host sessions establish a
production confidence guarantee.

Only actor-originating, server-destined segments are scored. Reverse tails and
unrelated flows are excluded and counted. Scenario windows provide labels;
they do not prove service denial or malicious intent for every individual GET.
Normal high-rate activity and malicious browsing-like traffic may overlap.
The live model serves the same server-ingress scope.

## Selection and artifact contract

`train_release.py` fits preprocessing only on training data, then compares
per-flow RF, causal RF at two forest sizes, and a parallel causal RF/invariant
Isolation Forest recipe. Confidence thresholds are considered only on
calibration sessions. Selection gates use calibration FPR ≤3%, macro attack
detection ≥70%, and P95 single-flow inference ≤5 ms, then rank category macro F1.
RF vote fractions are confidence scores, not empirically calibrated
probabilities.

A frozen `selection.json` is written before final-test captures are opened.
Final test evaluates the frozen selection, checks prediction equality after
serialization/reload and promotes only an accepted release. The selected
architecture is RF-only; an anomaly arm is not added solely to preserve the old
parallel design. The old serial/public-data interface remains available
explicitly for research and migration.

The model bundle stores preprocessing, classifier, feature order/units, classes,
flow configuration, threshold, environment versions, source implementation
hashes, model checksum, capture provenance and evaluation. The default pointer
selects this same artifact. Missing files, changed schemas, incompatible
versions or hashes fail explicitly. Checksums are not authenticity signatures;
joblib artifacts must come from a trusted source.

Do not rerun model selection against these already inspected test captures.
Future releases need fresh independent final captures. Public CICIDS performance
does not establish local-network performance, and this release's four-class
scope does not establish full original attack-vocabulary coverage.

### Intentional migration changes

`TwoStagePipeline.load_chosen()` now returns `ReleaseModel`, whose `predict()`
retains the verdict columns and adds model identity. Code depending on the old
object type or its detector attributes must migrate. Passing an explicit legacy
candidates directory to `load_chosen(models_dir)` retains the old research
loading behavior. `CHOSEN_MODELS` was renamed `LEGACY_CANDIDATES` so its filenames
cannot be mistaken for the application default.

`add_source_flow_rate()` now requires source IP and flow-start timestamps and
uses causal windows. Models trained with the former capture-wide feature must
be retrained; copying their old weights into a release is incompatible.
The active bundle was trained from the corrected definition.

The active release has four lab classes instead of the original public attack
vocabulary. This is a documented scope change justified by independent local
evidence, not a claim of equivalent original-class coverage. Original models and
explicit legacy loading remain available for that separate evaluation.

## Logs and event schema

`netguard.syslog` handles Cisco IOS messages, Linux syslog, Windows key/value,
NXLog JSON and a supported MSWinEventLog text form. Cisco padded days,
fractionless times and nearest-year rollover are handled explicitly. Linux
process attribution comes from the header, never a `sudo` substring in content.
Invalid timestamps or unsupported structures return `None` for quarantine.
Timezone-less devices use `NETGUARD_DEVICE_TIMEZONE` (UTC by default);
timestamps identify that assumption. Not every Windows/NXLog format is supported.

`netguard-alert-v1` includes UUID, event/ingestion timestamps, event source,
source/destination IP, severity/category, decision, detection method, model
version/score, explanation, structured evidence and processing status.
Stored events gain a storage timestamp and status. ML evidence includes ports,
protocol, flow boundaries, source rate, close reason and confidence. The original
ECS log event is retained inside syslog evidence.

The standalone `logic.py` keeps parser imports and JSONL filenames for existing
callers. `NETGUARD_SYSLOG_HOST` and `NETGUARD_SYSLOG_PORT` configure that collector.
The integrated service uses CLI arguments and UDP 5514 by default.

## Reliability and measurement

Queues and durable outbox are bounded and count overflow; they cannot guarantee
unlimited buffering. Delivery retries survive an ingestion outage. Database
retention is not an external archival or HA solution. The ingestion service
requires a token for nonloopback listeners, limits HTTP bodies/threads and uses
socket timeouts. The lab does not implement TLS or public multi-user access.
Health verifies storage access and the running syslog listener; sensor health
is reported separately through diagnostics.

`benchmark_system.py` measures decoding, flow construction, row extraction,
single/batch inference and normalization on a named capture and release.
Batch amortization is not single-flow latency. Live diagnostics measure
preprocessing, classifier, queue wait, completion wait, delivery/ingestion,
end-to-end time from first/last packet, CPU, peak RSS, throughput and drops.
Percentiles cover bounded recent samples, not an unlimited full-run history.
The inference gate excludes packet arrival, flow completion, queue and delivery.
It does not imply 5 ms packet-to-alert detection.

Production validation still requires independently captured real normal and
attack traffic across days, machines, networks and intensities, a substantially
larger normal evaluation sample, broader attacks, IPv6/protocol decisions,
security hardening, sustained-load/capacity testing and operational ownership.
