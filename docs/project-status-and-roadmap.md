# AI-NetGuard: status and roadmap

Status as of 2026-11-16, branch `engineering/integrated-netguard`. Every number
here comes from the reports in `network-anomaly-detection/reports/` and from
[the technical report](technical-report.md). All results are from the Docker
laboratory with scripted traffic. None of them prove production performance.

## 1. Summary

| Area | State |
|---|---|
| Laboratory system (capture, flows, model, alerts, dashboard) | Finished and tested |
| Evidence on real network traffic (team GNS3 lab or VMs) | Not started |
| Production hardening | Not started |
| Review and merge into `AI` | Waiting for the team |

## 2. What is finished

### 2.1 Problems found in the original pipeline and their status

| # | Original problem | Status |
|---|---|---|
| 1 | First packet of every flow counted as backward (old CICFlowMeter build) | Fixed in the extractor. Verified against the Friday capture: all 76 compared features match on at least 99.89% of 702,651 paired rows |
| 2 | Flag columns shuffled in the training data | Fixed with a contract and a repair for old CSVs |
| 3 | Wrong lab labels (the "Infiltration" file is a port scan) | Fixed. Labels follow the real traffic |
| 4 | Features tied to one network | Reduced. The new model uses 41 features that carry across networks |
| 5 | Serial design blocks attacks before Stage 2 | Fixed. The default is no longer serial |
| 6 | No shared path from flows to decisions | Fixed. One code path serves offline replay and live capture |
| 7 | Scores overstated by random flow splits | Fixed. Splits are by whole capture session, with leakage checks |
| 8 | Noise in the training data (UDP header columns, 6,789 mislabeled reverse flows) | **Not fixed** in the original 15-class models. See section 3 |
| 9 | Too few rows for rare attacks | **Not fixed**. See section 3 |
| 10 | Too little lab normal traffic | Fixed in the lab. 40,518 independently captured flows |

### 2.2 What was built

- **Live flow engine** (`network-anomaly-detection/src/streaming.py`): bounded memory, idle timeout 1 s, active timeout 8 s, closes on RST, FIN in both directions, timeout, or capacity. Late packets are dropped and counted.
- **Causal source-flow-rate feature:** counts only flow starts in the previous second, so it uses no future data. It replaces the old capture-wide calculation.
- **Packet capture** (`netguard/capture.py`): Linux AF_PACKET ring buffer with kernel timestamps and counters for drops and truncation.
- **Sensor** (`netguard/sensor.py`): capture, features, model, queue, durable outbox, authenticated delivery. Events survive an ingestion outage and a sensor restart.
- **Model release** (`src/release.py`, `models/releases/lab-v2/`): immutable bundle with checksum, feature order, classes, thresholds and source hashes. It is the actual default. SHA-256 `9a895917ab1964abcf8e59ad20a0518a4cbeab8718f3f9a51fffd0d5cca8bec0`.
- **Session-based evaluation** (`src/sessions.py`, `src/metrics.py`, `tools/train_release.py`): train, calibration and test come from separate capture sessions. The selection is saved before test data is read.
- **SIEM integration** (`netguard/`): one alert schema (`netguard-alert-v1`), SQLite storage, authenticated HTTP API, UDP syslog listener on 5514, and a dashboard that shows syslog and ML alerts together.
- **Syslog fixes** (`netguard/syslog.py`): Cisco padded days and missing fractional seconds, the Linux `sudo` misclassification, Windows key/value, NXLog JSON and MSWinEventLog formats. Bad input goes to quarantine instead of getting a made-up timestamp.
- **Docker laboratory** (`network-anomaly-detection/lab/integration/compose.yml`): two internal bridges, server, two clients, attack simulator, capture, sensor and ingest. No privileged containers, no host networking, resource limits.
- **Tests and CI:** 118 automated tests pass (0 failed, 0 skipped). A GitHub Actions workflow exists but has never run.
- **Documentation:** technical report, architecture, command list, topology diagram, large-file list.

### 2.3 Measured results (laboratory only)

| Measure | Result |
|---|---|
| False alarms, held-out sessions | 0.41% (4 of 981 normal flows) |
| False alarms, live concurrent run | 1.69% (3 of 177 normal flows) |
| Attack detection, held-out sessions | 99.94% average across attack types |
| Attack detection, live concurrent flood | 99.71% |
| One-flow classification, 95th percentile | 4.37 ms (target 5 ms met) |
| Packet to stored alert, live, 95th percentile | 1.12 s (**5 ms target not met**) |
| Memory use under load | 234 MiB of a 768 MiB limit |

The live delay is mostly the idle timeout that waits for a flow to end, plus
durable storage. It is not the model.

## 3. What is not finished

Each item has an ID used in the plan in section 4.

### A. Evidence on real traffic (highest priority)

- **A1.** No captures from the team's real network. Normal traffic and attacks must be captured on the same network, with the pcaps kept.
- **A2.** The team's old lab pcaps are not in the repo. Nobody has confirmed whether they still exist.
- **A3.** The exact CICFlowMeter version the team used is unconfirmed. `tools/check_extractor.py` on that tool's output would settle it.
- **A4.** Only the Friday public capture was compared packet by packet. Other days are unchecked.

### B. Model scope

- **B1.** The default model knows 4 classes: normal, HTTP flood, port scan, slow HTTP. The original 15-class models are kept but are not the default.
- **B2.** Rare classes have too few rows: Heartbleed 8, SQL Injection 15, Infiltration about 25. They cannot be learned or measured reliably.
- **B3.** Real DoS Hulk, GoldenEye, Bot and FTP-Patator have not been generated on one network. Models detect an attack from a network only after training on it.
- **B4.** Unknown attack types are untested.
- **B5.** Training noise remains in the original models: 6,789 mislabeled reverse flows, and unreliable UDP header columns in the Random Forest recipe.
- **B6.** Public-data results across unseen days stay near 12% false alarms for the original models, against a 3% target.

### C. Devices and log sources

- **C1.** No Cisco or Windows machine in the lab. Their syslog formats are tested only with sample messages.
- **C2.** Timestamps assume UTC unless a timezone is configured, and Cisco and Linux logs carry no year.

### D. Production readiness

- **D1.** Latency: packet to alert is about 1.1 s at the 95th percentile. A 5 ms packet-to-alert target is not met, and it may need a different definition (see step 4.6).
- **D2.** No TLS between sensor and ingest, only a shared token. The lab token `netguard-local-validation` must not be used outside the lab.
- **D3.** No high availability, and no sustained-load capacity test. The 499 verdicts/s seen was not a maximum.
- **D4.** No support yet for IPv6, fragmented packets, VLAN tags or jumbo frames. These are rejected and counted.
- **D5.** The sensor sees only traffic to or from the server. It is not inline and does not mirror the whole network.
- **D6.** A sensor crash loses flows that are still in memory. Delivered events are safe.
- **D7.** UDP syslog is unacknowledged, so messages can be lost.
- **D8.** The concurrent live test gave 1.69% false alarms against 0.41% on held-out sessions. The Wilson intervals assume independent flows, but flows in one session are correlated, so treat them as descriptive.

### E. Project housekeeping

- **E1.** The pull request into `AI` is not yet opened or reviewed.
- **E2.** The CI workflow has never run on GitHub.
- **E3.** The large files are not on Drive yet (see [large-files.md](large-files.md)).
- **E4.** Old notebooks still describe the legacy workflow. They carry warnings, and `test_on_localdata.ipynb` still reads lab CSVs the old way.
- **E5.** The folder `../ai-netguard-ml-fix` is a leftover. It has uncommitted changes that nobody compared with the new branch.

## 4. Plan for the unfinished work

### 4.1 Working rules (GitHub workflow)

1. Never commit directly to `main` or `AI`. Work on a branch named `<area>/<short-description>`.
2. Branch from the latest `engineering/integrated-netguard` until it is merged, then from `AI`.
3. Small commits with a message that says what and why.
4. Run `make test` (or the command in [validation-commands.md](validation-commands.md)) before every push.
5. Open a pull request. At least one teammate reviews it before merge.
6. Large files go to Drive and are listed in `docs/large-files.md`. Never commit pcaps, datasets or models above a few MB.
7. Every new capture gets provenance: date, machine, tool versions, attack command, and a SHA-256.
8. Never choose a threshold or model using the final test sessions. Test sessions are used once.

### 4.2 Steps in order

| Step | Owner | Work | Done when | Items |
|---|---|---|---|---|
| 1 | Anyone | Open the pull request, let CI run, fix what it shows, get team review, merge into `AI` | Branch merged and CI green | E1, E2 |
| 2 | Anyone | Upload the large files to Drive, add the link to `docs/large-files.md`, then delete the leftover folder `../ai-netguard-ml-fix` after comparing its uncommitted changes | Link in the repo and checksums verified | E3, E5 |
| 3 | Security team | Check whether the old lab pcaps exist. Record the CICFlowMeter version. Run `tools/check_extractor.py` on that tool's output | Written answer in the repo | A2, A3 |
| 4 | Security team | On the real network (GNS3 or VMs), capture normal traffic: tens of thousands of flows, mixed web, DNS, SSH, and Windows traffic, over several days | Pcaps and a provenance file for each session | A1, C1 |
| 5 | Security team | Capture each attack at least 5 times, on different days or machines: port scan, SYN flood, slowloris, Hulk, GoldenEye, Bot, FTP-Patator, and any others the team wants | Same, with attack source addresses recorded | A1, B3 |
| 6 | AI team | Re-extract all pcaps with `src/flow_extractor.py`, build a session manifest, and run the leakage checks | Manifest passes `src/sessions.py` checks | A1 |
| 7 | AI team | Retrain as `lab-v3` with `tools/train_release.py`: whole sessions for train, calibration and test. Keep the selection gates (calibration FPR at most 3%, macro detection at least 70%) | New bundle promoted by the gates, old bundle kept | B1, B3 |
| 8 | AI team | For rare classes, merge more data (other public datasets or generated attacks). Remove the mislabeled reverse flows and the unreliable UDP columns when retraining the 15-class models | Each class has enough rows to measure | B2, B5 |
| 9 | AI team | Test unknown attacks: hold one attack type out of training and measure the detector arm | Result added to the report | B4, B6 |
| 10 | AI team | Run the parity check on the other CICIDS2017 days if pcaps are available | Per-day parity table | A4 |
| 11 | Security team + AI team | Send real Cisco and Windows syslog into the collector. Add the real messages as test fixtures. Fix parser gaps and set timezones per device | Fixtures from real devices pass | C1, C2 |
| 12 | AI team | Decide what the latency target means (model only, or packet to alert). If packet to alert, shorten the idle timeout and re-measure the false alarms | Written definition and a new benchmark | D1 |
| 13 | AI team | Add TLS and per-sensor tokens. Remove the lab token from defaults | Sensor and ingest talk over TLS | D2 |
| 14 | AI team | Run a sustained-load test to find real capacity, and test restarts and queue overflow | Capacity number in the report | D3, D6 |
| 15 | AI team | Add IPv6 and VLAN support, and reassembly or safe handling of fragments | Tests for each case | D4 |
| 16 | Team | Decide where the sensor sits on the real network (mirror port or inline) | Design note | D5 |
| 17 | AI team | Update the old notebooks to the new workflow | Notebooks read the default release | E4 |
| 18 | Team | Run the final model for several days on live real traffic in alert-only mode. Count false alarms by hand | Measured production false-alarm rate | D8 |

Steps 1 and 2 can start today. Steps 3 to 5 are the main blocker: without real
captures, steps 6 to 10 cannot produce real-network evidence. Steps 11 to 17 can
run in parallel with them.

### 4.3 Exit criteria for the project

The project is ready to call production-ready only when all of these hold:

- The model is trained and tested on separate sessions from the team's real network.
- False alarms are 3% or lower on a session never used for training or tuning, with the interval reported.
- Every attack class the team cares about is detected on sessions not used for training.
- Real Cisco and Windows logs pass the parser tests.
- The latency target has a written definition and a measured result.
- Sensor-to-ingest traffic is encrypted and the lab token is removed.
- A multi-day live trial has been run and reviewed.

Until then, describe the system as validated on a laboratory only.
