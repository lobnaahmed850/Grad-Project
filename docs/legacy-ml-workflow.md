# Historical ML workflow — not the release default

This guide preserves the previous public-data/CSV repair workflow. Its chosen
candidates and source-rate experiments are not the integrated release.
Use `network-anomaly-detection/README.md` and
`docs/architecture-and-validation.md` for current serving and evaluation.

Flow-based intrusion detection with two models: an Isolation Forest that flags unusual flows, and a Random Forest that names the attack.

Install with `pip install -r requirements.txt`. Python 3.11 is required. `environment.yml` only works on Windows.

## Check an extractor before trusting its features

Run this first on any flow tool, including a CICFlowMeter build:

```bash
python tools/known_answer_pcap.py --out known_answer
# Run your extractor on known_answer.pcap, then:
python tools/check_extractor.py flows.csv known_answer.json
```

CICFlowMeter builds from 2018-05-31 to 2020-01-20 fail this check, because they count each flow's first packet as backward.

## Extract features from a capture

`src/flow_extractor.py` reads pcap and pcapng files. Its `training` profile reproduces the published CICIDS2017 features.

```bash
python -m src.flow_extractor capture.pcap flows.csv
```

## Score flows

```python
import pandas as pd
from src.pipeline import TwoStagePipeline

pipeline = TwoStagePipeline.load_chosen()
verdicts = pipeline.predict(pd.read_csv("flows.csv"))
```

This loads the chosen design, parallel at confidence 0.9. Both models see every flow, so an attack that Stage 1 misses can still raise an alert. Pass `mode="serial"` to `TwoStagePipeline.load` to compare it with the old design.

`predict` raises `IncompatibleFlows` when a batch breaks the feature contract in `src/feature_contract.py`. For example, flows from a defective extractor are rejected with the reason.

Lab CSVs from the older tool need repairing first. Re-extracting from the pcap is better when you have it.

```python
from src.lab_data import load_lab_csvs, remap_flags, repair_first_packet

flows = remap_flags(repair_first_packet(load_lab_csvs("localdata/*.csv")))
```

## Model files

Models over 100 MB can't go in Git. Everything in `models/` except `random_forest_final.joblib` is ignored.

| File | Stored in | Status |
|---|---|---|
| `models/iforest_v0.1.0.joblib` | Google Drive | Original Stage 1 model, 489 MB |
| `models/random_forest_final.joblib` | Git | Original Stage 2 model |
| `models/candidates/` | This machine only | Includes the chosen design's three models. Rebuild with `tools/train_candidates.py` and `tools/compare_designs.py` |

## Data

Put CICIDS2017 CSVs in `data/raw/MachineLearningCVE/`. Git ignores `data/`.

## Tests and experiments

Run the tests with `pytest tests`. Set `IF_MODEL_PATH` to run the tests that need the Isolation Forest file when it isn't in `models/`.

| Script | What it answers |
|---|---|
| `tools/parity_check.py` | Does the extractor match a published CSV, feature by feature? |
| `tools/e2e_real_traffic.py` | How do models score real packets on each extraction path? |
| `tools/eval_lab.py` | How do models score lab traffic before and after each data fix? |
| `tools/train_candidates.py` | How do feature sets and `max_samples` values compare? |
| `tools/compare_designs.py` | Is serial or parallel better, and how fast is it? |
| `tools/generalization_check.py` | How do models score unseen days, and can thresholds be set locally? |
| `tools/local_training_check.py` | How much does training on local traffic help? |
| `tools/mixed_check.py` | How do the designs score lab traffic mixed with real attack flows? |
| `tools/false_alarm_causes.py` | Which flow sizes and features cause the false alarms on normal traffic? |
| `tools/local_threshold_check.py` | Can a threshold set from a network's own normal traffic fix the false alarms, and what does it cost? |
| `tools/lab_retrain_check.py` | Does retraining the detector on same-network normal fix false alarms without losing the lab attacks? |
| `tools/lab_data_curve.py` | How far do false alarms fall as more same-network normal traffic is added? |
| `tools/lab_architecture_check.py` | Retrain both stages on matched lab data and compare pipeline architectures. |
| `tools/lab_metrics.py` | Per-class precision/recall/F1, macro F1 and a confusion matrix on matched lab data. |
| `tools/lab_frontier_check.py` | Can the pipeline reach 3% false alarms with detection kept? Sweeps the detector operating point. |
| `tools/lab_feature_check.py` | Does the `source flow rate` feature (`src/flow_extractor.py`) help? Trains the pipeline with and without it. |

Measured results are in `reports/`.
