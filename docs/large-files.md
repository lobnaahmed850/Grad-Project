# Large files kept outside Git

These files are too large for GitHub, so Git ignores them. They are shared
through Google Drive instead. Download them and put them at the paths below
before running the tools that need them.

**Drive folder:** _TO BE ADDED after upload_

Verify every download with `sha256sum <file>` and compare with the table.

## Datasets and captures

| File | Size | SHA-256 | Put it at | Needed for |
|---|---|---|---|---|
| `Friday-WorkingHours.pcap` (CICIDS2017) | 8.3 GB | `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0` | `network-anomaly-detection/data/raw/pcap/` | `tools/parity_check.py`, `tools/e2e_real_traffic.py` |
| `GeneratedLabelledFlows.zip` (published flow CSVs) | 271 MB | `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a` | `artifacts/public-validation/` | same tools |
| `MachineLearningCVE/` (8 CSV files) | 844 MB | not recorded | `network-anomaly-detection/data/raw/MachineLearningCVE/` | legacy training notebooks |
| Lab session captures (94 pcaps and manifests) | 830 MB | per-file hashes in the release manifest | `artifacts/sessions/` | retraining and `tools/train_release.py` |
| Earlier lab captures (11 pcaps) | 763 MB | not recorded | `network-anomaly-detection/lab/captures/` | legacy lab checks |

Other CICIDS2017 pcaps (Monday, Thursday) were listed in
`network-anomaly-detection/data/raw/pcap/expected_sha256.txt` but are not
present locally: Monday `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972`,
Thursday `38f8b1bb276849bf1721f7c4de22bebfa7f59a74e52286d4c0a37edbb118fe01`.

## Original models (not in Git)

| File | Size | SHA-256 | Put it at |
|---|---|---|---|
| `iforest_v0.1.0.joblib` | 467 MB | `e1ef25c0a5f9762a7516437bf37bfd7e254ce2d276fc15ca1d8f3237d95a7111` | `network-anomaly-detection/models/` (set `IF_MODEL_PATH` to it) |
| `if_portable_262144.joblib` | 38 MB | `57406583c3595480f323f91a4e682f25ee4c7b8eb2e03e047624fd26285b416d` | `network-anomaly-detection/models/candidates/` |
| `if_portable_65536.joblib` | 16 MB | `a68f064f49cd2a256d1a9658cd69cbebaf68731a333becb4601b3497800640f0` | same |
| `if_portable_timing_262144.joblib` | – | `f7db27e5d8dd10ed13a1fd12f5b563f841cc51851ce31928261a9a994e532ced` | same |
| `if_portable_timing_65536.joblib` | – | `180822a4166f163ee46e77b755796699a72ffa8256b6b184ff2c90052db5696b` | same |
| `rf14_all_features.joblib` | – | `b4ad2577ba5e2620a7e56dc8e2fa5f3ec865c215a0c8f688125fa53b871fd85a` | same |
| `rf14_portable.joblib` | – | `949ea1735434774f1cbd2249eb06d877626ff8b02b9bc9af30b763a66331977f` | same |
| `rf14_portable_timing.joblib` | – | `22d880983481105849e158760fa3cd59dc95cb881e7a6f740adbab5b91a6fb1a` | same |
| `rf15_portable.joblib` | – | `e062c520635880d463382188f9a2ad259677cc131af396919300a5e97f3faabf` | same |
| `rf15_portable_timing.joblib` | – | `f18e9bcf03c56c2eb1c8256d179552d0f814d220d9454e89b781f68148609833` | same |

The candidate models (about 158 MB in total) can be rebuilt with
`tools/train_candidates.py`, so uploading them is optional.

## What is already in Git

The default model, `network-anomaly-detection/models/releases/lab-v2/model.joblib`
(SHA-256 `9a895917ab1964abcf8e59ad20a0518a4cbeab8718f3f9a51fffd0d5cca8bec0`),
and `random_forest_final.joblib` are tracked, so the live system and its tests
run without any of the files above, except the original Isolation Forest used
by the legacy comparison tests.
