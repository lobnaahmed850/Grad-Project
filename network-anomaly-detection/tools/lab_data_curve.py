"""How far do false alarms fall as more same-network normal traffic is added to the detector?

A learning curve: the detector (Isolation Forest) is retrained on public normal plus a growing
sample of lab-normal, and measured each time on the SAME held-out lab-normal and the SAME lab
attacks, at the FPR<=3% operating point. This quantifies the "we need a lot and a lot of data"
question -- it shows whether false alarms keep dropping with more normal traffic, and what it
costs in attack recall. Nothing here overwrites a saved model.

    python tools/lab_data_curve.py --csv-dir data/raw/MachineLearningCVE \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
                 lab/captures/benign_big.pcap \
        --attack "PortScan=lab/captures/attack_lan_scan.pcap" "SYN flood=lab/captures/attack_lan_synflood.pcap" \
                 "HTTP flood=lab/captures/attack_lan_httpflood.pcap" \
        --out reports/lab_data_curve.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_WITH_TIMING as FEATURES  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import to_numeric_frame  # noqa: E402
from src.training import fit_detector, load_cicids, split_rows  # noqa: E402

OP = "FPR<=3%"
TRAIN_SIZES = [0, 500, 1000, 2000, 4000, 8000, 16000, 32000]
PUBLIC_TEST_CAP = 60000  # subsample the public test set for speed; estimates only


def feats(path: str) -> pd.DataFrame:
    return to_numeric_frame(extract_flows(str(path), "training"), FEATURES).replace([np.inf, -np.inf], np.nan)


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [float("nan"), float("nan")]
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    s = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [c - s, c + s]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--benign", nargs="+", required=True)
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap pairs")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = np.random.default_rng(0)

    print("extracting lab captures ...", flush=True)
    benign = pd.concat([feats(p) for p in args.benign], ignore_index=True)
    attacks = {}
    for pair in args.attack:
        name, path = pair.split("=", 1)
        attacks[name] = feats(path)

    # Fixed held-out test (30%) and threshold-calibration set (10%); the rest is the training pool.
    order = rng.permutation(len(benign))
    n_test, n_val = len(benign) * 3 // 10, len(benign) // 10
    lb_test = benign.iloc[order[:n_test]].reset_index(drop=True)
    lb_val = benign.iloc[order[n_test:n_test + n_val]].reset_index(drop=True)
    pool = benign.iloc[order[n_test + n_val:]].reset_index(drop=True)
    print(f"lab-normal {len(benign):,}: test {len(lb_test):,}, val {len(lb_val):,}, train pool {len(pool):,}", flush=True)

    print("loading public CICIDS2017 ...", flush=True)
    public = load_cicids(args.csv_dir)
    pub_train, pub_val, pub_test = split_rows(public["label"])
    public_small = public[FEATURES + ["label"]]
    if len(pub_test) > PUBLIC_TEST_CAP:
        pub_test = rng.choice(pub_test, PUBLIC_TEST_CAP, replace=False)
    pub_test_frame = public_small.iloc[pub_test]
    pub_test_attack = public["label"].to_numpy()[pub_test] != "BENIGN"
    print(f"public {len(public):,} rows", flush=True)

    sizes = [s for s in TRAIN_SIZES if s <= len(pool)] + ([len(pool)] if len(pool) not in TRAIN_SIZES else [])
    base_n = len(public_small)
    report = {}
    header = f"{'lab-normal in training':>22} {'lab FA':>8} " + " ".join(f"{n[:9]:>9}" for n in attacks) + f" {'pubFA':>6} {'pubRec':>7}"
    print("\n" + header, flush=True)
    for size in sizes:
        sample = pool.iloc[:size]
        aug = pd.concat([public_small, sample.assign(label="BENIGN"), lb_val.assign(label="BENIGN")], ignore_index=True)
        train_pos = np.concatenate([pub_train, np.arange(base_n, base_n + size)])
        val_pos = np.concatenate([pub_val, np.arange(base_n + size, base_n + size + len(lb_val))])
        detector, _ = fit_detector(aug, train_pos, val_pos, FEATURES, 65536, f"curve-{size}")
        t = detector.thresholds[OP]
        fa_scores = detector.score(lb_test)
        k = int((fa_scores >= t).sum())
        pub = detector.score(pub_test_frame)
        row = {
            "lab false alarm": float((fa_scores >= t).mean()),
            "lab FA 95% CI": wilson(k, len(fa_scores)),
            "public false alarm": float((pub[~pub_test_attack] >= t).mean()),
            "public recall": float((pub[pub_test_attack] >= t).mean()),
        }
        for name, frame in attacks.items():
            row[name] = float((detector.score(frame) >= t).mean())
        report[str(size)] = row
        cells = " ".join(f"{row[n]:8.1%}" for n in attacks)
        print(f"{size:22,} {row['lab false alarm']:7.1%} {cells} {row['public false alarm']:5.1%} {row['public recall']:6.1%}", flush=True)
        args.out.write_text(json.dumps(report, indent=1))

    print(f"\nwrote {args.out}")
