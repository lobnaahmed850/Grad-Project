"""Retrain both stages on matched lab data and compare pipeline architectures.

Tests three parallel pipelines (confidence 0.9) on the same held-out lab-normal and held-out lab
attacks:

  baseline               timing detector (retrained on lab normal) + the original Random Forest
  invariant + lab RF     timing-blind detector (low false alarms) + an RF retrained on lab attacks
  timing + lab RF        timing detector + the RF retrained on lab attacks

The point: timing features both cause the false alarms and carry the attack signal, so dropping
them cuts false alarms but needs the RF arm to recover detection -- and the RF only recognises the
lab attacks once it is retrained on them. Each --attack is "name=pcap=cicids_label"; the label maps
the lab attack to its nearest CICIDS class. Public training rows are subsampled for speed. Nothing
here overwrites a saved model.

    python tools/lab_architecture_check.py --csv-dir data/raw/MachineLearningCVE \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
                 lab/captures/benign_big.pcap \
        --attack "PortScan=lab/captures/attack_lan_scan.pcap=PortScan" \
                 "SYN flood=lab/captures/attack_lan_synflood.pcap=DDoS" \
                 "HTTP flood=lab/captures/attack_lan_httpflood.pcap=DoS Hulk" \
        --models models/candidates --out reports/lab_retrain_both.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline, _clean_name  # noqa: E402
from src.training import fit_classifier, fit_detector, load_cicids, split_rows  # noqa: E402

RF_FEATURES = PORTABLE_WITH_TIMING
PUBLIC_RF_SAMPLE = 500_000


def raw(p):
    return extract_flows(str(p), "training")


def frame(df, fs):
    return df[fs].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--benign", nargs="+", required=True)
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap=cicids_label triples")
    parser.add_argument("--models", type=Path, default=Path("models/candidates"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = np.random.default_rng(0)

    print("extracting lab captures ...", flush=True)
    benign = pd.concat([raw(p) for p in args.benign], ignore_index=True)
    attacks, label_of = {}, {}
    for spec in args.attack:
        name, path, label = spec.split("=", 2)
        attacks[name], label_of[name] = raw(path), label

    order = rng.permutation(len(benign))
    n_test, n_val = len(benign) * 3 // 10, len(benign) // 10
    test_i, val_i, train_i = order[:n_test], order[n_test:n_test + n_val], order[n_test + n_val:]
    test_raw = benign.iloc[test_i]
    attack_train, attack_test = {}, {}
    for name, df in attacks.items():
        o = rng.permutation(len(df))
        attack_train[name], attack_test[name] = df.iloc[o[:len(df) // 2]], df.iloc[o[len(df) // 2:]]

    print("loading public CICIDS2017 ...", flush=True)
    public = load_cicids(args.csv_dir)
    pub_train, pub_val, _ = split_rows(public["label"])

    def train_detector(fs):
        ps = public[fs + ["label"]]
        ltr, lva = frame(benign.iloc[train_i], fs), frame(benign.iloc[val_i], fs)
        aug = pd.concat([ps, ltr.assign(label="BENIGN"), lva.assign(label="BENIGN")], ignore_index=True)
        bn = len(ps)
        tr = np.concatenate([pub_train, np.arange(bn, bn + len(ltr))])
        va = np.concatenate([pub_val, np.arange(bn + len(ltr), bn + len(ltr) + len(lva))])
        return fit_detector(aug, tr, va, fs, 65536, "d")[0]

    print("training detectors ...", flush=True)
    inv_det, tim_det = train_detector(PORTABLE_FEATURES), train_detector(PORTABLE_WITH_TIMING)

    print(f"training RF on {PUBLIC_RF_SAMPLE:,} public rows + lab attacks ...", flush=True)
    pub_rf = public[RF_FEATURES + ["label"]]
    lab_rows = [frame(benign.iloc[train_i], RF_FEATURES).assign(label="BENIGN")]
    for name, df in attack_train.items():
        lab_rows.append(frame(df, RF_FEATURES).assign(label=label_of[name]))
    aug_rf = pd.concat([pub_rf] + lab_rows, ignore_index=True)
    pub_sample = rng.choice(pub_train, min(PUBLIC_RF_SAMPLE, len(pub_train)), replace=False)
    rows = np.concatenate([pub_sample, np.arange(len(pub_rf), len(aug_rf))])
    rf = fit_classifier(aug_rf, rows, RF_FEATURES)
    lab_names = [_clean_name(c) for c in rf["label_encoder"].classes_]

    rf15 = joblib.load(args.models / "rf15_portable_timing.joblib")
    rf14 = joblib.load(args.models / "rf14_all_features.joblib")
    base_names = [_clean_name(c) for c in rf15["label_encoder"].classes_]
    type_names = [_clean_name(c) for c in rf14["label_encoder"].classes_]

    def pipe(det, model, cnames, typ=None, tnames=None):
        return TwoStagePipeline(detector=det, classifier=model, class_names=cnames, mode="parallel",
                                min_confidence=0.9, type_classifier=typ, type_names=tnames)

    configs = {
        "baseline: timing det + original RF": pipe(tim_det, rf15["model"], base_names, rf14["model"], type_names),
        "invariant det + lab-trained RF": pipe(inv_det, rf["model"], lab_names),
        "timing det + lab-trained RF": pipe(tim_det, rf["model"], lab_names),
    }

    report = {}
    print(f"\n{'config':36} {'lab FA':>7}  detection (correct type)", flush=True)
    for name, pp in configs.items():
        alert = pp.predict(test_raw, validate=False)["decision"].to_numpy() == "alert"
        row = {"lab false alarm": float(alert.mean()), "detection": {}, "correct type": {}}
        parts = []
        for an, df in attack_test.items():
            v = pp.predict(df, validate=False)
            det = float((v["decision"].to_numpy() == "alert").mean())
            typ = float((v["attack_type"].to_numpy() == label_of[an]).mean())
            row["detection"][an], row["correct type"][an] = det, typ
            parts.append(f"{an} {det:.0%}({typ:.0%})")
        report[name] = row
        print(f"{name:36} {row['lab false alarm']:6.1%}  " + "  ".join(parts), flush=True)

    args.out.write_text(json.dumps(report, indent=1))
    print(f"\nwrote {args.out}")
