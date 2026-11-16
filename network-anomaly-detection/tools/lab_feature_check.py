"""Does the 'source flow rate' feature help, measured on an unseen session?

Trains the goal pipeline (invariant detector + lab-trained Random Forest) two ways -- with and
without the per-source flow-rate feature -- on the training sessions, and measures false alarms on
an unseen session plus detection per attack. The feature gives the classifier the context a single
flow lacks: how many flows a source opens per second. Each --attack is "name=pcap=cicids_label".
Nothing here overwrites a saved model.

    python tools/lab_feature_check.py --csv-dir data/raw/MachineLearningCVE \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_multi.pcap \
        --unseen lab/captures/benign_big.pcap \
        --attack "HTTP flood=lab/captures/attack_lan_httpflood.pcap=DoS Hulk" \
                 "Slowloris=lab/captures/attack_lan_slowloris.pcap=DoS slowloris" \
                 "PortScan=lab/captures/attack_lan_scan.pcap=PortScan" \
        --out reports/lab_feature_check.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING  # noqa: E402
from src.flow_extractor import add_source_flow_rate, extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline, _clean_name  # noqa: E402
from src.training import fit_classifier, fit_detector, load_cicids, split_rows  # noqa: E402

EXTRA = "source flow rate"
rng = np.random.default_rng(0)


def raw(p):
    return add_source_flow_rate(extract_flows(str(p), "training"))


def frame(df, fs):
    return df[fs].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--benign", nargs="+", required=True, help="training-session pcaps")
    parser.add_argument("--unseen", required=True, help="a session never used in training")
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap=cicids_label triples")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    print("extracting + adding source flow rate ...", flush=True)
    benign = pd.concat([raw(p) for p in args.benign], ignore_index=True)
    unseen = raw(args.unseen)
    attacks, label_of = {}, {}
    for spec in args.attack:
        name, path, label = spec.split("=", 2)
        attacks[name], label_of[name] = raw(path), label
    order = rng.permutation(len(benign))
    cut = len(benign) * 8 // 10
    det_train, val_raw = benign.iloc[order[:cut]], benign.iloc[order[cut:]]
    atr, ate = {}, {}
    for n, df in attacks.items():
        o = rng.permutation(len(df))
        atr[n], ate[n] = df.iloc[o[:len(df) // 2]], df.iloc[o[len(df) // 2:]]

    print("loading public ...", flush=True)
    public = load_cicids(args.csv_dir)
    pub_train, pub_val, _ = split_rows(public["label"])

    print("training invariant detector ...", flush=True)
    ps = public[PORTABLE_FEATURES + ["label"]]
    ltr, lva = frame(det_train, PORTABLE_FEATURES), frame(val_raw, PORTABLE_FEATURES)
    aug = pd.concat([ps, ltr.assign(label="BENIGN"), lva.assign(label="BENIGN")], ignore_index=True)
    bn = len(ps)
    det, _ = fit_detector(aug, np.concatenate([pub_train, np.arange(bn, bn + len(ltr))]),
                          np.concatenate([pub_val, np.arange(bn + len(ltr), bn + len(ltr) + len(lva))]),
                          PORTABLE_FEATURES, 65536, "inv")

    cols = list(attacks)
    report = {}
    for label, rf_features in (("without source flow rate", PORTABLE_WITH_TIMING),
                               ("with source flow rate", PORTABLE_WITH_TIMING + [EXTRA])):
        print(f"training RF {label} ...", flush=True)
        pub_rf = public[PORTABLE_WITH_TIMING + ["label"]].copy()
        pub_rf[EXTRA] = 0.0
        labrows = [frame(det_train, rf_features).assign(label="BENIGN")]
        for n, df in atr.items():
            labrows.append(frame(df, rf_features).assign(label=label_of[n]))
        aug_rf = pd.concat([pub_rf[rf_features + ["label"]]] + labrows, ignore_index=True)
        rows = np.concatenate([rng.choice(pub_train, min(500_000, len(pub_train)), replace=False),
                               np.arange(len(pub_rf), len(aug_rf))])
        rf = fit_classifier(aug_rf, rows, rf_features)
        pipe = TwoStagePipeline(detector=det, classifier=rf["model"],
                                class_names=[_clean_name(c) for c in rf["label_encoder"].classes_],
                                mode="parallel", min_confidence=0.9)
        pipe.threshold_op = None
        pipe.set_local_threshold(val_raw, 1e-9)  # RF arm only, the robust operating point
        fa = float((pipe.predict(unseen, validate=False)["decision"].to_numpy() == "alert").mean())
        rec = {n: float((pipe.predict(ate[n], validate=False)["decision"].to_numpy() == "alert").mean()) for n in cols}
        report[label] = {"unseen session FA": fa, "detection": rec}
        print(f"  unseen FA {fa:.1%}  " + "  ".join(f"{n} {rec[n]:.0%}" for n in cols), flush=True)

    args.out.write_text(json.dumps(report, indent=1))
    print(f"\nwrote {args.out}")
