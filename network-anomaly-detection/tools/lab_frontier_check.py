"""False-alarm / detection frontier for the best architecture (invariant detector + lab-trained RF).

Sweeps the detector's operating point (a target false-alarm rate set from held-out lab-normal) and
measures the full parallel pipeline's false alarms on lab-test plus detection per attack. Target 0%
= the RF arm alone (detector effectively off), the floor. Shows whether the 3% false-alarm target is
reachable with detection kept. Each --attack is "name=pcap=cicids_label". Nothing here overwrites a
saved model.

    python tools/lab_frontier_check.py --csv-dir data/raw/MachineLearningCVE \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
                 lab/captures/benign_big.pcap \
        --attack "PortScan=lab/captures/attack_lan_scan.pcap=PortScan" \
                 "SYN flood=lab/captures/attack_lan_synflood.pcap=DDoS" \
                 "HTTP flood=lab/captures/attack_lan_httpflood.pcap=DoS Hulk" \
                 "Slowloris=lab/captures/attack_lan_slowloris.pcap=DoS slowloris" \
                 "wrk flood=lab/captures/attack_lan_wrkflood.pcap=DoS Hulk" \
        --out reports/lab_frontier.json
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
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline, _clean_name  # noqa: E402
from src.training import fit_classifier, fit_detector, load_cicids, split_rows  # noqa: E402

RF_FEATURES = PORTABLE_WITH_TIMING
TARGETS = [0.0, 0.02, 0.03, 0.05, 0.10]


def raw(p):
    return extract_flows(str(p), "training")


def frame(df, fs):
    return df[fs].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--benign", nargs="+", required=True)
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap=cicids_label triples")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = np.random.default_rng(0)

    print("extracting ...", flush=True)
    benign = pd.concat([raw(p) for p in args.benign], ignore_index=True)
    attacks, label_of = {}, {}
    for spec in args.attack:
        name, path, label = spec.split("=", 2)
        attacks[name], label_of[name] = raw(path), label

    order = rng.permutation(len(benign))
    n_test, n_val = len(benign) * 3 // 10, len(benign) // 10
    test_raw, val_raw = benign.iloc[order[:n_test]], benign.iloc[order[n_test:n_test + n_val]]
    train_i = order[n_test + n_val:]
    atr, ate = {}, {}
    for n, df in attacks.items():
        o = rng.permutation(len(df))
        atr[n], ate[n] = df.iloc[o[:len(df) // 2]], df.iloc[o[len(df) // 2:]]

    print("loading public ...", flush=True)
    public = load_cicids(args.csv_dir)
    pub_train, pub_val, _ = split_rows(public["label"])

    print("training invariant detector ...", flush=True)
    ps = public[PORTABLE_FEATURES + ["label"]]
    ltr, lva = frame(benign.iloc[train_i], PORTABLE_FEATURES), frame(val_raw, PORTABLE_FEATURES)
    aug = pd.concat([ps, ltr.assign(label="BENIGN"), lva.assign(label="BENIGN")], ignore_index=True)
    bn = len(ps)
    det, _ = fit_detector(aug, np.concatenate([pub_train, np.arange(bn, bn + len(ltr))]),
                          np.concatenate([pub_val, np.arange(bn + len(ltr), bn + len(ltr) + len(lva))]),
                          PORTABLE_FEATURES, 65536, "inv")

    print("training lab RF ...", flush=True)
    pub_rf = public[RF_FEATURES + ["label"]]
    labrows = [frame(benign.iloc[train_i], RF_FEATURES).assign(label="BENIGN")]
    for n, df in atr.items():
        labrows.append(frame(df, RF_FEATURES).assign(label=label_of[n]))
    aug_rf = pd.concat([pub_rf] + labrows, ignore_index=True)
    rows = np.concatenate([rng.choice(pub_train, min(500_000, len(pub_train)), replace=False),
                           np.arange(len(pub_rf), len(aug_rf))])
    rf = fit_classifier(aug_rf, rows, RF_FEATURES)
    pipe = TwoStagePipeline(detector=det, classifier=rf["model"],
                            class_names=[_clean_name(c) for c in rf["label_encoder"].classes_],
                            mode="parallel", min_confidence=0.9)

    report = {}
    cols = list(attacks)
    print(f"\n{'det FA target':14} {'pipe FA':>8} " + " ".join(f"{c[:9]:>9}" for c in cols), flush=True)
    for target in TARGETS:
        pipe.threshold_op = None
        pipe.set_local_threshold(val_raw, target if target > 0 else 1e-9)
        fa = float((pipe.predict(test_raw, validate=False)["decision"].to_numpy() == "alert").mean())
        rec = {n: float((pipe.predict(ate[n], validate=False)["decision"].to_numpy() == "alert").mean()) for n in cols}
        report[f"{target:.0%}"] = {"pipeline FA": fa, "detection": rec}
        print(f"{target:>12.0%}  {fa:7.1%} " + " ".join(f"{rec[n]:8.1%}" for n in cols), flush=True)

    args.out.write_text(json.dumps(report, indent=1))
    print(f"\nwrote {args.out}")
