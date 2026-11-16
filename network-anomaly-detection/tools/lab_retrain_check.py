"""Does retraining the detector on same-network normal fix false alarms without losing the attacks?

Three scenarios are compared on the SAME held-out lab-normal and the SAME lab attacks, at the
detector's FPR<=3% operating point:

  baseline    the shipped detector (Isolation Forest trained on public normal only)
  threshold   the baseline detector, with its threshold recalibrated on lab-normal only
  retrained   a new Isolation Forest trained on public normal + half of the lab-normal

The point: a threshold set from a network's own normal traffic silences the false alarms but also
silences the attacks, because the detector cannot separate them by score alone. Retraining on that
normal traffic lowers the false alarms AND keeps the attacks -- so more same-network normal, not a
threshold, is the way forward. Nothing here overwrites a saved model.

    python tools/lab_retrain_check.py --csv-dir data/raw/MachineLearningCVE \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
        --attack "PortScan=lab/captures/attack_lan_scan.pcap" "SYN flood=lab/captures/attack_lan_synflood.pcap" \
                 "HTTP flood=lab/captures/attack_lan_httpflood.pcap" \
        --saved-if models/candidates/if_portable_timing_65536.joblib --out reports/lab_retrain_detector.json
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
from src.feature_contract import PORTABLE_WITH_TIMING as FEATURES  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import to_numeric_frame  # noqa: E402
from src.training import fit_detector, load_cicids, split_rows  # noqa: E402

OP = "FPR<=3%"


def feats(path: str) -> pd.DataFrame:
    return to_numeric_frame(extract_flows(str(path), "training"), FEATURES).replace([np.inf, -np.inf], np.nan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--benign", nargs="+", required=True, help="lab-normal pcaps")
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap pairs of lab attacks")
    parser.add_argument("--saved-if", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = np.random.default_rng(0)

    print("extracting lab captures ...", flush=True)
    benign = pd.concat([feats(p) for p in args.benign], ignore_index=True)
    attacks = {}
    for pair in args.attack:
        name, path = pair.split("=", 1)
        attacks[name] = feats(path)

    # 50% trains the retrained detector, 20% calibrates thresholds, 30% measures false alarms.
    order = rng.permutation(len(benign))
    n_tr, n_va = len(benign) // 2, len(benign) // 5
    lb_train, lb_val, lb_test = (benign.iloc[order[:n_tr]], benign.iloc[order[n_tr:n_tr + n_va]],
                                 benign.iloc[order[n_tr + n_va:]])
    print(f"lab-normal {len(benign):,} -> train {len(lb_train):,} val {len(lb_val):,} test {len(lb_test):,}", flush=True)

    print("loading public CICIDS2017 ...", flush=True)
    public = load_cicids(args.csv_dir)
    pub_train, pub_val, pub_test = split_rows(public["label"])
    public_small = public[FEATURES + ["label"]]
    pub_test_frame = public_small.iloc[pub_test]
    pub_test_attack = public["label"].to_numpy()[pub_test] != "BENIGN"

    base = joblib.load(args.saved_if)

    aug = pd.concat([public_small, lb_train.assign(label="BENIGN"), lb_val.assign(label="BENIGN")], ignore_index=True)
    base_n = len(public_small)
    train_pos = np.concatenate([pub_train, np.arange(base_n, base_n + len(lb_train))])
    val_pos = np.concatenate([pub_val, np.arange(base_n + len(lb_train), base_n + len(lb_train) + len(lb_val))])
    print("fitting retrained detector ...", flush=True)
    retrained, _ = fit_detector(aug, train_pos, val_pos, FEATURES, 65536, "lab-augmented")

    frames = {"lab normal (held out)": lb_test, **attacks}
    scores = {"baseline": {n: base.score(f) for n, f in frames.items()},
              "retrained": {n: retrained.score(f) for n, f in frames.items()}}
    pub_scores = {"baseline": base.score(pub_test_frame), "retrained": retrained.score(pub_test_frame)}

    scenarios = {
        "baseline": ("baseline", base.thresholds[OP]),
        "threshold (recalibrated on lab)": ("baseline", float(np.quantile(base.score(lb_val), 0.97))),
        "retrained (IF + lab normal)": ("retrained", retrained.thresholds[OP]),
    }

    header = f"{'scenario':34} {'lab FA':>7} " + " ".join(f"{n[:9]:>9}" for n in attacks) + f" {'pubFA':>6} {'pubRec':>7}"
    print("\n" + header, flush=True)
    report = {}
    for label, (detector, t) in scenarios.items():
        s, pub = scores[detector], pub_scores[detector]
        row = {"lab false alarm": float((s["lab normal (held out)"] >= t).mean()),
               "public false alarm": float((pub[~pub_test_attack] >= t).mean()),
               "public recall": float((pub[pub_test_attack] >= t).mean()), "threshold": t}
        for name in attacks:
            row[name] = float((s[name] >= t).mean())
        report[label] = row
        cells = " ".join(f"{row[n]:8.1%}" for n in attacks)
        print(f"{label:34} {row['lab false alarm']:6.1%} {cells} {row['public false alarm']:5.1%} {row['public recall']:6.1%}", flush=True)

    args.out.write_text(json.dumps(report, indent=1))
    print(f"\nwrote {args.out}")
