"""Run saved or candidate models on flows extracted from a real pcap, per extraction path.

Compares three versions of the same packets:
    training   extracted the way the training data was extracted
    defective  extracted the way the lab tool does it, read by column name
    repaired   extracted the way the lab tool does it, then fixed by src/lab_data.py

Scores are reported separately for held-out rows only, since Friday rows also appear
in the models' training sets.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from parity_check import load_published, pair_rows  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.lab_data import remap_flags, repair_first_packet  # noqa: E402

KEY_COLUMNS = [
    "destination port", "flow duration", "total fwd packets", "total backward packets",
    "total length of fwd packets", "total length of bwd packets", "flow iat mean",
    "init_win_bytes_forward", "init_win_bytes_backward", "packet length std", "idle mean",
]


def row_keys(frame: pd.DataFrame) -> pd.Series:
    values = frame[KEY_COLUMNS].astype(float).round(3).astype(str)
    return values.agg("|".join, axis=1)


def clean_label(label: str) -> str:
    return str(label).replace("�", "-").replace("\x96", "-").strip()


def score_version(name, flows, labels, detector, forest, class_names, threshold_name):
    frame = flows.replace([np.inf, -np.inf], np.nan)
    scores = detector.score(frame)
    is_attack = labels != "BENIGN"
    flagged = scores >= detector.thresholds[threshold_name]
    filled = frame[list(forest.feature_names_in_)].fillna(0)
    probabilities = forest.predict_proba(filled)
    predicted = np.array(class_names)[probabilities.argmax(axis=1)]
    top = probabilities.max(axis=1)
    result = {
        "version": name,
        "benign rows": int((~is_attack).sum()),
        "attack rows": int(is_attack.sum()),
        "IF false alarms": float(flagged[~is_attack].mean()),
        "IF attack recall": float(flagged[is_attack].mean()),
        "IF AUC": float(roc_auc_score(is_attack, scores)),
        "RF correct on attacks": float((predicted[is_attack] == labels[is_attack]).mean()),
        "RF confidence on attacks": float(top[is_attack].mean()),
    }
    per_class = {
        label: {
            "IF flagged": float(flagged[labels == label].mean()),
            "RF correct": float((predicted[labels == label] == label).mean()),
            "RF top prediction": pd.Series(predicted[labels == label]).value_counts().index[0],
        }
        for label in np.unique(labels) if label != "BENIGN"
    }
    return result, per_class


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("published_zip", type=Path)
    parser.add_argument("--day", default="Friday")
    parser.add_argument("--if-model", type=Path, required=True)
    parser.add_argument("--rf-model", type=Path, required=True)
    parser.add_argument("--heldout-if", type=Path, help="parquet of held-out IF rows")
    parser.add_argument("--heldout-rf", type=Path, help="parquet of held-out RF rows")
    parser.add_argument("--threshold", default="FPR<=3%")
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    published = load_published(args.published_zip, args.day)
    versions = {}
    for profile in ("training", "v4_2018"):
        cached = args.cache / f"{args.day}_{profile}.parquet"
        versions[profile] = pd.read_parquet(cached) if cached.exists() else extract_flows(args.pcap, profile)
        if not cached.exists():
            args.cache.mkdir(parents=True, exist_ok=True)
            versions[profile].to_parquet(cached, index=False)

    paired = {p: pair_rows(published, flows) for p, flows in versions.items()}
    print({p: len(frame) for p, frame in paired.items()}, "of", len(published), flush=True)

    def flows_from(frame):
        out = frame.rename(columns=lambda c: c[:-10] if c.endswith("_extracted") else c)
        out = out.loc[:, ~out.columns.str.endswith("_published")]
        return out

    training = paired["training"]
    keep = KEY_COLUMNS
    defective_pairs = paired["v4_2018"]
    key_cols = ["source ip", "source port", "destination ip", "destination port", "protocol", "flow duration", "pair"]
    joined = defective_pairs[key_cols].merge(training[key_cols], on=key_cols)
    training = training.merge(joined, on=key_cols).reset_index(drop=True)
    defective_pairs = defective_pairs.merge(joined, on=key_cols).reset_index(drop=True)

    labels = np.array([clean_label(v) for v in training["label"]])
    published_view = training.rename(columns=lambda c: c[:-10] if c.endswith("_published") else c)
    keys = row_keys(published_view)

    train_flows = flows_from(training)
    defect_flows = flows_from(defective_pairs)
    repaired_flows = remap_flags(repair_first_packet(defect_flows))
    views = {"training": train_flows, "defective": defect_flows, "repaired": repaired_flows}

    detector = joblib.load(args.if_model)
    bundle = joblib.load(args.rf_model)
    forest = bundle["model"]
    class_names = [clean_label(c) for c in bundle["label_encoder"].classes_]

    masks = {"all rows": np.ones(len(labels), dtype=bool)}
    if args.heldout_if and args.heldout_rf:
        holdout_if = set(row_keys(pd.read_parquet(args.heldout_if)))
        holdout_rf = set(row_keys(pd.read_parquet(args.heldout_rf)))
        benign_ok = keys.isin(holdout_if).to_numpy() & (labels == "BENIGN")
        attack_ok = keys.isin(holdout_rf).to_numpy() & keys.isin(holdout_if).to_numpy() & (labels != "BENIGN")
        attack_rf = keys.isin(holdout_rf).to_numpy() & (labels != "BENIGN")
        masks["held out"] = benign_ok | attack_rf
        print("held out: benign", int(benign_ok.sum()), "attack in RF test", int(attack_rf.sum()),
              "attack in both tests", int(attack_ok.sum()), flush=True)

    report = {}
    for mask_name, mask in masks.items():
        rows, classes = [], {}
        for name, view in views.items():
            row, per_class = score_version(
                name, view[mask].reset_index(drop=True), labels[mask], detector, forest, class_names, args.threshold,
            )
            rows.append(row)
            classes[name] = per_class
        table = pd.DataFrame(rows).set_index("version")
        print(f"\n=== {mask_name} ===")
        print(table.round(4).T.to_string())
        print(pd.concat({k: pd.DataFrame(v).T for k, v in classes.items()}, axis=1).to_string())
        report[mask_name] = dict(summary=rows, per_class=classes)

    # How well the CSV repair recovers true values, per feature.
    accuracy = {}
    for column in forest.feature_names_in_:
        a = repaired_flows[column].astype(float).to_numpy()
        b = train_flows[column].astype(float).to_numpy()
        accuracy[column] = float(np.isclose(a, b, rtol=1e-3, atol=1e-3, equal_nan=True).mean())
    report["repair_accuracy"] = accuracy
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1))
    series = pd.Series(accuracy).sort_values()
    print("\nRepair accuracy per feature, worst 24:")
    print(series.head(24).round(4).to_string())
    print(f"features >=99%: {(series >= .99).sum()} of {len(series)}")
