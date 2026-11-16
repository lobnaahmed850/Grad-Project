"""Score models on the lab CSVs, before and after each data fix.

    python tools/eval_lab.py --lab "localdata/*.csv" --if-model models/iforest_v0.1.0.joblib \
        --rf-model models/random_forest_final.joblib --out reports/lab.json
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
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402


def clean_label(label) -> str:
    return str(label).replace("�", "-").replace("\x96", "-").strip()


def score(frame, labelled, detector, forest, class_names):
    usable = frame.replace([np.inf, -np.inf], np.nan)
    mask = labelled["scored"].to_numpy()
    usable, info = usable[mask].reset_index(drop=True), labelled[mask].reset_index(drop=True)
    benign = (info["kind"] == "benign").to_numpy()
    scores = detector.score(usable)
    result = {
        "benign flows": int(benign.sum()),
        "attack flows": int((~benign).sum()),
        "IF AUC": float(roc_auc_score(~benign, scores)),
        "IF false alarms": {op: float((scores[benign] >= t).mean()) for op, t in detector.thresholds.items()},
        "IF recall": {op: float((scores[~benign] >= t).mean()) for op, t in detector.thresholds.items()},
    }
    filled = usable[list(forest.feature_names_in_)].fillna(0)
    probabilities = forest.predict_proba(filled)
    predicted = np.array(class_names)[probabilities.argmax(axis=1)]
    known = (info["kind"] == "known").to_numpy()
    result["RF correct, labels as filed"] = float((predicted[known] == info["Label_clean"][known]).mean())
    result["RF correct, true labels"] = float((predicted[known] == info["true_class"][known]).mean())
    result["RF confidence on attacks"] = float(probabilities[~benign].max(axis=1).mean())
    result["per file"] = {}
    for name, part in info.groupby("source_file"):
        rows = part.index.to_numpy()
        top = pd.Series(predicted[rows]).value_counts(normalize=True)
        result["per file"][name] = {
            "flows": len(rows),
            "true class": part["true_class"].iloc[0],
            "RF correct": float((predicted[rows] == part["true_class"]).mean()),
            "RF top": f"{top.index[0]} {top.iloc[0]:.0%}",
            "IF flagged": float((scores[rows] >= detector.thresholds[detector.default_op]).mean()),
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--if-model", type=Path, required=True)
    parser.add_argument("--rf-model", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    flows = load_lab_csvs(args.lab)
    labelled = add_true_labels(flows)
    labelled["Label_clean"] = (
        labelled["Label"].astype(str).str.strip().replace({"DoS-Slowloris": "DoS slowloris", "Benign": "BENIGN"})
    )
    detector = joblib.load(args.if_model)
    bundle = joblib.load(args.rf_model)
    forest = bundle["model"]
    class_names = [clean_label(c) for c in bundle["label_encoder"].classes_]

    versions = {
        "as extracted": flows,
        "flags fixed": remap_flags(flows),
        "first packet fixed": repair_first_packet(flows),
        "both fixed": remap_flags(repair_first_packet(flows)),
    }
    report = {name: score(frame, labelled, detector, forest, class_names) for name, frame in versions.items()}
    pd.set_option("display.width", 200)
    print("scored", int(labelled["scored"].sum()), "of", len(labelled))
    print(labelled.groupby(["source_file", "true_class", "kind"])["scored"].agg(["size", "sum"]).to_string())
    summary = pd.DataFrame({
        name: {
            "IF AUC": r["IF AUC"],
            "false alarms @3%": r["IF false alarms"]["FPR<=3%"],
            "false alarms @1%": r["IF false alarms"]["FPR<=1%"],
            "false alarms @0.1%": r["IF false alarms"]["FPR<=0.1%"],
            "recall @3%": r["IF recall"]["FPR<=3%"],
            "recall @0.1%": r["IF recall"]["FPR<=0.1%"],
            "RF correct, as filed": r["RF correct, labels as filed"],
            "RF correct, true labels": r["RF correct, true labels"],
            "RF confidence": r["RF confidence on attacks"],
        } for name, r in report.items()
    })
    print(summary.round(4).to_string())
    for name in ("as extracted", "both fixed"):
        print(f"\n{name}")
        print(pd.DataFrame(report[name]["per file"]).T.to_string())
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1))
