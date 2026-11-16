"""Test on traffic the model has not seen, which random splits cannot show.

Day test    Fit the Isolation Forest on Monday to Wednesday, set thresholds there, and
            score Thursday and Friday. Every attack in those days is new to the model.
Local test  Set a threshold on half of the lab's benign flows and score the other half,
            over many random splits. This shows how far a local threshold can be trusted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING  # noqa: E402
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402
from src.training import fit_detector, load_cicids  # noqa: E402

SEEN_DAYS = ("monday", "tuesday", "wednesday")
UNSEEN_DAYS = ("thursday", "friday")


def day_test(data, features, max_samples, name) -> dict:
    days = data["day"].to_numpy()
    seen = np.flatnonzero(np.isin(days, SEEN_DAYS))
    unseen = np.flatnonzero(np.isin(days, UNSEEN_DAYS))
    shuffled = np.random.default_rng(42).permutation(seen)
    cut = int(len(shuffled) * 0.85)
    detector, _ = fit_detector(data, shuffled[:cut], shuffled[cut:], features, max_samples, name)
    labels = data["label"].to_numpy()[unseen]
    scores = detector.score(data.iloc[unseen])
    benign = labels == "BENIGN"
    threshold = detector.thresholds["FPR<=3%"]
    recall = {c: float((scores[labels == c] >= threshold).mean()) for c in np.unique(labels) if c != "BENIGN"}
    return {
        "unseen day false alarms (target 3%)": float((scores[benign] >= threshold).mean()),
        "unseen day AUC": float(roc_auc_score(~benign, scores)),
        "unseen attack macro recall": float(np.mean(list(recall.values()))),
        "per class": recall,
    }


def local_threshold_test(detector, benign_flows, attack_flows, attack_classes, target=0.10, repeats=500) -> dict:
    benign_scores = detector.score(benign_flows)
    attack_scores = detector.score(attack_flows)
    classes = [c for c in np.unique(attack_classes) if (attack_classes == c).sum() >= 20]
    generator = np.random.default_rng(42)
    false_alarms, recalls, per_class = [], [], []
    for _ in range(repeats):
        order = generator.permutation(len(benign_scores))
        half = len(order) // 2
        threshold = np.quantile(benign_scores[order[:half]], 1 - target)
        false_alarms.append((benign_scores[order[half:]] >= threshold).mean())
        recalls.append((attack_scores >= threshold).mean())
        per_class.append([(attack_scores[attack_classes == c] >= threshold).mean() for c in classes])
    return {
        "target false alarms": target,
        "benign flows": int(len(benign_scores)),
        "false alarms median": float(np.median(false_alarms)),
        "false alarms 5th to 95th percentile": [float(np.quantile(false_alarms, q)) for q in (0.05, 0.95)],
        "attack recall median": float(np.median(recalls)),
        "macro attack recall median": float(np.median(np.mean(per_class, axis=1))),
        "per class median": {c: float(v) for c, v in zip(classes, np.median(per_class, axis=0))},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--saved-if", type=Path, required=True)
    parser.add_argument("--candidate-if", nargs="+", required=True, help="name=path pairs")
    parser.add_argument("--max-samples", type=int, default=65536)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    data = load_cicids(args.csv_dir)
    saved = joblib.load(args.saved_if)
    report = {"day test": {
        "saved feature set, full size": day_test(data, list(saved.features), 0.9612, "day-saved"),
        "saved feature set, same smaller size": day_test(data, list(saved.features), args.max_samples, "day-saved-small"),
        "portable features with timing": day_test(data, PORTABLE_WITH_TIMING, args.max_samples, "day-portable-timing"),
        "portable features": day_test(data, PORTABLE_FEATURES, args.max_samples, "day-portable"),
    }}
    for name, row in report["day test"].items():
        print(name, {k: round(v, 4) for k, v in row.items() if isinstance(v, float)}, flush=True)

    flows = load_lab_csvs(args.lab)
    labelled = add_true_labels(flows)
    keep = labelled["scored"].to_numpy()
    repaired = remap_flags(repair_first_packet(flows))[keep].replace([np.inf, -np.inf], np.nan).reset_index(drop=True)
    benign = labelled["kind"].to_numpy()[keep] == "benign"
    classes = labelled["true_class"].to_numpy()[keep]
    detectors = [("saved", saved)]
    for pair in args.candidate_if:
        name, path = pair.split("=", 1)
        detectors.append((name, joblib.load(path)))
    report["local threshold"] = {}
    for name, detector in detectors:
        for target in (0.05, 0.10):
            result = local_threshold_test(detector, repaired[benign], repaired[~benign], classes[~benign], target)
            report["local threshold"][f"{name} target {target:.0%}"] = result
            print(name, result, flush=True)
    args.out.write_text(json.dumps(report, indent=1))
