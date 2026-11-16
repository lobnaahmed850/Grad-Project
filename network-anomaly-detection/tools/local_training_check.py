"""Measure how much training on local lab traffic helps, using two kinds of hold-out.

Block test      Each lab file is cut into 5 contiguous blocks, and each block is scored by
                a model trained on the public data plus the other 4 blocks. Flows in a file
                come from one run, so this is an upper bound.
File test       Each lab file is scored by a model trained on the public data plus the other
                lab files. Most classes have one file, so the model has seen that attack
                only in public data. This is the honest test of a brand-new capture.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING  # noqa: E402
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402
from src.pipeline import to_numeric_frame  # noqa: E402
from src.training import RF_PARAMS, load_cicids, split_rows  # noqa: E402

MIN_CLASS_FLOWS = 20
FEATURE_SETS = {"portable": PORTABLE_FEATURES, "portable+timing": PORTABLE_WITH_TIMING}


def wilson(successes: int, total: int, z: float = 1.96) -> list[float]:
    if total == 0:
        return [float("nan"), float("nan")]
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return [float(centre - spread), float(centre + spread)]


def fit(public_x, public_y, lab_x, lab_y) -> RandomForestClassifier:
    x = pd.concat([public_x, lab_x], ignore_index=True)
    y = np.concatenate([public_y, lab_y])
    return RandomForestClassifier(**RF_PARAMS).fit(x, y)


def summarize(truth, predicted) -> dict:
    benign = truth == "BENIGN"
    rows = {}
    for name in sorted(set(truth[~benign])):
        where = truth == name
        if where.sum() < MIN_CLASS_FLOWS:
            continue
        top = pd.Series(predicted[where]).value_counts(normalize=True)
        rows[name] = {
            "flows": int(where.sum()),
            "correct": float((predicted[where] == name).mean()),
            "called benign": float((predicted[where] == "BENIGN").mean()),
            "top": f"{top.index[0]} {top.iloc[0]:.0%}",
        }
    false_alarms = int((predicted[benign] != "BENIGN").sum())
    return {
        "benign flows": int(benign.sum()),
        "false alarms": false_alarms / max(int(benign.sum()), 1),
        "false alarms 95% CI": wilson(false_alarms, int(benign.sum())),
        "macro correct": float(np.mean([r["correct"] for r in rows.values()])),
        "macro called benign": float(np.mean([r["called benign"] for r in rows.values()])),
        "per class": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--feature-sets", nargs="+", default=list(FEATURE_SETS), choices=list(FEATURE_SETS))
    args = parser.parse_args()

    data = load_cicids(args.csv_dir)
    flows = load_lab_csvs(args.lab)
    labelled = add_true_labels(flows)
    keep = labelled["scored"].to_numpy()
    repaired = remap_flags(repair_first_packet(flows))[keep].reset_index(drop=True)
    truth = labelled["true_class"].to_numpy()[keep]
    files = labelled["source_file"].to_numpy()[keep]

    report = {}
    for name in args.feature_sets:
        features = FEATURE_SETS[name]
        unique = data
        train, _, test = split_rows(unique["label"])
        public_x = unique[features].iloc[train].reset_index(drop=True)
        public_y = unique["label"].to_numpy()[train]
        test_x, test_y = unique[features].iloc[test], unique["label"].to_numpy()[test]
        lab_x = to_numeric_frame(repaired, features)

        blocks = np.zeros(len(lab_x), dtype=int)
        for file_name in np.unique(files):
            where = np.flatnonzero(files == file_name)
            blocks[where] = np.arange(len(where)) * 5 // len(where)

        predicted = np.empty(len(lab_x), dtype=object)
        public_scores = []
        for block in range(5):
            model = fit(public_x, public_y, lab_x[blocks != block], truth[blocks != block])
            predicted[blocks == block] = model.predict(lab_x[blocks == block])
            public_predicted = model.predict(test_x)
            attack = test_y != "BENIGN"
            per_class = [(public_predicted[test_y == c] == c).mean() for c in np.unique(test_y) if c != "BENIGN"]
            public_scores.append({
                "public macro recall": float(np.mean(per_class)),
                "public false alarms": float((public_predicted[~attack] != "BENIGN").mean()),
            })
            print(name, "block", block, public_scores[-1], flush=True)
        block_result = summarize(truth, predicted)
        block_result["public test"] = pd.DataFrame(public_scores).mean().to_dict()
        print(name, "BLOCK", {k: v for k, v in block_result.items() if k != "per class"}, flush=True)
        print(pd.DataFrame(block_result["per class"]).T.to_string(), flush=True)

        predicted = np.empty(len(lab_x), dtype=object)
        for file_name in np.unique(files):
            hold = files == file_name
            model = fit(public_x, public_y, lab_x[~hold], truth[~hold])
            predicted[hold] = model.predict(lab_x[hold])
            print(name, "file", file_name, pd.Series(predicted[hold]).value_counts(normalize=True).head(2).round(3).to_dict(), flush=True)
        file_result = summarize(truth, predicted)
        print(name, "FILE", {k: v for k, v in file_result.items() if k != "per class"}, flush=True)
        print(pd.DataFrame(file_result["per class"]).T.to_string(), flush=True)
        report[name] = {"block test": block_result, "file test": file_result}
        args.out.write_text(json.dumps(report, indent=1))
    print("done")
