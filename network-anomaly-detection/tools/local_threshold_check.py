"""Test whether a threshold set from a network's own normal traffic fixes false alarms, and what it costs.

Each lab capture is split at random, because the extractor writes flows still open at the end of
a capture last, so a split by position would be biased. One half sets the threshold, and the
other measures false alarms. Both halves come from one session, so false alarms on a new session
could be higher. Attack detection uses real public attack flows held out of training, and the
team's repaired lab CSVs. Those attacks come from other networks, so their detection rates show
the direction of the trade-off, not a real-world figure.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mixed_check import attack_flows, wilson  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402
from src.pipeline import TwoStagePipeline  # noqa: E402

TARGETS = [None, 0.10, 0.05, 0.03]
MIN_CLASS_FLOWS = 20


def detection(pipeline: TwoStagePipeline, flows: pd.DataFrame, truth: np.ndarray) -> dict:
    alert = pipeline.predict(flows, validate=False)["decision"].to_numpy() == "alert"
    per_class = {name: float(alert[truth == name].mean()) for name in np.unique(truth)
                 if (truth == name).sum() >= MIN_CLASS_FLOWS}
    return {"macro detected": float(np.mean(list(per_class.values()))), "per class": per_class}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", nargs="+", required=True, help="name=path pairs of lab pcaps")
    parser.add_argument("--lab", required=True, help="glob of the team's lab CSVs")
    friday = parser.add_mutually_exclusive_group(required=True)
    friday.add_argument("--friday-pcap", type=Path)
    friday.add_argument("--friday-flows", type=Path)
    parser.add_argument("--published-zip", type=Path, required=True)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--saved-holdout", type=Path, required=True)
    parser.add_argument("--models", type=Path, default=Path("models/candidates"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    pipeline = TwoStagePipeline.load_chosen(args.models)
    public_attacks, public_truth = attack_flows(args)
    team = load_lab_csvs(args.lab)
    labelled = add_true_labels(team)
    keep = labelled["scored"].to_numpy() & (labelled["kind"].to_numpy() != "benign")
    team_attacks = remap_flags(repair_first_packet(team))[keep].reset_index(drop=True)
    team_truth = labelled["true_class"].to_numpy()[keep]

    report = {}
    for pair in args.benign:
        name, path = pair.split("=", 1)
        flows = extract_flows(path, "training")
        middle = len(flows) // 2
        order = np.random.default_rng(0).permutation(len(flows))
        calibrate, test = flows.iloc[order[:middle]], flows.iloc[order[middle:]]
        report[name] = {}
        print(f"\n{name}: {middle:,} flows set the threshold, {len(test):,} measure false alarms")
        for target in TARGETS:
            label = "built-in threshold" if target is None else f"local, target {target:.0%}"
            pipeline.threshold_op = None
            if target is not None:
                pipeline.set_local_threshold(calibrate, target)
            alert = pipeline.predict(test, validate=False)["decision"].to_numpy() == "alert"
            row = {
                "threshold": float(pipeline.threshold),
                "false alarms": float(alert.mean()),
                "95% CI": wilson(int(alert.sum()), len(alert)),
                "public attacks": detection(pipeline, public_attacks, public_truth),
                "team lab attacks": detection(pipeline, team_attacks, team_truth),
            }
            report[name][label] = row
            print(f"  {label}: false alarms {row['false alarms']:.1%}, "
                  f"public attacks {row['public attacks']['macro detected']:.1%}, "
                  f"team lab attacks {row['team lab attacks']['macro detected']:.1%}")
            print("     team lab:", {k: round(v, 3) for k, v in row["team lab attacks"]["per class"].items()})
    args.out.write_text(json.dumps(report, indent=1))
