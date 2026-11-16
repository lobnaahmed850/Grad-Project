"""Test whole pipelines on lab normal traffic mixed with real attack packets.

Normal flows come from pcaps captured in the rebuilt lab. Attack flows come from the public
Friday capture, keeping only flows that both the saved and the candidate models held out of
training. Attacks and normal traffic come from different networks, so this checks that the
fixed path works end to end. It is not a measure of real-world accuracy.
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
from e2e_real_traffic import clean_label, row_keys  # noqa: E402
from parity_check import load_published, pair_rows  # noqa: E402
from src.feature_contract import validate_flows  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline  # noqa: E402
from src.training import load_cicids, split_rows  # noqa: E402


def wilson(successes: int, total: int, z: float = 1.96) -> list[float]:
    if total == 0:
        return [float("nan"), float("nan")]
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return [float(centre - spread), float(centre + spread)]


def traffic_type(flows: pd.DataFrame) -> np.ndarray:
    sport, dport = flows["source port"].to_numpy(), flows["destination port"].to_numpy()
    size = (flows["total length of fwd packets"] + flows["total length of bwd packets"]).to_numpy()
    web = dport == 8080
    return np.select(
        [dport == 53, (dport == 22) | (sport == 22), web & (size < 2_000), web & (size < 100_000), web, sport == 8080],
        ["DNS", "SSH", "Web, under 2 kB", "Web, 2 to 100 kB", "Web, over 100 kB", "Web, leftover from server"],
        "Other",
    )


def score_benign(designs, flows) -> dict:
    kinds = traffic_type(flows)
    result = {}
    for name, pipeline in designs.items():
        alert = pipeline.predict(flows, validate=False)["decision"].to_numpy() == "alert"
        result[name] = {
            "false alarms": float(alert.mean()),
            "95% CI": wilson(int(alert.sum()), len(alert)),
            "per type": {k: {"flows": int((kinds == k).sum()), "flagged": float(alert[kinds == k].mean())}
                         for k in pd.unique(kinds)},
        }
    return result


def attack_flows(args) -> tuple[pd.DataFrame, np.ndarray]:
    published = load_published(args.published_zip, "Friday")
    extracted = pd.read_parquet(args.friday_flows) if args.friday_flows else extract_flows(args.friday_pcap, "training")
    paired = pair_rows(published, extracted)
    labels = np.array([clean_label(v) for v in paired["label"]])
    view = paired.rename(columns=lambda c: c[:-10] if c.endswith("_published") else c)
    keys = row_keys(view)

    data = load_cicids(args.csv_dir)
    _, _, test = split_rows(data["label"])
    candidate_test = set(row_keys(data.iloc[test]))
    saved_test = set(row_keys(pd.read_parquet(args.saved_holdout)))
    keep = keys.isin(candidate_test).to_numpy() & keys.isin(saved_test).to_numpy() & (labels != "BENIGN")

    flows = paired[keep].rename(columns=lambda c: c[:-10] if c.endswith("_extracted") else c)
    flows = flows.loc[:, ~flows.columns.str.endswith("_published")].reset_index(drop=True)
    return flows, labels[keep]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", nargs="+", required=True, help="name=path pairs of lab pcaps")
    friday = parser.add_mutually_exclusive_group(required=True)
    friday.add_argument("--friday-pcap", type=Path)
    friday.add_argument("--friday-flows", type=Path, help="parquet of flows already extracted from the Friday pcap")
    parser.add_argument("--published-zip", type=Path, required=True)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--saved-holdout", type=Path, required=True, help="held-out rows of the saved Random Forest")
    parser.add_argument("--saved-if", type=Path, required=True)
    parser.add_argument("--saved-rf", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    new_if = args.models / "if_portable_timing_65536.joblib"
    designs = {
        "saved models": TwoStagePipeline.load(args.saved_if, args.saved_rf, mode="serial", min_confidence=0.0),
        "new Stage 1, saved Stage 2": TwoStagePipeline.load(new_if, args.saved_rf, mode="serial", min_confidence=0.0),
        "parallel, chosen": TwoStagePipeline.load_chosen(args.models),
    }
    report: dict = {"benign": {}}

    all_benign = []
    for pair in args.benign:
        name, path = pair.split("=", 1)
        flows = extract_flows(path, "training")
        old = extract_flows(path, "v4_2018")
        all_benign.append(flows)
        size = flows["max packet length"].max()
        entry = {
            "flows": len(flows),
            "largest packet": float(size),
            "median flow iat min (us)": float(flows["flow iat min"].median()),
            "contract issues": [i.code for i in validate_flows(flows) if i.severity == "error"],
            "old extraction": {
                "contract errors": [i.code for i in validate_flows(old) if i.severity == "error"],
            },
            "designs": score_benign(designs, flows),
        }
        old_alert = designs["saved models"].predict(old, validate=False)["decision"].to_numpy() == "alert"
        entry["old extraction"]["false alarms"] = float(old_alert.mean())
        entry["old extraction"]["95% CI"] = wilson(int(old_alert.sum()), len(old_alert))
        report["benign"][name] = entry
        print(f"\n{name}: {len(flows):,} flows, largest packet {size:.0f}, gap {entry['median flow iat min (us)']:.0f} us, "
              f"contract errors {entry['contract issues']}")
        print(f"  old extraction, saved models: {entry['old extraction']['false alarms']:.1%} "
              f"errors {entry['old extraction']['contract errors']}")
        for design, row in entry["designs"].items():
            print(f"  {design}: {row['false alarms']:.1%} CI {[round(v, 3) for v in row['95% CI']]}")
            print("     ", {k: (v["flows"], round(v["flagged"], 3)) for k, v in row["per type"].items()})

    benign = pd.concat(all_benign, ignore_index=True)
    attacks, truth = attack_flows(args)
    print(f"\nattack flows held out by both model sets: {len(attacks):,}", pd.Series(truth).value_counts().to_dict())

    report["mixed"] = {}
    for name, pipeline in designs.items():
        verdict = pipeline.predict(attacks, validate=False)
        alert = verdict["decision"].to_numpy() == "alert"
        types = verdict["attack_type"].to_numpy()
        benign_alert = pipeline.predict(benign, validate=False)["decision"].to_numpy() == "alert"
        per_class = {
            c: {"flows": int((truth == c).sum()), "detected": float(alert[truth == c].mean()),
                "correct type": float((types[truth == c] == c).mean())}
            for c in np.unique(truth)
        }
        report["mixed"][name] = {
            "benign flows": len(benign),
            "false alarms": float(benign_alert.mean()),
            "95% CI": wilson(int(benign_alert.sum()), len(benign_alert)),
            "attacks detected": float(alert.mean()),
            "macro detected": float(np.mean([v["detected"] for v in per_class.values()])),
            "macro correct type": float(np.mean([v["correct type"] for v in per_class.values()])),
            "per class": per_class,
        }
        row = report["mixed"][name]
        print(f"{name}: false alarms {row['false alarms']:.1%}, macro detected {row['macro detected']:.3f}, "
              f"macro correct type {row['macro correct type']:.3f}")
        print("    ", {k: (round(v["detected"], 3), round(v["correct type"], 3), v["flows"]) for k, v in per_class.items()})
    args.out.write_text(json.dumps(report, indent=1, default=float))
