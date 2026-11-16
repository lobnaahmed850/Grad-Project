"""Find out why normal flows of a given size get flagged.

Compares false alarms by flow size on held-out public benign flows and on lab captures. For the
largest lab flows, it then swaps one feature at a time for the typical public value and measures
how many flows stop being flagged, to show which features cause the alarms.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline  # noqa: E402
from src.training import load_cicids, split_rows  # noqa: E402

BUCKETS = [0, 2_000, 100_000, 1_000_000, np.inf]
BUCKET_NAMES = ["under 2 kB", "2 to 100 kB", "100 kB to 1 MB", "over 1 MB"]


def total_bytes(flows: pd.DataFrame) -> pd.Series:
    return flows["total length of fwd packets"] + flows["total length of bwd packets"]


def by_size(flows: pd.DataFrame, flagged: np.ndarray) -> dict:
    groups = pd.cut(total_bytes(flows), BUCKETS, labels=BUCKET_NAMES, right=False).to_numpy()
    return {name: {"flows": int((groups == name).sum()), "flagged": float(flagged[groups == name].mean())}
            for name in BUCKET_NAMES if (groups == name).any()}


def flagged_by(pipeline: TwoStagePipeline, flows: pd.DataFrame) -> np.ndarray:
    return pipeline.detector.score(pipeline._for_detector(flows)) >= pipeline.threshold


def swap_test(pipeline: TwoStagePipeline, lab: pd.DataFrame, public: pd.DataFrame) -> list[dict]:
    """Report how many flagged lab flows stop being flagged when one feature takes its public median."""
    flagged = lab[flagged_by(pipeline, lab)]
    rows = []
    for feature in pipeline.detector.features:
        typical = pd.to_numeric(public[feature], errors="coerce").replace([np.inf, -np.inf], np.nan).median()
        swapped = flagged.copy()
        swapped[feature] = typical
        lab_values = pd.to_numeric(flagged[feature], errors="coerce").replace([np.inf, -np.inf], np.nan)
        public_values = pd.to_numeric(public[feature], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        rows.append({
            "feature": feature,
            "alarms removed": float(1 - flagged_by(pipeline, swapped).mean()),
            "lab median": float(lab_values.median()),
            "public median": float(typical),
            "lab median's public percentile": float((public_values < lab_values.median()).mean()),
        })
    return sorted(rows, key=lambda row: -row["alarms removed"])


def feature_group(feature: str) -> str:
    if any(word in feature for word in ("iat", "duration", "/s", "active", "idle")):
        return "speed and timing"
    if any(word in feature for word in ("length", "size", "bytes")) and "header" not in feature:
        return "packet and flow sizes"
    if "packets" in feature:
        return "packet counts"
    return "flags, headers and windows"


def group_swap_test(pipeline: TwoStagePipeline, lab: pd.DataFrame, public: pd.DataFrame) -> dict:
    """Report how many flagged lab flows stop being flagged when a whole group takes public medians."""
    flagged = lab[flagged_by(pipeline, lab)]
    groups: dict[str, list[str]] = {}
    for feature in pipeline.detector.features:
        groups.setdefault(feature_group(feature), []).append(feature)
    groups["speed, timing and sizes"] = groups["speed and timing"] + groups["packet and flow sizes"]
    result = {}
    for name, features in groups.items():
        swapped = flagged.copy()
        for feature in features:
            values = pd.to_numeric(public[feature], errors="coerce").replace([np.inf, -np.inf], np.nan)
            swapped[feature] = values.median()
        result[name] = {"features": len(features), "alarms removed": float(1 - flagged_by(pipeline, swapped).mean())}
    return result


def at_public_mix(lab_sizes: dict, public_sizes: dict) -> float:
    """Estimate the false alarm rate if lab flows had the public flow-size mix."""
    total = sum(row["flows"] for row in public_sizes.values())
    return sum(public_sizes[name]["flows"] / total * lab_sizes[name]["flagged"] for name in public_sizes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", nargs="+", required=True, help="name=path pairs of lab pcaps")
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--models", type=Path, default=Path("models/candidates"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    pipeline = TwoStagePipeline.load_chosen(args.models)
    data = load_cicids(args.csv_dir)
    _, _, test = split_rows(data["label"])
    public = data.iloc[test]
    public = public[public["label"].astype(str).str.strip() == "BENIGN"].reset_index(drop=True)
    public_flagged = flagged_by(pipeline, public)

    report = {"public benign, held out": {"flows": len(public), "flagged": float(public_flagged.mean()),
                                          "by size": by_size(public, public_flagged)}}
    print("public benign:", f"{public_flagged.mean():.1%}", report["public benign, held out"]["by size"])
    web = public["destination port"].isin([80, 443, 8080])
    report["public benign, web ports"] = {"flows": int(web.sum()), "flagged": float(public_flagged[web].mean()),
                                          "by size": by_size(public[web], public_flagged[web])}
    print("public web:", f"{public_flagged[web].mean():.1%}", report["public benign, web ports"]["by size"])

    lab_large = []
    report["lab"] = {}
    for pair in args.benign:
        name, path = pair.split("=", 1)
        flows = extract_flows(path, "training")
        flagged = flagged_by(pipeline, flows)
        sizes = by_size(flows, flagged)
        estimate = at_public_mix(sizes, report["public benign, held out"]["by size"])
        report["lab"][name] = {"flows": len(flows), "flagged": float(flagged.mean()), "by size": sizes,
                               "flagged at public size mix": estimate}
        print(name, f"{flagged.mean():.1%}, at public size mix {estimate:.1%}", sizes)
        lab_large.append(flows[(flows["destination port"] == 8080) & (total_bytes(flows) >= 100_000)])

    large = pd.concat(lab_large, ignore_index=True)
    public_large = public[web & (total_bytes(public) >= 100_000)]
    report["large web flows"] = {
        "lab flows": len(large), "public flows": len(public_large),
        "swap test": swap_test(pipeline, large, public_large),
        "group swap test": group_swap_test(pipeline, large, public_large),
    }
    print(f"\nlarge web flows: lab {len(large)}, public {len(public_large)}, "
          f"flagged lab {flagged_by(pipeline, large).mean():.1%}, public {flagged_by(pipeline, public_large).mean():.1%}")
    for row in report["large web flows"]["swap test"][:12]:
        percentile = row["lab median's public percentile"]
        print(f"  {row['feature']:<32} removes {row['alarms removed']:6.1%}  lab {row['lab median']:>14,.1f}  "
              f"public {row['public median']:>14,.1f}  percentile {percentile:.3f}")
    print("group swaps:", report["large web flows"]["group swap test"])
    args.out.write_text(json.dumps(report, indent=1))
