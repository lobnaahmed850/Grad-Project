"""Run a capture through the whole fixed path: extract, check the contract, then score.

    python tools/test_capture.py lab/captures/benign.pcap --expect benign \
        --if-model models/iforest_v0.1.0.joblib --rf-model models/random_forest_final.joblib \
        --out reports/my_capture.json

Flows are labeled by --expect because the lab generated only that kind of traffic.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import validate_flows  # noqa: E402
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import TwoStagePipeline  # noqa: E402


def wilson(successes: int, total: int, z: float = 1.96) -> list[float]:
    if total == 0:
        return [float("nan"), float("nan")]
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return [float(centre - spread), float(centre + spread)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--expect", default="benign")
    parser.add_argument("--if-model", type=Path, required=True)
    parser.add_argument("--rf-model", type=Path, required=True)
    parser.add_argument("--models", type=Path, default=Path("models/candidates"), help="folder with the chosen design")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    flows = extract_flows(args.pcap, "training")
    print(f"{len(flows):,} flows, protocols {flows['protocol'].value_counts().to_dict()}")
    top_ports = flows["destination port"].value_counts().head(6).to_dict()
    print(f"top destination ports {top_ports}")

    issues = validate_flows(flows)
    print("contract:", [(i.severity, i.code) for i in issues] or "passed")
    report = {
        "flows": len(flows),
        "contract issues": [i.code for i in issues],
        "zero forward packets": float((flows["total fwd packets"] == 0).mean()),
        "median flow iat min (us)": float(flows["flow iat min"].median()),
        "median flow duration (us)": float(flows["flow duration"].median()),
        "models": {},
    }
    print(f"zero forward packets {report['zero forward packets']:.2%}, "
          f"median flow iat min {report['median flow iat min (us)']:.0f} us")

    # The same packets through the old extraction, to measure what the fix changes.
    defective = extract_flows(args.pcap, "v4_2018")
    report["old extraction"] = {
        "contract errors": [i.code for i in validate_flows(defective) if i.severity == "error"],
        "zero forward packets": float((defective["total fwd packets"] == 0).mean()),
    }
    saved = TwoStagePipeline.load(args.if_model, args.rf_model, mode="serial", min_confidence=0.0)
    old_verdict = saved.predict(defective, validate=False)
    old_alerts = int((old_verdict["decision"] == "alert").sum())
    report["old extraction"].update(
        alerts=old_alerts, share=old_alerts / len(defective), **{"95% CI": wilson(old_alerts, len(defective))},
    )
    print(f"OLD extraction, saved Stage 1: contract errors {report['old extraction']['contract errors']}")
    print(f"   zero forward packets {report['old extraction']['zero forward packets']:.2%}, "
          f"{old_alerts}/{len(defective)} flagged = {report['old extraction']['share']:.1%}")

    for name, pipeline in (("saved models", saved), ("chosen design", TwoStagePipeline.load_chosen(args.models))):
        verdict = pipeline.predict(flows)
        alerts = int((verdict["decision"] == "alert").sum())
        share = alerts / len(flows)
        by_port = flows.assign(alert=verdict["decision"].to_numpy() == "alert")
        ports = by_port.groupby("destination port")["alert"].agg(["size", "mean"]).sort_values("size", ascending=False).head(5)
        report["models"][name] = {
            "alerts": alerts, "share": share, "95% CI": wilson(alerts, len(flows)),
            "attack labels": verdict.loc[verdict["decision"] == "alert", "attack_type"].value_counts().head(5).to_dict(),
            "per port": {str(int(k)): {"flows": int(v["size"]), "alert share": float(v["mean"])} for k, v in ports.iterrows()},
        }
        ci = report["models"][name]["95% CI"]
        print(f"{name}: {alerts}/{len(flows)} flagged = {share:.1%} (95% CI {ci[0]:.1%} to {ci[1]:.1%})")
        print("   ", report["models"][name]["per port"])
    if args.out:
        args.out.write_text(json.dumps(report, indent=1))
