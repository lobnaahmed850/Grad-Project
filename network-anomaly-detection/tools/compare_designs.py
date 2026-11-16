"""Compare pipeline designs on public held-out rows and on lab traffic, and measure speed.

All candidate models share one train and test split. Public scores are reported for all
test rows and for test rows whose feature values never appear in training.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_WITH_TIMING  # noqa: E402
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402
from src.pipeline import TwoStagePipeline  # noqa: E402
from src.training import fit_classifier, load_cicids, split_rows, unseen_rows  # noqa: E402
from train_candidates import chain_results  # noqa: E402

MIN_CLASS_FLOWS = 20


def names_of(bundle) -> list[str]:
    return [str(c).replace("�", "-").replace("\x96", "-").strip() for c in bundle["label_encoder"].classes_]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--saved-if", type=Path, required=True)
    parser.add_argument("--saved-rf", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    data = load_cicids(args.csv_dir)
    train, _, test = split_rows(data["label"])
    views = {}
    for name, rows in (("public, all test rows", test), ("public, unseen rows", unseen_rows(data, train, test, PORTABLE_WITH_TIMING))):
        frame = data.iloc[rows].reset_index(drop=True)
        truth = frame["label"].to_numpy()
        views[name] = (frame, truth, np.where(truth == "BENIGN", "benign", "known"))
    public_rows = views["public, all test rows"][0]

    flows = load_lab_csvs(args.lab)
    labelled = add_true_labels(flows)
    keep = labelled["scored"].to_numpy()
    lab_flows = remap_flags(repair_first_packet(flows))[keep].reset_index(drop=True)
    lab_truth = labelled["true_class"].to_numpy()[keep]
    lab_kind = labelled["kind"].to_numpy()[keep]

    detector = joblib.load(args.models / "if_portable_timing_65536.joblib")
    rf15 = joblib.load(args.models / "rf15_portable_timing.joblib")

    # The team's Random Forest recipe on all 78 features, refit on the shared split so that
    # public test rows stay unseen. The saved Random Forest used a different split.
    all_features = list(joblib.load(args.saved_rf)["model"].feature_names_in_)
    attack_train = train[data["label"].to_numpy()[train] != "BENIGN"]
    type_bundle = fit_classifier(data, attack_train, all_features)
    joblib.dump(type_bundle, args.models / "rf14_all_features.joblib", compress=3)
    type_names = names_of(type_bundle)

    designs = {
        "serial": TwoStagePipeline(detector, type_bundle["model"], type_names, mode="serial", min_confidence=0.0),
        "parallel, RF15 confidence 0.5": TwoStagePipeline(
            detector, rf15["model"], names_of(rf15), mode="parallel", min_confidence=0.5,
            type_classifier=type_bundle["model"], type_names=type_names),
        "parallel, RF15 confidence 0.9": TwoStagePipeline(
            detector, rf15["model"], names_of(rf15), mode="parallel", min_confidence=0.9,
            type_classifier=type_bundle["model"], type_names=type_names),
    }
    report = {"designs": {}, "speed": {}}
    views["lab"] = (lab_flows, lab_truth, lab_kind)
    for name, pipeline in designs.items():
        report["designs"][name] = {}
        print(f"\n{name}")
        for view, (frame, truth, kind) in views.items():
            result = chain_results(pipeline, frame, truth, kind)
            report["designs"][name][view] = result
            print(f"  {view}: false alarms {result['false alarms']:.4f} CI "
                  f"{[round(v, 3) for v in result['false alarms 95% CI']]} detected {result['attacks detected']:.4f} "
                  f"macro detected {result['macro detected']:.4f} macro correct type {result['macro correct type']:.4f}")
            print("    ", {k: (round(v["detected"], 3), round(v["correct type"], 3), v["flows"])
                           for k, v in result["per class"].items()})

    saved_bundle = joblib.load(args.saved_rf)
    saved = TwoStagePipeline(
        joblib.load(args.saved_if), saved_bundle["model"], names_of(saved_bundle), mode="serial", min_confidence=0.0,
    )
    report["saved models on lab, with data fixes"] = chain_results(saved, lab_flows, lab_truth, lab_kind)
    result = report["saved models on lab, with data fixes"]
    print(f"\nsaved models, lab with fixes: false alarms {result['false alarms']:.4f} detected "
          f"{result['attacks detected']:.4f} macro detected {result['macro detected']:.4f} "
          f"macro correct type {result['macro correct type']:.4f}")
    print("    ", {k: (round(v["detected"], 3), round(v["correct type"], 3), v["flows"]) for k, v in result["per class"].items()})

    # Speed, using one worker per model as a serving process would.
    chosen = designs["parallel, RF15 confidence 0.9"]
    for model in (rf15["model"], type_bundle["model"]):
        model.n_jobs = 1
    sample = public_rows.sample(4096, random_state=42)
    for batch in (1, 32, 256, 1024):
        rows = sample.iloc[:batch]
        repeats = max(1, 256 // batch)
        started = time.perf_counter()
        for _ in range(repeats):
            chosen.predict(rows, validate=False)
        per_flow_ms = (time.perf_counter() - started) * 1000 / (repeats * batch)
        report["speed"][str(batch)] = per_flow_ms
        print(f"batch {batch}: {per_flow_ms:.3f} ms per flow", flush=True)
    report["sizes MB"] = {
        path.name: round(path.stat().st_size / 1e6, 1) for path in sorted(args.models.glob("*.joblib"))
    }
    print(report["sizes MB"])
    args.out.write_text(json.dumps(report, indent=1, default=float))
