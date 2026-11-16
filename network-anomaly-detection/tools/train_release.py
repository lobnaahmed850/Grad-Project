"""Train on complete runs, select/calibrate without test access, then evaluate once."""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING
from src.metrics import evaluate
from src.release import RELEASES, ReleaseModel, environment, sha256
from src.sessions import exclude_overlap, load_role, read_manifest
from src.streaming import FEATURE_VERSION, FlowConfig

ROOT = Path(__file__).resolve().parents[2]
FEATURES = PORTABLE_WITH_TIMING + ["source flow rate"]


def matrix(frame, features):
    values = frame[features].to_numpy(dtype=np.float64, copy=True)
    values[~np.isfinite(values)] = np.nan
    return values


def latency(model, sample, repeats=100):
    timings = []
    row = sample.iloc[:1]
    model.predict(row)
    for _ in range(repeats):
        started = time.perf_counter_ns()
        model.predict(row)
        timings.append((time.perf_counter_ns() - started) / 1e6)
    return {"mean_ms": float(np.mean(timings)), "p50_ms": float(np.median(timings)),
            "p95_ms": float(np.quantile(timings, 0.95)), "p99_ms": float(np.quantile(timings, 0.99)),
            "max_ms": max(timings)}


def train(manifest_path, release_dir, reports):
    if release_dir.exists():
        raise ValueError("Release directory exists; never overwrite an evaluated model")
    reports.mkdir(parents=True, exist_ok=True)
    config = FlowConfig(idle_seconds=1.0, active_seconds=8.0, rate_window_seconds=1.0)
    manifest = read_manifest(manifest_path, ROOT)
    print("Extracting training and calibration sessions", flush=True)
    training, train_excluded = load_role(manifest, "train", ROOT, config)
    calibration_all, cal_excluded = load_role(manifest, "calibration", ROOT, config)
    calibration, cal_overlap = exclude_overlap(training, calibration_all, FEATURES)
    expected = set(training["label"])
    if set(calibration["label"]) != expected or "BENIGN" not in expected or len(expected) < 2:
        raise ValueError("Independent calibration must retain benign and every training attack category after overlap removal")
    candidates = []
    all_metrics = {}
    for name, features, trees in (
        ("per-flow-rf32", PORTABLE_WITH_TIMING, 32),
        ("causal-rf32", FEATURES, 32),
        ("causal-rf64", FEATURES, 64),
    ):
        classifier = Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("forest", RandomForestClassifier(n_estimators=trees, max_depth=12, min_samples_leaf=2,
                                              class_weight="balanced_subsample", random_state=42, n_jobs=1)),
        ]).fit(matrix(training, features), training["label"].to_numpy())
        for confidence in (0.5, 0.7, 0.9):
            identifier = f"{name}-confidence-{confidence}"
            model = ReleaseModel(classifier, features, release_dir.name, config, confidence)
            metrics = evaluate(model, calibration)
            speed = latency(model, calibration, repeats=30)
            all_metrics[identifier] = {"calibration": metrics, "latency": speed}
            candidates.append((identifier, model, metrics, speed))
        if name == "causal-rf32":
            benign = training[training["label"].eq("BENIGN")]
            detector = Pipeline([
                ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
                ("forest", IsolationForest(n_estimators=32, max_samples=min(256, len(benign)), random_state=42, n_jobs=1)),
            ]).fit(matrix(benign, PORTABLE_FEATURES))
            benign_cal = calibration[calibration["label"].eq("BENIGN")]
            threshold = float(np.quantile(-detector.score_samples(matrix(benign_cal, PORTABLE_FEATURES)), 0.995))
            identifier = "parallel-causal-rf32-invariant"
            model = ReleaseModel(classifier, features, release_dir.name, config, 0.9,
                                 detector, PORTABLE_FEATURES, threshold)
            metrics, speed = evaluate(model, calibration), latency(model, calibration, repeats=30)
            all_metrics[identifier] = {"calibration": metrics, "latency": speed}
            candidates.append((identifier, model, metrics, speed))
    eligible = [item for item in candidates if item[2]["false_positive_rate"] <= 0.03
                and item[2]["macro_detection_rate"] >= 0.7 and item[3]["p95_ms"] <= 5.0]
    if not eligible:
        (reports / "candidate-selection-failed.json").write_text(json.dumps(all_metrics, indent=2))
        raise ValueError("No candidate satisfies calibration FPR <=3%, macro detection >=70% and single-flow P95 <=5 ms")
    chosen = max(eligible, key=lambda item: (item[2]["category_macro_f1"], item[2]["macro_detection_rate"], -item[3]["mean_ms"]))
    identifier, model, calibration_metrics, speed = chosen
    selection = {
        "chosen": identifier, "policy": "calibration FPR<=3%, macro detection>=70%, P95 single-flow<=5ms; maximize category macro F1",
        "feature_version": FEATURE_VERSION, "flow_config": asdict(config), "candidates": all_metrics,
        "calibration_overlap": cal_overlap, "environment": environment(),
        "selection_completed_unix": time.time(), "test_used_for_selection": False,
    }
    (reports / "selection.json").write_text(json.dumps(selection, indent=2, allow_nan=False) + "\n")
    print(f"Frozen choice: {identifier}. Opening final test sessions now.", flush=True)
    test_all, test_excluded = load_role(manifest, "test", ROOT, config)
    reference = __import__("pandas").concat([training, calibration_all], ignore_index=True)
    test, test_overlap = exclude_overlap(reference, test_all, FEATURES)
    if set(test["label"]) != expected:
        raise ValueError("Final test lacks independently novel examples for one or more classes")
    final = evaluate(model, test)
    final["all_independent_session_rows_secondary"] = evaluate(model, test_all)
    final["latency_single_flow"] = latency(model, test, repeats=200)
    final["overlap"] = test_overlap
    final["acceptance"] = {
        "fpr_point_estimate_at_most_3pct": final["false_positive_rate"] <= 0.03,
        "macro_detection_at_least_70pct": final["macro_detection_rate"] >= 0.7,
        "p95_single_flow_at_most_5ms": final["latency_single_flow"]["p95_ms"] <= 5,
        "scope": "independent synthetic Docker sessions; sample uncertainty and external validation remain",
    }
    final["acceptance"]["passed"] = all(value for value in final["acceptance"].values() if isinstance(value, bool))
    provenance = {
        "manifest_sha256": sha256(manifest_path), "manifest": manifest,
        "selection_sha256": sha256(reports / "selection.json"), "chosen_candidate": identifier,
        "training_rows": len(training), "calibration_rows": len(calibration), "test_rows": len(test),
        "excluded_reverse_or_unrelated_rows": {**train_excluded, **cal_excluded, **test_excluded},
        "preprocessing": "median imputation fitted on training sessions only; infinities become missing",
        "labels": "scenario assignment; only actor-originating flows to the lab server are scored",
    }
    model.save(release_dir, provenance, final)
    loaded = ReleaseModel.load(release_dir)
    before, after = model.predict(test), loaded.predict(test)
    if not before.equals(after):
        raise AssertionError("Reloaded model predictions differ from evaluated model")
    final["reload_predictions_identical"] = True
    (reports / "evaluation.json").write_text(json.dumps(final, indent=2, allow_nan=False) + "\n")
    if not final["acceptance"]["passed"]:
        raise ValueError("Frozen model failed final acceptance; artifact retained but default was not promoted")
    pointer = release_dir.parent / "current.json"
    temporary = pointer.with_suffix(".tmp")
    temporary.write_text(json.dumps({"release": release_dir.name, "feature_version": FEATURE_VERSION}, indent=2) + "\n")
    temporary.replace(pointer)
    print(json.dumps({"default_release": str(release_dir), "false_positive_rate": final["false_positive_rate"],
                      "macro_detection_rate": final["macro_detection_rate"], "latency": final["latency_single_flow"]}, indent=2), flush=True)
    return final


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--release", type=Path, default=RELEASES / "lab-v1")
    parser.add_argument("--reports", type=Path, default=ROOT / "network-anomaly-detection/reports/integration")
    args = parser.parse_args()
    train(args.manifest, args.release, args.reports)
