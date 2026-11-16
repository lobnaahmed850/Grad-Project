"""Train candidate models on portable features and compare them with the saved models.

Nothing here overwrites the saved models. Candidates go to --models-out, and every
result is written to --report.

    python tools/train_candidates.py --csv-dir data/raw/MachineLearningCVE --lab "localdata/*.csv" \
        --saved-if models/iforest_v0.1.0.joblib --saved-rf models/random_forest_final.joblib \
        --models-out models/candidates --report reports/candidates.json
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
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.feature_contract import PORTABLE_FEATURES, PORTABLE_WITH_TIMING  # noqa: E402
from src.lab_data import add_true_labels, load_lab_csvs, remap_flags, repair_first_packet  # noqa: E402
from src.pipeline import BENIGN, TwoStagePipeline, to_numeric_frame  # noqa: E402
from src.training import fit_classifier, fit_detector, load_cicids, split_rows, unseen_rows  # noqa: E402

FEATURE_SETS = {"portable": PORTABLE_FEATURES, "portable+timing": PORTABLE_WITH_TIMING}
MAX_SAMPLES = [4096, 65536, 262144, 0.9612]
MIN_CLASS_FLOWS = 20


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return float("nan"), float("nan")
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return float(centre - spread), float(centre + spread)


def detector_results(detector, data, positions, lab) -> dict:
    is_attack = (data["label"] != "BENIGN").to_numpy()[positions]
    scores = detector.score(data.iloc[positions])
    labels = data["label"].to_numpy()[positions]
    threshold = detector.thresholds["FPR<=3%"]
    recall = {name: float((scores[labels == name] >= threshold).mean()) for name in np.unique(labels) if name != "BENIGN"}
    lab_scores = detector.score(lab["flows"].replace([np.inf, -np.inf], np.nan))
    benign = lab["benign"]
    out = {
        "public AUC": float(roc_auc_score(is_attack, scores)),
        "public false alarms @3%": float((scores[~is_attack] >= threshold).mean()),
        "public recall @3%": float((scores[is_attack] >= threshold).mean()),
        "public macro recall @3%": float(np.mean(list(recall.values()))),
        "lab AUC": float(roc_auc_score(~benign, lab_scores)),
    }
    for op, t in detector.thresholds.items():
        flagged = lab_scores[benign] >= t
        out[f"lab false alarms {op}"] = float(flagged.mean())
        out[f"lab false alarms {op} 95% CI"] = wilson(int(flagged.sum()), len(flagged))
        out[f"lab recall {op}"] = float((lab_scores[~benign] >= t).mean())
    return out


def chain_results(pipeline, flows, truth, kind) -> dict:
    """Score a pipeline. truth holds class names, kind holds benign, known or unseen."""
    verdict = pipeline.predict(flows, validate=False)
    alert = verdict["decision"].to_numpy() == "alert"
    types = verdict["attack_type"].to_numpy()
    benign = kind == "benign"
    per_class = {}
    for name in sorted(set(truth[~benign])):
        rows = truth == name
        if rows.sum() < MIN_CLASS_FLOWS:
            continue
        per_class[name] = {
            "flows": int(rows.sum()),
            "detected": float(alert[rows].mean()),
            "correct type": float((types[rows] == name).mean()),
        }
    known = [name for name in per_class if kind[truth == name][0] == "known"]
    return {
        "benign flows": int(benign.sum()),
        "false alarms": float(alert[benign].mean()),
        "false alarms 95% CI": wilson(int(alert[benign].sum()), int(benign.sum())),
        "attacks detected": float(alert[~benign].mean()),
        "macro detected": float(np.mean([per_class[n]["detected"] for n in per_class])),
        "macro correct type": float(np.mean([per_class[n]["correct type"] for n in known])) if known else float("nan"),
        "per class": per_class,
    }


def forest_lab_results(bundle, lab) -> dict:
    forest = bundle["model"]
    names = np.array([str(c).replace("�", "-").replace("\x96", "-").strip() for c in bundle["label_encoder"].classes_])
    frame = to_numeric_frame(lab["flows"], list(forest.feature_names_in_))
    probabilities = forest.predict_proba(frame)
    predicted = names[probabilities.argmax(axis=1)]
    rows = {}
    known = lab["kind"] == "known"
    for name in sorted(set(lab["truth"][known])):
        where = lab["truth"] == name
        if where.sum() < MIN_CLASS_FLOWS:
            continue
        top = pd.Series(predicted[where]).value_counts(normalize=True)
        rows[name] = {
            "flows": int(where.sum()), "correct": float((predicted[where] == name).mean()),
            "top": f"{top.index[0]} {top.iloc[0]:.0%}",
        }
    return {
        "flow-weighted correct": float((predicted[known] == lab["truth"][known]).mean()),
        "macro correct": float(np.mean([r["correct"] for r in rows.values()])),
        "attack confidence": float(probabilities[lab["kind"] != "benign"].max(axis=1).mean()),
        "per class": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-dir", required=True)
    parser.add_argument("--lab", required=True)
    parser.add_argument("--saved-if", type=Path, required=True)
    parser.add_argument("--saved-rf", type=Path, required=True)
    parser.add_argument("--models-out", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.models_out.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {"max_samples": {}, "classifier": {}, "pipelines": {}}

    def save_report():
        args.report.write_text(json.dumps(report, indent=1, default=float))

    started = time.time()
    data = load_cicids(args.csv_dir)
    print(f"public rows {len(data):,} ({time.time() - started:.0f}s)", flush=True)

    flows = load_lab_csvs(args.lab)
    labelled = add_true_labels(flows)
    repaired = remap_flags(repair_first_packet(flows))
    scored = labelled["scored"].to_numpy()
    lab = {
        "flows": repaired[scored].reset_index(drop=True),
        "truth": labelled["true_class"].to_numpy()[scored],
        "kind": labelled["kind"].to_numpy()[scored],
    }
    lab["benign"] = lab["kind"] == "benign"
    print(f"lab rows {len(lab['flows']):,}, benign {int(lab['benign'].sum())}", flush=True)

    saved_detector = joblib.load(args.saved_if)
    saved_bundle = joblib.load(args.saved_rf)
    report["saved lab classifier"] = forest_lab_results(saved_bundle, lab)
    save_report()

    for set_name, features in FEATURE_SETS.items():
        unique = data
        train, val, test = split_rows(unique["label"])
        unseen = unseen_rows(unique, train, test, features)
        print(f"\n{set_name}: {len(features)} features, train {len(train):,} val {len(val):,} test {len(test):,}, "
              f"test rows never seen in training {len(unseen):,}", flush=True)
        report["max_samples"][set_name] = {}
        detectors = {}
        for max_samples in MAX_SAMPLES:
            tick = time.time()
            detector, stats = fit_detector(unique, train, val, features, max_samples, f"candidate-{set_name}-{max_samples}")
            stats["fit seconds"] = round(time.time() - tick, 1)
            stats.update(detector_results(detector, unique, test, lab))
            report["max_samples"][set_name][str(max_samples)] = stats
            detectors[max_samples] = detector
            print(f"  IF {max_samples}: {stats['fit seconds']}s nodes {stats['nodes']:,} val AP {stats['val_ap']:.3f} "
                  f"public AUC {stats['public AUC']:.3f} lab AUC {stats['lab AUC']:.3f} "
                  f"lab false alarms@3% {stats['lab false alarms FPR<=3%']:.3f}", flush=True)
            save_report()

        tick = time.time()
        attack_rows = train[(unique["label"].to_numpy()[train] != "BENIGN")]
        rf14 = fit_classifier(unique, attack_rows, features)
        print(f"  RF14 fit {time.time() - tick:.0f}s", flush=True)
        tick = time.time()
        rf15 = fit_classifier(unique, train, features)
        print(f"  RF15 fit {time.time() - tick:.0f}s", flush=True)

        labels = unique["label"].to_numpy()
        for name, bundle in (("RF14", rf14), ("RF15", rf15)):
            forest = bundle["model"]
            encoder = bundle["label_encoder"]
            result = {"lab": forest_lab_results(bundle, lab)}
            for scope, rows in (("all test rows", test), ("unseen test rows", unseen)):
                predicted = encoder.inverse_transform(forest.predict(unique[features].iloc[rows]))
                truth = labels[rows]
                attack = truth != "BENIGN"
                per_class = {
                    c: float((predicted[truth == c] == c).mean())
                    for c in np.unique(truth) if c != "BENIGN" and (truth == c).sum() >= MIN_CLASS_FLOWS
                }
                result[scope] = {
                    "flows": int(len(rows)),
                    "correct on attacks": float((predicted[attack] == truth[attack]).mean()),
                    "macro recall": float(np.mean(list(per_class.values()))),
                    "benign false alarms": float((predicted[~attack] != "BENIGN").mean()) if name == "RF15" else None,
                    "per class": per_class,
                }
            report["classifier"][f"{set_name} {name}"] = result
            print(f"  {name} public macro {result['all test rows']['macro recall']:.3f} "
                  f"unseen macro {result['unseen test rows']['macro recall']:.3f} "
                  f"lab macro {result['lab']['macro correct']:.3f} lab flow-weighted {result['lab']['flow-weighted correct']:.3f}", flush=True)
            print(f"     lab per class { {k: (round(v['correct'], 3), v['top']) for k, v in result['lab']['per class'].items()} }", flush=True)
        save_report()

        for max_samples in (65536, 262144):
            joblib.dump(detectors[max_samples], args.models_out / f"if_{set_name.replace('+', '_')}_{max_samples}.joblib", compress=3)
        joblib.dump(rf14, args.models_out / f"rf14_{set_name.replace('+', '_')}.joblib", compress=3)
        joblib.dump(rf15, args.models_out / f"rf15_{set_name.replace('+', '_')}.joblib", compress=3)
        print(f"  saved models ({time.time() - started:.0f}s total)", flush=True)
    print("done")
