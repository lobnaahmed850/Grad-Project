"""Full-pipeline evaluation metrics on matched lab data: the chosen design, scored per flow.

Reports per-class precision/recall/F1, macro F1, the false-alarm rate, and a confusion matrix over
benign plus every lab attack capture. Each --attack is "name=pcap=cicids_label"; the label is the
ground truth for that capture (the lab generated one kind of traffic per file).

    python tools/lab_metrics.py \
        --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
        --attack "PortScan=lab/captures/attack_lan_scan.pcap=PortScan" \
                 "SYN flood=lab/captures/attack_lan_synflood.pcap=DDoS" \
                 "HTTP flood=lab/captures/attack_lan_httpflood.pcap=DoS Hulk" \
                 "Slowloris=lab/captures/attack_lan_slowloris.pcap=DoS slowloris" \
                 "wrk flood=lab/captures/attack_lan_wrkflood.pcap=DoS Hulk" \
        --models models/candidates --out reports/lab_metrics.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.flow_extractor import extract_flows  # noqa: E402
from src.pipeline import BENIGN, TwoStagePipeline  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", nargs="+", required=True)
    parser.add_argument("--attack", nargs="+", required=True, help="name=pcap=cicids_label triples")
    parser.add_argument("--models", type=Path, default=Path("models/candidates"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    pipe = TwoStagePipeline.load_chosen(args.models)
    truths, preds = [], []

    def score(path, true_label):
        flows = extract_flows(str(path), "training")
        pred = pipe.predict(flows, validate=False)["attack_type"].to_numpy()
        truths.extend([true_label] * len(flows))
        preds.extend(pred.tolist())
        print(f"  {true_label:16} {len(flows):6,} flows", flush=True)

    print("scoring benign ...", flush=True)
    for p in args.benign:
        score(p, BENIGN)
    print("scoring attacks ...", flush=True)
    for spec in args.attack:
        _, path, label = spec.split("=", 2)
        score(path, label)

    y_true, y_pred = np.array(truths), np.array(preds)
    # Collapse any predicted label outside the ground-truth set into "other attack" for the matrix.
    labels = sorted(set(y_true))
    y_pred_m = np.where(np.isin(y_pred, labels), y_pred, "other attack")
    matrix_labels = labels + (["other attack"] if (y_pred_m == "other attack").any() else [])

    report = classification_report(y_true, y_pred_m, labels=labels, output_dict=True, zero_division=0)
    benign_mask = y_true == BENIGN
    false_alarm = float((y_pred[benign_mask] != BENIGN).mean())
    matrix = confusion_matrix(y_true, y_pred_m, labels=matrix_labels)

    print(f"\nfalse-alarm rate (benign flagged): {false_alarm:.1%}")
    print(f"macro F1 (all classes): {report['macro avg']['f1-score']:.3f}")
    attack_f1 = np.mean([report[c]["f1-score"] for c in labels if c != BENIGN])
    print(f"macro F1 (attacks only): {attack_f1:.3f}\n")
    print(f"{'class':16} {'precision':>9} {'recall':>7} {'f1':>6} {'support':>8}")
    for c in labels:
        r = report[c]
        print(f"{c:16} {r['precision']:9.2f} {r['recall']:7.2f} {r['f1-score']:6.2f} {int(r['support']):8,}")
    print("\nconfusion matrix (rows = true, cols = predicted):")
    print("           " + "  ".join(f"{c[:10]:>10}" for c in matrix_labels))
    for name, row in zip(matrix_labels, matrix):
        print(f"{name[:10]:>10} " + "  ".join(f"{v:>10,}" for v in row))

    out = {"false alarm rate": false_alarm, "macro F1 all": report["macro avg"]["f1-score"],
           "macro F1 attacks": float(attack_f1), "per class": report,
           "confusion": {"labels": matrix_labels, "matrix": matrix.tolist()}}
    args.out.write_text(json.dumps(out, indent=1))
    print(f"\nwrote {args.out}")
