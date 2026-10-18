"""
evaluation_multiclass.py

Multiclass counterpart of evaluation.py, for models that predict the ATTACK TYPE
(e.g. the Random Forest trained via prepare_rf_data, which excludes BENIGN).

Why a separate file: evaluation.py is binary (one anomaly score per row). Here the
model outputs one probability PER CLASS, so metrics are computed one-vs-rest for each
class and then averaged (macro) so rare attack types count as much as common ones.

Inputs used throughout:
    y_true      : encoded true labels (ints from LabelEncoder)
    y_pred      : encoded predicted labels, model.predict(X)
    y_proba     : model.predict_proba(X), shape (n_samples, n_classes)
    classes     : model.classes_  -> encoded label of each y_proba column
    class_names : label_encoder.inverse_transform(model.classes_) -> readable names
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
)


def evaluate_multiclass(y_true, y_pred, y_proba, classes, class_names,
                        model_name="Model", verbose=True):
    """
    Computes per-class and macro metrics (one-vs-rest).

    Classes that do not appear in y_true (can happen for very rare attacks in a small
    split) are skipped, since AUC/precision/recall are undefined without positives.

    Returns
    -------
    summary   : dict of overall metrics (macro_* are the headline numbers; this dict
                can be passed straight to evaluation.log_experiment)
    per_class : DataFrame with one row per class (support, AUC-ROC, AUC-PR,
                precision, recall, F1)
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    classes = np.asarray(classes)
    class_names = list(class_names)

    # one-hot ground truth; columns follow the same order as y_proba columns
    Y = (y_true[:, None] == classes[None, :]).astype(int)

    rows = []
    for i, (cls, name) in enumerate(zip(classes, class_names)):
        if Y[:, i].sum() == 0:
            continue
        pred_i = (y_pred == cls).astype(int)
        rows.append({
            "class": name,
            "support": int(Y[:, i].sum()),
            "auc_roc": roc_auc_score(Y[:, i], y_proba[:, i]),
            "auc_pr": average_precision_score(Y[:, i], y_proba[:, i]),
            "precision": precision_score(Y[:, i], pred_i, zero_division=0),
            "recall": recall_score(Y[:, i], pred_i, zero_division=0),
            "f1_score": f1_score(Y[:, i], pred_i, zero_division=0),
        })
    per_class = pd.DataFrame(rows)

    summary = {
        "accuracy": accuracy_score(y_true, y_pred),
        "macro_auc_roc": per_class["auc_roc"].mean(),
        "macro_auc_pr": per_class["auc_pr"].mean(),
        "macro_precision": per_class["precision"].mean(),
        "macro_recall": per_class["recall"].mean(),
        "macro_f1": per_class["f1_score"].mean(),
        "weighted_f1": np.average(per_class["f1_score"], weights=per_class["support"]),
    }

    if verbose:
        print(f"===== {model_name} — Multiclass Evaluation =====")
        for k, v in summary.items():
            print(f"{k:<16}: {v:.4f}")
        print("\nPer-class results:")
        print(per_class.round(4).to_string(index=False))

    return summary, per_class


def plot_confusion_matrix_multiclass(y_true, y_pred, classes, class_names,
                                     model_name="Model", normalize=True,
                                     figsize=(10, 8)):
    """
    Confusion matrix heatmap for many classes. With normalize=True each row sums to 1,
    so the diagonal reads directly as per-class recall (rare classes stay visible
    instead of being drowned out by DoS/PortScan counts).
    """
    classes = np.asarray(classes)
    cm = confusion_matrix(y_true, y_pred, labels=classes)

    if normalize:
        row_sums = cm.sum(axis=1, keepdims=True)
        cm_plot = np.divide(cm, row_sums, out=np.zeros(cm.shape, dtype=float),
                            where=row_sums != 0)
        fmt = ".2f"
    else:
        cm_plot = cm
        fmt = "d"

    fig, ax = plt.subplots(figsize=figsize)
    sns.heatmap(cm_plot, annot=True, fmt=fmt, cmap="Blues",
                xticklabels=class_names, yticklabels=class_names, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix — {model_name}" + (" (row-normalized)" if normalize else ""))
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_per_class_metric(per_class, metric="f1_score", model_name="Model"):
    """Horizontal bar chart of one per-class metric, sorted, to spot weak attack types."""
    data = per_class.sort_values(metric)
    plt.figure(figsize=(8, 0.4 * len(data) + 1.5))
    plt.barh(data["class"], data[metric], color="steelblue")
    plt.xlim(0, 1)
    plt.xlabel(metric)
    plt.title(f"{metric} per attack type — {model_name}")
    plt.tight_layout()
    plt.show()