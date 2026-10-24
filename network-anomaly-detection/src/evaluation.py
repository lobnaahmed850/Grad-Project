"""
evaluation.py

Shared evaluation utilities for the anomaly detection project.
Used by BOTH the Isolation Forest notebook and the Supervised model notebook,
so results are computed the exact same way and are directly comparable.

Convention used throughout this file:
    y_true   -> ground truth labels, 1 = anomaly/attack, 0 = normal
    y_scores -> continuous scores where HIGHER means MORE LIKELY to be anomaly/attack
                (for supervised models this is predict_proba()[:, 1])
                (for Isolation Forest this is the *converted* anomaly score, see below)
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


# ---------------------------------------------------------------------------
# 1. Isolation Forest score conversion
# ---------------------------------------------------------------------------
def convert_iforest_scores(model, X):
    """
    sklearn's IsolationForest.decision_function() returns HIGHER values for
    NORMAL points and LOWER (more negative) values for anomalies -- this is
    the opposite convention of what roc_auc_score/average_precision_score
    expect (they want higher score = more positive/anomalous class).

    This function flips the sign so that higher score = more anomalous,
    matching the convention used by predict_proba()[:, 1] in the supervised
    notebook. Always use this before passing Isolation Forest scores into
    evaluate_model().

    Parameters
    ----------
    model : fitted sklearn.ensemble.IsolationForest
    X     : feature matrix (already preprocessed, same as used for training)

    Returns
    -------
    np.ndarray of anomaly scores, higher = more anomalous
    """
    raw_scores = model.decision_function(X)   # high = normal, low = anomaly
    anomaly_scores = -raw_scores              # flip -> high = anomaly
    return anomaly_scores


def iforest_predictions_to_binary(model, X):
    """
    IsolationForest.predict() returns 1 for normal, -1 for anomaly.
    This converts that to the project's convention: 1 = anomaly, 0 = normal.
    """
    raw_preds = model.predict(X)              # 1 = normal, -1 = anomaly
    binary_preds = np.where(raw_preds == -1, 1, 0)
    return binary_preds


# ---------------------------------------------------------------------------
# 2. Core metric computation
# ---------------------------------------------------------------------------
def compute_fpr(y_true, y_pred):
    """
    False Positive Rate = FP / (FP + TN)

    The share of NORMAL flows that were wrongly flagged as attacks. Lower is better:
    0.01 means 10 false alarms per 1,000 normal flows. In an intrusion detection
    system this is the cost side of detection (analysts have to chase false alarms).

    Binary convention only (1 = attack, 0 = normal). Returns NaN if y_true contains
    no normal rows, because FPR is undefined without negatives.
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return fp / (fp + tn) if (fp + tn) > 0 else float("nan")


def compute_metrics(y_true, y_pred, y_scores):
    """
    Computes every metric the project needs for a single model, given:
      y_true   : ground-truth binary labels (1 = anomaly, 0 = normal)
      y_pred   : binary predictions (1 = anomaly, 0 = normal) at whatever
                 threshold/decision rule the model used
      y_scores : continuous anomaly scores, higher = more anomalous
                 (use convert_iforest_scores() first for Isolation Forest)

    Returns
    -------
    dict of metric_name -> value
    """
    metrics = {
        "auc_roc": roc_auc_score(y_true, y_scores),
        "auc_pr": average_precision_score(y_true, y_scores),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, zero_division=0),
        "fpr": compute_fpr(y_true, y_pred),
    }
    return metrics


def print_metrics_report(y_true, y_pred, y_scores, model_name="Model"):
    """
    Pretty-prints a full evaluation report: the core metrics dict,
    the sklearn classification_report, and the confusion matrix.
    """
    metrics = compute_metrics(y_true, y_pred, y_scores)

    print(f"===== {model_name} — Evaluation Report =====")
    print(f"AUC-ROC   : {metrics['auc_roc']:.4f}")
    print(f"AUC-PR    : {metrics['auc_pr']:.4f}")
    print(f"Precision : {metrics['precision']:.4f}")
    print(f"Recall    : {metrics['recall']:.4f}")
    print(f"F1-score  : {metrics['f1_score']:.4f}")
    print(f"FPR       : {metrics['fpr']:.4f}  ({metrics['fpr'] * 1000:.1f} false alarms per 1,000 normal flows)")
    print()
    print("Classification report:")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Anomaly"], zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    print("Confusion matrix:")
    print(cm)

    return metrics


# ---------------------------------------------------------------------------
# 3. Plots
# ---------------------------------------------------------------------------
def plot_confusion_matrix(y_true, y_pred, model_name="Model", ax=None):
    """Plots a labeled confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    if ax is None:
        fig, ax = plt.subplots(figsize=(5, 4))

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal", "Anomaly"],
        yticklabels=["Normal", "Anomaly"],
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix — {model_name}")
    return ax


def plot_roc_curve(y_true, y_scores, model_name="Model", ax=None):
    """Plots the ROC curve for one model, with AUC-ROC in the legend label."""
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    auc = roc_auc_score(y_true, y_scores)

    if ax is None:
        fig, ax = plt.subplots(figsize=(6, 5))

    ax.plot(fpr, tpr, label=f"{model_name} (AUC-ROC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random baseline")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend(loc="lower right")
    return ax


def plot_pr_curve(y_true, y_scores, model_name="Model", ax=None):
    """Plots the Precision-Recall curve for one model, with AUC-PR in the legend label."""
    precision, recall, _ = precision_recall_curve(y_true, y_scores)
    auc_pr = average_precision_score(y_true, y_scores)

    if ax is None:
        fig, ax = plt.subplots(figsize=(6, 5))

    ax.plot(recall, precision, label=f"{model_name} (AUC-PR = {auc_pr:.3f})")
    baseline = y_true.sum() / len(y_true)   # fraction of positives = random-classifier baseline for PR
    ax.axhline(baseline, linestyle="--", color="gray", label=f"Random baseline ({baseline:.3f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")
    ax.legend(loc="lower left")
    return ax


def plot_roc_and_pr(y_true, y_scores, model_name="Model"):
    """Convenience: plots ROC and PR curves side by side in one figure."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    plot_roc_curve(y_true, y_scores, model_name=model_name, ax=axes[0])
    plot_pr_curve(y_true, y_scores, model_name=model_name, ax=axes[1])
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# 4. Comparing multiple models on the same plot (for your final comparison)
# ---------------------------------------------------------------------------
def compare_models_roc_pr(models_scores_dict, y_true):
    """
    Plots ROC and PR curves for multiple models on the same two charts,
    so you can visually compare Isolation Forest vs the supervised model.

    Parameters
    ----------
    models_scores_dict : dict[str, np.ndarray]
        e.g. {"Isolation Forest": iforest_scores, "Supervised Model": supervised_scores}
    y_true : ground-truth labels shared by all models (must be the same test set!)
    """
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    for model_name, y_scores in models_scores_dict.items():
        plot_roc_curve(y_true, y_scores, model_name=model_name, ax=axes[0])
        plot_pr_curve(y_true, y_scores, model_name=model_name, ax=axes[1])

    plt.tight_layout()
    plt.show()


def build_comparison_table(models_results_dict):
    """
    Builds a tidy comparison DataFrame from multiple models' metric dicts.

    Parameters
    ----------
    models_results_dict : dict[str, dict]
        e.g. {"Isolation Forest": metrics_dict_1, "Supervised Model": metrics_dict_2}
        where each metrics_dict comes from compute_metrics()

    Returns
    -------
    pd.DataFrame, one row per model
    """
    df = pd.DataFrame(models_results_dict).T
    df.index.name = "model"
    return df.reset_index()


# ---------------------------------------------------------------------------
# 5. Experiment logging (for hyperparameter tuning tracking)
# ---------------------------------------------------------------------------
def log_experiment(log_path, model_name, params, metrics):
    """
    Appends one row to a CSV experiment log: model name, hyperparameters used,
    and resulting metrics. Creates the file with a header if it doesn't exist yet.

    Parameters
    ----------
    log_path : str, path to the results_log.csv file
    model_name : str, e.g. "IsolationForest" or "XGBoost"
    params : dict of hyperparameters used for this run
    metrics : dict returned by compute_metrics()
    """
    import os
    from datetime import datetime

    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": model_name,
        **params,
        **metrics,
    }

    row_df = pd.DataFrame([row])

    # Different models log different metrics/params (binary vs multiclass, and new
    # metrics like fpr). Blindly appending a row with new columns would misalign the
    # CSV, so we merge on column names: missing values become empty cells.
    if os.path.exists(log_path):
        old_df = pd.read_csv(log_path)
        out_df = pd.concat([old_df, row_df], ignore_index=True)
    else:
        out_df = row_df
    out_df.to_csv(log_path, index=False)

    print(f"Logged experiment for {model_name} -> {log_path}")