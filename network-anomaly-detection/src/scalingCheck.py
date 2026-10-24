"""
scaling_check.py

Empirically verifies that feature scaling does not matter for tree-based models
(Random Forest, Isolation Forest) on YOUR data, instead of taking it on faith.

Method: a controlled experiment.
  - same model, same random_state, same rows
  - the ONLY thing that changes is the input scaling (none / standard / robust)
  - compare validation metrics and the % of identical predictions
  - positive control: a scale-sensitive model (logistic regression) is run the same
    way, to prove the experiment CAN detect a scaling effect when one exists
"""

import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler, RobustScaler


def _subsample(X, y, n, seed):
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(X), size=min(n, len(X)), replace=False)
    return X.iloc[idx], np.asarray(y)[idx]


def check_scaling_invariance(X_train, y_train, X_val, y_val,
                             n_train=100_000, n_estimators=100,
                             include_control=True, random_state=42):
    """
    Parameters
    ----------
    X_train, X_val : pandas DataFrames (unscaled, already split)
    y_train, y_val : encoded labels (multiclass or binary both work)
    n_train        : training rows used per run (subsample, keeps this fast)

    Returns
    -------
    results   : DataFrame (model, input, macro_f1, accuracy)
    agreement : dict, share of validation rows where RF predicts exactly the same
                class with scaled input as with unscaled input
    """
    y_val = np.asarray(y_val)
    Xtr, ytr = _subsample(X_train, y_train, n_train, random_state)

    # scalers are fit on the training sample only, then applied to validation
    inputs = {"unscaled": (Xtr.values, X_val.values)}
    for name, scaler in {"standard": StandardScaler(), "robust": RobustScaler()}.items():
        inputs[name] = (scaler.fit_transform(Xtr), scaler.transform(X_val))

    rows, rf_preds = [], {}

    # ---- Random Forest on each version of the input ----
    for name, (A, B) in inputs.items():
        rf = RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=random_state,
        )
        rf.fit(A, ytr)
        pred = rf.predict(B)
        rf_preds[name] = pred
        rows.append({
            "model": "RandomForest",
            "input": name,
            "macro_f1": f1_score(y_val, pred, average="macro", zero_division=0),
            "accuracy": float((pred == y_val).mean()),
        })

    # ---- Positive control: a model that DOES depend on scale ----
    if include_control:
        Xc, yc = _subsample(X_train, y_train, 30_000, random_state)
        scaler = StandardScaler().fit(Xc)
        control_inputs = {
            "unscaled": (Xc.values, X_val.values),
            "standard": (scaler.transform(Xc), scaler.transform(X_val)),
        }
        for name, (A, B) in control_inputs.items():
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")   # unscaled data triggers convergence/overflow warnings
                lr = LogisticRegression(max_iter=200)
                lr.fit(A, yc)
                pred = lr.predict(B)
            rows.append({
                "model": "LogisticRegression (control)",
                "input": name,
                "macro_f1": f1_score(y_val, pred, average="macro", zero_division=0),
                "accuracy": float((pred == y_val).mean()),
            })

    results = pd.DataFrame(rows)

    agreement = {
        f"{n} vs unscaled": float((rf_preds[n] == rf_preds["unscaled"]).mean())
        for n in ("standard", "robust")
    }

    print(results.round(4).to_string(index=False))
    print("\nRandom Forest prediction agreement with the unscaled run:")
    for k, v in agreement.items():
        print(f"  {k}: {v * 100:.3f}% identical predictions")

    # ---- Comparison chart (bars should match for RF, differ for the control) ----
    labels = results["model"].str.replace(" (control)", "", regex=False) + "\n" + results["input"]
    colors = ["steelblue" if m == "RandomForest" else "darkorange" for m in results["model"]]
    plt.figure(figsize=(9, 4))
    plt.bar(labels, results["macro_f1"], color=colors)
    plt.ylabel("macro F1 (validation)")
    plt.title("Effect of scaling: Random Forest vs scale-sensitive control")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.show()

    return results, agreement