"""
resampling.py

Helpers for the class imbalance in the attack-type (multiclass) Random Forest.
Needs:  pip install imbalanced-learn

RULES THAT MUST NOT BE BROKEN
  1. Resample the TRAINING set only, and only AFTER the train/val/test split.
     If synthetic or duplicated rows touch validation/test, your scores are inflated
     (data leakage).
  2. Never resample before splitting.
  3. Evaluate on the untouched, real validation/test sets.
"""

import numpy as np
import pandas as pd

from imblearn.over_sampling import SMOTE, RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler


def class_count_report(y, label_encoder):
    """Samples per class, readable names, largest first."""
    counts = pd.Series(np.asarray(y)).value_counts()
    out = pd.DataFrame({
        "class": label_encoder.inverse_transform(counts.index),
        "count": counts.values,
    })
    return out.reset_index(drop=True)


def cap_majority_classes(X_train, y_train, cap=20_000, random_state=42):
    """
    Randomly undersample every class that has more than `cap` rows down to `cap`.
    Giant classes (DoS Hulk, PortScan, DDoS...) are extremely repetitive, so capping
    them loses little information, speeds up training a lot, and shrinks the
    imbalance that SMOTE has to bridge.
    """
    y_train = np.asarray(y_train)
    counts = pd.Series(y_train).value_counts()
    big = counts[counts > cap]
    if big.empty:
        return X_train, y_train
    rus = RandomUnderSampler(
        sampling_strategy={c: cap for c in big.index},
        random_state=random_state,
    )
    return rus.fit_resample(X_train, y_train)


def oversample_rare_classes(X_train, y_train, target_per_class=2_000,
                            max_multiplier=20, k_neighbors=5,
                            round_integer_cols=True, label_encoder=None,
                            random_state=42):
    """
    Raises every class with fewer than `target_per_class` TRAINING rows up to that
    number using SMOTE (synthetic points interpolated between real neighbours of the
    SAME class). Classes already at or above the target are left untouched, so the
    big classes are not touched and nothing explodes in size.

    max_multiplier : a class is never grown by more than this factor (default 20x),
        so a class with 8 real rows becomes 160, not 2,000. Interpolating hundreds of
        points out of a handful of real ones adds no information and makes the model
        over-trust that tiny region of feature space.

    Automatic safety handling for tiny classes:
      - SMOTE needs k_neighbors < class size, so k is lowered to fit the smallest
        class being oversampled.
      - A class with only 1 training row cannot be interpolated; it falls back to
        plain duplication (RandomOverSampler).

    round_integer_cols : SMOTE interpolates, which can produce values like 0.4 in a
        flag-count column or a port of 80.37. Columns that were whole numbers in the
        real data are rounded back to whole numbers.

    Returns
    -------
    X_res, y_res, report  (report = before/after counts for the classes that changed)
    """
    y_train = np.asarray(y_train)
    counts = pd.Series(y_train).value_counts()
    to_boost = counts[counts < target_per_class]

    if to_boost.empty:
        return X_train, y_train, pd.DataFrame()

    def _target(c):
        return int(min(target_per_class, counts[c] * max_multiplier))

    smote_targets = {c: _target(c) for c in to_boost.index if counts[c] >= 2}
    dup_targets = {c: _target(c) for c in to_boost.index if counts[c] < 2}

    int_cols = []
    if round_integer_cols and isinstance(X_train, pd.DataFrame):
        int_cols = [c for c in X_train.columns if np.all(np.mod(X_train[c].values, 1) == 0)]

    X_res, y_res = X_train, y_train

    if smote_targets:
        smallest = min(counts[c] for c in smote_targets)
        k = max(1, min(k_neighbors, smallest - 1))
        smote = SMOTE(sampling_strategy=smote_targets, k_neighbors=k, random_state=random_state)
        X_res, y_res = smote.fit_resample(X_res, y_res)

    if dup_targets:
        ros = RandomOverSampler(sampling_strategy=dup_targets, random_state=random_state)
        X_res, y_res = ros.fit_resample(X_res, y_res)

    if int_cols:
        X_res[int_cols] = X_res[int_cols].round()

    after = pd.Series(np.asarray(y_res)).value_counts()
    report = pd.DataFrame({"before": counts, "after": after}).fillna(0).astype(int)
    report = report[report["before"] != report["after"]].sort_values("before")
    if label_encoder is not None:
        report.index = label_encoder.inverse_transform(report.index)
    report.index.name = "class"

    print("Oversampled classes (training set only):")
    print(report.to_string())
    return X_res, y_res, report