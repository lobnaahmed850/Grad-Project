"""Load CICIDS2017 and fit models, using the team's chosen hyperparameters.

The hyperparameters come from notebooks/supervised.ipynb (Random Forest) and
notebooks/02_isolation_forest_v2.ipynb (Isolation Forest).
"""
from __future__ import annotations

import glob
import os
import re

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from src.IF_preprocess import FlowPreprocessor, IFDetector

SEED = 42
RF_PARAMS = dict(
    n_estimators=300, class_weight="balanced_subsample", max_depth=20, max_features="log2",
    min_samples_leaf=2, n_jobs=-1, random_state=SEED,
)
IF_PARAMS = dict(n_estimators=100, max_features=0.6, contamination="auto", n_jobs=-1, random_state=SEED)
FPR_BUDGETS = {"FPR<=3%": 0.03, "FPR<=1%": 0.01, "FPR<=0.1%": 0.001}


def load_cicids(csv_dir: str) -> pd.DataFrame:
    """Read and clean the published CSVs, the same way notebook 02 does."""
    frames = []
    for path in sorted(glob.glob(os.path.join(csv_dir, "*.csv"))):
        frame = pd.read_csv(path, encoding="latin1", low_memory=False)
        frame.columns = frame.columns.str.strip().str.lower()
        day = re.search(r"(monday|tuesday|wednesday|thursday|friday)", os.path.basename(path).lower())
        frame["day"] = day.group(1)
        frames.append(frame)
    if not frames:
        raise FileNotFoundError(f"No CSV files in {csv_dir}")
    data = pd.concat(frames, ignore_index=True)
    data["label"] = (
        data["label"].astype(str).str.strip().str.replace(r"Web Attack\s*\W+\s*", "Web Attack - ", regex=True)
    )
    features = [c for c in data.columns if c not in ("label", "day")]
    data = data.drop_duplicates(subset=features + ["label"]).copy()
    data[features] = data[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    return data.dropna(subset=features).reset_index(drop=True)


def split_rows(labels: pd.Series) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return 70/15/15 train, validation and test positions, stratified by label.

    Classes with too few rows to stratify stay in the training set.
    """
    positions = np.arange(len(labels))
    counts = labels.map(labels.value_counts())
    rare = positions[counts.to_numpy() < 7]
    common = positions[counts.to_numpy() >= 7]
    rest, test = train_test_split(common, test_size=0.15, random_state=SEED, stratify=labels.iloc[common])
    train, val = train_test_split(rest, test_size=0.15 / 0.85, random_state=SEED, stratify=labels.iloc[rest])
    return np.concatenate([train, rare]), val, test


def unseen_rows(data: pd.DataFrame, train: np.ndarray, test: np.ndarray, features: list[str]) -> np.ndarray:
    """Return the test positions whose feature values never appear in the training rows.

    Duplicates stay in training because how often each class owns a feature vector is real
    information. Dropping them turns a vector seen 90,000 times as PortScan and once as
    DoS Hulk into a 1-to-1 tie. Scoring these rows separately removes the leakage instead.
    """
    hashes = pd.util.hash_pandas_object(data[features].astype(float).round(6), index=False).to_numpy()
    return test[~np.isin(hashes[test], hashes[train])]


def fit_detector(
    data: pd.DataFrame, train: np.ndarray, val: np.ndarray, features: list[str], max_samples, version: str,
) -> tuple[IFDetector, dict]:
    """Fit an Isolation Forest on benign training rows, with thresholds from validation rows only."""
    is_attack = (data["label"] != "BENIGN").to_numpy()
    benign_train = train[~is_attack[train]]
    prep = FlowPreprocessor(features=features).fit(data.iloc[train])
    forest = IsolationForest(max_samples=max_samples, **IF_PARAMS).fit(prep.transform(data.iloc[benign_train]))
    forest.n_jobs = 1
    pipe = Pipeline([("prep", prep), ("iforest", forest)])
    val_scores = -pipe.decision_function(data.iloc[val])
    val_attack = is_attack[val]
    benign_scores = np.sort(val_scores[~val_attack])
    thresholds = {op: float(np.quantile(benign_scores, 1 - fpr)) for op, fpr in FPR_BUDGETS.items()}
    detector = IFDetector(
        pipe=pipe, thresholds=thresholds, default_op="FPR<=3%", benign_ref_sorted=benign_scores,
        features=features, model_version=version,
        meta={"max_samples": max_samples, "train_benign_rows": len(benign_train), "dataset": "CICIDS2017"},
    )
    return detector, {
        "val_ap": float(average_precision_score(val_attack, val_scores)),
        "val_auc": float(roc_auc_score(val_attack, val_scores)),
        "nodes": int(sum(tree.tree_.node_count for tree in forest.estimators_)),
    }


def fit_classifier(data: pd.DataFrame, rows: np.ndarray, features: list[str]) -> dict:
    """Fit the Random Forest on the given rows. Returns the same bundle shape as the saved model."""
    encoder = LabelEncoder()
    targets = encoder.fit_transform(data["label"].iloc[rows])
    frame = data[features].iloc[rows]
    return {"model": RandomForestClassifier(**RF_PARAMS).fit(frame, targets), "label_encoder": encoder}
