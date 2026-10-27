import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

LOG_KEYWORDS = ("bytes", "packets", "duration", "iat", "length", "size", "active", "idle")


def signed_log1p(x):
    """sign(x) * log1p(|x|): defined for negatives (CICFlowMeter overflow artefacts, -1 sentinels)."""
    x = np.asarray(x, dtype=np.float64)
    return np.sign(x) * np.log1p(np.abs(x))


class FlowPreprocessor(BaseEstimator, TransformerMixin):
    "inf/NaN -> median imputation -> signed log1p on heavy-tailed columns"

    def __init__(self, features, skew_threshold=2.0, log_keywords=LOG_KEYWORDS, log_cols=None):
        self.features = features
        self.skew_threshold = skew_threshold
        self.log_keywords = log_keywords
        self.log_cols = log_cols

    def _sanitize(self, X):
        missing = [c for c in self.features if c not in X.columns]
        if missing:
            raise KeyError(f"Missing feature columns: {missing[:5]}{'...' if len(missing) > 5 else ''}")
        Xs = X[list(self.features)].apply(pd.to_numeric, errors="coerce")
        return Xs.replace([np.inf, -np.inf], np.nan)

    def fit(self, X, y=None):
        Xs = self._sanitize(X)
        self.medians_ = Xs.median().fillna(0.0)
        if self.log_cols is None:
            skew = Xs.skew().abs()
            high_skew = set(skew[skew > self.skew_threshold].index)
            forced = {c for c in self.features if any(k in c.lower() for k in self.log_keywords)}
            self.log_cols_ = [c for c in self.features if c in (high_skew | forced)]
        else:
            self.log_cols_ = list(self.log_cols)
        return self

    def transform(self, X):
        Xs = self._sanitize(X).fillna(self.medians_)
        for c in self.log_cols_:
            Xs[c] = signed_log1p(Xs[c].to_numpy())
        return Xs.to_numpy(dtype=np.float32)


def anomaly_confidence(scores, benign_ref_sorted):
    
    return np.searchsorted(benign_ref_sorted, np.asarray(scores), side="right") / len(benign_ref_sorted)


class IFDetector:
    """Serving wrapper: fitted Pipeline(prep -> IsolationForest) + thresholds + confidence reference + metadata."""

    def __init__(self, pipe, thresholds, default_op, benign_ref_sorted, features, model_version, meta=None):
        self.pipe = pipe
        self.thresholds = dict(thresholds)
        self.default_op = default_op
        self.benign_ref_sorted = np.asarray(benign_ref_sorted)
        self.features = list(features)
        self.model_version = model_version
        self.meta = meta or {}

    def score(self, X):
        "Higher => more anomalous"
        return -self.pipe.decision_function(X)

    def predict(self, X, op=None):
        s = self.score(X)
        thr = self.thresholds[op or self.default_op]
        return pd.DataFrame({
            "anomaly_score": s,
            "is_anomaly": s >= thr,
            "confidence": anomaly_confidence(s, self.benign_ref_sorted),
            "model_version": self.model_version,
        }, index=getattr(X, "index", None))
