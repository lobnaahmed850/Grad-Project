"""One inference path from flow features to a decision, using both models.

Two modes are available:

    serial    Isolation Forest flags a flow, then the Random Forest names the attack.
              A flow the first stage misses never reaches the second.
    parallel  Both models see every flow. A confident attack label from the Random
              Forest raises an alert with that attack type. An Isolation Forest flag
              with no confident label raises an alert too, named by the optional type
              classifier when it is confident, otherwise "Unknown anomaly".

Parallel at confidence 0.9 is the chosen design and the default. Serial stays available so
the two can be compared.

A "BENIGN" answer from the Random Forest never cancels an Isolation Forest flag. On lab
traffic that Random Forest called almost every attack benign, so it can only add alerts.

Both modes clean inputs the same way, so an undefined value can't crash one stage
while another fills it in.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.feature_contract import require_compatible

BENIGN = "BENIGN"
UNKNOWN_ANOMALY = "Unknown anomaly"
UNKNOWN_ATTACK = "Unrecognized attack"

LEGACY_CANDIDATES = {
    "detector_path": "if_portable_timing_65536.joblib",
    "classifier_path": "rf15_portable_timing.joblib",
    "type_classifier_path": "rf14_all_features.joblib",
}


def _clean_name(label) -> str:
    return str(label).replace("�", "-").replace("\x96", "-").strip()


def to_numeric_frame(flows: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Keep the requested columns as numbers, and turn undefined values into 0.

    Undefined values are rates on zero-duration flows, where the tool's own
    per-direction rates report 0.
    """
    frame = flows[columns].apply(pd.to_numeric, errors="coerce")
    return frame.replace([np.inf, -np.inf], np.nan).fillna(0.0)


@dataclass
class TwoStagePipeline:
    detector: object
    classifier: object
    class_names: list[str]
    mode: str = "parallel"
    threshold_op: str | None = None
    min_confidence: float = 0.9
    type_classifier: object | None = None
    type_names: list[str] | None = None
    min_type_confidence: float = 0.0

    @classmethod
    def load(
        cls, detector_path: Path | str, classifier_path: Path | str, type_classifier_path: Path | str | None = None,
        **options,
    ) -> "TwoStagePipeline":
        """Load an IFDetector and {"model", "label_encoder"} Random Forest bundles."""
        bundle = joblib.load(classifier_path)
        names = [_clean_name(name) for name in bundle["label_encoder"].classes_]
        if type_classifier_path is not None:
            type_bundle = joblib.load(type_classifier_path)
            options["type_classifier"] = type_bundle["model"]
            options["type_names"] = [_clean_name(name) for name in type_bundle["label_encoder"].classes_]
        return cls(joblib.load(detector_path), bundle["model"], names, **options)

    @classmethod
    def load_chosen(cls, models_dir: Path | str | None = None):
        """Load the evaluated release; an explicit directory retains legacy candidate loading."""
        if models_dir is None:
            from src.release import ReleaseModel
            return ReleaseModel.load_default()
        return cls.load(**{key: Path(models_dir) / name for key, name in LEGACY_CANDIDATES.items()})

    @property
    def threshold(self) -> float:
        return self.detector.thresholds[self.threshold_op or self.detector.default_op]

    def set_local_threshold(self, benign_flows: pd.DataFrame, target_false_alarms: float) -> float:
        """Set the alert threshold from this network's own benign flows and return it.

        Use at least several thousand benign flows. With fewer, the false alarm rate
        on later traffic can differ a lot from the target.
        """
        scores = self.detector.score(self._for_detector(benign_flows))
        local = float(np.quantile(scores, 1 - target_false_alarms))
        self.detector.thresholds["local"] = local
        self.threshold_op = "local"
        return local

    def _for_detector(self, flows: pd.DataFrame) -> pd.DataFrame:
        return flows[self.detector.features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)

    def predict(self, flows: pd.DataFrame, validate: bool = True) -> pd.DataFrame:
        """Return one row per flow: decision, attack_type, anomaly_score, is_anomaly, confidence.

        decision is "benign" or "alert". validate=False skips the contract check, for
        micro-batches too small for its share-based tests.
        """
        if validate:
            require_compatible(flows)
        scores = self.detector.score(self._for_detector(flows))
        is_anomaly = scores >= self.threshold
        features = to_numeric_frame(flows, list(self.classifier.feature_names_in_))
        probabilities = self.classifier.predict_proba(features)
        names = np.array(self.class_names)[self.classifier.classes_]
        best = names[probabilities.argmax(axis=1)]
        confidence = probabilities.max(axis=1)

        if self.mode == "serial":
            attack_type = np.where(confidence >= self.min_confidence, best, UNKNOWN_ATTACK)
            attack_type = np.where(attack_type == BENIGN, UNKNOWN_ANOMALY, attack_type)
            attack_type = np.where(is_anomaly, attack_type, BENIGN)
        elif self.mode == "parallel":
            confident_attack = (best != BENIGN) & (confidence >= self.min_confidence)
            flag_name = np.full(len(flows), UNKNOWN_ANOMALY, dtype=object)
            if self.type_classifier is not None and is_anomaly.any():
                type_features = to_numeric_frame(flows, list(self.type_classifier.feature_names_in_))
                type_probabilities = self.type_classifier.predict_proba(type_features)
                type_best = np.array(self.type_names)[self.type_classifier.classes_][type_probabilities.argmax(axis=1)]
                flag_name = np.where(type_probabilities.max(axis=1) >= self.min_type_confidence, type_best, UNKNOWN_ANOMALY)
            attack_type = np.where(confident_attack, best, np.where(is_anomaly, flag_name, BENIGN))
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

        return pd.DataFrame({
            "decision": np.where(attack_type == BENIGN, "benign", "alert"),
            "attack_type": attack_type,
            "anomaly_score": scores,
            "is_anomaly": is_anomaly,
            "confidence": confidence,
        }, index=flows.index)
