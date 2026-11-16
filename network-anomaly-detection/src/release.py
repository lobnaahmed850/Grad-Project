"""Integrity-checked, versioned release artifacts. Only load trusted local bundles."""
from __future__ import annotations

import hashlib
import json
import platform
import time
from dataclasses import asdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from src.feature_contract import CONTRACT
from src.streaming import FEATURE_VERSION, FlowConfig

BUNDLE_FORMAT = 1
RELEASES = Path(__file__).resolve().parents[1] / "models" / "releases"


class BundleError(ValueError):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def environment():
    return {"python": platform.python_version(), "sklearn": sklearn.__version__,
            "numpy": np.__version__, "joblib": joblib.__version__, "pandas": pd.__version__}


def implementation_hashes():
    return {name: sha256(Path(__file__).parent / name) for name in ("flow_extractor.py", "streaming.py", "release.py")}


class ReleaseModel:
    def __init__(self, classifier, features, version, flow_config=None, confidence=0.9,
                 detector=None, detector_features=None, detector_threshold=None):
        self.classifier = classifier
        self.features = list(features)
        self.version = version
        self.flow_config = flow_config or FlowConfig()
        self.confidence = float(confidence)
        self.detector = detector
        self.detector_features = list(detector_features or [])
        self.detector_threshold = detector_threshold
        self.manifest = {}
        self.type_classifier = None
        self.last_timings = {}

    def predict(self, flows, validate=True):
        if not isinstance(flows, pd.DataFrame):
            flows = pd.DataFrame.from_records(flows)
        if flows.empty:
            return pd.DataFrame(columns=["decision", "attack_type", "anomaly_score", "is_anomaly", "confidence", "model_version"])
        missing = sorted(set(self.features + self.detector_features) - set(flows.columns))
        if missing:
            raise BundleError(f"Missing release features: {missing}")
        if validate:
            if "feature version" not in flows or not flows["feature version"].eq(FEATURE_VERSION).all():
                raise BundleError(f"Expected feature version {FEATURE_VERSION}; re-extract using the release flow engine")
            rate = pd.to_numeric(flows.get("source flow rate"), errors="coerce")
            if rate.isna().any() or (rate < 0).any() or not np.isfinite(rate).all():
                raise BundleError("Invalid causal source flow rate")
        started = time.perf_counter_ns()
        try:
            values = flows[self.features].to_numpy(dtype=np.float64, copy=True)
        except (TypeError, ValueError) as exc:
            raise BundleError("Release features must be numeric; malformed values are not silently imputed") from exc
        values[~np.isfinite(values)] = np.nan
        prepared = time.perf_counter_ns()
        probabilities = self.classifier.predict_proba(values)
        inferred = time.perf_counter_ns()
        best = probabilities.argmax(axis=1)
        labels = self.classifier.classes_[best]
        confidence = probabilities.max(axis=1)
        confident_attack = (labels != "BENIGN") & (confidence >= self.confidence)
        score = np.zeros(len(flows))
        anomaly = np.zeros(len(flows), dtype=bool)
        if self.detector is not None:
            detector_values = flows[self.detector_features].to_numpy(dtype=np.float64, copy=True)
            detector_values[~np.isfinite(detector_values)] = np.nan
            score = -self.detector.score_samples(detector_values)
            anomaly = score >= self.detector_threshold
        attack_type = np.where(confident_attack, labels, np.where(anomaly, "Unknown anomaly", "BENIGN"))
        self.last_timings = {"feature_preprocessing_ms": (prepared - started) / 1e6,
                             "classifier_inference_ms": (inferred - prepared) / 1e6}
        return pd.DataFrame({"decision": np.where(confident_attack | anomaly, "alert", "benign"),
                             "attack_type": attack_type, "anomaly_score": score, "is_anomaly": anomaly,
                             "confidence": confidence, "model_version": self.version}, index=flows.index)

    def save(self, directory, provenance, evaluation):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=False)
        model_path = directory / "model.joblib"
        joblib.dump(self, model_path, compress=3)
        schema = [{"name": feature, "unit": CONTRACT[feature].unit if feature in CONTRACT else "starts/second"}
                  for feature in self.features]
        manifest = {
            "bundle_format": BUNDLE_FORMAT, "model_version": self.version, "feature_version": FEATURE_VERSION,
            "created_unix": time.time(), "environment": environment(), "features": schema,
            "implementation_sha256": implementation_hashes(), "classes": self.classifier.classes_.tolist(),
            "flow_config": asdict(self.flow_config), "min_confidence": self.confidence,
            "detector_features": self.detector_features, "detector_threshold": self.detector_threshold,
            "model_sha256": sha256(model_path), "provenance": provenance, "evaluation": evaluation,
            "scope": "isolated synthetic Docker laboratory; external validation required",
        }
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
        self.manifest = manifest
        return manifest

    @classmethod
    def load(cls, directory):
        directory = Path(directory)
        try:
            manifest = json.loads((directory / "manifest.json").read_text())
            if manifest["bundle_format"] != BUNDLE_FORMAT or manifest["feature_version"] != FEATURE_VERSION:
                raise BundleError("Unsupported bundle or feature version")
            if manifest["implementation_sha256"] != implementation_hashes():
                raise BundleError("Feature/serving implementation differs from the evaluated release")
            for package in ("sklearn", "numpy", "joblib", "pandas"):
                if manifest["environment"][package] != environment()[package]:
                    raise BundleError(f"{package} version mismatch: bundle {manifest['environment'][package]}, runtime {environment()[package]}")
            if manifest["environment"]["python"].split(".")[:2] != environment()["python"].split(".")[:2]:
                raise BundleError("Python major/minor version differs from training")
            if sha256(directory / "model.joblib") != manifest["model_sha256"]:
                raise BundleError("Model checksum mismatch")
            model = joblib.load(directory / "model.joblib")
            if not isinstance(model, cls):
                raise BundleError("Unexpected model object")
            expected = [entry["name"] for entry in manifest["features"]]
            if model.features != expected or len(expected) != len(set(expected)):
                raise BundleError("Feature ordering differs from model manifest")
            if model.version != manifest["model_version"] or asdict(model.flow_config) != manifest["flow_config"]:
                raise BundleError("Model/configuration metadata mismatch")
            if model.confidence != manifest["min_confidence"] or model.detector_threshold != manifest["detector_threshold"]:
                raise BundleError("Calibration metadata mismatch")
            if model.detector_features != manifest["detector_features"]:
                raise BundleError("Detector feature metadata mismatch")
            if model.classifier.classes_.tolist() != manifest["classes"]:
                raise BundleError("Class labels differ from model manifest")
            model.manifest = manifest
            return model
        except BundleError:
            raise
        except (OSError, KeyError, TypeError, ValueError, EOFError) as exc:
            raise BundleError(f"Cannot load release bundle {directory}: {exc}") from exc

    @classmethod
    def load_default(cls, releases=RELEASES):
        releases = Path(releases)
        try:
            pointer = json.loads((releases / "current.json").read_text())
            directory = (releases / pointer["release"]).resolve()
            directory.relative_to(releases.resolve())
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise BundleError(f"No valid default release in {releases}; run tools/train_release.py: {exc}") from exc
        return cls.load(directory)
