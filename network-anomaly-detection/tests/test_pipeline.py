"""Tests of the decision logic. The stand-in models below exist only in this file."""
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.feature_contract import IncompatibleFlows
from src.flow_extractor import extract_flows
from src.lab_data import remap_flags, repair_first_packet
from src.pipeline import LEGACY_CANDIDATES, UNKNOWN_ANOMALY, UNKNOWN_ATTACK, TwoStagePipeline, to_numeric_frame

MODELS = Path(__file__).resolve().parents[1] / "models"
SAVED_IF = Path(os.environ.get("IF_MODEL_PATH", MODELS / "iforest_v0.1.0.joblib"))
SAVED_RF = MODELS / "random_forest_final.joblib"
CANDIDATES = Path(os.environ.get("LEGACY_CANDIDATE_DIR", MODELS / "candidates"))


class StubDetector:
    features = ["score"]
    thresholds = {"FPR<=3%": 0.5}
    default_op = "FPR<=3%"

    def score(self, frame):
        return frame["score"].fillna(0).to_numpy()


class StubClassifier:
    feature_names_in_ = np.array(["attack", "certainty"])
    classes_ = np.array([0, 1])

    def predict_proba(self, frame):
        certainty = frame["certainty"].to_numpy()
        attack = frame["attack"].to_numpy() > 0
        high = np.where(attack, certainty, 1 - certainty)
        return np.column_stack([1 - high, high])


def flows(*rows):
    return pd.DataFrame(rows, columns=["score", "attack", "certainty"])


def run(mode, table, names=("BENIGN", "DoS Hulk"), min_confidence=0.5):
    pipeline = TwoStagePipeline(
        StubDetector(), StubClassifier(), list(names), mode=mode, min_confidence=min_confidence,
    )
    return pipeline.predict(table, validate=False)


def test_serial_never_reports_a_flow_the_first_stage_missed():
    result = run("serial", flows((0.1, 1, 0.99))).iloc[0]
    assert result["decision"] == "benign"


def test_serial_names_the_attack_when_both_stages_agree():
    assert run("serial", flows((0.9, 1, 0.99))).iloc[0]["attack_type"] == "DoS Hulk"


def test_serial_marks_low_confidence_as_unrecognized_instead_of_guessing():
    result = run("serial", flows((0.9, 1, 0.6)), names=("Bot", "DoS Hulk"), min_confidence=0.7).iloc[0]
    assert result["attack_type"] == UNKNOWN_ATTACK
    assert result["decision"] == "alert"


def test_parallel_catches_a_flow_the_detector_missed():
    assert run("parallel", flows((0.1, 1, 0.99))).iloc[0]["attack_type"] == "DoS Hulk"


def test_parallel_reports_detector_only_flags_as_unknown_anomaly():
    assert run("parallel", flows((0.9, 0, 0.99))).iloc[0]["attack_type"] == UNKNOWN_ANOMALY


def test_parallel_lets_clean_flows_pass():
    assert run("parallel", flows((0.1, 0, 0.99))).iloc[0]["decision"] == "benign"


class StubTypeClassifier:
    feature_names_in_ = np.array(["certainty"])
    classes_ = np.array([0, 1])

    def predict_proba(self, frame):
        return np.tile([0.2, 0.8], (len(frame), 1))


def typed_pipeline(min_type_confidence=0.0):
    return TwoStagePipeline(
        StubDetector(), StubClassifier(), ["BENIGN", "DoS Hulk"], mode="parallel",
        type_classifier=StubTypeClassifier(), type_names=["Bot", "PortScan"],
        min_type_confidence=min_type_confidence,
    )


def test_type_classifier_names_a_detector_only_alert():
    result = typed_pipeline().predict(flows((0.9, 0, 0.99)), validate=False).iloc[0]
    assert (result["decision"], result["attack_type"]) == ("alert", "PortScan")


def test_benign_answer_never_cancels_a_detector_flag():
    assert typed_pipeline().predict(flows((0.9, 0, 0.99)), validate=False).iloc[0]["decision"] == "alert"


def test_unsure_type_classifier_reports_unknown_anomaly():
    result = typed_pipeline(min_type_confidence=0.9).predict(flows((0.9, 0, 0.99)), validate=False).iloc[0]
    assert result["attack_type"] == UNKNOWN_ANOMALY


def test_type_classifier_does_not_alert_on_unflagged_flows():
    assert typed_pipeline().predict(flows((0.1, 0, 0.99)), validate=False).iloc[0]["decision"] == "benign"


def test_undefined_values_do_not_crash_either_stage():
    table = flows((np.nan, np.inf, -np.inf))
    assert len(run("parallel", table)) == 1
    assert to_numeric_frame(table, ["attack", "certainty"]).to_numpy().tolist() == [[0.0, 0.0]]


def test_default_design_alerts_only_on_confident_attacks_the_detector_missed():
    pipeline = TwoStagePipeline(StubDetector(), StubClassifier(), ["BENIGN", "DoS Hulk"])
    result = pipeline.predict(flows((0.1, 1, 0.95), (0.1, 1, 0.6)), validate=False)
    assert result["decision"].tolist() == ["alert", "benign"]


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError, match="Unknown mode"):
        run("sideways", flows((0.1, 0, 0.5)))


def test_local_threshold_targets_the_requested_false_alarm_rate():
    pipeline = TwoStagePipeline(StubDetector(), StubClassifier(), ["BENIGN", "DoS Hulk"])
    pipeline.detector.thresholds = dict(pipeline.detector.thresholds)
    table = pd.DataFrame({"score": np.linspace(0, 1, 1001), "attack": 0, "certainty": 0.9})
    pipeline.set_local_threshold(table, 0.10)
    assert (table["score"] >= pipeline.threshold).mean() == pytest.approx(0.10, abs=0.002)


saved_models = pytest.mark.skipif(not (SAVED_IF.exists() and SAVED_RF.exists()), reason="saved models not present")


@saved_models
def test_saved_models_refuse_defective_flows(known_answer):
    pcap, _ = known_answer
    pipeline = TwoStagePipeline.load(SAVED_IF, SAVED_RF)
    batch = pd.concat([extract_flows(pcap, "v4_2018")] * 20, ignore_index=True)
    with pytest.raises(IncompatibleFlows):
        pipeline.predict(batch)


@saved_models
def test_saved_models_score_correct_and_repaired_flows_end_to_end(known_answer):
    pcap, _ = known_answer
    pipeline = TwoStagePipeline.load(SAVED_IF, SAVED_RF)
    correct = pd.concat([extract_flows(pcap, "training")] * 20, ignore_index=True)
    defective = pd.concat([extract_flows(pcap, "v4_2018")] * 20, ignore_index=True)
    assert len(pipeline.predict(correct)) == len(correct)
    assert len(pipeline.predict(remap_flags(repair_first_packet(defective)))) == len(defective)


@pytest.mark.skipif(
    not all((CANDIDATES / name).exists() for name in LEGACY_CANDIDATES.values()), reason="legacy candidate models not present",
)
def test_chosen_design_scores_correct_flows_end_to_end(known_answer):
    pcap, _ = known_answer
    pipeline = TwoStagePipeline.load_chosen(CANDIDATES)
    correct = pd.concat([extract_flows(pcap, "training")] * 20, ignore_index=True)
    assert pipeline.type_classifier is not None
    assert len(pipeline.predict(correct)) == len(correct)
