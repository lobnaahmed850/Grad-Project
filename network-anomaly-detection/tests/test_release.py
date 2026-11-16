import json

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from src.release import BundleError, ReleaseModel
from src.sessions import exclude_overlap, read_manifest
from src.streaming import FEATURE_VERSION


@pytest.fixture
def tiny_release():
    training = np.array([[0, 1], [0, 2], [1, 5], [1, 6], [0, np.nan], [1, 8]])
    model = Pipeline([("imputer", SimpleImputer()), ("forest", RandomForestClassifier(n_estimators=3, random_state=1))])
    model.fit(training, ["BENIGN", "BENIGN", "SCAN", "SCAN", "BENIGN", "SCAN"])
    return ReleaseModel(model, ["psh flag count", "source flow rate"], "fixture-v1", confidence=.5)


@pytest.fixture
def tiny_frame():
    return pd.DataFrame({"psh flag count": [0, 1], "source flow rate": [1, 7],
                         "feature version": [FEATURE_VERSION] * 2})


def test_bundle_round_trip_preserves_predictions_and_order(tmp_path, tiny_release, tiny_frame):
    directory = tmp_path / "release"
    tiny_release.save(directory, {"scope": "unit fixture"}, {})
    loaded = ReleaseModel.load(directory)
    pd.testing.assert_frame_equal(tiny_release.predict(tiny_frame), loaded.predict(tiny_frame))
    pd.testing.assert_frame_equal(loaded.predict(tiny_frame), loaded.predict(tiny_frame[tiny_frame.columns[::-1]]))
    with pytest.raises(FileExistsError):
        tiny_release.save(directory, {}, {})


@pytest.mark.parametrize("mutation", ["checksum", "feature_order", "environment", "version", "threshold"])
def test_corrupt_or_incompatible_bundles_fail_explicitly(tmp_path, tiny_release, mutation):
    directory = tmp_path / "release"
    tiny_release.save(directory, {}, {})
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    if mutation == "checksum":
        manifest["model_sha256"] = "wrong"
    elif mutation == "feature_order":
        manifest["features"].reverse()
    elif mutation == "environment":
        manifest["environment"]["sklearn"] = "0.0"
    elif mutation == "threshold":
        manifest["min_confidence"] = 0.1
    else:
        manifest["feature_version"] = "old"
    path.write_text(json.dumps(manifest))
    with pytest.raises(BundleError):
        ReleaseModel.load(directory)


def test_missing_model_and_feature_schema_fail(tmp_path, tiny_release, tiny_frame):
    with pytest.raises(BundleError, match="Cannot load"):
        ReleaseModel.load(tmp_path)
    with pytest.raises(BundleError, match="Missing release features"):
        tiny_release.predict(tiny_frame.drop(columns="source flow rate"))
    with pytest.raises(BundleError, match="feature version"):
        tiny_release.predict(tiny_frame.drop(columns="feature version"))
    bad = tiny_frame.copy()
    bad["source flow rate"] = -1
    with pytest.raises(BundleError, match="source flow rate"):
        tiny_release.predict(bad)
    assert tiny_release.predict(tiny_frame.iloc[:0]).empty
    malformed = tiny_frame.copy()
    malformed["psh flag count"] = ["bad", "values"]
    with pytest.raises(BundleError, match="numeric"):
        tiny_release.predict(malformed)


def test_default_pointer_cannot_escape_releases(tmp_path):
    (tmp_path / "current.json").write_text('{"release":"../../other"}')
    with pytest.raises(BundleError, match="valid default"):
        ReleaseModel.load_default(tmp_path)


def test_overlap_checks_remove_matching_feature_vectors():
    reference = pd.DataFrame({"a": [1.001, 2], "b": [5, 6]})
    target = pd.DataFrame({"a": [1.0011, 3], "b": [5, 6]})
    novel, report = exclude_overlap(reference, target, ["a", "b"])
    assert novel["a"].tolist() == [3]
    assert report["overlap_rows"] == 1


def test_same_capture_cannot_appear_in_two_roles(tmp_path):
    sessions = [{"session_id": name, "role": role, "sha256": "duplicate", "pcap": "x", "capture_dropped_packets": 0,
                 "label": "BENIGN", "actor_ips": ["10.77.0.20"]}
                for name, role in [("a", "train"), ("b", "test")]]
    (tmp_path / "x").write_bytes(b"")
    from src.release import sha256
    for session in sessions:
        session["sha256"] = sha256(tmp_path / "x")
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema": "netguard-sessions-v1", "sessions": sessions}))
    with pytest.raises(ValueError, match="Duplicate capture"):
        read_manifest(path, tmp_path)


def test_mixed_session_uses_actor_labels_before_evaluation(monkeypatch):
    import src.sessions as sessions
    frame = pd.DataFrame({"source ip": ["10.77.0.20", "10.77.0.21", "10.77.0.10"],
                          "destination ip": ["10.77.0.10", "10.77.0.10", "10.77.0.20"]})
    monkeypatch.setattr(sessions, "replay_capture", lambda *args: frame)
    manifest = {"sessions": [{"role": "test", "session_id": "mixed-independent-run", "pcap": "mixed.pcap",
                              "label": "MIXED", "actor_ips": ["10.77.0.20", "10.77.0.21"],
                              "server_ip": "10.77.0.10",
                              "actor_labels": {"10.77.0.20": "BENIGN", "10.77.0.21": "HTTP_FLOOD"}}]}
    result, excluded = sessions.load_role(manifest, "test", ".", None)
    assert result["label"].tolist() == ["BENIGN", "HTTP_FLOOD"]
    assert excluded == {"mixed-independent-run": 1}


def test_actual_default_is_the_evaluated_release(known_answer):
    from src.pipeline import TwoStagePipeline
    from src.streaming import replay_capture
    loaded = TwoStagePipeline.load_chosen()
    assert isinstance(loaded, ReleaseModel)
    assert loaded.manifest["evaluation"]["acceptance"]["passed"]
    assert loaded.manifest["provenance"]["chosen_candidate"]
    assert loaded.version == loaded.manifest["model_version"]
    frame = replay_capture(known_answer[0], loaded.flow_config)
    result = loaded.predict(frame)
    assert len(result) == len(frame)
    assert result["model_version"].eq(loaded.version).all()
