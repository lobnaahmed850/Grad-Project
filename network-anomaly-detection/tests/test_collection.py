import hashlib
import json

import pytest

import collect_sessions


def existing_plan(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_sessions, "ROOT", tmp_path)
    monkeypatch.setattr(collect_sessions.subprocess, "check_output", lambda *args, **kwargs: "fixture-revision")
    monkeypatch.setattr(collect_sessions, "docker", lambda *args, **kwargs:
                        '[{"Id":"fixture-image"}]' if args[0] == "image" else "fixture-docker")
    sessions = []
    for role_index, role in enumerate(("train", "calibration", "test")):
        for iteration, scenario in enumerate(("benign", "scan", "flood", "slow")):
            capture = tmp_path / f"{role}-{scenario}.pcap"
            capture.write_bytes(capture.name.encode())
            sessions.append({"role": role, "scenario": scenario, "pcap": capture.name,
                             "capture_dropped_packets": 0, "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                             "metadata": {"seed": 1000 * (role_index + 1) + iteration * 17}})
    manifest = {"environment": {"image_id": "fixture-image"}, "sessions": sessions,
                "collection_config": {"normal_runs": 1, "attack_runs": 1, "mixed_runs": 0, "seconds": 5}}
    output = tmp_path / "manifest.json"
    output.write_text(json.dumps(manifest))
    return output, manifest


def test_resume_checks_existing_data_and_never_regenerates_valid_plan(tmp_path, monkeypatch):
    output, original = existing_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(collect_sessions, "compose", lambda *args: pytest.fail("Existing capture must not be regenerated"))
    result = collect_sessions.collect(output, normal_runs=1, attack_runs=1, resume=True)
    assert result["sessions"] == original["sessions"]


def test_resume_rejects_altered_capture_before_generating_more_traffic(tmp_path, monkeypatch):
    output, original = existing_plan(tmp_path, monkeypatch)
    (tmp_path / original["sessions"][0]["pcap"]).write_bytes(b"altered capture")
    monkeypatch.setattr(collect_sessions, "compose", lambda *args: pytest.fail("Invalid evidence must stop collection"))
    with pytest.raises(ValueError, match="changed or lossy"):
        collect_sessions.collect(output, normal_runs=1, attack_runs=1, resume=True)
