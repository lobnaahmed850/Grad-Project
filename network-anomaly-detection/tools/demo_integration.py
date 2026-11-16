"""Exercise actual Docker traffic, model inference, UDP logs, storage and recovery."""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.metrics import summarize
from collect_sessions import compose, docker, ROOT

import pandas as pd


def get(endpoint, token, path):
    request = urllib.request.Request(endpoint + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def events_since(endpoint, token, sequence):
    rows, before = [], None
    while True:
        query = {"after": sequence, "limit": 1000}
        if before:
            query["before"] = before
        page = get(endpoint, token, "/api/events?" + urlencode(query))["events"]
        rows.extend(page)
        if len(page) < 1000:
            return rows
        before = min(row["sequence"] for row in page)


def run(endpoint, token, output, reliability=True):
    output.parent.mkdir(parents=True, exist_ok=True)
    releases = ROOT / "network-anomaly-detection/models/releases"
    chosen = json.loads((releases / "current.json").read_text())["release"]
    expected = json.loads((releases / chosen / "manifest.json").read_text())
    deadline = time.monotonic() + 15
    while True:
        try:
            summary = get(endpoint, token, "/api/summary")
        except OSError:
            if time.monotonic() > deadline:
                raise RuntimeError("Ingestion service did not become reachable")
            time.sleep(.2)
            continue
        health = summary.get("sensors", {}).get("lab-sensor", {})
        if health.get("status") == "capturing":
            if (health.get("model_version") != expected["model_version"]
                or health.get("model_sha256") != expected["model_sha256"]):
                raise RuntimeError("Running sensor does not serve the evaluated default bundle; rebuild/restart it")
            break
        if time.monotonic() > deadline:
            raise RuntimeError("Live sensor never reported capturing")
        time.sleep(.2)
    original = get(endpoint, token, "/api/events?limit=1")["events"]
    sequence = max([row["sequence"] for row in original], default=0)
    report = {"scope": "fresh synthetic live Docker scenarios; separate from release selection",
              "model_version": expected["model_version"], "model_sha256": expected["model_sha256"], "cases": []}
    labels = {"benign": "BENIGN", "scan": "PORT_SCAN", "flood": "HTTP_FLOOD", "slow": "SLOW_HTTP"}
    for index, scenario in enumerate(labels):
        metadata = json.loads(compose("exec", "-T", "client-a", "python3", "/lab/traffic.py",
                                      scenario, "--seconds", "4", "--seed", str(5000 + index)).splitlines()[-1])
        if metadata["errors"]:
            raise AssertionError(f"Traffic errors: {metadata}")
        deadline = time.monotonic() + 60
        while True:
            time.sleep(.25)
            diagnostic = get(endpoint, token, "/api/summary")["sensors"]["lab-sensor"]
            if (diagnostic["updated_unix"] >= metadata["ended_unix"] + 1.5
                and diagnostic["outbox_depth"] == 0 and diagnostic["queue_depth"] == 0
                and diagnostic["flow_engine"]["active_flows"] == 0):
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"Scenario did not drain: {diagnostic}")
        rows = [row for row in events_since(endpoint, token, sequence)
                if row["event_source"] == "ml" and row["source_ip"] == "10.77.0.20"
                and metadata["started_unix"] * 1e6 <= row["evidence"]["flow_start_us"] <= metadata["ended_unix"] * 1e6]
        if not rows:
            raise AssertionError("Actual traffic produced no stored model verdicts")
        truth = pd.DataFrame({"label": [labels[scenario]] * len(rows)})
        predictions = pd.DataFrame({"decision": [row["decision"] for row in rows],
                                    "attack_type": [row["evidence"]["attack_type"] for row in rows]})
        metrics = summarize(truth, predictions)
        if scenario != "benign" and not any(row["decision"] == "alert" for row in rows):
            raise AssertionError(f"No suspicious verdict for actual {scenario} traffic")
        report["cases"].append({"scenario": scenario, "traffic": metadata, "metrics": metrics,
                                 "sample_alert_ids": [row["alert_id"] for row in rows[:3]]})
        print(json.dumps({"scenario": scenario, "flows": len(rows), "recall": metrics["recall"],
                          "false_positive_rate": metrics["false_positive_rate"]}), flush=True)
    script = (
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        "messages=[b'<38>Jan  2 03:04:05 ubuntu sshd[9]: Failed password for sudo_admin', "
        "b'<189>12: R1: *Mar  1 00:01:02: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: bob] [Source: 10.77.0.20]', "
        "b'{\"EventTime\":\"2026-11-16T12:00:00Z\",\"Hostname\":\"WIN-LAB\",\"EventID\":4625,\"Message\":\"Logon failed\"}', "
        "b'unsupported input']; "
        "[s.sendto(message,('ingest',5514)) for message in messages]"
    )
    compose("exec", "-T", "client-b", "python3", "-c", script)
    time.sleep(1)
    rows = events_since(endpoint, token, sequence)
    sources = {row["event_source"] for row in rows}
    assert sources == {"ml", "syslog"}
    assert sum(row["event_source"] == "syslog" for row in rows) >= 3
    report["shared_ingestion"] = {"event_sources": sorted(sources), "syslog_events": sum(row["event_source"] == "syslog" for row in rows)}
    report["recovery"] = {}
    if reliability:
        before = len(rows)
        compose("stop", "-t", "5", "ingest")
        try:
            compose("exec", "-T", "client-a", "python3", "/lab/traffic.py", "scan", "--seconds", "2", "--seed", "6000")
            time.sleep(2)
            pending = int(compose("exec", "-T", "sensor", "python3", "-c",
                                  "import sqlite3; print(sqlite3.connect('/state/outbox.sqlite').execute('select count(*) from pending').fetchone()[0])"))
            assert pending > 0, "Outage did not leave durable pending events"
        finally:
            compose("start", "ingest")
        deadline = time.monotonic() + 20
        while True:
            try:
                summary = get(endpoint, token, "/api/summary")
                if summary["sensors"]["lab-sensor"]["outbox_depth"] == 0 and len(events_since(endpoint, token, sequence)) > before:
                    break
            except (OSError, KeyError):
                pass
            if time.monotonic() > deadline:
                raise AssertionError("Outbox did not recover after ingestion restart")
            time.sleep(.2)
        report["recovery"]["ingestion_restart"] = {"pending_during_outage": pending, "drained": True, "stored_events_preserved": True}
        compose("stop", "-t", "30", "sensor")
        log = compose("logs", "--no-log-prefix", "--tail", "5", "sensor")
        for line in reversed(log.splitlines()):
            try:
                diagnostic = json.loads(line)
            except ValueError:
                continue
            if "model_version" in diagnostic:
                report["sensor_final_diagnostics"] = diagnostic
                break
        compose("start", "sensor")
        previous_update = report["sensor_final_diagnostics"]["uptime_seconds"]
        deadline = time.monotonic() + 20
        while True:
            recovered = get(endpoint, token, "/api/summary")["sensors"]["lab-sensor"]
            if recovered["status"] == "capturing" and recovered["uptime_seconds"] < previous_update:
                break
            if time.monotonic() > deadline:
                raise AssertionError("Sensor did not resume capturing after restart")
            time.sleep(.2)
        last = max((row["sequence"] for row in events_since(endpoint, token, sequence)), default=sequence)
        compose("exec", "-T", "client-a", "python3", "/lab/traffic.py", "scan", "--seconds", "1", "--seed", "6001")
        deadline = time.monotonic() + 10
        while not any(row["event_source"] == "ml" for row in events_since(endpoint, token, last)):
            if time.monotonic() > deadline:
                raise AssertionError("Restarted sensor produced no stored verdicts")
            time.sleep(.2)
        report["recovery"]["sensor_restart"] = {"restarted": True, "flow_policy": "in-memory active flows flushed on graceful shutdown; crash starts new segments"}
    report["service_summary"] = get(endpoint, token, "/api/summary")
    report["stored_events_in_demo"] = len(events_since(endpoint, token, sequence))
    diagnostics = report.get("sensor_final_diagnostics", report["service_summary"]["sensors"]["lab-sensor"])
    for name in ("queue_dropped", "outbox_dropped", "inference_errors", "kernel_dropped", "capture_truncated"):
        if diagnostics[name]:
            raise AssertionError(f"Demo reported processing loss: {name}={diagnostics[name]}")
    report["passed"] = True
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(f"Verified live integration; report: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8090")
    parser.add_argument("--out", type=Path, default=ROOT / "network-anomaly-detection/reports/integration/live-demo.json")
    parser.add_argument("--no-reliability", action="store_true")
    args = parser.parse_args()
    run(args.endpoint, os.environ.get("NETGUARD_TOKEN", "netguard-local-validation"), args.out, not args.no_reliability)
