"""Measure real concurrent benign/flood traffic without retuning the release."""
import argparse
import concurrent.futures
import json
import os
import time
from pathlib import Path

import pandas as pd

from collect_sessions import compose, docker, ROOT
from demo_integration import events_since, get
from src.metrics import summarize


def run(endpoint, token, output, seconds):
    if not 2 <= seconds <= 30:
        raise ValueError("Load duration must be 2..30 seconds")
    releases = ROOT / "network-anomaly-detection/models/releases"
    chosen = json.loads((releases / "current.json").read_text())["release"]
    expected = json.loads((releases / chosen / "manifest.json").read_text())
    compose("stop", "-t", "30", "sensor")
    compose("start", "sensor")
    deadline = time.monotonic() + 20
    while True:
        state = get(endpoint, token, "/api/summary")["sensors"]["lab-sensor"]
        if state["status"] == "capturing" and state["uptime_seconds"] < 10:
            if state.get("model_sha256") != expected["model_sha256"]:
                raise RuntimeError("Running sensor differs from the evaluated default bundle")
            break
        if time.monotonic() > deadline:
            raise RuntimeError("Fresh sensor did not start")
        time.sleep(.2)
    latest = get(endpoint, token, "/api/events?limit=1")["events"]
    sequence = max((row["sequence"] for row in latest), default=0)
    started = time.time()
    workloads = [("client-a", "benign", "10.77.0.20", "BENIGN"),
                 ("client-b", "flood", "10.77.0.21", "HTTP_FLOOD")]

    def workload(item):
        client, scenario, _, _ = item
        return json.loads(compose("exec", "-T", client, "python3", "/lab/traffic.py", scenario,
                                  "--seconds", str(seconds), "--seed", "7100").splitlines()[-1])

    during_load = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(workload, item) for item in workloads]
        while not all(future.done() for future in futures):
            during_load.append({"unix": time.time(),
                                "diagnostics": get(endpoint, token, "/api/summary")["sensors"]["lab-sensor"],
                                "docker_stats": docker("stats", "--no-stream", "--format", "json",
                                                       "netguard-integration-sensor-1", "netguard-integration-ingest-1")})
            time.sleep(.25)
        traffic = [future.result() for future in futures]
    if any(item["errors"] or not item["operations"] for item in traffic):
        raise AssertionError(f"Workload failed: {traffic}")
    ended = time.time()
    deadline = time.monotonic() + 60
    while True:
        state = get(endpoint, token, "/api/summary")["sensors"]["lab-sensor"]
        if (state["updated_unix"] >= ended + 1.5 and state["queue_depth"] == 0
            and state["outbox_depth"] == 0 and state["flow_engine"]["active_flows"] == 0):
            break
        if time.monotonic() > deadline:
            raise AssertionError("Load did not drain within 60 seconds")
        time.sleep(.25)
    rows = [row for row in events_since(endpoint, token, sequence)
            if row["event_source"] == "ml" and started * 1e6 <= row["evidence"]["flow_start_us"] <= ended * 1e6]
    labels = {item[2]: item[3] for item in workloads}
    rows = [row for row in rows if row["source_ip"] in labels]
    if not all(any(row["source_ip"] == item[2] for row in rows) for item in workloads):
        raise AssertionError("Missing stored verdicts for a workload")
    truth = pd.DataFrame({"label": [labels[row["source_ip"]] for row in rows]})
    predictions = pd.DataFrame({"decision": [row["decision"] for row in rows],
                                "attack_type": [row["evidence"]["attack_type"] for row in rows]})
    report = {"scope": "fresh concurrent synthetic benign and HTTP flood; no selection or threshold changes",
              "started_unix": started, "ended_unix": ended, "traffic": traffic,
              "stored_flow_verdicts": len(rows), "metrics": summarize(truth, predictions),
              "sensor_diagnostics": state, "during_load": during_load,
              "docker_stats": docker("stats", "--no-stream", "--format", "json",
                                     "netguard-integration-sensor-1", "netguard-integration-ingest-1")}
    report["loss_counters"] = {name: state[name] for name in (
        "queue_dropped", "outbox_dropped", "inference_errors", "kernel_dropped", "capture_truncated")}
    report["passed"] = not any(report["loss_counters"].values())
    report["processing_integrity_passed"] = report["passed"]
    report["quality_acceptance"] = {"fpr_at_most_3pct": report["metrics"]["false_positive_rate"] <= .03,
                                    "recall_at_least_70pct": report["metrics"]["recall"] >= .7}
    report["passed"] = report["passed"] and all(report["quality_acceptance"].values())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    if not report["passed"]:
        raise AssertionError(f"Load acceptance failed; see {output}")
    print(json.dumps({"passed": True, "verdicts": len(rows), "metrics": report["metrics"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8090")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--out", type=Path, default=ROOT / "network-anomaly-detection/reports/integration/load-check.json")
    args = parser.parse_args()
    run(args.endpoint, os.environ.get("NETGUARD_TOKEN", "netguard-local-validation"), args.out, args.seconds)
