"""Measured offline stage benchmarks; live latency is reported separately by the sensor."""
import argparse
import itertools
import json
import os
import platform
import resource
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from netguard.alerts import from_ml
from netguard.sensor import distribution
from src.flow_extractor import Flow, _classic_frames, decode_frame, extract_flows
from src.release import ReleaseModel, environment, sha256
from src.streaming import StreamingFlows


def measure(function, repeats=100):
    values = []
    for _ in range(repeats):
        started = time.perf_counter_ns()
        function()
        values.append((time.perf_counter_ns() - started) / 1e6)
    return distribution(values)


def benchmark(pcap, output, legacy_if=None, legacy_rf=None):
    model = ReleaseModel.load_default()
    with open(pcap, "rb") as stream:
        magic = stream.read(4)
        frames = list(itertools.islice(_classic_frames(stream, magic), 20000))
    decode_times, packets = [], []
    for timestamp, raw, original, link_type in frames:
        started = time.perf_counter_ns()
        packet = decode_frame(timestamp, raw, original, link_type)
        decode_times.append((time.perf_counter_ns() - started) / 1e6)
        if packet:
            packets.append(packet)
    engine = StreamingFlows(model.flow_config)
    build_times, feature_times, rows = [], [], []
    original = Flow.to_row

    def timed_features(flow, profile):
        started = time.perf_counter_ns()
        row = original(flow, profile)
        feature_times.append((time.perf_counter_ns() - started) / 1e6)
        return row

    Flow.to_row = timed_features
    started_cpu = time.process_time()
    started_wall = time.perf_counter()
    try:
        for packet in packets:
            count = len(feature_times)
            started = time.perf_counter_ns()
            rows.extend(engine.feed(packet))
            duration = (time.perf_counter_ns() - started) / 1e6
            feature_cost = sum(feature_times[count:])
            build_times.append(max(0, duration - feature_cost))
        rows.extend(engine.flush())
    finally:
        Flow.to_row = original
    elapsed = time.perf_counter() - started_wall
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError("Capture contains no eligible flows")
    report = {
        "environment": environment(), "model_version": model.version, "capture_sha256": sha256(pcap),
        "hardware": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                     "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                                        if line.startswith("model name")), platform.processor())},
        "scope": "offline CPU benchmark, first 20000 frames; network delivery and flow completion are separate live measurements",
        "packet_decode_ms": distribution(decode_times), "flow_construction_ms_per_packet": distribution(build_times),
        "feature_extraction_ms_per_emitted_flow": distribution(feature_times), "flow_engine": engine.health(),
        "flow_engine_wall_seconds": elapsed, "flow_engine_cpu_seconds": time.process_time() - started_cpu,
        "flow_engine_packets_per_second": len(packets) / max(elapsed, .000001),
        "release_inference": {},
    }
    sample = pd.concat([frame] * (1024 // len(frame) + 1), ignore_index=True)
    for size in (1, 32, 256):
        batch = sample.iloc[:size]
        model.predict(batch)
        result = measure(lambda: model.predict(batch), 100 if size == 1 else 30)
        result["flows_per_second"] = size * 1000 / result["mean"]
        result["mean_ms_per_flow"] = result["mean"] / size
        report["release_inference"][str(size)] = result
    row = frame.iloc[0].to_dict()
    verdict = model.predict(frame.iloc[:1]).iloc[0].to_dict()
    report["alert_normalization_ms"] = measure(lambda: from_ml(row, verdict))
    if legacy_if and legacy_rf:
        import joblib
        from src.pipeline import TwoStagePipeline
        saved = joblib.load(legacy_rf)
        saved["model"].n_jobs = 1
        detector = joblib.load(legacy_if)
        detector.pipe.named_steps["iforest"].n_jobs = 1
        old = TwoStagePipeline(detector, saved["model"], saved["label_encoder"].classes_.tolist(),
                               mode="serial", min_confidence=0)
        old_frame = extract_flows(pcap)
        if not old_frame.empty:
            report["legacy_single_flow_inference_ms"] = measure(lambda: old.predict(old_frame.iloc[:1], validate=False), 100)
    report["process_peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"release_single": report["release_inference"]["1"],
                      "legacy_single": report.get("legacy_single_flow_inference_ms")}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--legacy-if", type=Path)
    parser.add_argument("--legacy-rf", type=Path)
    args = parser.parse_args()
    benchmark(args.pcap, args.out, args.legacy_if, args.legacy_rf)
