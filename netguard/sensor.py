"""Live AF_PACKET capture, bounded flow inference and durable HTTP delivery."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import resource
import signal
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import deque

import numpy as np
import pandas as pd

from netguard.alerts import from_ml
from netguard.capture import PacketRing
from netguard.storage import Outbox
from src.flow_extractor import decode_frame
from src.release import ReleaseModel
from src.streaming import StreamingFlows


def distribution(samples):
    values = list(samples)
    if not values:
        return {"samples": 0}
    return {"samples": len(values), "mean": float(np.mean(values)), "median": float(np.median(values)),
            "p95": float(np.quantile(values, .95)), "p99": float(np.quantile(values, .99)), "max": max(values)}


class Sensor:
    def __init__(self, model, endpoint, outbox_path, token="", queue_size=2048, batch_size=32,
                 batch_wait_ms=5, run_id=None):
        self.model, self.endpoint, self.token = model, endpoint.rstrip("/"), token
        self.flows = StreamingFlows(model.flow_config)
        self.queue = queue.Queue(queue_size)
        self.outbox = Outbox(outbox_path)
        self.batch_size, self.batch_wait_ms, self.run_id = batch_size, batch_wait_ms, run_id
        self.stop = threading.Event()
        self.inference_stop = threading.Event()
        self.sender_stop = threading.Event()
        self.lock = threading.RLock()
        self.counters = {"queue_dropped": 0, "outbox_dropped": 0, "inference_errors": 0,
                         "delivered": 0, "delivery_errors": 0, "capture_restarts": 0, "kernel_dropped": 0,
                         "queue_peak": 0, "decoded_packets": 0, "ignored_or_malformed_packets": 0,
                         "verdicts": 0, "alerts": 0, "capture_truncated": 0}
        self.samples = {name: deque(maxlen=4096) for name in (
            "packet_to_flow_ms", "feature_extraction_ms", "queue_delay_ms", "inference_batch_ms",
            "feature_preprocessing_ms", "classifier_inference_ms", "alert_normalization_ms", "ingestion_ms",
            "delivery_ms", "flow_completion_delay_ms", "end_to_end_since_flow_start_ms",
            "end_to_end_since_last_packet_ms")}
        self.started = time.monotonic()
        self.status = "initializing"
        self.threads = []
        self.server_ip = None

    def sample(self, name, value):
        with self.lock:
            self.samples[name].append(float(value))

    def submit(self, rows):
        for row in rows:
            if self.server_ip is not None and row["destination ip"] != self.server_ip:
                self.counters["excluded_non_ingress_flows"] = self.counters.get("excluded_non_ingress_flows", 0) + 1
                continue
            try:
                self.queue.put_nowait((row, time.perf_counter_ns()))
                self.counters["queue_peak"] = max(self.counters["queue_peak"], self.queue.qsize())
            except queue.Full:
                self.counters["queue_dropped"] += 1

    def start_workers(self):
        self.threads = [threading.Thread(target=self.infer, daemon=True), threading.Thread(target=self.deliver, daemon=True)]
        for worker in self.threads:
            worker.start()

    def infer(self):
        while not self.inference_stop.is_set() or not self.queue.empty():
            try:
                first = self.queue.get(timeout=.05)
            except queue.Empty:
                continue
            batch = [first]
            deadline = time.perf_counter_ns() + self.batch_wait_ms * 1e6
            while len(batch) < self.batch_size:
                remaining = (deadline - time.perf_counter_ns()) / 1e9
                if remaining <= 0:
                    break
                try:
                    batch.append(self.queue.get(timeout=remaining))
                except queue.Empty:
                    break
            started = time.perf_counter_ns()
            try:
                frame = pd.DataFrame.from_records(row for row, _ in batch)
                verdicts = self.model.predict(frame).to_dict("records")
                inference_ms = (time.perf_counter_ns() - started) / 1e6
                self.sample("inference_batch_ms", inference_ms)
                for name, value in self.model.last_timings.items():
                    self.sample(name, value)
                events = []
                for (row, queued), verdict in zip(batch, verdicts):
                    timings = {"queue_delay": (started - queued) / 1e6, "inference_batch": inference_ms,
                               "flow_completion": (row["flow emitted us"] - row["flow end us"]) / 1000}
                    normalized = time.perf_counter_ns()
                    event = from_ml(row, verdict, self.run_id, timings)
                    self.sample("alert_normalization_ms", (time.perf_counter_ns() - normalized) / 1e6)
                    self.sample("queue_delay_ms", timings["queue_delay"])
                    self.sample("flow_completion_delay_ms", timings["flow_completion"])
                    self.counters["verdicts"] += 1
                    self.counters["alerts"] += verdict["decision"] == "alert"
                    events.append(event)
                try:
                    self.outbox.put_many(events)
                except OverflowError:
                    self.counters["outbox_dropped"] += len(events)
            except Exception as exc:
                self.counters["inference_errors"] += len(batch)
                self.status = f"inference error: {type(exc).__name__}: {exc}"
            finally:
                for _ in batch:
                    self.queue.task_done()

    def post(self, path, payload):
        request = urllib.request.Request(self.endpoint + path, json.dumps(payload, allow_nan=False).encode(),
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)

    def deliver(self):
        next_diagnostic = 0
        while not self.sender_stop.is_set():
            if time.monotonic() >= next_diagnostic:
                try:
                    self.post("/api/diagnostics", {"sensor": "lab-sensor", "metrics": self.health()})
                except (OSError, ValueError):
                    self.counters["delivery_errors"] += 1
                next_diagnostic = time.monotonic() + 2
            pending = self.outbox.pending(16)
            if not pending:
                self.sender_stop.wait(.02)
                continue
            started = time.perf_counter_ns()
            try:
                response = self.post("/api/events/batch", pending)
                if len(response["inserted"]) != len(pending):
                    raise ValueError("Batch acknowledgment count mismatch")
            except (OSError, ValueError, KeyError):
                self.counters["delivery_errors"] += 1
                self.sender_stop.wait(.25)
                continue
            delivery_ms = (time.perf_counter_ns() - started) / 1e6
            try:
                self.outbox.ack_many([event["alert_id"] for event in pending])
            except sqlite3.Error:
                self.counters["delivery_errors"] += 1
                self.sender_stop.wait(.25)
                continue
            for event in pending:
                self.counters["delivered"] += 1
                self.sample("ingestion_ms", response["ingestion_ms"])
                self.sample("delivery_ms", delivery_ms)
                current_us = time.time_ns() / 1000
                evidence = event["evidence"]
                self.sample("end_to_end_since_flow_start_ms", (current_us - evidence["flow_start_us"]) / 1000)
                self.sample("end_to_end_since_last_packet_ms", (current_us - evidence["flow_end_us"]) / 1000)

    def health(self):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        with self.lock:
            timings = {name: distribution(values) for name, values in self.samples.items()}
        elapsed = time.monotonic() - self.started
        return {"status": self.status, "model_version": self.model.version, "uptime_seconds": elapsed,
                "model_sha256": self.model.manifest.get("model_sha256"),
                "flow_engine": self.flows.health(), **self.counters, "queue_depth": self.queue.qsize(),
                "outbox_depth": self.outbox.size(), "cpu_seconds": usage.ru_utime + usage.ru_stime,
                "cpu_percent_of_one_core_lifetime": 100 * (usage.ru_utime + usage.ru_stime) / max(elapsed, .001),
                "peak_rss_mb": usage.ru_maxrss / 1024, "throughput_flows_per_second": self.counters["verdicts"] / max(elapsed, .001),
                "timings_ms_last_4096_samples": timings}

    def capture(self, interface, include_net, server_ip):
        network = ipaddress.ip_network(include_net)
        ipaddress.ip_address(server_ip)
        self.server_ip = server_ip
        self.start_workers()
        while not self.stop.is_set():
            try:
                self._capture(interface, network, server_ip)
            except OSError as exc:
                self.status = f"capture error: {exc}"
                self.counters["capture_restarts"] += 1
                self.stop.wait(1)
        self.submit(self.flows.flush("shutdown"))
        self.inference_stop.set()
        self.threads[0].join(timeout=20)
        deadline = time.monotonic() + 10
        while self.outbox.size() and time.monotonic() < deadline:
            time.sleep(.05)
        self.status = "stopped"
        try:
            self.post("/api/diagnostics", {"sensor": "lab-sensor", "metrics": self.health()})
        except (OSError, ValueError):
            pass
        self.sender_stop.set()
        self.threads[1].join(timeout=3)
        print(json.dumps(self.health(), allow_nan=False), flush=True)
        self.outbox.close()

    def _capture(self, interface, network, server_ip):
        capture = PacketRing(interface)
        try:
            self.status = "capturing"
            diagnostic_deadline = time.monotonic() + 1
            try:
                while not self.stop.is_set():
                    packet = capture.receive()
                    if packet is None:
                        self.submit(self.flows.advance(max(self.flows.watermark, time.time_ns() // 1000)))
                        continue
                    if not packet:
                        continue
                    timestamp, raw = packet
                    decoded = decode_frame(timestamp, raw)
                    if decoded is None:
                        self.counters["ignored_or_malformed_packets"] += 1
                        continue
                    source, destination = socket.inet_ntoa(decoded[1]), socket.inet_ntoa(decoded[3])
                    if ipaddress.ip_address(source) not in network or ipaddress.ip_address(destination) not in network:
                        continue
                    if server_ip not in (source, destination):
                        continue
                    self.counters["decoded_packets"] += 1
                    started = time.perf_counter_ns()
                    rows = self.flows.feed(decoded)
                    duration = (time.perf_counter_ns() - started) / 1e6
                    self.sample("packet_to_flow_ms", duration)
                    if rows:
                        self.sample("feature_extraction_ms", duration)
                    self.submit(rows)
                    if time.monotonic() >= diagnostic_deadline:
                        self.counters["kernel_dropped"] += capture.dropped()
                        diagnostic_deadline = time.monotonic() + 1
            finally:
                self.counters["kernel_dropped"] += capture.dropped()
                self.counters["capture_truncated"] += capture.truncated
        finally:
            capture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8090")
    parser.add_argument("--outbox", default="runtime/outbox.sqlite")
    parser.add_argument("--include-net", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--batch-wait-ms", type=float, default=5)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 256 or not 0 <= args.batch_wait_ms <= 100:
        parser.error("Batch size must be 1..256 and batch wait 0..100 ms")
    sensor = Sensor(ReleaseModel.load_default(), args.endpoint, args.outbox, os.environ.get("NETGUARD_TOKEN", ""),
                    batch_size=args.batch_size, batch_wait_ms=args.batch_wait_ms, run_id=args.run_id)
    signal.signal(signal.SIGTERM, lambda *_: sensor.stop.set())
    signal.signal(signal.SIGINT, lambda *_: sensor.stop.set())
    sensor.capture(args.interface, args.include_net, args.server_ip)


if __name__ == "__main__":
    main()
