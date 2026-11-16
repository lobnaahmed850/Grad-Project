"""Common alert/observation envelope for independent syslog and ML inputs."""
from __future__ import annotations

import ipaddress
import math
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = "netguard-alert-v1"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timestamp(microseconds):
    return datetime.fromtimestamp(microseconds / 1e6, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def from_syslog(event, run_id=None):
    failed = event["event"].get("outcome") == "failure"
    suspicious = failed or event["event"]["severity"] <= 4
    return {
        "schema_version": SCHEMA_VERSION, "alert_id": str(uuid.uuid4()), "timestamp": event["@timestamp"],
        "ingested_at": now(), "event_source": "syslog", "source_ip": event["source"]["ip"],
        "destination_ip": event.get("destination", {}).get("ip"), "category": event["event"]["category"][0],
        "severity": "high" if failed or event["event"]["severity"] <= 3 else "medium" if suspicious else "info",
        "detection_method": "log-normalization", "decision": "alert" if suspicious else "benign",
        "model_version": None, "score": None, "explanation": event["message"], "evidence": event,
        "processing_status": "normalized", "run_id": run_id,
    }


def from_ml(flow, verdict, run_id=None, timings=None):
    attack = verdict["decision"] == "alert"
    evidence = {
        "source_port": int(flow["source port"]), "destination_port": int(flow["destination port"]),
        "protocol": int(flow["protocol"]), "flow_start_us": int(flow["flow start us"]),
        "flow_end_us": int(flow["flow end us"]), "flow_emitted_us": int(flow["flow emitted us"]),
        "forward_packets": int(flow["total fwd packets"]), "backward_packets": int(flow["total backward packets"]),
        "source_flow_rate": float(flow["source flow rate"]), "feature_version": flow["feature version"],
        "close_reason": flow["flow close reason"], "attack_type": verdict["attack_type"],
        "classifier_confidence": float(verdict["confidence"]), "is_anomaly": bool(verdict["is_anomaly"]),
        "timings_ms": timings or {},
    }
    return {
        "schema_version": SCHEMA_VERSION, "alert_id": str(uuid.uuid4()),
        "timestamp": _timestamp(flow["flow end us"]), "ingested_at": now(), "event_source": "ml",
        "source_ip": flow["source ip"], "destination_ip": flow["destination ip"],
        "category": "intrusion_detection" if attack else "network", "severity": "high" if attack else "info",
        "detection_method": "network-ml", "decision": verdict["decision"], "model_version": verdict["model_version"],
        "score": float(verdict["confidence"]), "explanation": (
            f"{verdict['attack_type']}: classifier confidence {verdict['confidence']:.3f}; "
            f"{flow['source flow rate']:.1f} source flow starts/s"
        ), "evidence": evidence, "processing_status": "normalized", "run_id": run_id,
    }


def validate(event):
    required = {"schema_version", "alert_id", "timestamp", "ingested_at", "event_source", "source_ip",
                "destination_ip", "category", "severity", "detection_method", "decision", "model_version",
                "score", "explanation", "evidence", "processing_status", "run_id"}
    if not isinstance(event, dict) or not required.issubset(event):
        raise ValueError("Missing normalized event fields")
    if event["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported alert schema")
    uuid.UUID(event["alert_id"])
    for field in ("timestamp", "ingested_at"):
        parsed = datetime.fromisoformat(event[field].replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamps require UTC offset")
    ipaddress.ip_address(event["source_ip"])
    if event["destination_ip"] is not None:
        ipaddress.ip_address(event["destination_ip"])
    if event["event_source"] not in ("ml", "syslog") or event["decision"] not in ("alert", "benign"):
        raise ValueError("Invalid source or decision")
    if event["severity"] not in ("info", "low", "medium", "high", "critical"):
        raise ValueError("Invalid severity")
    if not isinstance(event["evidence"], dict) or event["processing_status"] != "normalized":
        raise ValueError("Invalid evidence or processing status")
    if event["score"] is not None and (not isinstance(event["score"], (int, float)) or not math.isfinite(event["score"])):
        raise ValueError("Invalid detection score")
    if event["event_source"] == "ml" and not isinstance(event["model_version"], str):
        raise ValueError("ML events require a model version")
    if not isinstance(event["explanation"], str) or len(event["explanation"]) > 65507:
        raise ValueError("Invalid explanation")
    if event["run_id"] is not None and (not isinstance(event["run_id"], str) or len(event["run_id"]) > 200):
        raise ValueError("Invalid run ID")
    return event
