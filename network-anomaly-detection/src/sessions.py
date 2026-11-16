"""Capture provenance, complete-session splits and conservative overlap checks."""
from __future__ import annotations

import json
import ipaddress
from pathlib import Path

import numpy as np
import pandas as pd

from src.release import sha256
from src.streaming import replay_capture


def read_manifest(path, root):
    manifest = json.loads(Path(path).read_text())
    if manifest.get("schema") != "netguard-sessions-v1":
        raise ValueError("Unsupported session manifest")
    seen_ids, seen_hashes = set(), set()
    roles = set()
    for session in manifest["sessions"]:
        if session["session_id"] in seen_ids or session["sha256"] in seen_hashes:
            raise ValueError("Duplicate capture/session across dataset roles")
        seen_ids.add(session["session_id"])
        seen_hashes.add(session["sha256"])
        if session["role"] not in ("train", "calibration", "test"):
            raise ValueError("Invalid dataset role")
        roles.add(session["role"])
        path = (Path(root) / session["pcap"]).resolve()
        path.relative_to(Path(root).resolve())
        if sha256(path) != session["sha256"]:
            raise ValueError(f"Capture checksum mismatch: {session['session_id']}")
        if session.get("capture_dropped_packets") != 0:
            raise ValueError("Dataset contains a lossy or unverified capture")
        actor_labels = session.get("actor_labels", {actor: session["label"] for actor in session["actor_ips"]})
        if set(actor_labels) != set(session["actor_ips"]) or not all(
            isinstance(label, str) and label and label != "MIXED" for label in actor_labels.values()
        ):
            raise ValueError("Every actor requires an explicit valid label")
        for actor in session["actor_ips"]:
            ipaddress.ip_address(actor)
    if roles != {"train", "calibration", "test"}:
        raise ValueError("Training, calibration and final test sessions are all required")
    return manifest


def load_role(manifest, role, root, config):
    frames, excluded = [], {}
    for session in manifest["sessions"]:
        if session["role"] != role:
            continue
        frame = replay_capture(Path(root) / session["pcap"], config)
        if frame.empty:
            raise ValueError(f"No flows in {session['session_id']}")
        keep = frame["source ip"].isin(session["actor_ips"]) & frame["destination ip"].eq(session["server_ip"])
        excluded[session["session_id"]] = int((~keep).sum())
        frame = frame[keep].copy()
        if frame.empty:
            raise ValueError("No originating-actor flows; verify scenario provenance")
        actor_labels = session.get("actor_labels", {actor: session["label"] for actor in session["actor_ips"]})
        frame["label"] = frame["source ip"].map(actor_labels)
        frame["session_id"] = session["session_id"]
        frames.append(frame)
    if not frames:
        raise ValueError(f"No sessions for role {role}")
    return pd.concat(frames, ignore_index=True), excluded


def fingerprints(frame, features, decimals=3):
    values = frame[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(-999999.0)
    quantized = np.sign(values) * np.log1p(np.abs(values))
    return pd.util.hash_pandas_object(quantized.round(decimals), index=False).to_numpy()


def exclude_overlap(reference, target, features):
    reference_hashes = fingerprints(reference, features)
    target_hashes = fingerprints(target, features)
    mask = ~np.isin(target_hashes, reference_hashes)
    report = {"reference_rows": len(reference), "target_rows": len(target), "overlap_rows": int((~mask).sum()),
              "novel_rows": int(mask.sum()), "rounding_decimals": 3,
              "policy": "primary metrics exclude signed-log1p feature fingerprints rounded to 3 decimals matching earlier roles",
              "limitation": "quantized near-duplicate screening is not an exhaustive nearest-neighbor search"}
    return target[mask].reset_index(drop=True), report
