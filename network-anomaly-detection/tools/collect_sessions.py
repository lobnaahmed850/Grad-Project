"""Collect independent, role-assigned Docker sessions; never target outside the lab."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "network-anomaly-detection/lab/integration/compose.yml"
LABELS = {"benign": "BENIGN", "scan": "PORT_SCAN", "flood": "HTTP_FLOOD", "slow": "SLOW_HTTP"}


def docker(*arguments, check=True):
    completed = subprocess.run(["docker", *arguments], capture_output=True, text=True, check=check,
                               env={**os.environ, "NETGUARD_TOKEN": os.environ.get("NETGUARD_TOKEN", "netguard-local-validation")})
    return completed.stdout.strip()


def compose(*arguments):
    return docker("compose", "-f", str(COMPOSE), *arguments)


def collect(output, normal_runs=2, attack_runs=1, seconds=5, mixed_runs=0, resume=False):
    if output.exists() and not resume:
        raise ValueError("Manifest exists; choose a new output path to preserve provenance")
    output.parent.mkdir(parents=True, exist_ok=True)
    captures = ROOT / "artifacts/sessions"
    captures.mkdir(parents=True, exist_ok=True)
    image = json.loads(docker("image", "inspect", "netguard-lab-host:1"))[0]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {"schema": "netguard-sessions-v1", "scope": "synthetic isolated Docker lab", "sessions": [],
                "environment": {"image_id": image["Id"], "docker": docker("version", "--format", "{{.Server.Version}}"),
                                "git_base": revision, "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}}
    configuration = {"normal_runs": normal_runs, "attack_runs": attack_runs, "mixed_runs": mixed_runs, "seconds": seconds}
    if resume:
        manifest = json.loads(output.read_text())
        if manifest["environment"]["image_id"] != image["Id"]:
            raise ValueError("Resume requires the same traffic image; use a new manifest for a new environment")
        if "collection_config" in manifest and manifest["collection_config"] != configuration:
            raise ValueError("Resume configuration differs from the original run")
        for existing in manifest["sessions"]:
            if existing["capture_dropped_packets"] or hashlib.sha256((ROOT / existing["pcap"]).read_bytes()).hexdigest() != existing["sha256"]:
                raise ValueError("Previously admitted capture is missing, changed or lossy")
        manifest["environment"].setdefault("resumed_at", []).append(datetime.datetime.now(datetime.timezone.utc).isoformat())
    manifest["collection_config"] = configuration
    admitted = 0
    for role_index, role in enumerate(("train", "calibration", "test")):
        scenarios = (["benign"] * normal_runs + ["mixed"] * mixed_runs
                     + [name for name in ("scan", "flood", "slow") for _ in range(attack_runs)])
        for iteration, scenario in enumerate(scenarios):
            seed = 1000 * (role_index + 1) + iteration * 17
            if admitted < len(manifest["sessions"]):
                existing = manifest["sessions"][admitted]
                if (existing["role"], existing["scenario"], existing["metadata"]["seed"]) != (role, scenario, seed):
                    raise ValueError("Existing sessions do not match the requested plan prefix")
                admitted += 1
                continue
            identifier = f"{role}-{scenario}-{seed}-{time.time_ns()}"
            client = "client-a" if (role_index + iteration) % 2 == 0 else "client-b"
            actor = "10.77.0.20" if client == "client-a" else "10.77.0.21"
            relative = Path("artifacts/sessions") / f"{identifier}.pcap"
            capture = ROOT / relative
            command = f"tcpdump -Z root -B 16384 -i lab0 -U -s 0 -w /captures/{identifier}.pcap 'ip and host 10.77.0.10' >/tmp/capture.log 2>&1 & echo $! >/tmp/capture.pid"
            compose("exec", "-T", "capture", "sh", "-c", command)
            try:
                ready = False
                for _ in range(20):
                    size = compose("exec", "-T", "capture", "sh", "-c",
                                   f"test ! -f /captures/{identifier}.pcap || stat -c %s /captures/{identifier}.pcap")
                    if size and int(size) >= 24:
                        ready = True
                        break
                    time.sleep(0.1)
                if not ready:
                    raise RuntimeError("Packet capture did not initialize")
                def generate(selected_client, selected_scenario):
                    result = compose("exec", "-T", selected_client, "python3", "/lab/traffic.py", selected_scenario,
                                     "--seconds", str(seconds), "--seed", str(seed))
                    return json.loads(result.splitlines()[-1])

                if scenario == "mixed":
                    other_client = "client-b" if client == "client-a" else "client-a"
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        normal = executor.submit(generate, client, "benign")
                        attack = executor.submit(generate, other_client, "flood")
                        actors = [normal.result(), attack.result()]
                    metadata = {"scenario": "mixed", "seed": seed, "actors": actors,
                                "started_unix": min(item["started_unix"] for item in actors),
                                "ended_unix": max(item["ended_unix"] for item in actors),
                                "operations": sum(item["operations"] for item in actors),
                                "errors": sum(item["errors"] for item in actors)}
                else:
                    metadata = generate(client, scenario)
            finally:
                compose("exec", "-T", "capture", "sh", "-c", "kill -INT $(cat /tmp/capture.pid)")
                for _ in range(30):
                    stats = compose("exec", "-T", "capture", "cat", "/tmp/capture.log")
                    if "packets dropped by kernel" in stats:
                        break
                    time.sleep(0.1)
            container = compose("ps", "-q", "capture")
            docker("cp", f"{container}:/captures/{identifier}.pcap", str(capture))
            dropped = re.search(r"(\d+) packets dropped by kernel", stats)
            if not dropped:
                raise RuntimeError("Missing capture loss statistics")
            session = {
                "session_id": identifier, "role": role, "scenario": scenario, "label": LABELS.get(scenario, "MIXED"),
                "pcap": str(relative), "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                "bytes": capture.stat().st_size, "actor_ips": [actor], "server_ip": "10.77.0.10",
                "metadata": metadata, "capture_statistics": stats, "capture_dropped_packets": int(dropped[1]),
                "requested_capture_buffer_kib": 16384,
            }
            if scenario == "mixed":
                other_actor = "10.77.0.21" if actor == "10.77.0.20" else "10.77.0.20"
                session["actor_ips"] = [actor, other_actor]
                session["actor_labels"] = {actor: "BENIGN", other_actor: "HTTP_FLOOD"}
            if session["capture_dropped_packets"]:
                raise RuntimeError("Capture loss invalidates this session")
            if metadata["operations"] == 0:
                raise RuntimeError("No actual operations generated")
            if metadata["errors"]:
                raise RuntimeError(f"Scenario operations failed: {metadata}; preserve capture for diagnosis, do not admit to training")
            manifest["sessions"].append(session)
            admitted += 1
            output.write_text(json.dumps(manifest, indent=2) + "\n")
            print(json.dumps({"session": identifier, "operations": metadata["operations"], "bytes": session["bytes"],
                              "errors": metadata["errors"]}), flush=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "artifacts/sessions/manifest.json")
    parser.add_argument("--normal-runs", type=int, default=2)
    parser.add_argument("--attack-runs", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--mixed-runs", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    collect(args.manifest, args.normal_runs, args.attack_runs, args.seconds, args.mixed_runs, args.resume)
