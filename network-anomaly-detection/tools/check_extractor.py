"""Compare an extractor's CSV with the known answers from known_answer_pcap.py.

    python tools/check_extractor.py flows.csv known_answer.json

Any flow extractor can be tested this way, including a Java CICFlowMeter build.
Exit code 0 means every check passed, and 1 means at least one failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

# Different CICFlowMeter versions spell these columns differently.
ALIASES = {
    "src_ip": ["Src IP", "Source IP"],
    "src_port": ["Src Port", "Source Port"],
    "dst_ip": ["Dst IP", "Destination IP"],
    "dst_port": ["Dst Port", "Destination Port"],
    "protocol": ["Protocol"],
    "flow_duration_us": ["Flow Duration"],
    "tot_fwd_pkts": ["Tot Fwd Pkts", "Total Fwd Packet", "Total Fwd Packets"],
    "tot_bwd_pkts": ["Tot Bwd Pkts", "Total Bwd packets", "Total Backward Packets"],
    "totlen_fwd_bytes": ["TotLen Fwd Pkts", "Total Length of Fwd Packet", "Total Length of Fwd Packets"],
    "totlen_bwd_bytes": ["TotLen Bwd Pkts", "Total Length of Bwd Packet", "Total Length of Bwd Packets"],
    "fwd_header_bytes": ["Fwd Header Len", "Fwd Header Length"],
    "bwd_header_bytes": ["Bwd Header Len", "Bwd Header Length"],
    "init_win_fwd": ["Init Fwd Win Byts", "FWD Init Win Bytes", "Init_Win_bytes_forward"],
    "init_win_bwd": ["Init Bwd Win Byts", "Bwd Init Win Bytes", "Init_Win_bytes_backward"],
    "fwd_seg_size_min": ["Fwd Seg Size Min", "Fwd Segment Size Min", "min_seg_size_forward"],
    "syn_column": ["SYN Flag Cnt", "SYN Flag Count"],
    "psh_column": ["PSH Flag Cnt", "PSH Flag Count"],
}
_LOOKUP = {name.lower(): canonical for canonical, names in ALIASES.items() for name in names}


def read_flows(path: Path) -> pd.DataFrame:
    flows = pd.read_csv(path, low_memory=False, encoding="latin-1")
    return normalize_columns(flows)


def normalize_columns(flows: pd.DataFrame) -> pd.DataFrame:
    flows = flows.copy()
    flows.columns = flows.columns.str.strip()
    return flows.rename(columns=lambda c: _LOOKUP.get(c.lower(), c))


def find_flow(flows: pd.DataFrame, answer: dict) -> tuple[pd.DataFrame, bool]:
    """Return the rows for a scenario, and whether they name the client as source."""
    client = (answer["client_ip"], answer["client_port"])
    server = (answer["server_ip"], answer["server_port"])

    def rows(a, b):
        return flows[
            (flows["src_ip"] == a[0]) & (flows["src_port"] == a[1])
            & (flows["dst_ip"] == b[0]) & (flows["dst_port"] == b[1])
            & (flows["protocol"] == answer["protocol"])
        ]

    forward = rows(client, server)
    return (forward, True) if len(forward) else (rows(server, client), False)


def check(flows: pd.DataFrame, answers: list[dict]) -> list[dict]:
    results = []
    for answer in answers:
        scenario = answer["scenario"]
        found, client_is_source = find_flow(flows, answer)
        if found.empty:
            results.append(dict(scenario=scenario, check="flow present", expected="1 row", got="0 rows", ok=False))
            continue
        results.append(dict(scenario=scenario, check="flow count", expected=1, got=len(found), ok=len(found) == 1))
        results.append(dict(
            scenario=scenario, check="source is the client",
            expected=True, got=client_is_source, ok=client_is_source,
        ))
        row = found.iloc[0]
        for key, expected in answer.items():
            if key in {"scenario", "client_ip", "client_port", "server_ip", "server_port", "protocol"}:
                continue
            if key not in row.index:
                results.append(dict(scenario=scenario, check=key, expected=expected, got="missing", ok=False))
                continue
            got = pd.to_numeric(row[key], errors="coerce")
            results.append(dict(scenario=scenario, check=key, expected=expected, got=got, ok=bool(got == expected)))
    return results


def flag_layout(flows: pd.DataFrame, answers: list[dict]) -> str:
    """Report where a known SYN-only first packet appears, since layout varies by tool version."""
    probe = next(a for a in answers if a["scenario"] == "syn_probe_answered_by_rst")
    found, _ = find_flow(flows, probe)
    if found.empty or "syn_column" not in found.columns or "psh_column" not in found.columns:
        return "unknown"
    row = found.iloc[0]
    if row["syn_column"] > 0:
        return "named: remap_flags is needed before using the saved models"
    if row["psh_column"] > 0:
        return "training: matches the saved models"
    return "unknown"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flows_csv", type=Path)
    parser.add_argument("answers_json", type=Path)
    args = parser.parse_args()

    flows = read_flows(args.flows_csv)
    answers = json.loads(args.answers_json.read_text())
    outcome = pd.DataFrame(check(flows, answers))
    failed = outcome[~outcome["ok"]]
    print(f"{outcome['ok'].sum()} of {len(outcome)} checks passed")
    print(f"Flag layout: {flag_layout(flows, answers)}")
    if not failed.empty:
        print(failed.to_string(index=False))
    sys.exit(0 if failed.empty else 1)
