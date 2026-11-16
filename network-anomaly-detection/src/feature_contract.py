"""What each feature means, and checks that incoming flows really match that meaning.

Matching column names is not enough. The lab CSVs had every expected name, yet their
values meant something else. validate_flows() tests values, so it catches problems
that a name check can't.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

MICROSECONDS, BYTES, PACKETS = "microseconds", "bytes", "packets"

# status says how the feature compares between training data and the lab tool's output:
#   same            same meaning in both
#   repairable      moved by the first-packet defect, can be solved exactly from a CSV
#   estimate_only   moved by the defect, and only an estimate can be recovered from a CSV
#   lost            not stored anywhere in the defective output
#   renamed         correct value, but stored under a different column name
#   training_noise  the training values themselves are unreliable
#   constant        the same value on every training row, so it carries no information
_GROUPS = [
    (["destination port"], "port number", "same", "Server port. Tied to each network's services."),
    (["flow duration"], MICROSECONDS, "same", "Last packet time minus first packet time."),
    (["total fwd packets", "total backward packets", "subflow fwd packets", "subflow bwd packets"],
     PACKETS, "repairable", "Packets per direction. Forward means the direction of the flow's first packet."),
    (["total length of fwd packets", "total length of bwd packets", "subflow fwd bytes", "subflow bwd bytes"],
     BYTES, "repairable", "Bytes after the transport header, including Ethernet padding."),
    (["fwd packet length max", "fwd packet length min", "fwd packet length mean", "fwd packet length std",
      "avg fwd segment size", "bwd packet length mean", "bwd packet length std", "avg bwd segment size"],
     BYTES, "repairable", "Size statistics for one direction."),
    (["bwd packet length max", "bwd packet length min"], BYTES, "estimate_only", "Largest or smallest backward size."),
    (["min packet length", "max packet length", "packet length mean", "packet length std",
      "packet length variance", "average packet size"],
     BYTES, "same", "Size statistics for the flow. The tool counts the first packet twice."),
    (["flow bytes/s", "flow packets/s"], "per second", "same", "Rate over the flow. Undefined when duration is 0."),
    (["fwd packets/s", "bwd packets/s"], "per second", "repairable", "Packet rate for one direction."),
    (["flow iat mean", "flow iat std", "flow iat max", "flow iat min"], MICROSECONDS, "same", "Gaps between packets."),
    (["fwd iat total", "fwd iat mean", "fwd iat std", "fwd iat max", "fwd iat min",
      "bwd iat total", "bwd iat mean", "bwd iat std", "bwd iat max", "bwd iat min"],
     MICROSECONDS, "estimate_only", "Gaps between packets in one direction."),
    (["active mean", "active std", "active max", "active min", "idle mean", "idle std", "idle max", "idle min"],
     MICROSECONDS, "same", "Active and idle periods, split at 5 seconds of silence."),
    (["fwd psh flags", "fwd urg flags"], "0 or 1", "repairable", "Whether the first packet had PSH or URG."),
    (["bwd psh flags", "bwd urg flags"], "0 or 1", "constant", "Always 0 because only the first packet is checked."),
    (["fin flag count"], "0 or 1", "renamed", "First packet had RST."),
    (["syn flag count"], "0 or 1", "renamed", "First packet had PSH."),
    (["rst flag count"], "0 or 1", "renamed", "First packet had ECE."),
    (["psh flag count"], "0 or 1", "renamed", "First packet had SYN."),
    (["ack flag count"], "0 or 1", "same", "First packet had ACK."),
    (["urg flag count"], "0 or 1", "renamed", "First packet had FIN."),
    (["cwe flag count"], "0 or 1", "renamed", "First packet had URG."),
    (["ece flag count"], "0 or 1", "renamed", "First packet had CWR."),
    (["down/up ratio"], "whole number", "repairable", "Backward packets divided by forward packets, rounded down."),
    (["fwd header length", "fwd header length.1", "bwd header length"], BYTES, "training_noise",
     "TCP header bytes per direction. On training UDP rows this is left over from the previous TCP packet."),
    (["min_seg_size_forward"], BYTES, "training_noise", "Smallest forward header. Same UDP problem as above."),
    (["init_win_bytes_forward"], BYTES, "lost", "TCP window of the first packet. Depends on the operating system."),
    (["init_win_bytes_backward"], BYTES, "same", "TCP window of the last backward packet, despite the name."),
    (["act_data_pkt_fwd"], PACKETS, "same", "Forward packets with payload, not counting the first packet."),
    (["fwd avg bytes/bulk", "fwd avg packets/bulk", "fwd avg bulk rate", "bwd avg bytes/bulk", "bwd avg packets/bulk",
      "bwd avg bulk rate"], "unused", "constant", "Always 0 in the training data."),
]


@dataclass(frozen=True)
class Feature:
    unit: str
    status: str
    meaning: str


CONTRACT = {name: Feature(unit, status, meaning) for names, unit, status, meaning in _GROUPS for name in names}

# Sizes and packet counts that keep their meaning across networks and survive the CSV repair.
PORTABLE_FEATURES = [
    "total fwd packets", "total backward packets", "total length of fwd packets", "total length of bwd packets",
    "fwd packet length max", "fwd packet length min", "fwd packet length mean", "fwd packet length std",
    "bwd packet length mean", "bwd packet length std", "min packet length", "max packet length",
    "packet length mean", "packet length std", "packet length variance", "average packet size",
    "down/up ratio", "act_data_pkt_fwd",
    "fin flag count", "syn flag count", "psh flag count", "ack flag count", "urg flag count",
]
# The same list plus absolute timing, which is exact in the lab CSVs but depends on the network.
PORTABLE_WITH_TIMING = PORTABLE_FEATURES + [
    "flow duration", "flow bytes/s", "flow packets/s", "fwd packets/s", "bwd packets/s",
    "flow iat mean", "flow iat std", "flow iat max", "flow iat min",
    "active mean", "active std", "active max", "active min", "idle mean", "idle std", "idle max", "idle min",
]


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" or "warning"
    code: str
    message: str


class IncompatibleFlows(ValueError):
    """Flows that would produce meaningless scores if passed to the models."""

    def __init__(self, issues: list[Issue]):
        self.issues = issues
        super().__init__("; ".join(issue.message for issue in issues if issue.severity == "error"))


def detect_flag_layout(flows: pd.DataFrame) -> str:
    """Return 'training' or 'named': how flag columns are arranged in this data.

    In the training layout, "syn flag count" holds PSH of the first packet, so it
    always equals "fwd psh flags". A SYN in the first packet shows up in "psh flag
    count". In the named layout, "syn flag count" really is SYN.
    """
    tcp = flows[flows["protocol"] == 6] if "protocol" in flows else flows
    if tcp.empty:
        return "unknown"
    equal = (tcp["syn flag count"] > 0) == (tcp["fwd psh flags"] > 0)
    # Scan and handshake traffic starts with SYN. In named data that sets "syn flag
    # count" without "fwd psh flags", so the two columns disagree.
    return "training" if equal.mean() >= 0.99 else "named"


def validate_flows(flows: pd.DataFrame, min_rows: int = 50) -> list[Issue]:
    """Check flow values against the contract. Share-based checks need min_rows rows."""
    issues: list[Issue] = []
    missing = [name for name in CONTRACT if name not in flows.columns and name != "fwd header length.1"]
    if missing:
        issues.append(Issue("error", "missing_columns", f"Missing {len(missing)} features, such as {missing[:3]}"))
        return issues
    if len(flows) < min_rows:
        return issues

    frame = flows.replace([np.inf, -np.inf], np.nan)
    if (frame["total fwd packets"] == 0).mean() > 0.01:
        share = (frame["total fwd packets"] == 0).mean()
        issues.append(Issue(
            "error", "first_packet_backward",
            f"{share:.1%} of flows have no forward packets. A flow's first packet defines forward, so this should "
            "never happen. The extractor counts the first packet as backward, as CICFlowMeter did from 2018-05-31 "
            "to 2020-01-20. Re-extract with src/flow_extractor.py, or use src/lab_data.repair_first_packet.",
        ))
    tcp = frame[frame["protocol"] == 6] if "protocol" in frame else frame
    if len(tcp) and (tcp["min_seg_size_forward"] == 0).mean() > 0.5:
        issues.append(Issue(
            "error", "forward_fields_never_set",
            f"min_seg_size_forward is 0 on {(tcp['min_seg_size_forward'] == 0).mean():.1%} of TCP flows, so the "
            "first packet never reached the forward path.",
        ))
    if len(tcp) and (tcp["init_win_bytes_forward"] == -1).mean() > 0.5:
        issues.append(Issue(
            "error", "forward_window_missing",
            f"init_win_bytes_forward is -1 on {(tcp['init_win_bytes_forward'] == -1).mean():.1%} of TCP flows.",
        ))
    if detect_flag_layout(frame) == "named":
        issues.append(Issue(
            "error", "flag_columns_differ",
            "Flag columns use real flag names, but the models learned a shuffled layout. For example, training "
            '"psh flag count" holds SYN. Use src/lab_data.remap_flags before scoring.',
        ))

    timed = frame[frame["flow duration"] > 0]
    if len(timed):
        packets = timed["total fwd packets"] + timed["total backward packets"]
        expected = packets / (timed["flow duration"] / 1e6)
        close = np.isclose(timed["flow packets/s"], expected, rtol=0.01)
        if close.mean() < 0.95:
            issues.append(Issue(
                "error", "units_differ",
                f"Flow packets/s agrees with packets / duration on only {close.mean():.1%} of rows. "
                "Flow duration should be in microseconds.",
            ))
    negative = (frame["flow duration"] < 0).mean()
    if negative > 0.01:
        issues.append(Issue("warning", "negative_duration", f"{negative:.1%} of flows have a negative duration."))
    bad = flows[list(CONTRACT.keys() & set(flows.columns))].replace([np.inf, -np.inf], np.nan).isna().any(axis=1).mean()
    if bad > 0:
        issues.append(Issue(
            "warning", "undefined_values",
            f"{bad:.1%} of flows have undefined values, usually zero-duration flows. Keep and score them.",
        ))
    return issues


def require_compatible(flows: pd.DataFrame) -> list[Issue]:
    """Raise IncompatibleFlows on any error. Otherwise return the warnings."""
    issues = validate_flows(flows)
    if any(issue.severity == "error" for issue in issues):
        raise IncompatibleFlows(issues)
    return issues
