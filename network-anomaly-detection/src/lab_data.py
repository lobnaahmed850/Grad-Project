"""Load the lab CSVs and make them comparable with the training data.

The lab CSVs come from a CICFlowMeter build from 2018-2019 with two differences from
the tool that produced CICIDS2017:

* It counts the first packet of every flow as backward.
* It writes flag columns under their real names, while training columns are shuffled.

The flag fix is exact. Most of the first-packet repair is exact too, because the bad
values can be solved from other columns, but a few values are lost and must be estimated.
FIRST_PACKET_EXACT and FIRST_PACKET_ESTIMATED list which is which. Re-extracting from
pcaps with src/flow_extractor.py is always better than repairing a CSV.
"""
from __future__ import annotations

import glob
import os

import numpy as np
import pandas as pd

from src.flow_extractor import NAMED_FLAG_COLUMNS, TRAINING_FLAG_COLUMNS

CSV_TO_TRAINING_NAMES = {
    "Src IP": "source ip", "Src Port": "source port", "Dst IP": "destination ip", "Dst Port": "destination port",
    "Protocol": "protocol", "Flow Duration": "flow duration",
    "Tot Fwd Pkts": "total fwd packets", "Tot Bwd Pkts": "total backward packets",
    "TotLen Fwd Pkts": "total length of fwd packets", "TotLen Bwd Pkts": "total length of bwd packets",
    "Fwd Pkt Len Max": "fwd packet length max", "Fwd Pkt Len Min": "fwd packet length min",
    "Fwd Pkt Len Mean": "fwd packet length mean", "Fwd Pkt Len Std": "fwd packet length std",
    "Bwd Pkt Len Max": "bwd packet length max", "Bwd Pkt Len Min": "bwd packet length min",
    "Bwd Pkt Len Mean": "bwd packet length mean", "Bwd Pkt Len Std": "bwd packet length std",
    "Flow Byts/s": "flow bytes/s", "Flow Pkts/s": "flow packets/s",
    "Flow IAT Mean": "flow iat mean", "Flow IAT Std": "flow iat std",
    "Flow IAT Max": "flow iat max", "Flow IAT Min": "flow iat min",
    "Fwd IAT Tot": "fwd iat total", "Fwd IAT Mean": "fwd iat mean", "Fwd IAT Std": "fwd iat std",
    "Fwd IAT Max": "fwd iat max", "Fwd IAT Min": "fwd iat min",
    "Bwd IAT Tot": "bwd iat total", "Bwd IAT Mean": "bwd iat mean", "Bwd IAT Std": "bwd iat std",
    "Bwd IAT Max": "bwd iat max", "Bwd IAT Min": "bwd iat min",
    "Fwd PSH Flags": "fwd psh flags", "Bwd PSH Flags": "bwd psh flags",
    "Fwd URG Flags": "fwd urg flags", "Bwd URG Flags": "bwd urg flags",
    "Fwd Header Len": "fwd header length", "Bwd Header Len": "bwd header length",
    "Fwd Pkts/s": "fwd packets/s", "Bwd Pkts/s": "bwd packets/s",
    "Pkt Len Min": "min packet length", "Pkt Len Max": "max packet length",
    "Pkt Len Mean": "packet length mean", "Pkt Len Std": "packet length std", "Pkt Len Var": "packet length variance",
    "FIN Flag Cnt": "fin flag count", "SYN Flag Cnt": "syn flag count", "RST Flag Cnt": "rst flag count",
    "PSH Flag Cnt": "psh flag count", "ACK Flag Cnt": "ack flag count", "URG Flag Cnt": "urg flag count",
    "CWE Flag Count": "cwe flag count", "ECE Flag Cnt": "ece flag count",
    "Down/Up Ratio": "down/up ratio", "Pkt Size Avg": "average packet size",
    "Fwd Seg Size Avg": "avg fwd segment size", "Bwd Seg Size Avg": "avg bwd segment size",
    "Fwd Byts/b Avg": "fwd avg bytes/bulk", "Fwd Pkts/b Avg": "fwd avg packets/bulk", "Fwd Blk Rate Avg": "fwd avg bulk rate",
    "Bwd Byts/b Avg": "bwd avg bytes/bulk", "Bwd Pkts/b Avg": "bwd avg packets/bulk", "Bwd Blk Rate Avg": "bwd avg bulk rate",
    "Subflow Fwd Pkts": "subflow fwd packets", "Subflow Fwd Byts": "subflow fwd bytes",
    "Subflow Bwd Pkts": "subflow bwd packets", "Subflow Bwd Byts": "subflow bwd bytes",
    "Init Fwd Win Byts": "init_win_bytes_forward", "Init Bwd Win Byts": "init_win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "active mean", "Active Std": "active std", "Active Max": "active max", "Active Min": "active min",
    "Idle Mean": "idle mean", "Idle Std": "idle std", "Idle Max": "idle max", "Idle Min": "idle min",
}

TEXT_COLUMNS = {"Flow ID", "source ip", "destination ip", "Timestamp", "Label", "source_file"}

# What each lab file really contains, from the flows inside it. "kind" says how to score it:
# known    a class the Random Forest was trained on
# unseen   a real attack with no matching training class, so only detection can be scored
# benign   normal traffic
LAB_FILES = {
    "infilteration": dict(true_class="PortScan", kind="known",
                          note="SYN sweep of 65,536 ports, not an infiltration"),
    "PortScan": dict(true_class="PortScan", kind="known", note="Small scan of 40 ports"),
    "DoS-GoldenEye-2nd": dict(true_class="DoS GoldenEye", kind="known", note=""),
    "DoS-Slowloris": dict(true_class="DoS slowloris", kind="known", note=""),
    "ddos_hping3": dict(true_class="SYN flood", kind="unseen",
                        note="One source sending bare SYN packets; training DDoS is an HTTP flood"),
    "Bot": dict(true_class="Bot", kind="known", note="Too few flows to score alone"),
    "FTP_Patator": dict(true_class="FTP-Patator", kind="known", note="Too few flows to score alone"),
    "heartbleed_lab": dict(true_class="Heartbleed", kind="known", note="Too few flows to score alone"),
    "Benign": dict(true_class="BENIGN", kind="benign", note=""),
    "Benign-P1": dict(true_class="BENIGN", kind="benign", note=""),
    "Benign-Scenarios": dict(true_class="BENIGN", kind="benign", note=""),
    "SMB": dict(true_class="BENIGN", kind="benign", note=""),
    "email_traffic": dict(true_class="BENIGN", kind="benign", note="All flows are loopback"),
}

SERVICE_PORTS_ATTACKED = {"DoS-GoldenEye-2nd": 80, "DoS-Slowloris": 80}

FIRST_PACKET_EXACT = [
    "total fwd packets", "total backward packets", "subflow fwd packets", "subflow bwd packets",
    "total length of fwd packets", "total length of bwd packets", "subflow fwd bytes", "subflow bwd bytes",
    "fwd packet length mean", "fwd packet length std", "avg fwd segment size", "fwd packet length max",
    "fwd packet length min", "bwd packet length mean", "bwd packet length std", "avg bwd segment size",
    "fwd packets/s", "bwd packets/s", "down/up ratio", "fwd psh flags", "fwd urg flags", "bwd psh flags",
    "bwd urg flags",
]
FIRST_PACKET_ESTIMATED = [
    "init_win_bytes_forward", "min_seg_size_forward", "fwd header length", "bwd header length",
    "bwd packet length max", "bwd packet length min", "fwd iat total", "fwd iat mean", "fwd iat std", "fwd iat max",
    "fwd iat min", "bwd iat total", "bwd iat mean", "bwd iat std", "bwd iat max", "bwd iat min",
]


def load_lab_csvs(pattern: str) -> pd.DataFrame:
    """Load lab CSVs, using training column names and numeric types."""
    frames = []
    for path in sorted(glob.glob(pattern)):
        frame = pd.read_csv(path, low_memory=False, encoding="latin-1")
        frame.columns = frame.columns.str.strip()
        name = os.path.basename(path)
        for suffix in (".pcap_Flow.csv", "_labeled.csv", ".csv"):
            name = name.replace(suffix, "")
        frame["source_file"] = name.replace(".pcap_Flow", "").replace("_labeled", "")
        frames.append(frame)
    if not frames:
        raise FileNotFoundError(f"No CSV files match {pattern}")
    flows = pd.concat(frames, ignore_index=True).rename(columns=CSV_TO_TRAINING_NAMES)
    for column in flows.columns:
        if column not in TEXT_COLUMNS:
            flows[column] = pd.to_numeric(flows[column], errors="coerce")
    flows = flows[flows["flow duration"].notna()].reset_index(drop=True)
    flows["fwd header length.1"] = flows["fwd header length"]
    return flows


def remap_flags(flows: pd.DataFrame) -> pd.DataFrame:
    """Move flag values from their real names to the columns training stored them in. Exact."""
    remapped = flows.copy()
    real_flag = {flag: flows[column] for column, flag in NAMED_FLAG_COLUMNS.items()}
    for column, flag in TRAINING_FLAG_COLUMNS.items():
        remapped[column] = real_flag[flag]
    return remapped


def _add_sample(count, mean, std, value):
    """Return mean and sample std after adding one value."""
    new_count = count + 1
    new_mean = (count * mean + value) / new_count
    m2 = np.where(count > 1, std ** 2 * (count - 1), 0.0)
    m2 = m2 + (value - mean) * (value - new_mean) * (count > 0)
    new_std = np.sqrt(np.where(new_count > 1, np.maximum(m2, 0) / np.maximum(new_count - 1, 1), 0.0))
    return new_mean, new_std


def _remove_sample(count, mean, std, value):
    """Return mean and sample std after removing one value."""
    new_count = np.maximum(count - 1, 0)
    safe = np.maximum(new_count, 1)
    new_mean = np.where(new_count > 0, (count * mean - value) / safe, 0.0)
    m2 = np.where(count > 1, std ** 2 * (count - 1), 0.0) - (value - mean) * (value - new_mean)
    new_std = np.sqrt(np.where(new_count > 1, np.maximum(m2, 0) / np.maximum(new_count - 1, 1), 0.0))
    return new_mean, new_std


def repair_first_packet(flows: pd.DataFrame, assumed_init_window: float = 29200.0) -> pd.DataFrame:
    """Undo the first-packet defect on a table of flows from the defective tool.

    Run this before remap_flags. It reads first-packet flags by their real names.
    assumed_init_window fills init_win_bytes_forward on TCP flows, because that value
    is not stored anywhere in the defective output.
    """
    r = flows.copy()
    f = flows["total fwd packets"].to_numpy(dtype=float)
    b = flows["total backward packets"].to_numpy(dtype=float)
    fwd_total = flows["total length of fwd packets"].to_numpy(dtype=float)
    bwd_total = flows["total length of bwd packets"].to_numpy(dtype=float)
    average = flows["average packet size"].to_numpy(dtype=float)
    duration = flows["flow duration"].to_numpy(dtype=float)
    is_tcp = flows["protocol"].to_numpy() == 6
    first_syn = flows["syn flag count"].to_numpy(dtype=float) > 0

    # "average packet size" counts the first packet twice, which reveals its size.
    first_size = np.clip(np.round(average * (f + b) - fwd_total - bwd_total), 0, None)
    first_size = np.where(np.isfinite(first_size), first_size, 0.0)
    first_size = np.minimum(first_size, bwd_total)

    new_f, new_b = f + 1, np.maximum(b - 1, 0)
    new_fwd_total, new_bwd_total = fwd_total + first_size, bwd_total - first_size
    r["total fwd packets"] = new_f
    r["total backward packets"] = new_b
    r["subflow fwd packets"] = new_f
    r["subflow bwd packets"] = new_b
    r["total length of fwd packets"] = new_fwd_total
    r["total length of bwd packets"] = new_bwd_total
    r["subflow fwd bytes"] = new_fwd_total
    r["subflow bwd bytes"] = new_bwd_total

    fwd_mean, fwd_std = _add_sample(
        f, flows["fwd packet length mean"].to_numpy(dtype=float), flows["fwd packet length std"].to_numpy(dtype=float),
        first_size,
    )
    r["fwd packet length mean"] = fwd_mean
    r["avg fwd segment size"] = fwd_mean
    r["fwd packet length std"] = fwd_std
    old_fwd_max = flows["fwd packet length max"].to_numpy(dtype=float)
    old_fwd_min = flows["fwd packet length min"].to_numpy(dtype=float)
    r["fwd packet length max"] = np.where(f > 0, np.maximum(old_fwd_max, first_size), first_size)
    r["fwd packet length min"] = np.where(f > 0, np.minimum(old_fwd_min, first_size), first_size)

    bwd_mean, bwd_std = _remove_sample(
        b, flows["bwd packet length mean"].to_numpy(dtype=float), flows["bwd packet length std"].to_numpy(dtype=float),
        first_size,
    )
    r["bwd packet length mean"] = bwd_mean
    r["avg bwd segment size"] = bwd_mean
    r["bwd packet length std"] = bwd_std
    old_bwd_max = flows["bwd packet length max"].to_numpy(dtype=float)
    old_bwd_min = flows["bwd packet length min"].to_numpy(dtype=float)
    r["bwd packet length max"] = np.where(new_b == 0, 0.0, np.where(new_b == 1, bwd_mean, old_bwd_max))
    r["bwd packet length min"] = np.where(new_b == 0, 0.0, np.where(new_b == 1, bwd_mean, old_bwd_min))

    seconds = np.where(duration > 0, duration / 1e6, np.nan)
    r["fwd packets/s"] = np.nan_to_num(new_f / seconds)
    r["bwd packets/s"] = np.nan_to_num(new_b / seconds)
    r["down/up ratio"] = np.floor(new_b / new_f)

    # Header sizes: a SYN probe answered once splits exactly, others are estimated.
    fwd_header = flows["fwd header length"].to_numpy(dtype=float)
    bwd_header = flows["bwd header length"].to_numpy(dtype=float)
    later_forward = np.where(f > 0, fwd_header / np.maximum(f, 1), np.nan)
    first_header = np.where(first_syn, later_forward + 8, later_forward)
    probe = (f == 0) & (b == 2)
    first_header = np.where(probe, np.clip(bwd_header - 20, 20, 60), first_header)
    first_header = np.where(np.isnan(first_header), np.where(first_syn, 40.0, 32.0), first_header)
    # UDP header columns in training hold leftover TCP values, usually 20 or 32 per packet.
    first_header = np.where(is_tcp, first_header, 20.0)
    new_fwd_header = np.where(is_tcp, fwd_header + first_header, 20.0 * new_f)
    new_bwd_header = np.where(is_tcp, np.maximum(bwd_header - first_header, 0), 20.0 * new_b)
    r["fwd header length"] = new_fwd_header
    r["fwd header length.1"] = new_fwd_header
    r["bwd header length"] = new_bwd_header
    r["min_seg_size_forward"] = np.where(f > 0, np.minimum(first_header, later_forward), first_header)

    r["init_win_bytes_forward"] = np.where(is_tcp, assumed_init_window, -1.0)
    r["init_win_bytes_backward"] = np.where(new_b == 0, -1.0, flows["init_win_bytes_backward"].to_numpy(dtype=float))

    # First-packet PSH and URG never reached the forward counters. All packets' flag
    # columns describe only the first packet, so these are exact.
    r["fwd psh flags"] = flows["psh flag count"]
    r["fwd urg flags"] = flows["urg flag count"]
    r["bwd psh flags"] = 0
    r["bwd urg flags"] = 0

    # Gap from the first packet to the first later forward packet isn't stored, so the
    # flow's average gap stands in for it.
    gap = np.nan_to_num(flows["flow iat mean"].to_numpy(dtype=float), posinf=0.0, neginf=0.0)
    fwd_iat_count = np.maximum(f - 1, 0)
    fwd_iat_total = flows["fwd iat total"].to_numpy(dtype=float)
    new_iat_total = np.where(f > 0, fwd_iat_total + gap, 0.0)
    iat_mean, iat_std = _add_sample(
        fwd_iat_count, flows["fwd iat mean"].to_numpy(dtype=float), flows["fwd iat std"].to_numpy(dtype=float), gap,
    )
    r["fwd iat total"] = new_iat_total
    r["fwd iat mean"] = np.where(f > 0, iat_mean, 0.0)
    r["fwd iat std"] = np.where(f > 0, iat_std, 0.0)
    r["fwd iat max"] = np.where(f > 0, np.maximum(flows["fwd iat max"].to_numpy(dtype=float), gap), 0.0)
    old_min = flows["fwd iat min"].to_numpy(dtype=float)
    r["fwd iat min"] = np.where(f > 1, np.minimum(old_min, gap), np.where(f > 0, gap, 0.0))

    # With the first packet gone, one backward gap also disappears.
    bwd_gaps_left = np.maximum(b - 2, 0)
    old_bwd_mean = flows["bwd iat mean"].to_numpy(dtype=float)
    r["bwd iat total"] = old_bwd_mean * bwd_gaps_left
    for column in ("bwd iat mean", "bwd iat std", "bwd iat max", "bwd iat min"):
        r[column] = np.where(bwd_gaps_left > 0, flows[column].to_numpy(dtype=float), 0.0)
    return r


def add_true_labels(flows: pd.DataFrame) -> pd.DataFrame:
    """Add true_class, kind and scored columns based on what each file really contains.

    Flows that shouldn't count as attack evidence are marked scored=False: stray flows
    between other hosts, flows from the victim's service port, and non-IP artefacts.
    """
    labelled = flows.copy()
    info = labelled["source_file"].map(LAB_FILES)
    labelled["true_class"] = info.map(lambda item: item["true_class"] if isinstance(item, dict) else "unknown")
    labelled["kind"] = info.map(lambda item: item["kind"] if isinstance(item, dict) else "unknown")
    scored = labelled["protocol"].isin([6, 17]).to_numpy().copy()

    attack_rows = labelled["kind"].isin(["known", "unseen"])
    for name, group in labelled[attack_rows].groupby("source_file"):
        pair = (group["source ip"].astype(str) + ">" + group["destination ip"].astype(str)).value_counts().index[0]
        main = (labelled["source ip"].astype(str) + ">" + labelled["destination ip"].astype(str)) == pair
        if len(group) > 100:
            reverse = (labelled["destination ip"].astype(str) + ">" + labelled["source ip"].astype(str)) == pair
            scored &= ~((labelled["source_file"] == name) & ~(main | reverse)).to_numpy()
    for name, port in SERVICE_PORTS_ATTACKED.items():
        scored &= ~((labelled["source_file"] == name) & (labelled["source port"] == port)).to_numpy()
    labelled["scored"] = scored
    return labelled
