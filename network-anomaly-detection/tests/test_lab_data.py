import numpy as np
import pandas as pd
import pytest

from src.flow_extractor import TRAINING_FLAG_COLUMNS, extract_flows
from src.lab_data import FIRST_PACKET_EXACT, add_true_labels, remap_flags, repair_first_packet


@pytest.fixture(scope="module")
def flow_versions(known_answer):
    pcap, _ = known_answer
    order = ["destination port"]
    truth = extract_flows(pcap, "training").sort_values(order).reset_index(drop=True)
    defective = extract_flows(pcap, "v4_2018").sort_values(order).reset_index(drop=True)
    return truth, defective


def test_repair_recovers_exact_features(flow_versions):
    truth, defective = flow_versions
    repaired = repair_first_packet(defective)
    for column in FIRST_PACKET_EXACT:
        assert repaired[column].to_numpy(dtype=float) == pytest.approx(truth[column].to_numpy(dtype=float)), column


def test_syn_probe_header_split_is_exact(flow_versions):
    truth, defective = flow_versions
    repaired = repair_first_packet(defective)
    probe = truth["destination port"] == 22
    for column in ("fwd header length", "bwd header length", "min_seg_size_forward"):
        assert repaired.loc[probe, column].iloc[0] == truth.loc[probe, column].iloc[0], column


def test_remap_flags_moves_values_to_the_training_columns(flow_versions):
    truth, defective = flow_versions
    remapped = remap_flags(defective)
    for column in TRAINING_FLAG_COLUMNS:
        assert remapped[column].tolist() == truth[column].tolist(), column


def test_repair_handles_a_flow_of_two_backward_packets_with_payload():
    flow = pd.DataFrame([{
        "total fwd packets": 0, "total backward packets": 2,
        "total length of fwd packets": 0.0, "total length of bwd packets": 300.0,
        "average packet size": 200.0,  # (100 + 100 + 200) / 2 packets, so the first packet is 100 bytes
        "flow duration": 1000.0, "protocol": 6, "syn flag count": 0, "psh flag count": 1, "urg flag count": 0,
        "fwd packet length mean": 0.0, "fwd packet length std": 0.0, "fwd packet length max": 0.0,
        "fwd packet length min": 0.0, "bwd packet length mean": 150.0, "bwd packet length std": 70.71067811865476,
        "bwd packet length max": 200.0, "bwd packet length min": 100.0, "fwd header length": 0.0,
        "bwd header length": 64.0, "init_win_bytes_backward": 500, "flow iat mean": 1000.0,
        "fwd iat total": 0.0, "fwd iat mean": 0.0, "fwd iat std": 0.0, "fwd iat max": 0.0, "fwd iat min": 0.0,
        "bwd iat total": 1000.0, "bwd iat mean": 1000.0, "bwd iat std": 0.0, "bwd iat max": 1000.0, "bwd iat min": 1000.0,
    }])
    repaired = repair_first_packet(flow).iloc[0]
    assert repaired["total fwd packets"] == 1
    assert repaired["total backward packets"] == 1
    assert repaired["total length of fwd packets"] == 100
    assert repaired["total length of bwd packets"] == 200
    assert repaired["bwd packet length max"] == 200
    assert repaired["bwd packet length std"] == 0
    assert repaired["fwd psh flags"] == 1
    assert repaired["bwd iat total"] == 0


def test_repair_never_produces_undefined_values_from_zero_duration():
    flow = pd.DataFrame([{
        "total fwd packets": 0, "total backward packets": 2,
        "total length of fwd packets": 0.0, "total length of bwd packets": 0.0, "average packet size": 0.0,
        "flow duration": 0.0, "protocol": 6, "syn flag count": 1, "psh flag count": 0, "urg flag count": 0,
        "fwd packet length mean": 0.0, "fwd packet length std": 0.0, "fwd packet length max": 0.0,
        "fwd packet length min": 0.0, "bwd packet length mean": 0.0, "bwd packet length std": 0.0,
        "bwd packet length max": 0.0, "bwd packet length min": 0.0, "fwd header length": 0.0,
        "bwd header length": 44.0, "init_win_bytes_backward": 0, "flow iat mean": 0.0,
        "fwd iat total": 0.0, "fwd iat mean": 0.0, "fwd iat std": 0.0, "fwd iat max": 0.0, "fwd iat min": 0.0,
        "bwd iat total": 0.0, "bwd iat mean": 0.0, "bwd iat std": 0.0, "bwd iat max": 0.0, "bwd iat min": 0.0,
    }])
    repaired = repair_first_packet(flow).iloc[0]
    assert repaired["fwd packets/s"] == 0
    assert repaired["bwd packets/s"] == 0
    assert np.isfinite(repaired["down/up ratio"])


def lab_rows():
    def row(file, src, dst, sport, dport, protocol=6):
        return {"source_file": file, "source ip": src, "destination ip": dst, "source port": sport,
                "destination port": dport, "protocol": protocol}

    rows = [row("infilteration", "10.0.0.1", "10.0.0.2", 40000, port) for port in range(150)]
    rows.append(row("infilteration", "10.9.9.9", "10.8.8.8", 1234, 53, 17))
    rows += [row("DoS-Slowloris", "10.0.0.1", "10.0.0.2", 40000 + i, 80) for i in range(120)]
    rows.append(row("DoS-Slowloris", "10.0.0.2", "10.0.0.1", 80, 40000))
    rows.append(row("Benign-P1", "10.0.0.5", "10.0.0.6", 5000, 443))
    rows.append(row("Benign-P1", "8.6.0.1", "8.0.6.4", 0, 0, 0))
    return pd.DataFrame(rows)


def test_true_labels_describe_the_traffic_not_the_file_name():
    labelled = add_true_labels(lab_rows())
    sweep = labelled[labelled["source_file"] == "infilteration"]
    assert set(sweep["true_class"]) == {"PortScan"}


def test_scoring_excludes_stray_flows_reverse_flows_and_non_ip_rows():
    labelled = add_true_labels(lab_rows())
    assert not labelled[labelled["source ip"] == "10.9.9.9"]["scored"].any()
    reverse = (labelled["source_file"] == "DoS-Slowloris") & (labelled["source port"] == 80)
    assert not labelled[reverse]["scored"].any()
    assert not labelled[labelled["protocol"] == 0]["scored"].any()
    assert labelled[labelled["source ip"] == "10.0.0.5"]["scored"].all()
