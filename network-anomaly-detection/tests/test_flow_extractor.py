import struct

import pytest

from check_extractor import check, flag_layout, normalize_columns
from src.flow_extractor import extract_flows


def by_port(flows, port):
    return flows[flows["destination port"] == port].iloc[0]


def test_training_profile_matches_every_known_answer(known_answer):
    pcap, answers = known_answer
    flows = normalize_columns(extract_flows(pcap, "training"))
    results = check(flows.rename(columns=str), answers)
    failed = [r for r in results if not r["ok"]]
    assert not failed, failed


def test_defect_profile_fails_the_known_answer_check(known_answer):
    pcap, answers = known_answer
    flows = normalize_columns(extract_flows(pcap, "v4_2018"))
    checks = {r["check"] for r in check(flows, answers) if not r["ok"]}
    assert {"tot_fwd_pkts", "tot_bwd_pkts", "init_win_fwd", "fwd_seg_size_min"} <= checks


def test_defect_profile_reproduces_the_lab_signature(known_answer):
    pcap, _ = known_answer
    probe = by_port(extract_flows(pcap, "v4_2018"), 22)
    # 65,737 lab flows show this exact pattern: 0 forward, 2 backward, 44 header bytes.
    assert (probe["total fwd packets"], probe["total backward packets"]) == (0, 2)
    assert probe["bwd header length"] == 44
    assert probe["init_win_bytes_forward"] == -1
    assert probe["min_seg_size_forward"] == 0


def test_flag_layouts_differ_by_profile(known_answer):
    pcap, answers = known_answer
    training = by_port(extract_flows(pcap, "training"), 22)
    named = by_port(extract_flows(pcap, "v4_2018"), 22)
    assert (training["psh flag count"], training["syn flag count"]) == (1, 0)
    assert (named["psh flag count"], named["syn flag count"]) == (0, 1)
    assert flag_layout(normalize_columns(extract_flows(pcap, "training")), answers).startswith("training")
    assert flag_layout(normalize_columns(extract_flows(pcap, "v4_2018")), answers).startswith("named")


def test_flow_with_client_ip_above_server_ip_keeps_client_as_source(known_answer):
    pcap, _ = known_answer
    flow = by_port(extract_flows(pcap, "training"), 443)
    assert flow["source ip"] == "10.0.0.9"
    assert flow["total fwd packets"] == 4


def test_times_are_microseconds_and_rates_per_second(known_answer):
    pcap, _ = known_answer
    flow = by_port(extract_flows(pcap, "training"), 80)
    assert flow["flow duration"] == 17_000
    assert flow["flow packets/s"] == pytest.approx(7 / 0.017)


def test_first_packet_counts_twice_in_flow_size_statistics(known_answer):
    pcap, _ = known_answer
    flow = by_port(extract_flows(pcap, "training"), 53)
    # Sizes are 40 and 120. The first is counted twice, so (40 + 40 + 120) / 2 packets.
    assert flow["average packet size"] == pytest.approx(100.0)


def test_pcapng_gives_the_same_flows_as_classic_pcap(known_answer, tmp_path):
    pcap, _ = known_answer
    raw = pcap.read_bytes()
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    blocks = [section, interface]
    position = 24
    while position < len(raw):
        seconds, micros, captured, original = struct.unpack_from("<IIII", raw, position)
        frame = raw[position + 16:position + 16 + captured]
        position += 16 + captured
        ticks = seconds * 1_000_000 + micros
        padded = frame + b"\x00" * (-len(frame) % 4)
        length = 32 + len(padded)
        blocks.append(
            struct.pack("<IIIIIII", 6, length, 0, ticks >> 32, ticks & 0xFFFFFFFF, captured, original)
            + padded + struct.pack("<I", length)
        )
    converted = tmp_path / "known_answer.pcapng"
    converted.write_bytes(b"".join(blocks))

    classic = extract_flows(pcap).sort_values("destination port").reset_index(drop=True)
    pcapng = extract_flows(converted).sort_values("destination port").reset_index(drop=True)
    assert classic.equals(pcapng)


def test_rejects_files_that_are_not_captures(tmp_path):
    path = tmp_path / "notes.pcap"
    path.write_bytes(b"this is not a capture file at all")
    with pytest.raises(ValueError, match="not a pcap"):
        extract_flows(path)
