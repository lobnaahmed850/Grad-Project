import socket
import struct

import numpy as np
import pandas as pd
import pytest

from known_answer_pcap import tcp_packet
from src.feature_contract import PORTABLE_WITH_TIMING
from src.flow_extractor import decode_frame, extract_flows, read_packets, add_source_flow_rate
from src.streaming import FlowConfig, SourceRate, StreamingFlows, replay_capture


def packet(timestamp, port=40000, flags=2, reverse=False):
    source, destination = "10.0.0.1", "10.0.0.2"
    if reverse:
        return decode_frame(timestamp, tcp_packet(destination, 80, source, port, flags, 1000, 20))
    return decode_frame(timestamp, tcp_packet(source, port, destination, 80, flags, 1000, 20))


def test_source_rate_is_causal_and_expires_idle_sources():
    counter = SourceRate(1)
    assert counter.start("a", 0) == 1
    assert counter.start("a", 100000) == 2
    assert counter.start("b", 200000) == 1
    assert counter.start("a", 1000000) == 2
    counter.expire(3000000)
    assert not counter.counts and not counter.events


def test_source_rate_rejects_out_of_order_and_bounds_state():
    counter = SourceRate(1, max_sources=2, max_events=3)
    for index in range(10):
        counter.start(str(index), index)
    assert len(counter.events) <= 3 and len(counter.counts) <= 2
    assert counter.evictions > 0
    with pytest.raises(ValueError, match="Out-of-order"):
        counter.start("x", 0)


def test_adding_future_flows_never_changes_past_rates():
    first = pd.DataFrame({"source ip": ["a"] * 3, "flow start us": [0, 100000, 200000]})
    extended = pd.concat([first, pd.DataFrame({"source ip": ["a"], "flow start us": [300000]})], ignore_index=True)
    assert add_source_flow_rate(first)["source flow rate"].tolist() == add_source_flow_rate(extended)["source flow rate"][:3].tolist()
    with pytest.raises(ValueError, match="requires"):
        add_source_flow_rate(pd.DataFrame({"destination port": [80]}))


def test_fin_requires_both_sides_and_reset_closes_immediately():
    engine = StreamingFlows()
    assert not engine.feed(packet(0))
    assert not engine.feed(packet(1000, flags=17))
    rows = engine.feed(packet(2000, flags=17, reverse=True))
    assert rows[0]["flow close reason"] == "fin"
    engine.feed(packet(3000))
    assert engine.feed(packet(4000, flags=20, reverse=True))[0]["flow close reason"] == "reset"


def test_idle_active_capacity_and_shutdown():
    engine = StreamingFlows(FlowConfig(idle_seconds=1, active_seconds=2, max_flows=1))
    engine.feed(packet(0))
    assert engine.feed(packet(10, port=40001))[0]["flow close reason"] == "capacity"
    assert engine.advance(1000010)[0]["flow close reason"] == "idle_timeout"
    engine.feed(packet(2000000))
    engine.feed(packet(2500000))
    engine.feed(packet(3000000))
    engine.feed(packet(3500000))
    assert engine.advance(4000000)[0]["flow close reason"] == "active_timeout"
    engine.feed(packet(5000000))
    assert engine.flush()[0]["flow close reason"] == "shutdown"
    assert engine.health()["active_flows"] == 0


def test_late_packets_counted_and_heap_bounded():
    engine = StreamingFlows(FlowConfig(max_flows=2))
    for timestamp in range(100):
        engine.feed(packet(timestamp))
    assert len(engine.expirations) <= 8
    engine.feed(packet(0))
    assert engine.health()["late_packets"] == 1


def test_live_and_offline_release_replay_are_identical(known_answer):
    path, _ = known_answer
    engine = StreamingFlows()
    rows = []
    for item in read_packets(path):
        rows.extend(engine.feed(item))
    rows.extend(engine.flush("capture_end"))
    pd.testing.assert_frame_equal(pd.DataFrame(rows), replay_capture(path))


def test_eligible_legacy_feature_values_match_release(known_answer):
    path, _ = known_answer
    legacy = extract_flows(path).set_index("destination port")
    live = replay_capture(path).set_index("destination port")
    columns = [name for name in PORTABLE_WITH_TIMING if name != "destination port"]
    for port in (80, 443, 22, 53):
        np.testing.assert_allclose(live.loc[port, columns].astype(float), legacy.loc[port, columns].astype(float),
                                   rtol=1e-9, atol=1e-6, equal_nan=True)


@pytest.mark.parametrize("raw", [b"", b"x" * 13, b"\x00" * 100, b"\xff" * 60])
def test_malformed_frames_do_not_crash(raw):
    assert decode_frame(1, raw) is None


def test_fragmented_and_truncated_packets_are_rejected():
    frame = bytearray(tcp_packet("10.0.0.1", 10, "10.0.0.2", 80, 2, 1000, 20))
    assert decode_frame(1, frame[:-1]) is None
    frame[20:22] = b"\x20\x00"
    assert decode_frame(1, frame) is None


@pytest.mark.parametrize("config", [{"idle_seconds": 0}, {"max_flows": -1}, {"rate_window_seconds": float("nan")}])
def test_invalid_config_rejected(config):
    with pytest.raises(ValueError):
        FlowConfig(**config)


@pytest.mark.parametrize("body", [
    b"\xd4\xc3\xb2\xa1",
    struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, 2000000, 2000000),
    b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 4, 0x1A2B3C4D),
])
def test_malformed_capture_records_fail_without_large_allocation(tmp_path, body):
    path = tmp_path / "malformed.pcap"
    path.write_bytes(body)
    with pytest.raises(ValueError):
        list(read_packets(path))
