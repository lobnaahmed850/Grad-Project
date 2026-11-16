"""Turn a pcap into CICFlowMeter-style flow features, with no Java dependency.

This reimplements the flow logic of CICFlowMeter (MIT licence,
https://github.com/ahlashkari/CICFlowMeter). Versions of that tool differ in ways
that change the features' meaning, so each behaviour is a named switch:

    training     Matches the published CICIDS2017 CSVs, which the models learned from.
    v4_2018      Matches builds from 2018-06-04 to 2019-10-14, whose output the lab
                 CSVs match. Use it only to study the defect, never for inference.

Features are returned under the training column names.
"""
from __future__ import annotations

import argparse
import math
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pandas as pd

ETHERNET = 1
LINUX_SLL = 113
RAW_IP = 101

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

# Which real TCP flag each training column holds. The 2017 tool wrote flag counts in
# Java HashMap order, not header order, so most of these names don't match their contents.
TRAINING_FLAG_COLUMNS = {
    "fin flag count": RST,
    "syn flag count": PSH,
    "rst flag count": ECE,
    "psh flag count": SYN,
    "ack flag count": ACK,
    "urg flag count": FIN,
    "cwe flag count": URG,
    "ece flag count": CWR,
}
NAMED_FLAG_COLUMNS = {
    "fin flag count": FIN,
    "syn flag count": SYN,
    "rst flag count": RST,
    "psh flag count": PSH,
    "ack flag count": ACK,
    "urg flag count": URG,
    "cwe flag count": CWR,
    "ece flag count": ECE,
}


@dataclass(frozen=True)
class Profile:
    """The behaviours that differ between CICFlowMeter versions."""

    name: str
    first_packet_is_forward: bool
    flag_columns: dict[str, int]
    # The 2017 tool read UDP header length from a reused TCP object, so UDP rows hold
    # the header length of the previous TCP packet. Later builds report 8 bytes.
    udp_header_from_last_tcp: bool


PROFILES = {
    "training": Profile("training", True, TRAINING_FLAG_COLUMNS, True),
    "v4_2018": Profile("v4_2018", False, NAMED_FLAG_COLUMNS, False),
}

FLOW_TIMEOUT_US = 120_000_000
ACTIVITY_TIMEOUT_US = 5_000_000


class Stat:
    """Running statistics that behave like Apache Commons SummaryStatistics."""

    __slots__ = ("n", "total", "low", "high", "mean_", "m2")

    def __init__(self):
        self.n = 0
        self.total = 0.0
        self.low = math.inf
        self.high = -math.inf
        self.mean_ = 0.0
        self.m2 = 0.0

    def add(self, value: float) -> None:
        self.n += 1
        self.total += value
        if value < self.low:
            self.low = value
        if value > self.high:
            self.high = value
        delta = value - self.mean_
        self.mean_ += delta / self.n
        self.m2 += delta * (value - self.mean_)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else (0.0 if self.n == 1 else math.nan)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance) if self.n > 1 else (0.0 if self.n == 1 else math.nan)

    def values(self) -> tuple[float, float, float, float]:
        """Return (max, min, mean, std), all zero when nothing was added."""
        if self.n == 0:
            return 0.0, 0.0, 0.0, 0.0
        return self.high, self.low, self.mean_, self.std


class Flow:
    __slots__ = (
        "src", "dst", "sport", "dport", "proto", "start", "last", "fwd_last", "bwd_last",
        "fwd", "bwd", "length", "iat", "fwd_iat", "bwd_iat", "active", "idle",
        "fwd_header", "bwd_header", "init_win_fwd", "init_win_bwd", "min_seg", "act_data",
        "fwd_psh", "fwd_urg", "bwd_psh", "bwd_urg", "first_flags", "active_start", "active_end",
    )

    def __init__(self, ts, src, sport, dst, dport, proto, length, header, window, flags, first_is_forward):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.start = self.last = self.active_start = self.active_end = ts
        self.fwd_last = self.bwd_last = 0
        self.fwd, self.bwd, self.length = Stat(), Stat(), Stat()
        self.iat, self.fwd_iat, self.bwd_iat, self.active, self.idle = Stat(), Stat(), Stat(), Stat(), Stat()
        self.fwd_header = self.bwd_header = 0
        self.init_win_fwd = self.init_win_bwd = -1
        self.min_seg = self.act_data = 0
        self.fwd_psh = self.fwd_urg = self.bwd_psh = self.bwd_urg = 0
        self.first_flags = flags

        # The tool records the first packet's size twice in this statistic.
        self.length.add(length)
        self.length.add(length)
        if first_is_forward:
            self.min_seg = header
            self.init_win_fwd = window
            self.fwd.add(length)
            self.fwd_header = header
            self.fwd_last = ts
            self.fwd_psh = 1 if flags & PSH else 0
            self.fwd_urg = 1 if flags & URG else 0
        else:
            self.init_win_bwd = window
            self.bwd.add(length)
            self.bwd_header = header
            self.bwd_last = ts
            self.bwd_psh = 1 if flags & PSH else 0
            self.bwd_urg = 1 if flags & URG else 0

    def add(self, ts, from_source, length, header, window):
        self.length.add(length)
        if from_source:
            if length >= 1:
                self.act_data += 1
            self.fwd.add(length)
            self.fwd_header += header
            if self.fwd.n > 1:
                self.fwd_iat.add(ts - self.fwd_last)
            self.fwd_last = ts
            self.min_seg = min(header, self.min_seg)
        else:
            self.bwd.add(length)
            self.init_win_bwd = window
            self.bwd_header += header
            if self.bwd.n > 1:
                self.bwd_iat.add(ts - self.bwd_last)
            self.bwd_last = ts
        self.iat.add(ts - self.last)
        self.last = ts

    def update_active_idle(self, ts):
        if ts - self.active_end > ACTIVITY_TIMEOUT_US:
            if self.active_end > self.active_start:
                self.active.add(self.active_end - self.active_start)
            self.idle.add(ts - self.active_end)
            self.active_start = ts
        self.active_end = ts

    def to_row(self, profile: Profile) -> dict:
        fwd_max, fwd_min, fwd_mean, fwd_std = self.fwd.values()
        bwd_max, bwd_min, bwd_mean, bwd_std = self.bwd.values()
        active_mean, active_std, active_max, active_min = _mean_first(self.active)
        idle_mean, idle_std, idle_max, idle_min = _mean_first(self.idle)
        duration = self.last - self.start
        seconds = duration / 1_000_000
        packets = self.fwd.n + self.bwd.n
        data = self.fwd.total + self.bwd.total
        row = {
            "source ip": socket.inet_ntoa(self.src),
            "source port": self.sport,
            "destination ip": socket.inet_ntoa(self.dst),
            "destination port": self.dport,
            "protocol": self.proto,
            "flow start us": self.start,
            "flow duration": duration,
            "total fwd packets": self.fwd.n,
            "total backward packets": self.bwd.n,
            "total length of fwd packets": self.fwd.total,
            "total length of bwd packets": self.bwd.total,
            "fwd packet length max": fwd_max,
            "fwd packet length min": fwd_min,
            "fwd packet length mean": fwd_mean,
            "fwd packet length std": fwd_std,
            "bwd packet length max": bwd_max,
            "bwd packet length min": bwd_min,
            "bwd packet length mean": bwd_mean,
            "bwd packet length std": bwd_std,
            "flow bytes/s": _rate(data, seconds),
            "flow packets/s": _rate(packets, seconds),
            "flow iat mean": _or_nan(self.iat, self.iat.mean_),
            "flow iat std": self.iat.std,
            "flow iat max": _or_nan(self.iat, self.iat.high),
            "flow iat min": _or_nan(self.iat, self.iat.low),
            "fwd iat total": self.fwd_iat.total if self.fwd.n > 1 else 0.0,
            "fwd iat mean": self.fwd_iat.mean_ if self.fwd.n > 1 else 0.0,
            "fwd iat std": self.fwd_iat.std if self.fwd.n > 1 else 0.0,
            "fwd iat max": self.fwd_iat.high if self.fwd.n > 1 else 0.0,
            "fwd iat min": self.fwd_iat.low if self.fwd.n > 1 else 0.0,
            "bwd iat total": self.bwd_iat.total if self.bwd.n > 1 else 0.0,
            "bwd iat mean": self.bwd_iat.mean_ if self.bwd.n > 1 else 0.0,
            "bwd iat std": self.bwd_iat.std if self.bwd.n > 1 else 0.0,
            "bwd iat max": self.bwd_iat.high if self.bwd.n > 1 else 0.0,
            "bwd iat min": self.bwd_iat.low if self.bwd.n > 1 else 0.0,
            "fwd psh flags": self.fwd_psh,
            "bwd psh flags": self.bwd_psh,
            "fwd urg flags": self.fwd_urg,
            "bwd urg flags": self.bwd_urg,
            "fwd header length": self.fwd_header,
            "bwd header length": self.bwd_header,
            "fwd packets/s": self.fwd.n / seconds if duration > 0 else 0.0,
            "bwd packets/s": self.bwd.n / seconds if duration > 0 else 0.0,
            "min packet length": self.length.low,
            "max packet length": self.length.high,
            "packet length mean": self.length.mean_,
            "packet length std": self.length.std,
            "packet length variance": self.length.variance,
            "down/up ratio": self.bwd.n // self.fwd.n if self.fwd.n else 0,
            "average packet size": self.length.total / packets if packets else 0.0,
            "avg fwd segment size": self.fwd.total / self.fwd.n if self.fwd.n else 0.0,
            "avg bwd segment size": self.bwd.total / self.bwd.n if self.bwd.n else 0.0,
            "fwd header length.1": self.fwd_header,
            "fwd avg bytes/bulk": 0,
            "fwd avg packets/bulk": 0,
            "fwd avg bulk rate": 0,
            "bwd avg bytes/bulk": 0,
            "bwd avg packets/bulk": 0,
            "bwd avg bulk rate": 0,
            "subflow fwd packets": self.fwd.n,
            "subflow fwd bytes": self.fwd.total,
            "subflow bwd packets": self.bwd.n,
            "subflow bwd bytes": self.bwd.total,
            "init_win_bytes_forward": self.init_win_fwd,
            "init_win_bytes_backward": self.init_win_bwd,
            "act_data_pkt_fwd": self.act_data,
            "min_seg_size_forward": self.min_seg,
            "active mean": active_mean,
            "active std": active_std,
            "active max": active_max,
            "active min": active_min,
            "idle mean": idle_mean,
            "idle std": idle_std,
            "idle max": idle_max,
            "idle min": idle_min,
        }
        for column, flag in profile.flag_columns.items():
            row[column] = 1 if self.first_flags & flag else 0
        return row


def _mean_first(stat: Stat) -> tuple[float, float, float, float]:
    if stat.n == 0:
        return 0.0, 0.0, 0.0, 0.0
    return stat.mean_, stat.std, stat.high, stat.low


def _or_nan(stat: Stat, value: float) -> float:
    return value if stat.n else math.nan


def _rate(amount: float, seconds: float) -> float:
    if seconds > 0:
        return amount / seconds
    return math.nan if amount == 0 else math.inf


def _classic_frames(stream, magic: bytes) -> Iterator[tuple]:
    """Yield (timestamp_us, frame, original_length, link_type) from a classic pcap."""
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1), b"\xa1\xb2\xc3\xd4": (">", 1),
        b"\x4d\x3c\xb2\xa1": ("<", 1000), b"\xa1\xb2\x3c\x4d": (">", 1000),
    }
    endian, divisor = formats[magic]
    header = stream.read(20)
    if len(header) != 20:
        raise ValueError("Truncated pcap header")
    link_type = struct.unpack(endian + "I", header[16:20])[0]
    record = struct.Struct(endian + "IIII")
    while True:
        raw = stream.read(record.size)
        if not raw:
            return
        if len(raw) < record.size:
            raise ValueError("Truncated pcap record header")
        seconds, fraction, captured, original = record.unpack(raw)
        if captured > 1048576 or original < captured:
            raise ValueError("Invalid or oversized pcap record")
        frame = stream.read(captured)
        if len(frame) < captured:
            raise ValueError("Truncated pcap frame")
        yield seconds * 1_000_000 + fraction // divisor, frame, original, link_type


def _tsresol_ticks_per_us(options: bytes, endian: str) -> float:
    """Read if_tsresol from an interface block. The pcapng default is microseconds."""
    position = 0
    while position + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, position)
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[position + 4]
            ticks_per_second = 2 ** (value & 0x7F) if value & 0x80 else 10 ** value
            return ticks_per_second / 1_000_000
        position += 4 + length + (-length % 4)
    return 1.0


def _pcapng_frames(stream) -> Iterator[tuple]:
    """Yield (timestamp_us, frame, original_length, link_type) from a pcapng file."""
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    while True:
        head = stream.read(8)
        if not head:
            return
        if len(head) < 8:
            raise ValueError("Truncated pcapng block")
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            order = stream.read(4)
            if order not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise ValueError("Invalid pcapng byte order")
            endian = "<" if order == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", head[4:8])[0]
            if length < 28 or length > 16777216 or length % 4:
                raise ValueError("Invalid pcapng section size")
            if len(stream.read(length - 12)) != length - 12:
                raise ValueError("Truncated pcapng section")
            interfaces = []
            continue
        block_type, length = struct.unpack(endian + "II", head)
        if length < 12 or length > 16777216 or length % 4:
            raise ValueError("Invalid pcapng block size")
        body = stream.read(length - 8)
        if len(body) < length - 8:
            raise ValueError("Truncated pcapng block body")
        if struct.unpack_from(endian + "I", body, len(body) - 4)[0] != length:
            raise ValueError("Inconsistent pcapng block size")
        if block_type == 1:
            if len(body) < 12:
                raise ValueError("Truncated pcapng interface")
            link_type = struct.unpack_from(endian + "H", body)[0]
            interfaces.append((link_type, _tsresol_ticks_per_us(body[8:-4], endian)))
        elif block_type == 6:
            if len(body) < 24:
                raise ValueError("Truncated pcapng enhanced packet")
            interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(interfaces) or captured > len(body) - 24 or original < captured:
                raise ValueError("Invalid pcapng packet/interface")
            link_type, ticks_per_us = interfaces[interface]
            ticks = (high << 32) | low
            timestamp = ticks if ticks_per_us == 1.0 else int(ticks / ticks_per_us)
            yield timestamp, body[20:20 + captured], original, link_type


def read_packets(path: Path) -> Iterator[tuple]:
    """Yield (ts_us, src, sport, dst, dport, proto, payload, header, window, flags).

    Reads classic pcap and pcapng. Only IPv4 TCP and UDP packets are returned, as in
    the original tool.
    """
    with open(path, "rb") as stream:
        magic = stream.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            stream.seek(0)
            frames = _pcapng_frames(stream)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            frames = _classic_frames(stream, magic)
        else:
            raise ValueError(f"{path} is not a pcap or pcapng file")

        for timestamp, frame, original, link_type in frames:
            packet = decode_frame(timestamp, frame, original, link_type)
            if packet is not None:
                yield packet


def decode_frame(timestamp, frame, original=None, link_type=ETHERNET):
    """Decode one captured IPv4 TCP/UDP frame; reject fragments and malformed headers."""
    captured = len(frame)
    original = captured if original is None else original
    if link_type == ETHERNET:
        if captured < 14:
            return None
        offset = 14
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        while ether_type in (0x8100, 0x88A8) and captured >= offset + 4:
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ether_type != 0x0800:
            return None
    elif link_type == LINUX_SLL:
        offset = 16
        if captured < 16 or struct.unpack_from("!H", frame, 14)[0] != 0x0800:
            return None
    elif link_type == RAW_IP:
        offset = 0
    else:
        raise ValueError(f"unsupported link type {link_type}")
    if captured < offset + 20 or frame[offset] >> 4 != 4:
        return None
    ip_header_len = (frame[offset] & 0x0F) * 4
    total_length = struct.unpack_from("!H", frame, offset + 2)[0]
    fragments = struct.unpack_from("!H", frame, offset + 6)[0]
    if ip_header_len < 20 or total_length < ip_header_len or fragments & 0x3FFF:
        return None
    if captured < offset + total_length:
        return None
    proto = frame[offset + 9]
    transport = offset + ip_header_len
    src, dst = frame[offset + 12:offset + 16], frame[offset + 16:offset + 20]
    if proto == 6:
        if captured < transport + 20 or total_length < ip_header_len + 20:
            return None
        header = (frame[transport + 12] >> 4) * 4
        if header < 20 or transport + header > offset + total_length:
            return None
        sport, dport = struct.unpack_from("!HH", frame, transport)
        window = struct.unpack_from("!H", frame, transport + 14)[0]
        return timestamp, src, sport, dst, dport, 6, max(0, original - transport - header), header, window, frame[transport + 13]
    if proto == 17:
        if captured < transport + 8 or total_length < ip_header_len + 8:
            return None
        udp_length = struct.unpack_from("!H", frame, transport + 4)[0]
        if udp_length < 8 or udp_length > total_length - ip_header_len:
            return None
        sport, dport = struct.unpack_from("!HH", frame, transport)
        return timestamp, src, sport, dst, dport, 17, max(0, original - transport - 8), 8, -1, 0
    return None


def extract_flows(pcap: Path | str, profile: str = "training") -> pd.DataFrame:
    """Return one row per flow with at least two packets, as the original tool does."""
    config = PROFILES[profile]
    first_is_forward = config.first_packet_is_forward
    stale_udp_header = config.udp_header_from_last_tcp
    last_tcp_header = 20
    current: dict[tuple, Flow] = {}
    finished: list[Flow] = []

    for ts, src, sport, dst, dport, proto, payload, header, window, flags in read_packets(Path(pcap)):
        if proto == 6:
            last_tcp_header = header
        elif stale_udp_header:
            header = last_tcp_header
        a, b = (src, sport), (dst, dport)
        key = (a, b, proto) if a <= b else (b, a, proto)
        flow = current.get(key)
        if flow is None:
            current[key] = Flow(ts, src, sport, dst, dport, proto, payload, header, window, flags, first_is_forward)
            continue
        if ts - flow.start > FLOW_TIMEOUT_US:
            if flow.fwd.n + flow.bwd.n > 1:
                finished.append(flow)
            replacement = Flow(ts, src, sport, dst, dport, proto, payload, header, window, flags, first_is_forward)
            # A flow that continues after a timeout keeps the original direction.
            replacement.src, replacement.dst = flow.src, flow.dst
            replacement.sport, replacement.dport = flow.sport, flow.dport
            current[key] = replacement
        elif flags & FIN:
            flow.add(ts, src == flow.src and sport == flow.sport, payload, header, window)
            finished.append(flow)
            del current[key]
        else:
            flow.update_active_idle(ts)
            flow.add(ts, src == flow.src and sport == flow.sport, payload, header, window)

    finished.extend(flow for flow in current.values() if flow.fwd.n + flow.bwd.n > 1)
    return pd.DataFrame.from_records(flow.to_row(config) for flow in finished)


def add_source_flow_rate(flows: pd.DataFrame, window_seconds: float = 1.0) -> pd.DataFrame:
    """Causal start-rate replay in event-time order; never consult later flow starts."""
    from src.streaming import SourceRate

    required = {"source ip", "flow start us"}
    if not required.issubset(flows.columns):
        raise ValueError(f"Causal source rate requires {sorted(required)}")
    out = flows.copy()
    counter = SourceRate(window_seconds=window_seconds)
    rates = [0.0] * len(out)
    order = sorted(range(len(out)), key=lambda position: out.iloc[position]["flow start us"])
    for position in order:
        row = out.iloc[position]
        rates[position] = counter.start(str(row["source ip"]), int(row["flow start us"]))
    out["source flow rate"] = rates
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="training")
    args = parser.parse_args()
    flows = extract_flows(args.pcap, args.profile)
    flows.to_csv(args.output_csv, index=False)
    print(f"{len(flows):,} flows written to {args.output_csv}")
