"""Write a small pcap whose correct flow features are known in advance.

No traffic is sent anywhere: packets are built in memory and written to a file.
Run an extractor on the pcap, then compare its CSV with check_extractor.py.

    python tools/known_answer_pcap.py --out known_answer

This writes known_answer.pcap and known_answer.json.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
from pathlib import Path

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
START_US = 1_500_000_000_000_000


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip(src: str, dst: str, proto: int, body: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    checksum = _checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + body


def _ethernet(ip_packet: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip_packet


def tcp_packet(src, sport, dst, dport, flags, window, header_len, payload_len=0, seq=1, ack=0):
    """Build a TCP packet. header_len is the TCP header size, including options."""
    options = b"\x01" * (header_len - 20)
    data_offset = (header_len // 4) << 4
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, data_offset, flags, window, 0, 0)
    return _ethernet(_ip(src, dst, 6, tcp + options + b"A" * payload_len))


def udp_packet(src, sport, dst, dport, payload_len):
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0) + b"B" * payload_len
    return _ethernet(_ip(src, dst, 17, udp))


def _scenarios():
    """Return (name, client, sport, server, dport, proto, packets).

    Each packet is (offset_us, from_client, build_args). None of these flows
    sends FIN or RST before its last packet, so the answer doesn't depend on
    how a tool ends flows on TCP teardown.
    """
    client, server = "10.0.0.1", "10.0.0.2"
    tcp_session = [
        (0, True, dict(flags=SYN, window=29200, header_len=40)),
        (1_000, False, dict(flags=SYN | ACK, window=28960, header_len=40)),
        (2_000, True, dict(flags=ACK, window=229, header_len=32)),
        (3_000, True, dict(flags=PSH | ACK, window=229, header_len=32, payload_len=100)),
        (5_000, False, dict(flags=ACK, window=235, header_len=32)),
        (9_000, False, dict(flags=PSH | ACK, window=235, header_len=32, payload_len=500)),
        (17_000, True, dict(flags=ACK, window=229, header_len=32)),
    ]
    syn_probe = [
        (0, True, dict(flags=SYN, window=1024, header_len=24)),
        (50, False, dict(flags=RST | ACK, window=0, header_len=20)),
    ]
    udp_exchange = [(0, True, 40), (2_000, False, 120)]
    return [
        ("tcp_session_client_ip_lower", client, 50000, server, 80, 6, tcp_session),
        ("tcp_session_client_ip_higher", "10.0.0.9", 50001, server, 443, 6, tcp_session),
        ("syn_probe_answered_by_rst", client, 40000, server, 22, 6, syn_probe),
        ("udp_exchange", client, 53000, server, 53, 17, udp_exchange),
    ]


def _expected(name, client, sport, server, dport, proto, packets):
    forward, backward = [], []
    for offset, from_client, spec in packets:
        (forward if from_client else backward).append((offset, spec))
    offsets = [p[0] for p in packets]
    answer = {
        "scenario": name,
        "client_ip": client, "client_port": sport,
        "server_ip": server, "server_port": dport, "protocol": proto,
        "flow_duration_us": max(offsets) - min(offsets),
        "tot_fwd_pkts": len(forward),
        "tot_bwd_pkts": len(backward),
    }
    if proto == 6:
        def total(side, key, default=0):
            return sum(s.get(key, default) for _, s in side)

        answer.update(
            totlen_fwd_bytes=total(forward, "payload_len"),
            totlen_bwd_bytes=total(backward, "payload_len"),
            fwd_header_bytes=total(forward, "header_len"),
            bwd_header_bytes=total(backward, "header_len"),
            init_win_fwd=forward[0][1]["window"],
            # Despite its name, this column holds the last backward packet's window.
            init_win_bwd=backward[-1][1]["window"],
            fwd_seg_size_min=min(s["header_len"] for _, s in forward),
        )
    else:
        answer.update(
            totlen_fwd_bytes=sum(p for _, c, p in packets if c),
            totlen_bwd_bytes=sum(p for _, c, p in packets if not c),
        )
    return answer


def write_known_answer(prefix: Path) -> tuple[Path, Path]:
    pcap_path, json_path = prefix.with_suffix(".pcap"), prefix.with_suffix(".json")
    records, answers = [], []
    for index, scenario in enumerate(_scenarios()):
        name, client, sport, server, dport, proto, packets = scenario
        base = START_US + index * 1_000_000
        for offset, from_client, spec in packets:
            src, s_port, dst, d_port = (
                (client, sport, server, dport) if from_client else (server, dport, client, sport)
            )
            frame = (
                tcp_packet(src, s_port, dst, d_port, **spec)
                if proto == 6
                else udp_packet(src, s_port, dst, d_port, spec)
            )
            records.append((base + offset, frame))
        answers.append(_expected(*scenario))

    records.sort(key=lambda record: record[0])
    with pcap_path.open("wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in records:
            out.write(struct.pack("<IIII", timestamp // 1_000_000, timestamp % 1_000_000, len(frame), len(frame)))
            out.write(frame)
    json_path.write_text(json.dumps(answers, indent=2) + "\n")
    return pcap_path, json_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("known_answer"), help="output path without extension")
    args = parser.parse_args()
    for path in write_known_answer(args.out):
        print(path)
