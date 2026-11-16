"""Backward-compatible parser imports and standalone JSONL syslog collector."""
import hashlib
import json
import os
import socket
from datetime import datetime, timezone

from netguard.syslog import (
    CISCO_EVENT_MAP, CISCO_PATTERN, LINUX_EVENT_MAP, PARSER_VERSION,
    WINDOWS_EVENT_MAP, WINDOWS_PATTERN, map_severity, normalize,
    normalize_cisco_timestamp, parse_gns3_event, parse_linux_event, parse_windows_event,
)

UDP_IP = os.environ.get("NETGUARD_SYSLOG_HOST", "0.0.0.0")
UDP_PORT = int(os.environ.get("NETGUARD_SYSLOG_PORT", "514"))
NORMALIZED_FILE = "normalized_events.jsonl"
RAW_LOGS_FILE = "raw_logs.json"
QUARANTINE_FILE = "quarantine.jsonl"


def save_event(event_dict, filepath):
    with open(filepath, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event_dict) + "\n")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((UDP_IP, UDP_PORT))
        print(f"Listening for Syslog messages on UDP port {UDP_PORT}...", flush=True)
        try:
            while True:
                data, address = sock.recvfrom(65535)
                raw = data.decode(errors="replace").strip()
                received = datetime.now(timezone.utc).isoformat()
                save_event({"event_id": hashlib.sha256(raw.encode()).hexdigest()[:16], "received_at": received,
                            "source_ip": address[0], "raw_payload": raw}, RAW_LOGS_FILE)
                event = normalize(raw, address[0], received)
                if event is None:
                    save_event({"raw": raw, "source_ip": address[0], "received_at": received,
                                "reason": "unsupported format or invalid fields/timestamp"}, QUARANTINE_FILE)
                else:
                    save_event(event, NORMALIZED_FILE)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
