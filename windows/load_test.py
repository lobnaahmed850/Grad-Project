#!/usr/bin/env python3

import socket
import time
import argparse
import json
from datetime import datetime, timezone

# Configuration - Destination server IP and port
HOST = "192.168.1.6"
PORT = 10514

def build_message(seq):
    """Builds a JSON Windows log message mimicking NXLog format."""
    # Generate ISO formatted timestamp compatible with the SIEM parser
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    # Simulate a Windows event (e.g., failed logon EventID 4625)
    log_dict = {
        "EventTime": timestamp,
        "Hostname": "Win10-Target-VM",
        "EventID": 4625,
        "AccountName": "Administrator",
        "SeverityValue": 4,
        "Severity": "warning",
        "Channel": "Security",
        "Message": f"Windows Latency & Load Test Packet #{seq}"
    }
    
    # Convert dictionary to JSON string and encode to bytes
    message = json.dumps(log_dict)
    return message.encode("utf-8")

def run_test(rate, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total_events = rate * duration

    print("=" * 60)
    print("AI NET - Windows Python Load Test Generator")
    print("=" * 60)
    print(f"Destination : {HOST}:{PORT}")
    print(f"Target EPS  : {rate}")
    print(f"Duration    : {duration} seconds")
    print(f"Expected    : {total_events} events")
    print("=" * 60)

    start = time.perf_counter()
    next_send = start
    sent = 0

    try:
        while sent < total_events:
            now = time.perf_counter()

            if now < next_send:
                time.sleep(next_send - now)

            seq = sent + 1
            payload = build_message(seq)

            try:
                sock.sendto(payload, (HOST, PORT))
                sent += 1
            except OSError as e:
                print(f"Send error at sequence {seq}: {e}")

            # Calculate the precise next send time to maintain target EPS
            next_send = start + (sent / rate)

    finally:
        sock.close()

    end = time.perf_counter()
    elapsed = end - start
    actual_eps = sent / elapsed if elapsed > 0 else 0

    print()
    print("=" * 60)
    print("WINDOWS LOAD TEST COMPLETE")
    print("=" * 60)
    print(f"Events sent : {sent}")
    print(f"Elapsed     : {elapsed:.3f} seconds")
    print(f"Actual EPS  : {actual_eps:.2f}")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI NET Windows UDP load generator in Python")
    parser.add_argument("--rate", type=int, required=True, help="Target events per second")
    parser.add_argument("--duration", type=int, required=True, help="Duration in seconds")
    
    args = parser.parse_args()
    run_test(args.rate, args.duration)
