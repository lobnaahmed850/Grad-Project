import socket
import json
import time
from datetime import datetime, timezone

# Target SIEM Server Configuration
SERVER_IP = "192.168.1.13"  # Replace with your actual SIEM server IP
SERVER_PORT = 514           # UDP port for log collection

# Initialize UDP socket for network transmission
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

total_logs = 100            # Number of log packets to generate for the load test
latencies = []

print(f"[*] Starting VM Load Test: Sending {total_logs} logs to {SERVER_IP}:{SERVER_PORT}...")

for i in range(total_logs):
    # Record the precise transmission start time
    send_time = time.time()
    
    # Construct standard log payload simulating Windows event data
    log_entry = {
        "EventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Hostname": "Win10-Target-VM",
        "EventID": 4625,
        "AccountName": "Administrator",
        "SeverityValue": 4,
        "Severity": "warning",
        "Channel": "Security",
        "Message": f"VM Latency Test Packet #{i+1}"
    }
    
    # Serialize and send the log payload over UDP
    payload = json.dumps(log_entry).encode('utf-8')
    sock.sendto(payload, (SERVER_IP, SERVER_PORT))
    
    # Calculate round-trip or local processing latency
    receive_time = time.time()
    latency_ms = (receive_time - send_time) * 1000
    latencies.append(latency_ms)
    
    # Small delay to simulate steady traffic flow
    time.sleep(0.02)

# Compute average network and processing latency
avg_latency = sum(latencies) / len(latencies)

print(f"\n[+] VM Test Completed Successfully!")
print(f"[📊] Total Logs Sent from VM: {total_logs}")
print(f"[⚡] Average Network Latency: {avg_latency:.2f} ms")

# Close the socket connection
sock.close()
