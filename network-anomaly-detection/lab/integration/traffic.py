"""Bounded standard-library traffic scenarios, confined to the integration subnet."""
import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
import random
import signal
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NETWORK = ipaddress.ip_network("10.77.0.0/24")


def target(value):
    address = socket.gethostbyname(value)
    if ipaddress.ip_address(address) not in NETWORK:
        raise ValueError("Traffic target must be inside the isolated 10.77.0.0/24 laboratory")
    return address


class WebHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            size = min(max(int(self.path.lstrip("/") or 1000), 1), 2000000)
        except ValueError:
            size = 128
        body = b"N" * size
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


def dns_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 5353))
        while True:
            data, address = sock.recvfrom(4096)
            if len(data) < 12:
                continue
            response = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:]
            response += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("10.77.0.10")
            sock.sendto(response, address)


def serve():
    os.makedirs("/run/sshd", exist_ok=True)
    subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-p", "2222", "-o", "PidFile=/tmp/sshd.pid"])
    threading.Thread(target=dns_server, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), WebHandler)
    server.daemon_threads = True
    server.serve_forever()


def http_request(address, size):
    connection = http.client.HTTPConnection(address, 8080, timeout=2)
    try:
        connection.request("GET", f"/{size}", headers={"Connection": "close"})
        connection.getresponse().read()
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()
    return True


def dns_query(address, transaction):
    query = struct.pack("!HHHHHH", transaction, 0x100, 1, 0, 0, 0) + b"\x03lab\x08netguard\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.sendto(query, (address, 5353))
        sock.recvfrom(4096)


def generate(args):
    address = target(args.target)
    rng = random.Random(args.seed)
    started = time.time()
    end = time.monotonic() + min(max(args.seconds, 1), 30)
    count = 0
    errors = 0
    if args.scenario == "slow":
        sockets = []
        try:
            for _ in range(30 + args.seed % 15):
                sock = socket.create_connection((address, 8080), timeout=1)
                sock.sendall(b"GET /128 HTTP/1.1\r\nHost: netguard\r\n")
                sockets.append(sock)
                time.sleep(0.005)
            while time.monotonic() < end:
                for sock in sockets:
                    try:
                        sock.sendall(b"X-Lab: keep-open\r\n")
                        count += 1
                    except OSError:
                        errors += 1
                time.sleep(0.4)
        finally:
            for sock in sockets:
                sock.close()
    elif args.scenario == "scan":
        ports = rng.sample(range(10000, 16000), min(int(args.seconds * 100), 2000))
        for port in ports:
            if time.monotonic() >= end:
                break
            with socket.socket() as sock:
                sock.settimeout(0.1)
                sock.connect_ex((address, port))
            count += 1
            time.sleep(0.005 + rng.random() * 0.003)
    elif args.scenario == "flood":
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            while time.monotonic() < end:
                results = list(pool.map(lambda _: http_request(address, 128), range(12)))
                count += len(results)
                errors += results.count(False)
                time.sleep(0.012 + (args.seed % 3) * 0.004)
    elif args.scenario == "benign":
        while time.monotonic() < end:
            errors += not http_request(address, rng.choice([128, 300, 1000, 20000, 150000, 1000000]))
            count += 1
            if count % 3 == 0:
                try:
                    dns_query(address, rng.randrange(65536))
                except OSError:
                    errors += 1
            if count % 15 == 0:
                completed = subprocess.run(["ssh", "-p", "2222", "-o", "BatchMode=yes", "-o", "ConnectTimeout=1",
                                            "root@" + address, "printf netguard"], capture_output=True, timeout=3)
                errors += completed.returncode != 0
            time.sleep(rng.uniform(0.035, 0.12))
    print(json.dumps({"scenario": args.scenario, "seed": args.seed, "target": address,
                      "started_unix": started, "ended_unix": time.time(), "operations": count,
                      "errors": errors, "tools": {"python": os.sys.version}}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["serve", "benign", "scan", "flood", "slow"])
    parser.add_argument("--target", default="10.77.0.10")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--seconds", type=float, default=5)
    args = parser.parse_args()
    serve() if args.scenario == "serve" else generate(args)
