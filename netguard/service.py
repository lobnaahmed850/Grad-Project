"""Authenticated HTTP ingestion, UDP syslog, persistent storage and read-only UI."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from netguard.alerts import from_syslog, now
from netguard.storage import EventStore
from netguard.syslog import normalize


class IngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, token=""):
        self.store, self.token = store, token
        self.syslog_ready = None
        self.syslog_thread = None
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.store.count("http_overload")
            request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def reply(self, status, payload, content_type="application/json"):
        content = payload.encode() if isinstance(payload, str) else json.dumps(payload, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def authorized(self):
        expected = self.server.token
        return not expected or hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + expected)

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            return self.reply(200, (Path(__file__).parent / "dashboard.html").read_text(), "text/html")
        if parsed.path == "/health":
            if self.server.syslog_ready is not None and (
                not self.server.syslog_ready.is_set() or not self.server.syslog_thread.is_alive()
            ):
                return self.reply(503, {"status": "unavailable", "reason": "syslog listener is not running"})
            try:
                with self.server.store.lock:
                    self.server.store.db.execute("SELECT 1").fetchone()
            except Exception:
                return self.reply(503, {"status": "unavailable", "reason": "storage is not available"})
            return self.reply(200, {"status": "ready", "storage": "sqlite-wal"})
        if not self.authorized():
            return self.reply(401, {"error": "Bearer token required"})
        if parsed.path == "/api/summary":
            return self.reply(200, self.server.store.summary())
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            try:
                events = self.server.store.query(int(query.get("limit", [100])[0]), int(query.get("after", [0])[0]),
                                                 query.get("source", [None])[0], query.get("run_id", [None])[0],
                                                 query.get("before", [None])[0])
                return self.reply(200, {"events": events})
            except ValueError:
                return self.reply(400, {"error": "Invalid pagination"})
        return self.reply(404, {"error": "Unknown endpoint"})

    def do_POST(self):
        if not self.authorized():
            return self.reply(401, {"error": "Bearer token required"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 131072:
                return self.reply(413, {"error": "Request must be 1..131072 bytes"})
            payload = json.loads(self.rfile.read(length))
            if self.path == "/api/events":
                started = time.perf_counter_ns()
                inserted = self.server.store.put(payload)
                return self.reply(201 if inserted else 200, {"inserted": inserted, "ingestion_ms": (time.perf_counter_ns() - started) / 1e6})
            if self.path == "/api/events/batch":
                started = time.perf_counter_ns()
                inserted = self.server.store.put_many(payload)
                return self.reply(200, {"inserted": inserted, "ingestion_ms": (time.perf_counter_ns() - started) / 1e6})
            if self.path == "/api/diagnostics":
                if not isinstance(payload, dict) or not isinstance(payload.get("sensor"), str) or not isinstance(payload.get("metrics"), dict):
                    raise ValueError("Expected sensor and metrics")
                self.server.store.diagnostic(payload["sensor"][:100], payload["metrics"])
                return self.reply(200, {"stored": True})
            return self.reply(404, {"error": "Unknown endpoint"})
        except (ValueError, TypeError, KeyError, AttributeError, TimeoutError):
            self.server.store.count("invalid_http_events")
            return self.reply(400, {"error": "Invalid normalized event"})


def syslog_loop(address, store, stop, ready=None, bound_socket=None):
    with bound_socket or socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if bound_socket is None:
            sock.bind(address)
        sock.settimeout(0.2)
        if ready:
            ready(sock.getsockname())
        while not stop.is_set():
            try:
                raw, sender = sock.recvfrom(65535)
            except socket.timeout:
                continue
            text = raw.decode(errors="replace").strip()
            event = normalize(text, sender[0], now())
            if event is None:
                store.quarantine(text, sender[0], "unsupported format or invalid fields/timestamp")
            else:
                store.put(from_syslog(event))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--syslog-port", type=int, default=5514)
    parser.add_argument("--database", default="runtime/events.sqlite")
    args = parser.parse_args()
    token = os.environ.get("NETGUARD_TOKEN", "")
    if args.host not in ("127.0.0.1", "::1", "localhost") and not token:
        parser.error("NETGUARD_TOKEN is required for a non-loopback listener")
    store = EventStore(args.database)
    server = IngestServer((args.host, args.port), store, token)
    stop = threading.Event()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.bind((args.host, args.syslog_port))
    except OSError:
        udp_socket.close()
        server.server_close()
        store.close()
        raise
    server.syslog_ready = threading.Event()
    udp = threading.Thread(target=syslog_loop, args=((args.host, args.syslog_port), store, stop),
                           kwargs={"ready": lambda _: server.syslog_ready.set(), "bound_socket": udp_socket}, daemon=True)
    server.syslog_thread = udp
    udp.start()

    def shutdown(*_):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        stop.set()
        udp.join(timeout=2)
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
