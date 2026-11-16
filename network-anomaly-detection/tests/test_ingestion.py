import json
import queue
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from netguard.alerts import from_syslog, validate
from netguard.service import IngestServer, syslog_loop
from netguard.storage import EventStore, Outbox
from netguard.syslog import normalize


def event():
    return from_syslog(normalize("<38>Jan  2 03:04:05 ubuntu sshd[9]: Failed password for bob",
                                 "127.0.0.1", "2026-01-02T03:04:06Z"))


def test_storage_is_idempotent_persistent_and_bounded(tmp_path):
    path = tmp_path / "events.sqlite"
    store = EventStore(path, max_events=2)
    first = event()
    assert store.put(first)
    assert not store.put(first)
    store.put(event())
    store.put(event())
    assert len(store.query()) == 2
    assert store.summary()["counters"]["retention_deleted"] == 1
    store.close()
    restarted = EventStore(path)
    assert len(restarted.query()) == 2
    assert restarted.query()[0]["processing_status"] == "stored"
    restarted.close()


def test_outbox_survives_restart_and_reports_overload(tmp_path):
    path = tmp_path / "outbox.sqlite"
    outbox = Outbox(path, max_events=1)
    first = event()
    outbox.put(first)
    with pytest.raises(OverflowError):
        outbox.put(event())
    outbox.close()
    outbox = Outbox(path)
    assert outbox.pending()[0]["alert_id"] == first["alert_id"]
    outbox.ack(first["alert_id"])
    assert outbox.size() == 0
    outbox.close()


def test_batch_ingestion_is_atomic_and_idempotent(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    first, second = event(), event()
    assert store.put_many([first, second]) == [True, True]
    assert store.put_many([first, second]) == [False, False]
    invalid = event()
    invalid["timestamp"] = "broken"
    with pytest.raises(ValueError):
        store.put_many([event(), invalid])
    assert len(store.query()) == 2
    store.close()


def test_outbox_batches_keep_capacity_atomicity_and_durable_acknowledgments(tmp_path):
    path = tmp_path / "outbox.sqlite"
    outbox = Outbox(path, max_events=2)
    first, second = event(), event()
    outbox.put_many([first, second])
    outbox.put_many([first, second])
    with pytest.raises(OverflowError):
        outbox.put_many([first, event()])
    assert outbox.size() == 2
    outbox.ack_many([first["alert_id"], second["alert_id"]])
    outbox.close()
    restarted = Outbox(path, max_events=2)
    assert restarted.size() == 0
    restarted.close()


@pytest.mark.parametrize("mutation", ["timestamp", "source", "score", "schema", "id", "evidence"])
def test_invalid_alerts_are_rejected(mutation):
    payload = event()
    key, value = {
        "timestamp": ("timestamp", "yesterday"), "source": ("source_ip", "not-an-ip"),
        "score": ("score", float("nan")), "schema": ("schema_version", "wrong"),
        "id": ("alert_id", "not-uuid"), "evidence": ("evidence", []),
    }[mutation]
    payload[key] = value
    with pytest.raises(ValueError):
        validate(payload)


def test_udp_and_http_events_share_storage_and_dashboard_api(tmp_path):
    store = EventStore(tmp_path / "events.sqlite")
    server = IngestServer(("127.0.0.1", 0), store, "test-token")
    stop = threading.Event()
    ready = queue.Queue()
    udp = threading.Thread(target=syslog_loop, args=(("127.0.0.1", 0), store, stop, ready.put))
    http = threading.Thread(target=server.serve_forever)
    udp.start()
    http.start()
    endpoint = "http://127.0.0.1:" + str(server.server_port)
    try:
        address = ready.get(timeout=2)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"<38>Jan  2 03:04:05 ubuntu sshd[9]: Failed password for bob", address)
            sender.sendto(b"not-a-supported-log", address)
        payload = event()
        payload.update(event_source="ml", model_version="integration-fixture", detection_method="network-ml")
        request = urllib.request.Request(endpoint + "/api/events", json.dumps(payload).encode(),
                                         headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            assert response.status == 201
        request = urllib.request.Request(endpoint + "/api/events/batch", json.dumps([payload, event()]).encode(),
                                         headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["inserted"] == [False, True]
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(endpoint + "/api/events")
        assert error.value.code == 401
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and len(store.query()) < 2:
            time.sleep(.01)
        request = urllib.request.Request(endpoint + "/api/events", headers={"Authorization": "Bearer test-token"})
        with urllib.request.urlopen(request) as response:
            result = json.load(response)
        assert {row["event_source"] for row in result["events"]} == {"syslog", "ml"}
        with urllib.request.urlopen(endpoint) as response:
            assert "Event console" in response.read().decode()
        server.syslog_ready = threading.Event()
        server.syslog_thread = udp
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(endpoint + "/health")
        assert error.value.code == 503
        server.syslog_ready.set()
        with urllib.request.urlopen(endpoint + "/health") as response:
            assert json.load(response)["status"] == "ready"
        assert store.summary()["counters"]["quarantined"] == 1
    finally:
        stop.set()
        server.shutdown()
        udp.join(timeout=2)
        http.join(timeout=2)
        server.server_close()
        store.close()
