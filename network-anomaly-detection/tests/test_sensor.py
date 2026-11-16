import threading

from netguard.alerts import validate
from netguard.sensor import Sensor
from src.release import ReleaseModel
from src.streaming import replay_capture


def test_real_release_worker_scores_flows_and_persists_normalized_events(known_answer, tmp_path):
    model = ReleaseModel.load_default()
    rows = replay_capture(known_answer[0], model.flow_config).to_dict("records")
    sensor = Sensor(model, "http://127.0.0.1:1", tmp_path / "outbox.sqlite", batch_wait_ms=0)
    sensor.submit(rows)
    sensor.inference_stop.set()
    worker = threading.Thread(target=sensor.infer)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert sensor.counters["inference_errors"] == 0
    assert sensor.outbox.size() == len(rows)
    for event in sensor.outbox.pending():
        validate(event)
        assert event["event_source"] == "ml"
        assert event["model_version"] == model.version
    sensor.outbox.close()


def test_queue_overload_is_bounded_and_counted(known_answer, tmp_path):
    model = ReleaseModel.load_default()
    sensor = Sensor(model, "http://127.0.0.1:1", tmp_path / "outbox.sqlite", queue_size=1)
    rows = replay_capture(known_answer[0], model.flow_config).to_dict("records")
    sensor.submit(rows)
    assert sensor.queue.qsize() == 1
    assert sensor.counters["queue_dropped"] == len(rows) - 1
    sensor.outbox.close()
