"""Bounded event-time flow lifecycle shared by release training, replay and capture."""
from __future__ import annotations

import heapq
import math
import socket
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass

import pandas as pd

from src.flow_extractor import FIN, RST, Flow, Profile, TRAINING_FLAG_COLUMNS, read_packets

FEATURE_VERSION = "stream-v2-causal-start-rate"
STREAM_PROFILE = Profile(FEATURE_VERSION, True, TRAINING_FLAG_COLUMNS, False)


@dataclass(frozen=True)
class FlowConfig:
    idle_seconds: float = 2.0
    active_seconds: float = 30.0
    rate_window_seconds: float = 1.0
    max_flows: int = 10000
    max_sources: int = 4096
    max_rate_events: int = 100000

    def __post_init__(self):
        for name, value in asdict(self).items():
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name in ("max_flows", "max_sources", "max_rate_events"):
            if not isinstance(getattr(self, name), int):
                raise ValueError(f"{name} must be an integer")


class SourceRate:
    """Starts in (t-window, t] / fixed window, sampled at this flow's start.

    Ties use observation order. Events older than the watermark are rejected.
    Expiration is global so idle sources disappear even when never seen again.
    Capacity eviction increments a counter rather than hiding lost context.
    """

    def __init__(self, window_seconds=1.0, max_sources=4096, max_events=100000):
        if not math.isfinite(window_seconds) or window_seconds <= 0 or max_sources < 1 or max_events < 1:
            raise ValueError("Invalid source-rate bounds")
        self.window_us = round(window_seconds * 1e6)
        if self.window_us < 1:
            raise ValueError("Source-rate window must be at least one microsecond")
        self.window_seconds = window_seconds
        self.max_sources, self.max_events = max_sources, max_events
        self.events = deque()
        self.counts = {}
        self.watermark = -1
        self.evictions = 0

    def expire(self, timestamp):
        if timestamp < self.watermark:
            raise ValueError("Out-of-order source-rate timestamp")
        self.watermark = timestamp
        while self.events and self.events[0][0] <= timestamp - self.window_us:
            self._pop()

    def _pop(self):
        _, source = self.events.popleft()
        self.counts[source] -= 1
        if self.counts[source] == 0:
            del self.counts[source]

    def start(self, source, timestamp):
        self.expire(timestamp)
        while len(self.events) >= self.max_events or (source not in self.counts and len(self.counts) >= self.max_sources):
            self._pop()
            self.evictions += 1
        self.events.append((timestamp, source))
        self.counts[source] = self.counts.get(source, 0) + 1
        return self.counts[source] / self.window_seconds


@dataclass
class ActiveFlow:
    flow: Flow
    rate: float
    fin_sides: int = 0


class StreamingFlows:
    def __init__(self, config=None):
        self.config = config or FlowConfig()
        self.rate = SourceRate(self.config.rate_window_seconds, self.config.max_sources, self.config.max_rate_events)
        self.active = OrderedDict()
        self.expirations = []
        self.watermark = -1
        self.metrics = {"packets": 0, "late_packets": 0, "emitted": 0, "capacity_evictions": 0}

    def _deadline(self, state):
        return min(state.flow.last + round(self.config.idle_seconds * 1e6),
                   state.flow.start + round(self.config.active_seconds * 1e6))

    def _emit(self, key, timestamp, reason):
        state = self.active.pop(key)
        row = state.flow.to_row(STREAM_PROFILE)
        row.update({"source flow rate": state.rate, "flow end us": state.flow.last,
                    "flow emitted us": timestamp, "flow close reason": reason,
                    "feature version": FEATURE_VERSION})
        self.metrics["emitted"] += 1
        return row

    def advance(self, timestamp):
        if timestamp < self.watermark:
            raise ValueError("Flow watermark cannot move backwards")
        self.watermark = timestamp
        self.rate.expire(timestamp)
        rows = []
        while self.expirations and self.expirations[0][0] <= timestamp:
            deadline, start, key = heapq.heappop(self.expirations)
            state = self.active.get(key)
            if state is None or state.flow.start != start or self._deadline(state) != deadline:
                continue
            reason = "active_timeout" if deadline == state.flow.start + round(self.config.active_seconds * 1e6) else "idle_timeout"
            rows.append(self._emit(key, timestamp, reason))
        return rows

    def feed(self, packet):
        timestamp, src, sport, dst, dport, proto, payload, header, window, flags = packet
        self.metrics["packets"] += 1
        if timestamp < self.watermark:
            self.metrics["late_packets"] += 1
            return []
        rows = self.advance(timestamp)
        endpoints = sorted(((src, sport), (dst, dport)))
        key = (endpoints[0], endpoints[1], proto)
        state = self.active.get(key)
        if state is None:
            if len(self.active) >= self.config.max_flows:
                rows.append(self._emit(next(iter(self.active)), timestamp, "capacity"))
                self.metrics["capacity_evictions"] += 1
            rate = self.rate.start(socket.inet_ntoa(src), timestamp)
            state = ActiveFlow(Flow(timestamp, src, sport, dst, dport, proto, payload, header, window, flags, True), rate)
            self.active[key] = state
        else:
            from_source = (src, sport) == (state.flow.src, state.flow.sport)
            state.flow.update_active_idle(timestamp)
            state.flow.add(timestamp, from_source, payload, header, window)
            self.active.move_to_end(key)
        if flags & FIN:
            state.fin_sides |= 1 if (src, sport) == (state.flow.src, state.flow.sport) else 2
        if flags & RST or state.fin_sides == 3:
            rows.append(self._emit(key, timestamp, "reset" if flags & RST else "fin"))
        else:
            heapq.heappush(self.expirations, (self._deadline(state), state.flow.start, key))
        if len(self.expirations) > 4 * self.config.max_flows:
            self.expirations = [(self._deadline(item), item.flow.start, flow_key) for flow_key, item in self.active.items()]
            heapq.heapify(self.expirations)
        return rows

    def flush(self, reason="shutdown"):
        return [self._emit(key, self.watermark, reason) for key in list(self.active)]

    def health(self):
        return {**self.metrics, "active_flows": len(self.active), "rate_events": len(self.rate.events),
                "sources": len(self.rate.counts), "rate_evictions": self.rate.evictions}


def replay_capture(path, config=None):
    engine = StreamingFlows(config)
    rows = []
    for packet in read_packets(path):
        rows.extend(engine.feed(packet))
    rows.extend(engine.flush("capture_end"))
    return pd.DataFrame.from_records(rows)
