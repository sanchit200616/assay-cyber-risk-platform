"""Correlation IDs, JSON logs, metrics and lightweight span timing.

Spans are timing log records, not OpenTelemetry exports (see docs for the OTel mapping).
"""
from __future__ import annotations

import contextvars
import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager

correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")
log = logging.getLogger("cyberrisk")


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
                   "level": record.levelname, "logger": record.name, "msg": record.getMessage(),
                   "correlation_id": correlation_id.get()}
        extra = getattr(record, "fields", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger("cyberrisk")
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


def event(msg: str, **fields) -> None:
    log.info(msg, extra={"fields": fields})


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.counters: dict = {}
        self.timings: dict = {}

    def inc(self, name: str, **labels) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + 1

    def observe(self, name: str, seconds: float, **labels) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            c, s, m = self.timings.get(key, (0, 0.0, 0.0))
            self.timings[key] = (c + 1, s + seconds, max(m, seconds))

    def get(self, name: str, **labels) -> int:
        return self.counters.get((name, tuple(sorted(labels.items()))), 0)

    def render(self) -> str:
        def lab(ls):
            return "{" + ",".join(f'{k}="{v}"' for k, v in ls) + "}" if ls else ""
        lines = []
        with self._lock:
            for (n, ls), v in sorted(self.counters.items()):
                lines.append(f"{n}{lab(ls)} {v}")
            for (n, ls), (c, s, m) in sorted(self.timings.items()):
                lines.append(f"{n}_count{lab(ls)} {c}")
                lines.append(f"{n}_seconds_sum{lab(ls)} {s:.6f}")
                lines.append(f"{n}_seconds_max{lab(ls)} {m:.6f}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()


@contextmanager
def span(name: str, **fields):
    start = time.perf_counter()
    try:
        yield
    finally:
        dur = time.perf_counter() - start
        METRICS.observe("span", dur, span=name)
        log.debug("span", extra={"fields": {"span": name, "duration_ms": round(dur * 1000, 2), **fields}})
