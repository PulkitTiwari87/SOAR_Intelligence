"""Tiny in-process metrics: counters and latency summaries exposed at /api/system/metrics."""
from __future__ import annotations

import threading
from collections import defaultdict, deque


class Metrics:
    def __init__(self, window: int = 500) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._samples: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def count(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counters[name] += n

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self._samples[name].append(value)

    def snapshot(self) -> dict:
        with self._lock:
            latencies = {}
            for name, samples in self._samples.items():
                if not samples:
                    continue
                ordered = sorted(samples)
                latencies[name] = {
                    "count": len(ordered),
                    "avg": round(sum(ordered) / len(ordered), 2),
                    "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 2),
                    "max": round(ordered[-1], 2),
                }
            return {"counters": dict(self._counters), "latency_ms": latencies}

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._samples.clear()


metrics = Metrics()
