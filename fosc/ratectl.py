"""Adaptive, per-host request budget for every tool that touches the target.

Instead of a fixed conservative rate (slow on robust targets) or tool defaults
(nuclei at 150 req/s took a target down), each host gets ONE shared budget:

- starts at RATE_START req/s and adapts AIMD-style from the health probe's
  latency: healthy -> +RATE_STEP, slow/failing -> halve (never below RATE_MIN);
- tools running at the same time on the same host SPLIT the budget instead of
  adding up (two scanners at "10 req/s" each used to mean 20 req/s on the host).

A tool takes its share when it launches (`with share(host) as (rate, threads)`),
so a budget change applies to the next tool launched. The health circuit
breaker (fosc/health.py) remains the hard stop.
"""
import threading
import time
from contextlib import contextmanager

from . import config


class HostRate:
    """Pure AIMD controller for one host. observe() returns the new rate."""

    def __init__(self, start: int = config.RATE_START, lo: int = config.RATE_MIN,
                 hi: int = config.RATE_MAX, step: int = config.RATE_STEP):
        self.rate = max(lo, min(hi, start))
        self.lo, self.hi, self.step = lo, hi, step
        self.baseline_ms: float | None = None
        self.history: list[tuple[float, int, str]] = []   # (ts, rate, reason) for audit/UI

    def _slow(self, ms: float) -> bool:
        if self.baseline_ms is None:
            return ms > config.RATE_SLOW_MS
        return ms > max(config.RATE_SLOW_MS, 3 * self.baseline_ms)

    def observe(self, ok: bool, ms: float | None) -> int:
        old = self.rate
        if not ok or (ms is not None and self._slow(ms)):
            self.rate = max(self.lo, self.rate // 2)
            reason = "falha" if not ok else f"lento ({int(ms)} ms)"
        else:
            if ms is not None:  # EWMA of healthy latency = the host's normal speed
                self.baseline_ms = ms if self.baseline_ms is None else 0.8 * self.baseline_ms + 0.2 * ms
            self.rate = min(self.hi, self.rate + self.step)
            reason = "saudável"
        if self.rate != old:
            self.history.append((time.time(), self.rate, reason))
            self.history = self.history[-50:]
        return self.rate


class _Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._hosts: dict[str, HostRate] = {}
        self._active: dict[str, int] = {}
        self._alloc: dict[str, int] = {}

    def host(self, host: str) -> HostRate:
        with self._lock:
            return self._hosts.setdefault(host.lower(), HostRate())

    def observe(self, host: str, ok: bool, ms: float | None) -> int:
        return self.host(host).observe(ok, ms)

    @contextmanager
    def share(self, host: str, parts: int = 1):
        """Reserve a slice of the host budget for one tool. Yields (rate, threads).

        `parts` = how many tools the caller expects to run at once on this host,
        so the first one doesn't grab the whole budget. Slices never add up to
        more than the host budget (what is already allocated is subtracted)."""
        h = host.lower()
        hr = self.host(h)
        with self._lock:
            n = self._active.get(h, 0) + 1
            used = self._alloc.get(h, 0)
            rate = max(1, min(hr.rate // max(parts, n), hr.rate - used))
            self._active[h] = n
            self._alloc[h] = used + rate
        threads = max(1, min(config.RECON_THREADS, rate))
        try:
            yield rate, threads
        finally:
            with self._lock:
                self._active[h] = max(0, self._active.get(h, 1) - 1)
                self._alloc[h] = max(0, self._alloc.get(h, rate) - rate)

    def snapshot(self, host: str) -> dict:
        hr = self.host(host)
        return {"rate": hr.rate, "baseline_ms": round(hr.baseline_ms or 0), "active_tools": self._active.get(host.lower(), 0),
                "changes": [{"ts": t, "rate": r, "reason": why} for t, r, why in hr.history[-10:]]}

    def reset(self):
        with self._lock:
            self._hosts.clear()
            self._active.clear()
            self._alloc.clear()


REGISTRY = _Registry()
share = REGISTRY.share
observe = REGISTRY.observe
