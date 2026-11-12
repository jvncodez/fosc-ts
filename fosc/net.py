"""Connectivity probe — so FOSC says 'sem internet' instead of spinning forever.

FOSC shells out to the `claude` CLI, which when offline retries silently until the
hard task timeout (minutes of a 'pensando…' spinner with no explanation). A fast
TCP probe lets the front-ends fail loudly and immediately (preflight), and an
in-flight watchdog catches a connection that drops mid-task.
"""
import socket
import time

# TCP endpoints that signal "the internet is reachable". api.anthropic.com is the
# one that actually matters (that's who the claude CLI talks to); the resolvers are
# fallbacks so a single-host hiccup doesn't read as a full outage.
_PROBES = [("api.anthropic.com", 443), ("1.1.1.1", 443), ("8.8.8.8", 53)]

_cache = {"ts": 0.0, "val": None}
_CACHE_TTL = 4.0  # seconds; don't hammer the probes when checked in a tight spot


def online(timeout: float = 2.5, use_cache: bool = True) -> bool:
    """True if any probe endpoint accepts a TCP connection. Cheap, stdlib-only."""
    now = time.time()
    if use_cache and _cache["val"] is not None and now - _cache["ts"] < _CACHE_TTL:
        return _cache["val"]
    ok = False
    for host, port in _PROBES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                ok = True
                break
        except OSError:
            continue
    _cache.update(ts=now, val=ok)
    return ok


def offline(timeout: float = 2.5, use_cache: bool = True) -> bool:
    return not online(timeout, use_cache)
