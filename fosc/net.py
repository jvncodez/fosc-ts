"""Connectivity probe — so FOSC says 'sem internet' instead of spinning forever.

FOSC shells out to the `claude` CLI, which when offline retries silently until the
hard task timeout (minutes of a 'pensando…' spinner with no explanation). A fast
TCP probe lets the front-ends fail loudly and immediately (preflight), and an
in-flight watchdog catches a connection that drops mid-task.
"""
import socket
import time

from . import config

# TCP endpoints that signal "the internet is reachable" in the DIRECT Anthropic
# setup. api.anthropic.com is the one that actually matters (that's who the
# claude CLI talks to); the public resolvers are fallbacks so a single-host
# hiccup doesn't read as a full outage.
_ANTHROPIC_PROBES = [("api.anthropic.com", 443), ("1.1.1.1", 443), ("8.8.8.8", 53)]

_cache = {"ts": 0.0, "val": None}
_CACHE_TTL = 4.0  # seconds; don't hammer the probes when checked in a tight spot


def _probes() -> list[tuple[str, int]]:
    """Probe targets, aware of the provider in play.

    On Bedrock the claude CLI never talks to the public internet at all — it
    calls bedrock-runtime, typically through a VPC endpoint with egress closed
    to everything else (no NAT, no 0.0.0.0/0). The direct-Anthropic probes
    (api.anthropic.com, 1.1.1.1, 8.8.8.8) are then unreachable by design, which
    made this check report "offline" even with Bedrock fully reachable. Probe
    what will actually be called instead.
    """
    if config.MODEL_PROVIDER == "bedrock":
        region = config.AWS_REGION
        return [
            (f"bedrock-runtime.{region}.amazonaws.com", 443),
            (f"sts.{region}.amazonaws.com", 443),
        ]
    return _ANTHROPIC_PROBES


def online(timeout: float = 2.5, use_cache: bool = True) -> bool:
    """True if any probe endpoint accepts a TCP connection. Cheap, stdlib-only."""
    now = time.time()
    if use_cache and _cache["val"] is not None and now - _cache["ts"] < _CACHE_TTL:
        return _cache["val"]
    ok = False
    for host, port in _probes():
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
