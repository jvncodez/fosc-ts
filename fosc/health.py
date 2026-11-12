"""Target-health circuit breaker — don't take down what we're testing.

A background thread probes the target's base URL every HEALTH_INTERVAL seconds.
HEALTH_FAILS consecutive failures (timeout, connection error, or 502/503/504)
TRIP the breaker: the engine pauses the hunt, kills everything in flight and
tells the operator. Recovery is reported but never auto-resumes: a human
decides when to hit the target again (human-in-the-loop).

The decision logic (`Breaker`) is pure so it can be unit-tested without a network.
"""
import ssl
import threading
import time
import urllib.error
import urllib.request

from . import config

_UNHEALTHY_STATUS = {502, 503, 504}
_RECOVER_OKS = 2  # consecutive good probes before reporting recovery


class Breaker:
    """Pure state machine. feed(ok) -> "trip" | "recover" | None."""

    def __init__(self, fails: int = config.HEALTH_FAILS):
        self.fails = max(1, fails)
        self.bad = 0
        self.good = 0
        self.tripped = False
        self.recovered = False

    def feed(self, ok: bool) -> str | None:
        if ok:
            self.bad = 0
            self.good += 1
            if self.tripped and not self.recovered and self.good >= _RECOVER_OKS:
                self.recovered = True
                return "recover"
            return None
        self.good = 0
        self.bad += 1
        if not self.tripped and self.bad >= self.fails:
            self.tripped = True
            self.recovered = False
            return "trip"
        return None

    def reset(self):
        """Operator resumed the hunt: arm again from a clean slate."""
        self.__init__(self.fails)


def probe(url: str, timeout: int = config.HEALTH_TIMEOUT) -> tuple[bool, str]:
    """One light GET. Healthy = any HTTP answer except 502/503/504 within timeout
    (a 401/403/404 still means the server is up)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # target certs are often self-signed in engagements
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "FOSC-TS-healthcheck"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # timeout, refused, reset, DNS…
        return False, f"{type(e).__name__}: {str(e)[:80]}"
    ms = int((time.time() - t0) * 1000)
    if code in _UNHEALTHY_STATUS:
        return False, f"HTTP {code} ({ms} ms)"
    return True, f"HTTP {code} ({ms} ms)"


class TargetHealth:
    """Background prober wired to engine callbacks."""

    def __init__(self, url: str, on_trip, on_recover, interval: int = config.HEALTH_INTERVAL,
                 fails: int = config.HEALTH_FAILS, timeout: int = config.HEALTH_TIMEOUT, prober=probe):
        self.url = url
        self.on_trip = on_trip
        self.on_recover = on_recover
        self.interval = interval
        self.timeout = timeout
        self.breaker = Breaker(fails)
        self.last = ""
        self._prober = prober
        self._stop = threading.Event()
        self._thread = None

    @property
    def tripped(self) -> bool:
        return self.breaker.tripped

    def reset(self):
        self.breaker.reset()

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval):
            ok, detail = self._prober(self.url, self.timeout)
            self.last = detail
            ev = self.breaker.feed(ok)
            try:
                if ev == "trip":
                    self.on_trip(detail)
                elif ev == "recover":
                    self.on_recover(detail)
            except Exception as e:  # a callback bug must never kill the watchdog
                print(f"[fosc] health callback error: {e}")
