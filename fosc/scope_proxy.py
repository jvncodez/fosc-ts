"""Network-level scope enforcement (G0) — the egress proxy.

The deterministic `Scope` guards our recon queue, but during active exploitation the
hunting sub-agent has a shell and could — by model drift or prompt-injection from the
target's own responses — try to reach a host OUTSIDE scope. This proxy closes that at
the wire: the agent's HTTP(S) traffic is routed through it (HTTP(S)_PROXY), and it
ALLOWS only in-scope hosts plus the model-API egress. Everything else gets 403 and is
written to the audit ledger. Scope stops being merely *forbidden in a prompt* and
becomes *impossible on the wire*.

Stdlib only. HTTPS is filtered on the CONNECT host (no MITM, no certificate needed).
Opt-in: `config.SCOPE_PROXY` (env `SENTINELA_SCOPE_PROXY=1`), because it must be given
the right model-API egress allowlist for the environment (Anthropic API or Bedrock).
"""
import select
import socket
import socketserver
import threading

from . import config


def _norm_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("[") and "]" in host:        # [::1]:443 -> ::1
        return host[1:host.index("]")]
    if host.count(":") == 1:                          # host:port -> host (not IPv6)
        host = host.split(":", 1)[0]
    return host


def _egress_hosts() -> list[str]:
    # Hosts the model layer itself must reach (never the target). Entries starting
    # with "." are suffix matches (e.g. ".amazonaws.com" for Bedrock).
    hosts = list(config.PROXY_EGRESS_HOSTS)
    return [h.lower() for h in hosts]


def host_allowed(host: str, scope, egress: list[str]) -> bool:
    """Pure decision: is this host reachable? In-scope target OR model-API egress."""
    h = _norm_host(host)
    if not h:
        return False
    for e in egress:
        if e.startswith(".") and (h == e[1:] or h.endswith(e)):
            return True
        if h == e:
            return True
    try:
        return scope.allows_host(h)
    except Exception:
        return False


class ScopeProxy:
    """Threaded forward proxy that enforces `scope` on every outbound connection."""

    def __init__(self, scope, audit_log=None, on_block=None):
        self.scope = scope
        self.audit = audit_log
        self.on_block = on_block
        self.egress = _egress_hosts()
        self.blocked = 0
        self.allowed = 0
        self._seen_blocked: dict[str, int] = {}   # host -> times blocked (dedup the trail)
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self.port = None

    @property
    def url(self) -> str | None:
        return f"http://127.0.0.1:{self.port}" if self.port else None

    def _decide(self, host: str) -> bool:
        ok = host_allowed(host, self.scope, self.egress)
        h = _norm_host(host)
        if ok:
            self.allowed += 1
            return True
        self.blocked += 1
        # Dedup the trail: an agent loop can hammer the same out-of-scope host
        # thousands of times. Record the FIRST block per host (the custody-relevant
        # event), just count the rest. The counter is reconciled on proxy_stop.
        with self._lock:
            first = h not in self._seen_blocked
            self._seen_blocked[h] = self._seen_blocked.get(h, 0) + 1
        if first:
            if self.audit:
                try:
                    self.audit.record("scope_block", host=h, layer="proxy")
                except Exception:
                    pass
            if self.on_block:
                try:
                    self.on_block(h)
                except Exception:
                    pass
        return False

    def block_summary(self) -> dict:
        with self._lock:
            return dict(self._seen_blocked)

    def start(self) -> str:
        proxy = self
        class Handler(socketserver.StreamRequestHandler):
            timeout = 30
            def handle(self):
                try:
                    _serve(self, proxy)
                except Exception:
                    pass
        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def _deny(wfile, host: str):
    body = f"blocked by scope proxy: {host} is out of scope".encode()
    wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                b"Connection: close\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\n\r\n" + body)
    wfile.flush()


def _pipe(a: socket.socket, b: socket.socket):
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 60)
            if x or not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def _serve(handler, proxy: ScopeProxy):
    line = handler.rfile.readline(65536)
    if not line:
        return
    parts = line.decode("latin-1").split()
    if len(parts) < 2:
        return
    method, target = parts[0], parts[1]
    # drain request headers
    headers = []
    while True:
        h = handler.rfile.readline(65536)
        if h in (b"\r\n", b"\n", b""):
            break
        headers.append(h)

    if method.upper() == "CONNECT":                  # HTTPS tunnel
        host = _norm_host(target)
        if not proxy._decide(target):
            _deny(handler.wfile, host)
            return
        port = 443
        if ":" in target and not target.startswith("["):
            port = int(target.rsplit(":", 1)[1])
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            _deny(handler.wfile, host)
            return
        handler.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        handler.wfile.flush()
        _pipe(handler.connection, upstream)
        return

    # plain HTTP absolute-URI forward
    host = ""
    if "://" in target:
        rest = target.split("://", 1)[1]
        host = rest.split("/", 1)[0]
    if not host:
        for h in headers:
            if h.lower().startswith(b"host:"):
                host = h.split(b":", 1)[1].decode("latin-1").strip()
                break
    if not proxy._decide(host):
        _deny(handler.wfile, _norm_host(host))
        return
    hostname = _norm_host(host)
    port = 80
    if ":" in host and not host.startswith("["):
        try:
            port = int(host.rsplit(":", 1)[1])
        except ValueError:
            port = 80
    path = "/"
    if "://" in target:
        rest = target.split("://", 1)[1]
        path = rest[len(host):] or "/"
    try:
        upstream = socket.create_connection((hostname, port), timeout=15)
    except OSError:
        _deny(handler.wfile, hostname)
        return
    req = f"{method} {path} HTTP/1.1\r\n".encode("latin-1") + b"".join(headers) + b"\r\n"
    upstream.sendall(req)
    _pipe(handler.connection, upstream)
