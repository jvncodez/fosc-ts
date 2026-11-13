"""`fosc -v -p <port>` -- localhost-only web panel (stdlib HTTP server + SSE).

Hunts launched from the panel run as detached `bin/fosc -h` processes, so
closing the viewer never kills them. The panel itself only reads RunState
files and writes control files (PAUSE/STOP) and ~/.fosc/config.json.

Hardening, since this panel can launch real hunts:
  - binds 127.0.0.1 only, no flag to widen it
  - Host header must be 127.0.0.1/localhost (blocks DNS rebinding)
  - every POST needs the X-FOSC header and a same-origin Origin (blocks CSRF
    from any other site open in the browser)
"""
import hashlib
import http.server
import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import config, knowledge
from .claude_runner import stream_to_text
from .cognito_auth import CognitoAuth, CognitoSettings
from .notify import send_telegram
from .state import RunState, list_runs

_JS = "application/javascript; charset=utf-8"
_CSS = "text/css; charset=utf-8"
# Front oficial (anadevfs) em web/ na raiz: SPA ES-module servido por esta
# whitelist fixa (sem path traversal). O api.js em modo live consome a API real
# deste viewer. Fallbacks: front antigo em web/ e o legado em fosc/web.
_FRONT = Path(__file__).resolve().parent.parent / "web"
if (_FRONT / "src" / "app.js").is_file():
    WEB_DIR = _FRONT
    STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
              "/styles.css": ("styles.css", _CSS),
              "/tokens.css": ("tokens.css", _CSS),
              "/features.css": ("features.css", _CSS),
              "/terminal.css": ("terminal.css", _CSS),
              "/assets/fosc-ts.svg": ("assets/fosc-ts.svg", "image/svg+xml"),
              "/src/app.js": ("src/app.js", _JS),
              "/src/services/api.js": ("src/services/api.js", _JS)}
elif (_FRONT / "index.html").is_file():
    WEB_DIR = _FRONT
    STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
              "/css/app.css": ("css/app.css", _CSS),
              "/js/app.js": ("js/app.js", _JS),
              "/assets/logo.svg": ("assets/logo.svg", "image/svg+xml"),
              "/js/mock.js": (None, _JS)}
else:
    WEB_DIR = Path(__file__).resolve().parent / "web"
    STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
              "/app.css": ("app.css", _CSS),
              "/app.js": ("app.js", _JS),
              "/logo.svg": ("logo.svg", "image/svg+xml")}
TARGET_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/_]{0,250}$")
LIVE = ("running", "paused", "sleeping", "recon")


def _auth_error_page(message: str, login_url: str) -> bytes:
    """Small Portuguese error page shown when a Cognito callback is rejected."""
    safe_url = login_url.replace('"', "%22")
    return (
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>FOSC/TS — Login</title>"
        "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;"
        "font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f4f7fc;color:#1d2940}"
        ".card{background:#fff;border:1px solid #e3e9f2;border-radius:12px;padding:28px 32px;"
        "max-width:380px;text-align:center;box-shadow:0 14px 38px #1725411a}"
        "h1{font-size:18px;margin:0 0 8px}p{font-size:13px;color:#59667d;margin:0 0 18px}"
        "a{display:inline-block;background:#1f6fb5;color:#fff;text-decoration:none;"
        "font-size:13px;font-weight:700;padding:10px 18px;border-radius:7px}</style></head>"
        f"<body><div class=\"card\"><h1>{message}</h1>"
        "<p>Volte para a página de login e tente novamente.</p>"
        f"<a href=\"{safe_url}\">Voltar para o login</a></div></body></html>"
    ).encode("utf-8")


def overview() -> dict:
    targets, tot_conf, tot_cost = [], 0, 0.0
    for st in list_runs():
        snap = st.snapshot(results=0, activity=0)
        m = snap["meta"]
        targets.append({
            "target": st.target, "status": snap["status"], "confirmed": snap["confirmed_count"],
            "severity": snap["severity"], "cost": m.get("cost_usd") or 0, "done": snap["done"],
            "surface_total": snap["surface_total"], "round": m.get("round"),
            "started_at": m.get("started_at"),
        })
        tot_conf += snap["confirmed_count"]
        tot_cost += m.get("cost_usd") or 0
    targets.sort(key=lambda t: (t["status"] not in LIVE, -(t["started_at"] or 0)))
    return {"version": config.VERSION, "targets": targets,
            "totals": {"confirmed": tot_conf, "cost": round(tot_cost, 4),
                       "live": sum(1 for t in targets if t["status"] in LIVE)}}


def queue_state() -> dict:
    if not config.QUEUE_ENABLED:
        return {"enabled": False, "jobs": [], "running": 0, "cap": config.MAX_HUNTS}
    from . import jobqueue
    q = jobqueue.get_queue()
    return {"enabled": True, "backend": q.kind, "cap": config.MAX_HUNTS,
            "running": q.running_count(), "jobs": q.snapshot()}


def start_hunt(p: dict) -> dict:
    target = config.normalize_target(p.get("target") or "")
    if not TARGET_RX.match(target):
        return {"ok": False, "error": "alvo inválido"}
    # Com a fila ativa, o painel enfileira (concorrência global, um alvo = uma
    # campanha). Um despachante/worker lança a caçada quando houver vaga.
    if config.QUEUE_ENABLED:
        from . import jobqueue
        q = jobqueue.get_queue()
        opts = {k: p.get(k) for k in ("workers", "timeout", "max_items", "continuous", "fresh", "no_nuclei", "scope")}
        job, created = q.enqueue(target, opts, priority=int(p.get("priority") or 5),
                                 who=p.get("who") or "painel")
        pos = next((j.get("position") for j in q.snapshot() if j["job_id"] == job["job_id"]), None)
        return {"ok": True, "queued": True, "created": created, "job_id": job["job_id"],
                "position": pos, "target": target,
                "message": ("enfileirado" if created else "já havia campanha para este alvo")}
    st = RunState(target)
    if st.status() in LIVE:
        return {"ok": False, "error": f"já existe uma caçada rodando em {target}"}
    st.stop_path.unlink(missing_ok=True)
    st.pause_path.unlink(missing_ok=True)
    argv = [str(config.FOSC_BIN), "-h", "-a", target,
            "--workers", str(max(1, min(12, int(p.get("workers") or config.DEFAULT_WORKERS)))),
            "--timeout", str(max(60, int(p.get("timeout") or config.DEFAULT_TASK_TIMEOUT)))]
    if p.get("max_items"):
        argv += ["--max-items", str(max(1, int(p["max_items"])))]
    if p.get("continuous"):
        argv += ["--continuous", "--interval", str(max(60, int(p.get("interval") or config.DEFAULT_CONTINUOUS_INTERVAL)))]
    if p.get("fresh"):
        argv.append("--fresh")
    if p.get("no_nuclei"):
        argv.append("--no-nuclei")
    scope = (p.get("scope") or "").strip()
    if scope:
        argv += ["--scope", scope[:500]]
    log = st.log_path.open("a")
    log.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} launched from viewer =====\n")
    log.flush()
    proc = subprocess.Popen(argv, cwd=str(config.REPO_ROOT), stdout=log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True, env=os.environ.copy())
    st.write_meta(target=target, pid=proc.pid, status="recon", started_at=time.time())
    return {"ok": True, "pid": proc.pid}


def control(p: dict) -> dict:
    target, action = (p.get("target") or "").strip(), p.get("action")
    if not target:
        return {"ok": False, "error": "alvo obrigatório"}
    if not config.run_exists(target):
        return {"ok": False, "error": "alvo desconhecido"}
    st = RunState(target)
    if action == "pause":
        st.pause_path.write_text("paused via viewer\n")
    elif action == "resume":
        st.pause_path.unlink(missing_ok=True)
    elif action == "stop":
        st.stop_path.write_text("stop requested via viewer\n")
        st.pause_path.unlink(missing_ok=True)
    else:
        return {"ok": False, "error": "ação inválida"}
    st.activity(None, f"{action} requested from viewer", kind="system")
    return {"ok": True}


def finding_detail(target: str, fid: str) -> dict:
    if not config.run_exists(target):
        return {"ok": False, "error": "alvo desconhecido"}
    st = RunState(target)
    for f in st.confirmed():
        if f.get("id") == fid:
            report = ""
            if f.get("report_path"):
                rp = (st.dir / f["report_path"]).resolve()
                if st.dir.resolve() in rp.parents and rp.exists():
                    report = rp.read_text(errors="replace")
                    # Always show a Windows-runnable PoC, even for reports written
                    # by an older run (the hunt process predates the pocfmt fix).
                    from . import pocfmt
                    report, _ = pocfmt.patch_markdown(report)
            return {"ok": True, "finding": f, "report": report}
    return {"ok": False, "error": "achado não encontrado"}


def task_log(target: str, iid: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{16}", iid or ""):
        return {"ok": False, "error": "id inválido"}
    if not config.run_exists(target):
        return {"ok": False, "error": "alvo desconhecido"}
    st = RunState(target)
    tdir = st.dir / "tasks" / iid
    return {"ok": True, "hunt": stream_to_text(tdir / "stream.jsonl"),
            "review": stream_to_text(tdir / "verify.stream.jsonl")}


CHAT_MODELS = {"sonnet", "opus", "haiku"}


def chat_history(target: str) -> dict:
    from .chat import ChatStore
    key = (target or "").strip() or "_global"
    store = ChatStore(key)
    return {"ok": True, "key": key, "target": (target or "").strip() or None,
            "messages": store.messages()[-200:], "live": store.live()}


def chat_send(p: dict) -> dict:
    from .chat import ChatStore
    message = str(p.get("message", ""))
    target = (p.get("target") or "").strip() or None
    model = str(p.get("model") or config.HUNT_MODEL)
    if model not in CHAT_MODELS:
        model = config.HUNT_MODEL
    key = target or "_global"
    store = ChatStore(key)
    state = RunState(target) if (target and config.run_exists(target)) else None
    scope = (state.read_meta().get("scope") if state else None) or target
    return store.post(message, state, target, scope, model, config.DEFAULT_TASK_TIMEOUT)


def get_config() -> dict:
    cfg = config.load_user_config()
    tok = cfg.get("telegram_token") or ""
    return {"telegram_configured": bool(tok and cfg.get("telegram_chat_id")),
            "telegram_chat_id": cfg.get("telegram_chat_id") or "",
            "telegram_token_masked": (tok[:6] + "…" + tok[-4:]) if len(tok) > 12 else ("•" * len(tok))}


def set_config(p: dict) -> dict:
    cfg = config.load_user_config()
    if p.get("telegram_token"):
        cfg["telegram_token"] = p["telegram_token"].strip()
    if "telegram_chat_id" in p:
        cfg["telegram_chat_id"] = str(p["telegram_chat_id"]).strip()
    config.save_user_config(cfg)
    return {"ok": True, **get_config()}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FOSC-TS-Viewer"
    port = 5555
    # Initialized only after Cognito configuration succeeds, before the port binds.
    auth: CognitoAuth | None = None

    def log_message(self, fmt, *args):
        pass

    # -- guards ----------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        allowed = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        if self.auth:
            allowed.add(urlparse(self.auth.settings.public_url).netloc.lower())
        return host in allowed

    def _post_ok(self) -> bool:
        if self.headers.get("X-FOSC") != "1":
            return False
        origin = self.headers.get("Origin")
        if self.auth:
            return origin == self.auth.settings.public_origin
        return origin in (None, f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}")

    def _session(self):
        return self.auth.session(self.headers) if self.auth else {}

    def _unauthenticated(self, path: str) -> bool:
        if not self.auth or self._session():
            return False
        if path.startswith("/api/"):
            self._json({"ok": False, "error": "authentication required"}, 401)
        else:
            self._redirect(f"{self.auth.settings.public_url}/auth/login")
        return True

    # -- responses -------------------------------------------------------
    def _send(self, body: bytes, ctype: str, status=200, headers: list[tuple[str, str]] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                         "connect-src 'self'; frame-ancestors 'none'")
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj).encode(), "application/json; charset=utf-8", status)

    def _redirect(self, location: str, cookies: list[str] | None = None):
        self._send(b"", "text/plain; charset=utf-8", 302,
                   [("Location", location)] + [("Set-Cookie", cookie) for cookie in (cookies or [])])

    def _auth_callback(self, query: dict[str, str]):
        login_url = f"{self.auth.settings.public_url}/auth/login"
        if query.get("error"):
            return self._send(_auth_error_page("Login cancelado ou não concluído.", login_url),
                              "text/html; charset=utf-8", 400)
        identity, cookies = self.auth.complete(self.headers, query)
        if not identity:
            return self._send(_auth_error_page("Não foi possível verificar o login.", login_url),
                              "text/html; charset=utf-8", 400,
                              [("Set-Cookie", cookie) for cookie in cookies])
        return self._redirect(f"{self.auth.settings.public_url}/", cookies)

    def do_GET(self):
        if not self._host_ok():
            return self._json({"error": "bad host"}, 403)
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}

        # The only unauthenticated routes when Cognito is enabled.
        if self.auth and u.path == "/auth/login":
            location, cookie = self.auth.begin()
            return self._redirect(location, [cookie])
        if self.auth and u.path == "/auth/callback":
            return self._auth_callback(q)
        if self.auth and u.path == "/auth/logout":
            location, cookies = self.auth.logout(self.headers)
            return self._redirect(location, cookies)

        if self._unauthenticated(u.path):
            return
        if u.path in STATIC:
            name, ctype = STATIC[u.path]
            body = (WEB_DIR / name).read_bytes() if name else b"/* live: sem mock */\n"
            return self._send(body, ctype)
        if u.path == "/api/session":
            return self._json({"ok": True, "enabled": bool(self.auth), "user": self._session()})
        if u.path == "/api/overview":
            return self._json(overview())
        if u.path == "/api/workspace":
            from . import wsview
            return self._json(wsview.workspace(q.get("target")))
        if u.path == "/api/campaigns":
            from . import wsview
            return self._json(wsview.campaigns())
        if u.path == "/api/state":
            if not q.get("target"):
                return self._json({"error": "target obrigatório"}, 400)
            if not config.run_exists(q["target"]):
                return self._json({"error": "alvo desconhecido"}, 404)
            return self._json(RunState(q["target"]).snapshot())
        if u.path == "/api/finding":
            return self._json(finding_detail(q.get("target", ""), q.get("id", "")))
        if u.path == "/api/log":
            return self._json(task_log(q.get("target", ""), q.get("item_id", "")))
        if u.path == "/api/config":
            return self._json(get_config())
        if u.path == "/api/chat":
            return self._json(chat_history(q.get("target", "")))
        if u.path == "/api/knowledge":
            return self._json({"playbook": knowledge.read_playbook(), "stats": knowledge.stats_summary(),
                               "lessons": knowledge.all_lessons(200)})
        if u.path == "/api/queue":
            return self._json(queue_state())
        if u.path == "/api/events":
            return self._sse(q.get("target"))
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._host_ok():
            return self._json({"error": "forbidden"}, 403)
        if self._unauthenticated(urlparse(self.path).path):
            return
        if not self._post_ok():
            return self._json({"error": "forbidden"}, 403)
        length = min(int(self.headers.get("Content-Length") or 0), 200_000)
        try:
            p = json.loads(self.rfile.read(length).decode() or "{}") if length else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._json({"error": "json inválido"}, 400)
        path = urlparse(self.path).path
        try:
            if path == "/api/hunt":
                return self._json(start_hunt(p))
            if path == "/api/control":
                return self._json(control(p))
            if path == "/api/approval":
                from . import wsview
                return self._json(wsview.resolve_approval(
                    (p.get("target") or "").strip(), str(p.get("id") or ""), str(p.get("decision") or "")))
            if path == "/api/halt":
                from . import wsview
                return self._json(wsview.halt((p.get("target") or "").strip()))
            if path == "/api/chat":
                return self._json(chat_send(p))
            if path == "/api/config":
                return self._json(set_config(p))
            if path == "/api/telegram/test":
                ok, err = send_telegram("✅ <b>FOSC/TS</b>: notificações do Telegram funcionando.")
                return self._json({"ok": ok, "error": err})
            if path == "/api/knowledge/playbook":
                knowledge.write_playbook(str(p.get("text", ""))[:20000])
                return self._json({"ok": True})
            if path == "/api/knowledge/delete":
                return self._json({"ok": knowledge.delete_lesson(str(p.get("id", "")))})
        except (ValueError, TypeError) as e:
            return self._json({"ok": False, "error": str(e)}, 400)
        return self._json({"error": "not found"}, 404)

    def _sse(self, target):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        last = {}
        try:
            while True:
                # Recheck so an expired opaque session does not retain a live feed.
                if self.auth and not self._session():
                    return
                payloads = {"overview": overview()}
                if target and config.run_exists(target):
                    payloads["state"] = RunState(target).snapshot()
                for name, obj in payloads.items():
                    body = json.dumps(obj)
                    h = hashlib.sha1(body.encode()).hexdigest()
                    if last.get(name) != h:
                        last[name] = h
                        self.wfile.write(f"event: {name}\ndata: {body}\n\n".encode())
                self.wfile.write(b": ping\n\n")
                self.wfile.flush()
                time.sleep(1.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def run_viewer(port: int, preselect_target: str | None = None):
    # Validate authentication before binding so an incomplete Cognito setup
    # cannot accidentally leave the operator dashboard unprotected.
    settings = CognitoSettings.from_environment(port)
    Handler.port = port
    Handler.auth = CognitoAuth(settings) if settings else None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    url = f"http://127.0.0.1:{port}/" + (f"#/t/{preselect_target}" if preselect_target else "")
    auth_note = " · Cognito login required" if settings else " · Cognito disabled"
    location = settings.public_url if settings else url
    print(f"[fosc] viewer: {location}/  (127.0.0.1 only{auth_note}; Ctrl+C para fechar; caçadas continuam rodando)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        Handler.auth = None
