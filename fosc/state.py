"""Run-persisted state for one target. Survives restarts.

Only the hunt process writes most of these files; the viewer and `fosc -w`
just read them (the viewer also writes the PAUSE/STOP control files).

  meta.json        target, pid, status, round, workers, cost, timestamps
  done.json        dedup set of hunted item ids
  results.jsonl    every task result (any verdict)
  confirmed.jsonl  deduplicated confirmed findings (class + route pattern)
  active.json      in-flight tasks
  activity.jsonl   live feed lines from the agents
  PAUSE / STOP     control files
"""
import json
import os
import threading
import time
import uuid
from pathlib import Path

from . import config
from .recon import item_id

ACTIVITY_MAX_BYTES = 2_000_000

# Ordered buckets: the agent writes free-text vuln classes ("path traversal /
# LFI", "Local File Inclusion (CWE-98)…"), which splits dedup. We canonicalize to
# a slug so the same bug on the same endpoint collapses regardless of wording.
# Order matters: the injection/exec classes win over generic "disclosure".
_CLASS_BUCKETS = [
    ("rce", ("remote code execution", "command injection", " rce", "webshell", "code execution", "deserial")),
    ("sqli", ("sql injection", "sqli", "union-based", "union based", "blind sql", "time-based sql")),
    ("lfi", ("local file inclusion", "lfi", "path traversal", "arbitrary file read",
             "directory traversal", "file inclusion", "cwe-98", "cwe-22")),
    ("ssrf", ("ssrf", "server-side request", "server side request")),
    ("xxe", ("xxe", "xml external entity")),
    ("upload", ("unrestricted upload", "file upload", "arbitrary file upload")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("idor", ("idor", "insecure direct object", "broken object level")),
    ("ssti", ("ssti", "template injection")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("open-redirect", ("open redirect",)),
    ("auth-bypass", ("authentication bypass", "auth bypass", "broken auth",
                     "forgeable session", "session forgery")),
    ("info-disclosure", ("disclosure", "exposed", "credential", "backup", "sensitive information",
                         "config file", "source code", "information leak", "db credential")),
]


def canonical_class(vuln_class: str | None) -> str:
    s = (vuln_class or "").strip().lower()
    if not s:
        return "unknown"
    for slug, needles in _CLASS_BUCKETS:
        if any(n in s for n in needles):
            return slug
    return s[:40]


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(errors="replace").splitlines()
    if limit:
        lines = lines[-limit:]
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except json.JSONDecodeError:
            continue
    return out


def pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True


class RunState:
    def __init__(self, target: str, fresh: bool = False):
        self.target = target
        self.dir = config.run_dir(target)
        self.meta_path = self.dir / "meta.json"
        self.done_path = self.dir / "done.json"
        self.results_path = self.dir / "results.jsonl"
        self.confirmed_path = self.dir / "confirmed.jsonl"
        self.active_path = self.dir / "active.json"
        self.activity_path = self.dir / "activity.jsonl"
        self.stop_path = self.dir / "STOP"
        self.pause_path = self.dir / "PAUSE"
        self.log_path = self.dir / "hunt.log"
        self.privesc_path = self.dir / "privesc.json"
        self.claims_path = self.dir / "claims.json"
        self._lock = threading.Lock()
        if fresh:
            for p in (self.done_path, self.results_path, self.confirmed_path, self.active_path,
                      self.activity_path, self.stop_path, self.pause_path, self.privesc_path,
                      self.claims_path, self.dir / "surface.json"):
                p.unlink(missing_ok=True)
        self.done: set[str] = set(_read_json(self.done_path, []))

    # -- per-task paths -------------------------------------------------
    def task_dir(self, item: dict) -> Path:
        return self.dir / "tasks" / item_id(item)

    def stream_path(self, item: dict) -> Path:
        return self.task_dir(item) / "stream.jsonl"

    # -- meta -----------------------------------------------------------
    def read_meta(self) -> dict:
        return _read_json(self.meta_path, {})

    def write_meta(self, **fields):
        with self._lock:
            meta = _read_json(self.meta_path, {})
            meta.update(fields)
            self.meta_path.write_text(json.dumps(meta))

    def add_cost(self, usd: float):
        if not usd:
            return
        with self._lock:
            meta = _read_json(self.meta_path, {})
            meta["cost_usd"] = round(float(meta.get("cost_usd") or 0) + usd, 6)
            self.meta_path.write_text(json.dumps(meta))

    def status(self) -> str:
        meta = self.read_meta()
        if pid_alive(meta.get("pid")) and meta.get("status") in ("running", "paused", "sleeping", "recon"):
            if self.pause_path.exists():
                return "paused"
            return meta.get("status", "running")
        st = meta.get("status")
        if st in ("running", "paused", "sleeping", "recon"):
            return "crashed"
        return st or "idle"

    # -- dedup / results --------------------------------------------------
    def is_done(self, item: dict) -> bool:
        return item_id(item) in self.done

    def record(self, item: dict, result: dict) -> dict:
        rec = {"ts": time.time(), "item_id": item_id(item), "url": item["url"],
               "pattern": item.get("pattern"), **result}
        with self._lock:
            with self.results_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            self.done.add(item_id(item))
            self.done_path.write_text(json.dumps(sorted(self.done)))
        return rec

    def finding_key(self, vuln_class: str | None, pattern: str | None) -> str:
        return f"{canonical_class(vuln_class)}|{pattern or ''}"

    def confirmed(self) -> list[dict]:
        return _read_jsonl(self.confirmed_path)

    def has_confirmed(self, key: str) -> bool:
        return any(f.get("key") == key for f in self.confirmed())

    def claim_finding(self, key: str) -> bool:
        """Atomically reserve a finding key BEFORE the (slow) verification, so N
        parallel workers that each re-discover the same bug don't all add it.
        Returns True to the first claimer only."""
        with self._lock:
            claims = set(_read_json(self.claims_path, []))
            if key in claims:
                return False
            claims.add(key)
            self.claims_path.write_text(json.dumps(sorted(claims)))
            return True

    def add_confirmed(self, finding: dict) -> dict:
        finding = {"id": uuid.uuid4().hex[:10], "ts": time.time(), **finding}
        with self._lock:
            with self.confirmed_path.open("a") as f:
                f.write(json.dumps(finding) + "\n")
        return finding

    # -- privesc (once per run) ---------------------------------------------
    def claim_privesc(self) -> bool:
        """Atomically mark that the privesc stage is being run for this host.
        Returns True to the first caller only, so N parallel RCE findings don't
        all kick off a privesc attempt."""
        with self._lock:
            if self.privesc_path.exists():
                return False
            self.privesc_path.write_text(json.dumps({"claimed_at": time.time()}))
            return True

    def save_privesc(self, result: dict):
        self.privesc_path.write_text(json.dumps({"finished_at": time.time(), **result}))

    def privesc_result(self) -> dict:
        return _read_json(self.privesc_path, {})

    # -- active / activity --------------------------------------------------
    def set_active(self, item: dict, phase: str = "hunting"):
        with self._lock:
            active = _read_json(self.active_path, {})
            prev = active.get(item_id(item), {})
            active[item_id(item)] = {"url": item["url"], "pattern": item.get("pattern"),
                                     "started_at": prev.get("started_at", time.time()), "phase": phase}
            self.active_path.write_text(json.dumps(active))

    def unset_active(self, item: dict):
        with self._lock:
            active = _read_json(self.active_path, {})
            active.pop(item_id(item), None)
            self.active_path.write_text(json.dumps(active))

    def clear_active(self):
        with self._lock:
            self.active_path.write_text("{}")

    def read_active(self) -> dict:
        return _read_json(self.active_path, {})

    def activity(self, item: dict | None, msg: str, kind: str = "agent"):
        rec = {"ts": time.time(), "kind": kind, "msg": msg}
        if item:
            rec.update(item_id=item_id(item), url=item["url"])
        with self._lock:
            with self.activity_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            try:
                if self.activity_path.stat().st_size > ACTIVITY_MAX_BYTES:
                    tail = self.activity_path.read_text(errors="replace").splitlines()[-2000:]
                    self.activity_path.write_text("\n".join(tail) + "\n")
            except OSError:
                pass

    # -- control ---------------------------------------------------------------
    def should_stop(self) -> bool:
        return self.stop_path.exists()

    def is_paused(self) -> bool:
        return self.pause_path.exists()

    # -- snapshot for UIs -------------------------------------------------------
    def snapshot(self, results: int = 200, activity: int = 120) -> dict:
        confirmed = self.confirmed()
        sev = {s: 0 for s in config.SEVERITIES}
        for f in confirmed:
            s = (f.get("severity") or "info").lower()
            sev[s] = sev.get(s, 0) + 1
        res = _read_jsonl(self.results_path, results)
        res.reverse()
        verdicts: dict[str, int] = {}
        for r in _read_jsonl(self.results_path):
            verdicts[r.get("verdict", "?")] = verdicts.get(r.get("verdict", "?"), 0) + 1
        surface = _read_json(self.dir / "surface.json", {})
        total = len(surface.get("items", [])) if isinstance(surface, dict) else 0
        act = _read_jsonl(self.activity_path, activity)
        act.reverse()
        return {
            "target": self.target,
            "status": self.status(),
            "meta": self.read_meta(),
            "active": self.read_active(),
            "done": len(_read_json(self.done_path, [])),  # fresh from disk: watchers keep one RunState open
            "surface_total": total,
            "confirmed_count": len(confirmed),
            "severity": sev,
            "verdicts": verdicts,
            "confirmed": list(reversed(confirmed)),
            "results": res,
            "activity": act,
        }


def list_runs() -> list[RunState]:
    if not config.STATE_ROOT.exists():
        return []
    runs = []
    for d in sorted(config.STATE_ROOT.iterdir()):
        if not d.is_dir():
            continue
        meta = _read_json(d / "meta.json", {})
        runs.append(RunState(meta.get("target") or d.name))
    return runs
