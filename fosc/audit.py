"""Audit & Evidence Manager — tamper-evident chain of custody (challenge #8, R4).

One append-only JSONL ledger per run (`audit.jsonl`). Every record is hash-chained:
it stores `prev` (the previous record's hash) and `hash` = SHA-256(prev + canonical
payload). Any later edit, deletion or reordering breaks the chain, and `verify()`
reports the first broken link. This is the custody guarantee a bank needs: not just
"we found it", but a cryptographically verifiable record of HOW every step happened.

It records the whole governance story in chronological order:
  run_start · scope · plan (hypothesis/action/expected/stop) · approval_request ·
  approval_decision · command · task · finding · halt.

LGPD: `redact()` masks obvious personal data (emails, CPF, long card-like digit
runs) so evidence captured into the ledger is minimized to what proves the finding.
"""
import hashlib
import json
import re
import threading
import time
from pathlib import Path

_GENESIS = "0" * 64

# --- LGPD minimization ------------------------------------------------------
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_CPF = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_LONGNUM = re.compile(r"\b\d{13,19}\b")  # card / account-like runs


def redact(value):
    """Mask obvious PII while keeping it recognizable as 'present' (for evidence).
    Recurses through dict/list; leaves non-strings untouched."""
    if isinstance(value, str):
        v = _EMAIL.sub(lambda m: m.group(1) + "***" + m.group(2), value)
        v = _CPF.sub("***.***.***-**", v)
        v = _LONGNUM.sub(lambda m: m.group(0)[:4] + "*" * (len(m.group(0)) - 4), v)
        return v
    if isinstance(value, dict):
        return {k: redact(x) for k, x in value.items()}
    if isinstance(value, list):
        return [redact(x) for x in value]
    return value


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(prev: str, payload_canon: str) -> str:
    return hashlib.sha256((prev + payload_canon).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        last = _GENESIS
        if self.path.exists():
            for line in self.path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    def record(self, kind: str, actor: str | None = None, *, minimize: bool = False, **data) -> dict:
        """Append one hash-chained record. `minimize=True` runs the payload through
        the LGPD redactor first (use for anything that may hold personal data)."""
        if minimize:
            data = redact(data)
        with self._lock:
            prev = self._last_hash()
            payload = {"ts": round(time.time(), 3), "kind": kind, "actor": actor, "data": data}
            rec = {**payload, "prev": prev, "hash": _hash(prev, _canon(payload))}
            with self.path.open("a") as f:
                f.write(_canon(rec) + "\n")
                f.flush()
        return rec

    def entries(self) -> list[dict]:
        out = []
        if self.path.exists():
            for line in self.path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out

    def verify(self) -> tuple[bool, int, str]:
        """Walk the chain. Returns (ok, index_checked_or_broken, message). A broken
        link means the ledger was tampered with after the fact."""
        prev = _GENESIS
        entries = self.entries()
        for i, rec in enumerate(entries):
            try:
                payload = {k: rec[k] for k in ("ts", "kind", "actor", "data")}
            except KeyError:
                return (False, i, "malformed record")
            if rec.get("prev") != prev:
                return (False, i, f"broken link at #{i} (prev mismatch)")
            if _hash(prev, _canon(payload)) != rec.get("hash"):
                return (False, i, f"tampered content at #{i} (hash mismatch)")
            prev = rec["hash"]
        return (True, len(entries), f"chain intact · {len(entries)} records")
