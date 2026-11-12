"""Authorization Engine — human-in-the-loop gate before sensitive actions.

Autonomy is not unrestricted autonomy: finding something is not authorization to
act on it. Before any SENSITIVE action (active exploitation, privilege escalation,
database scan, reverse shell) the agent STOPS, records an authenticated approval
request, and proceeds only after a human approves. Passive recon is auto-approved.

Headless-friendly (AWS/Kiro): a pending request is written to the run's append-only
approvals log; a human decides via `fosc --approve <id>` or the web panel. In an
interactive terminal it prompts inline. Every request and decision is attributed
and logged — this log is the first link of the chain of custody (Audit & Evidence).
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import config

# action type -> risk. Unknown defaults to SENSITIVE (fail safe).
_PASSIVE = {"recon", "passive", "read", "enumerate", "fingerprint", "discovery"}
_SENSITIVE = {"active-hunt", "exploit", "exploitation", "privilege-escalation",
              "db-scan", "database-scan", "reverse-shell", "upload", "write",
              "lateral-movement", "data-exfil", "credential-access"}


def risk(action_type: str) -> str:
    a = (action_type or "").strip().lower()
    if a in _PASSIVE:
        return "passive"
    return "sensitive"  # sensitive or unknown -> treat as sensitive


def operator() -> str:
    """Who is accountable for an approval. Real deployments bind this to an
    authenticated identity; here it comes from the environment / git identity."""
    env = os.environ.get("SENTINELA_OPERATOR") or os.environ.get("USER")
    if env:
        return env
    try:
        import subprocess
        out = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=3)
        if out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return "operador"


@dataclass
class Decision:
    approved: bool
    status: str          # approved | denied | auto | pending | expired
    id: str
    approver: str = ""
    reason: str = ""


class ApprovalStore:
    """Append-only event log of approval requests and decisions for one run.

    Events (one JSON per line): {"type":"request"|"decision", "id", "ts", ...}.
    Append-only so it doubles as tamper-evident custody evidence; status is
    derived from the latest decision event for an id.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, ev: dict):
        with self.path.open("a") as f:
            f.write(json.dumps(ev) + "\n")

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def request(self, action: str, target: str, rsk: str, context: str) -> str:
        rid = uuid.uuid4().hex[:10]
        self._append({"type": "request", "id": rid, "ts": time.time(), "action": action,
                      "target": target, "risk": rsk, "context": context, "status": "pending"})
        return rid

    def decide(self, rid: str, approved: bool, approver: str, reason: str = ""):
        self._append({"type": "decision", "id": rid, "ts": time.time(),
                      "approved": bool(approved), "approver": approver, "reason": reason})

    def status(self, rid: str) -> str:
        st = "pending"
        for ev in self._events():
            if ev.get("id") == rid and ev.get("type") == "decision":
                st = "approved" if ev.get("approved") else "denied"
        return st

    def request_meta(self, rid: str) -> dict:
        for ev in self._events():
            if ev.get("id") == rid and ev.get("type") == "request":
                return ev
        return {}

    def pending(self) -> list[dict]:
        reqs = {e["id"]: e for e in self._events() if e.get("type") == "request"}
        for e in self._events():
            if e.get("type") == "decision":
                reqs.pop(e.get("id"), None)
        return list(reqs.values())


def require(store: ApprovalStore, action: str, target: str, context: str = "", *,
            mode: str | None = None, interactive: bool | None = None,
            wait: bool = True, timeout: int | None = None,
            on_notice=None) -> Decision:
    """The gate. Returns a Decision; the caller runs the action only if approved.

    mode: 'ask' (human-in-the-loop, default), 'yolo' (auto-approve, lab only),
          'paranoid' (approve EVERYTHING, even passive).
    """
    mode = (mode or config.AUTHZ_MODE or "ask").lower()
    rsk = risk(action)

    # passive auto-approve (unless paranoid), always logged
    if rsk == "passive" and mode != "paranoid":
        rid = store.request(action, target, rsk, context)
        store.decide(rid, True, "auto", "ação passiva auto-aprovada")
        return Decision(True, "auto", rid, "auto")

    if mode == "yolo":
        rid = store.request(action, target, rsk, context)
        store.decide(rid, True, operator(), "modo yolo (laboratório)")
        return Decision(True, "auto", rid, operator(), "yolo")

    # sensitive -> needs a human
    rid = store.request(action, target, rsk, context)
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()

    if interactive:
        who = operator()
        try:
            ans = input(f"\n\033[1;33m⚠ AUTORIZAÇÃO NECESSÁRIA\033[0m [{who}]\n"
                        f"  ação: {action}  (risco: {rsk})\n  alvo: {target}\n"
                        f"  {context}\n  aprovar? [s/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        approved = ans in ("s", "sim", "y", "yes")
        store.decide(rid, approved, who, "aprovação interativa")
        return Decision(approved, "approved" if approved else "denied", rid, who)

    # headless: wait for an external decision (fosc --approve / painel)
    if on_notice:
        on_notice(f"aguardando autorização humana: {action} em {target} "
                  f"(id {rid}) — rode: fosc --approve {rid}")
    if not wait:
        return Decision(False, "pending", rid)
    deadline = time.time() + (timeout if timeout is not None else config.AUTHZ_TIMEOUT)
    while time.time() < deadline:
        st = store.status(rid)
        if st != "pending":
            return Decision(st == "approved", st, rid)
        time.sleep(config.AUTHZ_POLL)
    return Decision(False, "expired", rid, reason="timeout sem aprovação")
