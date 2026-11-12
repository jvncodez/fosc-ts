"""Adversarial verification before anything is called "confirmed".

A fresh Opus session gets the claimed finding plus the agent's PoC and is
told to refute it like a strict triager. FOSC itself never replays the
agent's requests; the reviewer reproduces whatever it needs inside its own
sandboxed session.

  survives      -> confirmed
  refuted       -> refuted (and the reason becomes a false-positive lesson)
  error/timeout -> unverified (never silently promoted to confirmed)
"""
from pathlib import Path

from . import config
from .claude_runner import run_claude
from .prompts import VERIFY_SCHEMA, VERIFY_SYSTEM, build_verify_prompt


def _read_poc(task_dir: Path, poc_path: str | None) -> str:
    if not poc_path:
        return ""
    try:
        p = (task_dir / poc_path).resolve()
        if task_dir.resolve() not in p.parents and p != task_dir.resolve():
            return ""  # only read files the agent wrote inside its own task dir
        if p.is_dir():
            parts = []
            for f in sorted(p.iterdir())[:5]:
                if f.is_file() and f.stat().st_size < 200_000:
                    parts.append(f"--- {f.name} ---\n{f.read_text(errors='replace')}")
            return "\n".join(parts)
        if p.is_file() and p.stat().st_size < 500_000:
            return p.read_text(errors="replace")
    except OSError:
        pass
    return ""


def verify_finding(scope_note: str, item: dict, finding: dict, task_dir: Path, on_activity=None,
                   timeout: int = config.DEFAULT_VERIFY_TIMEOUT) -> dict:
    poc_text = _read_poc(task_dir, finding.get("poc_path"))
    run = run_claude(
        build_verify_prompt(scope_note, item, finding, poc_text),
        cwd=task_dir / "verify",
        timeout=timeout,
        stream_path=task_dir / "verify.stream.jsonl",
        model=config.VERIFY_MODEL,
        system_prompt=VERIFY_SYSTEM,
        schema=VERIFY_SCHEMA,
        on_activity=(lambda m: on_activity(f"[review] {m}")) if on_activity else None,
        effort=config.VERIFY_EFFORT,
    )
    out = run["output"] or {}
    if run["status"] != "ok":
        return {"verdict": "unverified", "reason": run["error"] or run["status"], "cost": run["cost"]}
    return {
        "verdict": "confirmed" if out.get("survives") else "refuted",
        "reason": out.get("reason", ""),
        "severity": out.get("severity") or finding.get("severity"),
        "cvss": out.get("cvss") if out.get("cvss") is not None else finding.get("cvss"),
        "vuln_class": out.get("vuln_class") or finding.get("vuln_class"),
        "lesson": out.get("lesson"),
        "cost": run["cost"],
    }
