"""Privilege-escalation follow-up — the post-RCE stage.

When a web finding gives real command execution on the host (shell_obtained),
the engine runs this once per host: a dedicated agent reuses that exec channel
to enumerate and escalate toward root, honestly reporting what worked and what
was blocked. This is where FOSC stops being "just" a web scanner and tries to
own the box.

The stage is PERSISTENT: it runs up to PRIVESC_MAX_PASSES. A pass that doesn't
escalate but leaves researchable leads feeds its own enumeration + unfinished
vectors into the next pass (which researches/installs and retries), sharing one
budget across the whole stage. It stops early on a win, or when a pass leaves no
researchable lead to resume from.
"""
import time
from pathlib import Path

from . import config, knowledge, models
from .prompts import PRIVESC_SCHEMA, PRIVESC_SYSTEM, build_privesc_prompt

# fields worth mining a confirmed finding for leaked credentials/secrets
_LOOT_FIELDS = ("summary", "impact", "evidence", "repro_curl", "repro", "steps")
_LOOT_NEEDLES = ("cred", "senha", "password", "passwd", "root/", "root:", "token",
                 "secret", "api key", "apikey", ".ini", ".env", "backup.sql",
                 "mysql", "db_pass", "private key", "ssh")


def _loot(state) -> str:
    """Structured digest of creds/secrets already surfaced, with the REAL values,
    so the privesc agent can actually attempt reuse instead of guessing."""
    bits = []
    for f in state.confirmed():
        blob_parts = []
        for k in _LOOT_FIELDS:
            v = f.get(k)
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            if v:
                blob_parts.append(str(v))
        blob = " ".join(blob_parts)
        low = blob.lower()
        if not any(n in low for n in _LOOT_NEEDLES):
            continue
        # keep the credential-bearing text (trimmed), not just the class name
        snippet = blob.strip().replace("\n", " ")
        if len(snippet) > 320:
            snippet = snippet[:320] + "…"
        bits.append(f"- [{f.get('vuln_class')}] {f.get('url')}: {snippet}")
    return "\n".join(bits[:10])


def _prior_block(pv: dict) -> str:
    """Format a finished pass's leads for the next pass's prompt."""
    out = []
    enum = pv.get("enumeration") or []
    if enum:
        out.append("Enumeration already done:\n" + "\n".join(f"  - {e}" for e in enum[:20]))
    att = pv.get("attempts") or []
    live = [a for a in att if a.get("status") in ("blocked", "partial", "untested")]
    if att:
        out.append("Vectors tried:\n" + "\n".join(
            f"  - [{a.get('status')}{'/researchable' if a.get('researchable') else ''}] "
            f"{a.get('vector')}: {a.get('detail') or ''}" for a in att[:20]))
    dead = [b for b in (pv.get("blocked") or [])]
    if dead:
        out.append("Confirmed dead ends (do NOT repeat):\n" + "\n".join(f"  - {b}" for b in dead[:20]))
    ns = pv.get("next_steps") or []
    if ns:
        out.append("Suggested next steps:\n" + "\n".join(f"  - {n}" for n in ns[:12]))
    _ = live  # leads are highlighted inline via the researchable flag above
    return "\n\n".join(out)


def _has_live_lead(pv: dict) -> bool:
    """Is there anything a follow-up pass could realistically resume from?"""
    if any(a.get("researchable") and a.get("status") in ("blocked", "partial", "untested")
           for a in (pv.get("attempts") or [])):
        return True
    return bool(pv.get("next_steps"))


def _merge(acc: dict, pv: dict):
    """Fold a pass result into the accumulator (dedup list fields, keep latest scalars)."""
    for k in ("enumeration", "attempts", "blocked", "lessons", "tools_installed",
              "next_steps", "steps"):
        seen = acc.setdefault(k, [])
        for v in (pv.get(k) or []):
            key = v if isinstance(v, str) else str(sorted(v.items())) if isinstance(v, dict) else str(v)
            if key not in {x if isinstance(x, str) else str(sorted(x.items())) if isinstance(x, dict) else str(x)
                           for x in seen}:
                seen.append(v)
    for k in ("escalated", "from_user", "to_user", "vector", "summary", "evidence",
              "repro", "severity", "in_container", "container_escape_possible", "host_reached"):
        if pv.get(k) not in (None, "", [], False) or k not in acc:
            acc[k] = pv.get(k)


def _write_report(state, target: str, finding: dict, pv: dict) -> str:
    sev = (pv.get("severity") or ("critical" if pv.get("escalated") else "info")).upper()
    cont = pv.get("in_container")
    cont_line = "desconhecido" if cont is None else (
        "sim" + (" — escape p/ host POSSÍVEL" if pv.get("container_escape_possible")
                 else " — isolado (sem escape p/ host)" if pv.get("container_escape_possible") is False
                 else "") if cont else "não (host direto)")
    lines = [
        f"# Privilege escalation — {target}",
        "",
        f"- **Resultado:** {'ESCALOU' if pv.get('escalated') else 'não escalou'}"
        f" ({pv.get('from_user') or '?'} → {pv.get('to_user') or '?'})",
        f"- **Root no HOST alcançado:** {'sim' if pv.get('host_reached') else 'não'}",
        f"- **Container:** {cont_line}",
        f"- **Vetor:** {pv.get('vector') or '-'}",
        f"- **Severidade:** {sev}",
        f"- **Passes:** {pv.get('passes', 1)}",
        f"- **Origem (RCE):** {finding.get('vuln_class')} @ {finding.get('url')}",
        "",
        "## Resumo",
        pv.get("summary") or "-",
        "",
    ]
    if pv.get("steps"):
        lines += ["## Passos"] + [f"{i}. {s}" for i, s in enumerate(pv["steps"], 1)] + [""]
    if pv.get("evidence"):
        lines += ["## Evidência", "```", pv["evidence"], "```", ""]
    if pv.get("repro"):
        lines += ["## Reprodução", "```", pv["repro"], "```", ""]
    if pv.get("attempts"):
        lines += ["## Vetores testados"]
        for a in pv["attempts"]:
            flag = " _(pesquisável)_" if a.get("researchable") else ""
            lines.append(f"- **[{a.get('status')}]** {a.get('vector')}{flag} — {a.get('detail') or ''}")
        lines += [""]
    if pv.get("enumeration"):
        lines += ["## Enumeração relevante"] + [f"- {e}" for e in pv["enumeration"]] + [""]
    if pv.get("blocked"):
        lines += ["## Dead ends"] + [f"- {b}" for b in pv["blocked"]] + [""]
    if pv.get("next_steps"):
        lines += ["## Próximos passos (resumo p/ operador)"] + [f"- {n}" for n in pv["next_steps"]] + [""]
    path = Path(state.dir) / "privesc_report.md"
    path.write_text("\n".join(lines))
    return str(path)


def _one_pass(state, target, scope_note, finding, exec_howto, looted, prior,
              on_activity, timeout, budget, pass_no) -> dict:
    prompt = build_privesc_prompt(target, scope_note, finding, exec_howto, looted, prior)
    arsenal = knowledge.read_tools()
    if arsenal:
        prompt += f"\nArsenal já instalado pelo FOSC (reutilize em vez de reinstalar):\n{arsenal}\n"
    run = models.run(
        "privesc",
        prompt,
        cwd=Path(state.dir) / "privesc",
        timeout=timeout,
        stream_path=Path(state.dir) / f"privesc.pass{pass_no}.stream.jsonl",
        system_prompt=PRIVESC_SYSTEM,
        schema=PRIVESC_SCHEMA,
        on_activity=(lambda m: on_activity(f"[privesc p{pass_no}] {m}")) if on_activity else None,
        effort=config.HUNT_EFFORT,
        budget=budget,
    )
    state.add_cost(run["cost"])
    if run["status"] != "ok":
        return {"_error": run.get("error") or run["status"], "_status": run["status"],
                "cost": run["cost"]}
    out = run["output"] or {}
    out["cost"] = run["cost"]
    return out


def attempt_privesc(state, target: str, scope_note: str, finding: dict, on_activity=None,
                    timeout: int | None = None) -> dict:
    """Run the privesc stage (up to PRIVESC_MAX_PASSES). Returns the merged
    structured result (+ cost, passes, report_path)."""
    exec_howto = (finding.get("shell_howto") or "").strip()
    if not exec_howto or "__CMD__" not in exec_howto:
        return {"escalated": False, "summary": "no usable exec channel (shell_howto missing __CMD__)",
                "skipped": True, "cost": 0.0, "passes": 0}

    per_pass_timeout = timeout or config.PRIVESC_TIMEOUT
    total_budget = config.PRIVESC_BUDGET_USD
    looted = _loot(state)
    acc: dict = {"cost": 0.0}
    prior = ""
    last = {}

    for pass_no in range(1, config.PRIVESC_MAX_PASSES + 1):
        remaining = (total_budget - acc["cost"]) if total_budget else config.DEFAULT_TASK_BUDGET_USD
        if total_budget and remaining < 0.5:  # not enough left for a useful pass
            break
        pv = _one_pass(state, target, scope_note, finding, exec_howto, looted, prior,
                       on_activity, per_pass_timeout, remaining, pass_no)
        acc["cost"] = round(acc["cost"] + pv.get("cost", 0.0), 6)
        if pv.get("_error"):
            if not last:  # first pass failed outright
                return {"escalated": False, "summary": pv["_error"], "status": pv["_status"],
                        "cost": acc["cost"], "passes": pass_no}
            break
        _merge(acc, pv)
        last = pv
        if pv.get("escalated"):
            break
        if not _has_live_lead(pv):
            break  # nothing researchable to resume from — stop burning budget
        prior = _prior_block(pv)  # feed this pass's leads into the next

    acc["passes"] = pass_no
    acc.setdefault("escalated", False)
    acc.setdefault("summary", last.get("summary", "privesc stage produced no result"))
    acc["report_path"] = _write_report(state, target, finding, acc)
    _record(state, target, finding, acc)
    return acc


def _record(state, target: str, finding: dict, pv: dict):
    """Feed the knowledge flywheel from the merged result."""
    tech = finding.get("tech") or []
    if pv.get("escalated"):
        knowledge.add_lesson("win", f"privesc {pv.get('from_user')}→{pv.get('to_user')} via "
                             f"{pv.get('vector')}: {(pv.get('summary') or '')[:260]}",
                             target, {"pattern": "host"}, "privilege-escalation", tech)
        knowledge.note_target(target, f"PRIVESC: {pv.get('from_user')}→{pv.get('to_user')} via {pv.get('vector')}"
                              + (" (root no host)" if pv.get("host_reached") else " (root de container, isolado)"
                                 if pv.get("in_container") else ""))
    else:
        for a in (pv.get("attempts") or []):
            if a.get("status") == "blocked":
                knowledge.note_target(target, f"privesc blocked: {a.get('vector')} — {(a.get('detail') or '')[:160]}")
        for b in (pv.get("blocked") or [])[:4]:
            knowledge.note_target(target, f"privesc blocked: {b}")
    if pv.get("in_container"):
        knowledge.note_target(target, f"host é container; escape p/ host "
                              f"{'possível' if pv.get('container_escape_possible') else 'não encontrado'}")
    for les in (pv.get("lessons") or [])[:4]:
        knowledge.add_lesson("note", f"privesc: {les}", target, {"pattern": "host"},
                             "privilege-escalation", tech)
    for tool in (pv.get("tools_installed") or []):
        knowledge.note_tool(tool)
