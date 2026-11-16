"""Exploit-chaining pass.

After a round, FOSC confirms findings INDEPENDENTLY. A strong attacker combines
them: an IDOR plus a weak session becomes account takeover; an SSRF reaches cloud
metadata; an upload becomes RCE. This pass hands the already-verified findings to
an Opus session that tries to PROVE a single higher-severity chain end-to-end.

A chain only becomes a confirmed finding if it survives the SAME gates a normal
finding does: adversarial verification, then the Council. It never touches the
engine's state machine — it uses the existing RunState methods only.
"""
import hashlib
import json

from . import config, council, mitre, models
from .notify import notify_finding
from .prompts import CHAIN_SCHEMA, CHAIN_SYSTEM, build_chain_prompt
from .verify import verify_finding


def _signature(findings: list[dict]) -> str:
    ids = sorted(str(f.get("id") or f.get("key") or f.get("url")) for f in findings)
    return hashlib.sha1("|".join(ids).encode()).hexdigest()[:16]


def _attempted(state) -> set:
    p = state.dir / "chains.attempted.json"
    try:
        return set(json.loads(p.read_text())) if p.exists() else set()
    except (OSError, ValueError):
        return set()


def _mark_attempted(state, sig: str):
    p = state.dir / "chains.attempted.json"
    done = _attempted(state)
    done.add(sig)
    try:
        p.write_text(json.dumps(sorted(done)))
    except OSError:
        pass


def run_chain_pass(state, out, target: str, scope_note: str, audit_log=None):
    """Try to combine this run's confirmed findings into one higher-severity
    chain. Returns the new chained finding dict, or None. Idempotent per
    confirmed-set: the same set is never attempted twice."""
    if not config.CHAIN_ENABLED:
        return None
    # Only chain PRIMARY findings — never feed a chain back into itself (that
    # would change the signature every round and re-chain the chain).
    base = [f for f in state.confirmed() if not f.get("is_chain")]
    if len(base) < config.CHAIN_MIN_FINDINGS:
        return None
    sig = _signature(base)
    if sig in _attempted(state):
        return None
    _mark_attempted(state, sig)

    out.info(f"encadeamento: analisando {len(base)} achado(s) confirmado(s)")
    state.activity(None, f"passe de encadeamento: tentando combinar {len(base)} achado(s) "
                         f"em uma cadeia de maior impacto", kind="system")

    task_dir = state.dir / "chain"
    task_dir.mkdir(parents=True, exist_ok=True)

    def act(msg):
        state.activity(None, f"[chain] {msg}", kind="system")
        out.activity(f"[chain] {msg}")

    run = models.run("chain", build_chain_prompt(target, scope_note, base),
                     cwd=task_dir, timeout=config.DEFAULT_VERIFY_TIMEOUT,
                     stream_path=task_dir / "chain.stream.jsonl",
                     system_prompt=CHAIN_SYSTEM, schema=CHAIN_SCHEMA, on_activity=act,
                     effort=config.VERIFY_EFFORT)
    state.add_cost(run["cost"])
    if run["status"] != "ok" or not (run["output"] or {}).get("chained"):
        reason = "sem cadeia" if run["status"] == "ok" else run.get("error") or run["status"]
        state.activity(None, f"encadeamento: nenhuma cadeia comprovada ({reason})", kind="system")
        return None

    c = run["output"]
    comp_ids = [str(x) for x in (c.get("components") or [])]
    comps = [f for f in base if str(f.get("id")) in comp_ids] or base
    primary_url = comps[0].get("url") if comps else target
    chain_class = c.get("chain_class") or "exploit chain"
    key = state.finding_key(chain_class, f"chain:{sig}")
    if not state.claim_finding(key):
        return None

    item = {"url": primary_url, "pattern": f"chain:{sig}"}
    finding = {
        "key": key, "url": primary_url, "pattern": f"chain:{sig}",
        "vuln_class": chain_class, "severity": c.get("severity") or "high",
        "cvss": c.get("cvss"), "confidence": c.get("confidence") or "medium",
        "title": c.get("title") or chain_class,
        "summary": c.get("summary", ""), "impact": c.get("impact"),
        "steps": c.get("steps") or [], "repro_curl": c.get("repro_curl"),
        "evidence_marker": c.get("evidence_marker"), "poc_path": c.get("poc_path"),
        "is_chain": True, "chain_components": comp_ids,
        "mitre": mitre.techniques(chain_class), "item_id": f"chain:{sig}",
    }

    # Same gates as any finding: adversarial verification first.
    act("entregando a cadeia ao revisor Opus")
    review = verify_finding(scope_note, item, finding, task_dir, on_activity=act)
    state.add_cost(review.get("cost", 0))
    if review["verdict"] != "confirmed":
        state.activity(None, f"encadeamento refutado na verificação: {(review.get('reason') or '')[:200]}",
                       kind="system")
        return None
    finding["severity"] = review.get("severity") or finding["severity"]
    finding["cvss"] = review.get("cvss") if review.get("cvss") is not None else finding["cvss"]
    finding["confidence"] = review.get("confidence") or finding["confidence"]
    finding["review"] = review.get("reason")

    # Then the Council (veto suppresses; else reclassifies severity/confidence).
    if config.COUNCIL_ENABLED:
        decisao = council.revisar(finding, item, scope_note, task_dir, on_activity=act)
        state.add_cost(decisao.get("custo", 0))
        finding["council"] = decisao
        if audit_log:
            audit_log.record("council", minimize=True, url=primary_url,
                             aprovado=decisao["aprovado"], severidade=decisao["severidade_final"],
                             chain=True)
        if not decisao["aprovado"]:
            state.activity(None, "conselho vetou a cadeia: " +
                           "; ".join(f"{v['cadeira']}: {v['motivo']}" for v in decisao["motivos_veto"])[:300],
                           kind="system")
            return None
        finding["severity"] = decisao["severidade_final"]
        finding["confidence"] = decisao["confianca_final"]
        finding["lgpd"] = decisao["lgpd_dado_pessoal"]
        finding["cia_pilares"] = decisao["cia_pilares"]
        finding["risco_corporativo"] = decisao["risco_corporativo"]

    finding = state.add_confirmed(finding)
    try:
        from .report import write_report
        finding["report_path"] = write_report(state.dir, finding["id"], target, item, finding,
                                               review, task_dir)
    except Exception as e:
        out.warn(f"chain report error: {e}")
    if audit_log:
        audit_log.record("finding", minimize=True, id=finding["id"], url=primary_url,
                         vuln_class=finding["vuln_class"], severity=finding["severity"],
                         chain=True, components=comp_ids)
    state.activity(None, f"CADEIA CONFIRMADA ({finding['severity']}): {chain_class} "
                         f"combinando {len(comp_ids) or len(comps)} achado(s)", kind="result")
    out.confirmed(finding)
    ok, err = notify_finding(target, finding)
    if not ok and err != "telegram not configured":
        state.activity(None, f"telegram failed: {err}", kind="system")
    return finding
