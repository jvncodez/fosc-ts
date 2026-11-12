"""Adapta o estado REAL do motor ao shape do front da Ana
(`web/src/services/api.js`): campaign · policies · plan · commands · approvals ·
findings · audit.

Camada só de leitura/tradução — NÃO altera a engine de caça. O front não muda de
estrutura: consome exatamente os mesmos campos do mock, agora com dados reais.
"""
import hashlib
import json
import os
import signal
import time
from pathlib import Path

from . import authz, config
from .authz import ApprovalStore, operator
from .state import RunState, list_runs

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
_CONF_NUM = {"high": 0.92, "medium": 0.68, "low": 0.4, "alta": 0.92, "media": 0.68, "baixa": 0.4}
# status da engine -> status do front (draft/running/completed/interrupted)
_STATUS = {"running": "running", "recon": "running", "sleeping": "running", "paused": "running",
           "finished": "completed", "done": "completed", "stopped": "interrupted",
           "halted": "interrupted", "error": "interrupted", "denied": "interrupted",
           "refused": "interrupted", "crashed": "interrupted", "idle": "draft", "none": "draft"}


def _map_status(raw: str) -> str:
    # Fail-safe: um status desconhecido NUNCA vira "running" (não alega campanha
    # viva sem estar). Qualquer estado vivo real já está mapeado explicitamente.
    return _STATUS.get(raw, "interrupted")


def _fmt(ts) -> str:
    if not ts:
        return "—"
    try:
        lt, now = time.localtime(float(ts)), time.localtime()
        hm = time.strftime("%H:%M:%S", lt)
        return f"Hoje, {hm}" if lt.tm_yday == now.tm_yday and lt.tm_year == now.tm_year \
            else time.strftime("%d/%m %H:%M", lt)
    except (ValueError, TypeError, OSError):
        return "—"


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-limit:] if limit else rows


def _asset(url: str) -> str:
    u = (url or "").replace("https://", "").replace("http://", "")
    return u.split("/")[0] or u


def _conf_num(f: dict) -> float:
    c = f.get("council") or {}
    v = c.get("confianca_final") or f.get("confidence") or "medium"
    return _CONF_NUM.get(str(v).lower(), 0.6)


# --------- as 7 coleções do workspace -------------------------------------

def _scope_id(target: str) -> str:
    return "SCP-" + hashlib.sha1(target.encode()).hexdigest()[:6].upper()


def _campaign(st: RunState | None, snap: dict) -> dict:
    if not st:
        return {"id": "—", "name": "Nenhuma campanha", "target": "", "status": "draft",
                "progress": 0, "startedAt": None, "owner": operator(), "scopeId": "—"}
    m = snap["meta"]
    total = snap.get("surface_total") or 0
    done = snap.get("done") or 0
    progress = int(done / total * 100) if total else (100 if snap["status"] in ("finished", "done") else 0)
    return {"id": st.target, "name": f"Campanha — {st.target}", "target": st.target,
            "status": _map_status(snap["status"]), "progress": progress,
            "startedAt": _fmt(m.get("started_at")), "owner": operator(),
            "scopeId": _scope_id(st.target),
            "cost": round(m.get("cost_usd") or 0, 2), "confirmed": snap.get("confirmed_count") or 0}


# Rótulos PT para os action-types reais do Authorization Engine (authz.tiers()).
# Um token sem rótulo aqui aparece como ele mesmo — nada é inventado.
_ACTION_PT = {
    "recon": "Reconhecimento e enumeração passiva", "passive": "Coleta passiva (sem alterar estado)",
    "read": "Leitura de respostas dentro do escopo", "enumerate": "Enumeração de endpoints e parâmetros",
    "fingerprint": "Fingerprint de tecnologia", "discovery": "Descoberta de superfície (mineração do JS da SPA)",
    "active-hunt": "Teste ativo de vulnerabilidade", "exploit": "Exploração de vulnerabilidade",
    "exploitation": "Exploração de vulnerabilidade", "privilege-escalation": "Escalada de privilégio",
    "db-scan": "Varredura de banco de dados", "database-scan": "Varredura de banco de dados",
    "reverse-shell": "Shell reverso / execução remota", "upload": "Upload de arquivo",
    "write": "Ação que altera estado (write)", "lateral-movement": "Movimentação lateral",
    "data-exfil": "Exfiltração de dados", "credential-access": "Acesso a credenciais",
    "destroy": "Destruição de dados", "delete-data": "Apagamento de dados", "ransom": "Ransomware / extorsão",
    "encrypt-data": "Criptografia de dados da vítima", "dos": "Negação de serviço (DoS)",
    "ddos": "Negação de serviço distribuída (DDoS)", "denial-of-service": "Negação de serviço",
    "phishing": "Phishing", "social-engineering": "Engenharia social",
    "exfil-pii-bulk": "Exfiltração em massa de PII", "modify-production-data": "Modificação de dados de produção",
    "disable-logging": "Desativar logging / telemetria", "persistence": "Persistência no alvo",
}


def _tier_items(tokens: list[str]) -> list[str]:
    out, seen = [], set()
    for t in tokens:
        label = _ACTION_PT.get(t, t)
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _policies(st: RunState | None = None) -> dict:
    """As três listas vêm dos tiers determinísticos REAIS do Authorization Engine
    (authz.tiers()): passivas auto-aprovadas / sensíveis exigem aprovação humana /
    proibidas recusadas automaticamente. Em 'allowed' entra ainda o escopo real da
    campanha (meta.scope ou o alvo), que o proxy de escopo impõe a cada requisição."""
    t = authz.tiers()
    allowed = _tier_items(t["passive"])
    if st:
        scope = " ".join((st.read_meta().get("scope") or "").split())
        line = scope.split(". ")[0][:160] if scope else f"Restrito ao escopo autorizado: {st.target}"
        allowed = [line] + allowed
    return {"allowed": allowed, "conditional": _tier_items(t["sensitive"]),
            "prohibited": _tier_items(t["prohibited"])}


def _plan(audit: list[dict]) -> list[dict]:
    out = []
    for i, ev in enumerate((e for e in audit if e.get("kind") == "plan"), 1):
        d = ev.get("data") or {}
        out.append({
            "id": f"PLN-{i:02d}",
            "hypothesis": d.get("hypothesis") or "—",
            "action": d.get("action") or "—",
            "expected": d.get("expected_result") or "—",
            "stop": d.get("stop_condition") or "—",
            "status": "Registrado antes da ação (trilha de auditoria)",
            "command": d.get("command") or "",
        })
    return out[-40:]


def _commands(audit: list[dict]) -> list[dict]:
    out = []
    for ev in audit:
        k, d = ev.get("kind"), ev.get("data") or {}
        if k == "task":
            for cmd in (d.get("commands") or [])[:6]:
                out.append({"id": f"CMD-{len(out)+1}", "time": _fmt(ev.get("ts")),
                            "command": cmd, "status": "allowed", "planId": None, "approvalId": None,
                            "actor": ev.get("actor") or "Agente",
                            "output": [f"veredito: {d.get('verdict', '—')} · {d.get('url', '')}"]})
        elif k == "scope_block":
            out.append({"id": f"CMD-{len(out)+1}", "time": _fmt(ev.get("ts")),
                        "command": d.get("url") or d.get("host") or "(fora de escopo)",
                        "status": "blocked", "planId": None, "approvalId": None,
                        "actor": "Política de escopo",
                        "output": ["Bloqueado: host fora do escopo. Nenhuma requisição foi enviada."]})
    return out[-120:]


def _approvals(st: RunState | None) -> list[dict]:
    if not st:
        return []
    events = _read_jsonl(st.approvals_path)
    reqs, decisions = {}, {}
    for e in events:
        if e.get("type") == "request":
            reqs[e["id"]] = e
        elif e.get("type") == "decision":
            decisions[e["id"]] = e
    out = []
    for rid, r in reqs.items():
        dec = decisions.get(rid)
        status = "pending" if not dec else ("approved" if dec.get("approved") else "denied")
        out.append({
            "id": rid, "planId": None, "title": r.get("context") or r.get("action") or "Ação sensível",
            "scope": r.get("target") or "", "reason": (dec.get("reason") if dec else None) or r.get("context") or "",
            "impact": f"risco {r.get('risk', '—')}", "requestedAt": _fmt(r.get("ts")), "status": status,
        })
    out.sort(key=lambda a: a["status"] != "pending")  # pendentes primeiro
    return out


def _findings(st: RunState | None, snap: dict) -> list[dict]:
    if not st:
        return []
    out = []
    for f in snap.get("confirmed") or st.confirmed():
        out.append({
            "id": f.get("id") or f.get("url"), "title": f.get("title") or f.get("vuln_class") or "Achado",
            "asset": _asset(f.get("url")), "severity": _SEV.get((f.get("severity") or "low").lower(), "low"),
            "confidence": _conf_num(f), "impact": f.get("impact") or f.get("summary") or "",
            "classification": "confirmed", "evidence": f.get("evidence_marker") or (f.get("summary") or "")[:200],
            "observedAt": _fmt(f.get("ts")), "council": f.get("council"),
        })
    # resultados não confirmados -> inconclusive/discarded (para a aba de achados)
    for r in snap.get("results") or []:
        v = r.get("verdict")
        if v in ("confirmed", "duplicate"):
            continue
        out.append({
            "id": r.get("item_id") or r.get("url"), "title": r.get("vuln_class") or "Hipótese",
            "asset": _asset(r.get("url")), "severity": _SEV.get((r.get("severity") or "low").lower(), "low"),
            "confidence": 0.3, "impact": (r.get("summary") or "")[:300],
            "classification": "inconclusive" if v == "inconclusive" else "discarded",
            "evidence": (r.get("summary") or "")[:200], "observedAt": _fmt(r.get("ts")), "council": None,
        })
    return out


_AUDIT_KIND = {"run_start": "campaign", "run_end": "result", "plan": "hypothesis",
               "task": "command", "finding": "result", "approval": "approval",
               "scope_block": "decision", "halt": "emergency", "council": "decision",
               "health_start": "decision", "proxy_start": "decision"}
_AUDIT_TITLE = {"run_start": "Campanha configurada", "run_end": "Campanha concluída",
                "plan": "Hipótese registrada", "task": "Ação registrada",
                "finding": "Achado confirmado", "approval": "Decisão de aprovação",
                "scope_block": "Bloqueio por escopo", "halt": "Interrupção de emergência",
                "council": "Parecer do Conselho", "health_start": "Disjuntor ativo",
                "proxy_start": "Proxy de escopo ativo"}


def _activity(snap: dict) -> list[dict]:
    """Feed AO VIVO do agente (snapshot.activity) — o 'terminal' em tempo real:
    recon, autorizações, vereditos, achados. Mesma ideia do painel antigo."""
    out = []
    for a in snap.get("activity") or []:
        out.append({"time": _fmt(a.get("ts")), "kind": a.get("kind") or "system",
                    "msg": str(a.get("msg") or "")})
    return out[-200:]


def _audit(audit: list[dict]) -> list[dict]:
    out = []
    for ev in reversed(audit[-80:]):
        k, d = ev.get("kind"), ev.get("data") or {}
        detail = d.get("context") or d.get("url") or d.get("action") or d.get("status") \
            or d.get("vuln_class") or json.dumps(d, ensure_ascii=False)[:160]
        out.append({"id": ev.get("hash", "")[:8] or f"EVT-{len(out)}", "time": _fmt(ev.get("ts")),
                    "kind": _AUDIT_KIND.get(k, "decision"), "title": _AUDIT_TITLE.get(k, k or "Evento"),
                    "detail": str(detail)[:240], "actor": ev.get("actor") or "Agente"})
    return out


# --------- API pública -----------------------------------------------------

_LIVE = ("running", "recon", "sleeping", "paused")


def _pick(target: str | None) -> RunState | None:
    t = (target or "").strip()
    if t:
        # Alvo explícito: mostra ESSE run se existir; senão None (campanha na
        # fila/preparando) — nunca cai numa campanha diferente.
        return RunState(t) if config.run_exists(t) else None
    runs = list_runs()
    if not runs:
        return None
    # Sem alvo pedido: a campanha "atual" = a viva; senão a de início mais recente.
    return max(runs, key=lambda st: (st.status() in _LIVE, st.read_meta().get("started_at") or 0))


def _queue_position(target: str) -> int | None:
    if not (config.QUEUE_ENABLED and target):
        return None
    try:
        from . import jobqueue
        for j in jobqueue.get_queue().snapshot():
            if j.get("target") == target:
                return j.get("position") or 0  # 0 = já em execução/lançando
    except Exception:
        return None
    return None


def _draft_workspace(target: str) -> dict:
    """Campanha pedida mas ainda sem run (recém-iniciada/enfileirada): mostra ESSE
    alvo como 'na fila/preparando', não outra campanha."""
    camp = _campaign(None, {})
    if target:
        camp = {"id": target, "name": f"Campanha — {target}", "target": target, "status": "draft",
                "progress": 0, "startedAt": None, "owner": operator(), "scopeId": _scope_id(target),
                "cost": 0, "confirmed": 0}
        pos = _queue_position(target)
        if pos is not None:
            camp["status"] = "running"   # comprometida: na fila/lançando
            camp["queued"] = True
            camp["queuePosition"] = pos
    return {"campaign": camp, "policies": _policies(), "plan": [], "commands": [],
            "approvals": [], "findings": [], "audit": [], "activity": []}


def workspace(target: str | None = None) -> dict:
    st = _pick(target)
    if not st:
        return _draft_workspace((target or "").strip())
    snap = st.snapshot(results=200, activity=200)
    audit = _read_jsonl(st.audit_path)
    return {
        "campaign": _campaign(st, snap),
        "policies": _policies(st),
        "plan": _plan(audit),
        "commands": _commands(audit),
        "approvals": _approvals(st),
        "findings": _findings(st, snap),
        "audit": _audit(audit),
        "activity": _activity(snap),
    }


def campaigns() -> dict:
    """Todas as campanhas do motor, no shape do front da Ana — para a página
    'Campanhas' (frota). Vivas primeiro, depois as de início mais recente."""
    out = []
    for st in list_runs():
        snap = st.snapshot(results=0, activity=0)
        m = snap["meta"]
        raw = snap["status"]
        out.append({
            "target": st.target, "status": _map_status(raw), "rawStatus": raw,
            "live": raw in _LIVE, "confirmed": snap["confirmed_count"], "severity": snap["severity"],
            "cost": round(m.get("cost_usd") or 0, 2), "scopeId": _scope_id(st.target),
            "startedAt": _fmt(m.get("started_at")), "_sort": m.get("started_at") or 0,
        })
    out.sort(key=lambda c: (not c["live"], -c["_sort"]))
    for c in out:
        c.pop("_sort", None)
    totals = {"count": len(out), "live": sum(1 for c in out if c["live"]),
              "confirmed": sum(c["confirmed"] for c in out),
              "cost": round(sum(c["cost"] for c in out), 2)}
    return {"campaigns": out, "totals": totals}


def resolve_approval(target: str, rid: str, decision: str) -> dict:
    """Espelha `fosc --approve/--deny`: grava a decisão no ApprovalStore, o que
    desbloqueia o gate que o agente está esperando (authz.require)."""
    st = _pick(target)
    if not st:
        return {"ok": False, "error": "alvo desconhecido"}
    store = ApprovalStore(st.approvals_path)
    if not store.request_meta(rid):
        return {"ok": False, "error": "solicitação não encontrada"}
    if store.status(rid) in ("approved", "denied"):
        return {"ok": False, "error": "esta solicitação já foi resolvida"}
    approved = decision == "approved"
    store.decide(rid, approved, operator(), "decisão pelo painel")
    return {"ok": True, "id": rid, "status": "approved" if approved else "denied"}


def halt(target: str) -> dict:
    """Espelha `fosc --halt`: parada de emergência — encerra tarefas em voo AGORA,
    preserva evidências e trilha."""
    st = _pick(target)
    if not st:
        return {"ok": False, "error": "alvo desconhecido"}
    st.halt_path.write_text("HALT\n")
    st.pause_path.unlink(missing_ok=True)
    pid = st.read_meta().get("pid")
    if pid:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    return {"ok": True, "target": st.target}
