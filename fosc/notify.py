"""Telegram notifications + remote control (stdlib only).

Outbound: finding alerts and campaign lifecycle events. A failed send never breaks
a hunt. Inbound (see telegram_bot.py): the operator can APPROVE/DENY a sensitive
action and HALT the campaign straight from the chat — human-in-the-loop on the
phone, which is the "aprovação remota" the governance challenge asks for.
"""
import html
import json
import urllib.error
import urllib.request

from . import config

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
API = "https://api.telegram.org/bot{token}/{method}"


def telegram_cfg(cfg: dict | None = None) -> tuple[str | None, str | None]:
    cfg = cfg if cfg is not None else config.load_user_config()
    return cfg.get("telegram_token"), cfg.get("telegram_chat_id")


def configured(cfg: dict | None = None) -> bool:
    t, c = telegram_cfg(cfg)
    return bool(t and c)


def _call(method: str, payload: dict, cfg: dict | None = None) -> tuple[bool, str | None, dict]:
    token, _ = telegram_cfg(cfg)
    if not token:
        return False, "telegram not configured", {}
    req = urllib.request.Request(
        API.format(token=token, method=method),
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read().decode() or "{}")
            return bool(body.get("ok")), body.get("description"), body.get("result") or {}
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode()).get("description"), {}
        except Exception:
            return False, f"HTTP {e.code}", {}
    except Exception as e:
        return False, str(e), {}


def send_telegram(text: str, cfg: dict | None = None, buttons: list | None = None) -> tuple[bool, str | None]:
    token, chat = telegram_cfg(cfg)
    if not token or not chat:
        return False, "telegram not configured"
    payload = {"chat_id": chat, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    if buttons:  # buttons = list of rows; each row a list of (label, callback_data)
        payload["reply_markup"] = {"inline_keyboard": [
            [{"text": lbl, "callback_data": data} for (lbl, data) in row] for row in buttons]}
    ok, desc, _ = _call("sendMessage", payload, cfg)
    return ok, desc


def send_test(cfg: dict | None = None) -> tuple[bool, str | None]:
    return send_telegram("✅ <b>BB-Sentinela</b> — Telegram conectado. "
                         "Você receberá achados, pedidos de aprovação e alertas aqui.", cfg)


def _mitre_line(finding: dict) -> str:
    tags = [t.get("id") for t in (finding.get("mitre") or []) if t.get("id")]
    return ", ".join(tags)


def notify_finding(target: str, finding: dict) -> tuple[bool, str | None]:
    sev = (finding.get("severity") or "unrated").lower()
    e = html.escape
    lines = [
        f"{SEV_ICON.get(sev, '🔺')} <b>{e(sev.upper())} confirmado</b> — {e(finding.get('vuln_class') or 'achado')}",
        f"alvo: <code>{e(target)}</code>",
        f"endpoint: <code>{e(finding.get('url', ''))}</code>",
    ]
    meta = []
    if finding.get("cvss") is not None:
        meta.append(f"CVSS {finding['cvss']}")
    if finding.get("confidence"):
        meta.append(f"confiança {e(str(finding['confidence']))}")
    mit = _mitre_line(finding)
    if mit:
        meta.append(f"MITRE {e(mit)}")
    if meta:
        lines.append(" · ".join(meta))
    if finding.get("summary"):
        lines.append("")
        lines.append(e(finding["summary"][:600]))
    if finding.get("report_path"):
        lines.append("")
        lines.append(f"📄 <code>{e(finding['report_path'])}</code>")
    return send_telegram("\n".join(lines))


def notify_event(kind: str, target: str, detail: str = "") -> tuple[bool, str | None]:
    """Campaign lifecycle: started / finished / denied / halted / sleeping."""
    e = html.escape
    icon = {"started": "🚀", "finished": "🏁", "denied": "⛔", "halted": "🛑",
            "sleeping": "💤", "offline": "📡"}.get(kind, "ℹ️")
    head = {"started": "campanha iniciada", "finished": "campanha concluída",
            "denied": "teste ativo não autorizado", "halted": "PARADA DE EMERGÊNCIA",
            "sleeping": "fila vazia — dormindo", "offline": "sem conexão"}.get(kind, kind)
    text = f"{icon} <b>{e(head)}</b>\nalvo: <code>{e(target)}</code>"
    if detail:
        text += f"\n{e(detail)}"
    return send_telegram(text)


def notify_approval(target: str, action: str, context: str, request_id: str) -> tuple[bool, str | None]:
    """Human-in-the-loop on the phone: a sensitive action is pending. The buttons'
    callback_data is read back by telegram_bot.py to write the decision."""
    e = html.escape
    text = (f"⚠️ <b>AUTORIZAÇÃO NECESSÁRIA</b>\n"
            f"ação: <b>{e(action)}</b>\nalvo: <code>{e(target)}</code>\n{e(context)}\n\n"
            f"<i>id {e(request_id)}</i> — aprove ou negue abaixo.")
    buttons = [[("✅ Aprovar", f"approve:{request_id}"), ("❌ Negar", f"deny:{request_id}")]]
    return send_telegram(text, buttons=buttons)
