"""Telegram notifications (stdlib only). A failed send never breaks a hunt."""
import html
import json
import urllib.error
import urllib.request

from . import config

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def send_telegram(text: str, cfg: dict | None = None) -> tuple[bool, str | None]:
    cfg = cfg if cfg is not None else config.load_user_config()
    token, chat = cfg.get("telegram_token"), cfg.get("telegram_chat_id")
    if not token or not chat:
        return False, "telegram not configured"
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps({"chat_id": chat, "text": text, "parse_mode": "HTML",
                         "disable_web_page_preview": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read().decode() or "{}")
            return bool(body.get("ok")), body.get("description")
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode()).get("description")
        except Exception:
            return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)


def notify_finding(target: str, finding: dict) -> tuple[bool, str | None]:
    sev = (finding.get("severity") or "unrated").lower()
    e = html.escape
    text = (
        f"{SEV_ICON.get(sev, '🔺')} <b>FOSC: {e(sev.upper())} confirmed</b>\n"
        f"<b>{e(finding.get('vuln_class') or 'finding')}</b> on <code>{e(target)}</code>\n"
        f"<code>{e(finding.get('url', ''))}</code>\n\n"
        f"{e((finding.get('summary') or '')[:600])}"
    )
    return send_telegram(text)
