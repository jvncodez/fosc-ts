"""Telegram remote control — inbound side of the bot.

Long-polls getUpdates in a daemon thread and turns inline-button callbacks into
approval decisions, plus `/halt` and `/status` commands. This is how the operator
does human-in-the-loop FROM THEIR PHONE: a sensitive action pauses the pipeline,
a message with ✅/❌ buttons arrives, and the tap writes the decision the gate is
waiting on. `parse_update` is pure and unit-tested; the thread is thin IO around it.
"""
import threading

from . import notify


def parse_update(upd: dict) -> dict | None:
    """Pure: one getUpdates entry -> an actionable intent, or None.
    {"kind": approve|deny|halt|status, "id": <approval id>, "from": <user>,
     "callback_id": <for answerCallbackQuery>}."""
    cq = upd.get("callback_query")
    if cq:
        data = cq.get("data") or ""
        who = ((cq.get("from") or {}).get("username")
               or (cq.get("from") or {}).get("first_name") or "telegram")
        if ":" in data:
            verb, rid = data.split(":", 1)
            if verb in ("approve", "deny"):
                return {"kind": verb, "id": rid, "from": who, "callback_id": cq.get("id", "")}
        return None
    msg = upd.get("message") or {}
    text = (msg.get("text") or "").strip().lower()
    who = ((msg.get("from") or {}).get("username")
           or (msg.get("from") or {}).get("first_name") or "telegram")
    if text.startswith("/halt"):
        return {"kind": "halt", "id": "", "from": who, "callback_id": ""}
    if text.startswith("/status"):
        return {"kind": "status", "id": "", "from": who, "callback_id": ""}
    return None


class TelegramBot:
    def __init__(self, on_decision=None, on_halt=None, on_status=None, cfg=None):
        self.on_decision = on_decision   # (rid, approved: bool, who: str) -> None
        self.on_halt = on_halt           # (who: str) -> None
        self.on_status = on_status       # (who: str) -> str
        self.cfg = cfg
        self._stop = threading.Event()
        self._offset = None
        self._thread = None

    def start(self) -> bool:
        if not notify.configured(self.cfg):
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            payload = {"timeout": 15}
            if self._offset is not None:
                payload["offset"] = self._offset
            ok, _, result = notify._call("getUpdates", payload, self.cfg)
            if not ok or not isinstance(result, list):
                self._stop.wait(3)
                continue
            for upd in result:
                self._offset = upd.get("update_id", 0) + 1
                try:
                    self._handle(parse_update(upd))
                except Exception:
                    pass

    def _handle(self, intent):
        if not intent:
            return
        kind = intent["kind"]
        if kind in ("approve", "deny") and self.on_decision:
            self.on_decision(intent["id"], kind == "approve", intent["from"])
            if intent.get("callback_id"):
                notify._call("answerCallbackQuery",
                             {"callback_query_id": intent["callback_id"],
                              "text": "✅ aprovado" if kind == "approve" else "❌ negado"}, self.cfg)
            notify.send_telegram(f"{'✅' if kind == 'approve' else '❌'} decisão registrada por "
                                 f"{intent['from']} (id {intent['id']})", self.cfg)
        elif kind == "halt" and self.on_halt:
            self.on_halt(intent["from"])
            notify.send_telegram(f"🛑 HALT solicitado por {intent['from']} — parando tudo.", self.cfg)
        elif kind == "status" and self.on_status:
            notify.send_telegram(self.on_status(intent["from"]), self.cfg)
