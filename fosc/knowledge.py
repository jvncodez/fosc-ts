"""Cross-hunt learning store, shared by every target (~/.fosc/knowledge/).

Files:
  events.jsonl         one line per hunted item: tech, class, pattern, verdict
  lessons.jsonl        reusable lessons: kind = win | fp | note
  playbook.md          consolidated, deduplicated playbook (rewritten by an LLM pass)
  targets/<name>.md    per-target notes so a new hunt resumes with context
  state.json           consolidation bookkeeping

Used two ways: relevant() feeds the top lessons into each task's prompt,
and class_stats() lets the ranker boost (tech, class) pairs that paid off
before and demote the ones that keep producing false positives.
"""
import json
import math
import re
import threading
import time
import uuid

from . import config

_lock = threading.Lock()
_TOKEN = re.compile(r"[a-z0-9]{3,}")


def _p(name):
    config.KNOWLEDGE_ROOT.mkdir(parents=True, exist_ok=True)
    (config.KNOWLEDGE_ROOT / "targets").mkdir(exist_ok=True)
    return config.KNOWLEDGE_ROOT / name


def _append(name: str, rec: dict):
    with _lock:
        with _p(name).open("a") as f:
            f.write(json.dumps(rec) + "\n")


def _read(name: str, limit: int | None = None) -> list[dict]:
    path = _p(name)
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    if limit:
        lines = lines[-limit:]
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except json.JSONDecodeError:
            continue
    return out


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall((text or "").lower()))


def _norm_class(c: str | None) -> str:
    return (c or "").strip().lower()


# -- writes -----------------------------------------------------------

def record_event(target: str, item: dict, verdict: str, vuln_class: str | None, tech: list[str]):
    _append("events.jsonl", {
        "ts": time.time(), "target": target, "pattern": item.get("pattern"),
        "tech": sorted(set(tech or [])), "vuln_class": vuln_class, "verdict": verdict,
    })


def add_lesson(kind: str, text: str, target: str, item: dict, vuln_class: str | None, tech: list[str]) -> str | None:
    text = (text or "").strip()
    if not text:
        return None
    lid = uuid.uuid4().hex[:12]
    _append("lessons.jsonl", {
        "id": lid, "ts": time.time(), "kind": kind, "text": text[:600],
        "target": target, "pattern": item.get("pattern"),
        "vuln_class": vuln_class, "tech": sorted(set(tech or [])),
    })
    return lid


def note_target(target: str, line: str):
    line = (line or "").strip()
    if not line:
        return
    path = _p("targets") / f"{config.safe_name(target)}.md"
    with _lock:
        existing = path.read_text() if path.exists() else f"# {target}\n\n"
        if line in existing:
            return
        path.write_text(existing + f"- {line}\n")


def note_tool(name: str, howto: str = ""):
    """Record a tool FOSC installed, so future runs know it's in the arsenal."""
    name = (name or "").strip().strip("`")
    if not name:
        return
    path = _p("tools.md")
    with _lock:
        existing = path.read_text() if path.exists() else "# arsenal instalado pelo FOSC\n\n"
        if f"`{name}`" in existing:
            return
        path.write_text(existing + f"- `{name}`" + (f" — {howto}" if howto else "") + "\n")


def read_tools() -> str:
    """The tools FOSC has installed across runs (its growing arsenal)."""
    path = _p("tools.md")
    if not path.exists():
        return ""
    lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip().startswith("- ")]
    return "\n".join(lines[-50:])


def read_target_notes(target: str) -> str:
    """Durable facts learned about one target, accumulated across runs/sessions."""
    path = _p("targets") / f"{config.safe_name(target)}.md"
    if not path.exists():
        return ""
    lines = [l for l in path.read_text(errors="replace").splitlines()
             if l.strip().startswith("- ")]
    return "\n".join(lines[-40:])


def all_lessons(limit: int = 300) -> list[dict]:
    return list(reversed(_read("lessons.jsonl", limit)))


def delete_lesson(lid: str) -> bool:
    path = _p("lessons.jsonl")
    if not path.exists():
        return False
    with _lock:
        lines = path.read_text().splitlines()
        kept = [l for l in lines if f'"id": "{lid}"' not in l]
        path.write_text("\n".join(kept) + ("\n" if kept else ""))
    return len(kept) != len(lines)


def read_playbook() -> str:
    p = _p("playbook.md")
    return p.read_text() if p.exists() else ""


def write_playbook(text: str):
    _p("playbook.md").write_text(text)


def read_target_notes(target: str) -> str:
    p = _p("targets") / f"{config.safe_name(target)}.md"
    return p.read_text() if p.exists() else ""


# -- reads used by the hunter -----------------------------------------

def class_stats() -> dict:
    """{(tech, class): {"tries", "wins", "fps"}} plus ("*", class) aggregates."""
    stats: dict = {}
    for ev in _read("events.jsonl", 20000):
        cls = _norm_class(ev.get("vuln_class"))
        if not cls:
            continue
        for tech in (ev.get("tech") or []) + ["*"]:
            s = stats.setdefault((tech.lower(), cls), {"tries": 0, "wins": 0, "fps": 0})
            s["tries"] += 1
            if ev.get("verdict") == "confirmed":
                s["wins"] += 1
            elif ev.get("verdict") in ("refuted", "unverified"):
                s["fps"] += 1
    return stats


def relevant(item: dict, classes: list[str], k: int = 8) -> list[dict]:
    lessons = _read("lessons.jsonl", 3000)
    if not lessons:
        return []
    item_tech = {t.lower() for t in item.get("tech") or []}
    item_tok = _tokens(item.get("pattern", "") + " " + " ".join(item.get("params") or []))
    class_tok = _tokens(" ".join(classes[:5]))
    now = time.time()
    scored = []
    for les in lessons:
        s = 0.0
        s += 3 * len(item_tech & {t.lower() for t in les.get("tech") or []})
        s += 2 * min(3, len(class_tok & _tokens(les.get("vuln_class") or "")))
        s += 1 * min(4, len(item_tok & _tokens((les.get("pattern") or "") + " " + les.get("text", ""))))
        s += {"win": 3, "fp": 2}.get(les.get("kind"), 0.5)
        age_days = (now - les.get("ts", now)) / 86400
        s *= math.exp(-age_days / 60)  # ~2 month half-ish life
        if s > 1.0:
            scored.append((s, les))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [les for _, les in scored[:k]]


def format_for_prompt(lessons: list[dict], target: str) -> str:
    parts = []
    pb = read_playbook().strip()
    if pb:
        parts.append("Playbook (consolidated from past hunts):\n" + pb[:2500])
    notes = read_target_notes(target).strip()
    if notes:
        parts.append("Notes about this target from earlier hunts:\n" + notes[-1500:])
    if lessons:
        tag = {"win": "WORKED", "fp": "FALSE POSITIVE, avoid", "note": "note"}
        parts.append("Most relevant lessons for this item:\n" + "\n".join(
            f"- [{tag.get(l.get('kind'), l.get('kind'))}] ({l.get('vuln_class') or '-'}; tech={','.join(l.get('tech') or []) or '-'}) {l.get('text')}"
            for l in lessons))
    return "\n\n".join(parts)


# -- consolidation ----------------------------------------------------

def pending_for_consolidation() -> list[dict]:
    st_path = _p("state.json")
    st = json.loads(st_path.read_text()) if st_path.exists() else {}
    last = st.get("consolidated_until", 0)
    return [l for l in _read("lessons.jsonl", 5000) if l.get("ts", 0) > last]


def mark_consolidated(ts: float):
    st_path = _p("state.json")
    st = json.loads(st_path.read_text()) if st_path.exists() else {}
    st["consolidated_until"] = ts
    st_path.write_text(json.dumps(st))


def stats_summary() -> dict:
    stats = class_stats()
    rows = []
    for (tech, cls), s in stats.items():
        if tech != "*":
            continue
        rows.append({"vuln_class": cls, **s, "hit_rate": round(s["wins"] / s["tries"], 3) if s["tries"] else 0})
    rows.sort(key=lambda r: (r["wins"], r["tries"]), reverse=True)
    tech_rows = []
    for (tech, cls), s in stats.items():
        if tech == "*" or s["wins"] == 0:
            continue
        tech_rows.append({"tech": tech, "vuln_class": cls, **s})
    tech_rows.sort(key=lambda r: r["wins"], reverse=True)
    return {"by_class": rows, "by_tech": tech_rows[:30], "lessons": len(_read("lessons.jsonl"))}
