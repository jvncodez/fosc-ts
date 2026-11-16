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


def record_technique(target: str, item: dict, waf: str | None, vuln_class: str | None,
                     payload: str, status: str, note: str | None, tech: list[str]):
    """Structured payload memory: one exact payload/bypass and whether it worked
    or was blocked, keyed by (tech, class, WAF) for later recall."""
    payload = (payload or "").strip()
    if not payload or status not in ("worked", "blocked"):
        return
    _append("techniques.jsonl", {
        "ts": time.time(), "target": target, "pattern": item.get("pattern"),
        "tech": sorted(set(tech or [])), "waf": (waf or "").strip().lower() or None,
        "vuln_class": _norm_class(vuln_class), "payload": payload[:400],
        "status": status, "note": (note or "")[:300],
    })


def record_techniques(target: str, item: dict, waf: str | None, techniques: list[dict], tech: list[str]):
    seen = set()
    for t in techniques or []:
        payload = (t.get("payload") or "").strip()
        key = (payload, t.get("status"), _norm_class(t.get("vuln_class")))
        if not payload or key in seen:
            continue
        seen.add(key)
        record_technique(target, item, waf, t.get("vuln_class"), payload,
                         t.get("status"), t.get("note"), tech)


def target_waf(target: str) -> str | None:
    """The WAF most recently observed for a target (stable across runs)."""
    for r in reversed(_read("techniques.jsonl", 5000)):
        if r.get("target") == target and r.get("waf"):
            return r["waf"]
    return None


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


# Semantic rerank pool: lexical recall first picks this many candidates, then
# (only if an embedding backend is up) meaning-based similarity reorders them.
# This bounds embedding cost to the pool, not the whole lesson store, and makes
# the result never worse than lexical — semantic only reshuffles the top.
_SEM_PREFILTER = 60


def _lex_overlap(item_tech, item_tok, class_tok, les) -> float:
    """The legacy lexical signal (token overlap only, no kind/recency)."""
    s = 0.0
    s += 3 * len(item_tech & {t.lower() for t in les.get("tech") or []})
    s += 2 * min(3, len(class_tok & _tokens(les.get("vuln_class") or "")))
    s += 1 * min(4, len(item_tok & _tokens((les.get("pattern") or "") + " " + les.get("text", ""))))
    return s


def relevant(item: dict, classes: list[str], k: int = 8) -> list[dict]:
    lessons = _read("lessons.jsonl", 3000)
    if not lessons:
        return []
    item_tech = {t.lower() for t in item.get("tech") or []}
    item_tok = _tokens(item.get("pattern", "") + " " + " ".join(item.get("params") or []))
    class_tok = _tokens(" ".join(classes[:5]))
    now = time.time()
    pool = []  # (base_score, lex, kind_w, recency, lesson)
    for les in lessons:
        lex = _lex_overlap(item_tech, item_tok, class_tok, les)
        kind_w = {"win": 3, "fp": 2}.get(les.get("kind"), 0.5)
        rec = math.exp(-((now - les.get("ts", now)) / 86400) / 60)  # ~2mo half-ish life
        base = (lex + kind_w) * rec
        if base > 1.0:
            pool.append((base, lex, kind_w, rec, les))
    pool.sort(key=lambda x: x[0], reverse=True)
    pool = pool[: max(k, _SEM_PREFILTER)]

    # Semantic rerank of the lexical top-pool. Off/absent -> exact legacy order.
    sims = None
    if config.EMBED_BLEND > 0:
        from . import semantic
        if semantic.available():
            query = " ".join(classes[:5]) + " " + item.get("pattern", "") + " " + \
                " ".join(item.get("params") or [])
            docs = [f"{(l.get('vuln_class') or '')} {(l.get('pattern') or '')} {l.get('text', '')}"
                    for *_, l in pool]
            sims = semantic.similarities(query, docs)
    if sims is None:
        return [les for *_, les in pool[:k]]

    b = config.EMBED_BLEND
    blended = []
    for (_, lex, kind_w, rec, les), sim in zip(pool, sims):
        # BLEND=0 reduces this to the legacy (lex+kind_w)*rec exactly.
        score = ((1 - b) * lex + b * max(0.0, sim) * 8 + kind_w) * rec
        blended.append((score, les))
    blended.sort(key=lambda x: x[0], reverse=True)
    return [les for _, les in blended[:k]]


def payload_hints(target: str, item: dict, classes: list[str], k: int = 6) -> str:
    """The exact payloads/bypasses that worked (and the notable dead ends) on
    similar stacks, so the agent arrives already knowing what lands. Keyed by
    (tech, class) and boosted when the WAF matches this target's known WAF."""
    recs = _read("techniques.jsonl", 5000)
    if not recs:
        return ""
    item_tech = {t.lower() for t in item.get("tech") or []}
    class_set = {c.lower() for c in classes}
    waf = target_waf(target)
    item_tok = _tokens(item.get("pattern", "") + " " + " ".join(item.get("params") or []))
    now = time.time()

    pool = []  # (base, rec, dedup_key, record)
    seen = set()
    for r in recs:
        tech_ov = len(item_tech & {t.lower() for t in r.get("tech") or []})
        cls_match = 1 if (r.get("vuln_class") or "") in class_set else 0
        tok_ov = len(item_tok & _tokens((r.get("pattern") or "") + " " + r.get("note", "")))
        if tech_ov == 0 and cls_match == 0 and tok_ov == 0:
            continue  # unrelated to this endpoint
        key = (r.get("payload"), r.get("status"), r.get("vuln_class"))
        if key in seen:
            continue
        seen.add(key)
        base = 3 * cls_match + 2 * tech_ov + min(2, tok_ov)
        base += 1.5 if (r.get("waf") and waf and r["waf"] == waf) else 0.0
        base += 1.5 if r.get("status") == "worked" else 0.3
        rec = math.exp(-((now - r.get("ts", now)) / 86400) / 90)  # ~3mo half-ish
        pool.append((base * rec, rec, key, r))
    if not pool:
        return ""
    pool.sort(key=lambda x: x[0], reverse=True)
    pool = pool[: max(k * 2, _SEM_PREFILTER)]

    # Semantic rerank: match payload+note meaning to the class/endpoint context.
    sims = None
    if config.EMBED_BLEND > 0:
        from . import semantic
        if semantic.available():
            query = " ".join(classes[:5]) + " " + item.get("pattern", "")
            docs = [f"{(r.get('vuln_class') or '')} {r.get('payload', '')} {r.get('note', '')}"
                    for *_, r in pool]
            sims = semantic.similarities(query, docs)
    if sims is not None:
        b = config.EMBED_BLEND
        pool = sorted(
            ((((1 - b) * base + b * max(0.0, sim) * 6) , rec, key, r)
             for (base, rec, key, r), sim in zip(pool, sims)),
            key=lambda x: x[0], reverse=True)

    worked, blocked = [], []
    for _, _, _, r in pool:
        waf_tag = f", waf={r['waf']}" if r.get("waf") else ""
        tech_tag = (",".join(r.get("tech") or [])[:40]) or "-"
        line = f"- ({r.get('vuln_class') or '-'}; tech={tech_tag}{waf_tag}) `{r.get('payload')}`" + \
               (f" — {r['note']}" if r.get("note") else "")
        (worked if r.get("status") == "worked" else blocked).append(line)
        if len(worked) >= k and len(blocked) >= max(2, k // 2):
            break
    parts = []
    if worked:
        parts.append("Payloads/bypasses that WORKED before on similar stacks (reuse first):\n"
                     + "\n".join(worked[:k]))
    if blocked:
        parts.append("Blocked before on similar stacks (bring a real bypass or skip):\n"
                     + "\n".join(blocked[: max(2, k // 2)]))
    return "\n\n".join(parts)


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
