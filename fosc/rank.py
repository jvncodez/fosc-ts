"""Attack-surface ranking: heuristics + nuclei signal + what past hunts learned."""
import re

from . import config

HIGH_VALUE_PATH = re.compile(
    r"(admin|api/|graphql|login|auth|account|user|profile|order|payment|"
    r"invoice|upload|file|export|import|reset|token|session|cart|checkout|"
    r"webhook|callback|redirect|proxy|fetch|rest/|v[0-9]+/)",
    re.I,
)
ID_LIKE_PARAM = re.compile(r"(id|uid|uuid|user|account|order|doc|file|path|url|redirect|next|token)", re.I)
NUCLEI_WEIGHT = {"critical": 25, "high": 15, "medium": 8}

# param/path keyword -> classes it hints at, in priority order
HINTS = [
    (re.compile(r"(url|uri|dest|redirect|next|return|callback|webhook|proxy|fetch|feed|image|link)", re.I),
     ["SSRF", "open redirect"]),
    (re.compile(r"(^id$|_id$|id$|uid|uuid|user|account|order|invoice|doc|basket|cart)", re.I),
     ["IDOR", "API auth bypass / missing authZ on object access"]),
    (re.compile(r"(q|query|search|s|term|keyword|name|comment|message|msg|title)$", re.I),
     ["XSS (reflected/stored/DOM)", "SQLi / NoSQLi"]),
    (re.compile(r"(file|path|dir|folder|template|page|include|doc|download)", re.I),
     ["path traversal / LFI", "SSTI"]),
    (re.compile(r"(upload|avatar|attachment|import)", re.I), ["file upload bypass"]),
    (re.compile(r"(login|auth|session|token|reset|password|otp|mfa|2fa)", re.I),
     ["broken auth / session handling"]),
    (re.compile(r"(price|amount|qty|quantity|coupon|discount|checkout|payment|transfer|balance)", re.I),
     ["business logic abuse (price/qty/race condition)", "mass assignment"]),
]


def _learned(stats: dict, tech: list[str], cls: str) -> float:
    """Learned signal for (tech, class): >0 paid off before, <0 kept producing false positives."""
    cls = cls.lower()
    vals = []
    for t in [x.lower() for x in tech] + ["*"]:
        s = stats.get((t, cls))
        if not s or not s["tries"]:
            continue
        weight = 1.0 if t != "*" else 0.4  # stack-specific evidence counts more
        vals.append(weight * (3 * s["wins"] - 1.5 * s["fps"]) / s["tries"] * min(1, s["tries"] / 3))
    return max(vals, key=abs) if vals else 0.0


def suggest_classes(item: dict, stats: dict | None = None) -> list[str]:
    stats = stats or {}
    text = " ".join([item.get("path", "")] + list(item.get("params") or []))
    hinted: list[str] = []
    for rx, classes in HINTS:
        if any(rx.search(tok) for tok in re.split(r"[/?&=_.\-]", text) if tok):
            hinted += [c for c in classes if c not in hinted]
    order = {c: i for i, c in enumerate(hinted)}
    def key(c):
        return (-(10 - order[c]) if c in order else 0) - 2 * _learned(stats, item.get("tech") or [], c)
    return sorted(config.VULN_BUNDLE, key=key)


def score(item: dict, stats: dict | None = None) -> float:
    stats = stats or {}
    s = 0.0
    params = item.get("params") or []
    if params:
        s += 2 * len(params)
        if any(ID_LIKE_PARAM.search(p) for p in params):
            s += 5
    if HIGH_VALUE_PATH.search(item.get("path", "") + " " + item.get("url", "")):
        s += 6
    if item.get("method", "GET") != "GET":
        s += 3
    for hit in item.get("nuclei") or []:
        s += NUCLEI_WEIGHT.get((hit.get("severity") or "").lower(), 0)
    top = suggest_classes(item, stats)[:3]
    s += sum(_learned(stats, item.get("tech") or [], c) for c in top) * 2
    return s


def rank(items: list[dict], stats: dict | None = None) -> list[dict]:
    return sorted(items, key=lambda it: score(it, stats), reverse=True)
