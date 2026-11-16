"""Stealth / OPSEC profile for AUTHORIZED engagements.

Goal: emulate a real user and stay under the radar on the in-scope target — so
FOSC can actually test (a tripped WAF blocks the whole assessment) and so the
engagement realistically mirrors an attacker. This is realism within scope, not
evasion of defenders for malicious use; it never changes WHAT is tested, only
HOW loud it is.

Two levers:
  - headers(): realistic browser headers (sent on every request instead of the
    default scanner/curl/python User-Agent that screams "automated tool").
  - a prompt directive (prompt_block) telling the agent to pace low-and-slow,
    back off on WAF/ratelimit blocks, and adapt encoding to the known WAF.
Rate is pinned low via ratectl.configure() by the engine when stealth is on.
"""
import hashlib

from . import config

# A small pool of current, common desktop browser UAs. One is chosen
# deterministically per target so a single campaign is self-consistent.
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


def enabled() -> bool:
    return config.STEALTH_ENABLED


def user_agent(seed: str = "") -> str:
    if config.STEALTH_UA:
        return config.STEALTH_UA
    h = int(hashlib.sha1((seed or "fosc").encode()).hexdigest(), 16)
    return _UA_POOL[h % len(_UA_POOL)]


def headers(seed: str = "") -> list[str]:
    """Realistic browser headers as 'Name: value' strings, for every request."""
    return [
        f"User-Agent: {user_agent(seed)}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-Mode: navigate",
    ]


def merge_headers(base: list[str] | None, extra: list[str]) -> list[str]:
    """Add stealth headers without duplicating a header the operator already set."""
    base = list(base or [])
    have = {h.split(":", 1)[0].strip().lower() for h in base}
    for h in extra:
        if h.split(":", 1)[0].strip().lower() not in have:
            base.append(h)
    return base


def prompt_block(waf: str | None = None) -> str:
    waf_line = (f"Known WAF/CDN on this target: {waf}. Adapt payload encoding to it and reuse the "
                f"bypasses from payload memory above."
                if waf else
                "Fingerprint the WAF/CDN first (response headers, cookies, block/challenge pages) "
                "and adapt accordingly.")
    return (
        "STEALTH / OPSEC (authorized engagement — look like legitimate traffic, stay under the radar):\n"
        "- Pace LOW-AND-SLOW: small bursts with randomized delays between requests; never hammer the target.\n"
        "- Send the realistic browser headers provided above on EVERY request; do NOT fall back to default "
        "scanner/curl/python User-Agents.\n"
        "- Prefer targeted, hand-crafted requests over broad noisy scans: keep wordlists small and derived "
        "from the app, avoid high-rate brute force (it trips rate limits and WAFs and blocks the whole test).\n"
        "- If you see WAF/ratelimit/block responses (403/406/429/503, challenge/captcha pages, Cloudflare or "
        "Akamai blocks), BACK OFF immediately: slow down, switch encoding/technique, and record what tripped "
        "it — do not keep retrying the same blocked payload.\n"
        f"- {waf_line}\n"
        "- Goal: be indistinguishable from a real user while still testing THOROUGHLY (stealth changes how "
        "loud you are, not how deep you go)."
    )
