"""Mechanical recon: subfinder -> httpx (+tech) -> katana/gau/waybackurls -> nuclei.

Deterministic and tool-driven, no LLM here. The output is deduplicated by
route *pattern* (`/user/123?id=5` and `/user/456?id=9` are one item), so
the hunter spends one Claude task per distinct endpoint shape instead of
one per URL. Static assets never become hunt items; .js URLs are kept
aside as context for the agent.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs

from . import config
from .scope import Scope
from .toolrunner import run_lines, have

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_NUM = re.compile(r"^\d+$")


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def target_host(target: str) -> str:
    if _is_url(target):
        return (urlparse(target).hostname or "").lower()
    return target.lower()


def _is_ip_or_local(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def in_scope(url: str, target: str) -> bool:
    # Single source of truth: the deterministic Scope Manager. Strict for a URL/IP
    # target (exact host), subdomains allowed only for a bare-domain target.
    return Scope.from_target(target).allows(url)


def route_pattern(url: str) -> str:
    p = urlparse(url)
    segs = []
    for s in (p.path or "/").split("/"):
        if _NUM.match(s):
            segs.append("{n}")
        elif _UUID.match(s):
            segs.append("{uuid}")
        elif _HEX.match(s):
            segs.append("{hash}")
        else:
            segs.append(s)
    path = "/".join(segs) or "/"
    keys = sorted(parse_qs(p.query, keep_blank_values=True).keys())
    q = ("?" + "&".join(keys)) if keys else ""
    return f"{(p.hostname or '').lower()}{path}{q}"


def is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    dot = path.rfind(".")
    return dot != -1 and path[dot:] in config.STATIC_EXT


def item_id(item: dict) -> str:
    key = item.get("pattern") or item["url"]
    return hashlib.sha1(key.encode()).hexdigest()[:16]


# -- stages -----------------------------------------------------------

def _dns_wordlist() -> str | None:
    for w in config.DNS_WORDLISTS:
        if os.path.exists(w):
            return w
    return None


def dns_bruteforce(domain: str, timeout: int) -> set[str]:
    """DNS subdomain brute-force via dnsx (resolves a wordlist against the apex).
    Returns resolving hostnames. No-op without dnsx/wordlist or if disabled."""
    if not (config.DNS_BRUTE and have("dnsx")):
        return set()
    wl = _dns_wordlist()
    if not wl:
        return set()
    out = {l.strip() for l in run_lines(["dnsx", "-d", domain, "-w", wl, "-silent"], timeout)
           if l.strip()}
    if out:
        print(f"[fosc] dns brute: {len(out)} subdomínio(s) resolvendo")
    return out


def discover_hosts(target: str, timeout: int) -> list[dict]:
    """Return [{url, tech:[...], status, title}] for live hosts."""
    if _is_url(target):
        candidates = [target]
    else:
        names = {target}
        if not _is_ip_or_local(target):
            if have("subfinder"):
                names.update(l.strip() for l in run_lines(["subfinder", "-d", target, "-silent"], timeout))
            names.update(dns_bruteforce(target, timeout))
        candidates = sorted(names)

    hosts = []
    if have("httpx"):
        try:
            proc = subprocess.run(
                ["httpx", "-silent", "-json", "-td", "-title", "-sc"],
                input="\n".join(candidates), capture_output=True, text=True, timeout=timeout,
            )
            for line in proc.stdout.splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("url"):
                    hosts.append({
                        "url": rec["url"],
                        "tech": sorted(set(rec.get("tech") or [])),
                        "status": rec.get("status_code"),
                        "title": rec.get("title"),
                    })
        except Exception as e:
            print(f"[fosc] httpx probe failed: {e}")

    if not hosts:
        fallback = candidates[0] if _is_url(target) else f"https://{target}"
        hosts = [{"url": fallback, "tech": [], "status": None, "title": None}]
    return hosts


def collect_urls(target: str, hosts: list[dict], timeout: int) -> set[str]:
    found = {h["url"] for h in hosts}
    if have("katana"):
        for h in hosts:
            found.update(
                l.strip() for l in run_lines(
                    ["katana", "-u", h["url"], "-silent", "-jc", "-kf", "all", "-d", "3"], timeout)
                if l.strip().startswith("http")
            )
    root = target_host(target)
    if not _is_ip_or_local(root):
        archive = []
        if have("gau"):
            archive += run_lines(["gau", "--subs", root], timeout)
        if have("waybackurls"):
            try:
                proc = subprocess.run(["waybackurls"], input=root, capture_output=True, text=True, timeout=timeout)
                archive += proc.stdout.splitlines()
            except Exception as e:
                print(f"[fosc] waybackurls failed: {e}")
        found.update(u.strip() for u in archive[: config.MAX_ARCHIVE_URLS] if u.strip().startswith("http"))
    return {u for u in found if in_scope(u, target)}


# --- SPA / JS-bundle endpoint extraction ---------------------------------- #
# A hash-router SPA (https://host/#/) exposes NO server routes to a crawler: the
# real API paths (/rest/*, /api/*) live as string literals inside the JS bundle.
# Without mining them the hunt queue comes up empty — exactly the migbot symptom.
_QUOTED_PATH = re.compile(r"""['"`](/[A-Za-z0-9_\-./~%:?=&${}]{1,160})['"`]""")
_ABS_URL = re.compile(r"""['"`](https?://[^'"`\s)]{6,200})['"`]""")
_API_HINT = ("/api", "/rest", "/graphql", "/v1/", "/v2/", "/v3/", "/oauth", "/auth",
             "/user", "/admin", "/account", "/product", "/order", "/token", "/login",
             "/logout", "/register", "/upload", "/file", "/export", "/search",
             "/feedback", "/basket", "/wallet", "/address", "/card", "/metrics")
_DYN_SEG = re.compile(r"(:[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]+>)")


def _normalize_js_path(p: str) -> str | None:
    """Turn a route literal into a concrete, testable path, or None to drop it."""
    if p.startswith("//"):
        return None  # protocol-relative URL (//host/..) = EXTERNAL host, not a path
    p = p.split("?")[0].split("#")[0]
    if "//" in p[1:] or " " in p or p.endswith("/") and p != "/":
        p = p.rstrip("/") or "/"
    p = _DYN_SEG.sub("1", p)          # /rest/products/:id -> /rest/products/1
    if "${" in p or "{{" in p or "<" in p:
        return None                   # unresolved interpolation -> not testable
    if len(p) < 2 or p.count("/") < 1:
        return None
    return p


def _paths_from_js(body: str) -> set[str]:
    """Pure: extract candidate API paths + absolute URLs from JS source."""
    paths: set[str] = set()
    for m in _QUOTED_PATH.finditer(body):
        p = _normalize_js_path(m.group(1))
        if not p or is_static("http://x" + p):
            continue
        low = p.lower()
        # keep clear API paths, or any multi-segment path that isn't an asset dir
        if any(h in low for h in _API_HINT) or (p.count("/") >= 2 and not low.startswith(
                ("/assets/", "/i18n/", "/static/", "/fonts/", "/images/", "/img/"))):
            paths.add(p)
    for m in _ABS_URL.finditer(body):
        paths.add(m.group(1))         # absolute URLs (scope filter applied by caller)
    return paths


def js_endpoints(target: str, urls: set[str], hosts: list[dict], timeout: int = 20,
                 max_js: int = 30) -> set[str]:
    """Download in-scope JS bundles and mine API endpoints out of them, building
    concrete in-scope URLs. This is what makes SPAs huntable."""
    import urllib.request

    js = [u for u in urls if urlparse(u).path.lower().endswith((".js", ".mjs"))
          and in_scope(u, target)][:max_js]
    if not js:
        return set()
    bases = sorted({f"{urlparse(h['url']).scheme}://{urlparse(h['url']).netloc}"
                    for h in hosts if h.get("url")})
    out: set[str] = set()
    for ju in js:
        try:
            req = urllib.request.Request(ju, headers={"User-Agent": "bb-sentinela-recon"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(3_000_000).decode("utf-8", "replace")
        except Exception:
            continue
        for p in _paths_from_js(body):
            if p.startswith("http"):
                out.add(p)
            else:
                for base in bases:
                    out.add(base + p)
    scoped = {u for u in out if in_scope(u, target)}
    if scoped:
        print(f"[fosc] JS mining: {len(scoped)} endpoint(s) de {len(js)} bundle(s)")
    return set(list(scoped)[: config.CONTENT_MAX_RESULTS])


def _pick_wordlist() -> str | None:
    for w in config.CONTENT_WORDLISTS:
        if os.path.exists(w):
            return w
    return None


def _content_bases(target: str, hosts: list[dict]) -> list[str]:
    """Base URLs to brute-force: each live host, plus its scheme://host root so
    siblings of a path target (e.g. /config next to /purple) are reached too."""
    bases = set()
    for h in hosts:
        u = h["url"].rstrip("/")
        bases.add(u)
        p = urlparse(h["url"])
        bases.add(f"{p.scheme}://{p.netloc}")
    return sorted(bases)[:config.CONTENT_MAX_BASES]


def content_discovery(target: str, hosts: list[dict], timeout: int) -> set[str]:
    """Directory/file brute-force to surface unlinked endpoints. Returns URLs."""
    wl = _pick_wordlist()
    if not wl:
        print("[fosc] content discovery: nenhuma wordlist encontrada, pulando")
        return set()
    bases = _content_bases(target, hosts)
    found: set[str] = set()
    for base in bases:
        if have("feroxbuster"):
            lines = run_lines(
                ["feroxbuster", "-u", base, "-w", wl, "-x", config.CONTENT_EXTENSIONS,
                 "-d", str(config.CONTENT_DEPTH), "-s", config.CONTENT_STATUS,
                 "-t", "40", "--time-limit", f"{timeout}s", "--silent", "-k",
                 "--no-state"], timeout + 20)
            found.update(l.strip() for l in lines if l.strip().startswith("http"))
        elif have("ffuf"):
            found.update(_ffuf_base(base, wl, timeout))
        else:
            print("[fosc] content discovery: nem feroxbuster nem ffuf instalados, pulando")
            return set()
        if len(found) >= config.CONTENT_MAX_RESULTS:
            break
    in_scope_found = {u for u in found if in_scope(u, target)}
    print(f"[fosc] content discovery: {len(in_scope_found)} url(s) em {len(bases)} base(s)")
    return set(list(in_scope_found)[: config.CONTENT_MAX_RESULTS])


def _ffuf_base(base: str, wordlist: str, timeout: int) -> set[str]:
    exts = "." + ",.".join(e for e in config.CONTENT_EXTENSIONS.split(",") if e)
    out = set()
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        path = tf.name
    try:
        subprocess.run(
            ["ffuf", "-u", f"{base}/FUZZ", "-w", wordlist, "-e", exts,
             "-mc", config.CONTENT_STATUS, "-ac", "-t", "40", "-maxtime", str(timeout),
             "-of", "json", "-o", path, "-s"],
            capture_output=True, text=True, timeout=timeout + 20, check=False)
        data = json.loads(open(path).read() or "{}")
        for r in data.get("results", []):
            if r.get("url"):
                out.add(r["url"])
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as e:
        print(f"[fosc] ffuf falhou em {base}: {e}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return out


def run_nuclei(hosts: list[dict], timeout: int) -> list[dict]:
    if not have("nuclei") or not hosts:
        return []
    try:
        proc = subprocess.run(
            ["nuclei", "-silent", "-jsonl", "-severity", "medium,high,critical", "-nc"],
            input="\n".join(h["url"] for h in hosts), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[fosc] nuclei timed out after {timeout}s, continuing without it")
        return []
    except Exception as e:
        print(f"[fosc] nuclei failed: {e}")
        return []
    hits = []
    for line in proc.stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        hits.append({
            "template": rec.get("template-id"),
            "name": (rec.get("info") or {}).get("name"),
            "severity": (rec.get("info") or {}).get("severity"),
            "matched": rec.get("matched-at") or rec.get("host"),
        })
    return hits


def build_items(urls: set[str], hosts: list[dict], nuclei_hits: list[dict]) -> tuple[list[dict], list[str]]:
    tech_by_host = {(urlparse(h["url"]).hostname or "").lower(): h["tech"] for h in hosts}
    js_files = sorted(u for u in urls if urlparse(u).path.lower().endswith((".js", ".mjs")))
    by_pattern: dict[str, dict] = {}
    for u in sorted(urls):
        if is_static(u):
            continue
        pat = route_pattern(u)
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        params = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
        if pat in by_pattern:
            by_pattern[pat]["examples"] = (by_pattern[pat]["examples"] + [u])[:3]
            continue
        by_pattern[pat] = {
            "url": u, "method": "GET", "path": parsed.path or "/", "params": params,
            "host": host, "pattern": pat, "tech": tech_by_host.get(host, []),
            "examples": [u], "nuclei": [],
        }
    for hit in nuclei_hits:
        matched = hit.get("matched") or ""
        mpat = route_pattern(matched) if matched.startswith("http") else None
        for it in by_pattern.values():
            if (mpat and it["pattern"] == mpat) or (matched and matched.rstrip("/") == it["url"].rstrip("/")):
                it["nuclei"].append(hit)
    return list(by_pattern.values()), js_files


def build_surface(target: str, recon_timeout: int = config.DEFAULT_RECON_TIMEOUT, nuclei: bool = True,
                  content: bool = True) -> dict:
    hosts = discover_hosts(target, recon_timeout)
    print(f"[fosc] {len(hosts)} live host(s) for {target}")
    urls = collect_urls(target, hosts, recon_timeout)
    if config.JS_MINING:
        urls |= js_endpoints(target, urls, hosts, recon_timeout)  # SPA/bundle endpoints
    if content and config.CONTENT_DISCOVERY:
        urls |= content_discovery(target, hosts, config.CONTENT_TIMEOUT)
    hits = run_nuclei(hosts, recon_timeout * 2) if nuclei else []
    items, js_files = build_items(urls, hosts, hits)
    print(f"[fosc] {len(urls)} url(s) -> {len(items)} distinct endpoint pattern(s), {len(js_files)} js file(s), {len(hits)} nuclei hit(s)")
    return {"hosts": hosts, "items": items, "js": js_files, "nuclei": hits}


def load_or_build(target: str, run_dir, fresh: bool = False, nuclei: bool = True, content: bool = True) -> dict:
    cache = run_dir / "surface.json"
    if cache.exists() and not fresh:
        try:
            data = json.loads(cache.read_text())
            if isinstance(data, dict) and "items" in data:
                return data
        except json.JSONDecodeError:
            pass
    surface = build_surface(target, nuclei=nuclei, content=content)
    if cache.exists() and fresh:
        # continuous re-recon: keep previously known items, add new ones
        try:
            old = json.loads(cache.read_text())
            if isinstance(old, dict):
                known = {it["pattern"] for it in surface["items"]}
                surface["items"] += [it for it in old.get("items", []) if it.get("pattern") not in known]
        except json.JSONDecodeError:
            pass
    cache.write_text(json.dumps(surface, indent=2))
    return surface
