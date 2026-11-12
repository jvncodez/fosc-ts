"""Paths, defaults and the small user config file (~/.fosc/config.json)."""
import json
import os
from pathlib import Path

VERSION = "0.2.0-bb"

HOME = Path(os.path.expanduser("~"))
# Isolated state root for the Banco do Brasil governance build, so its runs,
# knowledge and audit trail never mix with the base FOSC install. Override with
# the SENTINELA_HOME env var (useful on AWS/Kiro).
FOSC_HOME = Path(os.environ.get("SENTINELA_HOME", str(HOME / ".bb-sentinela")))
STATE_ROOT = FOSC_HOME / "runs"
KNOWLEDGE_ROOT = FOSC_HOME / "knowledge"
CHAT_ROOT = FOSC_HOME / "chat"
CONFIG_PATH = FOSC_HOME / "config.json"

# repo root, used by the viewer to spawn detached `bin/fosc -h` processes
REPO_ROOT = Path(__file__).resolve().parents[1]
FOSC_BIN = REPO_ROOT / "bin" / "fosc"

DEFAULT_WORKERS = 2
DEFAULT_TASK_TIMEOUT = 1200         # seconds per headless claude hunt task (deep, persistent)
DEFAULT_VERIFY_TIMEOUT = 480        # seconds for the adversarial Opus review
DEFAULT_CONTINUOUS_INTERVAL = 1800  # seconds between recon refresh passes
DEFAULT_RECON_TIMEOUT = 180         # seconds per external recon tool call
MAX_ARCHIVE_URLS = 3000             # cap on gau/waybackurls output per run

# Active content discovery (directory/file brute-force) — finds the unlinked
# endpoints that passive sources (gau/wayback/katana) never see. feroxbuster
# (recursive) is preferred, ffuf is the fallback.
CONTENT_DISCOVERY = True
CONTENT_WORDLISTS = [                # first one that exists on disk is used
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]
CONTENT_EXTENSIONS = "php,html,sql,ini,bak,txt,old,json,conf,inc,zip,env,git,asp,aspx,jsp,do"
CONTENT_DEPTH = 2                    # feroxbuster recursion depth
CONTENT_TIMEOUT = 240               # seconds budget per base URL scan
CONTENT_MAX_BASES = 6               # cap how many base URLs we brute-force
CONTENT_MAX_RESULTS = 1500          # cap discovered URLs fed to the surface
CONTENT_STATUS = "200,204,301,302,307,401,403,405"

# --- Proteção do alvo (não derrubar o que estamos testando) ---------------
# Teto de requisições/s e de concorrência para TODA ferramenta de recon que
# toca o alvo (httpx, katana, feroxbuster/ffuf, nuclei). Os padrões das
# ferramentas (nuclei 150 req/s, ferox/ffuf 40 threads) derrubam servidor
# pequeno. Ajustável por env para alvos robustos.
RECON_RATE = int(os.environ.get("SENTINELA_RECON_RATE", "10"))       # req/s por ferramenta
RECON_THREADS = int(os.environ.get("SENTINELA_RECON_THREADS", "5"))  # conexões simultâneas
# Disjuntor: sonda o alvo periodicamente; N falhas seguidas (timeout, erro de
# conexão ou 502/503/504) pausam a caçada e encerram o que está em voo.
HEALTH_CHECK = os.environ.get("SENTINELA_HEALTH", "1").lower() not in ("0", "false", "no")
HEALTH_INTERVAL = int(os.environ.get("SENTINELA_HEALTH_INTERVAL", "20"))  # s entre sondas
HEALTH_FAILS = int(os.environ.get("SENTINELA_HEALTH_FAILS", "3"))        # falhas seguidas p/ desarmar
HEALTH_TIMEOUT = int(os.environ.get("SENTINELA_HEALTH_TIMEOUT", "10"))   # s por sonda

# DNS subdomain brute-force (domain targets only; skipped for IP/URL/localhost).
# dnsx resolves a wordlist of candidate subdomains against the target apex.
DNS_BRUTE = True
DNS_WORDLISTS = [                   # first one that exists on disk is used
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
]

CLAUDE_BIN = "claude"
HUNT_MODEL = "sonnet"      # kept as the primary of the hunt ladder (back-compat)
VERIFY_MODEL = "opus"
CONSOLIDATE_MODEL = "sonnet"

# ---------------------------------------------------------------------------
# Model layer (fosc/models.py). The application asks for a ROLE, never a model;
# the router picks the provider and FAILS OVER to the next model on error /
# refusal / slowness. Swapping, reordering or adding a model (e.g. moving to
# Amazon Bedrock on AWS) is configuration here — never an application change.
# ---------------------------------------------------------------------------
# Global provider for bare aliases. Per-ladder entries may override it with an
# explicit "provider:model-id". On AWS: SENTINELA_PROVIDER=bedrock.
MODEL_PROVIDER = os.environ.get("SENTINELA_PROVIDER", "anthropic").lower()  # anthropic | bedrock

# Alias -> concrete model id, per provider. Bedrock ids are inference-profile ids
# and vary by account/region, so every one is env-overridable (set on AWS).
ANTHROPIC_MODEL_IDS = {"sonnet": "sonnet", "opus": "opus", "haiku": "haiku"}
BEDROCK_MODEL_IDS = {
    "sonnet": os.environ.get("BEDROCK_SONNET", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    "opus":   os.environ.get("BEDROCK_OPUS",   "us.anthropic.claude-opus-4-1-20250805-v1:0"),
    "haiku":  os.environ.get("BEDROCK_HAIKU",  "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
}

# Role -> ordered fallback ladder. Entry is an alias (resolved via the provider
# above) or an explicit "provider:model-id" to pin/cross providers. The first
# entry of each ladder reproduces the legacy single-model behaviour.
MODEL_LADDERS = {
    "hunt":        ["sonnet", "haiku"],
    "verify":      ["opus", "sonnet"],
    "consolidate": ["sonnet", "haiku"],
    "privesc":     ["sonnet", "opus"],
}

MODEL_MAX_ATTEMPTS = 3        # never try more than this many models for one call
# A slow (not offline) model is abandoned at this fraction of the task's hard
# timeout so the fallback model still has time to finish.
MODEL_ATTEMPT_FRACTION = 0.6

# ---------------------------------------------------------------------------
# Network-level scope enforcement (G0, fosc/scope_proxy.py). When on, the agent's
# HTTP(S) traffic is routed through an egress proxy that allows ONLY in-scope hosts
# plus the model-API egress below — so leaving scope is impossible on the wire, not
# just forbidden in a prompt. Opt-in because the egress allowlist is environment
# specific (Anthropic API vs Bedrock).
SCOPE_PROXY = os.environ.get("SENTINELA_SCOPE_PROXY", "").lower() in ("1", "true", "yes")
# Hosts the model/agent layer itself must reach (NEVER the target). A "." prefix is
# a suffix match. ".anthropic.com" covers api + mcp-proxy + statsig; ".amazonaws.com"
# covers Bedrock runtime/STS on AWS. Third-party telemetry (e.g. datadog) is left
# OUT on purpose — it is harmless to block and keeps egress minimal.
PROXY_EGRESS_HOSTS = [
    ".anthropic.com",
    ".amazonaws.com",
]

# Depth controls. FOSC hunts deep and persistent by default; budget caps keep a
# single endpoint from running away. budget 0 = uncapped.
HUNT_EFFORT = "high"                 # reasoning effort per hunt task
VERIFY_EFFORT = "high"               # reasoning effort for the Opus review
DEFAULT_TASK_BUDGET_USD = 3.0        # max spend per endpoint (0 = uncapped)

# Privesc is deeper than a single web endpoint: more enumeration, more retries,
# more research-and-install detours. It gets its own (larger) caps and a bounded
# multi-pass loop that feeds each pass's enumeration back into the next.
PRIVESC_TIMEOUT = 2400               # seconds per privesc pass
PRIVESC_BUDGET_USD = 6.0             # max spend across the whole privesc stage
PRIVESC_MAX_PASSES = 3               # stop after a win, or after this many passes

# Connectivity. If a task streams nothing for this long, FOSC probes the network
# and, if offline, kills the (silently-retrying) claude process and says so,
# instead of spinning until the hard timeout.
NET_WATCHDOG_SECS = 25

# SPA support: mine API endpoints out of JS bundles (a hash-router SPA exposes no
# routes to a crawler, so without this the hunt queue is empty).
JS_MINING = True

# Authorization Engine (human-in-the-loop). mode: ask (default, require human
# approval for sensitive actions) | yolo (auto-approve, lab only) | paranoid
# (approve everything). AUTHZ_HUNT_GATE also gates the start of active hunting.
AUTHZ_MODE = os.environ.get("SENTINELA_AUTHZ", "ask").lower()  # ask | yolo | paranoid
AUTHZ_HUNT_GATE = True      # ask once per run before active testing begins
AUTHZ_TIMEOUT = 1800        # headless: seconds to wait for a human decision
AUTHZ_POLL = 2              # headless: seconds between checks of the approvals log

VULN_BUNDLE = [
    "IDOR", "broken auth / session handling", "SSRF", "XSS (reflected/stored/DOM)",
    "SQLi / NoSQLi", "open redirect", "path traversal / LFI", "SSTI",
    "business logic abuse (price/qty/race condition)", "mass assignment",
    "file upload bypass", "API auth bypass / missing authZ on object access",
]

# never queued as hunt items; .js URLs are still kept as context for the agent
STATIC_EXT = {
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".mp3", ".webm",
    ".pdf", ".zip", ".gz",
}

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def normalize_target(target: str) -> str:
    """Canonical form of what the operator typed (CLI and web panel).

    The URL fragment (`#/`, `#/login`…) is client-side SPA routing: it never
    reaches the server, so it is not part of the target. Without this,
    `https://x/#/` is rejected by the panel and splits into a separate
    campaign from `https://x`. A bare trailing "/" on the origin is dropped
    for the same reason."""
    t = (target or "").strip()
    t = t.split("#", 1)[0]
    if "://" in t:
        scheme, rest = t.split("://", 1)
        if rest.endswith("/") and rest.count("/") == 1:
            rest = rest[:-1]
        t = f"{scheme.lower()}://{rest}"
    return t


def safe_name(target: str) -> str:
    return target.replace("/", "_").replace(":", "_")


def run_exists(target: str) -> bool:
    """True if a run dir already exists (read-only paths must not create one)."""
    return (STATE_ROOT / safe_name(target)).is_dir()


def run_dir(target: str) -> Path:
    d = STATE_ROOT / safe_name(target)
    d.mkdir(parents=True, exist_ok=True)
    (d / "tasks").mkdir(exist_ok=True)
    (d / "pocs").mkdir(exist_ok=True)
    return d


def load_user_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def save_user_config(cfg: dict):
    FOSC_HOME.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    os.chmod(CONFIG_PATH, 0o600)
