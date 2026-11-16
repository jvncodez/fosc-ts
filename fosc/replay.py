"""Cheap mechanical replay — a deterministic pre-gate before the Opus reviewer.

FOSC replays the hunting agent's `repro_curl` and checks whether the claimed
`evidence_marker` actually appears in the response. A clear non-reproduction is a
strong false-positive signal, so we can suppress the finding WITHOUT spending an
Opus verification. This never promotes anything on its own — a reproduction still
goes to the adversarial reviewer (an echoed payload can reproduce yet not be a
real bug). It only short-circuits the clear negatives.

Safety: replay is restricted to IDEMPOTENT requests (GET/HEAD, no body/upload),
to IN-SCOPE hosts only, runs with no shell (argv list), a hard timeout, and
through the scope proxy when one is active. Anything outside that is skipped, not
guessed.
"""
import shlex
import subprocess

from . import recon

# Request shapes that could change server state — never auto-replayed.
_UNSAFE_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                 "--data-urlencode", "-F", "--form", "-T", "--upload-file", "--json"}
_SAFE_METHODS = {"GET", "HEAD"}
_DROP_WITH_ARG = {"-o", "--output"}
_DROP_NO_ARG = {"-O", "--remote-name"}


def _url_of(argv: list[str]) -> str | None:
    for t in argv[1:]:
        if t.startswith("http://") or t.startswith("https://"):
            return t
    return None


def _is_idempotent(argv: list[str]) -> bool:
    for i, t in enumerate(argv):
        if t in _UNSAFE_FLAGS or t.startswith("--data") or t.startswith("--form"):
            return False
        if t in ("-X", "--request"):
            method = (argv[i + 1].upper() if i + 1 < len(argv) else "")
            if method not in _SAFE_METHODS:
                return False
    return True


def _sanitize(argv: list[str], timeout: int, proxy_url: str | None) -> list[str]:
    clean, skip = [argv[0]], False
    for t in argv[1:]:
        if skip:
            skip = False
            continue
        if t in _DROP_WITH_ARG:
            skip = True
            continue
        if t in _DROP_NO_ARG:
            continue
        clean.append(t)
    clean += ["--max-time", str(timeout), "-s", "-S"]
    if proxy_url:
        clean += ["--proxy", proxy_url]
    return clean


def replay_check(repro_curl: str | None, marker: str | None, target: str,
                 proxy_url: str | None = None, timeout: int = 15) -> dict:
    """Return {"status": reproduced|absent|skipped|error, "detail": str}.
    Only "absent" is actionable (suppress); everything else falls through to the
    adversarial reviewer."""
    marker = (marker or "").strip()
    if not repro_curl or not marker:
        return {"status": "skipped", "detail": "sem repro_curl ou evidence_marker"}
    try:
        argv = shlex.split(repro_curl)
    except ValueError:
        return {"status": "skipped", "detail": "repro_curl não parseável"}
    if not argv or not argv[0].rsplit("/", 1)[-1].startswith("curl"):
        return {"status": "skipped", "detail": "repro não é um curl"}
    if not _is_idempotent(argv):
        return {"status": "skipped", "detail": "método não idempotente — replay pulado"}
    url = _url_of(argv)
    if not url:
        return {"status": "skipped", "detail": "sem URL no repro_curl"}
    try:
        if not recon.in_scope(url, recon.target_host(target)):
            return {"status": "skipped", "detail": "URL fora de escopo"}
    except Exception:
        return {"status": "skipped", "detail": "escopo indeterminado"}
    try:
        p = subprocess.run(_sanitize(argv, timeout, proxy_url), capture_output=True,
                           timeout=timeout + 5, text=True, errors="replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"status": "error", "detail": f"replay falhou: {type(e).__name__}"}
    body = (p.stdout or "")[:2_000_000]
    if marker in body or marker.lower() in body.lower():
        return {"status": "reproduced", "detail": "evidence_marker presente na resposta"}
    return {"status": "absent", "detail": "evidence_marker ausente na resposta replayada"}
