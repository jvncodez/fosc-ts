"""Thin, defensive wrapper around external CLI recon tools.

Every tool runs in its own process group and is registered while alive, so the
emergency HALT and the target-health circuit breaker can kill recon mid-flight
(before, only the agent sessions were killable — nuclei kept hammering a target
that was already down). HOLD, once set, makes new tool launches no-ops.
"""
import os
import shutil
import signal
import subprocess
import threading

HOLD = threading.Event()          # set by HALT / circuit breaker: launch nothing new
_LIVE: set[int] = set()           # pgids of running tools
_LIVE_LOCK = threading.Lock()

# The full pentest arsenal the agent may reach via Bash, by purpose. Detected at
# runtime; whatever is on PATH is advertised to the agent in the hunt prompt so it
# actually uses the right tool instead of hand-rolling curl loops. Port scanners
# (nmap/masscan/naabu) do RAW TCP and bypass the HTTP scope proxy — keep them gated
# by the scope note and, in production, by egress firewall (see deploy/steering).
ARSENAL = {
    "subdomínios/DNS": ["subfinder", "amass", "assetfinder", "dnsx"],
    "descoberta HTTP": ["httpx", "katana", "gau", "waybackurls", "hakrawler"],
    "portas/serviços": ["nmap", "masscan", "naabu"],
    "conteúdo/fuzzing": ["ffuf", "feroxbuster", "gobuster", "dirsearch"],
    "scan de vulnerabilidade": ["nuclei", "nikto", "wpscan"],
    "exploração web": ["sqlmap", "dalfox", "arjun"],
    "fingerprint/WAF": ["whatweb", "wafw00f"],
    "utilitários": ["jq", "curl", "openssl"],
}


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def arsenal_on_path() -> dict:
    """Which arsenal tools are actually installed, grouped by purpose."""
    found = {}
    for purpose, tools in ARSENAL.items():
        present = [t for t in tools if have(t)]
        if present:
            found[purpose] = present
    return found


def arsenal_note() -> str:
    """A compact line for the hunt prompt listing the installed arsenal, so the
    agent prefers a real tool over improvising."""
    found = arsenal_on_path()
    if not found:
        return ""
    lines = ["Ferramentas de pentest disponíveis no PATH (use via Bash quando ajudar, "
             "SEMPRE dentro do escopo autorizado — não varra nada fora dele):"]
    for purpose, tools in found.items():
        lines.append(f"  - {purpose}: {', '.join(tools)}")
    return "\n".join(lines)


def run_proc(cmd: list[str], *, input: str | None = None, timeout: int) -> tuple[int | None, str, str]:
    """Run a tool tracked for kill_tools(). Returns (returncode, stdout, stderr).
    Raises subprocess.TimeoutExpired (after killing the group) like subprocess.run."""
    if HOLD.is_set():
        print(f"[fosc] alvo em espera (halt/disjuntor) — não iniciando {cmd[0]}")
        return None, "", ""
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    with _LIVE_LOCK:
        _LIVE.add(proc.pid)
    try:
        out, err = proc.communicate(input, timeout=timeout)
        return proc.returncode, out or "", err or ""
    except subprocess.TimeoutExpired:
        _killpg(proc.pid)
        proc.communicate()
        raise
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(proc.pid)


def _killpg(pgid: int) -> bool:
    try:
        os.killpg(pgid, signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def kill_tools() -> int:
    """SIGKILL every running recon tool. Returns how many were killed."""
    with _LIVE_LOCK:
        pgids = list(_LIVE)
    return sum(_killpg(g) for g in pgids)


def run_lines(cmd: list[str], timeout: int) -> list[str]:
    """Run a command, return stdout split into non-empty lines.

    Never raises: missing binary, timeout, or non-zero exit all just
    produce an empty/partial result plus a stderr note so one dead tool
    never takes the whole run down with it.
    """
    if not have(cmd[0]):
        print(f"[fosc] tool not found, skipping: {cmd[0]}")
        return []
    try:
        rc, out, err = run_proc(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[fosc] tool timed out after {timeout}s: {' '.join(cmd)}")
        return []
    except Exception as e:
        print(f"[fosc] tool failed: {' '.join(cmd)}: {e}")
        return []
    if rc not in (0, None) and not out:
        if err:
            print(f"[fosc] {cmd[0]} stderr: {err.strip()[:300]}")
    return [l for l in out.splitlines() if l.strip()]
