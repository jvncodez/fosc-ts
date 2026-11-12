"""Thin, defensive wrapper around external CLI recon tools."""
import shutil
import subprocess

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
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        print(f"[fosc] tool timed out after {timeout}s: {' '.join(cmd)}")
        return []
    except Exception as e:
        print(f"[fosc] tool failed: {' '.join(cmd)}: {e}")
        return []
    if proc.returncode not in (0, None) and not proc.stdout:
        if proc.stderr:
            print(f"[fosc] {cmd[0]} stderr: {proc.stderr.strip()[:300]}")
    return [l for l in proc.stdout.splitlines() if l.strip()]
