"""Startup banner: FOSC/TS wordmark (paleta BB amarelo→azul) + tagline + status."""
import sys

from . import config

# "FOSC", ANSI Shadow font. O "/TS" vem como acento abaixo.
LOGO = [
    "███████╗ ██████╗ ███████╗ ██████╗",
    "██╔════╝██╔═══██╗██╔════╝██╔════╝",
    "█████╗  ██║   ██║███████╗██║     ",
    "██╔══╝  ██║   ██║╚════██║██║     ",
    "██║     ╚██████╔╝███████║╚██████╗",
    "╚═╝      ╚═════╝ ╚══════╝ ╚═════╝",
]
# Paleta Banco do Brasil: amarelo no topo -> azul claro embaixo.
_TOP = (250, 225, 0)      # amarelo BB
_BOTTOM = (46, 139, 218)  # azul claro BB
RESET = "\033[0m"
DIM = "\033[38;2;120;120;128m"


def _rgb(r, g, b):
    return f"\033[1;38;2;{r};{g};{b}m"


def _grad(i: int, n: int):
    """Interpola TOP->BOTTOM na linha i de n."""
    t = i / max(n - 1, 1)
    return tuple(round(a + (b - a) * t) for a, b in zip(_TOP, _BOTTOM))


def _status_line() -> str:
    try:
        from .state import list_runs
        runs = list_runs()
        live = sum(1 for r in runs if r.status() in ("running", "paused", "sleeping", "recon"))
        confirmed = sum(len(r.confirmed()) for r in runs)
        return f"{live} campanha(s) ativa(s) · {confirmed} achado(s) confirmado(s) · {len(runs)} alvo(s)"
    except Exception:
        return ""


def print_banner():
    if not sys.stdout.isatty():
        return  # mantém o output piped e o hunt.log limpos
    print()
    n = len(LOGO)
    for i, line in enumerate(LOGO):
        print("  " + _rgb(*_grad(i, n)) + line + RESET)
    print(f"  {_rgb(46, 139, 218)}/ TS{RESET}  {_rgb(10, 61, 122)}Ferramenta Ofensiva de "
          f"Segurança Cibernética para Tecnologia e Serviços{RESET}")
    print(f"  {DIM}escopo estrito · human-in-the-loop · trilha auditável · MITRE ATT&CK"
          f"  ·  v{config.VERSION}{RESET}")
    status = _status_line()
    if status:
        print(f"  {DIM}{status}{RESET}")
    print()
