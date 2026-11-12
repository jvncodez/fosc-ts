"""Startup banner: red gradient FOSC AGENT logo + tagline + live status."""
import sys

from . import config

# "FOSC" over "AGENT", ANSI Shadow font.
LOGO = [
    "███████╗ ██████╗ ███████╗ ██████╗",
    "██╔════╝██╔═══██╗██╔════╝██╔════╝",
    "█████╗  ██║   ██║███████╗██║     ",
    "██╔══╝  ██║   ██║╚════██║██║     ",
    "██║     ╚██████╔╝███████║╚██████╗",
    "╚═╝      ╚═════╝ ╚══════╝ ╚═════╝",
    "",
    " █████╗  ██████╗ ███████╗███╗   ██╗████████╗",
    "██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝",
    "███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ",
    "██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ",
    "██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ",
    "╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ",
]
# bright red at the top fading to deep crimson, interpolated over all rows
_TOP = (255, 92, 92)
_BOTTOM = (150, 6, 26)
RESET = "\033[0m"
DIM = "\033[38;2;120;120;128m"


def _rgb(r, g, b):
    return f"\033[1;38;2;{r};{g};{b}m"


def _grad(i: int, n: int):
    """Interpolate TOP->BOTTOM at row i of n."""
    t = i / max(n - 1, 1)
    return tuple(round(a + (b - a) * t) for a, b in zip(_TOP, _BOTTOM))


def _status_line() -> str:
    try:
        from .state import list_runs
        runs = list_runs()
        live = sum(1 for r in runs if r.status() in ("running", "paused", "sleeping", "recon"))
        confirmed = sum(len(r.confirmed()) for r in runs)
        return f"{live} hunt(s) running · {confirmed} confirmed finding(s) · {len(runs)} target(s)"
    except Exception:
        return ""


def print_banner():
    if not sys.stdout.isatty():
        return  # keep piped output and hunt.log clean
    print()
    n = len(LOGO)
    for i, line in enumerate(LOGO):
        if not line:
            print()
            continue
        print("  " + _rgb(*_grad(i, n)) + line + RESET)
    print(f"  {_rgb(255, 64, 64)}Ferramenta Ofensiva de Segurança Cibernética{RESET}")
    print(f"  {_rgb(214, 24, 40)}recon → hunt → review → PoC{RESET}  {DIM}v{config.VERSION} · never stops on a finding{RESET}")
    status = _status_line()
    if status:
        print(f"  {DIM}{status}{RESET}")
    print()
