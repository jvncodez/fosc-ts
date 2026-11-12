"""Terminal output for `fosc -h`: rich when on a TTY, plain lines otherwise
(plain is what lands in hunt.log when the viewer launches a hunt).

On a TTY it also keeps a live, Claude-Code-style "thinking" status line pinned
at the bottom (rotating hacker verbs + elapsed + progress + the tool running),
and every real print is drawn cleanly above it."""
import sys
import threading
import time
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import config
from .thinking import ACCENT as A_ANSI, DIM, TEXT, RESET, FRAMES, VERBS, TOOL_VERB

ACCENT = "#ff3b3b"
VERDICT_STYLE = {
    "confirmed": "bold #38d458", "refuted": "#b07cff", "unverified": "#e0a84a",
    "duplicate": "#6c8cff", "rejected": "grey50", "inconclusive": "#e0c34a",
    "timeout": "magenta", "error": "bold red", "offline": "bold #e0a84a",
}
SEV_STYLE = {"critical": "bold white on #b0001a", "high": "bold #ff5a36", "medium": "bold #ffb020",
             "low": "#4aa8ff", "info": "grey62"}


def _fmt_elapsed(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    return f"{sec // 60}m{sec % 60:02d}s"


class Out:
    def __init__(self, rich_mode: bool):
        self.rich = rich_mode
        self.c = Console(highlight=False) if rich_mode else None
        self._lock = threading.Lock()
        self._t0 = time.time()
        # live status line (TTY only)
        self._live_on = False
        self._stop = threading.Event()
        self._thread = None
        self._done = 0
        self._total = 0
        self._running = 0
        self._pin_verb = None
        self._pin_detail = ""
        self._pin_until = 0.0
        self._cost = 0.0

    # --- live status line ------------------------------------------------- #
    def start_live(self):
        if not self.rich or self._thread:
            return
        self._live_on = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop_live(self):
        if not self._thread:
            return
        self._stop.set()
        self._thread.join(timeout=0.5)
        self._thread = None
        with self._lock:
            self._clear_live()
            self._live_on = False

    def set_counts(self, done, total):
        self._done, self._total = done, total

    def set_running(self, n):
        self._running = n

    def activity(self, msg):
        """Feed a tool-activity line from a worker; pins the matching verb."""
        if not self.rich:
            return
        low = (msg or "").lower()
        verb = next((v for k, v in TOOL_VERB.items() if k in low), None)
        detail = (msg or "").strip().replace("\n", " ")
        if len(detail) > 48:
            detail = detail[:47] + "…"
        self._pin_verb = verb
        self._pin_detail = detail
        self._pin_until = time.time() + 3.5

    def _animate(self):
        while not self._stop.is_set():
            with self._lock:
                self._clear_live()
                self._draw_live()
            self._stop.wait(0.1)

    def _clear_live(self):
        if self._live_on:
            sys.stdout.write("\r\033[0K")
            sys.stdout.flush()

    def _draw_live(self):
        if not self._live_on:
            return
        now = time.time()
        if now < self._pin_until:
            verb = self._pin_verb or VERBS[int((now - self._t0) / 2.2) % len(VERBS)]
            detail = self._pin_detail
        else:
            verb = VERBS[int((now - self._t0) / 2.2) % len(VERBS)]
            detail = ""
        frame = FRAMES[int(now / 0.1) % len(FRAMES)]
        bits = [_fmt_elapsed(now - self._t0)]
        if self._total:
            bits.append(f"{self._done}/{self._total}")
        if self._running:
            bits.append(f"{self._running} ativo(s)")
        if self._cost:
            bits.append(f"${self._cost:.2f}")
        if detail:
            bits.append(detail)
        meta = " · ".join(bits)
        sys.stdout.write(f"\r\033[0K{A_ANSI}{frame}{RESET} {TEXT}{verb}…{RESET} {DIM}({meta}){RESET}")
        sys.stdout.flush()

    @contextmanager
    def _region(self):
        """Hold the lock, clear the live line, run the print, redraw the line."""
        with self._lock:
            self._clear_live()
            try:
                yield
            finally:
                self._draw_live()

    # --- prints ----------------------------------------------------------- #
    def _plain(self, msg: str):
        with self._region():
            print(f"[fosc {time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def header(self, target, run_dir, workers, continuous):
        if not self.rich:
            return self._plain(f"hunt {target} workers={workers} continuous={continuous} state={run_dir}")
        g = Table.grid(padding=(0, 3))
        g.add_row(Text("target", style="grey50"), Text(target, style="bold"),
                  Text("mode", style="grey50"), Text("continuous" if continuous else "single pass"))
        from . import models
        ms = models.summary()
        hunt_ladder = " → ".join(ms["ladders"].get("hunt", []))
        g.add_row(Text("workers", style="grey50"), Text(str(workers)),
                  Text("provider", style="grey50"), Text(ms["provider"]))
        g.add_row(Text("", style="grey50"), Text(""),
                  Text("hunt", style="grey50"), Text(hunt_ladder, style="grey62"))
        g.add_row(Text("state", style="grey50"), Text(str(run_dir), style="grey62"), Text(""), Text(""))
        with self._region():
            self.c.print(Panel(g, title=f"[bold {ACCENT}]FOSC/TS[/]", border_style=ACCENT, expand=False))

    def info(self, msg):
        if not self.rich:
            return self._plain(msg)
        with self._region():
            self.c.print(f"[{ACCENT}]›[/] {msg}")

    def warn(self, msg):
        if not self.rich:
            return self._plain("WARN " + msg)
        with self._region():
            self.c.print(f"[bold #e0a84a]![/] {msg}")

    def round_start(self, n, total):
        self._done, self._total = 0, total
        if not self.rich:
            return self._plain(f"round {n}: {total} endpoint(s)")
        with self._region():
            self.c.rule(f"[bold]round {n}[/] · {total} endpoint(s)", style="grey30")

    def result(self, item, res, done, total):
        self._done, self._total = done, total
        self._cost += res.get("cost", 0) or 0
        v = res.get("verdict", "?")
        if not self.rich:
            return self._plain(f"[{done}/{total}] {v.upper()} {item['url']} -- {(res.get('summary') or '')[:120]}")
        bar_w = 18
        filled = int(bar_w * done / max(1, total))
        bar = f"[{ACCENT}]{'━' * filled}[/][grey23]{'━' * (bar_w - filled)}[/]"
        sev = (res.get("severity") or "").lower()
        sev_txt = f" [{SEV_STYLE.get(sev, '')}] {sev.upper()} [/]" if sev and v == "confirmed" else ""
        cost = f"[grey50]${res.get('cost', 0):.3f}[/]"
        with self._region():
            self.c.print(f"{bar} [grey50]{done:>3}/{total}[/] [{VERDICT_STYLE.get(v, '')}]{v:<12}[/]"
                         f"{sev_txt} {item['url']}  {cost}")
            if v not in ("rejected",) and res.get("summary"):
                self.c.print(f"   [grey50]{(res['summary'] or '')[:150]}[/]")

    def confirmed(self, f):
        if not self.rich:
            return self._plain(f"*** CONFIRMED {f.get('severity')} {f.get('vuln_class')} {f.get('url')} -> {f.get('report_path')}")
        sev = (f.get("severity") or "info").lower()
        body = Table.grid(padding=(0, 2))
        body.add_row(Text("class", style="grey50"), Text(f.get("vuln_class") or "-", style="bold"))
        body.add_row(Text("severity", style="grey50"), Text(f" {sev.upper()} ", style=SEV_STYLE.get(sev, "")))
        body.add_row(Text("endpoint", style="grey50"), Text(f.get("url", "")))
        mitre = ", ".join(t.get("id", "") for t in (f.get("mitre") or []))
        if mitre:
            body.add_row(Text("att&ck", style="grey50"), Text(mitre, style="#6c8cff"))
        body.add_row(Text("report", style="grey50"), Text(f.get("report_path") or "-", style="grey62"))
        body.add_row(Text("summary", style="grey50"), Text((f.get("summary") or "")[:300]))
        with self._region():
            self.c.print(Panel(body, title="[bold #38d458]✔ confirmed finding[/]", border_style="#38d458"))

    def privesc(self, pv):
        esc = pv.get("escalated")
        route = f"{pv.get('from_user') or '?'} → {pv.get('to_user') or '?'}"
        passes = pv.get("passes", 1)
        # host root vs isolated container root — don't oversell the latter
        host = pv.get("host_reached")
        in_cont = pv.get("in_container")
        if host:
            scope = "root no HOST"
        elif in_cont and esc:
            scope = "root de CONTAINER (isolado)"
        else:
            scope = "root"
        if not self.rich:
            tag = f"ESCALATED [{scope}]" if esc else "no-escalation"
            return self._plain(f"*** PRIVESC {tag} {route} via {pv.get('vector')} "
                               f"({passes}p) -> {pv.get('report_path')}")
        if esc:
            color = "#38d458" if host else "#e0a84a"  # amber for isolated container root
            body = Table.grid(padding=(0, 2))
            body.add_row(Text("escalou", style="grey50"), Text(f"{route}  [{scope}]", style=f"bold {color}"))
            body.add_row(Text("vetor", style="grey50"), Text(pv.get("vector") or "-"))
            body.add_row(Text("passes", style="grey50"), Text(str(passes)))
            body.add_row(Text("report", style="grey50"), Text(pv.get("report_path") or "-", style="grey62"))
            body.add_row(Text("resumo", style="grey50"), Text((pv.get("summary") or "")[:300]))
            with self._region():
                self.c.print(Panel(body, title=f"[bold {color}]★ PRIVILEGE ESCALATION — {scope}[/]",
                                   border_style=color))
        else:
            ns = pv.get("next_steps") or []
            tail = f" · próximos: {ns[0][:80]}" if ns else ""
            with self._region():
                self.c.print(f"[#e0a84a]privesc:[/] não escalou ({route}, {passes}p) · "
                             f"[grey50]{(pv.get('summary') or '')[:120]}{tail}[/]")

    def footer(self, state):
        snap = state.snapshot(results=0, activity=0)
        cost = snap["meta"].get("cost_usd") or 0
        msg = (f"done {snap['done']} · confirmed {snap['confirmed_count']} · "
               f"cost ${cost:.2f} · status {snap['meta'].get('status')}")
        if not self.rich:
            return self._plain(msg)
        with self._region():
            self.c.print(Panel(msg, border_style="grey30", expand=False))
