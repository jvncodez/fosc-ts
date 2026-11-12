"""`fosc -w -a <target>` -- read-only live terminal dashboard.

Polls RunState.snapshot(); never touches the hunt process, so it can be
opened and closed freely from any terminal.
"""
import time

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .state import RunState
from .ui import ACCENT, SEV_STYLE, VERDICT_STYLE

STATUS_STYLE = {"running": "bold #38d458", "paused": "bold #e0a84a", "sleeping": "#6c8cff",
                "recon": "#6c8cff", "finished": "grey62", "stopped": "grey62", "crashed": "bold red"}


def _fmt_age(ts, now):
    s = int(max(0, now - (ts or now)))
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def _render(state: RunState) -> Layout:
    snap = state.snapshot(results=14, activity=14)
    meta, now = snap["meta"], time.time()

    kpi = Table.grid(expand=True)
    for _ in range(6):
        kpi.add_column(ratio=1)
    total = snap["surface_total"] or 0
    kpi.add_row(
        Text.assemble(("status\n", "grey50"), (snap["status"], STATUS_STYLE.get(snap["status"], ""))),
        Text.assemble(("round\n", "grey50"), (f"{meta.get('round', '-')}", "bold"),
                      (f"  {meta.get('round_done', 0)}/{meta.get('round_total', 0)}", "grey50")),
        Text.assemble(("tested\n", "grey50"), (f"{snap['done']}", "bold"), (f" / {total}", "grey50")),
        Text.assemble(("confirmed\n", "grey50"), (f"{snap['confirmed_count']}", "bold #38d458")),
        Text.assemble(("cost\n", "grey50"), (f"${(meta.get('cost_usd') or 0):.2f}", "bold")),
        Text.assemble(("uptime\n", "grey50"), (_fmt_age(meta.get("started_at"), now) if meta.get("started_at") else "-", "bold")),
    )
    sev = Text("  ")
    for s, n in snap["severity"].items():
        if n:
            sev.append(f" {s.upper()} {n} ", style=SEV_STYLE.get(s, ""))
            sev.append("  ")
    header = Panel(Group(kpi, sev) if sev.plain.strip() else kpi,
                   title=f"[bold {ACCENT}]FOSC[/] · {snap['target']}", border_style=ACCENT)

    active = Table(expand=True, box=None, header_style="grey50")
    active.add_column("elapsed", width=9)
    active.add_column("phase", width=10)
    active.add_column("endpoint")
    for a in sorted(snap["active"].values(), key=lambda v: v.get("started_at", 0)):
        active.add_row(_fmt_age(a.get("started_at"), now), a.get("phase", ""), a.get("url", ""))
    if not snap["active"]:
        active.add_row("-", "", Text("idle", style="grey50"))

    feed = Table(expand=True, box=None, show_header=False)
    feed.add_column(width=9, style="grey50")
    feed.add_column()
    for a in snap["activity"]:
        style = {"result": "bold", "system": ACCENT}.get(a.get("kind"), "grey70")
        feed.add_row(time.strftime("%H:%M:%S", time.localtime(a["ts"])), Text(a.get("msg", ""), style=style))

    results = Table(expand=True, box=None, header_style="grey50")
    results.add_column("verdict", width=12)
    results.add_column("sev", width=9)
    results.add_column("class", width=22)
    results.add_column("endpoint")
    for r in snap["results"]:
        v, s = r.get("verdict", "?"), (r.get("severity") or "").lower()
        results.add_row(Text(v, style=VERDICT_STYLE.get(v, "")),
                        Text(s.upper() if s and v == "confirmed" else "", style=SEV_STYLE.get(s, "")),
                        str(r.get("vuln_class") or "-"), r.get("url", ""))

    layout = Layout()
    layout.split_column(
        Layout(header, size=6 if sev.plain.strip() else 5),
        Layout(Panel(active, title="in flight", border_style="grey30"), size=max(5, len(snap["active"]) + 4)),
        Layout(name="bottom"),
    )
    layout["bottom"].split_row(
        Layout(Panel(feed, title="live activity", border_style="grey30")),
        Layout(Panel(results, title="results", border_style="grey30")),
    )
    return layout


def watch(target: str, interval: float = 2.0):
    state = RunState(target)
    if not state.meta_path.exists():
        print(f"[fosc] no run found yet for '{target}'. Start one first: fosc -h -a {target}")
        return
    try:
        with Live(_render(state), refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(interval)
                live.update(_render(state))
    except KeyboardInterrupt:
        pass
