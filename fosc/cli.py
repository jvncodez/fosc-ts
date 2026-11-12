import argparse
import json
import sys

from . import config
from .banner import print_banner
from .engine import run_hunt
from .state import RunState
from .tui import watch as tui_watch
from .webview import run_viewer


def do_hunt(args):
    if args.effort:
        config.HUNT_EFFORT = args.effort
    if args.budget is not None:
        config.DEFAULT_TASK_BUDGET_USD = args.budget
    run_hunt(
        target=args.target,
        scope_note=args.scope,
        workers=args.workers,
        timeout=args.timeout,
        continuous=args.continuous,
        interval=args.interval,
        max_items=args.max_items,
        fresh=args.fresh,
        nuclei=not args.no_nuclei,
        content=not args.no_content,
        extra_headers=(args.header or []) + ([args.auth] if args.auth else []),
    )
    # Single-pass hunt finished on a terminal: open the follow-up chat.
    # (continuous mode never returns here; panel-launched hunts aren't a TTY.)
    if not args.continuous and not args.no_chat and sys.stdin.isatty() and sys.stdout.isatty():
        from .chat import chat_session
        state = RunState(args.target)
        scope_note = args.scope or state.read_meta().get("scope") or args.target
        chat_session(state, args.target, scope_note, model=args.chat_model, timeout=args.timeout)


def do_chat(args):
    from .chat import chat_session
    state, scope_note = None, None
    if args.target:
        if config.run_exists(args.target):
            state = RunState(args.target)
            scope_note = state.read_meta().get("scope") or args.target
        else:
            scope_note = args.target
    chat_session(state, args.target, scope_note, model=args.chat_model, timeout=args.timeout)


def do_watch(args):
    tui_watch(args.target, interval=args.refresh)


def do_status(args):
    snap = RunState(args.target).snapshot(results=0, activity=0)
    m = snap["meta"]
    print(f"status:     {snap['status']}")
    print(f"state dir:  {RunState(args.target).dir}")
    print(f"tested:     {snap['done']} / {snap['surface_total']}")
    print(f"confirmed:  {snap['confirmed_count']}  " +
          " ".join(f"{k}={v}" for k, v in snap["severity"].items() if v))
    print(f"verdicts:   " + ", ".join(f"{k}={v}" for k, v in sorted(snap["verdicts"].items())))
    print(f"cost:       ${(m.get('cost_usd') or 0):.2f}")


def do_report(args):
    state = RunState(args.target)
    if args.confirmed_only:
        rows = state.confirmed()
        if not rows:
            print("no confirmed findings yet.")
        for f in rows:
            print(f"[{(f.get('severity') or '?').upper()}] {f.get('vuln_class')}  {f.get('url')}")
            print(f"    {f.get('summary') or ''}")
            print(f"    report: {state.dir / f['report_path'] if f.get('report_path') else '-'}")
        return
    if not state.results_path.exists():
        print("no results yet.")
        return
    for line in state.results_path.read_text().splitlines():
        rec = json.loads(line)
        print(f"[{rec.get('verdict')}] {rec.get('url')}  class={rec.get('vuln_class')}")
        if rec.get("summary"):
            print(f"    {rec['summary']}")


def do_stop(args):
    state = RunState(args.target)
    state.stop_path.write_text("stop requested\n")
    state.pause_path.unlink(missing_ok=True)
    print(f"stop requested for {args.target}: in-flight tasks finish, then the hunt exits.")


def do_pause(args):
    RunState(args.target).pause_path.write_text("paused\n")
    print(f"paused {args.target}: no new tasks start until `fosc --resume -a {args.target}`.")


def do_resume(args):
    RunState(args.target).pause_path.unlink(missing_ok=True)
    print(f"resumed {args.target}.")


def do_view(args):
    run_viewer(args.port, preselect_target=args.target)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fosc",
        add_help=False,
        description="Autonomous recon-to-PoC bug hunting loop.",
        epilog="examples:\n"
               "  fosc -h -a alvo.com\n"
               "  fosc -h -a alvo.com --max-items 5\n"
               "  fosc -h -a alvo.com --continuous\n"
               "  fosc -w -a alvo.com\n"
               "  fosc -v -p 5555\n"
               "  fosc -s -a alvo.com\n"
               "  fosc -r -a alvo.com --confirmed-only\n"
               "  fosc --pause -a alvo.com   /   fosc --resume -a alvo.com\n"
               "  fosc -x -a alvo.com\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--help", action="help", help="show this help message and exit")

    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument("-h", "--hunt", dest="action", action="store_const", const="hunt",
                         help="hunter mode: recon -> rank -> hunt -> validate -> PoC, loops over the surface")
    action.add_argument("-c", "--chat", dest="action", action="store_const", const="chat",
                         help="conversar com o FOSC AGENT (assistente de pentest); -a opcional dá contexto do alvo")
    action.add_argument("-w", "--watch", dest="action", action="store_const", const="watch",
                         help="live terminal dashboard for a running (or finished) hunt")
    action.add_argument("-v", "--view", dest="action", action="store_const", const="view",
                         help="viewer: localhost web panel to watch progress, launch new hunts and stop them")
    action.add_argument("-s", "--status", dest="action", action="store_const", const="status",
                         help="print progress counters for a target")
    action.add_argument("-r", "--report", dest="action", action="store_const", const="report",
                         help="print the findings log for a target")
    action.add_argument("-x", "--stop", dest="action", action="store_const", const="stop",
                         help="parar: in-flight tasks finish, then the hunt exits")
    action.add_argument("--pause", dest="action", action="store_const", const="pause",
                         help="pausar: stop starting new tasks until --resume")
    action.add_argument("--resume", dest="action", action="store_const", const="resume",
                         help="retomar a paused hunt")
    action.add_argument("--shell", dest="action", action="store_const", const="shell",
                         help="reverse shell: sobe túnel ngrok + listener e dispara a RCE do alvo (ou --exec)")
    action.add_argument("--approvals", dest="action", action="store_const", const="approvals",
                         help="listar pedidos de autorização pendentes (human-in-the-loop)")
    action.add_argument("--approve", dest="action", action="store_const", const="approve",
                         help="aprovar um pedido de autorização (use com --id)")
    action.add_argument("--deny", dest="action", action="store_const", const="deny",
                         help="negar um pedido de autorização (use com --id)")

    p.add_argument("-a", "--alvo", dest="target", default=None,
                    help="alvo: target domain or URL, e.g. alvo.com or https://app.alvo.com "
                         "(required for every action except -v)")
    p.add_argument("-p", "--port", type=int, default=5555,
                    help="porta: with -v, the localhost port to serve the viewer panel on (default 5555)")

    p.add_argument("--scope", help="explicit scope/authorization note passed to each hunt task")
    p.add_argument("--workers", type=int, default=config.DEFAULT_WORKERS)
    p.add_argument("--timeout", type=int, default=config.DEFAULT_TASK_TIMEOUT,
                    help="seconds per hunt task before it's killed")
    p.add_argument("--continuous", action="store_true",
                    help="never stop: re-recon and keep hunting forever (until -x / Ctrl+C)")
    p.add_argument("--interval", type=int, default=config.DEFAULT_CONTINUOUS_INTERVAL,
                    help="seconds between re-recon passes in --continuous mode")
    p.add_argument("--max-items", type=int, default=None,
                    help="cap items per round, useful for a first smoke test")
    p.add_argument("--fresh", action="store_true", help="ignore cached recon/state and start over")
    p.add_argument("--no-nuclei", action="store_true", help="skip the nuclei pass during recon")
    p.add_argument("--no-content", action="store_true",
                    help="skip active content discovery (feroxbuster/ffuf dir brute) during recon")
    p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default=None,
                    help="profundidade de raciocínio por endpoint (padrão: high). Mais = mais fundo e mais caro")
    p.add_argument("--budget", type=float, default=None,
                    help="teto de gasto por endpoint em US$ (padrão 3.0; 0 = sem teto)")
    p.add_argument("--header", action="append", metavar="'Nome: valor'",
                    help="header enviado em toda requisição (repetível); use p/ autenticar e testar a superfície logada")
    p.add_argument("--auth", default=None, metavar="'Authorization: Bearer ...'",
                    help="atalho para um header de autenticação")
    p.add_argument("--no-chat", action="store_true",
                    help="with -h: do not open the interactive follow-up chat after the hunt")
    p.add_argument("--chat-model", default=None,
                    help="with -h: model for the follow-up chat (default: the hunt model)")
    p.add_argument("--confirmed-only", action="store_true", help="with -r: only print confirmed findings")
    p.add_argument("--refresh", type=float, default=2.0, help="with -w: dashboard refresh interval in seconds")
    p.add_argument("--exec", dest="exec_howto", default=None, metavar="'curl ...__CMD__...'",
                    help="with --shell: canal de RCE com placeholder __CMD__ p/ auto-disparar o payload")
    p.add_argument("--method", choices=["bash", "python", "nc", "php", "perl"], default="bash",
                    help="with --shell: tipo de payload de reverse shell (padrão bash)")
    p.add_argument("--lport", type=int, default=None, help="with --shell: porta local do listener (padrão: aleatória)")
    p.add_argument("--listener", choices=["socat", "nc"], default="socat",
                    help="with --shell: listener (socat dá TTY melhor; padrão socat)")
    p.add_argument("--tunnel", choices=["auto", "pinggy", "ngrok"], default="auto",
                    help="with --shell: provider do túnel TCP (auto=pinggy e depois ngrok; ngrok TCP exige cartão)")
    p.add_argument("--urlencode", action="store_true",
                    help="with --shell: url-encoda o payload ao injetar no __CMD__ (canais via URL)")
    p.add_argument("--id", dest="approval_id", default=None,
                    help="with --approve/--deny: id do pedido (veja 'fosc --approvals')")
    p.add_argument("--reason", default="", help="with --approve/--deny: motivo da decisão")
    return p


def do_shell(args):
    from .revshell import pop_shell, howto_from_state
    exec_howto = args.exec_howto or (howto_from_state(args.target) if args.target else None)
    if not exec_howto:
        print("sem canal de RCE: passe --exec \"curl 'http://alvo/sh.php?c=__CMD__'\" (ou rode um hunt que "
              "confirme RCE antes). Vou subir túnel+listener e imprimir os payloads pra você disparar manualmente.")
    raise SystemExit(pop_shell(exec_howto, method=args.method, lport=args.lport,
                               listener=args.listener, urlencode=args.urlencode, provider=args.tunnel))


def _find_approval(aid: str):
    from .authz import ApprovalStore
    if not config.STATE_ROOT.exists():
        return None, None
    for d in sorted(config.STATE_ROOT.iterdir()):
        if not d.is_dir():
            continue
        store = ApprovalStore(d / "approvals.jsonl")
        if store.request_meta(aid):
            return store, d.name
    return None, None


def do_approvals(args):
    from .authz import ApprovalStore
    if args.target:
        roots = [RunState(args.target).dir]
    elif config.STATE_ROOT.exists():
        roots = [d for d in sorted(config.STATE_ROOT.iterdir()) if d.is_dir()]
    else:
        roots = []
    found = False
    for d in roots:
        for r in ApprovalStore(d / "approvals.jsonl").pending():
            found = True
            import time as _t
            age = int(_t.time() - r.get("ts", 0))
            print(f"[{r['id']}] {d.name} · {r['action']} (risco {r['risk']}, {age}s atrás)\n"
                  f"        {r.get('context','')}\n"
                  f"        aprovar: fosc --approve --id {r['id']}   |   negar: fosc --deny --id {r['id']}")
    if not found:
        print("nenhum pedido de autorização pendente.")


def _decide(args, approved: bool):
    from .authz import operator
    if not args.approval_id:
        print("informe --id <id> (veja 'fosc --approvals')")
        return
    store, tgt = _find_approval(args.approval_id)
    if not store:
        print(f"id {args.approval_id} não encontrado em nenhum run.")
        return
    who = operator()
    store.decide(args.approval_id, approved, who, args.reason)
    print(f"{'✓ APROVADO' if approved else '✗ NEGADO'} {args.approval_id} ({tgt}) por {who}"
          + (f" — {args.reason}" if args.reason else ""))


def do_approve(args):
    _decide(args, True)


def do_deny(args):
    _decide(args, False)


DISPATCH = {
    "hunt": do_hunt,
    "chat": do_chat,
    "watch": do_watch,
    "view": do_view,
    "status": do_status,
    "report": do_report,
    "stop": do_stop,
    "pause": do_pause,
    "resume": do_resume,
    "shell": do_shell,
    "approvals": do_approvals,
    "approve": do_approve,
    "deny": do_deny,
}

_NO_TARGET = ("view", "chat", "shell", "approvals", "approve", "deny")


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.action not in _NO_TARGET and not args.target:
        parser.error("-a/--alvo is required for this action")
    print_banner()
    DISPATCH[args.action](args)


if __name__ == "__main__":
    sys.exit(main())
