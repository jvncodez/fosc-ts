"""The hunt loop.

"Never stop on a confirmed finding" lives here: every task result is
recorded and the scheduler moves on. A run only ends when the queue is
empty (single pass) or a STOP file appears; PAUSE holds new submissions
while letting in-flight tasks finish.
"""
import json
import os
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from . import config, knowledge, net
from .claude_runner import run_claude
from .notify import notify_finding
from .privesc import attempt_privesc
from .prompts import (CONSOLIDATE_SCHEMA, CONSOLIDATE_SYSTEM, HUNT_SCHEMA, HUNT_SYSTEM,
                      build_consolidate_prompt, build_hunt_prompt)
from .rank import rank, suggest_classes
from .recon import load_or_build, item_id, route_pattern, target_host
from .scope import Scope
from . import mitre
from .report import write_report
from .state import RunState
from .ui import Out
from .verify import verify_finding


def _js_for(item: dict, surface: dict) -> list[str]:
    host = item.get("host")
    return [u for u in surface.get("js", []) if host and host in u][:15]


def hunt_one(state: RunState, out: Out, target: str, scope_note: str, item: dict,
             surface: dict, stats: dict, timeout: int, extra_headers: list[str] | None = None) -> dict:
    classes = suggest_classes(item, stats)
    lessons = knowledge.relevant(item, classes)
    learned = knowledge.format_for_prompt(lessons, target)
    arsenal = knowledge.read_tools()
    if arsenal:
        learned = (learned + "\n\nArsenal já instalado pelo FOSC em runs anteriores (reutilize em vez de "
                   "reinstalar):\n" + arsenal).strip()
    prompt = build_hunt_prompt(target, scope_note, item, classes, learned, _js_for(item, surface), extra_headers)

    def act(msg):
        state.activity(item, msg)
        out.activity(msg)  # feed the live themed status line

    state.set_active(item, "hunting")
    try:
        run = run_claude(prompt, cwd=state.task_dir(item), timeout=timeout,
                         stream_path=state.stream_path(item), model=config.HUNT_MODEL,
                         system_prompt=HUNT_SYSTEM, schema=HUNT_SCHEMA, on_activity=act,
                         effort=config.HUNT_EFFORT, budget=config.DEFAULT_TASK_BUDGET_USD)
        state.add_cost(run["cost"])
        cost = run["cost"]
        if run["status"] != "ok":
            verdict = {"timeout": "timeout", "offline": "offline"}.get(run["status"], "error")
            knowledge.record_event(target, item, verdict, None, item.get("tech") or [])
            return {"verdict": verdict, "summary": run["error"] or verdict, "cost": cost,
                    "lessons_used": len(lessons)}

        f = run["output"]
        tech = sorted(set((item.get("tech") or []) + (f.get("tech_observed") or [])))
        cls = f.get("vuln_class")
        for les in f.get("lessons") or []:
            knowledge.add_lesson("note", les, target, item, cls, tech)
        for note in f.get("target_notes") or []:
            knowledge.note_target(target, note)
        for tool in f.get("tools_installed") or []:
            knowledge.note_tool(tool)  # grow the permanent arsenal

        verdict = f.get("verdict", "inconclusive")
        res = {"verdict": verdict, "vuln_class": cls, "severity": f.get("severity"),
               "summary": f.get("summary", ""), "cost": cost, "lessons_used": len(lessons)}

        if verdict == "confirmed":
            # Dedup on the endpoint where the vuln ACTUALLY lives. If the agent
            # pivoted to a different route (e.g. two static pages both reaching
            # the same login/search sink), key on THAT route so the same bug
            # isn't reported once per entry point. With no pivot, keep the item's
            # own pattern (recon already normalized ids like /users/{n}).
            ve = (f.get("vuln_endpoint") or "").strip()
            if ve.startswith("http") and route_pattern(ve) != route_pattern(item["url"]):
                endpoint_url, vpat = ve, route_pattern(ve)
            else:
                endpoint_url, vpat = item["url"], item.get("pattern")
            key = state.finding_key(cls, vpat)
            if not state.claim_finding(key):
                res["verdict"] = "duplicate"
            else:
                state.set_active(item, "reviewing")
                act("handing finding to Opus reviewer")
                review = verify_finding(scope_note, item, f, state.task_dir(item), on_activity=act)
                state.add_cost(review.get("cost", 0))
                res["cost"] = cost + review.get("cost", 0)
                res["review"] = review.get("reason")
                res["verdict"] = review["verdict"]
                if review["verdict"] == "confirmed":
                    finding = {"key": key, "url": endpoint_url, "pattern": vpat,
                               "vuln_class": review.get("vuln_class") or cls,
                               "severity": review.get("severity") or f.get("severity"),
                               "cvss": review.get("cvss"), "title": f.get("title"),
                               "summary": f.get("summary"), "impact": f.get("impact"),
                               "steps": f.get("steps") or [], "repro_curl": f.get("repro_curl"),
                               "evidence_marker": f.get("evidence_marker"),
                               "shell_obtained": bool(f.get("shell_obtained")),
                               "shell_howto": f.get("shell_howto"),
                               "mitre": mitre.techniques(review.get("vuln_class") or cls),
                               "review": review.get("reason"), "item_id": item_id(item)}
                    finding = state.add_confirmed(finding)
                    finding["report_path"] = write_report(state.dir, finding["id"], target, item, f,
                                                          review, state.task_dir(item))
                    # rewrite the last line with the report path (small file, append-only otherwise)
                    _patch_last_confirmed(state, finding)
                    res["severity"] = finding["severity"]
                    knowledge.add_lesson("win", f"{finding['vuln_class']} on {item.get('pattern')}: "
                                         f"{(f.get('summary') or '')[:300]}", target, item,
                                         finding["vuln_class"], tech)
                    ok, err = notify_finding(target, finding)
                    if not ok and err != "telegram not configured":
                        state.activity(item, f"telegram failed: {err}", kind="system")
                    out.confirmed(finding)
                    # Post-RCE: if this finding gives command execution, run the
                    # privilege-escalation stage once for the whole host.
                    if finding.get("shell_obtained") and finding.get("shell_howto") and state.claim_privesc():
                        act("RCE confirmado — iniciando escalonamento de privilégio")
                        state.set_active(item, "privesc")
                        try:
                            # privesc has its own (larger) per-pass timeout/budget
                            pv = attempt_privesc(state, target, scope_note, finding,
                                                 on_activity=act)
                            state.save_privesc(pv)
                            out.privesc(pv)
                            verb = (f"escalou para {pv.get('to_user')} via {pv.get('vector')}"
                                    if pv.get("escalated") else "não escalou")
                            state.activity(item, f"privesc: {verb}", kind="result")
                            if pv.get("escalated"):
                                notify_finding(target, {"severity": pv.get("severity") or "critical",
                                                        "vuln_class": "privilege-escalation",
                                                        "url": target, "summary": pv.get("summary"),
                                                        "report_path": pv.get("report_path")})
                        except Exception as e:
                            out.warn(f"privesc error: {e}")
                elif review["verdict"] == "refuted" and review.get("lesson"):
                    knowledge.add_lesson("fp", review["lesson"], target, item, cls, tech)

        knowledge.record_event(target, item, res["verdict"], res.get("vuln_class") or cls, tech)
        return res
    finally:
        state.unset_active(item)


def _patch_last_confirmed(state: RunState, finding: dict):
    lines = state.confirmed_path.read_text().splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if f'"id": "{finding["id"]}"' in lines[i]:
            lines[i] = json.dumps(finding)
            break
    state.confirmed_path.write_text("\n".join(lines) + "\n")


def consolidate(state: RunState, out: Out):
    pending = knowledge.pending_for_consolidation()
    if len(pending) < 5:
        return
    out.info(f"consolidating {len(pending)} new lesson(s) into the playbook")
    run = run_claude(build_consolidate_prompt(knowledge.read_playbook(), pending),
                     cwd=config.KNOWLEDGE_ROOT / "work", timeout=300,
                     stream_path=config.KNOWLEDGE_ROOT / "work" / "consolidate.stream.jsonl",
                     model=config.CONSOLIDATE_MODEL, system_prompt=CONSOLIDATE_SYSTEM,
                     schema=CONSOLIDATE_SCHEMA, allow_tools=False)
    state.add_cost(run["cost"])
    if run["status"] == "ok" and run["output"].get("playbook_markdown"):
        knowledge.write_playbook(run["output"]["playbook_markdown"][:8000])
        knowledge.mark_consolidated(max(l.get("ts", 0) for l in pending))
        state.activity(None, f"playbook updated with {len(pending)} lessons", kind="system")
    else:
        out.warn(f"playbook consolidation failed: {run['error']}")


def _sleep_interruptible(state: RunState, seconds: int, heartbeat: int = 60):
    """Sleep up to `seconds`, but post a heartbeat to the feed every `heartbeat`
    seconds so a continuous hunt visibly stays alive between rounds."""
    end = time.time() + seconds
    next_beat = time.time() + heartbeat
    while time.time() < end and not state.should_stop():
        if time.time() >= next_beat:
            left = int(end - time.time())
            state.activity(None, f"aguardando próximo recon em {left}s (caçada ativa)", kind="system")
            next_beat += heartbeat
        time.sleep(2)


def run_hunt(target: str, scope_note: str | None = None, workers: int = config.DEFAULT_WORKERS,
             timeout: int = config.DEFAULT_TASK_TIMEOUT, continuous: bool = False,
             interval: int = config.DEFAULT_CONTINUOUS_INTERVAL, max_items: int | None = None,
             fresh: bool = False, nuclei: bool = True, content: bool = True,
             extra_headers: list[str] | None = None, scope_subdomains: bool = False):
    # Deterministic scope: strict (exact host) by default for a bank engagement;
    # subdomains only when the operator explicitly opts in. The note handed to the
    # agent forbids drift, and in_scope() enforces the same rule mechanically.
    scope = Scope.from_target(target, allow_subdomains=scope_subdomains or None)
    scope_note = scope_note or scope.note()
    state = RunState(target, fresh=fresh)
    out = Out(sys.stdout.isatty())
    state.stop_path.unlink(missing_ok=True)
    state.clear_active()
    prev_cost = state.read_meta().get("cost_usd", 0) if not fresh else 0
    state.write_meta(target=target, pid=os.getpid(), status="recon", workers=workers, timeout=timeout,
                     continuous=continuous, scope=scope_note, started_at=time.time(), round=0,
                     cost_usd=prev_cost, version=config.VERSION, auth=bool(extra_headers))
    out.header(target, state.dir, workers, continuous)
    out.info(f"escopo: {scope.label()}")
    if net.offline():
        out.warn("sem conexão com a internet — o FOSC precisa da rede para o recon e para a "
                 "API do Claude. Reconecte e rode de novo.")
        state.write_meta(status="offline", finished_at=time.time())
        return
    out.start_live()  # Claude-Code-style themed "thinking" line (TTY only)
    state.activity(None, f"hunt started (workers={workers}, continuous={continuous})", kind="system")

    round_no = 0
    final_status = "finished"
    try:
        while not state.should_stop():
            round_no += 1
            state.write_meta(round=round_no, status="recon", last_round_started_at=time.time())
            out.info(f"round {round_no}: recon")
            state.activity(None, f"rodada {round_no}: recon" + (" (mais fundo)" if round_no > 1 else ""), kind="system")
            surface = load_or_build(target, state.dir, fresh=(fresh and round_no == 1) or (continuous and round_no > 1),
                                    nuclei=nuclei, content=content)
            stats = knowledge.class_stats()
            todo = [i for i in rank(surface.get("items", []), stats) if not state.is_done(i)]
            if max_items:
                todo = todo[:max_items]

            if not todo:
                conf = len(state.confirmed())
                if not continuous:
                    out.info("queue empty, nothing left to test")
                    state.activity(None, f"superfície toda testada · {conf} achado(s) confirmado(s)", kind="system")
                    break
                msg = (f"testei toda a superfície conhecida e {('ainda não confirmei nenhuma vulnerabilidade' if not conf else f'confirmei {conf} até agora')}. "
                       f"Vou dormir {interval}s e refazer o recon para ir mais fundo.")
                state.activity(None, msg, kind="system")
                state.write_meta(status="sleeping", next_round_at=time.time() + interval)
                out.info(f"queue empty, sleeping {interval}s before re-recon")
                _sleep_interruptible(state, interval)
                continue

            state.write_meta(status="running", round_total=len(todo), round_done=0)
            state.activity(None, f"round {round_no}: {len(todo)} endpoint(s) queued", kind="system")
            out.round_start(round_no, len(todo))
            queue = list(todo)
            running = {}
            finished = 0
            with ThreadPoolExecutor(max_workers=workers) as ex:
                while queue or running:
                    stop = state.should_stop()
                    paused = state.is_paused()
                    state.write_meta(status="paused" if paused else "running")
                    while queue and len(running) < workers and not stop and not paused:
                        item = queue.pop(0)
                        state.activity(item, "task started", kind="system")
                        running[ex.submit(hunt_one, state, out, target, scope_note, item,
                                          surface, stats, timeout, extra_headers)] = item
                    out.set_running(len(running))
                    if stop and not running:
                        break
                    if not running:
                        time.sleep(2)  # paused with nothing in flight
                        continue
                    done, _ = wait(list(running), timeout=2, return_when=FIRST_COMPLETED)
                    for fut in done:
                        item = running.pop(fut)
                        try:
                            res = fut.result()
                        except Exception as e:
                            res = {"verdict": "error", "summary": f"{type(e).__name__}: {e}"}
                        state.record(item, res)
                        finished += 1
                        state.write_meta(round_done=finished)
                        state.activity(item, f"{res['verdict']}: {(res.get('summary') or '')[:160]}", kind="result")
                        out.result(item, res, finished, len(todo))
                        # no branch on verdict: confirmed findings are logged and the loop keeps going
            if state.should_stop():
                final_status = "stopped"
                break
            conf = len(state.confirmed())
            if conf:
                summary = f"rodada {round_no} concluída: {finished} endpoint(s) testado(s), {conf} confirmado(s) no total."
            else:
                summary = (f"rodada {round_no} concluída: {finished} endpoint(s) testado(s), nada confirmado ainda — "
                           f"{'vou refazer o recon e ir mais fundo' if continuous else 'fim do passe único'}.")
            state.activity(None, summary, kind="system")
            try:
                consolidate(state, out)
            except Exception as e:
                out.warn(f"consolidation error: {e}")
            if not continuous:
                break  # single pass: exactly one round (so --max-items caps the whole run)
        else:
            final_status = "stopped"
    except KeyboardInterrupt:
        final_status = "stopped"
        out.warn("interrupted")
    finally:
        out.stop_live()
        state.clear_active()
        state.write_meta(status=final_status, pid=None, finished_at=time.time())
        state.activity(None, f"hunt {final_status}", kind="system")
        out.footer(state)
