"""Spawns one headless claude -p process per task and streams it.

  - fresh process + fresh context per task -> no context bloat, no wedged
    long-lived session.
  - --dangerously-skip-permissions -> never blocks on an approval prompt.
  - --output-format stream-json -> every event is written to stream.jsonl
    as it happens and turned into a short human-readable activity line
    (on_activity callback) for the live feed in the terminal and panel.
  - --json-schema -> the answer arrives as structured_output on the final
    result event; no text parsing.
  - hard deadline + process-group kill -> a stuck task cannot stall the run.
"""
import json
import os
import signal
import subprocess
import threading
from pathlib import Path

from . import config, net

# Registry of in-flight task process groups, so an emergency HALT can kill every
# running `claude` task NOW instead of waiting for them to finish (challenge #6).
_LIVE_PGIDS: set[int] = set()
_LIVE_LOCK = threading.Lock()

# Set by the engine when the scope proxy is on (G0): every task's HTTP(S) traffic
# is then forced through it, so the agent cannot reach an out-of-scope host.
PROXY_URL: str | None = None


def kill_all() -> int:
    """SIGKILL every in-flight task process group. Returns how many were signalled."""
    with _LIVE_LOCK:
        pgids = list(_LIVE_PGIDS)
    n = 0
    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGKILL)
            n += 1
        except ProcessLookupError:
            pass
    return n


def _short(s, n=140) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def describe_event(ev: dict) -> list[str]:
    """Turn one stream-json event into zero or more activity lines."""
    out = []
    if ev.get("type") == "assistant":
        for c in (ev.get("message") or {}).get("content") or []:
            if c.get("type") == "tool_use":
                name = c.get("name") or "tool"
                inp = c.get("input") or {}
                if name == "StructuredOutput":
                    out.append("writing final verdict")
                elif name == "Bash":
                    out.append(f"$ {_short(inp.get('command', ''))}")
                elif name == "Skill":
                    out.append(f"skill: {inp.get('skill') or inp.get('name') or ''} {_short(inp.get('args') or '', 80)}")
                elif name in ("Read", "Write", "Edit"):
                    out.append(f"{name.lower()} {_short(inp.get('file_path', ''), 100)}")
                elif name in ("WebFetch", "WebSearch"):
                    out.append(f"{name}: {_short(inp.get('url') or inp.get('query') or '', 100)}")
                else:
                    out.append(f"{name}: {_short(json.dumps(inp), 100)}")
            elif c.get("type") == "text" and c.get("text", "").strip():
                out.append(_short(c["text"], 160))
    return out


def run_claude(prompt: str, cwd: Path, timeout: int, stream_path: Path, *, model: str,
               system_prompt: str, schema: dict | None, on_activity=None,
               allow_tools: bool = True, effort: str | None = None,
               budget: float | None = None, env_extra: dict | None = None) -> dict:
    """Spawn one headless `claude` task. Low-level primitive: it runs exactly the
    model/provider it is told to. Model selection, provider choice and failover
    live one layer up in `fosc/models.py` — callers ask for a ROLE there, not a
    model here, so swapping models never touches the application.

    `env_extra` is merged into the child environment (the model router uses it to
    flip the `claude` CLI between the Anthropic API and Amazon Bedrock per attempt).

    Returns {"output": dict|None, "cost": float,
             "status": ok|timeout|error|offline|refused, "error": str|None, "turns": int}.
    A status of error/timeout/refused is failover-worthy; offline is not (another
    model will not help when the network is down)."""
    cwd.mkdir(parents=True, exist_ok=True)
    stream_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        config.CLAUDE_BIN, "-p",
        "--output-format", "stream-json", "--verbose",
        "--model", model,
        "--dangerously-skip-permissions",
        "--append-system-prompt", system_prompt,
    ]
    if effort:
        cmd += ["--effort", effort]
    if budget and budget > 0:
        cmd += ["--max-budget-usd", str(budget)]
    if schema:
        cmd += ["--json-schema", json.dumps(schema)]
    if not allow_tools:
        # `=` form: the flag is variadic and would otherwise swallow the prompt
        cmd.append("--disallowedTools=Bash,Write,Edit,WebFetch,WebSearch,Agent")
    cmd.append(prompt)

    result = {"output": None, "cost": 0.0, "status": "error", "error": None, "turns": 0}
    child_env = os.environ.copy()
    if PROXY_URL:  # G0: force the agent's traffic through the scope-enforcing proxy
        child_env.update({"HTTP_PROXY": PROXY_URL, "HTTPS_PROXY": PROXY_URL,
                          "http_proxy": PROXY_URL, "https_proxy": PROXY_URL})
    if env_extra:
        child_env.update({k: str(v) for k, v in env_extra.items()})
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True, bufsize=1, env=child_env,
        )
    except FileNotFoundError:
        result["error"] = "claude CLI not found on PATH"
        return result

    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        pgid = proc.pid
    with _LIVE_LOCK:
        _LIVE_PGIDS.add(pgid)

    timed_out = threading.Event()
    offline_hit = threading.Event()
    progress = threading.Event()  # set once real output flows (not just the init event)

    def _kill():
        timed_out.set()
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _watchdog():
        # Offline, `claude` emits its init event then retries the API silently for
        # minutes. If nothing real has streamed and the network is down, stop and
        # report it instead of burning the whole task timeout.
        if progress.is_set() or timed_out.is_set():
            return
        if net.offline():
            offline_hit.set()
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    timer = threading.Timer(timeout, _kill)
    timer.start()
    watchdog = threading.Timer(config.NET_WATCHDOG_SECS, _watchdog)
    watchdog.start()
    final = None
    try:
        with stream_path.open("w") as sink:
            for line in proc.stdout:
                sink.write(line)
                sink.flush()
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = ev.get("type")
                if etype in ("assistant", "stream_event", "result"):
                    progress.set()
                if etype == "result":
                    final = ev
                elif on_activity:
                    for msg in describe_event(ev):
                        try:
                            on_activity(msg)
                        except Exception:
                            pass
        proc.wait()
    finally:
        timer.cancel()
        watchdog.cancel()
        with _LIVE_LOCK:
            _LIVE_PGIDS.discard(pgid)
        if proc.stdout:
            proc.stdout.close()

    if offline_hit.is_set():
        result.update(status="offline", error="sem conexão com a internet (rede fora durante a tarefa)")
        return result
    if timed_out.is_set():
        result.update(status="timeout", error=f"killed after {timeout}s")
        return result
    if not final:
        result["error"] = f"no result event (exit {proc.returncode})"
        return result

    result["cost"] = float(final.get("total_cost_usd") or 0.0)
    result["turns"] = int(final.get("num_turns") or 0)
    # Refusal: the model declined the task (policy stop). Distinct from a crash so
    # the router can fail over to another model instead of recording an empty find.
    subtype = str(final.get("subtype") or "")
    if subtype == "refusal" or final.get("stop_reason") == "refusal":
        result.update(status="refused", error=_short(final.get("result") or "model refused the task", 300))
        return result
    if final.get("is_error"):
        result["error"] = _short(final.get("result") or final.get("subtype") or "error", 300)
        return result
    out = final.get("structured_output")
    if out is None and final.get("result"):
        # fallback: model answered in text; try to pull a JSON object out of it
        txt = final["result"]
        start, end = txt.find("{"), txt.rfind("}")
        if start != -1 and end > start:
            try:
                out = json.loads(txt[start:end + 1])
            except json.JSONDecodeError:
                out = None
    if out is None:
        result["error"] = "no structured output"
        return result
    result.update(output=out, status="ok")
    return result


def stream_to_text(stream_path: Path, limit: int = 400) -> str:
    """Readable transcript of a task's stream.jsonl for the panel's log view."""
    if not stream_path.exists():
        return ""
    lines = []
    for raw in stream_path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "user":
            for c in (ev.get("message") or {}).get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    content = c.get("content")
                    if isinstance(content, list):
                        content = " ".join(x.get("text", "") for x in content if isinstance(x, dict))
                    lines.append("  ↳ " + _short(content or "", 300))
        elif ev.get("type") == "result":
            lines.append(f"== done: {ev.get('subtype')} · ${float(ev.get('total_cost_usd') or 0):.4f} · {ev.get('num_turns')} turns")
        else:
            lines += describe_event(ev)
    return "\n".join(lines[-limit:])
