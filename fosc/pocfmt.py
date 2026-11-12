"""Make a bash `curl` PoC also runnable in Windows cmd.exe.

Why this exists: the agent writes PoCs in bash quoting (single-quoted body,
often with the `'"'"'` trick for an embedded quote). Pasted into Windows
cmd.exe those quotes are literal, so the request body is mangled and the PoC
"fails to reproduce" even though the finding is real (migbot SQLi login).

to_cmd() converts a `-d '<body>'` / `--data '<body>'` so the SAME bytes reach
the server from cmd.exe: wrap the body in double quotes, escape inner `"` as
`\"`, and keep single quotes literal. Headers quoted with '...' get the same
treatment. Pure string work, no shell involved. Returns None when there is no
single-quoted argument to convert (nothing to do)."""
import re

# a single-quoted shell token, including the bash '"'"' escape for an inner quote
_SQ = re.compile(r"'(?:[^']|'\"'\"')*'")


def _unquote_bash(tok: str) -> str:
    """'abc'\"'\"'def'  ->  abc'def   (reverse the bash single-quote escaping)."""
    inner = tok[1:-1].replace("'\"'\"'", "'")
    return inner


def _cmd_dquote(s: str) -> str:
    """Wrap for cmd.exe: double-quote, escape inner " as \\", keep ' literal."""
    return '"' + s.replace('"', '\\"') + '"'


def to_cmd(curl: str) -> str | None:
    """Rewrite a bash curl so it runs byte-identically in Windows cmd.exe.
    None if there is nothing single-quoted to convert."""
    if "curl" not in curl or "'" not in curl:
        return None
    out = _SQ.sub(lambda m: _cmd_dquote(_unquote_bash(m.group(0))), curl)
    return out if out != curl else None


def blocks(curl: str) -> list[str]:
    """Markdown code blocks for a report: bash as given, plus a cmd.exe variant
    when the bash one wouldn't survive cmd quoting."""
    md = ["```bash", curl.strip(), "```"]
    cmd = to_cmd(curl.strip())
    if cmd:
        md += ["", "_Windows (cmd.exe):_", "```bat", cmd, "```"]
    return md


# a ```bash ... ``` fenced block (the repro curl, as write_report emits it)
_BASH_BLOCK = re.compile(r"```bash\n(.*?)\n```", re.S)


def patch_markdown(md: str) -> tuple[str, bool]:
    """Insert a Windows (cmd.exe) variant after each bash curl block that needs
    one. Idempotent: a block already followed by '_Windows (cmd.exe):_' is left
    alone. Returns (text, changed)."""
    changed = False

    def _repl(m: re.Match) -> str:
        nonlocal changed
        body = m.group(1)
        tail = md[m.end():m.end() + 40]
        if "curl" not in body or "Windows (cmd.exe)" in tail:
            return m.group(0)
        cmd = to_cmd(body.strip())
        if not cmd:
            return m.group(0)
        changed = True
        return m.group(0) + "\n\n_Windows (cmd.exe):_\n```bat\n" + cmd + "\n```"

    return _BASH_BLOCK.sub(_repl, md), changed


def patch_reports(run_dir) -> tuple[int, int]:
    """Walk <run_dir>/pocs/*/report.md and add the Windows PoC variant where it
    was missing. Returns (files_scanned, files_patched)."""
    from pathlib import Path
    scanned = patched = 0
    for rep in sorted(Path(run_dir).glob("pocs/*/report.md")):
        scanned += 1
        text = rep.read_text()
        new, changed = patch_markdown(text)
        if changed:
            rep.write_text(new)
            patched += 1
    return scanned, patched
