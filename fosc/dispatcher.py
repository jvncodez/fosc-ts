"""Queue dispatcher — leases jobs and launches hunts, up to a global cap.

One dispatcher per box (local) or one per worker container (AWS). It never
exceeds SENTINELA_MAX_HUNTS running hunts across the whole system, because the
lease is bounded by the shared running-count. Each leased job becomes a detached
`fosc -h` process; when that process exits the job is marked done and the SQS
message (if any) deleted, freeing a slot.
"""
import os
import subprocess
import threading
import time

from . import config, jobqueue
from .state import RunState

# Run meta statuses that mean the hunt is over (so a still-RUNNING job is an orphan).
_TERMINAL = {"finished", "stopped", "halted", "denied", "offline", "error", "completed"}


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True            # exists but not ours
    except (ValueError, TypeError, OSError):
        return False
    return True


def reap_stale(queue, grace: int = None, on_event=None) -> int:
    """Free jobs stuck in RUNNING because their hunt process is gone (crashed
    worker/dispatcher). Only acts when the RUN STATE proves the hunt is not alive
    — a long but healthy hunt is never touched. Returns how many were freed."""
    grace = config.QUEUE_REAP_GRACE if grace is None else grace
    try:
        jobs = queue.store.running_jobs()
    except Exception:
        return 0
    now, freed = time.time(), 0
    for j in jobs:
        if now - (j.get("started_at") or 0) < grace:
            continue                       # too fresh — the hunt may still be booting
        try:
            meta = RunState(j["target"]).read_meta()
        except Exception:
            meta = {}
        status = (meta.get("status") or "").lower()
        pid = meta.get("pid")
        if _pid_alive(pid) and status not in _TERMINAL:
            continue                       # genuinely running — leave it
        ok = status == "finished"
        try:
            queue.complete(j["job_id"], ok)
            freed += 1
            if on_event:
                on_event("reaped", j)
        except Exception:
            pass
    return freed


def _argv_for(job: dict) -> list[str]:
    p = job.get("opts") or {}
    argv = [str(config.FOSC_BIN), "-h", "-a", job["target"],
            "--workers", str(max(1, min(12, int(p.get("workers") or config.DEFAULT_WORKERS)))),
            "--timeout", str(max(60, int(p.get("timeout") or config.DEFAULT_TASK_TIMEOUT)))]
    if p.get("max_items"):
        argv += ["--max-items", str(max(1, int(p["max_items"])))]
    if p.get("continuous"):
        argv += ["--continuous", "--interval", str(max(60, int(p.get("interval") or config.DEFAULT_CONTINUOUS_INTERVAL)))]
    if p.get("fresh"):
        argv.append("--fresh")
    if p.get("no_nuclei"):
        argv.append("--no-nuclei")
    if (p.get("scope") or "").strip():
        argv += ["--scope", str(p["scope"]).strip()[:500]]
    for h in (p.get("account_a") or []):
        argv += ["--account-a", str(h)[:1000]]
    for h in (p.get("account_b") or []):
        argv += ["--account-b", str(h)[:1000]]
    if p.get("stealth"):
        argv.append("--stealth")
    return argv


def _run_job(queue, job: dict, on_event=None):
    argv = _argv_for(job)
    if on_event:
        on_event("start", job)
    try:
        proc = subprocess.Popen(argv, cwd=str(config.REPO_ROOT), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True, env=os.environ.copy())
        rc = proc.wait()
        ok = rc == 0
    except Exception as e:
        print(f"[fosc] dispatcher: falha ao lançar {job['target']}: {e}")
        ok = False
    kw = {"receipt": job["_receipt"]} if job.get("_receipt") else {}
    queue.complete(job["job_id"], ok, **kw)
    if on_event:
        on_event("done" if ok else "failed", job)


class Dispatcher:
    def __init__(self, queue=None, max_hunts: int = None, on_event=None):
        self.queue = queue or jobqueue.get_queue()
        self.cap = max_hunts or config.MAX_HUNTS
        self.on_event = on_event
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def _reap(self):
        self._threads = [t for t in self._threads if t.is_alive()]

    def tick(self) -> int:
        """One lease+launch cycle. Returns how many jobs were started."""
        self._reap()
        try:
            n = reap_stale(self.queue, on_event=self.on_event)
            if n:
                print(f"[fosc] reaper: {n} job(s) preso(s) liberado(s) (processo morto)")
        except Exception as e:
            print(f"[fosc] reaper erro: {e}")
        room = self.cap - len(self._threads)
        if room <= 0:
            return 0
        jobs = self.queue.lease(room, self.cap)
        for job in jobs:
            t = threading.Thread(target=_run_job, args=(self.queue, job, self.on_event), daemon=True)
            t.start()
            self._threads.append(t)
        return len(jobs)

    def run(self):
        print(f"[fosc] despachante iniciado · backend {self.queue.kind} · "
              f"até {self.cap} caçada(s) simultânea(s)")
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:
                print(f"[fosc] dispatcher erro: {e}")
            self._stop.wait(config.QUEUE_POLL)

    def stop(self):
        self._stop.set()
