"""Hunt queue — so N pentesters don't each wait on recon, don't flood a target,
and don't open the same campaign twice.

One interface, two backends:
  - SqsQueue   : Amazon SQS FIFO (production, AWS/Bedrock). MessageGroupId = the
                 target, so at most one in-flight message per target; content
                 dedup collapses duplicate submits inside the dedup window. A
                 small SQLite side-store (on the EFS SENTINELA_HOME) holds status
                 and queue position for the panel.
  - LocalQueue : SQLite only (dev, single box, and the tests). Same interface.

Selection is by env: SENTINELA_SQS_URL present -> SQS, else local. The engine
never imports boto3 unless SQS is actually used, so the dev box needs nothing.

"One target, one campaign": enqueue() normalizes the target and refuses a second
QUEUED/RUNNING job for the same one, returning the existing job instead. The
dispatcher leases up to SENTINELA_MAX_HUNTS jobs at once (global concurrency cap,
matched to the Bedrock quota) and launches `fosc -h` for each.
"""
import json
import sqlite3
import threading
import time
import uuid

from . import config

QUEUED, RUNNING, DONE, FAILED = "queued", "running", "done", "failed"
_ACTIVE = (QUEUED, RUNNING)


def new_job(target: str, opts: dict | None = None, *, priority: int = 5, who: str = "") -> dict:
    return {
        "job_id": uuid.uuid4().hex[:16],
        "target": config.normalize_target(target),
        "opts": opts or {},
        "priority": max(1, min(9, priority)),   # 1 = highest
        "who": who,
        "status": QUEUED,
        "enqueued_at": time.time(),
        "started_at": None,
        "finished_at": None,
    }


class _Store:
    """SQLite status/position store shared by both backends. Thread- and
    process-safe via WAL + a short busy timeout (many workers, one EFS file)."""

    def __init__(self, path):
        self.path = str(path)
        self._local = threading.local()
        self._init()

    def _conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.c = c
        return c

    def _init(self):
        self._conn().execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY, target TEXT NOT NULL, opts TEXT NOT NULL,
                priority INTEGER NOT NULL, who TEXT, status TEXT NOT NULL,
                enqueued_at REAL NOT NULL, started_at REAL, finished_at REAL,
                lease_until REAL)""")
        self._conn().execute("CREATE INDEX IF NOT EXISTS idx_status ON jobs(status)")

    def active_for(self, target: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM jobs WHERE target=? AND status IN (?,?) ORDER BY enqueued_at LIMIT 1",
            (target, QUEUED, RUNNING)).fetchone()
        return _row(row)

    def insert(self, job: dict):
        self._conn().execute(
            "INSERT INTO jobs(job_id,target,opts,priority,who,status,enqueued_at) VALUES(?,?,?,?,?,?,?)",
            (job["job_id"], job["target"], json.dumps(job["opts"]), job["priority"],
             job["who"], job["status"], job["enqueued_at"]))

    def set_status(self, job_id: str, status: str):
        now = time.time()
        col = {RUNNING: "started_at", DONE: "finished_at", FAILED: "finished_at"}.get(status)
        if col:
            self._conn().execute(f"UPDATE jobs SET status=?, {col}=? WHERE job_id=?", (status, now, job_id))
        else:
            self._conn().execute("UPDATE jobs SET status=? WHERE job_id=?", (status, job_id))

    def claim_local(self, max_jobs: int, running: int, cap: int) -> list[dict]:
        """Atomically lease up to (cap-running) queued jobs, highest priority first."""
        room = max(0, min(max_jobs, cap - running))
        if not room:
            return []
        c = self._conn()
        got = []
        c.execute("BEGIN IMMEDIATE")
        try:
            rows = c.execute(
                "SELECT * FROM jobs WHERE status=? ORDER BY priority, enqueued_at LIMIT ?",
                (QUEUED, room)).fetchall()
            for r in rows:
                c.execute("UPDATE jobs SET status=?, started_at=? WHERE job_id=?",
                          (RUNNING, time.time(), r["job_id"]))
                got.append(_row(r))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        return got

    def running_count(self) -> int:
        return self._conn().execute("SELECT COUNT(*) FROM jobs WHERE status=?", (RUNNING,)).fetchone()[0]

    def snapshot(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM jobs WHERE status IN (?,?) ORDER BY status DESC, priority, enqueued_at",
            (QUEUED, RUNNING)).fetchall()
        out, pos = [], 0
        for r in rows:
            j = _row(r)
            if j["status"] == QUEUED:
                pos += 1
                j["position"] = pos
                j["eta_s"] = pos * config.QUEUE_ETA_PER_JOB
            out.append(j)
        return out

    def get(self, job_id: str) -> dict | None:
        return _row(self._conn().execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone())


def _row(r) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    d["opts"] = json.loads(d["opts"]) if d.get("opts") else {}
    return d


class LocalQueue:
    """SQLite-only queue + lease. Default off AWS."""
    kind = "local"

    def __init__(self, store_path=None):
        self.store = _Store(store_path or (config.FOSC_HOME / "queue.db"))

    def enqueue(self, target: str, opts=None, *, priority=5, who="") -> tuple[dict, bool]:
        job = new_job(target, opts, priority=priority, who=who)
        existing = self.store.active_for(job["target"])
        if existing:
            return existing, False            # one target, one campaign
        self.store.insert(job)
        return job, True

    def lease(self, max_jobs: int, cap: int) -> list[dict]:
        return self.store.claim_local(max_jobs, self.store.running_count(), cap)

    def complete(self, job_id: str, ok: bool = True):
        self.store.set_status(job_id, DONE if ok else FAILED)

    def snapshot(self) -> list[dict]:
        return self.store.snapshot()

    def running_count(self) -> int:
        return self.store.running_count()


class SqsQueue:
    """Amazon SQS FIFO for the job stream + the SQLite side-store for status.

    boto3 is imported lazily and a client can be injected (tests). The FIFO
    MessageGroupId is the target: SQS keeps at most one in-flight message per
    group, so two workers never run the same target at once."""
    kind = "sqs"

    def __init__(self, queue_url=None, client=None, store_path=None):
        self.queue_url = queue_url or config.SQS_URL
        self.store = _Store(store_path or (config.FOSC_HOME / "queue.db"))
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import boto3  # noqa: imported only when SQS is really used
            self._client = boto3.client("sqs", region_name=config.AWS_REGION)
        return self._client

    def enqueue(self, target: str, opts=None, *, priority=5, who="") -> tuple[dict, bool]:
        job = new_job(target, opts, priority=priority, who=who)
        existing = self.store.active_for(job["target"])
        if existing:
            return existing, False
        self.store.insert(job)
        self.client.send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(job),
            MessageGroupId=job["target"],          # one in-flight per target
            MessageDeduplicationId=job["job_id"],
        )
        return job, True

    def lease(self, max_jobs: int, cap: int) -> list[dict]:
        room = max(0, min(max_jobs, cap - self.store.running_count()))
        if not room:
            return []
        resp = self.client.receive_message(
            QueueUrl=self.queue_url, MaxNumberOfMessages=min(10, room),
            WaitTimeSeconds=config.SQS_WAIT, VisibilityTimeout=config.SQS_VISIBILITY)
        jobs = []
        for m in resp.get("Messages", []):
            job = json.loads(m["Body"])
            job["_receipt"] = m["ReceiptHandle"]
            self.store.set_status(job["job_id"], RUNNING)
            jobs.append(job)
        return jobs

    def complete(self, job_id: str, ok: bool = True, receipt: str | None = None):
        self.store.set_status(job_id, DONE if ok else FAILED)
        if receipt:
            try:
                self.client.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)
            except Exception as e:
                print(f"[fosc] sqs delete falhou: {e}")

    def snapshot(self) -> list[dict]:
        return self.store.snapshot()

    def running_count(self) -> int:
        return self.store.running_count()


def get_queue(client=None, store_path=None):
    """SQS when SENTINELA_SQS_URL is set, else the local SQLite queue."""
    if config.SQS_URL:
        return SqsQueue(client=client, store_path=store_path)
    return LocalQueue(store_path=store_path)
