import http.server
import os
import threading
import time
import unittest

from fosc import config, dispatcher, replay
from fosc.jobqueue import LocalQueue, RUNNING
from fosc.state import RunState
from tests.helpers import isolate

MARKER = "SECRET-MARK-123"


class _Reflect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        body = MARKER if self.path.startswith("/vuln") else "nothing to see"
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class MechanicalReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Reflect)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def test_reproduced(self):
        r = replay.replay_check(f"curl {self.base}/vuln", MARKER, self.base)
        self.assertEqual(r["status"], "reproduced")

    def test_absent_is_actionable(self):
        r = replay.replay_check(f"curl {self.base}/safe", MARKER, self.base)
        self.assertEqual(r["status"], "absent")

    def test_non_idempotent_is_skipped(self):
        r = replay.replay_check(f"curl -X POST -d a=1 {self.base}/vuln", MARKER, self.base)
        self.assertEqual(r["status"], "skipped")

    def test_out_of_scope_is_skipped(self):
        r = replay.replay_check("curl http://evil.example/x", MARKER, self.base)
        self.assertEqual(r["status"], "skipped")

    def test_missing_marker_is_skipped(self):
        r = replay.replay_check(f"curl {self.base}/vuln", "", self.base)
        self.assertEqual(r["status"], "skipped")


class ReaperTests(unittest.TestCase):
    def setUp(self):
        isolate(self)
        self.q = LocalQueue(store_path=config.FOSC_HOME / "queue.db")

    def _running(self, target, started_ago=1000):
        job, _ = self.q.enqueue(target)
        self.q.store.set_status(job["job_id"], RUNNING)
        self.q.store._conn().execute("UPDATE jobs SET started_at=? WHERE job_id=?",
                                     (time.time() - started_ago, job["job_id"]))
        return job

    def test_reaps_dead_pid(self):
        t = config.normalize_target("https://dead.test")
        RunState(t).write_meta(target=t, pid=999999, status="running")  # pid not alive
        self._running(t)
        self.assertEqual(dispatcher.reap_stale(self.q, grace=0), 1)
        self.assertIsNone(self.q.store.active_for(t))      # target freed to re-run

    def test_reaps_orphan_with_terminal_meta(self):
        t = config.normalize_target("https://done.test")
        RunState(t).write_meta(target=t, pid=os.getpid(), status="finished")  # ended, not marked
        self._running(t)
        self.assertEqual(dispatcher.reap_stale(self.q, grace=0), 1)

    def test_keeps_live_hunt(self):
        t = config.normalize_target("https://live.test")
        RunState(t).write_meta(target=t, pid=os.getpid(), status="running")  # alive + running
        self._running(t)
        self.assertEqual(dispatcher.reap_stale(self.q, grace=0), 0)
        self.assertIsNotNone(self.q.store.active_for(t))   # untouched

    def test_fresh_job_not_reaped(self):
        t = config.normalize_target("https://fresh.test")
        RunState(t).write_meta(target=t, pid=999999, status="running")
        self._running(t, started_ago=0)                    # just leased
        self.assertEqual(dispatcher.reap_stale(self.q, grace=120), 0)


if __name__ == "__main__":
    unittest.main()
