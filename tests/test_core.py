import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fosc import config, knowledge
from fosc.claude_runner import describe_event, run_claude
from fosc.rank import rank, suggest_classes
from fosc.recon import build_items, in_scope, is_static, route_pattern

from tests.helpers import isolate


class ReconTests(unittest.TestCase):
    def test_route_pattern_collapses_ids(self):
        a = route_pattern("https://App.test/user/123/orders/9f86d081884c7d659a2feaa0c55ad015?id=5&b=1")
        b = route_pattern("https://app.test/user/456/orders/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?b=2&id=9")
        self.assertEqual(a, b)
        self.assertEqual(a, "app.test/user/{n}/orders/{hash}?b&id")

    def test_static_and_scope(self):
        self.assertTrue(is_static("https://a.test/static/app.js"))
        self.assertTrue(is_static("https://a.test/logo.PNG"))
        self.assertFalse(is_static("https://a.test/api/users"))
        self.assertTrue(in_scope("https://api.alvo.com/x", "alvo.com"))
        self.assertFalse(in_scope("https://alvo.com.evil.net/x", "alvo.com"))
        self.assertFalse(in_scope("https://other.alvo.com/x", "https://app.alvo.com"))

    def test_build_items_dedups_and_drops_static(self):
        urls = {"https://a.test/api/users/1", "https://a.test/api/users/2", "https://a.test/main.js",
                "https://a.test/search?q=x", "https://a.test/search?q=y"}
        hosts = [{"url": "https://a.test", "tech": ["express"]}]
        items, js = build_items(urls, hosts, [{"matched": "https://a.test/search?q=x", "severity": "high", "name": "x"}])
        pats = sorted(i["pattern"] for i in items)
        self.assertEqual(pats, ["a.test/api/users/{n}", "a.test/search?q"])
        self.assertEqual(js, ["https://a.test/main.js"])
        search = next(i for i in items if i["pattern"] == "a.test/search?q")
        self.assertEqual(len(search["nuclei"]), 1)
        self.assertEqual(search["tech"], ["express"])


class RankTests(unittest.TestCase):
    def test_hints(self):
        self.assertEqual(suggest_classes({"path": "/fetch", "params": ["url"]})[0], "SSRF")
        self.assertEqual(suggest_classes({"path": "/api/order", "params": ["order_id"]})[0], "IDOR")

    def test_learning_moves_ranking(self):
        a = {"url": "https://a.test/x?q=1", "path": "/x", "params": ["q"], "tech": ["php"]}
        b = {"url": "https://a.test/y?q=1", "path": "/y", "params": ["q"], "tech": ["express"]}
        stats = {("express", "xss (reflected/stored/dom)"): {"tries": 4, "wins": 3, "fps": 0},
                 ("php", "xss (reflected/stored/dom)"): {"tries": 4, "wins": 0, "fps": 4}}
        self.assertEqual(rank([a, b], stats)[0]["url"], b["url"])


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        isolate(self)

    def test_relevant_prefers_matching_tech_and_class(self):
        item = {"pattern": "a.test/api/users/{n}", "params": [], "tech": ["express"]}
        knowledge.add_lesson("win", "sequential ids on users endpoint", "a.test", item, "IDOR", ["express"])
        knowledge.add_lesson("note", "wordpress xmlrpc was disabled", "b.test", {"pattern": "b.test/xmlrpc.php"}, "SSRF", ["wordpress"])
        top = knowledge.relevant(item, ["IDOR", "SSRF"])
        self.assertTrue(top)
        self.assertEqual(top[0]["vuln_class"], "IDOR")
        text = knowledge.format_for_prompt(top, "a.test")
        self.assertIn("WORKED", text)

    def test_stats_and_delete(self):
        item = {"pattern": "p"}
        knowledge.record_event("t", item, "confirmed", "IDOR", ["express"])
        knowledge.record_event("t", item, "refuted", "IDOR", ["express"])
        s = knowledge.class_stats()[("express", "idor")]
        self.assertEqual((s["tries"], s["wins"], s["fps"]), (2, 1, 1))
        lid = knowledge.add_lesson("fp", "x", "t", item, "IDOR", [])
        self.assertTrue(knowledge.delete_lesson(lid))
        self.assertFalse(any(l["id"] == lid for l in knowledge.all_lessons()))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = isolate(self)

    def test_structured_output_and_activity(self):
        lines = []
        r = run_claude("hunt", self.tmp / "t", 20, self.tmp / "t" / "s.jsonl", model="sonnet",
                       system_prompt="x", schema={"type": "object"}, on_activity=lines.append)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["output"]["vuln_class"], "IDOR")
        self.assertAlmostEqual(r["cost"], 0.0123)
        self.assertTrue(any(l.startswith("$ curl") for l in lines))
        self.assertTrue((self.tmp / "t" / "s.jsonl").read_text().count("\n") >= 3)

    def test_timeout_kills(self):
        os.environ["FAKE_HUNT"] = "sleep"
        t0 = time.time()
        r = run_claude("hunt", self.tmp / "t", 2, self.tmp / "t" / "s.jsonl", model="sonnet",
                       system_prompt="x", schema=None)
        self.assertEqual(r["status"], "timeout")
        self.assertLess(time.time() - t0, 10)

    def test_describe_event(self):
        ev = {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "poc"}}]}}
        self.assertEqual(describe_event(ev), ["skill: poc "])

    def test_run_claude_reports_offline_fast(self):
        """Offline, claude retries silently; the watchdog must kill it and return
        'offline' quickly instead of spinning until the task timeout."""
        from fosc import net
        saved_online, saved_wd = net.online, config.NET_WATCHDOG_SECS
        net.online = lambda *a, **k: False
        config.NET_WATCHDOG_SECS = 0.3
        os.environ["FAKE_HUNT"] = "sleep"  # emits init, then hangs with no real event
        try:
            t0 = time.time()
            r = run_claude("hunt", self.tmp / "t", 30, self.tmp / "t" / "s.jsonl",
                           model="sonnet", system_prompt="x", schema=None)
            self.assertEqual(r["status"], "offline")
            self.assertIn("inter", (r["error"] or "").lower())
            self.assertLess(time.time() - t0, 10)  # not the 30s task timeout
        finally:
            net.online, config.NET_WATCHDOG_SECS = saved_online, saved_wd
            os.environ.pop("FAKE_HUNT", None)


class NetTests(unittest.TestCase):
    def test_online_probe_and_cache(self):
        import socket
        from fosc import net
        calls = {"n": 0}

        def boom(*a, **k):
            calls["n"] += 1
            raise OSError("no route")

        saved = socket.create_connection
        socket.create_connection = boom
        net._cache.update(ts=0.0, val=None)
        try:
            self.assertFalse(net.online(use_cache=False))         # all probes fail
            self.assertTrue(net.offline())                        # cached, no new calls
            n_after = calls["n"]
            net.online()                                          # cache hit
            self.assertEqual(calls["n"], n_after)
        finally:
            socket.create_connection = saved
            net._cache.update(ts=0.0, val=None)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = isolate(self)

    def _seed(self, target):
        from fosc.state import RunState
        st = RunState(target)
        items = [{"url": f"https://app.test/api/users/{i}", "method": "GET", "path": f"/api/users/{i}",
                  "params": [], "host": "app.test", "pattern": f"app.test/api/users{i}", "tech": ["express"],
                  "examples": [], "nuclei": []} for i in range(3)]
        (st.dir / "surface.json").write_text(json.dumps({"hosts": [], "items": items, "js": [], "nuclei": []}))
        return st

    def test_full_pipeline_confirms_reports_learns_and_keeps_going(self):
        from fosc.engine import run_hunt
        st = self._seed("app.test")
        run_hunt("app.test", workers=2, timeout=30, nuclei=False)
        snap = st.snapshot()
        self.assertEqual(snap["done"], 3, "must keep hunting after the first confirmed finding")
        self.assertEqual(snap["confirmed_count"], 3)  # distinct patterns -> distinct findings
        f = snap["confirmed"][0]
        self.assertEqual(f["severity"], "high")
        self.assertTrue((st.dir / f["report_path"]).exists())
        self.assertTrue(list((st.dir / "pocs").glob("*/poc.md")))
        self.assertEqual(snap["meta"]["status"], "finished")
        self.assertGreater(snap["meta"]["cost_usd"], 0)
        kinds = {l["kind"] for l in knowledge.all_lessons()}
        self.assertEqual(kinds, {"win", "note"})
        self.assertIn("IDOR", knowledge.read_playbook())  # consolidation ran (>=5 new lessons)
        self.assertIn("JWT", knowledge.read_target_notes("app.test"))

    def test_refuted_becomes_false_positive_lesson(self):
        from fosc.engine import run_hunt
        os.environ["FAKE_REVIEW"] = "refute"
        st = self._seed("app2.test")
        run_hunt("app2.test", workers=1, timeout=30, nuclei=False, max_items=1)
        snap = st.snapshot()
        self.assertEqual(snap["confirmed_count"], 0)
        self.assertEqual(snap["verdicts"].get("refuted"), 1)
        self.assertTrue(any(l["kind"] == "fp" for l in knowledge.all_lessons()))

    def test_stop_file_ends_run(self):
        from fosc.engine import run_hunt
        st = self._seed("app3.test")
        st.stop_path.write_text("x")  # run_hunt clears a stale STOP at start...
        os.environ["FAKE_HUNT"] = "slow"
        th = threading.Thread(target=run_hunt, kwargs=dict(target="app3.test", workers=1, timeout=30,
                                                           continuous=True, interval=60, nuclei=False))
        th.start()
        time.sleep(1.5)
        st.stop_path.write_text("x")  # ...so a STOP written mid-task must end it after that task
        th.join(20)
        self.assertFalse(th.is_alive())
        self.assertEqual(st.read_meta()["status"], "stopped")
        self.assertEqual(st.snapshot()["done"], 1, "in-flight task finishes, no new one starts")

    def test_max_items_caps_single_pass(self):
        from fosc.engine import run_hunt
        os.environ["FAKE_HUNT"] = "rejected"
        st = self._seed("app4.test")
        run_hunt("app4.test", workers=2, timeout=30, nuclei=False, max_items=2)
        self.assertEqual(st.snapshot()["done"], 2)


class ViewerGuardTests(unittest.TestCase):
    def setUp(self):
        isolate(self)
        import http.server
        from fosc import webview
        webview.Handler.port = 0
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), webview.Handler)
        webview.Handler.port = self.srv.server_address[1]
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def _req(self, path, data=None, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_get_ok_and_static(self):
        code, body = self._req("/api/overview")
        self.assertEqual(code, 200)
        self.assertIn("targets", json.loads(body))
        self.assertEqual(self._req("/")[0], 200)
        self.assertEqual(self._req("/app.js")[0], 200)

    def test_bad_host_rejected(self):
        self.assertEqual(self._req("/api/overview", headers={"Host": "evil.test"})[0], 403)

    def test_post_requires_header_and_same_origin(self):
        from fosc.state import RunState
        RunState("x.test")  # control only acts on existing runs
        body = json.dumps({"target": "x.test", "action": "pause"}).encode()
        ct = {"Content-Type": "application/json"}
        self.assertEqual(self._req("/api/control", body, ct)[0], 403)
        self.assertEqual(self._req("/api/control", body, {**ct, "X-FOSC": "1", "Origin": "https://evil.test"})[0], 403)
        code, resp = self._req("/api/control", body, {**ct, "X-FOSC": "1", "Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(resp)["ok"])

    def test_log_rejects_path_traversal(self):
        code, body = self._req("/api/log?target=x.test&item_id=../../etc")
        self.assertFalse(json.loads(body)["ok"])

    def test_chat_roundtrip(self):
        # empty history
        code, body = self._req("/api/chat")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["messages"], [])
        # send a message (spawns a background turn via the fake claude)
        payload = json.dumps({"message": "oi"}).encode()
        hdr = {"Content-Type": "application/json", "X-FOSC": "1", "Origin": f"http://127.0.0.1:{self.port}"}
        code, body = self._req("/api/chat", payload, hdr)
        self.assertTrue(json.loads(body)["ok"])
        # wait for the turn to finish
        for _ in range(60):
            data = json.loads(self._req("/api/chat")[1])
            if data["messages"] and not data["live"].get("running"):
                break
            time.sleep(0.25)
        roles = [m["role"] for m in data["messages"]]
        self.assertEqual(roles[:2], ["user", "assistant"])
        self.assertFalse(data["live"].get("running"))

    def test_reads_do_not_create_run_dirs(self):
        self.assertEqual(self._req("/api/state?target=ghost.test")[0], 404)
        self._req("/api/log?target=ghost.test&item_id=0123456789abcdef")
        self._req("/api/finding?target=ghost.test&id=x")
        self.assertFalse(config.run_exists("ghost.test"))


class ScopeTests(unittest.TestCase):
    def test_url_target_is_strict_exact_host(self):
        from fosc.scope import Scope
        s = Scope.from_target("https://1.migbot.com.br/#/")
        self.assertFalse(s.allow_subdomains)
        self.assertTrue(s.allows("https://1.migbot.com.br/rest/products"))
        # the leak cases the bank cares about — all must be rejected:
        for bad in ("https://migbot.com.br/",            # parent
                    "https://2.migbot.com.br/",          # sibling
                    "https://admin.1.migbot.com.br/",    # subdomain
                    "https://1migbot.com.br/",           # look-alike
                    "https://evil.com/?x=1.migbot.com.br"):
            self.assertFalse(s.allows(bad), bad)
            self.assertIn("fora do escopo", s.reason(bad))

    def test_bare_domain_allows_subdomains_only(self):
        from fosc.scope import Scope
        s = Scope.from_target("example.com")
        self.assertTrue(s.allow_subdomains)
        self.assertTrue(s.allows("https://api.example.com/v1"))
        self.assertTrue(s.allows("https://example.com/"))
        self.assertFalse(s.allows("https://evil.com/"))
        self.assertFalse(s.allows("https://notexample.com/"))  # suffix look-alike

    def test_localhost_juice_shop_is_strict(self):
        from fosc.scope import Scope
        s = Scope.from_target("http://127.0.0.1:3000")
        self.assertFalse(s.allow_subdomains)
        self.assertTrue(s.allows("http://127.0.0.1:3000/rest/user/login"))
        self.assertFalse(s.allows("http://10.0.0.5/"))        # different host
        self.assertFalse(s.allows("http://localhost:3000/"))  # name != IP, strict

    def test_strict_note_forbids_drift(self):
        from fosc.scope import Scope
        note = Scope.from_target("https://1.migbot.com.br/").note()
        self.assertIn("ESTRITO", note)
        self.assertIn("1.migbot.com.br", note)
        self.assertIn("PROIBIDO", note)

    def test_recon_in_scope_delegates(self):
        from fosc.recon import in_scope
        self.assertTrue(in_scope("https://1.migbot.com.br/a", "https://1.migbot.com.br/#/"))
        self.assertFalse(in_scope("https://x.migbot.com.br/a", "https://1.migbot.com.br/#/"))


class SpaReconTests(unittest.TestCase):
    def test_mines_api_paths_from_js_bundle(self):
        from fosc.recon import _paths_from_js
        js = ('this.http.post("/rest/user/login",c);'
              'this.http.get("/rest/products/search?q="+q);'
              'const u="/api/Feedbacks/";{path:"product/:id"};'
              'fetch(`/rest/basket/`+id);logo:"assets/img/logo.png";i:"/i18n/en.json"')
        paths = _paths_from_js(js)
        self.assertIn("/rest/user/login", paths)
        self.assertIn("/rest/products/search", paths)      # query stripped
        self.assertIn("/api/Feedbacks", paths)
        self.assertNotIn("/i18n/en.json", paths)           # asset filtered
        self.assertFalse(any("logo" in p for p in paths))  # asset filtered

    def test_normalize_drops_uninterpolated(self):
        from fosc.recon import _normalize_js_path
        self.assertEqual(_normalize_js_path("/rest/products/:id/reviews"), "/rest/products/1/reviews")
        self.assertEqual(_normalize_js_path("/rest/${id}/x"), "/rest/1/x")   # resolved to testable
        self.assertIsNone(_normalize_js_path("/rest/${broken/x"))            # malformed -> dropped
        self.assertIsNone(_normalize_js_path("//api.ipinfodb.com/v3/ip"))    # external (scope hygiene)


class MitreTests(unittest.TestCase):
    def test_maps_classes_to_techniques(self):
        from fosc import mitre
        self.assertEqual(mitre.tag("SQL injection (UNION-based)"), "T1190, T1213")
        self.assertIn("T1059.007", mitre.tag("reflected XSS"))        # JS execution
        self.assertEqual(mitre.tag("remote code execution"), "T1190, T1059")
        self.assertEqual(mitre.tag("some unknown class"), "T1190")    # default
        rows = mitre.techniques("local file inclusion")
        self.assertTrue(all({"id", "name", "tactic"} <= r.keys() for r in rows))


class AuthzTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from fosc.authz import ApprovalStore
        self.store = ApprovalStore(Path(tempfile.mkdtemp(prefix="authz-")) / "approvals.jsonl")

    def test_risk_classification(self):
        from fosc.authz import risk
        self.assertEqual(risk("recon"), "passive")
        self.assertEqual(risk("active-hunt"), "sensitive")
        self.assertEqual(risk("privilege-escalation"), "sensitive")
        self.assertEqual(risk("something-new"), "sensitive")  # unknown -> fail safe

    def test_store_request_decide_status(self):
        rid = self.store.request("active-hunt", "app.test", "sensitive", "ctx")
        self.assertEqual(self.store.status(rid), "pending")
        self.assertEqual([r["id"] for r in self.store.pending()], [rid])
        self.store.decide(rid, True, "alice", "ok")
        self.assertEqual(self.store.status(rid), "approved")
        self.assertEqual(self.store.pending(), [])

    def test_require_auto_approves_passive(self):
        from fosc.authz import require
        d = require(self.store, "recon", "app.test", mode="ask", interactive=False)
        self.assertTrue(d.approved)
        self.assertEqual(d.status, "auto")

    def test_require_yolo_approves_sensitive(self):
        from fosc.authz import require
        d = require(self.store, "exploit", "app.test", mode="yolo", interactive=False)
        self.assertTrue(d.approved)

    def test_require_sensitive_blocks_then_pending(self):
        from fosc.authz import require
        d = require(self.store, "active-hunt", "app.test", mode="ask",
                    interactive=False, wait=False)
        self.assertFalse(d.approved)
        self.assertEqual(d.status, "pending")
        # a human approves out-of-band -> status flips, next check sees it
        self.store.decide(d.id, True, "bob", "autorizado")
        self.assertEqual(self.store.status(d.id), "approved")

    def test_require_headless_wait_sees_approval(self):
        from fosc.authz import require
        import threading
        rid_box = {}

        def approve_soon():
            import time as _t
            _t.sleep(0.3)
            p = self.store.pending()
            if p:
                rid_box["id"] = p[0]["id"]
                self.store.decide(p[0]["id"], True, "carol")

        threading.Thread(target=approve_soon, daemon=True).start()
        d = require(self.store, "db-scan", "app.test", mode="ask",
                    interactive=False, wait=True, timeout=5)
        self.assertTrue(d.approved)


class ComposerTests(unittest.TestCase):
    def test_layout_wraps_and_tracks_cursor(self):
        from fosc.composer import Composer
        c = Composer("abcdef")           # 6 chars, width 3
        lines, (row, col) = c.layout(3)
        self.assertEqual(lines[:2], ["abc", "def"])
        # cursor sits at end; an exact-width fill pushes it onto a fresh next row
        self.assertEqual((row, col), (2, 0))

    def test_newline_and_backspace(self):
        from fosc.composer import Composer
        c = Composer("ab")
        c.insert("\n")
        c.insert("c")
        self.assertEqual(c.value(), "ab\nc")
        lines, _ = c.layout(40)
        self.assertEqual(lines, ["ab", "c"])
        c.backspace()
        self.assertEqual(c.value(), "ab\n")

    def test_render_borders_align_and_use_crlf(self):
        """Regression: raw mode has no ONLCR, so rows must be CRLF-joined and all
        three borders must be the same visible width."""
        import re
        from fosc.composer import Composer, _render
        c = Composer("linha um")
        c.insert("\nlinha dois mais longa")
        inner_w = 50
        s, _ = _render(c, "enter = nova linha · ctrl+e = enviar", inner_w, None)
        self.assertIn("\r\n", s)                      # CRLF join
        plain = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", s)
        widths = {r[0]: len(r) for r in (ln.replace("\r", "") for ln in plain.split("\r\n"))
                  if r and r[0] in "╭│╰"}
        self.assertEqual(len(widths), 3)              # top, body, bottom glyphs seen
        self.assertEqual(len(set(widths.values())), 1, f"borders misaligned: {widths}")
        self.assertEqual(next(iter(widths.values())), inner_w + 4)


class PrivescStageTests(unittest.TestCase):
    def test_merge_dedups_and_keeps_scalars(self):
        from fosc import privesc
        acc = {"cost": 0.0}
        pv = {"enumeration": ["mysql root"], "blocked": ["dumpfile 0666"],
              "attempts": [{"vector": "6662", "status": "blocked", "researchable": True}],
              "escalated": False, "summary": "s1", "in_container": True}
        privesc._merge(acc, pv)
        privesc._merge(acc, pv)                       # idempotent
        self.assertEqual(len(acc["attempts"]), 1)
        self.assertEqual(len(acc["enumeration"]), 1)
        self.assertTrue(acc["in_container"])

    def test_live_lead_detection(self):
        from fosc import privesc
        self.assertTrue(privesc._has_live_lead(
            {"attempts": [{"vector": "udf", "status": "partial", "researchable": True}]}))
        self.assertTrue(privesc._has_live_lead({"next_steps": ["try redis"]}))
        self.assertFalse(privesc._has_live_lead(
            {"attempts": [{"vector": "sudo", "status": "blocked", "researchable": False}]}))

    def test_loot_extracts_real_values(self):
        from fosc import privesc
        class FakeState:
            def confirmed(self):
                return [{"vuln_class": "info-disclosure", "url": "http://x/config.ini",
                         "summary": "exposed DB credential root/root in purple.ini"},
                        {"vuln_class": "xss", "url": "http://x/s", "summary": "alert(1)"}]
        loot = privesc._loot(FakeState())
        self.assertIn("root/root", loot)
        self.assertNotIn("alert(1)", loot)            # non-cred finding filtered out


class ModelRouterTests(unittest.TestCase):
    """The model layer: provider is config, and a failing/refusing/slow model
    fails over to the next WITHOUT the caller knowing. No app rewrite, per the
    BB AWS/Bedrock requirement."""

    def setUp(self):
        self.tmp = isolate(self)
        from fosc import models
        self.models = models
        self._saved = (config.MODEL_PROVIDER, dict(config.MODEL_LADDERS), config.MODEL_MAX_ATTEMPTS)
        config.MODEL_PROVIDER = "anthropic"
        config.MODEL_LADDERS = {"hunt": ["sonnet", "haiku"], "verify": ["opus", "sonnet"]}
        config.MODEL_MAX_ATTEMPTS = 3

    def tearDown(self):
        config.MODEL_PROVIDER, config.MODEL_LADDERS, config.MODEL_MAX_ATTEMPTS = self._saved

    def _patch(self, scripted):
        calls = []

        def fake(prompt, cwd, timeout, stream_path, *, model, system_prompt,
                 schema=None, on_activity=None, allow_tools=True, effort=None,
                 budget=None, env_extra=None):
            Path(stream_path).parent.mkdir(parents=True, exist_ok=True)
            Path(stream_path).write_text(f"stream for {model}\n")
            calls.append({"model": model, "env": env_extra})
            return dict(scripted[len(calls) - 1])
        self.models.run_claude = fake
        return calls

    def _run(self, role="hunt", on_activity=None):
        return self.models.run(role, "p", cwd=self.tmp / "t", timeout=100,
                               stream_path=self.tmp / "t" / "s.jsonl",
                               system_prompt="x", on_activity=on_activity)

    def test_resolve_provider_from_config(self):
        self.assertEqual(self.models.resolve("sonnet").env["CLAUDE_CODE_USE_BEDROCK"], "0")
        self.assertEqual(self.models.resolve("bedrock:opus").env["CLAUDE_CODE_USE_BEDROCK"], "1")
        self.assertEqual(self.models.resolve("bedrock:sonnet").model_id,
                         config.BEDROCK_MODEL_IDS["sonnet"])

    def test_failover_on_error(self):
        calls = self._patch([
            {"output": None, "cost": 0.01, "status": "error", "error": "500"},
            {"output": {"ok": 1}, "cost": 0.02, "status": "ok", "error": None},
        ])
        msgs = []
        r = self._run(on_activity=msgs.append)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["model"], "anthropic:haiku")          # second model answered
        self.assertEqual([c["model"] for c in calls], ["sonnet", "haiku"])
        self.assertAlmostEqual(r["cost"], 0.03)                  # both attempts charged
        self.assertEqual(len(r["attempts"]), 2)
        self.assertTrue(any("failover" in m for m in msgs))

    def test_failover_on_refusal(self):
        self._patch([
            {"output": None, "cost": 0.0, "status": "refused", "error": "declined"},
            {"output": {"ok": 1}, "cost": 0.02, "status": "ok", "error": None},
        ])
        r = self._run()
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["attempts"][0]["status"], "refused")

    def test_offline_does_not_failover(self):
        calls = self._patch([
            {"output": None, "cost": 0.0, "status": "offline", "error": "sem internet"},
            {"output": {"ok": 1}, "cost": 0.02, "status": "ok", "error": None},
        ])
        r = self._run()
        self.assertEqual(r["status"], "offline")                 # stops immediately
        self.assertEqual(len(calls), 1)                          # second model never tried

    def test_all_fail_returns_last(self):
        self._patch([
            {"output": None, "cost": 0.01, "status": "error", "error": "a"},
            {"output": None, "cost": 0.01, "status": "timeout", "error": "b"},
        ])
        r = self._run()
        self.assertEqual(r["status"], "timeout")
        self.assertEqual(len(r["attempts"]), 2)
        self.assertAlmostEqual(r["cost"], 0.02)

    def test_failed_attempt_stream_preserved(self):
        self._patch([
            {"output": None, "cost": 0.0, "status": "error", "error": "a"},
            {"output": {"ok": 1}, "cost": 0.0, "status": "ok", "error": None},
        ])
        self._run()
        self.assertTrue((self.tmp / "t" / "s.try0.jsonl").exists())  # first try kept
        self.assertTrue((self.tmp / "t" / "s.jsonl").exists())       # winner at canonical path


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = isolate(self)
        from fosc.audit import AuditLog
        self.path = self.tmp / "audit.jsonl"
        self.log = AuditLog(self.path)

    def test_chain_links_and_verifies(self):
        self.log.record("run_start", actor="x", target="t")
        self.log.record("plan", hypothesis="h")
        self.log.record("finding", severity="high")
        ok, n, _ = self.log.verify()
        self.assertTrue(ok)
        self.assertEqual(n, 3)
        e = self.log.entries()
        self.assertEqual(e[0]["prev"], "0" * 64)
        self.assertEqual(e[1]["prev"], e[0]["hash"])     # each links to the previous

    def test_tamper_is_detected(self):
        self.log.record("a", x=1)
        self.log.record("b", x=2)
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["data"]["x"] = 999                            # edit a past record
        lines[0] = json.dumps(rec)
        self.path.write_text("\n".join(lines) + "\n")
        ok, idx, _ = self.log.verify()
        self.assertFalse(ok)                              # broken chain caught
        self.assertEqual(idx, 0)

    def test_redact_minimizes_pii(self):
        from fosc import audit
        out = audit.redact("mail joao@banco.com cpf 123.456.789-00 cartao 4111111111111111")
        self.assertNotIn("joao@banco.com", out)
        self.assertIn("@banco.com", out)                  # kept recognizable, local masked
        self.assertIn("***.***.***-**", out)
        self.assertNotIn("4111111111111111", out)


class PlanTests(unittest.TestCase):
    def test_hunt_plan_has_all_four_elements(self):
        from fosc import plan
        p = plan.hunt_plan({"url": "http://x/a"}, ["IDOR", "SQLi"],
                           budget=1.0, timeout=600, scope_label="x [estrito]")
        for k in ("hypothesis", "action", "expected_result", "stop_condition"):
            self.assertTrue(p[k])
        self.assertIn("IDOR", p["hypothesis"])
        self.assertIn("600", p["stop_condition"])         # bounded, explicit


class AuthzProhibitedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = isolate(self)

    def test_prohibited_tier(self):
        from fosc import authz
        self.assertEqual(authz.risk("dos"), "prohibited")
        self.assertEqual(authz.risk("recon"), "passive")

    def test_prohibited_refused_even_in_yolo(self):
        from fosc import authz
        store = authz.ApprovalStore(self.tmp / "ap.jsonl")
        dec = authz.require(store, "ddos", "t", mode="yolo")   # no mode can enable it
        self.assertFalse(dec.approved)
        self.assertEqual(dec.status, "prohibited")


class HaltTests(unittest.TestCase):
    def test_kill_all_kills_registered_tasks(self):
        import subprocess
        import signal
        from fosc import claude_runner
        p = subprocess.Popen(["sleep", "30"], start_new_session=True)
        pgid = os.getpgid(p.pid)
        with claude_runner._LIVE_LOCK:
            claude_runner._LIVE_PGIDS.add(pgid)
        try:
            n = claude_runner.kill_all()
            self.assertGreaterEqual(n, 1)
            p.wait(timeout=5)
            self.assertIsNotNone(p.poll())                 # task is dead
        finally:
            with claude_runner._LIVE_LOCK:
                claude_runner._LIVE_PGIDS.discard(pgid)
            if p.poll() is None:
                p.kill()


class ScopeProxyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = isolate(self)

    def test_host_allowed_decision(self):
        from fosc.scope_proxy import host_allowed
        from fosc.scope import Scope
        sc = Scope.from_target("http://127.0.0.1:3001")
        egress = ["api.anthropic.com", ".amazonaws.com"]
        self.assertTrue(host_allowed("127.0.0.1", sc, egress))            # in scope
        self.assertTrue(host_allowed("api.anthropic.com", sc, egress))    # model egress
        self.assertTrue(host_allowed("bedrock-runtime.us-east-1.amazonaws.com", sc, egress))
        self.assertFalse(host_allowed("evil.com", sc, egress))            # out of scope
        self.assertFalse(host_allowed("169.254.169.254", sc, egress))     # cloud metadata

    def test_connect_out_of_scope_is_blocked(self):
        import socket
        from fosc.scope_proxy import ScopeProxy
        from fosc.scope import Scope
        from fosc.audit import AuditLog
        log = AuditLog(self.tmp / "audit.jsonl")
        px = ScopeProxy(Scope.from_target("http://allowed.example"), audit_log=log)
        px.start()
        try:
            s = socket.create_connection(("127.0.0.1", px.port), timeout=5)
            s.sendall(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            resp = s.recv(200)
            s.close()
            self.assertIn(b"403", resp)
            self.assertEqual(px.blocked, 1)
            self.assertIn("scope_block", [e["kind"] for e in log.entries()])
        finally:
            px.stop()

    def test_connect_in_scope_tunnels(self):
        import socket
        import threading as _t
        from fosc.scope_proxy import ScopeProxy
        from fosc.scope import Scope
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def echo():
            c, _ = srv.accept()
            c.sendall(b"ECHO:" + c.recv(100))
            c.close()
        _t.Thread(target=echo, daemon=True).start()
        px = ScopeProxy(Scope.from_target(f"http://127.0.0.1:{port}"))
        px.start()
        try:
            s = socket.create_connection(("127.0.0.1", px.port), timeout=5)
            s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
            self.assertIn(b"200", s.recv(100))             # tunnel established
            s.sendall(b"hello")
            self.assertIn(b"ECHO:hello", s.recv(100))       # bytes flow through
            s.close()
        finally:
            px.stop()
            srv.close()


class TelegramTests(unittest.TestCase):
    def test_parse_callback_approve(self):
        from fosc.telegram_bot import parse_update
        i = parse_update({"update_id": 5, "callback_query": {
            "id": "cq1", "data": "approve:abc123", "from": {"username": "joao"}}})
        self.assertEqual(i["kind"], "approve")
        self.assertEqual(i["id"], "abc123")
        self.assertEqual(i["from"], "joao")
        self.assertEqual(i["callback_id"], "cq1")

    def test_parse_callback_deny_and_halt(self):
        from fosc.telegram_bot import parse_update
        self.assertEqual(parse_update({"callback_query": {"data": "deny:x", "from": {"first_name": "A"}}})["kind"], "deny")
        self.assertEqual(parse_update({"message": {"text": "/halt now", "from": {"username": "op"}}})["kind"], "halt")

    def test_parse_ignores_noise(self):
        from fosc.telegram_bot import parse_update
        self.assertIsNone(parse_update({"message": {"text": "oi tudo bem"}}))
        self.assertIsNone(parse_update({"callback_query": {"data": "weird-no-colon"}}))

    def test_send_telegram_not_configured(self):
        from fosc import notify
        ok, desc = notify.send_telegram("hi", cfg={})
        self.assertFalse(ok)
        self.assertEqual(desc, "telegram not configured")

    def test_secrets_from_env(self):
        """AWS injects Telegram creds as env from Secrets Manager — no repo/image."""
        from fosc import notify
        os.environ["TELEGRAM_TOKEN"] = "tok"
        os.environ["TELEGRAM_CHAT_ID"] = "42"
        try:
            self.assertTrue(notify.configured(cfg={}))
            self.assertEqual(notify.telegram_cfg(cfg={}), ("tok", "42"))
        finally:
            os.environ.pop("TELEGRAM_TOKEN", None)
            os.environ.pop("TELEGRAM_CHAT_ID", None)

    def test_approval_message_has_buttons(self):
        from fosc import notify
        captured = {}
        orig = notify.send_telegram
        notify.send_telegram = lambda text, cfg=None, buttons=None: (captured.update(text=text, buttons=buttons), (True, None))[1]
        try:
            notify.notify_approval("tgt", "active-hunt", "ctx", "rid9")
        finally:
            notify.send_telegram = orig
        self.assertIn("AUTORIZAÇÃO", captured["text"])
        self.assertEqual(captured["buttons"][0][0][1], "approve:rid9")   # ✅ button
        self.assertEqual(captured["buttons"][0][1][1], "deny:rid9")      # ❌ button


if __name__ == "__main__":
    unittest.main()
