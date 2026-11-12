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
        from fosc import webview
        js = next((k for k in webview.STATIC if k.endswith("app.js")), None)
        self.assertIsNotNone(js)              # qualquer front servido tem um app.js
        self.assertEqual(self._req(js)[0], 200)

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


class ArsenalTests(unittest.TestCase):
    def test_arsenal_note_lists_present_tools(self):
        from fosc import toolrunner
        orig = toolrunner.have
        toolrunner.have = lambda b: b in {"nmap", "httpx", "sqlmap"}
        try:
            found = toolrunner.arsenal_on_path()
            note = toolrunner.arsenal_note()
        finally:
            toolrunner.have = orig
        self.assertIn("nmap", note)
        self.assertIn("httpx", note)
        self.assertIn("sqlmap", note)
        flat = {t for ts in found.values() for t in ts}
        self.assertEqual(flat, {"nmap", "httpx", "sqlmap"})
        self.assertIn("escopo", note.lower())                 # reminder not to leave scope

    def test_arsenal_empty_when_nothing_installed(self):
        from fosc import toolrunner
        orig = toolrunner.have
        toolrunner.have = lambda b: False
        try:
            self.assertEqual(toolrunner.arsenal_note(), "")
            self.assertEqual(toolrunner.arsenal_on_path(), {})
        finally:
            toolrunner.have = orig


if __name__ == "__main__":
    unittest.main()


class NormalizeTargetTests(unittest.TestCase):
    """What the operator types in the panel/CLI must map to one campaign."""

    def test_spa_fragment_is_dropped(self):
        from fosc import config, webview
        for raw in ("https://1.migbot.com.br/#/", " https://1.migbot.com.br/#/login ",
                    "https://1.migbot.com.br/", "https://1.migbot.com.br"):
            t = config.normalize_target(raw)
            self.assertEqual(t, "https://1.migbot.com.br")
            self.assertTrue(webview.TARGET_RX.match(t))

    def test_path_and_bare_host_kept(self):
        from fosc import config
        self.assertEqual(config.normalize_target("https://x.com/app/#/a"), "https://x.com/app/")
        self.assertEqual(config.normalize_target("x.com"), "x.com")
        self.assertEqual(config.normalize_target("HTTPS://x.com/"), "https://x.com")


class CircuitBreakerTests(unittest.TestCase):
    """Don't take down the target: N failures trip, recovery never auto-resumes."""

    def test_trips_after_consecutive_failures_only(self):
        from fosc.health import Breaker
        b = Breaker(fails=3)
        self.assertEqual([b.feed(x) for x in (False, False, True, False, False)], [None] * 5)
        self.assertEqual(b.feed(False), "trip")          # 3rd in a row
        self.assertIsNone(b.feed(False))                 # trips once
        self.assertEqual([b.feed(True), b.feed(True)], [None, "recover"])
        self.assertTrue(b.tripped)                        # recovered but still tripped (human resumes)
        b.reset()
        self.assertFalse(b.tripped)

    def test_watchdog_calls_trip_and_recover(self):
        import time as _t
        from fosc.health import TargetHealth
        seq = iter([False, False, False, True, True] + [True] * 50)
        ev = []
        w = TargetHealth("https://x", lambda r: ev.append(("trip", r)), lambda d: ev.append(("rec", d)),
                         interval=0.01, fails=3, prober=lambda u, t: (next(seq), "p"))
        w.start(); _t.sleep(0.3); w.stop()
        self.assertEqual([e[0] for e in ev], ["trip", "rec"])

    def test_probe_treats_5xx_gateway_as_down_and_404_as_up(self):
        import http.server, threading
        from fosc.health import probe
        codes = {"/up": 404, "/down": 503}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(codes[self.path]); self.end_headers()
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_port}"
        import os
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
        try:
            self.assertTrue(probe(base + "/up", 3)[0])
            self.assertFalse(probe(base + "/down", 3)[0])
            self.assertFalse(probe("http://127.0.0.1:1/", 2)[0])   # refused
        finally:
            srv.shutdown()


class ToolKillAndRateTests(unittest.TestCase):
    def test_kill_tools_stops_running_recon_tool(self):
        import threading, time as _t
        from fosc import toolrunner
        res = {}
        th = threading.Thread(target=lambda: res.setdefault("r", toolrunner.run_proc(["sleep", "30"], timeout=60)))
        t0 = _t.time(); th.start(); _t.sleep(0.4)
        self.assertGreaterEqual(toolrunner.kill_tools(), 1)
        th.join(5)
        self.assertLess(_t.time() - t0, 5)

    def test_hold_blocks_new_tools(self):
        from fosc import toolrunner
        toolrunner.HOLD.set()
        try:
            self.assertEqual(toolrunner.run_proc(["echo", "x"], timeout=5), (None, "", ""))
        finally:
            toolrunner.HOLD.clear()

    def test_every_target_touching_tool_is_rate_limited(self):
        import pathlib, tempfile
        src = pathlib.Path("fosc/recon.py").read_text()
        for tool, flag in (("httpx", '"-rl"'), ("katana", '"-rl"'), ("feroxbuster", '"--rate-limit"'),
                           ("ffuf", '"-rate"'), ("nuclei", '"-rl"')):
            i = src.index(f'["{tool}",')
            self.assertIn(flag, src[i:i + 400], tool)
        self.assertNotIn('"-t", "40"', src)


class AdaptiveRateTests(unittest.TestCase):
    """Per-host budget: adapts to latency, shared across concurrent tools."""

    def test_aimd_halves_on_failure_and_grows_on_health(self):
        from fosc.ratectl import HostRate
        r = HostRate(start=20, lo=3, hi=60, step=5)
        self.assertEqual(r.observe(True, 100), 25)        # healthy -> +step
        self.assertEqual(r.observe(False, None), 12)       # failure -> halve
        self.assertEqual(r.observe(True, 120), 17)         # recover -> +step
        for _ in range(50):
            r.observe(False, None)
        self.assertEqual(r.rate, 3)                         # never below floor

    def test_slow_latency_backs_off(self):
        from fosc.ratectl import HostRate
        r = HostRate(start=40, lo=3, hi=60, step=5)
        for _ in range(5):
            r.observe(True, 80)                            # establish a fast baseline
        fast = r.rate
        r.observe(True, 5000)                              # a sudden 5s response = slow
        self.assertLess(r.rate, fast)

    def test_concurrent_tools_split_one_host_budget(self):
        from fosc.ratectl import _Registry
        reg = _Registry()
        reg.host("h").rate = 30
        # tools that expect company (parts=2, as content/nuclei pass) split the budget
        with reg.share("h", parts=2) as (r1, _):
            with reg.share("h", parts=2) as (r2, _):
                self.assertLessEqual(r1 + r2, 30)          # together never exceed the host budget
                self.assertGreaterEqual(min(r1, r2), 1)
        # a lone tool (parts=1) may use the whole budget
        with reg.share("h") as (r1, _):
            self.assertEqual(r1, 30)

    def test_budget_is_per_host(self):
        from fosc.ratectl import _Registry
        reg = _Registry()
        reg.observe("a.com", False, None)
        self.assertNotEqual(reg.host("a.com").rate, reg.host("b.com").rate)


class ProgressiveReconTests(unittest.TestCase):
    """Fast phase unblocks the hunt; background stages feed the queue."""

    def test_background_recon_drains_new_endpoints(self):
        import time
        from fosc import recon
        hosts = [{"url": "https://t.test", "tech": [], "status": 200, "title": None}]
        surface = {"hosts": hosts, "items": [], "js": [], "nuclei": [], "urls": []}
        import pathlib, tempfile
        cache = pathlib.Path(tempfile.mkdtemp()) / "surface.json"
        bg = recon.BackgroundRecon.__new__(recon.BackgroundRecon)
        # drive the pure merge logic without spawning tools
        bg.target = "https://t.test"; bg.surface = surface; bg.cache = cache
        bg._lock = __import__("threading").Lock(); bg._known = set(); bg._urls = set()
        bg._pending = []; bg._hits = []; bg.stats = {}
        bg._add_urls("content", {"https://t.test/api/users", "https://t.test/api/orders"})
        new, hits = bg.drain()
        self.assertEqual(len(new), 2)
        self.assertEqual(bg.drain()[0], [])                # drain is one-shot

    def test_cache_ttl_reused_then_expired(self):
        import time, os
        from fosc import recon, config
        import pathlib, tempfile
        d = pathlib.Path(tempfile.mkdtemp())
        cache = d / "surface.json"
        cache.write_text(json.dumps({"items": [{"pattern": "x"}], "hosts": [], "js": [], "nuclei": []}))
        self.assertTrue(recon._cache_fresh(cache))
        old = time.time() - config.RECON_CACHE_TTL - 10
        os.utime(cache, (old, old))
        self.assertFalse(recon._cache_fresh(cache))

    def test_attach_hits_is_idempotent(self):
        from fosc.recon import attach_hits
        items = [{"pattern": "h/api/x", "url": "https://h/api/x", "nuclei": []}]
        hit = {"matched": "https://h/api/x", "template": "t", "severity": "high"}
        attach_hits(items, [hit]); attach_hits(items, [hit])
        self.assertEqual(len(items[0]["nuclei"]), 1)


class _FakeSqs:
    """Minimal in-memory SQS FIFO: enough to test SqsQueue without boto3/AWS."""
    def __init__(self):
        self.msgs = []           # (body, group, dedup, receipt, visible_until, inflight_group)
        self._n = 0
        self.deleted = []
    def send_message(self, QueueUrl, MessageBody, MessageGroupId, MessageDeduplicationId):
        if any(m["dedup"] == MessageDeduplicationId for m in self.msgs):
            return {}
        self._n += 1
        self.msgs.append({"body": MessageBody, "group": MessageGroupId, "dedup": MessageDeduplicationId,
                          "receipt": f"r{self._n}", "inflight": False})
        return {"MessageId": str(self._n)}
    def receive_message(self, QueueUrl, MaxNumberOfMessages=1, WaitTimeSeconds=0, VisibilityTimeout=0):
        out, groups_inflight = [], {m["group"] for m in self.msgs if m["inflight"]}
        for m in self.msgs:
            if len(out) >= MaxNumberOfMessages:
                break
            if m["inflight"] or m["group"] in groups_inflight:
                continue
            m["inflight"] = True
            groups_inflight.add(m["group"])
            out.append({"Body": m["body"], "ReceiptHandle": m["receipt"]})
        return {"Messages": out}
    def delete_message(self, QueueUrl, ReceiptHandle):
        self.msgs = [m for m in self.msgs if m["receipt"] != ReceiptHandle]
        self.deleted.append(ReceiptHandle)


class JobQueueTests(unittest.TestCase):
    def _db(self):
        import tempfile, pathlib
        return pathlib.Path(tempfile.mkdtemp()) / "q.db"

    def test_one_target_one_campaign(self):
        from fosc.jobqueue import LocalQueue
        q = LocalQueue(store_path=self._db())
        j1, c1 = q.enqueue("https://x.com/#/")
        j2, c2 = q.enqueue("https://x.com")           # same target after normalization
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(j1["job_id"], j2["job_id"])

    def test_lease_respects_global_cap(self):
        from fosc.jobqueue import LocalQueue
        q = LocalQueue(store_path=self._db())
        for i in range(5):
            q.enqueue(f"https://t{i}.com")
        leased = q.lease(max_jobs=10, cap=2)
        self.assertEqual(len(leased), 2)
        self.assertEqual(q.running_count(), 2)
        self.assertEqual(len(q.lease(10, cap=2)), 0)   # cap reached
        q.complete(leased[0]["job_id"])
        self.assertEqual(len(q.lease(10, cap=2)), 1)   # a slot freed

    def test_snapshot_positions(self):
        from fosc.jobqueue import LocalQueue
        q = LocalQueue(store_path=self._db())
        q.enqueue("https://a.com", priority=5)
        q.enqueue("https://b.com", priority=1)         # higher priority -> position 1
        snap = q.snapshot()
        first = [j for j in snap if j["status"] == "queued"][0]
        self.assertEqual(first["target"], "https://b.com")
        self.assertEqual(first["position"], 1)

    def test_sqs_enqueue_lease_complete_with_fake_client(self):
        from fosc.jobqueue import SqsQueue
        fake = _FakeSqs()
        q = SqsQueue(queue_url="http://q", client=fake, store_path=self._db())
        job, created = q.enqueue("https://x.com/#/")
        self.assertTrue(created)
        self.assertEqual(len(fake.msgs), 1)
        _, dup = q.enqueue("https://x.com")            # one target, one campaign -> no 2nd msg
        self.assertFalse(dup)
        self.assertEqual(len(fake.msgs), 1)
        leased = q.lease(max_jobs=10, cap=5)
        self.assertEqual(len(leased), 1)
        q.complete(leased[0]["job_id"], True, receipt=leased[0]["_receipt"])
        self.assertEqual(fake.deleted, [leased[0]["_receipt"]])

    def test_sqs_fifo_one_inflight_per_target(self):
        from fosc.jobqueue import SqsQueue, _Store
        fake = _FakeSqs()
        db = self._db()
        q = SqsQueue(queue_url="http://q", client=fake, store_path=db)
        q.enqueue("https://x.com")
        first = q.lease(10, cap=5)
        # same target already in flight in SQS -> second lease yields nothing new for it
        self.assertEqual(len(first), 1)
        self.assertEqual(len(q.lease(10, cap=5)), 0)

    def test_get_queue_selects_backend(self):
        from fosc import config, jobqueue
        old = config.SQS_URL
        try:
            config.SQS_URL = ""
            self.assertEqual(jobqueue.get_queue(store_path=self._db()).kind, "local")
            config.SQS_URL = "http://q"
            self.assertEqual(jobqueue.get_queue(client=_FakeSqs(), store_path=self._db()).kind, "sqs")
        finally:
            config.SQS_URL = old


class DispatcherTests(unittest.TestCase):
    def test_launches_up_to_cap_then_frees(self):
        import tempfile, pathlib, threading
        from fosc.jobqueue import LocalQueue
        from fosc.dispatcher import Dispatcher
        q = LocalQueue(store_path=pathlib.Path(tempfile.mkdtemp()) / "q.db")
        for i in range(4):
            q.enqueue(f"https://t{i}.com")
        gate = threading.Event()
        launched = []
        # patch the module-level launcher to not spawn real processes
        import fosc.dispatcher as dmod
        orig = dmod._run_job
        def fake_run(queue, job, on_event=None):
            launched.append(job["target"]); gate.wait(2); queue.complete(job["job_id"], True)
        dmod._run_job = fake_run
        try:
            d = Dispatcher(queue=q, max_hunts=2)
            self.assertEqual(d.tick(), 2)      # cap
            self.assertEqual(d.tick(), 0)      # full
            gate.set()
            import time as _t; _t.sleep(0.2)
            self.assertGreaterEqual(d.tick(), 1)  # slots freed
        finally:
            dmod._run_job = orig
        self.assertGreaterEqual(len(launched), 2)


class PocWindowsTests(unittest.TestCase):
    """A bash curl PoC must also run byte-identically in Windows cmd.exe
    (the migbot SQLi report failed to reproduce only because of cmd quoting)."""

    def _cmd_body(self, cmd_curl: str) -> str:
        """Simulate how cmd.exe hands the -d argument to curl: outer "..." is
        stripped and \\" becomes "; single quotes are literal."""
        import re
        m = re.search(r'-d "((?:[^"\\]|\\.)*)"', cmd_curl)
        self.assertIsNotNone(m, cmd_curl)
        return m.group(1).replace('\\"', '"')

    def test_sqli_login_body_is_preserved_for_cmd(self):
        from fosc.pocfmt import to_cmd
        bash = ('curl -s -X POST https://t/rest/user/login '
                "-H 'Content-Type: application/json' "
                "-d '{\"email\":\"'\"'\"' or 1=1--\",\"password\":\"x\"}'")
        cmd = to_cmd(bash)
        self.assertIsNotNone(cmd)
        self.assertNotIn("'\"'\"'", cmd)                       # no bash escape left
        self.assertEqual(self._cmd_body(cmd), '{"email":"\' or 1=1--","password":"x"}')

    def test_header_single_quotes_become_double(self):
        from fosc.pocfmt import to_cmd
        cmd = to_cmd("curl -H 'Content-Type: application/json' https://t")
        self.assertIn('"Content-Type: application/json"', cmd)

    def test_plain_curl_needs_no_conversion(self):
        from fosc.pocfmt import to_cmd
        self.assertIsNone(to_cmd("curl https://t/api/x"))

    def test_report_blocks_include_windows_variant(self):
        from fosc.pocfmt import blocks
        md = "\n".join(blocks("curl -d '{\"a\":\"'\"'\"'b\"}' https://t"))
        self.assertIn("```bash", md)
        self.assertIn("cmd.exe", md)
        self.assertIn("```bat", md)


class PocReportPatchTests(unittest.TestCase):
    """Reports already on disk (written by an older run) must gain a Windows PoC."""

    def test_patch_markdown_adds_windows_block_once(self):
        from fosc.pocfmt import patch_markdown
        md = ("## Steps\n\n```bash\ncurl -d '{\"email\":\"'\"'\"'x\"}' https://t\n```\n\n"
              "Expected evidence: `ok`\n")
        out, changed = patch_markdown(md)
        self.assertTrue(changed)
        self.assertIn("_Windows (cmd.exe):_", out)
        self.assertIn("```bat", out)
        again, changed2 = patch_markdown(out)      # idempotent
        self.assertFalse(changed2)
        self.assertEqual(again.count("```bat"), 1)

    def test_patch_skips_portable_curl(self):
        from fosc.pocfmt import patch_markdown
        md = "```bash\ncurl https://t/api/x\n```\n"
        _, changed = patch_markdown(md)
        self.assertFalse(changed)

    def test_patch_reports_walks_run_dir(self):
        import tempfile, pathlib
        d = pathlib.Path(tempfile.mkdtemp())
        rep = d / "pocs" / "abc"
        rep.mkdir(parents=True)
        (rep / "report.md").write_text("```bash\ncurl -d '{\"a\":\"'\"'\"'b\"}' https://t\n```\n")
        from fosc.pocfmt import patch_reports
        scanned, patched = patch_reports(d)
        self.assertEqual((scanned, patched), (1, 1))
        self.assertIn("cmd.exe", (rep / "report.md").read_text())


def _parecer(cadeira, *, ok=True, veto=False, sev=None, conf=None, risco="baixo",
             lgpd=None, pilares=None, motivo=None):
    return {"cadeira": cadeira, "nome": cadeira, "ok": ok, "parecer": "parecer",
            "risco": risco, "severidade_sugerida": sev, "confianca": conf,
            "veto": veto, "motivo_veto": motivo, "lgpd_dado_pessoal": lgpd,
            "cia_pilares": pilares, "cost": 0.01}


class CouncilDecideTests(unittest.TestCase):
    """decidir() é pura e determinística: veto, reclassificação, piso de confiança."""

    def test_approved_when_no_veto(self):
        from fosc.council import decidir
        d = decidir([_parecer("lgpd"), _parecer("corporativo", sev="high")], "medium", "high")
        self.assertTrue(d["aprovado"])
        self.assertEqual(d["cadeiras_ok"], 2)
        self.assertEqual(d["motivos_veto"], [])

    def test_any_veto_blocks(self):
        from fosc.council import decidir
        d = decidir([_parecer("corporativo", sev="high"),
                     _parecer("governanca", veto=True, motivo="fora de escopo")], "high", "high")
        self.assertFalse(d["aprovado"])
        self.assertEqual([v["cadeira"] for v in d["motivos_veto"]], ["governanca"])
        self.assertEqual(d["motivos_veto"][0]["motivo"], "fora de escopo")

    def test_corporate_seat_sets_severity(self):
        from fosc.council import decidir
        # corporativa rebaixa para low mesmo com outra cadeira sugerindo critical
        d = decidir([_parecer("cia", sev="critical"),
                     _parecer("corporativo", sev="low")], "high", "medium")
        self.assertEqual(d["severidade_final"], "low")

    def test_highest_suggested_when_no_corporate(self):
        from fosc.council import decidir
        d = decidir([_parecer("cia", sev="medium"), _parecer("usuario", sev="high")], "low", "medium")
        self.assertEqual(d["severidade_final"], "high")

    def test_severity_falls_back_to_current(self):
        from fosc.council import decidir
        d = decidir([_parecer("cia"), _parecer("usuario")], "high", "medium")
        self.assertEqual(d["severidade_final"], "high")

    def test_confidence_floor_is_most_conservative(self):
        from fosc.council import decidir
        d = decidir([_parecer("cia", conf="alta"), _parecer("corporativo", conf="baixa")], "high", "high")
        self.assertEqual(d["confianca_final"], "low")

    def test_lgpd_and_cia_aggregated(self):
        from fosc.council import decidir
        d = decidir([_parecer("lgpd", lgpd=True),
                     _parecer("cia", pilares=["confidencialidade", "integridade"])], "medium", "medium")
        self.assertTrue(d["lgpd_dado_pessoal"])
        self.assertEqual(d["cia_pilares"], ["confidencialidade", "integridade"])
        self.assertEqual(d["risco_corporativo"], "baixo")

    def test_risk_takes_maximum(self):
        from fosc.council import decidir
        d = decidir([_parecer("cia", risco="baixo"), _parecer("corporativo", risco="critico")], "medium", "medium")
        self.assertEqual(d["risco_corporativo"], "critico")

    def test_failed_seat_vote_ignored(self):
        from fosc.council import decidir
        # uma cadeira que não respondeu (ok=False) não conta veto nem severidade
        d = decidir([_parecer("corporativo", sev="high"),
                     _parecer("governanca", ok=False, veto=True)], "medium", "medium")
        self.assertTrue(d["aprovado"])
        self.assertEqual(d["cadeiras_ok"], 1)


class WsViewTests(unittest.TestCase):
    """Adaptador motor -> shape do front da Ana (campaign/policies/plan/commands/
    approvals/findings/audit). Leitura pura, sem tocar na engine."""

    def test_empty_workspace_has_all_collections(self):
        isolate(self)
        from fosc import wsview
        ws = wsview.workspace(None)
        self.assertEqual(set(ws), {"campaign", "policies", "plan", "commands",
                                   "approvals", "findings", "audit"})
        self.assertEqual(ws["campaign"]["status"], "draft")
        self.assertEqual(ws["findings"], [])
        # as 3 listas de política sempre existem (allowed/conditional/prohibited)
        self.assertTrue(ws["policies"]["allowed"] and ws["policies"]["prohibited"])

    def test_real_run_maps_to_front_shape(self):
        isolate(self)
        from fosc.state import RunState
        from fosc.authz import ApprovalStore
        from fosc import wsview
        t = "alvo.example.com"
        st = RunState(t)
        st.write_meta(target=t, status="running", started_at=1700000000.0)
        st.add_confirmed({"url": f"https://{t}/login", "vuln_class": "SQLi",
                          "severity": "high", "title": "SQLi no login", "summary": "resumo",
                          "impact": "impacto", "evidence_marker": "admin@x", "confidence": "high"})
        ApprovalStore(st.approvals_path).request("active-hunt", t, "sensitive", "iniciar teste ativo")
        ws = wsview.workspace(t)
        self.assertEqual(ws["campaign"]["status"], "running")
        self.assertEqual(ws["campaign"]["target"], t)
        conf = [f for f in ws["findings"] if f["classification"] == "confirmed"]
        self.assertEqual(len(conf), 1)
        self.assertEqual(conf[0]["severity"], "high")
        self.assertEqual(conf[0]["asset"], t)
        self.assertGreaterEqual(conf[0]["confidence"], 0.9)   # "high" -> número
        pend = [a for a in ws["approvals"] if a["status"] == "pending"]
        self.assertEqual(len(pend), 1)
        self.assertEqual(pend[0]["title"], "iniciar teste ativo")

    def test_resolve_approval_unblocks_and_is_idempotent(self):
        isolate(self)
        from fosc.state import RunState
        from fosc.authz import ApprovalStore
        from fosc import wsview
        t = "alvo2.example.com"
        st = RunState(t)
        st.write_meta(target=t, status="running")
        rid = ApprovalStore(st.approvals_path).request("active-hunt", t, "sensitive", "ctx")
        r = wsview.resolve_approval(t, rid, "approved")
        self.assertTrue(r["ok"])
        self.assertEqual(ApprovalStore(st.approvals_path).status(rid), "approved")
        # idempotente: decidir de novo é recusado
        self.assertFalse(wsview.resolve_approval(t, rid, "denied")["ok"])

    def test_halt_writes_emergency_file(self):
        isolate(self)
        from fosc.state import RunState
        from fosc import wsview
        t = "alvo3.example.com"
        st = RunState(t)
        st.write_meta(target=t, status="running")
        r = wsview.halt(t)
        self.assertTrue(r["ok"])
        self.assertTrue(st.halt_path.exists())
