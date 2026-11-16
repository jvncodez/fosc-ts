import unittest

from fosc import config, ratectl, stealth
from fosc.cli import build_parser
from fosc.dispatcher import _argv_for
from fosc.prompts import build_hunt_prompt

ITEM = {"url": "https://acme.test/x", "pattern": "acme.test/x", "params": []}


class StealthTests(unittest.TestCase):
    def setUp(self):
        self._ua = config.STEALTH_UA
        self.addCleanup(lambda: setattr(config, "STEALTH_UA", self._ua))

    def test_headers_are_realistic_and_stable(self):
        hs = stealth.headers("acme")
        self.assertTrue(any(h.startswith("User-Agent: Mozilla") for h in hs))
        self.assertEqual(stealth.headers("acme"), hs)  # deterministic per seed

    def test_merge_does_not_duplicate_operator_header(self):
        merged = stealth.merge_headers(["User-Agent: custom-op"], stealth.headers("acme"))
        uas = [h for h in merged if h.lower().startswith("user-agent:")]
        self.assertEqual(uas, ["User-Agent: custom-op"])  # operator's UA wins, no dup

    def test_ua_override(self):
        config.STEALTH_UA = "MyScanner/1.0"
        self.assertEqual(stealth.user_agent("acme"), "MyScanner/1.0")

    def test_prompt_block_injected_with_waf(self):
        block = stealth.prompt_block("cloudflare")
        p = build_hunt_prompt("https://acme.test", "scope", ITEM, ["XSS"], "", [],
                              None, None, None, block)
        self.assertIn("STEALTH / OPSEC", p)
        self.assertIn("cloudflare", p)
        self.assertIn("BACK OFF", p)

    def test_no_block_when_absent(self):
        p = build_hunt_prompt("https://acme.test", "scope", ITEM, ["XSS"], "", [])
        self.assertNotIn("STEALTH / OPSEC", p)

    def test_rate_cap_holds_under_pressure(self):
        ratectl.REGISTRY.configure("cap.test", start=3, hi=3)
        hr = ratectl.REGISTRY.host("cap.test")
        for _ in range(12):
            hr.observe(True, 40)          # healthy -> tries to climb
        self.assertLessEqual(hr.rate, 3)

    def test_cli_and_dispatcher_thread_stealth(self):
        a = build_parser().parse_args(["-h", "-a", "https://acme.test", "--stealth"])
        self.assertTrue(a.stealth)
        argv = _argv_for({"target": "https://acme.test", "opts": {"stealth": True}})
        self.assertIn("--stealth", argv)
        argv2 = _argv_for({"target": "https://acme.test", "opts": {}})
        self.assertNotIn("--stealth", argv2)


if __name__ == "__main__":
    unittest.main()
