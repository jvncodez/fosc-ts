import unittest

from fosc import config, knowledge, semantic
from tests.helpers import isolate


class PayloadMemoryTests(unittest.TestCase):
    def setUp(self):
        isolate(self)
        config.EMBED_CACHE = config.KNOWLEDGE_ROOT / "embeddings.jsonl"
        semantic._backend = ("none", None)  # lexical path, deterministic
        semantic._cache = None
        semantic.EMBED_FN = None
        self.addCleanup(self._reset)
        seen = {"pattern": "/fetch", "params": ["url"], "tech": ["nginx"]}
        knowledge.record_techniques("acme", seen, "cloudflare", [
            {"payload": "http://127.0.0.1@evil/", "vuln_class": "SSRF",
             "status": "worked", "note": "creds-in-host bypass beat CF"},
            {"payload": "http://169.254.169.254/", "vuln_class": "SSRF",
             "status": "blocked", "note": "CF blocked raw metadata IP"},
        ], ["nginx"])

    def _reset(self):
        semantic._backend = None
        semantic._cache = None
        semantic.EMBED_FN = None

    def test_target_waf_remembered(self):
        self.assertEqual(knowledge.target_waf("acme"), "cloudflare")
        self.assertIsNone(knowledge.target_waf("unknown-target"))

    def test_worked_payload_is_recalled_for_similar_endpoint(self):
        new_item = {"pattern": "/proxy/image", "params": ["src"], "tech": ["nginx"]}
        hints = knowledge.payload_hints("acme", new_item, ["SSRF", "open redirect"])
        self.assertIn("127.0.0.1@evil", hints)      # the bypass that landed
        self.assertIn("WORKED", hints)
        self.assertIn("Blocked before", hints)      # dead end surfaced separately

    def test_unrelated_endpoint_gets_no_hints(self):
        other = {"pattern": "/blog/post", "params": ["slug"], "tech": ["wordpress"]}
        hints = knowledge.payload_hints("acme", other, ["XSS"])
        self.assertEqual(hints, "")

    def test_dedup_identical_payloads(self):
        seen = {"pattern": "/fetch", "params": ["url"], "tech": ["nginx"]}
        for _ in range(3):
            knowledge.record_techniques("acme", seen, "cloudflare", [
                {"payload": "http://127.0.0.1@evil/", "vuln_class": "SSRF",
                 "status": "worked", "note": "dup"}], ["nginx"])
        new_item = {"pattern": "/proxy/image", "params": ["src"], "tech": ["nginx"]}
        hints = knowledge.payload_hints("acme", new_item, ["SSRF"])
        self.assertEqual(hints.count("127.0.0.1@evil"), 1)  # collapsed to one line


if __name__ == "__main__":
    unittest.main()
