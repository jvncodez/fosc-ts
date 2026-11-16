import unittest

from fosc import chain, config
from fosc.state import RunState
from tests.helpers import isolate


class _Out:
    """Minimal Out stand-in — the chain pass only needs these."""
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def activity(self, *a, **k): pass
    def confirmed(self, *a, **k): pass


class ChainPassTests(unittest.TestCase):
    def setUp(self):
        isolate(self)
        saved = (config.COUNCIL_ENABLED, config.CHAIN_ENABLED, config.CHAIN_MIN_FINDINGS,
                 chain.models.run, chain.verify_finding)

        def restore():
            (config.COUNCIL_ENABLED, config.CHAIN_ENABLED, config.CHAIN_MIN_FINDINGS,
             chain.models.run, chain.verify_finding) = saved
        self.addCleanup(restore)
        config.COUNCIL_ENABLED = False   # exercise verify gate in isolation
        config.CHAIN_ENABLED = True
        self.state = RunState("https://acme.test", fresh=True)
        self.state.add_confirmed({"key": "idor|/a", "url": "https://acme.test/api/users/{n}",
                                  "vuln_class": "IDOR", "severity": "medium",
                                  "summary": "read other users", "repro_curl": "curl ...",
                                  "evidence_marker": "other@user"})
        self.state.add_confirmed({"key": "redir|/b", "url": "https://acme.test/go",
                                  "vuln_class": "open redirect", "severity": "low",
                                  "summary": "open redirect on ?next="})
        self._patch_models()

    def _patch_models(self):
        ids = [f["id"] for f in self.state.confirmed()]
        self._chain_out = {
            "chained": True, "chain_class": "IDOR -> account takeover",
            "severity": "critical", "cvss": 9.1, "confidence": "high",
            "title": "ATO via IDOR + open redirect", "summary": "full ATO",
            "impact": "takeover", "steps": ["s1", "s2"],
            "repro_curl": "curl ...", "evidence_marker": "victim-session",
            "components": ids,
        }
        chain.models.run = lambda *a, **k: {"status": "ok", "cost": 0.1, "output": self._chain_out}
        chain.verify_finding = lambda *a, **k: {"verdict": "confirmed", "reason": "holds",
                                                "severity": "critical", "cvss": 9.1,
                                                "confidence": "high", "cost": 0.05}

    def test_chain_promoted_as_new_critical(self):
        before = len(self.state.confirmed())
        res = chain.run_chain_pass(self.state, _Out(), "https://acme.test", "scope")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("is_chain"))
        self.assertEqual(res.get("severity"), "critical")
        self.assertEqual(len(self.state.confirmed()), before + 1)

    def test_idempotent_same_set(self):
        chain.run_chain_pass(self.state, _Out(), "https://acme.test", "scope")
        # same primary set -> second call is a no-op, never re-chains the chain
        res2 = chain.run_chain_pass(self.state, _Out(), "https://acme.test", "scope")
        self.assertIsNone(res2)
        chains = [f for f in self.state.confirmed() if f.get("is_chain")]
        self.assertEqual(len(chains), 1)

    def test_no_chain_when_model_declines(self):
        chain.models.run = lambda *a, **k: {"status": "ok", "cost": 0.1,
                                            "output": {"chained": False, "summary": "no chain"}}
        res = chain.run_chain_pass(self.state, _Out(), "https://acme.test", "scope")
        self.assertIsNone(res)

    def test_skips_below_minimum(self):
        config.CHAIN_MIN_FINDINGS = 5
        res = chain.run_chain_pass(self.state, _Out(), "https://acme.test", "scope")
        self.assertIsNone(res)
        config.CHAIN_MIN_FINDINGS = 2


if __name__ == "__main__":
    unittest.main()
