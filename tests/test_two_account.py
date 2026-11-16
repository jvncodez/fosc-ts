import unittest

from fosc.cli import build_parser
from fosc.dispatcher import _argv_for
from fosc.prompts import build_hunt_prompt

ITEM = {"url": "https://acme.test/api/orders/5", "pattern": "acme.test/api/orders/{n}",
        "params": ["id"]}


class TwoAccountTests(unittest.TestCase):
    def test_cli_parses_repeatable_accounts(self):
        a = build_parser().parse_args(
            ["-h", "-a", "https://acme.test",
             "--account-a", "Cookie: s=AAA", "--account-a", "X-Role: user",
             "--account-b", "Cookie: s=BBB"])
        self.assertEqual(a.account_a, ["Cookie: s=AAA", "X-Role: user"])
        self.assertEqual(a.account_b, ["Cookie: s=BBB"])

    def test_prompt_has_cross_account_block(self):
        prompt = build_hunt_prompt("https://acme.test", "scope", ITEM, ["IDOR"], "", [],
                                   None, ["Cookie: s=AAA"], ["Cookie: s=BBB"])
        self.assertIn("TWO AUTHENTICATED IDENTITIES", prompt)
        self.assertIn("s=AAA", prompt)
        self.assertIn("s=BBB", prompt)
        self.assertIn("CROSS-ACCOUNT evidence", prompt)

    def test_single_account_has_no_cross_block(self):
        prompt = build_hunt_prompt("https://acme.test", "scope", ITEM, ["IDOR"], "", [],
                                   None, ["Cookie: s=AAA"], None)
        self.assertNotIn("TWO AUTHENTICATED IDENTITIES", prompt)

    def test_account_a_as_primary_shows_auth_block(self):
        # run_hunt sets extra_headers = account_a when no explicit auth is given,
        # so general authenticated testing uses A while the cross test runs on top.
        prompt = build_hunt_prompt("https://acme.test", "scope", ITEM, ["IDOR"], "", [],
                                   ["Cookie: s=AAA"], ["Cookie: s=AAA"], ["Cookie: s=BBB"])
        self.assertIn("send these header(s) on EVERY request", prompt)
        self.assertIn("TWO AUTHENTICATED IDENTITIES", prompt)

    def test_dispatcher_threads_accounts_from_opts(self):
        job = {"target": "https://acme.test",
               "opts": {"workers": 6, "account_a": ["Cookie: s=AAA"],
                        "account_b": ["Cookie: s=BBB"]}}
        argv = _argv_for(job)
        self.assertIn("--account-a", argv)
        self.assertIn("Cookie: s=AAA", argv)
        self.assertIn("--account-b", argv)
        self.assertIn("Cookie: s=BBB", argv)


if __name__ == "__main__":
    unittest.main()
