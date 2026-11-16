import unittest

from fosc import config, knowledge, semantic
from tests.helpers import isolate


def _stub_embedder(texts):
    """Deterministic keyword presence vectors — a stand-in for a real embedding
    model so the rerank logic is testable offline, without boto3 or a GPU."""
    vocab = ["ssrf", "request", "forgery", "image", "avatar", "url", "fetch",
             "internal", "metadata", "xss", "reflected", "pagination", "cursor",
             "redirect", "profile", "loader"]
    return [[1.0 if w in t.lower() else 0.0 for w in vocab] for t in texts]


class SemanticMemoryTests(unittest.TestCase):
    def setUp(self):
        tmp = isolate(self)
        config.EMBED_CACHE = config.KNOWLEDGE_ROOT / "embeddings.jsonl"
        config.EMBED_BLEND = 0.6
        # reset module caches between tests
        semantic._cache = None
        semantic._backend = None
        semantic.EMBED_FN = None
        self.addCleanup(self._reset)
        # seed: an SSRF lesson that shares NO tokens with the avatar-url endpoint
        knowledge.add_lesson("win", "server side request forgery reaching internal metadata via a remote image loader",
                             "acme", {"pattern": "/img", "params": ["src"]}, "SSRF", ["nginx"])
        knowledge.add_lesson("note", "pagination uses cursor tokens, nothing interesting",
                             "acme", {"pattern": "/list", "params": ["cursor"]}, "none", ["nginx"])
        knowledge.add_lesson("fp", "reflected xss false positive, output was encoded",
                             "acme", {"pattern": "/search", "params": ["q"]}, "XSS", ["react"])

    def _reset(self):
        semantic._cache = None
        semantic._backend = None
        semantic.EMBED_FN = None

    def test_fallback_without_backend_matches_legacy(self):
        """No embedding backend -> recall still works (lexical path), never empty."""
        semantic._backend = ("none", None)
        self.assertFalse(semantic.available())
        item = {"pattern": "/profile/avatar", "params": ["url"], "tech": ["nginx"]}
        res = knowledge.relevant(item, ["SSRF", "open redirect"], k=3)
        self.assertTrue(res)  # degrades gracefully, returns lessons

    def test_semantic_rerank_surfaces_related_lesson(self):
        """With embeddings on, the SSRF lesson ranks first for an avatar-url
        endpoint even though they share no lexical tokens."""
        semantic.EMBED_FN = _stub_embedder
        self.assertTrue(semantic.available())
        item = {"pattern": "/profile/avatar", "params": ["url"], "tech": ["nginx"]}
        res = knowledge.relevant(item, ["SSRF", "open redirect"], k=3)
        self.assertTrue(res)
        self.assertEqual(res[0].get("vuln_class"), "SSRF")

    def test_blend_zero_is_legacy_order(self):
        """EMBED_BLEND=0 must reproduce the pure lexical ordering even with a
        backend present (semantic contributes nothing)."""
        semantic.EMBED_FN = _stub_embedder
        config.EMBED_BLEND = 0.0
        item = {"pattern": "/search", "params": ["q"], "tech": ["react"]}
        res = knowledge.relevant(item, ["XSS"], k=3)
        # the react/XSS lesson shares tech+class+tokens -> wins lexically
        self.assertEqual(res[0].get("vuln_class"), "XSS")

    def test_embedding_cache_persists(self):
        semantic.EMBED_FN = _stub_embedder
        semantic.embed(["hello world", "another doc"])
        self.assertTrue(config.EMBED_CACHE.exists())
        self.assertEqual(len(semantic._load_cache()), 2)
        # second call hits cache, not the embedder
        semantic.EMBED_FN = lambda t: (_ for _ in ()).throw(AssertionError("should be cached"))
        v = semantic.embed(["hello world"])
        self.assertIsNotNone(v)


if __name__ == "__main__":
    unittest.main()
