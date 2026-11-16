"""Semantic memory backend — turns FOSC's cross-hunt recall from lexical
token-overlap into meaning-based similarity.

Why this exists: a lesson about "SSRF via image parameter" must surface when the
agent is about to test "fetch avatar from a URL", even though they share no
tokens. Lexical matching (knowledge.relevant's legacy path) misses that; an
embedding backend does not.

Design contract — NEVER regress:
  - Embeddings are OPTIONAL. `available()` is False when no backend is reachable
    (no boto3/creds on Bedrock, no sentence-transformers locally, or disabled by
    config). When False, every caller keeps its existing lexical behaviour.
  - Backends are tried in order and the choice is cached: Bedrock Titan v2 first
    (the production path), then a local sentence-transformers model if installed.
  - Vectors are cached on disk keyed by a hash of the text, so a lesson is
    embedded once ever, not once per hunt.

Vectors are L2-normalised, so cosine similarity is a plain dot product.
"""
import hashlib
import json
import math
import os
import threading

from . import config

_lock = threading.Lock()
_cache: dict[str, list[float]] | None = None   # text-hash -> vector
_backend: tuple[str, object] | None = None     # ("bedrock"|"local", client/model) or ("none", None)
# Tests (and advanced callers) can inject a deterministic embedder here.
EMBED_FN = None  # Optional[Callable[[list[str]], list[list[float]]]]


# -- backend detection -------------------------------------------------

def _detect_backend():
    """Resolve the embedding backend once. Returns (name, handle)."""
    if not config.EMBED_ENABLED or config.EMBED_PROVIDER == "off":
        return ("none", None)
    want = config.EMBED_PROVIDER  # auto | bedrock | local
    if want in ("auto", "bedrock"):
        cli = _try_bedrock()
        if cli is not None:
            return ("bedrock", cli)
        if want == "bedrock":
            return ("none", None)
    if want in ("auto", "local"):
        mdl = _try_local()
        if mdl is not None:
            return ("local", mdl)
    return ("none", None)


def _try_bedrock():
    try:
        import boto3  # noqa: F401
        sess = boto3.session.Session(region_name=config.AWS_REGION)
        if sess.get_credentials() is None:
            return None
        return sess.client("bedrock-runtime", region_name=config.AWS_REGION)
    except Exception:
        return None


def _try_local():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer(config.EMBED_LOCAL_MODEL)
    except Exception:
        return None


def backend_name() -> str:
    global _backend
    if _backend is None:
        with _lock:
            if _backend is None:
                _backend = _detect_backend()
    return _backend[0]


def available() -> bool:
    return EMBED_FN is not None or backend_name() != "none"


# -- embedding ---------------------------------------------------------

def _raw_embed(texts: list[str]) -> list[list[float]] | None:
    """Embed a batch with the active backend (no cache). None on failure."""
    if EMBED_FN is not None:
        try:
            return [_normalize(v) for v in EMBED_FN(texts)]
        except Exception:
            return None
    name = backend_name()
    if name == "bedrock":
        return _bedrock_embed(texts)
    if name == "local":
        return _local_embed(texts)
    return None


def _bedrock_embed(texts: list[str]) -> list[list[float]] | None:
    client = _backend[1]
    out = []
    for t in texts:
        try:
            body = json.dumps({"inputText": t[:8000], "dimensions": config.EMBED_DIM,
                               "normalize": True})
            resp = client.invoke_model(modelId=config.EMBED_BEDROCK_MODEL, body=body)
            vec = json.loads(resp["body"].read())["embedding"]
            out.append(_normalize(vec))
        except Exception:
            return None   # fail the whole batch -> caller falls back to lexical
    return out


def _local_embed(texts: list[str]) -> list[list[float]] | None:
    try:
        model = _backend[1]
        vecs = model.encode([t[:8000] for t in texts], normalize_embeddings=True)
        return [list(map(float, v)) for v in vecs]
    except Exception:
        return None


def _normalize(vec) -> list[float]:
    v = [float(x) for x in vec]
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


# -- disk cache --------------------------------------------------------

def _key(text: str) -> str:
    return hashlib.sha1((text or "").strip().lower().encode("utf-8", "replace")).hexdigest()


def _load_cache() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    _cache = {}
    p = config.EMBED_CACHE
    try:
        if p.exists():
            for line in p.read_text().splitlines():
                try:
                    rec = json.loads(line)
                    _cache[rec["k"]] = rec["v"]
                except Exception:
                    continue
    except OSError:
        pass
    return _cache


def _persist(new: dict):
    if not new:
        return
    try:
        config.KNOWLEDGE_ROOT.mkdir(parents=True, exist_ok=True)
        with config.EMBED_CACHE.open("a") as f:
            for k, v in new.items():
                f.write(json.dumps({"k": k, "v": v}) + "\n")
    except OSError:
        pass


def embed(texts: list[str]) -> list[list[float]] | None:
    """Return a cached/freshly-computed vector per text, or None if no backend.
    Only cache-missing texts hit the backend; new vectors are persisted."""
    if not texts or not available():
        return None
    cache = _load_cache()
    keys = [_key(t) for t in texts]
    missing_idx = [i for i, k in enumerate(keys) if k not in cache]
    if missing_idx:
        fresh = _raw_embed([texts[i] for i in missing_idx])
        if fresh is None:
            return None
        new = {}
        with _lock:
            for j, i in enumerate(missing_idx):
                cache[keys[i]] = fresh[j]
                new[keys[i]] = fresh[j]
        _persist(new)
    return [cache[k] for k in keys]


def embed_one(text: str) -> list[float] | None:
    r = embed([text])
    return r[0] if r else None


def cosine(a: list[float], b: list[float]) -> float:
    """Dot product; inputs are unit vectors so this is cosine similarity."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def similarities(query: str, docs: list[str]) -> list[float] | None:
    """Cosine of `query` against each doc, or None when embeddings are off.
    Length matches `docs`; a doc that failed to embed scores 0.0."""
    if not available() or not docs:
        return None
    qv = embed_one(query)
    if qv is None:
        return None
    dvs = embed(docs)
    if dvs is None:
        return None
    return [cosine(qv, dv) for dv in dvs]
