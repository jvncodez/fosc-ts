"""Server-side Cognito User Pool authentication for the local FOSC/TS viewer.

The browser performs no token handling. It is redirected through Cognito managed
login using authorization code + PKCE, then receives only an opaque local
HttpOnly session cookie. This module deliberately supports a public User Pool
app client only: never configure a client secret for this loopback flow.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

try:
    import jwt
    from jwt import PyJWKClient
except ImportError:  # Keep unauthenticated local development usable without PyJWT.
    jwt = None
    PyJWKClient = None

_TRUE_VALUES = {"1", "true", "yes", "on"}
_PREAUTH_COOKIE = "FOSC_PREAUTH"
_SESSION_COOKIE = "FOSC_SESSION"
_PREAUTH_TTL_SECONDS = 600
_SESSION_TTL_SECONDS = 3600
_MAX_RECORDS = 512


@dataclass(frozen=True)
class CognitoSettings:
    """Validated User Pool settings for one loopback viewer instance."""

    domain: str
    user_pool_id: str
    client_id: str
    redirect_uri: str
    issuer: str
    scopes: tuple[str, ...]
    public_url: str
    public_origin: str
    public_path: str
    secure_cookie: bool

    @classmethod
    def enabled(cls) -> bool:
        return os.environ.get("SENTINELA_COGNITO_ENABLED", "").lower() in _TRUE_VALUES

    @classmethod
    def from_environment(cls, port: int) -> "CognitoSettings | None":
        """Load settings or reject an incomplete or unsafe enabled configuration."""
        if not cls.enabled():
            return None
        values = {
            "domain": os.environ.get("SENTINELA_COGNITO_DOMAIN", "").strip().rstrip("/"),
            "user_pool_id": os.environ.get("SENTINELA_COGNITO_USER_POOL_ID", "").strip(),
            "client_id": os.environ.get("SENTINELA_COGNITO_CLIENT_ID", "").strip(),
            "redirect_uri": os.environ.get("SENTINELA_COGNITO_REDIRECT_URI", "").strip(),
            "public_url": os.environ.get("SENTINELA_PUBLIC_URL", f"http://127.0.0.1:{port}").strip().rstrip("/"),
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ValueError("Cognito is enabled but missing: " + ", ".join(missing))
        if jwt is None:
            raise ValueError("Cognito is enabled but PyJWT[crypto] is not installed. Run pip install -r requirements.txt.")

        domain_url = urlparse(values["domain"])
        if domain_url.scheme != "https" or not domain_url.netloc or domain_url.path not in ("", "/") or domain_url.query or domain_url.fragment:
            raise ValueError("SENTINELA_COGNITO_DOMAIN must be an HTTPS Cognito domain without a path.")

        public_url = urlparse(values["public_url"])
        public_is_loopback = (
            public_url.scheme == "http" and public_url.hostname == "127.0.0.1" and
            public_url.port == port and public_url.path in ("", "/")
        )
        public_is_https = public_url.scheme == "https" and bool(public_url.hostname)
        if (not (public_is_loopback or public_is_https) or public_url.username or public_url.password or
                public_url.params or public_url.query or public_url.fragment):
            raise ValueError(
                "SENTINELA_PUBLIC_URL must be the local viewer URL or a trusted HTTPS proxy URL without query/fragment."
            )
        expected_redirect = f"{values['public_url']}/auth/callback"
        if values["redirect_uri"] != expected_redirect:
            raise ValueError(f"SENTINELA_COGNITO_REDIRECT_URI must be exactly {expected_redirect}")

        # A User Pool ID is <region>_<pool suffix>; the region forms the trusted issuer.
        if "_" not in values["user_pool_id"]:
            raise ValueError("SENTINELA_COGNITO_USER_POOL_ID must be a Cognito User Pool ID.")
        region, suffix = values["user_pool_id"].split("_", 1)
        if not region or not suffix:
            raise ValueError("SENTINELA_COGNITO_USER_POOL_ID must be a Cognito User Pool ID.")

        scopes = tuple(dict.fromkeys(os.environ.get("SENTINELA_COGNITO_SCOPES", "openid profile email").split()))
        if "openid" not in scopes:
            raise ValueError("SENTINELA_COGNITO_SCOPES must include openid.")
        return cls(
            domain=values["domain"], user_pool_id=values["user_pool_id"], client_id=values["client_id"],
            redirect_uri=values["redirect_uri"],
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{values['user_pool_id']}", scopes=scopes,
            public_url=values["public_url"],
            public_origin=f"{public_url.scheme}://{public_url.netloc}",
            public_path=public_url.path.rstrip("/"),
            secure_cookie=public_url.scheme == "https",
        )


def _log_login_failure(reason: str) -> None:
    """Print why a login callback was rejected. Never includes tokens, codes, or secrets."""
    print(f"[fosc] login Cognito falhou: {reason}", file=sys.stderr, flush=True)


def _describe_cause(error: BaseException) -> str:
    cause = error.__cause__
    return type(cause).__name__ if cause else "sem causa adicional"


def _safe_error_code(body: str) -> str:
    try:
        return str(json.loads(body).get("error", "erro desconhecido"))
    except (ValueError, AttributeError):
        return "resposta não JSON"


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cookie_value(request_headers: Any, name: str) -> str | None:
    try:
        cookies = SimpleCookie(request_headers.get("Cookie", ""))
        return cookies.get(name).value if cookies.get(name) else None
    except (KeyError, ValueError):
        return None


def cookie_header(name: str, value: str, *, path: str, max_age: int, secure: bool = False) -> str:
    """Create a host-only cookie with safe browser attributes."""
    cookies = SimpleCookie()
    cookies[name] = value
    item = cookies[name]
    item["path"] = path
    item["max-age"] = str(max_age)
    item["httponly"] = True
    item["samesite"] = "Lax"
    if secure:
        item["secure"] = True
    return item.OutputString()


class CognitoAuth:
    """PKCE transaction and opaque-session manager for a single viewer process."""

    def __init__(self, settings: CognitoSettings):
        self.settings = settings
        self._preauth: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._jwks = PyJWKClient(f"{settings.issuer}/.well-known/jwks.json", cache_keys=True)

    def _purge_expired(self) -> None:
        now = time.time()
        for records in (self._preauth, self._sessions):
            for key in [key for key, value in records.items() if value["expires_at"] <= now]:
                records.pop(key, None)
            if len(records) > _MAX_RECORDS:
                for key in sorted(records, key=lambda record: records[record]["expires_at"])[:-_MAX_RECORDS]:
                    records.pop(key, None)

    def begin(self) -> tuple[str, str]:
        """Create a single-use PKCE transaction and its short-lived cookie."""
        transaction_id = secrets.token_urlsafe(32)
        verifier = _base64url(secrets.token_bytes(64))
        state = _base64url(secrets.token_bytes(32))
        nonce = _base64url(secrets.token_bytes(32))
        challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
        with self._lock:
            self._purge_expired()
            self._preauth[transaction_id] = {
                "state": state, "nonce": nonce, "verifier": verifier,
                "expires_at": time.time() + _PREAUTH_TTL_SECONDS,
            }
        params = urlencode({
            "response_type": "code", "client_id": self.settings.client_id,
            "redirect_uri": self.settings.redirect_uri, "scope": " ".join(self.settings.scopes),
            "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
            # Localize the Cognito Managed Login page (sign-in/MFA/password screens).
            # Cognito's language code for Brazilian Portuguese is "pt-BR" (not "pt").
            "lang": os.environ.get("SENTINELA_COGNITO_LANG", "pt-BR"),
        })
        return f"{self.settings.domain}/oauth2/authorize?{params}", cookie_header(
            _PREAUTH_COOKIE, transaction_id,
            path=f"{self.settings.public_path}/auth" or "/auth",
            max_age=_PREAUTH_TTL_SECONDS,
            secure=self.settings.secure_cookie,
        )

    def complete(self, request_headers: Any, query: dict[str, str]) -> tuple[dict[str, str] | None, list[str]]:
        """Validate callback state, exchange the code, and issue a local session."""
        clear_preauth = cookie_header(
            _PREAUTH_COOKIE, "", path=f"{self.settings.public_path}/auth" or "/auth",
            max_age=0, secure=self.settings.secure_cookie,
        )
        transaction_id = _cookie_value(request_headers, _PREAUTH_COOKIE)
        returned_state = query.get("state", "")
        if not transaction_id:
            _log_login_failure("cookie FOSC_PREAUTH ausente: o navegador não enviou o cookie de login neste callback")
            return None, [clear_preauth]
        if not returned_state:
            _log_login_failure("parâmetro state ausente no callback")
            return None, [clear_preauth]
        with self._lock:
            self._purge_expired()
            transaction = self._preauth.get(transaction_id)
            if not transaction:
                _log_login_failure("transação de login não encontrada ou expirada (viewer reiniciado ou login antigo)")
                return None, [clear_preauth]
            if not secrets.compare_digest(transaction["state"], returned_state):
                _log_login_failure("state retornado não confere com o state da transação")
                return None, [clear_preauth]
            self._preauth.pop(transaction_id, None)  # prevents callback replay before token exchange
        try:
            claims = self._exchange_and_verify(query.get("code", ""), transaction["verifier"], transaction["nonce"])
        except ValueError as error:
            _log_login_failure(f"{error}: {_describe_cause(error)}")
            return None, [clear_preauth]

        session_id = secrets.token_urlsafe(32)
        identity = {key: str(claims[key]) for key in ("sub", "email", "cognito:username", "name") if claims.get(key) is not None}
        with self._lock:
            self._purge_expired()
            self._sessions[session_id] = {"identity": identity, "expires_at": time.time() + _SESSION_TTL_SECONDS}
        return identity, [
            clear_preauth,
            cookie_header(
                _SESSION_COOKIE, session_id, path=f"{self.settings.public_path}/" or "/",
                max_age=_SESSION_TTL_SECONDS, secure=self.settings.secure_cookie,
            ),
        ]

    def _exchange_and_verify(self, code: str, verifier: str, nonce: str) -> dict[str, Any]:
        if not code or len(code) > 4096:
            raise ValueError("invalid code")
        data = urlencode({
            "grant_type": "authorization_code", "client_id": self.settings.client_id, "code": code,
            "redirect_uri": self.settings.redirect_uri, "code_verifier": verifier,
        }).encode("ascii")
        request = Request(f"{self.settings.domain}/oauth2/token", data=data, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        try:
            with urlopen(request, timeout=10) as response:
                token_response = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            body = error.read().decode("utf-8", "replace")[:300]
            raise ValueError(f"token exchange failed (HTTP {error.code}: {_safe_error_code(body)})") from error
        except (URLError, OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("token exchange failed") from error
        id_token = token_response.get("id_token")
        if not isinstance(id_token, str):
            raise ValueError("missing id token")
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(id_token, signing_key.key, algorithms=["RS256"], audience=self.settings.client_id,
                                issuer=self.settings.issuer, options={"require": ["exp", "iat", "sub", "nonce"]})
        except Exception as error:  # PyJWT's exception hierarchy varies across supported releases.
            raise ValueError(f"invalid id token ({type(error).__name__}: {error})") from error
        if claims.get("token_use") != "id" or not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise ValueError("invalid token claims")
        return claims

    def session(self, request_headers: Any) -> dict[str, str] | None:
        session_id = _cookie_value(request_headers, _SESSION_COOKIE)
        if not session_id:
            return None
        with self._lock:
            self._purge_expired()
            entry = self._sessions.get(session_id)
            return dict(entry["identity"]) if entry else None

    def logout(self, request_headers: Any) -> tuple[str, list[str]]:
        session_id = _cookie_value(request_headers, _SESSION_COOKIE)
        if session_id:
            with self._lock:
                self._sessions.pop(session_id, None)
        params = urlencode({"client_id": self.settings.client_id, "logout_uri": f"{self.settings.public_url}/"})
        cleared = cookie_header(
            _SESSION_COOKIE, "", path=f"{self.settings.public_path}/" or "/",
            max_age=0, secure=self.settings.secure_cookie,
        )
        return f"{self.settings.domain}/logout?{params}", [cleared]
