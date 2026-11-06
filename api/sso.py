"""
Sign-in with Microsoft Entra for the hub (Mary, 2026-11-06: "entra"; the hub goes first, the other apps reuse this).

Every page of the hub comes through here (vercel.json). Until ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET are
set in Vercel it serves the hub as before, open to anyone with the link. Once they're set, anyone not signed in goes to the
Microsoft sign-in for Quilt's directory (only accounts in that tenant get in) and comes back to /auth/callback. A signed
cookie keeps them in for 7 days.

OpenID Connect, authorization code flow with PKCE, confidential client. The ID token comes straight from Microsoft's token
endpoint over TLS with our client secret, so its issuer is checked by TLS (OpenID Connect Core 3.1.3.7) and the claims are
checked here: issuer and tenant, audience, expiry, nonce. Standard library only.

To register it in Entra (IT): App registrations > New registration, single tenant, Web redirect URI
  https://quilt-salesops-hub.vercel.app/auth/callback
then Certificates & secrets > New client secret. Give us the Directory (tenant) ID, Application (client) ID and the secret
value; they go in Vercel > Settings > Environment Variables, never in the repo.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlsplit

TENANT = os.environ.get("ENTRA_TENANT_ID", "").strip()
CLIENT = os.environ.get("ENTRA_CLIENT_ID", "").strip()
SECRET = os.environ.get("ENTRA_CLIENT_SECRET", "").strip()
BASE = os.environ.get("HUB_BASE_URL", "https://quilt-salesops-hub.vercel.app").rstrip("/")
ON = bool(TENANT and CLIENT and SECRET)
DAYS = 7
COOKIE, FLOW = "hub_sso", "hub_sso_flow"
PAGE = Path(__file__).with_name("_hub.html")
AUTHORITY = os.environ.get("ENTRA_AUTHORITY_FOR_TESTS") or f"https://login.microsoftonline.com/{TENANT}"     # tests point this at a stand-in


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def key() -> bytes:
    return hashlib.sha256(b"hub-sso|" + SECRET.encode()).digest()       # a new client secret signs everyone out


def seal(obj: dict) -> str:
    body = b64(json.dumps(obj, separators=(",", ":")).encode())
    return body + "." + b64(hmac.new(key(), body.encode(), hashlib.sha256).digest())


def unseal(token: str) -> dict | None:
    try:
        body, sig = token.split(".")
        if not hmac.compare_digest(b64(hmac.new(key(), body.encode(), hashlib.sha256).digest()), sig):
            return None
        obj = json.loads(unb64(body))
        return obj if obj.get("exp", 0) > time.time() else None
    except (ValueError, json.JSONDecodeError):
        return None


def safe_next(path: str) -> str:
    return path if path.startswith("/") and not path.startswith("//") else "/"


class handler(BaseHTTPRequestHandler):
    def cookie(self, name: str) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def send(self, code: int, body: bytes = b"", ctype: str = "text/html; charset=utf-8", headers: list | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in headers or []:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def go(self, url: str, cookies: list | None = None):
        self.send(302, b"", "text/plain", [("Location", url)] + [("Set-Cookie", c) for c in cookies or []])

    def page(self, user: dict | None):
        html = PAGE.read_text(encoding="utf-8")
        if user:                # the request form knows who's asking; a sign-out link joins the side pane
            who = json.dumps({"name": user.get("name", ""), "email": user.get("email", "")}).replace("<", "\\u003c")
            html = html.replace("<head>", f"<head><script>window.HUB_USER={who};</script>", 1)
        self.send(200, html.encode("utf-8"))

    def fail(self, why: str):
        self.send(400, (f"<!doctype html><meta charset=utf-8><title>Sign-in problem</title><body style=\"font:15px system-ui;margin:60px auto;max-width:520px;color:#141A38\">"
                        f"<h2>We couldn't sign you in</h2><p>{why}</p><p><a href=\"/auth/login\">Try again</a></p>").encode())

    def do_GET(self):
        url = urlsplit(self.path)
        path, q = url.path, {k: v[0] for k, v in parse_qs(url.query).items()}
        if not ON:                                   # not set up yet: the hub as it's always been
            return self.page(None)
        user = unseal(self.cookie(COOKIE))
        secure = "; Secure" if BASE.startswith("https") else ""
        if path == "/auth/logout":
            return self.go(f"{AUTHORITY}/oauth2/v2.0/logout?" + urlencode({"post_logout_redirect_uri": BASE + "/"}),
                           [f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}"])
        if path == "/auth/callback":
            return self.callback(q, secure)
        if user:
            return self.page(user)
        # not signed in: off to Microsoft, remembering where they were going
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        flow = seal({"s": state, "n": nonce, "v": verifier, "next": safe_next(q.get("next") or path if path != "/auth/login" else "/"), "exp": time.time() + 600})
        challenge = b64(hashlib.sha256(verifier.encode()).digest())
        auth = f"{AUTHORITY}/oauth2/v2.0/authorize?" + urlencode({
            "client_id": CLIENT, "response_type": "code", "redirect_uri": BASE + "/auth/callback", "response_mode": "query",
            "scope": "openid profile email", "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
        return self.go(auth, [f"{FLOW}={flow}; Path=/auth; Max-Age=600; HttpOnly; SameSite=Lax{secure}"])

    def callback(self, q: dict, secure: str):
        flow = unseal(self.cookie(FLOW))
        if q.get("error"):
            return self.fail("Microsoft said: " + (q.get("error_description") or q["error"]).split("\r")[0][:300].replace("<", "&lt;"))
        if not flow or not q.get("code") or not hmac.compare_digest(q.get("state", ""), flow["s"]):
            return self.fail("The sign-in took too long or was started in another window.")
        data = urlencode({"client_id": CLIENT, "client_secret": SECRET, "grant_type": "authorization_code", "code": q["code"],
                          "redirect_uri": BASE + "/auth/callback", "code_verifier": flow["v"], "scope": "openid profile email"}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{AUTHORITY}/oauth2/v2.0/token", data=data,
                                                               headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=10) as r:
                tok = json.load(r)
        except (urllib.error.URLError, ValueError) as exc:
            return self.fail("Microsoft didn't accept the sign-in. " + str(getattr(exc, "reason", "") or "")[:200].replace("<", "&lt;"))
        try:
            claims = json.loads(unb64(tok["id_token"].split(".")[1]))
        except (KeyError, IndexError, ValueError):
            return self.fail("Microsoft's answer was missing who you are.")
        now = time.time()
        if (claims.get("iss") != f"https://login.microsoftonline.com/{TENANT}/v2.0" or claims.get("tid") != TENANT or claims.get("aud") != CLIENT
                or claims.get("exp", 0) < now or not hmac.compare_digest(str(claims.get("nonce", "")), flow["n"])):
            return self.fail("That sign-in isn't for Quilt's directory.")
        user = {"name": claims.get("name", ""), "email": (claims.get("email") or claims.get("preferred_username") or "").lower(),
                "oid": claims.get("oid", ""), "exp": now + DAYS * 86400}
        return self.go(safe_next(flow.get("next", "/")),
                       [f"{COOKIE}={seal(user)}; Path=/; Max-Age={DAYS * 86400}; HttpOnly; SameSite=Lax{secure}",
                        f"{FLOW}=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax{secure}"])
