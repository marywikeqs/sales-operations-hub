"""
The hub's signed-in areas: the Team Portal (/portal) and the Commission Portal
(/commissions). Each has its own password, so signing in to one doesn't open
the other.

Vercel sends /<portal>, /<portal>/login and /<portal>/logout here (vercel.json).
Passwords are environment variables in the Vercel project (PORTAL_PASSWORD,
COMMISSION_PASSWORD); a signed sign-in cookie keeps people in for 30 days.
Nothing is stored, so it works the same on every copy of the function, and
changing a password signs everyone out of that portal. A portal with no
password set stays closed.

Standard library only. To add an app, add it to that portal's apps below.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

DAYS = 30

PORTALS = {
    "portal": {
        "name": "Team Portal", "env": "PORTAL_PASSWORD", "section": "Team apps",
        "lede": "The Sales Ops team's own tools. Each app still has its own sign-in.",
        "apps": [
            {"title": "Weekly Progress", "tag": "Every Friday", "icon": "progress",
             "desc": "Send your weekly update: projects, other work and Claude usage. Leadership digest and projects over time.",
             "url": "https://internal-team-weeklyprogress.vercel.app/"},
            {"title": "Team Time Off", "tag": "Personal link", "icon": "calendar",
             "desc": "Request PTO and pick holiday days. Opens with your personal link.",
             "url": "https://internal-team-off.vercel.app/"},
        ]},
    "commissions": {
        "name": "Commission Portal", "env": "COMMISSION_PASSWORD", "section": "Commission apps",
        "lede": "Compensation planning: plans, quotas and allocations. Each app still has its own sign-in.",
        "apps": [
            {"title": "Commission Plan Builder", "tag": "Sales Ops only", "icon": "plan",
             "desc": "Build and export written comp plans, quotas and allocations.",
             "url": "https://commission-planner.vercel.app/"},
        ]},
}


def password(slug: str) -> str:
    return os.environ.get(PORTALS[slug]["env"], "")


ICONS = {
    "progress": '<path d="M4 19V5M4 19h16"/><path d="M8 15l3.5-4 3 2.5L20 7"/>',
    "calendar": '<rect x="3.5" y="5" width="17" height="15" rx="2.5"/><path d="M3.5 10h17M8 3v4M16 3v4"/><path d="M8 14h3"/>',
    "plan": ('<path d="M7 3.5h7l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20V4a.5.5 0 0 1 .5-.5z"/><path d="M14 3.5V8h4"/>'
             '<path d="M12 11v6M10.2 12.6c0-.7.8-1.2 1.8-1.2s1.8.5 1.8 1.2-.8 1-1.8 1.2-1.8.5-1.8 1.2.8 1.2 1.8 1.2 1.8-.5 1.8-1.2"/>'),
    "lock": '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/>',
    "back": '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    "out": '<path d="M14 4h4.5a1.5 1.5 0 0 1 1.5 1.5v13a1.5 1.5 0 0 1-1.5 1.5H14"/><path d="M10 16l-4-4 4-4M6 12h10"/>',
}
MARK = ('<svg viewBox="4 0 32 48"><path d="M20 2 34 16 20 30 6 16z" fill="#84B0D5"/>'
        '<path d="M20 18 34 32 20 46 6 32z" fill="#8F568F"/><path d="M20 18 26 24 20 30 14 24z" fill="#18214E"/></svg>')
FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='4 0 32 48'%3E%3Cpath d='M20 2 34 16 20 30 6 16z' "
           "fill='%2384B0D5'/%3E%3Cpath d='M20 18 34 32 20 46 6 32z' fill='%238F568F'/%3E%3Cpath d='M20 18 26 24 20 30 14 24z' fill='%2318214E'/%3E%3C/svg%3E")


def svg(name: str, cls: str = "ti") -> str:
    return (f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


# ---------------- sign-in ----------------

def _key(slug: str) -> bytes:
    return hashlib.sha256(f"hub-portal-session|{slug}|".encode() + password(slug).encode("utf-8")).digest()


def make_session(slug: str) -> str:
    exp = str(int(time.time()) + DAYS * 86400)
    return exp + "." + hmac.new(_key(slug), exp.encode(), hashlib.sha256).hexdigest()


def session_ok(slug: str, value: str) -> bool:
    exp, _, sig = (value or "").partition(".")
    if not password(slug) or not exp.isdigit() or int(exp) < time.time():
        return False
    return hmac.compare_digest(sig, hmac.new(_key(slug), exp.encode(), hashlib.sha256).hexdigest())


# ---------------- pages (the hub's look: Quilt navy, Geist, white cards) ----------------

HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>__TITLE__</title><link rel="icon" href=\"""" + FAVICON + """\">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400..700&family=Geist+Mono:wght@500;600&display=swap">
<style>
:root{--q-navy:#18214E;--q-plum:#8F568F;--q-sky:#84B0D5;--bg:#F4F6FA;--surface:#fff;--surface-2:#F9FAFB;--ink:#141A38;--muted:#6A7385;
--faint:#98A0AE;--line:#E7EAF0;--line-strong:#D6DBE4;--plum-soft:#F4ECF4;--bad:#B42318;
--font:"Geist","Segoe UI",system-ui,sans-serif;--mono:"Geist Mono",ui-monospace,"Cascadia Mono",monospace;color-scheme:light}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.55 var(--font);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}:focus-visible{outline:2px solid var(--q-sky);outline-offset:2px;border-radius:6px}
h1,h2,h3{margin:0;line-height:1.2;letter-spacing:-.015em}p{margin:0}
.qmark{display:inline-grid;place-items:center;width:26px;height:38px;flex:none}.qmark svg{width:100%;height:100%;display:block}
.ti{width:17px;height:17px;flex:none}
</style>"""

LOGIN = HEAD.replace("__TITLE__", "Sign in · __NAME__") + """<style>
body{min-height:100vh;display:grid;place-items:center;padding:16px}
form{width:100%;max-width:370px;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px 26px;
  box-shadow:0 1px 2px rgba(20,26,56,.05),0 18px 40px -20px rgba(24,33,78,.35);position:relative;overflow:hidden}
form::before{content:"";position:absolute;inset:0 0 auto;height:4px;background:linear-gradient(90deg,var(--q-sky) 0 50%,var(--q-plum) 50% 100%)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.brand b{display:block;font-size:17px;font-weight:650;color:var(--q-navy)}.brand small{color:var(--muted);font-size:12.5px}
label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}
input{width:100%;font:15px var(--font);color:var(--ink);padding:11px 12px;border:1px solid var(--line-strong);border-radius:9px}
input:focus{outline:0;border-color:var(--q-sky);box-shadow:0 0 0 3px rgba(132,176,213,.32)}
button{width:100%;margin-top:16px;font:600 15px var(--font);padding:11px;border:0;border-radius:9px;background:var(--q-navy);color:#fff;cursor:pointer;
  box-shadow:0 1px 2px rgba(24,33,78,.3),inset 0 1px 0 rgba(255,255,255,.1)}
button:hover{background:#0F1638}.err{color:var(--bad);font-size:13px;margin:12px 0 0}
.note{color:var(--faint);font-size:12px;margin:14px 0 0}.back{display:block;text-align:center;margin-top:16px;font-size:13px;color:var(--muted)}
.back:hover{color:var(--q-navy)}
</style></head><body><div>
<form method="post" action="/__SLUG__/login">
<div class="brand"><span class="qmark" aria-hidden="true">""" + MARK + """</span><div><b>__NAME__</b><small>Quilt Software · Sales Operations</small></div></div>
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
__ERROR__
<button type="submit">Sign in</button>
<p class="note">Stays signed in on this browser for 30 days, or until you sign out.</p>
</form><a class="back" href="/">← Back to the Sales Ops Hub</a></div></body></html>"""

PAGE_STYLE = """<style>
.bar{background:var(--q-navy);color:#fff;position:sticky;top:0;z-index:10;box-shadow:inset 0 -3px 0 0 var(--q-plum)}
.bar-in{display:flex;align-items:center;gap:12px 20px;flex-wrap:wrap;padding:10px 16px}
.brand{display:flex;align-items:center;gap:10px;color:#fff}.brand b{font-weight:650;font-size:15px;display:block}
.brand small{display:block;font-size:12px;color:#AFC6E3;line-height:1.15}
.nav{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;width:100%}.nav::-webkit-scrollbar{display:none}
.nav a{display:inline-flex;align-items:center;gap:9px;padding:7px 11px;border-radius:7px;color:#C2CCE3;font-weight:500;white-space:nowrap}
.nav a:hover{background:rgba(255,255,255,.07);color:#fff}.nav a.on{background:rgba(255,255,255,.12);color:#fff;box-shadow:inset 3px 0 0 var(--q-sky)}
.bar-foot{display:none}
@media (min-width:1000px){body{display:grid;grid-template-columns:236px minmax(0,1fr);align-items:start}
  .bar{height:100vh;box-shadow:none}.bar-in{flex-direction:column;align-items:stretch;flex-wrap:nowrap;height:100%;padding:20px 12px;gap:26px}
  .brand{padding:0 6px}.nav{flex-direction:column;overflow:visible}.nav a{width:100%;padding:8px 10px}
  .bar-foot{display:block;margin-top:auto;padding:0 8px;font-size:12px;color:#8F9CC0}}
main{max-width:1160px;width:100%;margin:0 auto;padding:34px 16px 64px;display:grid;gap:30px}
@media (min-width:700px){main{padding:40px 36px 72px}}
.hero h1{font-size:30px;font-weight:650;letter-spacing:-.025em;color:var(--q-navy)}
.hero h1::after{content:"";display:block;width:44px;height:4px;border-radius:2px;margin-top:12px;background:linear-gradient(90deg,var(--q-sky) 0 50%,var(--q-plum) 50% 100%)}
.hero p{color:var(--muted);font-size:15px;margin-top:14px;max-width:60ch}
.sec-h{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:14px}
.sec-h h2{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.sec-h p{font-size:13px;color:var(--faint)}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.app{position:relative;display:grid;grid-template-columns:minmax(0,1fr);grid-template-rows:auto auto 1fr auto;gap:10px;min-width:0;padding:20px;background:var(--surface);
  border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px rgba(20,26,56,.05);overflow:hidden;transition:transform .18s,box-shadow .18s,border-color .18s}
.app::before{content:"";position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,var(--q-sky) 0 50%,var(--q-plum) 50% 100%);opacity:0;transition:opacity .18s}
.app:hover{transform:translateY(-2px);border-color:#C9CFDB;box-shadow:0 2px 4px rgba(20,26,56,.05),0 12px 28px -12px rgba(24,33,78,.28)}.app:hover::before{opacity:1}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.icon{width:42px;height:42px;border-radius:10px;background:var(--q-navy);color:#fff;display:grid;place-items:center}.icon .ti{width:21px;height:21px}
.app h3{font-size:16.5px;font-weight:650}.app p{color:var(--muted);font-size:13.5px}
.tag{white-space:nowrap;font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;background:var(--plum-soft);color:var(--q-plum)}
.foot{min-width:0;display:flex;align-items:center;justify-content:space-between;gap:10px;padding-top:12px;border-top:1px solid var(--line)}
.host{flex:1;min-width:0;font:500 11.5px var(--mono);color:var(--faint);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.open{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;color:var(--q-navy)}.open svg{width:14px;height:14px;transition:transform .18s}
.app:hover .open svg{transform:translateX(3px)}
footer{color:var(--faint);font-size:12px;padding-top:8px;border-top:1px solid var(--line)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>"""


def portal_page(slug: str) -> str:
    p = PORTALS[slug]
    name = escape(p["name"])
    arrow = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
             'stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>')
    cards = "".join(
        f'<a class="app" href="{escape(a["url"])}" target="_blank" rel="noopener">'
        f'<div class="top"><span class="icon">{svg(a["icon"])}</span><span class="tag">{escape(a["tag"])}</span></div>'
        f'<h3>{escape(a["title"])}</h3><p>{escape(a["desc"])}</p>'
        f'<div class="foot"><span class="host">{escape(urlsplit(a["url"]).netloc)}</span><span class="open">Open {arrow}</span></div></a>'
        for a in p["apps"])
    others = "".join(f'<a href="/{k}">{svg("lock")}{escape(v["name"])}</a>' for k, v in PORTALS.items() if k != slug)
    return (HEAD.replace("__TITLE__", f"{name} · Quilt Sales Ops") + PAGE_STYLE + "</head><body>"
            f'<header class="bar"><div class="bar-in">'
            f'<a class="brand" href="/{slug}"><span class="qmark" aria-hidden="true">{MARK}</span><span><b>Quilt Software</b><small>{name}</small></span></a>'
            f'<nav class="nav" aria-label="Portals"><a class="on" href="/{slug}" aria-current="page">{svg("lock")}{name}</a>{others}'
            f'<a href="/">{svg("back")}Sales Ops Hub</a><a href="/{slug}/logout">{svg("out")}Sign out</a></nav>'
            f'<div class="bar-foot">Signed in · {name}</div></div></header>'
            f'<main><div class="hero"><h1>{name}</h1><p>{escape(p["lede"])}</p></div>'
            f'<section><div class="sec-h"><h2>{escape(p["section"])}</h2><p>Signed-in only</p></div><div class="apps">{cards}</div></section>'
            f'<footer>Quilt Software · Sales Operations · Internal use only</footer></main></body></html>')


class handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send(self, code, body: str = "", headers=None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def route(self):
        """('portal' or 'commissions', 'login' / 'logout' / ''), or (None, None)."""
        parts = urlsplit(self.path).path.strip("/").split("/")
        if parts[0] in PORTALS and len(parts) <= 2 and (len(parts) == 1 or parts[1] in ("login", "logout")):
            return parts[0], (parts[1] if len(parts) == 2 else "")
        return None, None

    def cookie(self, slug: str) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == f"{slug}_session":
                return v
        return ""

    def cookie_header(self, slug: str, value: str, age: int) -> tuple:
        return ("Set-Cookie", f"{slug}_session={value}; Path=/{slug}; Max-Age={age}; HttpOnly; Secure; SameSite=Lax")

    def login_page(self, slug: str, code=HTTPStatus.OK, error: str = ""):
        page = LOGIN.replace("__NAME__", escape(PORTALS[slug]["name"])).replace("__SLUG__", slug)
        self.send(code, page.replace("__ERROR__", f'<p class="err" role="alert">{escape(error)}</p>' if error else ""))

    def do_GET(self):
        slug, page = self.route()
        if not slug:
            return self.send(HTTPStatus.NOT_FOUND, "Not found.")
        if page == "logout":
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/login"), self.cookie_header(slug, "", 0)])
        signed_in = session_ok(slug, self.cookie(slug))
        if page == "login":
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}")]) if signed_in else self.login_page(slug)
        if signed_in:
            return self.send(HTTPStatus.OK, portal_page(slug))
        self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/login")])

    def do_POST(self):
        slug, page = self.route()
        if not slug or page != "login":
            return self.send(HTTPStatus.NOT_FOUND, "Not found.")
        p = PORTALS[slug]
        if not password(slug):
            return self.login_page(slug, HTTPStatus.SERVICE_UNAVAILABLE,
                                   f"The {p['name']} is closed until a password is set ({p['env']} in Vercel).")
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(min(n, 4096)).decode("utf-8", "replace")) if n > 0 else {}
        pw = (form.get("password") or [""])[0]
        if not hmac.compare_digest(pw.encode("utf-8"), password(slug).encode("utf-8")):
            time.sleep(1)                        # slows guessing
            return self.login_page(slug, HTTPStatus.UNAUTHORIZED, "That password isn't right.")
        self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}"),
                                             self.cookie_header(slug, make_session(slug), DAYS * 86400)])
