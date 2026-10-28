"""
The hub's signed-in areas: the Team Portal (/portal) and the Commission Portal
(/commissions). Signing in to one doesn't open the other.

The Team Portal has its own people (Mary, 2026-10: "anyone can access the hub
but not everyone should access the team portal"): each signs in with their
email and a password an admin sets at /portal/users. The list lives in the
Upstash database connected to the hub project (key hub:users; no names in this
public repo). "admin" with PORTAL_PASSWORD always works, so nobody is locked
out. The Commission Portal keeps its one password (COMMISSION_PASSWORD); the
hub's sidebar now links straight to the Commission Plan Builder's own sign-in.

Vercel sends /<portal>, /<portal>/login, /logout and /portal/users here
(vercel.json). A signed cookie keeps people in for 30 days. Changing someone's
password or access, or removing them, signs them out; changing the portal
password signs everyone out. A portal with no password set stays closed.

Standard library only. To add an app, add it to that portal's apps below.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.request
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlsplit

DAYS = 30

PORTALS = {
    "portal": {
        "name": "Team Portal", "env": "PORTAL_PASSWORD", "section": "Team apps", "people": True,
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
        "link": "https://commission-planner.vercel.app/login",
        "lede": "Compensation planning: plans, quotas and allocations. Sign in with your own email and password.",
        "apps": [
            {"title": "Commission Plan Builder", "tag": "Sales Ops only", "icon": "plan",
             "desc": "Build and export written comp plans, quotas and allocations.",
             "url": "https://commission-planner.vercel.app/login"},
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
    "users": '<circle cx="9" cy="9" r="3.2"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><circle cx="17" cy="10" r="2.5"/><path d="M15.5 14.6A4.5 4.5 0 0 1 21 19"/>',
    "out": '<path d="M14 4h4.5a1.5 1.5 0 0 1 1.5 1.5v13a1.5 1.5 0 0 1-1.5 1.5H14"/><path d="M10 16l-4-4 4-4M6 12h10"/>',
}
MARK = ('<svg viewBox="4 0 32 48"><path d="M20 2 34 16 20 30 6 16z" fill="#84B0D5"/>'
        '<path d="M20 18 34 32 20 46 6 32z" fill="#8F568F"/><path d="M20 18 26 24 20 30 14 24z" fill="#18214E"/></svg>')
FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='4 0 32 48'%3E%3Cpath d='M20 2 34 16 20 30 6 16z' "
           "fill='%2384B0D5'/%3E%3Cpath d='M20 18 34 32 20 46 6 32z' fill='%238F568F'/%3E%3Cpath d='M20 18 26 24 20 30 14 24z' fill='%2318214E'/%3E%3C/svg%3E")


def svg(name: str, cls: str = "ti") -> str:
    return (f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


# ---------------- storage: the Upstash database connected to the hub project ----------------

def _env_ending(*suffixes: str) -> str:
    """An env var by name, or by its ending: Vercel can prefix storage variables (STORAGE_KV_REST_API_URL)."""
    for x in suffixes:
        if os.environ.get(x):
            return os.environ[x]
    for x in suffixes:
        for k, v in sorted(os.environ.items()):
            if k.endswith("_" + x) and v and "READ_ONLY" not in k:
                return v
    return ""


KV_URL = _env_ending("KV_REST_API_URL", "UPSTASH_REDIS_REST_URL").rstrip("/")
KV_TOKEN = _env_ending("KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_TOKEN")


def kv(*cmd):
    req = urllib.request.Request(KV_URL, data=json.dumps(cmd).encode("utf-8"), method="POST",
                                 headers={"Authorization": f"Bearer {KV_TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise OSError(out["error"])
    return out["result"]


def load_users() -> list:
    if not KV_URL:
        return []
    raw = kv("GET", "hub:users")
    return json.loads(raw) if raw else []


def save_users(users: list) -> None:
    if not KV_URL:
        raise OSError("storage isn't connected")
    kv("SET", "hub:users", json.dumps(users, separators=(",", ":")))


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return "pbkdf2$200000$" + salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200000).hex()


def check_password(pw: str, stored: str) -> bool:
    try:
        _, n, salt, h = (stored or "").split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), int(n)).hex(), h)
    except ValueError:
        return False


def make_password() -> str:
    abc = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(abc) for _ in range(14))


# ---------------- sign-in ----------------
ADMIN = {"id": "admin", "name": "Admin", "email": "admin", "role": "admin", "sv": 0}


def _key(slug: str) -> bytes:
    return hashlib.sha256(f"hub-portal-session|{slug}|".encode() + password(slug).encode("utf-8")
                          + b"|" + KV_TOKEN.encode("utf-8")).digest()


def _sig(slug: str, uid: str, exp: str, sv) -> str:
    return hmac.new(_key(slug), f"{uid}|{exp}|{sv}".encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(slug: str, user: dict = ADMIN) -> str:
    exp = str(int(time.time()) + DAYS * 86400)
    return f"{user['id']}.{exp}.{_sig(slug, user['id'], exp, user.get('sv', 0))}"


def session_user(slug: str, value: str):
    """Who a portal cookie belongs to, or None."""
    uid, _, rest = (value or "").partition(".")
    exp, _, sig = rest.partition(".")
    if not password(slug) or not exp.isdigit() or int(exp) < time.time():
        return None
    if uid == "admin":
        user = ADMIN
    elif PORTALS[slug].get("people"):
        try:
            user = next((u for u in load_users() if u["id"] == uid and u.get("active", True)), None)
        except (OSError, ValueError):
            user = None
        if user is None:
            return None
    else:
        return None
    return user if hmac.compare_digest(sig, _sig(slug, uid, exp, user.get("sv", 0))) else None


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
label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}input+label{margin-top:14px}
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
__EMAILFIELD__<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" required__PWFOCUS__>
__ERROR__
<button type="submit">Sign in</button>
<p class="note">Stays signed in on this browser for 30 days, or until you sign out.__WHO__</p>
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


USERS_STYLE = """<style>
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px 22px;box-shadow:0 1px 2px rgba(20,26,56,.05)}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;font-size:11.5px;font-weight:600;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em;padding:8px 10px;border-bottom:1px solid var(--line)}td{padding:10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr.off td{color:var(--faint)}.muted{color:var(--muted)}.acts{text-align:right;white-space:nowrap}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:99px;background:#EEF2F9;color:var(--q-navy)}
.pill.admin{background:var(--plum-soft);color:var(--q-plum)}
.btn{display:inline-flex;align-items:center;gap:6px;font:600 13px var(--font);padding:7px 12px;border-radius:8px;border:1px solid var(--line-strong);
  background:#fff;color:var(--q-navy);cursor:pointer;margin-left:6px}.btn:hover{background:#F7F8FB}
.btn.primary{background:var(--q-navy);border-color:var(--q-navy);color:#fff}.btn.primary:hover{background:#0F1638}
.btn.danger{color:#A3283F}.btn.danger:hover{background:#FCEEF1;border-color:#E8B9C3}
form.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px 16px;align-items:end;margin-top:14px}
form.grid label{display:grid;gap:5px;font-size:13px;font-weight:600}
input,select{width:100%;font:14px var(--font);color:var(--ink);padding:9px 11px;border:1px solid var(--line-strong);border-radius:9px;background:#fff}
input:focus,select:focus{outline:0;border-color:var(--q-sky);box-shadow:0 0 0 3px rgba(132,176,213,.32)}
.mono{font-family:var(--mono)}.hint{color:var(--muted);font-size:13px;margin-top:8px}
.msg{padding:10px 14px;border-radius:10px;background:#EEF2F9;color:var(--q-navy);font-size:14px}.msg.bad{background:#FCEEF1;color:#A3283F}
.scroll{overflow-x:auto}
</style>"""


def shell(slug: str, user: dict, title: str, body: str, on: str) -> str:
    """A signed-in portal page: the sidebar, then `body`."""
    name = escape(PORTALS[slug]["name"])
    others = "".join(f'<a href="{escape(v.get("link") or "/" + k)}">{svg("lock")}{escape(v["name"])}</a>'
                     for k, v in PORTALS.items() if k != slug)
    people = (f'<a class="{"on" if on == "users" else ""}" href="/{slug}/users">{svg("users")}Users</a>'
              if PORTALS[slug].get("people") and user.get("role") == "admin" else "")
    return (HEAD.replace("__TITLE__", f"{escape(title)} · Quilt Sales Ops") + PAGE_STYLE + USERS_STYLE + "</head><body>"
            f'<header class="bar"><div class="bar-in">'
            f'<a class="brand" href="/{slug}"><span class="qmark" aria-hidden="true">{MARK}</span><span><b>Quilt Software</b><small>{name}</small></span></a>'
            f'<nav class="nav" aria-label="Portals"><a class="{"on" if on == "home" else ""}" href="/{slug}">{svg("lock")}{name}</a>{people}{others}'
            f'<a href="/">{svg("back")}Sales Ops Hub</a><a href="/{slug}/logout">{svg("out")}Sign out</a></nav>'
            f'<div class="bar-foot">Signed in as {escape(user.get("name") or "")}</div></div></header>'
            f'<main>{body}<footer>Quilt Software · Sales Operations · Internal use only</footer></main></body></html>')


def users_page(slug: str, me: dict, users: list, q: dict, msg: str = "", bad: bool = False) -> str:
    edit, pw, add = q.get("edit", [""])[0], q.get("pw", [""])[0], q.get("add", [""])[0]
    role = lambda r: f'<select name="role"><option value="member"{" selected" if r == "member" else ""}>Member</option><option value="admin"{" selected" if r == "admin" else ""}>Admin</option></select>'
    rows = []
    for u in sorted(users, key=lambda x: x["name"].lower()):
        uid = escape(u["id"])
        if edit == u["id"]:
            rows.append(f'<tr><td colspan="5"><form class="grid" method="post" action="/{slug}/users"><input type="hidden" name="action" value="update">'
                        f'<input type="hidden" name="id" value="{uid}"><label>Name<input name="name" value="{escape(u["name"])}" required></label>'
                        f'<label>Email<input name="email" type="email" value="{escape(u["email"])}" required></label><label>Access{role(u["role"])}</label>'
                        f'<label><span><input type="checkbox" name="active" value="1"{" checked" if u.get("active", True) else ""} style="width:auto"> Can sign in</span></label>'
                        f'<div><button class="btn primary" type="submit">Save</button><a class="btn" href="/{slug}/users">Cancel</a></div></form></td></tr>')
            continue
        if pw == u["id"]:
            rows.append(f'<tr><td colspan="5"><form class="grid" method="post" action="/{slug}/users"><input type="hidden" name="action" value="password">'
                        f'<input type="hidden" name="id" value="{uid}"><label>New password for {escape(u["name"])}'
                        f'<input class="mono" name="password" value="{make_password()}" required minlength="10" autocomplete="off"></label>'
                        f'<div><button class="btn primary" type="submit">Set password</button><a class="btn" href="/{slug}/users">Cancel</a></div></form>'
                        f'<p class="hint">Copy it before you save and send it to them yourself. This signs them out.</p></td></tr>')
            continue
        last = f'Signed in {escape(u["lastLogin"][:10])}' if u.get("lastLogin") else "Hasn’t signed in yet"
        mine = u["id"] == me.get("id")
        remove = "" if mine else (f'<form method="post" action="/{slug}/users" style="display:inline" onsubmit="return confirm(\'Remove this person from the Team Portal?\')">'
                                  f'<input type="hidden" name="action" value="remove"><input type="hidden" name="id" value="{uid}">'
                                  f'<button class="btn danger" type="submit">Remove</button></form>')
        rows.append(f'<tr class="{"" if u.get("active", True) else "off"}"><td><b>{escape(u["name"])}</b>{" <span class=muted>(you)</span>" if mine else ""}</td>'
                    f'<td>{escape(u["email"])}</td><td><span class="pill {escape(u["role"])}">{"Admin" if u["role"] == "admin" else "Member"}</span></td>'
                    f'<td class="muted">{last if u.get("active", True) else "Can’t sign in"}</td>'
                    f'<td class="acts"><a class="btn" href="/{slug}/users?edit={uid}">Edit</a><a class="btn" href="/{slug}/users?pw={uid}">Reset password</a>{remove}</td></tr>')
    adder = (f'<form class="grid" method="post" action="/{slug}/users"><input type="hidden" name="action" value="add">'
             f'<label>Name<input name="name" required autofocus></label><label>Work email<input name="email" type="email" required></label>'
             f'<label>Access{role("member")}</label><label>Password<input class="mono" name="password" value="{make_password()}" required minlength="10" autocomplete="off"></label>'
             f'<div><button class="btn primary" type="submit">Add person</button><a class="btn" href="/{slug}/users">Cancel</a></div></form>'
             f'<p class="hint">Copy the password before you add them and send it yourself. They sign in at this portal with their email and it.</p>'
             if add else f'<p style="margin-top:14px"><a class="btn primary" href="/{slug}/users?add=1" style="margin-left:0">+ Add a person</a></p>')
    store = "" if KV_URL else ('<p class="msg bad">Storage isn’t connected, so people can’t be added yet. In Vercel: quilt-salesops-hub → Storage → '
                               'Connect the Upstash database → Redeploy.</p>')
    body = (f'<div class="hero"><h1>Users</h1><p>Who can open the {escape(PORTALS[slug]["name"])}. Everyone else can still use the hub. '
            f'<b>Admin</b>: gets in and manages this list. <b>Member</b>: gets in. "admin" with the portal password always works too.</p></div>'
            + (f'<p class="msg{" bad" if bad else ""}">{escape(msg)}</p>' if msg else "") + store
            + f'<section class="card"><div class="scroll"><table><thead><tr><th>Name</th><th>Email</th><th>Access</th><th>Status</th><th></th></tr></thead>'
            f'<tbody>{"".join(rows) or "<tr><td colspan=5 class=muted>No one yet. Add yourself first, as an Admin.</td></tr>"}</tbody></table></div>{adder}</section>')
    return shell(slug, me, "Users", body, "users")


def portal_page(slug: str, user: dict) -> str:
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
    body = (f'<div class="hero"><h1>{name}</h1><p>{escape(p["lede"])}</p></div>'
            f'<section><div class="sec-h"><h2>{escape(p["section"])}</h2><p>Signed-in only</p></div><div class="apps">{cards}</div></section>')
    return shell(slug, user, p["name"], body, "home")


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
        sub = ("login", "logout", "users") if parts[0] in PORTALS and PORTALS[parts[0]].get("people") else ("login", "logout")
        if parts[0] in PORTALS and len(parts) <= 2 and (len(parts) == 1 or parts[1] in sub):
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

    def login_page(self, slug: str, code=HTTPStatus.OK, error: str = "", email: str = ""):
        people = PORTALS[slug].get("people")
        page = LOGIN.replace("__NAME__", escape(PORTALS[slug]["name"])).replace("__SLUG__", slug)
        page = page.replace("__EMAILFIELD__", f'<label for="em">Email</label><input id="em" name="email" type="text" inputmode="email" '
                                              f'autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus value="{escape(email)}">'
                            if people else "")
        page = page.replace("__PWFOCUS__", "" if people else " autofocus")
        page = page.replace("__WHO__", " No login yet? Ask Mary." if people else "")
        self.send(code, page.replace("__ERROR__", f'<p class="err" role="alert">{escape(error)}</p>' if error else ""))

    def form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return parse_qs(self.read_body(min(n, 16384)).decode("utf-8", "replace")) if n > 0 else {}

    def read_body(self, n: int) -> bytes:
        return self.rfile.read(n)

    def do_GET(self):
        slug, page = self.route()
        if not slug:
            return self.send(HTTPStatus.NOT_FOUND, "Not found.")
        if page == "logout":
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/login"), self.cookie_header(slug, "", 0)])
        user = session_user(slug, self.cookie(slug))
        if page == "login":
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}")]) if user else self.login_page(slug)
        if not user:
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/login")])
        if page == "users":
            if user.get("role") != "admin":
                return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}")])
            q = parse_qs(urlsplit(self.path).query)
            try:
                users = load_users()
            except (OSError, ValueError):
                return self.send(HTTPStatus.OK, users_page(slug, user, [], {}, "Couldn't reach the user list. Try again in a minute.", True))
            return self.send(HTTPStatus.OK, users_page(slug, user, users, q, q.get("msg", [""])[0]))
        self.send(HTTPStatus.OK, portal_page(slug, user))

    def do_POST(self):
        slug, page = self.route()
        if slug and page == "users":
            return self.post_users(slug)
        if not slug or page != "login":
            return self.send(HTTPStatus.NOT_FOUND, "Not found.")
        p = PORTALS[slug]
        if not password(slug):
            return self.login_page(slug, HTTPStatus.SERVICE_UNAVAILABLE,
                                   f"The {p['name']} is closed until a password is set ({p['env']} in Vercel).")
        form = self.form()
        pw = (form.get("password") or [""])[0]
        email = (form.get("email") or [""])[0].strip().lower()
        user = None
        if not p.get("people") or email in ("", "admin"):
            if hmac.compare_digest(pw.encode("utf-8"), password(slug).encode("utf-8")):
                user = ADMIN
        else:
            try:
                users = load_users()
                found = next((u for u in users if u["email"] == email and u.get("active", True)), None)
                if found and check_password(pw, found.get("pw", "")):
                    user = found
                    found["lastLogin"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    save_users(users)
            except (OSError, ValueError):
                pass
        if user is None:
            time.sleep(1)                        # slows guessing
            msg = "That email and password don't match." if p.get("people") else "That password isn't right."
            return self.login_page(slug, HTTPStatus.UNAUTHORIZED, msg, email)
        self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}"),
                                             self.cookie_header(slug, make_session(slug, user), DAYS * 86400)])

    def post_users(self, slug: str):
        """Admins add, change, reset and remove Team Portal people (/portal/users forms)."""
        me = session_user(slug, self.cookie(slug))
        form = self.form()
        if not me or me.get("role") != "admin":
            return self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/login")])
        f = lambda k: (form.get(k) or [""])[0].strip()
        back = lambda msg: self.send(HTTPStatus.SEE_OTHER, "", [("Location", f"/{slug}/users?msg={quote(msg)}")])
        try:
            users = load_users()
        except (OSError, ValueError):
            return back("Couldn't reach the user list. Try again in a minute.")
        action, target = f("action"), next((u for u in users if u["id"] == f("id")), None)
        name, email, role, pw = f("name")[:80], f("email").lower()[:120], f("role"), (form.get("password") or [""])[0]
        if action != "add" and target is None:
            return back("That person isn't in the list any more.")
        if action in ("add", "update"):
            if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or role not in ("admin", "member"):
                return back("Add a name, a work email and their access.")
            if any(u["email"] == email and u is not target for u in users):
                return back(f"{email} already has a login.")
        if action in ("add", "password") and len(pw) < 10:
            return back("Passwords need at least 10 characters.")
        if target is not None and target["id"] == me["id"] and (action == "remove" or (action == "update" and (role != "admin" or not f("active")))):
            return back("You can't take away your own admin access.")
        if action == "add":
            users.append({"id": secrets.token_hex(6), "name": name, "email": email, "role": role, "active": True,
                          "pw": hash_password(pw), "sv": 1, "created": time.strftime("%Y-%m-%d", time.gmtime())})
            done = f"Added {name}. Send them their password."
        elif action == "update":
            changed = target["role"] != role or (target.get("active", True) and not f("active"))
            target.update(name=name, email=email, role=role, active=bool(f("active")))
            if changed:
                target["sv"] = target.get("sv", 0) + 1
            done = f"Saved {name}."
        elif action == "password":
            target["pw"], target["sv"] = hash_password(pw), target.get("sv", 0) + 1
            done = f"New password set for {target['name']}. Send it to them."
        elif action == "remove":
            users = [u for u in users if u is not target]
            done = f"{target['name']} can't open the portal any more."
        else:
            return back("Bad request.")
        try:
            save_users(users)
        except (OSError, ValueError):
            return back("Couldn't save just now. Try again in a minute.")
        return back(done)
