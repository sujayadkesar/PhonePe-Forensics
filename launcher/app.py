"""PhonePe Forensics — unified launcher.

One address for both analysers. The launcher owns its own pages under
`/__launcher/` and reverse-proxies every other path to whichever tool the
session has selected, so the analyser you picked appears at the same host and
port you started on. That matters for more than tidiness: same-origin means the
tools' cookies, redirects and absolute asset paths (`/static/...`,
`/transactions`) all work untouched, which is what lets both codebases stay
byte-identical.

Neither tool is modified. The only launcher-side change to what a tool returns
is a navigation block injected into the top of its sidebar — added to the
response body in flight, never to a template file.
"""
from __future__ import annotations

import os
import re
import secrets
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from flask import (
    Flask, Response, redirect, render_template, request, session, url_for,
)

from .tools import TOOLS, all_cases, stop_all

app = Flask(__name__, template_folder="templates", static_folder="static",
            static_url_path="/__launcher/static")
app.config["TEMPLATES_AUTO_RELOAD"] = True
# Both analysers are Flask apps and both name their session cookie `session`.
# Proxied onto one origin, whichever replied last would overwrite the launcher's
# cookie and the launcher would forget which tool the session had chosen — so it
# needs a name of its own. (Renaming theirs would mean editing them.)
app.config["SESSION_COOKIE_NAME"] = "pp_launcher"
# Per-process key: a shipped default would be a known signing key, and this
# session decides which tool your requests are proxied to.
app.secret_key = os.environ.get("PP_LAUNCHER_SECRET") or secrets.token_hex(32)

# Hop-by-hop headers are connection-scoped and must not be forwarded (RFC 7230).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

# Both analysers open their sidebar with exactly this tag, which makes it a
# reliable anchor for injecting a nav entry without editing either template.
_SIDEBAR_ANCHOR = '<aside class="sidebar">'

# The way back belongs in the sidebar, next to every other navigation control —
# that is where an analyst looks. A thin strip pinned to the bottom edge is
# present but not findable, and in the Android layout it collides with the
# tool's own floating status pill.
_SIDEBAR_BLOCK = """
<div id="__launcher_nav" style="margin:12px 12px 4px;padding:11px 12px;border-radius:10px;
     background:linear-gradient(135deg,rgba(139,92,246,.16),rgba(109,40,217,.10));
     border:1px solid rgba(139,92,246,.42);
     font:12px/1.45 ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif">
  <div style="font-size:9px;letter-spacing:.7px;text-transform:uppercase;color:#8a91a4">
    Analysing
  </div>
  <div style="font-size:14px;font-weight:700;color:#f3f4f6;margin:2px 0 9px">{label}</div>
  <a href="/__launcher/" style="display:block;text-align:center;padding:7px 10px;
     border-radius:8px;background:#8b5cf6;color:#fff;font-weight:600;text-decoration:none">
    &larr; Back to Launcher
  </a>
  <a href="/__launcher/cases" style="display:block;text-align:center;margin-top:6px;
     padding:6px 10px;border-radius:8px;border:1px solid #1e2638;background:#111726;
     color:#cbd1de;text-decoration:none">
    Switch case / platform
  </a>
</div>
"""



# ---------------------------------------------------------------------------
# Launcher pages
# ---------------------------------------------------------------------------

@app.route("/__launcher/")
def home():
    return render_template("home.html", tools=TOOLS.values(),
                           case_count=len(all_cases()))


@app.route("/__launcher/parse")
def parse_pick():
    return render_template("parse.html", tools=TOOLS.values())


@app.route("/__launcher/cases")
def cases():
    rows = all_cases()
    platform = request.args.get("platform") or ""
    if platform in TOOLS:
        rows = [r for r in rows if r["platform"] == platform]
    return render_template("cases.html", cases=rows, tools=TOOLS.values(),
                           active_filter=platform, total=len(all_cases()))


@app.route("/__launcher/open/<key>")
def open_tool(key: str):
    """Hand the session over to one analyser and land on its own start page."""
    tool = TOOLS.get(key)
    if tool is None:
        return render_template("error.html", message=f"Unknown platform '{key}'."), 404
    if not tool.ensure_running():
        return render_template("error.html",
                               message=f"The {tool.label} analyser did not start.",
                               detail=tool.last_error), 502
    session["platform"] = key
    return redirect(request.args.get("to") or "/")


@app.route("/__launcher/stop/<key>", methods=["POST"])
def stop_tool(key: str):
    tool = TOOLS.get(key)
    if tool:
        tool.stop()
        if session.get("platform") == key:
            session.pop("platform", None)
    return redirect(url_for("home"))


@app.route("/__launcher/switch")
def switch():
    """Leave the current tool without stopping it, so its case stays loaded."""
    session.pop("platform", None)
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Reverse proxy — everything that is not a launcher page
# ---------------------------------------------------------------------------

@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>",
           methods=["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"])
def proxy(path: str):
    key = session.get("platform")
    tool = TOOLS.get(key) if key else None
    if tool is None:
        return redirect(url_for("home"))
    if not tool.ensure_running():
        return render_template("error.html",
                               message=f"The {tool.label} analyser is not running.",
                               detail=tool.last_error), 502

    # Both analysers reject state-changing requests whose Origin is not their own
    # host. Behind a proxy that check would fail every POST, because the browser's
    # Origin is the launcher's port and the tool's is its own. The proxy therefore
    # re-presents the request as same-origin below — which means the launcher has
    # to make the check itself first, or it would launder a cross-site POST from
    # any page the analyst happens to have open.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if source:
            parsed, here = urlsplit(source), urlsplit(request.host_url)
            if (parsed.hostname, parsed.port) != (here.hostname, here.port):
                app.logger.warning("Rejected cross-origin %s %s from %s",
                                   request.method, request.path, source)
                return Response('{"ok": false, "error": "cross-origin request rejected"}',
                                status=403, content_type="application/json")

    target = f"{tool.base_url}/{path}"
    if request.query_string:
        target += "?" + request.query_string.decode("latin-1")

    # `identity` because the response body is rewritten below to append the
    # launcher bar; a gzipped body would have to be decoded first for no gain
    # over a loopback socket.
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in _HOP_BY_HOP and k.lower() != "host"}
    headers["Accept-Encoding"] = "identity"
    if "Cookie" in request.headers:
        unwrapped = _cookie_to_upstream(request.headers["Cookie"], tool.key)
        if unwrapped:
            headers["Cookie"] = unwrapped
        else:
            headers.pop("Cookie", None)
    # Having verified the real origin above, rewrite it to the backend's own so
    # the tool sees the same-origin request it is entitled to expect.
    if "Origin" in request.headers:
        headers["Origin"] = tool.base_url or ""
    if "Referer" in request.headers:
        headers["Referer"] = _rewrite_referer(request.headers["Referer"], tool.base_url)

    body = request.get_data() if request.method in ("POST", "PUT", "PATCH") else None
    req = urllib.request.Request(target, data=body, headers=headers,
                                 method=request.method)
    try:
        # redirects are returned to the browser rather than followed here, so the
        # address bar stays truthful and relative Location headers keep working.
        opener = urllib.request.build_opener(_NoRedirect)
        upstream = opener.open(req, timeout=600)
        status, raw_headers, payload = upstream.status, upstream.headers, upstream.read()
    except urllib.error.HTTPError as exc:
        status, raw_headers, payload = exc.code, exc.headers, exc.read()
    except Exception as exc:
        return render_template("error.html",
                               message=f"The {tool.label} analyser stopped responding.",
                               detail=str(exc)), 502

    out = []
    for k, v in raw_headers.items():
        if k.lower() in _HOP_BY_HOP or k.lower() == "content-length":
            continue
        if k.lower() == "set-cookie":
            v = _cookie_from_upstream(v, tool.key)
        out.append((k, v))
    ctype = raw_headers.get("Content-Type", "")
    if "text/html" in ctype.lower() and payload:
        payload = _inject_bar(payload, tool.label)
    return Response(payload, status=status, headers=out)



def _cookie_to_upstream(header: str, key: str) -> str:
    """Browser -> analyser: unwrap this tool's cookies, hide everyone else's.

    Both analysers are Flask apps and both name their session cookie `session`.
    Proxied onto one origin they are the same cookie, so whichever replied last
    overwrote the other's — visiting iOS silently reset the Android analyser's
    display settings, and a cleared cookie deleted them outright. Each tool's
    cookies are therefore stored under a per-tool prefix and unwrapped here, so
    from inside each analyser nothing has changed.
    """
    out = []
    for part in header.split(";"):
        part = part.strip()
        if not part or part.startswith("pp_launcher="):
            continue                      # the launcher's own; no tool needs it
        name = part.split("=", 1)[0]
        if name.startswith(key + "__"):
            out.append(part[len(key) + 2:])
        elif "__" in name:
            continue                      # another tool's — must not leak across
        else:
            out.append(part)
    return "; ".join(out)


def _cookie_from_upstream(value: str, key: str) -> str:
    """Analyser -> browser: store this tool's cookie under its own name."""
    return re.sub(r"^\s*([^=;\s]+)=", lambda m: f"{key}__{m.group(1)}=", value, count=1)


def _rewrite_referer(referer: str, base_url: Optional[str]) -> str:
    """Keep the path, swap the host — the backend sees its own address."""
    if not base_url:
        return referer
    parts, base = urlsplit(referer), urlsplit(base_url)
    return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _inject_bar(payload: bytes, label: str) -> bytes:
    """Add the way back to a proxied page, without touching either template.

    A single placement: a block at the top of the analyser's sidebar, where its
    other navigation already lives. A pinned strip along the bottom edge was
    tried and removed — it was easy to miss and collided with the Android
    layout's own floating status pill.

    Pages with no sidebar (error pages) therefore get nothing injected; the
    launcher stays reachable at /__launcher/ and the browser's back button
    works, which is enough for a page you land on by accident.
    """
    anchor = _SIDEBAR_ANCHOR.encode("utf-8")
    idx = payload.find(anchor)
    if idx == -1:
        return payload
    block = _SIDEBAR_BLOCK.format(label=label).encode("utf-8")
    cut = idx + len(anchor)
    return payload[:cut] + block + payload[cut:]


@app.errorhandler(404)
def _404(_e):
    return render_template("error.html", code=404,
                           message="No such launcher page."), 404


def run(host: str = "127.0.0.1", port: int = 8750) -> None:
    print(f"[*] PhonePe Forensics launcher  →  http://{host}:{port}/__launcher/")
    print("[*] iOS and Android analysers start on demand; Ctrl-C stops everything.")
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    finally:
        stop_all()
