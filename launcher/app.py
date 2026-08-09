"""PhonePe Forensics — unified launcher.

One address for both analysers. The launcher owns its own pages under
`/__launcher/` and reverse-proxies every other path to whichever tool the
session has selected, so the analyser you picked appears at the same host and
port you started on. That matters for more than tidiness: same-origin means the
tools' cookies, redirects and absolute asset paths (`/static/...`,
`/transactions`) all work untouched, which is what lets both codebases stay
byte-identical.

Neither tool is modified. The only launcher-side change to what a tool returns
is a small "back to launcher" bar appended to HTML responses — injected into the
response body in flight, never into a template file.
"""
from __future__ import annotations

import os
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

_BACK_BAR = """
<div id="__launcher_bar" style="position:fixed;left:0;right:0;bottom:0;z-index:2147483646;
     display:flex;align-items:center;gap:10px;padding:7px 14px;
     background:#0c0e16;border-top:1px solid #1e2638;
     font:12px/1.4 ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;color:#8a91a4">
  <a href="/__launcher/" style="color:#f3f4f6;text-decoration:none;font-weight:600">&larr; Launcher</a>
  <span style="color:#5b6478">|</span>
  <span>Analysing as <b style="color:#8b5cf6">{label}</b></span>
  <span style="margin-left:auto;color:#5b6478">PhonePe Forensics</span>
</div>
<div style="height:34px"></div>
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

    out = [(k, v) for k, v in raw_headers.items()
           if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"]
    ctype = raw_headers.get("Content-Type", "")
    if "text/html" in ctype.lower() and payload:
        payload = _inject_bar(payload, tool.label)
    return Response(payload, status=status, headers=out)


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
    bar = _BACK_BAR.format(label=label).encode("utf-8")
    lowered = payload.lower()
    idx = lowered.rfind(b"</body>")
    if idx == -1:
        return payload + bar
    return payload[:idx] + bar + payload[idx:]


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
