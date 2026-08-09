"""Process supervision for the two analyser tools.

Why subprocesses rather than imports
------------------------------------
Both tools ship a package named `phonepe_forensics`. Python cannot hold two
different packages under one name in one interpreter, so importing both into the
launcher is impossible without renaming one of them — and the whole point of this
layer is that neither codebase is edited. Each tool therefore runs in its own
interpreter, in its own working directory, and the launcher proxies to it.

Each tool keeps its case registry at `<cwd>/.pp_forensics/cases.json`, so giving
them separate working directories keeps their registries separate for free. The
launcher reads both to build the combined case list.

Tools are started with an inline bootstrap rather than their own `run.py`,
because both `run.py` files pop a browser window on startup. Importing the app
object directly skips that without touching the file.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The bootstrap run inside each tool's interpreter. `cwd` is the tool directory,
# so `sys.path[0] = ""` already resolves its own `phonepe_forensics`; the
# explicit insert just makes that independent of how Python was invoked.
_BOOTSTRAP = (
    "import sys; sys.path.insert(0, '');"
    "from phonepe_forensics.webapp import app;"
    "app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)"
)


@dataclass
class Tool:
    key: str                      # "ios" | "android"
    label: str
    blurb: str
    cwd: str                      # working directory = where its registry lives
    port: Optional[int] = None
    process: Optional[subprocess.Popen] = None
    last_error: Optional[str] = None

    # ---- lifecycle --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @property
    def base_url(self) -> Optional[str]:
        return f"http://127.0.0.1:{self.port}" if self.running and self.port else None

    def ensure_running(self, timeout: float = 25.0) -> bool:
        """Start the tool if it isn't up, and wait until it accepts connections.

        Returns False and records `last_error` rather than raising: a tool that
        fails to boot should render as a message in the launcher, not a 500.
        """
        if self.running:
            return True
        if not os.path.isdir(self.cwd):
            self.last_error = f"tool directory not found: {self.cwd}"
            return False

        self.port = _free_port()
        env = dict(os.environ)
        # Belt and braces: the bootstrap already skips run.py's browser call, but
        # anything else that reaches for a browser gets a no-op too.
        env["BROWSER"] = "true"
        env["PP_FORENSICS_NOBROWSER"] = "1"
        env.setdefault("PYTHONIOENCODING", "utf-8")

        try:
            self.process = subprocess.Popen(
                [sys.executable, "-c", _BOOTSTRAP.format(port=self.port)],
                cwd=self.cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except Exception as exc:                       # pragma: no cover
            self.last_error = f"could not start: {exc}"
            return False

        if _wait_for_port(self.port, timeout):
            self.last_error = None
            return True

        # It never came up. Surface whatever it printed — an ImportError or a
        # missing dependency is the usual cause, and it is worth showing.
        self.last_error = self._drain_output() or "did not start within timeout"
        self.stop()
        return False

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:          # pragma: no cover
                self.process.kill()
        self.process = None
        self.port = None

    def _drain_output(self, limit: int = 4000) -> str:
        if not self.process or not self.process.stdout:
            return ""
        try:
            self.process.stdout.flush()
            data = self.process.stdout.read(limit) or b""
            return data.decode("utf-8", "replace").strip()
        except Exception:                              # pragma: no cover
            return ""

    # ---- case registry ----------------------------------------------------

    def cases(self) -> List[Dict[str, Any]]:
        """Read this tool's case registry without starting it.

        The combined case list must work while both tools are stopped, so this
        reads the JSON directly instead of asking the running app.
        """
        path = os.path.join(self.cwd, ".pp_forensics", "cases.json")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            return []
        rows = payload.get("cases", payload) if isinstance(payload, dict) else payload
        out: List[Dict[str, Any]] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            out.append({
                "id": row.get("id"),
                "name": row.get("name") or "(unnamed)",
                "investigator": row.get("investigator"),
                "notes": row.get("notes"),
                "created_at_ms": row.get("created_at_ms"),
                "status": row.get("status"),
                "root": row.get("single_root") or row.get("root"),
                # The registry's own `platform` field is not trusted here: each
                # tool only ever writes its own, and one of them predates the
                # field entirely. Which registry the row came from is the fact.
                "platform": self.key,
                "platform_label": self.label,
            })
        return out


# ---------------------------------------------------------------------------

TOOLS: Dict[str, Tool] = {
    "ios": Tool(
        key="ios", label="iOS",
        blurb="PhonePe iOS analyser — parses an iOS app container.",
        cwd=ROOT,
    ),
    "android": Tool(
        key="android", label="Android",
        blurb="PhonePe Android analyser — parses a com.phonepe.app data directory.",
        cwd=os.path.join(ROOT, "android"),
    ),
}


def all_cases() -> List[Dict[str, Any]]:
    """Every case from both registries, newest first."""
    rows: List[Dict[str, Any]] = []
    for tool in TOOLS.values():
        rows.extend(tool.cases())
    rows.sort(key=lambda r: r.get("created_at_ms") or 0, reverse=True)
    return rows


def stop_all() -> None:
    for tool in TOOLS.values():
        tool.stop()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False
