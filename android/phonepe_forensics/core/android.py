"""
PhonePe Forensics — Android-only parsing primitives
===================================================
The ``com.phonepe.app`` data layout and the formats Android stores it in. The
heavy lifting (SQLiteReader, timestamps, hashing) is platform-neutral and lives
in ``core.common``; only what is genuinely Android-shaped is here:

    AndroidCasePaths   databases/ · shared_prefs/ · files/ · app_webview/
    decode_json_blob   Android payloads are plain JSON strings, not bplists
    chromium_ts        WebView cookie timestamps (microseconds since 1601)
    first_or_dict      ZDATA-style fields that swing between list and dict
    read_shared_pref   shared_prefs/*.xml -> flat {key: value}
"""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .common import (  # noqa: F401  (re-exported for the extractors)
    EPOCH_S_MAX,
    SUCCESS_STATES,
    SQLiteReader,
    _ts_dict,
    amount_to_rupees,
    decode_txn_id,
    evidence_manifest,
    evidence_warnings,
    hash_file,
    normalize_timestamp,
    safe_float,
    safe_int,
    tri_bool,
)

PACKAGE = "com.phonepe.app"


# ---------------------------------------------------------------------------
# JSON blob decode  (Android's entire "BLOB" decoder)
# ---------------------------------------------------------------------------

def decode_json_blob(value: Any) -> Any:
    """Android stores structured payloads as plain JSON *strings* in TEXT columns.

    Returns the parsed object, or the original value if it isn't JSON. Never raises.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "replace")
        except Exception:
            return {"_raw_size": len(value)}
    if isinstance(value, str):
        s = value.strip()
        if not s or s[0] not in "{[":
            return value
        try:
            return json.loads(s)
        except Exception:
            return value
    return value


def chromium_ts(utc: Any) -> Optional[Dict[str, Any]]:
    """Chromium/WebKit timestamps are microseconds since 1601-01-01. Convert to the
    normalized ts-dict shape {epoch_ms, iso, display, tz, source}. None on 0/invalid."""
    n = safe_int(utc, default=0)
    if n <= 0:
        return None
    epoch_s = n / 1_000_000.0 - 11_644_473_600.0  # 1601→1970 offset
    if epoch_s <= 0 or epoch_s > EPOCH_S_MAX:
        return None
    return _ts_dict(epoch_s, "chromium_webkit")


def first_or_dict(v: Any) -> Dict[str, Any]:
    """Fields like `from`/`to`/`paidFrom`/`receivedIn` are sometimes a dict and
    sometimes a single-element list. Normalize to one dict."""
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], dict) else {}
    if isinstance(v, dict):
        return v
    return {}


def pick(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    """First non-empty value among keys."""
    for k in keys:
        val = d.get(k)
        if val not in (None, "", [], {}):
            return val
    return None


# ---------------------------------------------------------------------------
# shared_prefs/*.xml reader
# ---------------------------------------------------------------------------

def read_shared_pref(path: str) -> Dict[str, Any]:
    """Parse an Android shared_prefs XML into a flat {name: value} dict.

    Handles <string>, <int>, <long>, <float>, <boolean>, <set>. Values that are
    themselves JSON are left as strings (callers decode on demand).
    """
    out: Dict[str, Any] = {}
    try:
        tree = ET.parse(path)
    except Exception:
        return out
    root = tree.getroot()
    for el in root:
        name = el.get("name")
        if name is None:
            continue
        tag = el.tag
        if tag in ("string",):
            out[name] = el.text
        elif tag in ("int", "long"):
            out[name] = safe_int(el.get("value"))
        elif tag == "float":
            out[name] = safe_float(el.get("value"))
        elif tag == "boolean":
            out[name] = el.get("value") == "true"
        elif tag == "set":
            out[name] = [c.text for c in el]
        else:
            out[name] = el.get("value") if el.get("value") is not None else el.text
    return out


# ---------------------------------------------------------------------------
# Android path resolver
# ---------------------------------------------------------------------------

class AndroidCasePaths:
    """Resolve the PhonePe Android app-data layout.

    Accepts either the ``com.phonepe.app`` directory itself, or any ancestor that
    contains it somewhere underneath (e.g. an extraction root). The canonical
    marker is a ``databases`` subdir containing ``phonepe_core``.
    """

    APP_DIR_NAME = PACKAGE

    def __init__(self, root: str):
        root = os.path.abspath(root)
        self.root = root
        self.app_dir = self._find_app_dir(root)
        self.databases_dir = self._sub("databases")
        self.shared_prefs_dir = self._sub("shared_prefs")
        self.files_dir = self._sub("files")
        self.webview_dir = self._sub("app_webview")

    # ---- discovery ----
    def _find_app_dir(self, root: str) -> Optional[str]:
        # The root itself is the app dir?
        if os.path.isdir(os.path.join(root, "databases")):
            return root
        # A child named com.phonepe.app?
        cand = os.path.join(root, self.APP_DIR_NAME)
        if os.path.isdir(os.path.join(cand, "databases")):
            return cand
        # Walk down (bounded) to find data/data/com.phonepe.app
        for cur, dirs, _ in os.walk(root):
            if os.path.basename(cur) == self.APP_DIR_NAME and \
               os.path.isdir(os.path.join(cur, "databases")):
                return cur
            # don't descend into huge irrelevant trees forever
            if cur.count(os.sep) - root.count(os.sep) > 8:
                dirs[:] = []
        return None

    def _sub(self, name: str) -> Optional[str]:
        if not self.app_dir:
            return None
        p = os.path.join(self.app_dir, name)
        return p if os.path.isdir(p) else None

    # ---- accessors ----
    def db(self, name: str) -> Optional[str]:
        """Path to a database file in databases/, or None."""
        if not self.databases_dir:
            return None
        p = os.path.join(self.databases_dir, name)
        return p if os.path.exists(p) else None

    def shared_pref(self, name: str) -> Optional[str]:
        if not self.shared_prefs_dir:
            return None
        p = os.path.join(self.shared_prefs_dir, name)
        return p if os.path.exists(p) else None

    def is_valid(self) -> bool:
        return bool(self.db("phonepe_core"))

    def all_sqlites(self) -> List[str]:
        """Every SQLite-format file under databases/ (skip -wal/-shm/-journal)."""
        out: List[str] = []
        if not self.databases_dir:
            return out
        skip = ("-wal", "-shm", "-journal")
        for f in sorted(os.listdir(self.databases_dir)):
            full = os.path.join(self.databases_dir, f)
            if not os.path.isfile(full) or f.endswith(skip):
                continue
            try:
                with open(full, "rb") as fh:
                    if fh.read(16).startswith(b"SQLite format 3"):
                        out.append(full)
            except OSError:
                continue
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "platform": "android",
            "root": self.root,
            "app_dir": self.app_dir,
            "package": PACKAGE,
            "databases_dir": self.databases_dir,
            "shared_prefs_dir": self.shared_prefs_dir,
            "valid": self.is_valid(),
            "sqlite_count": len(self.all_sqlites()),
            # compatibility keys the templates expect — mapped to Android
            "app_domain": self.app_dir,
            "group_app": self.databases_dir,
            "group_shared": self.shared_prefs_dir,
        }
