"""
PhonePe iOS Forensics — Core Parsing Engine
==========================================
Handles low-level parsing primitives used by all forensic modules:

    sqlite_reader      WAL-aware read-only SQLite access
    plist_reader       Apple plist (binary + XML)
    BinaryCookieReader Apple Cookies.binarycookies
    bplist_decode      NSKeyedArchiver bplist -> Python dict
    decode_txn_id      PhonePe transaction ID -> embedded timestamp
    Timestamp helpers  Unix-ms / Unix-s / Apple CoreData / ISO

All parsers are defensive: they degrade gracefully on partial corruption,
because forensic acquisitions frequently contain truncated or partially
checkpointed databases.
"""
from __future__ import annotations

import hashlib
import io
import os
import plistlib
import re
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

APPLE_EPOCH_OFFSET = 978_307_200          # seconds from Unix epoch to 2001-01-01
NSDATE_REASONABLE_MIN = 100_000_000        # ~1973 in NSDate seconds
NSDATE_REASONABLE_MAX = 2_000_000_000      # ~2033 in NSDate seconds


def _to_dt(ts_seconds: float) -> datetime:
    return datetime.fromtimestamp(ts_seconds, tz=timezone.utc)


def normalize_timestamp(value: Any) -> Optional[Dict[str, Any]]:
    """Best-effort timestamp interpreter.

    PhonePe iOS data uses three formats interchangeably:
        * Unix milliseconds  (~1.6e12 .. ~1.8e12)  — most SQLite columns
        * Unix seconds float (~1.6e9  .. ~1.8e9)   — some columns and JSON
        * Apple CoreData     (~6e8   .. ~9e8)      — when value < 1e10

    Returns {epoch_ms, iso, source} or None on failure.
    """
    if value is None or value == 0:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None

    # Unix milliseconds
    if v > 1e12:
        epoch_s = v / 1000.0
        source = "unix_ms"
    # Unix seconds (post-2001)
    elif v > 1e9:
        epoch_s = v
        source = "unix_s"
    # Apple CoreData (NSDate seconds since 2001-01-01)
    elif NSDATE_REASONABLE_MIN < v < NSDATE_REASONABLE_MAX:
        epoch_s = v + APPLE_EPOCH_OFFSET
        source = "apple_coredata"
    else:
        return None

    try:
        dt = _to_dt(epoch_s)
    except (OSError, ValueError, OverflowError):
        return None
    return {
        "epoch_ms": int(epoch_s * 1000),
        "iso": dt.isoformat(),
        "display": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
    }


def fmt_ts(value: Any) -> str:
    norm = normalize_timestamp(value)
    return norm["display"] if norm else ""


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_file(path: str, algo: str = "sha256", chunk: int = 65_536) -> str:
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as fh:
            while True:
                data = fh.read(chunk)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# SQLite reader (WAL aware, read-only)
# ---------------------------------------------------------------------------

class SQLiteReader:
    """Open SQLite databases read-only.

    SQLite default behavior is to apply -wal contents on open. We rely on that
    so that uncommitted-but-checkpointed transactions are visible. We never
    write to the database; ``immutable=1`` would skip WAL, so we use ``mode=ro``
    plus ``cache=private`` to avoid sharing connection state across threads.
    """

    def __init__(self, path: str):
        self.path = path
        # forward-slash uri form, stable across Windows & POSIX
        uri = "file:" + path.replace("\\", "/").replace(" ", "%20") + "?mode=ro&cache=private"
        self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self.conn.text_factory = lambda b: b.decode("utf-8", errors="replace") if isinstance(b, bytes) else b

    def close(self):
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # context manager
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- introspection ----
    def tables(self) -> List[str]:
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [r[0] for r in cur.fetchall()]

    def columns(self, table: str) -> List[str]:
        cur = self.conn.execute(f'PRAGMA table_info("{table}")')
        return [r[1] for r in cur.fetchall()]

    def count(self, table: str) -> int:
        try:
            cur = self.conn.execute(f'SELECT COUNT(*) FROM "{table}"')
            return int(cur.fetchone()[0])
        except sqlite3.Error:
            return -1

    def has_table(self, table: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        return cur.fetchone() is not None

    # ---- queries ----
    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        try:
            cur = self.conn.execute(sql, params)
            cols = [d[0] for d in cur.description] if cur.description else []
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            return [{"_error": str(exc)}]

    def iter_rows(self, table: str, columns: Optional[Sequence[str]] = None) -> Iterable[Dict[str, Any]]:
        cols = columns or self.columns(table)
        col_sql = ", ".join(f'"{c}"' for c in cols)
        try:
            cur = self.conn.execute(f'SELECT {col_sql} FROM "{table}"')
            for row in cur:
                yield dict(zip(cols, row))
        except sqlite3.Error:
            return

    # ---- forensic stats ----
    def deletion_signals(self) -> Dict[str, Any]:
        try:
            freelist = int(self.conn.execute("PRAGMA freelist_count").fetchone()[0])
            page_count = int(self.conn.execute("PRAGMA page_count").fetchone()[0])
        except sqlite3.Error:
            return {}
        ratio = (freelist / page_count) if page_count else 0.0
        return {
            "freelist_pages": freelist,
            "total_pages": page_count,
            "free_ratio": round(ratio, 4),
            "deletion_intensity": "high" if ratio > 0.2 else "medium" if ratio > 0.05 else "low",
        }


# ---------------------------------------------------------------------------
# Plist reader (binary + XML)
# ---------------------------------------------------------------------------

def read_plist(path: str) -> Optional[Any]:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def flatten_plist(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Flatten a possibly-nested plist into dotted keys, scalars only."""
    if out is None:
        out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten_plist(v, key, out)
    elif isinstance(value, list):
        for idx, v in enumerate(value):
            flatten_plist(v, f"{prefix}[{idx}]", out)
    elif isinstance(value, (bytes, bytearray)):
        # try secondary bplist decode
        try:
            decoded = plistlib.loads(bytes(value))
            flatten_plist(decoded, prefix + ".__bplist", out)
        except Exception:
            out[prefix] = f"<bytes:{len(value)}>"
    elif isinstance(value, datetime):
        out[prefix] = value.isoformat()
    else:
        out[prefix] = value
    return out


# ---------------------------------------------------------------------------
# Cookies.binarycookies parser (Apple binary cookie format)
# ---------------------------------------------------------------------------

class BinaryCookieReader:
    """Parser for Apple Library/Cookies/Cookies.binarycookies.

    Format reference: a public reverse-engineered spec. We implement a robust
    subset: magic, page count, page sizes, page header, cookies. Each cookie
    has cookie size, flags, url-offset, name-offset, path-offset, value-offset,
    expiry (Mac absolute time), creation (Mac absolute time), and four CSTRINGs.
    """

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.cookies: List[Dict[str, Any]] = []
        self._parse()

    def _read_cstring(self, offset: int) -> str:
        end = self.data.index(b"\x00", offset)
        return self.data[offset:end].decode("utf-8", errors="replace")

    def _parse(self):
        if len(self.data) < 12 or self.data[:4] != b"cook":
            return
        num_pages = struct.unpack(">I", self.data[4:8])[0]
        page_sizes = [
            struct.unpack(">I", self.data[8 + 4 * i: 8 + 4 * i + 4])[0] for i in range(num_pages)
        ]
        cursor = 8 + 4 * num_pages
        for size in page_sizes:
            page = self.data[cursor:cursor + size]
            cursor += size
            self._parse_page(page)

    def _parse_page(self, page: bytes):
        if len(page) < 12 or page[:4] != b"\x00\x00\x01\x00":
            return
        num_cookies = struct.unpack("<I", page[4:8])[0]
        cookie_offsets = [
            struct.unpack("<I", page[8 + 4 * i: 8 + 4 * i + 4])[0] for i in range(num_cookies)
        ]
        for off in cookie_offsets:
            self._parse_cookie(page, off)

    def _parse_cookie(self, page: bytes, offset: int):
        if offset + 56 > len(page):
            return
        size = struct.unpack("<I", page[offset:offset + 4])[0]
        if offset + size > len(page):
            return
        flags = struct.unpack("<I", page[offset + 8:offset + 12])[0]
        url_off = struct.unpack("<I", page[offset + 16:offset + 20])[0]
        name_off = struct.unpack("<I", page[offset + 20:offset + 24])[0]
        path_off = struct.unpack("<I", page[offset + 24:offset + 28])[0]
        value_off = struct.unpack("<I", page[offset + 28:offset + 32])[0]
        # 8 reserved bytes here in spec, then 8-byte expiry double, 8-byte creation double
        expiry = struct.unpack("<d", page[offset + 40:offset + 48])[0]
        creation = struct.unpack("<d", page[offset + 48:offset + 56])[0]

        def _safe_cstr(rel: int) -> str:
            try:
                end = page.index(b"\x00", offset + rel)
                return page[offset + rel:end].decode("utf-8", errors="replace")
            except ValueError:
                return ""

        flag_names = []
        if flags & 0x1: flag_names.append("Secure")
        if flags & 0x4: flag_names.append("HTTPOnly")

        self.cookies.append({
            "domain": _safe_cstr(url_off),
            "name": _safe_cstr(name_off),
            "path": _safe_cstr(path_off),
            "value": _safe_cstr(value_off),
            "flags": flag_names,
            "expiry_iso": _to_dt(expiry + APPLE_EPOCH_OFFSET).isoformat() if NSDATE_REASONABLE_MIN < expiry < NSDATE_REASONABLE_MAX else None,
            "creation_iso": _to_dt(creation + APPLE_EPOCH_OFFSET).isoformat() if NSDATE_REASONABLE_MIN < creation < NSDATE_REASONABLE_MAX else None,
            "expiry_epoch": expiry,
            "creation_epoch": creation,
        })


# ---------------------------------------------------------------------------
# NSKeyedArchiver bplist decoder
# ---------------------------------------------------------------------------

class _Uid:
    __slots__ = ("value",)

    def __init__(self, v):
        self.value = v


def _resolve(obj: Any, objects: List[Any], seen: Optional[set] = None) -> Any:
    if seen is None:
        seen = set()
    if isinstance(obj, plistlib.UID):
        if obj.data in seen:
            return f"<cycle:{obj.data}>"
        seen = seen | {obj.data}
        return _resolve(objects[obj.data], objects, seen)
    if isinstance(obj, dict):
        if "$class" in obj and "NS.keys" in obj and "NS.objects" in obj:
            keys = [_resolve(k, objects, seen) for k in obj["NS.keys"]]
            vals = [_resolve(v, objects, seen) for v in obj["NS.objects"]]
            return dict(zip(keys, vals))
        if "$class" in obj and "NS.objects" in obj:
            return [_resolve(v, objects, seen) for v in obj["NS.objects"]]
        if "$class" in obj and "NS.string" in obj:
            return _resolve(obj["NS.string"], objects, seen)
        return {k: _resolve(v, objects, seen) for k, v in obj.items() if k != "$class"}
    if isinstance(obj, list):
        return [_resolve(v, objects, seen) for v in obj]
    if isinstance(obj, bytes):
        # try nested bplist
        try:
            inner = plistlib.loads(obj)
            if isinstance(inner, dict) and inner.get("$archiver") == "NSKeyedArchiver":
                return decode_nskeyedarchiver(obj)
        except Exception:
            pass
        return obj
    return obj


def decode_nskeyedarchiver(blob: bytes) -> Any:
    """Decode an NSKeyedArchiver bplist BLOB into a plain Python structure."""
    if not blob:
        return None
    try:
        plist = plistlib.loads(bytes(blob))
    except Exception:
        return None
    if not isinstance(plist, dict) or plist.get("$archiver") != "NSKeyedArchiver":
        return plist
    objects = plist.get("$objects", [])
    top = plist.get("$top", {})
    if not isinstance(top, dict):
        return plist
    root_uid = top.get("root")
    if isinstance(root_uid, plistlib.UID):
        return _resolve(root_uid, objects)
    return _resolve(top, objects)


def safe_decode_blob(blob: Any) -> Any:
    """Safely decode a SQLite BLOB column.

    Tries (in order): NSKeyedArchiver, regular bplist, JSON, raw text.
    Returns the Python representation or a {'_raw': len, '_hex': preview} stub.
    """
    if blob is None:
        return None
    if isinstance(blob, str):
        # already string — try JSON
        s = blob.strip()
        if s and s[0] in "{[":
            try:
                import json
                return json.loads(s)
            except Exception:
                return blob
        return blob
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return blob
    raw = bytes(blob)
    if not raw:
        return None
    # NSKeyedArchiver?
    if raw[:8] == b"bplist00":
        decoded = decode_nskeyedarchiver(raw)
        if decoded is not None:
            return decoded
        try:
            return plistlib.loads(raw)
        except Exception:
            pass
    # JSON?
    try:
        return _try_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    # Last-resort hex preview
    return {"_raw_size": len(raw), "_hex_preview": raw[:64].hex()}


def _try_json(text: str) -> Any:
    import json
    text = text.strip()
    if not text:
        return text
    if text[0] in "{[":
        return json.loads(text)
    return text


# ---------------------------------------------------------------------------
# PhonePe transaction ID decoder
# ---------------------------------------------------------------------------

# PhonePe iOS transaction IDs follow the pattern T<YY><MM><DD><HH><MM><SS><digits>
#   T2502241950445948970469  -> 25/02/24 19:50:44 + 5948970469 (server seq + node)
# Group IDs use a different scheme: GP<32 hex chars>
# Refund IDs prefix: R<TXN-ID>
_TXN_ID_RX = re.compile(r"^[TR]?(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\d+$")


def decode_txn_id(txn_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not txn_id or not isinstance(txn_id, str):
        return None
    m = _TXN_ID_RX.match(txn_id.strip())
    if not m:
        return None
    yy, mm, dd, hh, mn, ss = (int(g) for g in m.groups())
    year = 2000 + yy if yy < 70 else 1900 + yy
    try:
        dt = datetime(year, mm, dd, hh, mn, ss, tzinfo=timezone.utc)
    except ValueError:
        return None
    return {
        "embedded_iso": dt.isoformat(),
        "embedded_epoch_ms": int(dt.timestamp() * 1000),
        "year": year,
        "month": mm,
        "day": dd,
    }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def amount_to_rupees(paise: Any) -> Optional[float]:
    """PhonePe stores amounts in paise (1/100 INR) as integers."""
    n = safe_int(paise, default=-1)
    if n < 0:
        return None
    return round(n / 100.0, 2)


def first_match(rx_pattern: str, text: str) -> Optional[str]:
    m = re.search(rx_pattern, text)
    return m.group(1) if m else None


def find_files(root: str, suffixes: Sequence[str]) -> List[str]:
    out: List[str] = []
    for r, _, files in os.walk(root):
        for f in files:
            for s in suffixes:
                if f.endswith(s):
                    out.append(os.path.join(r, f))
                    break
    return out


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# ---------------------------------------------------------------------------
# Path resolver
# ---------------------------------------------------------------------------

class CasePaths:
    """Locate the three iOS containers and resolve known artifact paths.

    Initialise with the parent directory containing the AppDomain* folders
    (or pass the AppDomain folder directly). The resolver finds the three
    canonical containers regardless of the parent's casing/structure.
    """

    AD = "AppDomain-com.phonepe.PhonePeApp"
    ADG_APP = "AppDomainGroup-group.com.phonepe.PhonePeApp"
    ADG_SHARED = "AppDomainGroup-group.com.phonepe.shared"

    def __init__(self, root: str):
        root = os.path.abspath(root)
        self.root = root
        self.app_domain = self._find_container(root, self.AD)
        self.group_app = self._find_container(root, self.ADG_APP)
        self.group_shared = self._find_container(root, self.ADG_SHARED)

    @staticmethod
    def _find_container(root: str, name: str) -> Optional[str]:
        # Direct path
        cand = os.path.join(root, name)
        if os.path.isdir(cand):
            return cand
        # Walk one level up
        parent = os.path.dirname(root)
        if parent and parent != root:
            cand = os.path.join(parent, name)
            if os.path.isdir(cand):
                return cand
        # Walk from root
        for entry in os.listdir(root) if os.path.isdir(root) else []:
            full = os.path.join(root, entry)
            if entry == name and os.path.isdir(full):
                return full
        return None

    def is_valid(self) -> bool:
        return all([self.app_domain, self.group_app or self.group_shared])

    def documents(self) -> Optional[str]:
        return os.path.join(self.app_domain, "Documents") if self.app_domain else None

    def preferences(self) -> Optional[str]:
        return os.path.join(self.app_domain, "Library", "Preferences") if self.app_domain else None

    def cookies_path(self) -> Optional[str]:
        if not self.app_domain:
            return None
        p = os.path.join(self.app_domain, "Library", "Cookies", "Cookies.binarycookies")
        return p if os.path.exists(p) else None

    def webkit_dir(self) -> Optional[str]:
        if not self.app_domain:
            return None
        p = os.path.join(self.app_domain, "Library", "WebKit")
        return p if os.path.isdir(p) else None

    def resolve(self, *parts: str) -> Optional[str]:
        if not self.app_domain:
            return None
        path = os.path.join(self.app_domain, *parts)
        return path if os.path.exists(path) else None

    def group(self, *parts: str) -> Optional[str]:
        if not self.group_app:
            return None
        path = os.path.join(self.group_app, *parts)
        return path if os.path.exists(path) else None

    def all_sqlites(self) -> List[str]:
        out: List[str] = []
        for base in (self.app_domain, self.group_app, self.group_shared):
            if base:
                out.extend(find_files(base, [".sqlite", ".db"]))
        return out

    def all_plists(self) -> List[str]:
        out: List[str] = []
        for base in (self.app_domain, self.group_app, self.group_shared):
            if base:
                out.extend(find_files(base, [".plist"]))
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "app_domain": self.app_domain,
            "group_app": self.group_app,
            "group_shared": self.group_shared,
            "valid": self.is_valid(),
            "sqlite_count": len(self.all_sqlites()),
            "plist_count": len(self.all_plists()),
        }
