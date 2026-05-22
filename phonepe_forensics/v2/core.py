"""Core utilities: bplist decoding, timestamp normalization, console UTF-8."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytz

try:
    from bpylist2 import archiver
except ImportError as e:
    raise SystemExit("bpylist2 is required: pip install bpylist2") from e

IST = pytz.timezone("Asia/Kolkata")


def force_utf8_stdout() -> None:
    """Avoid Windows cp1252 UnicodeEncodeError on ✓ ❌ ₹ characters."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def ro_connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite file strictly read-only via URI mode."""
    p = Path(db_path)
    if not p.exists():
        raise FileNotFoundError(p)
    return sqlite3.connect(f"file:{p}?mode=ro", uri=True)


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes | None) -> str | None:
    if b is None:
        return None
    return hashlib.sha256(b).hexdigest()


def safe_decode_blob(zdata: bytes | None) -> dict | list | None:
    """Decode a ZDATA blob (NSKeyedArchiver bplist) into a Python dict/list.
    Returns None on failure; never raises."""
    if not zdata:
        return None
    try:
        return archiver.unarchive(zdata)
    except Exception:
        return None


def normalize_timestamp_ms(value, fallback_globalpaymentid: str | None = None) -> int | None:
    """Return milliseconds since epoch.

    Accepts ints/floats in either seconds or milliseconds. Falls back to
    decoding a `T<YYMMDDhhmmss>` style globalPaymentId when value is null/zero.
    Returns None if nothing can be derived.
    """
    ts = None
    if value:
        try:
            v = float(value)
            ts = v if v > 1e11 else v * 1000.0  # heuristic: ms if > 10^11
        except (TypeError, ValueError):
            ts = None

    if not ts and fallback_globalpaymentid:
        pid = str(fallback_globalpaymentid)
        if len(pid) >= 13 and pid[0] in "TP":
            try:
                yy, mm, dd = pid[1:3], pid[3:5], pid[5:7]
                hh, mi, ss = pid[7:9], pid[9:11], pid[11:13]
                dt = datetime.strptime(
                    f"20{yy}-{mm}-{dd} {hh}:{mi}:{ss}", "%Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                ts = dt.timestamp() * 1000.0
            except (ValueError, TypeError):
                ts = None
    return int(ts) if ts else None


def ts_ms_to_ist_str(ms: int | None) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000.0, tz=IST).strftime("%Y-%m-%d %H:%M:%S")


def ts_ms_to_utc_str(ms: int | None) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def ts_ms_to_naive_ist(ms: int | None):
    """Excel-friendly naive datetime (tzinfo stripped)."""
    if not ms:
        return None
    return (
        datetime.fromtimestamp(ms / 1000.0, tz=IST)
        .replace(tzinfo=None)
    )


def normalize_phone(raw) -> str | None:
    """Return last 10 digits (Indian mobile) or None."""
    if not raw:
        return None
    digits = "".join(c for c in str(raw) if c.isdigit())
    if not digits:
        return None
    return digits[-10:] if len(digits) >= 10 else digits


def first_or_dict(v):
    """ZDATA fields swing between list and dict. Normalize to a single dict."""
    if isinstance(v, list):
        return v[0] if v else {}
    if isinstance(v, dict):
        return v
    return {}


def find_case_root(start: str | Path) -> Path:
    """Given a path that's either the case root or any DB underneath, return the root
    that contains an `AppDomain-com.phonepe.PhonePeApp/` subtree."""
    p = Path(start).resolve()
    while p != p.parent:
        if (p / "AppDomain-com.phonepe.PhonePeApp").exists():
            return p
        # Some acquisitions place everything under <root>/database
        if (p / "database" / "AppDomain-com.phonepe.PhonePeApp").exists():
            return p / "database"
        p = p.parent
    raise FileNotFoundError(
        f"Could not locate AppDomain-com.phonepe.PhonePeApp anywhere above {start}"
    )


def case_db_path(case_root: Path, relative: str) -> Path | None:
    candidate = Path(case_root) / relative
    return candidate if candidate.exists() else None
