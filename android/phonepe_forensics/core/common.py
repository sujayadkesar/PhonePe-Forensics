"""
PhonePe Forensics — platform-neutral parsing primitives
=======================================================
Everything here is true of any acquisition, on any platform:

    SQLiteReader / snapshots   read evidence databases without modifying them
    Timestamp helpers          Unix-ms / Unix-s / Apple CoreData -> UTC ISO-8601
    hash_file                  SHA-256 for the chain-of-custody manifest
    decode_txn_id              PhonePe transaction ID -> embedded wall clock
    safe_int / amount_to_rupees / find_files ...

Platform-specific parsing lives in ``core.ios`` and ``core.android``. Keeping the
split explicit is what lets the Android build take fixes from upstream without
vendoring a private copy of the shared engine.

All parsers are defensive: they degrade gracefully on partial corruption, because
forensic acquisitions frequently contain truncated or partially checkpointed
databases.
"""
from __future__ import annotations

import atexit
import hashlib
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

APPLE_EPOCH_OFFSET = 978_307_200          # seconds from Unix epoch to 2001-01-01
NSDATE_REASONABLE_MIN = 100_000_000        # ~1973 in NSDate seconds
NSDATE_REASONABLE_MAX = 2_000_000_000      # ~2033 in NSDate seconds

# Anything past 2100-01-01 is a mis-scaled value, not a real event. Without this
# bound a 1e11 column is read as unix seconds and lands in the year 5138.
EPOCH_S_MAX = 4_102_444_800                # 2100-01-01T00:00:00Z, seconds
EPOCH_MS_MAX = EPOCH_S_MAX * 1000

# Every timestamp this tool emits is UTC. It is stated explicitly in `display`
# and `tz` because a bare "14:17:56" in an IST jurisdiction is a 5h30m error.
DISPLAY_TZ = "UTC"


def _to_dt(ts_seconds: float) -> datetime:
    return datetime.fromtimestamp(ts_seconds, tz=timezone.utc)


def _ts_dict(epoch_s: float, source: str) -> Optional[Dict[str, Any]]:
    try:
        dt = _to_dt(epoch_s)
    except (OSError, ValueError, OverflowError):
        return None
    return {
        "epoch_ms": int(round(epoch_s * 1000)),
        "iso": dt.isoformat(),                                    # 2026-07-25T14:17:56+00:00
        "display": dt.strftime("%Y-%m-%d %H:%M:%S ") + DISPLAY_TZ,
        "tz": DISPLAY_TZ,
        "source": source,
    }


def normalize_timestamp(value: Any) -> Optional[Dict[str, Any]]:
    """Best-effort timestamp interpreter.

    PhonePe data may use several timestamp formats (Android data is Unix-ms):
        * Unix milliseconds  (~1.6e12 .. ~1.8e12)  — most SQLite columns
        * Unix seconds float (~1.6e9  .. ~1.8e9)   — some columns and JSON
        * CoreData seconds   (~6e8   .. ~9e8)      — when value < 1e10

    Returns {epoch_ms, iso, display, tz, source} or None when the value cannot be
    interpreted as a real-world instant between 1973 and 2100.
    """
    if value is None or value == 0:
        return None
    if isinstance(value, bool):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None

    # Unix milliseconds
    if v > 1e12:
        if v > EPOCH_MS_MAX:
            return None
        epoch_s = v / 1000.0
        source = "unix_ms"
    # Unix seconds (post-2001)
    elif v > 1e9:
        if v > EPOCH_S_MAX:
            return None
        epoch_s = v
        source = "unix_s"
    # Apple CoreData (NSDate seconds since 2001-01-01)
    elif NSDATE_REASONABLE_MIN < v < NSDATE_REASONABLE_MAX:
        epoch_s = v + APPLE_EPOCH_OFFSET
        source = "apple_coredata"
    else:
        return None

    return _ts_dict(epoch_s, source)


def fmt_ts(value: Any) -> str:
    norm = normalize_timestamp(value)
    return norm["display"] if norm else ""


# ---------------------------------------------------------------------------
# Transaction state vocabulary
# ---------------------------------------------------------------------------
#
# Lives here, in the platform-neutral core, because BOTH the parser (deciding what
# to sum into a module summary) and the correlator (deciding what to flag) need the
# same answer. It previously existed only as inline literals repeated at five call
# sites in the correlator, which produced two bugs: ``ERRORED`` — the state Android
# actually writes for a failed payment — was missing from the failed set, so real
# failed payments raised no finding; and the correlator's comparisons were
# case-sensitive while the extractor's were not.
#
# Keeping it here also preserves the dependency direction the extractors follow
# (parser -> core, never parser -> correlator).
#
# Anything in neither set is neither summed nor flagged, which is the safe default
# for a state this tool has not seen — and is reported rather than ignored.

SUCCESS_STATES = frozenset({"COMPLETED", "SUCCESS", "SETTLED", "SUCCEEDED"})

#: States meaning the payment did not complete. ERRORED is Android's; the rest are
#: kept so the shared engine stays usable for iOS acquisitions.
FAILED_STATES = frozenset({
    "ERRORED", "ERROR", "FAILED", "FAILURE", "REJECTED", "DECLINED",
    "CANCELLED", "CANCELED", "TIMED_OUT", "EXPIRED",
})

#: In-flight rather than failed, but reported alongside: a payment still pending at
#: acquisition time is as interesting as one that failed.
PENDING_STATES = frozenset({"PENDING", "IN_PROGRESS", "INITIATED", "CREATED"})


def normalise_state(value: Any) -> str:
    return str(value or "").strip().upper()


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
# Evidence snapshots
# ---------------------------------------------------------------------------
#
# Forensic acquisitions are normally mounted read-only, and the container must
# come back byte-identical to the manifest taken at seizure. That rules out
# SQLite's default open path: `mode=ro` still needs to create a `-shm` file next
# to the database to read a WAL, which both fails on write-protected media and
# mutates the evidence folder when it succeeds.
#
# So: hash the original db + every sidecar, copy the whole set to a scratch dir,
# and let SQLite recover the WAL against the *copy*. The evidence is opened for
# reading only and is never written to. Databases with no WAL/journal sidecar
# skip the copy entirely and open with `immutable=1`, which SQLite guarantees
# will not create or modify any file.

_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

_snapshot_root: Optional[str] = None
_snapshots: Dict[str, "EvidenceSnapshot"] = {}
_snapshot_lock = threading.RLock()


class EvidenceSnapshot:
    """Record of how one evidence database was made readable, and its hashes."""

    __slots__ = ("original", "working", "hashes", "sidecars", "copied",
                 "wal_present", "wal_applied", "degraded")

    def __init__(self, original: str, working: str, hashes: Dict[str, str],
                 sidecars: List[str], copied: bool, wal_present: bool,
                 wal_applied: bool, degraded: Optional[str]):
        self.original = original
        self.working = working
        self.hashes = hashes
        self.sidecars = sidecars
        self.copied = copied
        self.wal_present = wal_present
        self.wal_applied = wal_applied
        self.degraded = degraded

    def as_dict(self) -> Dict[str, Any]:
        return {
            "original": self.original,
            "sha256": self.hashes.get(os.path.basename(self.original), ""),
            "sidecar_hashes": {k: v for k, v in self.hashes.items()
                               if k != os.path.basename(self.original)},
            "sidecars": self.sidecars,
            "opened_via": "scratch copy" if self.copied else "immutable (in place)",
            "wal_present": self.wal_present,
            "wal_applied": self.wal_applied,
            "warning": self.degraded,
        }


def _scratch_root() -> str:
    global _snapshot_root
    if _snapshot_root is None:
        _snapshot_root = tempfile.mkdtemp(prefix="ppforensics-evidence-")
        atexit.register(shutil.rmtree, _snapshot_root, True)
    return _snapshot_root


def _snapshot_key(path: str) -> str:
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
        return f"{real}|{st.st_size}|{st.st_mtime_ns}"
    except OSError:
        return real


def snapshot_database(path: str) -> EvidenceSnapshot:
    """Hash a database + its sidecars, and stage a working copy when a WAL or
    rollback journal exists. Cached per (path, size, mtime) for the process."""
    key = _snapshot_key(path)
    with _snapshot_lock:
        cached = _snapshots.get(key)
        if cached is not None:
            return cached

        base = os.path.basename(path)
        sidecars = [s for s in _SIDECAR_SUFFIXES if os.path.exists(path + s)]
        hashes = {base: hash_file(path)}
        for s in sidecars:
            hashes[base + s] = hash_file(path + s)
        # -shm is a pure rebuildable index; only -wal/-journal hold committed data
        # that would be invisible to an immutable open.
        wal_present = any(s in ("-wal", "-journal") for s in sidecars)

        if not wal_present:
            snap = EvidenceSnapshot(path, path, hashes, sidecars, False, False, False, None)
        else:
            try:
                dest_dir = tempfile.mkdtemp(dir=_scratch_root())
                working = os.path.join(dest_dir, base)
                shutil.copy2(path, working)
                for s in sidecars:
                    shutil.copy2(path + s, working + s)
                snap = EvidenceSnapshot(path, working, hashes, sidecars, True, True, True, None)
            except OSError as exc:
                snap = EvidenceSnapshot(
                    path, path, hashes, sidecars, False, True, False,
                    f"Could not stage a working copy ({exc}); opened in place with "
                    f"immutable=1, so records held only in {'/'.join(sidecars)} are "
                    f"NOT included in this analysis.",
                )
        _snapshots[key] = snap
        return snap


def _under(path: str, root: Optional[str]) -> bool:
    """True when `path` belongs to `root` (or root is unset)."""
    if not root:
        return True
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) \
            == os.path.realpath(root)
    except (ValueError, OSError):
        return False


def evidence_manifest(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Databases opened, with the hashes taken before parsing.

    Scoped to `root`, because the snapshot cache is process-wide: an analyst who
    opens a second case would otherwise get the first case's files listed in the
    second case's custody manifest.
    """
    with _snapshot_lock:
        snaps = list(_snapshots.values())
    return sorted((s.as_dict() for s in snaps if _under(s.original, root)),
                  key=lambda e: e["original"])


def evidence_warnings(root: Optional[str] = None) -> List[str]:
    """Integrity warnings the UI must show (e.g. WAL content excluded)."""
    with _snapshot_lock:
        snaps = list(_snapshots.values())
    return [f"{os.path.basename(s.original)}: {s.degraded}"
            for s in snaps if s.degraded and _under(s.original, root)]


# Columns an extractor asked for that this acquisition's schema does not have.
# Recorded globally so every hard-coded SELECT is covered without each extractor
# having to thread the information back out by hand.
_schema_gaps: Dict[Tuple[str, str], set] = {}


def _record_schema_gap(db_path: str, table: str, missing: Iterable[str]) -> None:
    with _snapshot_lock:
        _schema_gaps.setdefault((db_path, table), set()).update(missing)


def schema_gaps(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Requested-but-absent columns, grouped by database and table.

    Scoped to `root` for the same reason the manifest is: the registry outlives
    any one case.
    """
    with _snapshot_lock:
        items = sorted(_schema_gaps.items())
    return [{"database": os.path.basename(db), "database_path": db, "table": table,
             "missing_columns": sorted(cols)}
            for (db, table), cols in items if _under(db, root)]


# `SELECT a, b, c FROM tbl <rest>` — the shape every extractor query uses. Only
# this shape is rewritten; anything with a function call, a star, or a join is
# passed through untouched.
_SIMPLE_SELECT_RX = re.compile(
    r'^\s*SELECT\s+(?P<cols>[^()*]+?)\s+FROM\s+"?(?P<table>[A-Za-z_]\w*)"?(?P<rest>\s+.*)?$',
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# SQLite reader (WAL aware, never writes to evidence)
# ---------------------------------------------------------------------------

class SQLiteReader:
    """Open an evidence SQLite database without modifying it.

    Databases carrying a `-wal` or `-journal` are staged to a scratch copy and
    recovered there, so WAL-resident records are visible; everything else opens
    in place with `immutable=1`. Either way the connection is switched to
    `query_only` once the schema has been read, so no query can mutate anything.
    """

    def __init__(self, path: str, snapshot: bool = True):
        self.path = path
        self.snapshot = snapshot_database(path) if snapshot else None
        self.missing_columns: Dict[str, List[str]] = {}
        working = self.snapshot.working if self.snapshot else path
        immutable = not (self.snapshot and self.snapshot.copied)
        uri = Path(os.path.abspath(working)).as_uri()
        uri += "?immutable=1&cache=private" if immutable else "?cache=private"
        self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self.conn.text_factory = lambda b: b.decode("utf-8", errors="replace") if isinstance(b, bytes) else b
        if not immutable:
            # Touch the schema so SQLite recovers the WAL into the copy, then bar
            # writes for the rest of the connection's life.
            try:
                self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
                self.conn.execute("PRAGMA query_only=ON")
            except sqlite3.Error:
                pass

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
        try:
            cur = self.conn.execute(f'PRAGMA table_info("{table}")')
        except sqlite3.Error:
            return []
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
    def _prune_absent_columns(self, sql: str) -> Tuple[str, List[str]]:
        """Drop columns this acquisition's schema doesn't have from a simple SELECT.

        PhonePe changes its Room schema with every release. A hard-coded column
        list means one renamed column returns `no such column` for the whole
        query, and the evidence page renders empty as though the data were never
        there. Narrowing the projection degrades to partial data instead, and the
        dropped columns are recorded so the UI can report the gap.
        """
        m = _SIMPLE_SELECT_RX.match(sql)
        if not m:
            return sql, []
        raw_cols = [c.strip() for c in m.group("cols").split(",")]
        if not all(re.fullmatch(r'"?[A-Za-z_]\w*"?', c) for c in raw_cols):
            return sql, []          # aliases / expressions — leave it alone
        table = m.group("table")
        available = {c.lower() for c in self.columns(table)}
        if not available:
            return sql, []          # no such table; let the real error surface
        kept, missing = [], []
        for c in raw_cols:
            (kept if c.strip('"').lower() in available else missing).append(c)
        if not kept and missing:
            # Every requested column is gone. The query is left untouched so SQLite's
            # own "no such column" surfaces as an extraction error, but the gap is
            # still recorded: without this the Audit page showed no schema gap for
            # the very worst case of drift, where a whole projection went missing.
            self.missing_columns.setdefault(table, []).extend(
                s.strip('"') for s in missing)
            _record_schema_gap(self.path, table, (s.strip('"') for s in missing))
            return sql, missing
        if not missing:
            return sql, missing
        self.missing_columns.setdefault(table, []).extend(s.strip('"') for s in missing)
        _record_schema_gap(self.path, table, (s.strip('"') for s in missing))
        # Quote the kept names: a column called `rank`, `filter` or `key` parses
        # fine in the original text but not always once we re-emit it.
        quoted = ", ".join('"%s"' % c.strip('"') for c in kept)
        rebuilt = f'SELECT {quoted} FROM "{table}"{m.group("rest") or ""}'
        return rebuilt, missing

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        effective, missing = self._prune_absent_columns(sql)
        try:
            cur = self.conn.execute(effective, params)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            return [{"_error": str(exc)}]
        # Keep the .get() contract callers rely on: absent columns read as None.
        if missing and effective != sql:
            blanks = {c.strip('"'): None for c in missing}
            for r in rows:
                for k, v in blanks.items():
                    r.setdefault(k, v)
        return rows

    def query_rows(self, sql: str, params: Sequence[Any] = (),
                   max_rows: int = 1000) -> Tuple[List[Dict[str, Any]], List[str], bool]:
        """Run an arbitrary query and take at most `max_rows` rows.

        Capping at fetch time (rather than appending ` LIMIT n` to the user's SQL)
        is what makes PRAGMA, EXPLAIN, and queries with their own LIMIT work.
        Returns (rows, columns, truncated).
        """
        cur = self.conn.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        fetched = cur.fetchmany(max_rows + 1)
        truncated = len(fetched) > max_rows
        rows = [dict(zip(cols, r)) for r in fetched[:max_rows]]
        return rows, cols, truncated

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
# PhonePe transaction ID decoder
# ---------------------------------------------------------------------------

# PhonePe transaction IDs follow the pattern T<YY><MM><DD><HH><MM><SS><digits>
#   T<YYMMDD><HHMMSS><server-seq+node>  e.g. the leading 12 digits decode to a
#   wall-clock timestamp; the trailing digits are an opaque server sequence + node id.
# Group IDs use a different scheme: GP<32 hex chars>
# Refund IDs prefix: R<TXN-ID>
_TXN_ID_RX = re.compile(r"^[TR]?(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\d+$")

# The timezone PhonePe's issuing server stamps into the ID is not documented and
# has not been validated against a ground-truth transaction. Reported values are
# the raw wall-clock digits; the epoch conversion assumes UTC and carries this
# caveat so it is never silently trusted as a corroborating timestamp.
TXN_ID_TZ_CAVEAT = (
    "Wall-clock digits as issued by the PhonePe server. Server timezone is "
    "undocumented and unvalidated (IST is plausible); the epoch value below "
    "assumes UTC and may be offset by the server's true zone."
)


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
        "embedded_wallclock": dt.strftime("%Y-%m-%d %H:%M:%S"),
        "embedded_iso": dt.isoformat(),
        "embedded_epoch_ms": int(dt.timestamp() * 1000),
        "tz_assumed": "UTC (unvalidated)",
        "tz_caveat": TXN_ID_TZ_CAVEAT,
        "year": year,
        "month": mm,
        "day": dd,
    }


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def safe_int(v: Any, default: int = 0) -> int:
    # bool is an int subclass, so a True in an amount or timestamp column would
    # otherwise read as the value 1 — i.e. ₹0.01 for a paise column. A boolean is
    # not a number here; treat it as absent.
    if isinstance(v, bool):
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def tri_bool(v: Any) -> Optional[bool]:
    """True / False / None — never inventing False out of an absent value.

    `bool(row.get("someFlag"))` is the wrong coercion for evidence: a NULL column,
    a JSON key the record does not carry, and a stored `0` all collapse to False,
    which reports "this is not the case" where the evidence says nothing at all.
    Keep the three states distinct here and let the presentation layer decide how
    to show unknown (`yes_no` renders it "—").

    Strings are handled because shared_prefs XML and some JSON payloads store
    booleans as text, and every non-empty string is truthy — so "false" would
    otherwise be True. An unrecognised string is unknown rather than a guess.
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "1"):
            return True
        if s in ("false", "no", "0"):
            return False
        return None
    if isinstance(v, (int, float)):
        return bool(v)
    return None


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

