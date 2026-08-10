"""
PhonePe Android Forensics — Deleted-record carving
==================================================
Recovers records that SQLite no longer indexes but has not yet overwritten.

Deleting a row does not erase it. SQLite unlinks the cell and adds its bytes to
one of four pools, all of which usually still hold the original payload:

    freelist pages     whole pages released back to the database
    freeblocks         gaps inside a live page, chained from the page header
    page slack         the unallocated middle of a live page, between the cell
                       pointer array and the cell content area
    WAL / journal      superseded images of pages, holding pre-delete content

This module walks all four, brute-force scans them for SQLite record headers,
and decodes any that match a known table's shape. That is where deleted
``chatMessage`` and ``transaction_core`` rows actually live.

Forensic constraints this implementation holds to:

  * Nothing is asserted that cannot be shown. Every recovered record carries the
    pool it came from, the page number, the byte offset, and how it was matched.
  * A record whose column shape fits several tables is reported against ALL of
    them and flagged ambiguous, never silently assigned to one.
  * Records still present in the live table are excluded — those are stale page
    copies, not deletions. Only what is genuinely gone is reported as recovered.
  * Partially overwritten records are decoded as far as they parse and marked
    truncated, rather than dropped or padded.
  * Whether freed content survived is reported from what was actually recovered,
    not from ``PRAGMA secure_delete`` — that pragma is per-connection and would
    describe the examining build, not the phone that did the deleting.
  * An empty result is never presented as proof that nothing was deleted.
"""
from __future__ import annotations

import os
import struct
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .core import SQLiteReader, hash_file

# ---------------------------------------------------------------------------
# SQLite primitives
# ---------------------------------------------------------------------------

PAGE_LEAF_TABLE = 0x0D
PAGE_INTERIOR_TABLE = 0x05
PAGE_LEAF_INDEX = 0x0A
PAGE_INTERIOR_INDEX = 0x02

_TEXT_ENCODINGS = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}


def read_varint(buf: bytes, off: int) -> Tuple[int, int]:
    """SQLite's big-endian base-128 varint. Returns (value, next_offset)."""
    value = 0
    for i in range(8):
        if off + i >= len(buf):
            raise ValueError("varint runs past end of buffer")
        byte = buf[off + i]
        if byte & 0x80:
            value = (value << 7) | (byte & 0x7F)
        else:
            return (value << 7) | byte, off + i + 1
    if off + 8 >= len(buf):
        raise ValueError("varint runs past end of buffer")
    return (value << 8) | buf[off + 8], off + 9


def serial_type_size(stype: int) -> int:
    if stype in (0, 8, 9):
        return 0
    if stype in (1, 2, 3, 4):
        return stype
    if stype == 5:
        return 6
    if stype in (6, 7):
        return 8
    if stype in (10, 11):
        return -1          # internal use only; never valid in a real record
    return (stype - 12) // 2 if stype % 2 == 0 else (stype - 13) // 2


def decode_serial(stype: int, buf: bytes, off: int, encoding: str) -> Any:
    size = serial_type_size(stype)
    if stype == 0:
        return None
    if stype == 8:
        return 0
    if stype == 9:
        return 1
    if stype in (1, 2, 3, 4, 5, 6):
        return int.from_bytes(buf[off:off + size], "big", signed=True)
    if stype == 7:
        return struct.unpack(">d", buf[off:off + 8])[0]
    raw = buf[off:off + size]
    if stype % 2 == 0:                       # BLOB
        return raw
    try:                                     # TEXT
        return raw.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


# Which serial types are plausible for a declared column affinity. Used to score
# a candidate record against a table, not to reject data outright.
_INT_TYPES = {0, 1, 2, 3, 4, 5, 6, 8, 9}
_REAL_TYPES = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}


def _affinity(decl_type: Optional[str]) -> str:
    """SQLite's column-affinity rules (§3 of the datatype documentation)."""
    t = (decl_type or "").upper()
    if "INT" in t:
        return "INTEGER"
    if "CHAR" in t or "CLOB" in t or "TEXT" in t:
        return "TEXT"
    if "BLOB" in t or not t:
        return "BLOB"
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return "REAL"
    return "NUMERIC"


def _type_ok(affinity: str, stype: int) -> bool:
    if stype == 0:
        return True                          # NULL fits any column
    if affinity == "INTEGER":
        return stype in _INT_TYPES
    if affinity == "REAL" or affinity == "NUMERIC":
        return stype in _REAL_TYPES or stype >= 12
    if affinity == "TEXT":
        return stype >= 13 and stype % 2 == 1
    return True                              # BLOB / untyped accepts anything


# ---------------------------------------------------------------------------
# Candidate regions
# ---------------------------------------------------------------------------

class Region:
    """Where to look for freed records, and the page they live in.

    `page` is the whole page image and `start`/`end` bound the part of it that is
    unallocated. Decoding reads from the full page, not just the bounded slice: a
    freed record often begins inside a freeblock and runs past its end, and
    clipping it there would report a truncated row where a complete one survives.
    """

    __slots__ = ("pool", "page_no", "page", "start", "end", "file_base", "source")

    def __init__(self, pool: str, page_no: int, page: bytes, start: int, end: int,
                 file_base: int, source: str):
        self.pool = pool           # freelist | freeblock | page-slack | wal | journal | superseded
        self.page_no = page_no
        self.page = page
        self.start = start
        self.end = end
        self.file_base = file_base  # file offset of page[0]
        self.source = source


class SQLiteCarver:
    """Reads a database's unallocated space and recovers records from it."""

    # A record needs at least a header byte plus one serial type.
    MIN_RECORD_BYTES = 4

    def __init__(self, db_path: str, wal_path: Optional[str] = None,
                 journal_path: Optional[str] = None):
        self.db_path = db_path
        self.wal_path = wal_path if wal_path and os.path.exists(wal_path) else None
        self.journal_path = (journal_path if journal_path and os.path.exists(journal_path)
                             else None)
        with open(db_path, "rb") as fh:
            self.data = fh.read()
        if len(self.data) < 100 or self.data[:15] != b"SQLite format 3":
            raise ValueError("not a SQLite database")
        raw_page_size = struct.unpack(">H", self.data[16:18])[0]
        self.page_size = 65536 if raw_page_size == 1 else raw_page_size
        self.reserved = self.data[20]
        self.page_count = struct.unpack(">I", self.data[28:32])[0] or \
            (len(self.data) // self.page_size)
        self.freelist_trunk = struct.unpack(">I", self.data[32:36])[0]
        self.freelist_count = struct.unpack(">I", self.data[36:40])[0]
        self.encoding = _TEXT_ENCODINGS.get(
            struct.unpack(">I", self.data[56:60])[0], "utf-8")
        self.notes: List[str] = []

    # ---- page access ----
    def page(self, page_no: int) -> bytes:
        if page_no < 1:
            return b""
        start = (page_no - 1) * self.page_size
        return self.data[start:start + self.page_size]

    def _page_header_offset(self, page_no: int) -> int:
        # Page 1 carries the 100-byte database header before its page header.
        return 100 if page_no == 1 else 0

    def _usable_size(self) -> int:
        return self.page_size - self.reserved

    # ---- pool 1: freelist ----
    def freelist_pages(self) -> List[int]:
        """Every page on the freelist, following the trunk chain."""
        pages: List[int] = []
        seen: set = set()
        trunk = self.freelist_trunk
        while trunk and trunk not in seen and trunk <= self.page_count:
            seen.add(trunk)
            buf = self.page(trunk)
            if len(buf) < 8:
                break
            pages.append(trunk)
            next_trunk = struct.unpack(">I", buf[0:4])[0]
            n_leaves = struct.unpack(">I", buf[4:8])[0]
            # A corrupt count would make us read the whole page as pointers.
            n_leaves = min(n_leaves, (self._usable_size() - 8) // 4)
            for i in range(n_leaves):
                leaf = struct.unpack(">I", buf[8 + 4 * i:12 + 4 * i])[0]
                if 0 < leaf <= self.page_count and leaf not in seen:
                    seen.add(leaf)
                    pages.append(leaf)
            trunk = next_trunk
        return pages

    # ---- pool 2 + 3: freeblocks and slack inside live pages ----
    def _live_page_regions(self, page_no: int, buf: Optional[bytes] = None,
                           pool_prefix: str = "", source: Optional[str] = None,
                           file_base: Optional[int] = None) -> Iterator[Region]:
        if buf is None:
            buf = self.page(page_no)
        if len(buf) < 12:
            return
        hdr = self._page_header_offset(page_no)
        ptype = buf[hdr]
        if ptype not in (PAGE_LEAF_TABLE, PAGE_LEAF_INDEX):
            return
        first_free = struct.unpack(">H", buf[hdr + 1:hdr + 3])[0]
        n_cells = struct.unpack(">H", buf[hdr + 3:hdr + 5])[0]
        content_start = struct.unpack(">H", buf[hdr + 5:hdr + 7])[0] or 65536
        ptr_array_end = hdr + 8 + 2 * n_cells
        base = (page_no - 1) * self.page_size if file_base is None else file_base
        src = source or self.db_path

        # Slack: the unallocated middle of the page, between the cell pointer
        # array and the cell content area. Freed cells survive here until the
        # page is next compacted.
        if content_start > ptr_array_end and content_start <= len(buf):
            if content_start - ptr_array_end >= self.MIN_RECORD_BYTES:
                yield Region(pool_prefix + "page-slack", page_no, buf,
                             ptr_array_end, content_start, base, src)

        # Freeblock chain: cell bodies released inside the content area.
        seen: set = set()
        off = first_free
        while 0 < off < len(buf) - 3 and off not in seen:
            seen.add(off)
            next_off = struct.unpack(">H", buf[off:off + 2])[0]
            size = struct.unpack(">H", buf[off + 2:off + 4])[0]
            if size < 4 or off + size > len(buf):
                break
            yield Region(pool_prefix + "freeblock", page_no, buf,
                         off, off + size, base, src)
            off = next_off

    # ---- pool 4: WAL frames ----
    def _wal_frames(self) -> List[Tuple[int, int, bytes]]:
        """Every frame in the -wal, in order: (page_no, file_offset, page_image)."""
        frames: List[Tuple[int, int, bytes]] = []
        if not self.wal_path:
            return frames
        with open(self.wal_path, "rb") as fh:
            wal = fh.read()
        if len(wal) < 32 or wal[:4] not in (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83"):
            self.notes.append("-wal present but its header is not recognised; skipped")
            return frames
        wal_page_size = struct.unpack(">I", wal[8:12])[0]
        if wal_page_size != self.page_size:
            self.notes.append(
                f"-wal page size {wal_page_size} disagrees with the database's "
                f"{self.page_size}; frames skipped")
            return frames
        frame_size = 24 + self.page_size
        pos = 32
        while pos + frame_size <= len(wal):
            page_no = struct.unpack(">I", wal[pos:pos + 4])[0]
            frames.append((page_no, pos + 24, wal[pos + 24:pos + frame_size]))
            pos += frame_size
        if frames:
            self.notes.append(f"{len(frames)} WAL frame(s) read")
        return frames

    def wal_regions(self) -> Iterator[Region]:
        """Freed space inside every WAL frame, plus every superseded page image.

        A WAL holds successive versions of a page. Only the last version of each
        page is current; all the earlier ones — and, for any page the WAL rewrote,
        the image still sitting in the main database file — are stale. When a
        deletion is recorded in the WAL, the row is not in anyone's free space at
        all: it is a perfectly live cell in the stale image. Those pages therefore
        have to be scanned whole, not just their unallocated parts, with the
        live-row comparison deciding what actually counts as deleted.
        """
        frames = self._wal_frames()
        if not frames:
            return
        last_index: Dict[int, int] = {}
        for i, (page_no, _, _) in enumerate(frames):
            last_index[page_no] = i
        superseded = 0
        for i, (page_no, offset, body) in enumerate(frames):
            if last_index.get(page_no) == i:
                # Current version: only its free space can hold deleted rows.
                yield from self._live_page_regions(
                    page_no, body, "wal-", self.wal_path, offset)
            else:
                superseded += 1
                yield Region("wal-superseded", page_no, body, 0, len(body),
                             offset, self.wal_path)
        # The main-file image of any page the WAL rewrote is itself superseded.
        for page_no in sorted(last_index):
            buf = self.page(page_no)
            if buf:
                superseded += 1
                yield Region("pre-wal-image", page_no, buf, 0, len(buf),
                             (page_no - 1) * self.page_size, self.db_path)
        if superseded:
            self.notes.append(f"{superseded} superseded page image(s) scanned in full")

    # ---- rollback journal ----
    def journal_regions(self) -> Iterator[Region]:
        """Pre-image pages from a rollback journal — each page exactly as it was
        before the transaction that modified it, so a committed delete leaves the
        original row intact here."""
        if not self.journal_path:
            return
        with open(self.journal_path, "rb") as fh:
            jrnl = fh.read()
        if len(jrnl) < 28 or jrnl[:8] != b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
            self.notes.append("-journal present but its header is not recognised; skipped")
            return
        sector = struct.unpack(">I", jrnl[20:24])[0] or 512
        page_size = struct.unpack(">I", jrnl[24:28])[0] or self.page_size
        pos = sector
        count = 0
        while pos + 4 + page_size + 4 <= len(jrnl):
            page_no = struct.unpack(">I", jrnl[pos:pos + 4])[0]
            body = jrnl[pos + 4:pos + 4 + page_size]
            if page_no:
                yield Region("journal", page_no, body, 0, len(body),
                             pos + 4, self.journal_path)
                count += 1
            pos += 4 + page_size + 4
        if count:
            self.notes.append(f"{count} rollback-journal page(s) scanned")

    # ---- all regions ----
    def regions(self) -> Iterator[Region]:
        for page_no in self.freelist_pages():
            buf = self.page(page_no)
            if buf:
                yield Region("freelist", page_no, buf, 0, len(buf),
                             (page_no - 1) * self.page_size, self.db_path)
        for page_no in range(1, self.page_count + 1):
            yield from self._live_page_regions(page_no)
        yield from self.wal_regions()
        yield from self.journal_regions()

    # ---- schema ----
    def schema(self) -> Dict[str, Dict[str, Any]]:
        """Column names and declared types per table, read through SQLite itself.

        Corruption is exactly when carving matters most, so a database SQLite
        refuses to open is reported and skipped rather than aborting the run.
        """
        out: Dict[str, Dict[str, Any]] = {}
        try:
            reader = SQLiteReader(self.db_path)
        except Exception as exc:
            self.notes.append(f"schema unreadable ({exc}); no tables could be targeted")
            return out
        with reader as db:
            try:
                tables = db.tables()
            except Exception as exc:
                self.notes.append(f"table list unreadable ({exc})")
                return out
            for table in tables:
                try:
                    cols = db.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
                except Exception:
                    continue
                if not cols:
                    continue
                out[table] = {
                    "columns": [c[1] for c in cols],
                    "declared_types": [c[2] for c in cols],
                    "affinities": [_affinity(c[2]) for c in cols],
                    "ncols": len(cols),
                    # An INTEGER PRIMARY KEY column is the rowid; it is stored as
                    # NULL in the record body, so its serial type is always 0.
                    "rowid_alias_index": next(
                        (i for i, c in enumerate(cols)
                         if c[5] and _affinity(c[2]) == "INTEGER"), None),
                }
        return out

    def secure_delete_reader_default(self) -> Optional[bool]:
        """This reader's compile-time ``secure_delete`` default.

        Deliberately NOT reported as the device's setting: the pragma is
        per-connection, so what comes back here describes the SQLite build doing
        the examination, not the one that performed the deletions on the phone.
        Whether freed content survived is answered empirically instead, by
        whether anything was recoverable.
        """
        try:
            with SQLiteReader(self.db_path) as db:
                row = db.conn.execute("PRAGMA secure_delete").fetchone()
            return bool(row[0]) if row else None
        except Exception:
            return None

    # ---- record parsing ----
    def _try_record(self, buf: bytes, off: int, ncols: int,
                    affinities: Sequence[str]) -> Optional[Dict[str, Any]]:
        """Attempt to read a record of exactly `ncols` columns at `off`."""
        try:
            header_size, p = read_varint(buf, off)
        except ValueError:
            return None
        header_end = off + header_size
        # A header must at least hold its own length byte plus one type per column,
        # and cannot claim to extend past the region.
        if header_size < 1 + ncols or header_end > len(buf):
            return None
        stypes: List[int] = []
        while p < header_end:
            try:
                stype, p = read_varint(buf, p)
            except ValueError:
                return None
            if stype in (10, 11):
                return None                  # reserved; a real record never has these
            stypes.append(stype)
            if len(stypes) > ncols:
                return None
        if p != header_end or len(stypes) != ncols:
            return None

        body_len = 0
        for stype in stypes:
            size = serial_type_size(stype)
            if size < 0:
                return None
            body_len += size
        if body_len == 0 and ncols > 1:
            return None                      # an all-NULL row is indistinguishable from padding

        # Affinity check: this is what keeps the false-positive rate down.
        mismatches = sum(1 for aff, st in zip(affinities, stypes) if not _type_ok(aff, st))
        if mismatches:
            return None

        # A payload larger than the page can hold locally continues on an overflow
        # page. Those bytes are not contiguous here, so anything at or past the
        # local limit is padding and the overflow pointer, not data — decoding
        # through it silently corrupts the last field.
        local_limit = min(len(buf), header_end + max(0, self.max_local_payload() - header_size))
        available = len(buf) - header_end
        truncated = body_len > available
        overflow = header_size + body_len > self.max_local_payload()
        values: List[Any] = []
        reliable = 0
        cursor = header_end
        for stype in stypes:
            size = serial_type_size(stype)
            if cursor + size > len(buf) or cursor + size > local_limit:
                values.append(None)
                continue
            values.append(decode_serial(stype, buf, cursor, self.encoding))
            cursor += size
            reliable += 1
        # Text carrying NULs or decode-replacement glyphs is page padding read as
        # a string, not a value. Reporting it would claim a row was deleted on the
        # strength of bytes that were never that row's data.
        if any(isinstance(v, str) and ("\x00" in v or "�" in v) for v in values):
            return None
        return {
            "values": values,
            "serial_types": stypes,
            "record_length": header_size + min(body_len, available),
            "truncated": truncated,
            "overflow": overflow,
            "reliable_columns": reliable,
        }

    def max_local_payload(self) -> int:
        """Largest payload a table-leaf cell stores on its own page."""
        return self._usable_size() - 35

    # How many leading columns a damaged record may have lost and still be worth
    # reporting. Freeing a cell writes a 4-byte freeblock header over its first
    # bytes — the payload varint, the rowid varint, the record header size and
    # the first serial type — so exactly one column is normally lost. The range
    # allows for a second freeblock link landing on a wider header.
    MAX_LOST_LEADING_COLUMNS = 3
    MIN_SURVIVING_COLUMNS = 4
    # Widest value a lost leading column may have held. Bounds the search for
    # where the surviving fields actually begin.
    MAX_LOST_FIELD_BYTES = 96

    def _freeblock_header_before(self, buf: bytes, off: int) -> Optional[int]:
        """If the four bytes before `off` are a freeblock header, return its size.

        Freeing a cell writes ``[next:2][size:2]`` over the start of the cell —
        the payload varint, the rowid varint, the record's header-size byte and
        its first serial type. That header is the anchor for partial recovery:
        without it, scanning every byte for a headerless record produces
        convincing-looking misalignments, which is worse than recovering nothing.
        """
        if off < 4:
            return None
        next_off = struct.unpack(">H", buf[off - 4:off - 2])[0]
        size = struct.unpack(">H", buf[off - 2:off])[0]
        if size < 4 or (off - 4) + size > len(buf):
            return None
        # `next` is either the end of the chain or another offset inside the page.
        if next_off != 0 and not (4 <= next_off < len(buf)):
            return None
        return size

    def _try_partial_record(self, buf: bytes, off: int, ncols: int,
                            affinities: Sequence[str]) -> Optional[Dict[str, Any]]:
        """Recover the surviving tail of a record whose header start was overwritten.

        Requiring an intact header would discard nearly every deleted row: SQLite
        stamps a freeblock header over the front of a freed cell, taking the first
        serial type with it. The remaining types still describe the remaining
        columns, so the row is recoverable minus its leading field(s) — but only
        where that freeblock header is actually present, so the alignment is known
        rather than guessed.
        """
        if ncols < self.MIN_SURVIVING_COLUMNS + 1:
            return None
        block_size = self._freeblock_header_before(buf, off)
        if block_size is None:
            return None
        best: Optional[Dict[str, Any]] = None
        best_score: Tuple[int, int, int] = (-1, -1, -1)
        # How much of the header the freeblock swallowed depends on how wide the
        # cell's payload and rowid varints were. On a small row it takes the
        # payload byte, the rowid byte, the header-size byte and the first serial
        # type — one column lost. On a row past 127 bytes the payload varint is
        # two bytes wide, so only the header-size byte goes and every column type
        # survives. Both have to be tried.
        for lost in range(0, min(self.MAX_LOST_LEADING_COLUMNS,
                                 ncols - self.MIN_SURVIVING_COLUMNS) + 1):
            remaining = ncols - lost
            tail_aff = affinities[lost:]
            p = off
            stypes: List[int] = []
            ok = True
            for _ in range(remaining):
                try:
                    stype, p = read_varint(buf, p)
                except ValueError:
                    ok = False
                    break
                if stype in (10, 11) or serial_type_size(stype) < 0:
                    ok = False
                    break
                stypes.append(stype)
            if not ok or len(stypes) != remaining:
                continue
            if any(not _type_ok(a, s) for a, s in zip(tail_aff, stypes)):
                continue
            body_len = sum(serial_type_size(s) for s in stypes)
            if body_len <= 0:
                continue

            # Only the lost columns' *serial types* were overwritten; their values
            # are still at the front of the body, with no type left to size them.
            # Solve for that width: the correct one is the offset at which every
            # surviving text field decodes cleanly, and a wrong one shows up
            # immediately as a field boundary landing mid-character.
            max_skip = min(self.MAX_LOST_FIELD_BYTES, block_size - (p - off) - body_len - 4)
            for skip in range(0, max(0, max_skip) + 1):
                if lost == 0 and skip:
                    break        # every type survived, so the body starts here
                start = p + skip
                if start + body_len > len(buf):
                    break
                values: List[Any] = []
                cursor = start
                for stype in stypes:
                    size = serial_type_size(stype)
                    values.append(decode_serial(stype, buf, cursor, self.encoding))
                    cursor += size
                texts = [v for v in values if isinstance(v, str)]
                if not texts or not any(len(v) >= 3 for v in texts):
                    continue
                if any("�" in v or not v.isprintable() for v in texts):
                    continue
                # A misalignment slides an integer field over neighbouring text.
                # Six- and eight-byte integers whose bytes are all printable ASCII
                # are that, not real values — a genuine millisecond timestamp does
                # not spell out characters.
                if self._ints_look_like_text(buf, start, stypes):
                    continue
                # The skipped bytes are the lost column(s); they have no declared
                # type any more, so they are reported as raw text, flagged as
                # reconstructed rather than decoded.
                head_raw = buf[p:start]
                try:
                    head = head_raw.decode(self.encoding)
                    if not head.isprintable():
                        head = None
                except (UnicodeDecodeError, LookupError):
                    head = None
                # Decisive check on where the lost field ended. A one-byte shift
                # keeps every character printable when the data is ASCII, so
                # cleanliness cannot separate the alignments — but only the
                # correct one ends exactly where the next freed cell's own
                # freeblock header begins.
                end = start + body_len
                abuts_next = 1 if (end + 4 <= len(buf) and
                                   self._freeblock_header_before(buf, end + 4) is not None) else 0
                clean, recovered = self._score(values, ncols)
                score = (abuts_next, clean, recovered)
                if score > best_score:
                    best_score = score
                    best = {
                        "values": ([head] + [None] * (lost - 1)) if lost else [],
                        "head_bytes": len(head_raw),
                        "serial_types": stypes,
                        "record_length": (p - off) + skip + body_len,
                        "truncated": False,
                        "partial": True,
                        "lost_leading_columns": lost,
                        "reconstructed_head": head is not None,
                        "anchored": bool(abuts_next),
                        "_tail": values,
                    }
        if best is not None:
            best["values"] = best["values"] + best.pop("_tail")
        return best

    @staticmethod
    def _ints_look_like_text(buf: bytes, start: int, stypes: Sequence[int]) -> bool:
        """True when a wide integer field is really misread text."""
        cursor = start
        for stype in stypes:
            size = serial_type_size(stype)
            if stype in (5, 6) and size:      # 6- and 8-byte integers
                raw = buf[cursor:cursor + size]
                if len(raw) == size and all(0x20 <= b < 0x7F for b in raw):
                    return True
            cursor += size
        return False

    @staticmethod
    def _score(values: Sequence[Any], ncols: int) -> Tuple[int, int]:
        """Rank one reading of a byte range against another.

        Clean text wins first: a misaligned parse reads a field boundary in the
        wrong place, and the tell is a control character or a decode-replacement
        glyph inside a string. Only among equally clean readings does explaining
        more columns win.
        """
        texts = [v for v in values if isinstance(v, str)]
        clean = 1 if all(v.isprintable() and "�" not in v for v in texts) else 0
        recovered = sum(1 for v in values if v is not None)
        return (clean, recovered)

    # ---- carving ----
    def carve(self, tables: Optional[Sequence[str]] = None,
              max_records: int = 20_000) -> Dict[str, Any]:
        """Recover deleted records for the named tables (default: all tables)."""
        schema = self.schema()
        targets = {t: s for t, s in schema.items()
                   if (tables is None or t in tables) and s["ncols"] >= 2}
        if not targets:
            return {"records": [], "notes": self.notes, "summary": {
                "database": os.path.basename(self.db_path),
                "recovered_count": 0, "truncated_count": 0, "ambiguous_count": 0,
                "partial_count": 0, "regions_scanned": 0, "by_pool": {}, "by_table": {},
                "tables_targeted": [], "freed_content_retained": False,
                "note": "no carvable tables — schema unreadable or all tables too narrow",
            }}

        # Group tables by column count: one scan serves every table of that width.
        by_ncols: Dict[int, List[str]] = {}
        for name, spec in targets.items():
            by_ncols.setdefault(spec["ncols"], []).append(name)

        live = {name: self._live_fingerprints(name) for name in targets}
        enum_domains = {name: self._live_enum_domains(name) for name in targets}
        recovered: List[Dict[str, Any]] = []
        seen_fp: set = set()
        pools: Dict[str, int] = {}
        regions_scanned = 0
        capped = False

        for region in self.regions():
            if capped:
                break
            regions_scanned += 1
            buf = region.page
            off = region.start
            end = min(region.end, len(buf) - self.MIN_RECORD_BYTES)
            while off < end:
                if len(recovered) >= max_records:
                    self.notes.append(
                        f"record cap of {max_records} reached; scan stopped early")
                    capped = True
                    break
                # Collect every reading of these bytes — intact records and, where
                # a freeblock header anchors one, damaged tails — then keep the
                # best-supported. Taking the first parse that succeeds lets a
                # bogus intact match, formed by reading serial types out of a
                # neighbouring row's body, hide the real damaged record beneath it.
                candidates: List[Tuple[Tuple[int, int], str, Dict[str, Any]]] = []
                for name, spec in targets.items():
                    full = self._try_record(buf, off, spec["ncols"], spec["affinities"])
                    if full is not None:
                        candidates.append((self._score(full["values"], spec["ncols"]),
                                           name, full))
                    tail = self._try_partial_record(buf, off, spec["ncols"],
                                                    spec["affinities"])
                    if tail is not None:
                        candidates.append((self._score(tail["values"], spec["ncols"]),
                                           name, tail))
                if not candidates:
                    off += 1
                    continue
                best_score = max(c[0] for c in candidates)
                winners = [c for c in candidates if c[0] == best_score]
                rec = winners[0][2]
                fits = sorted({c[1] for c in winners})

                # A record whose body ran past the page is only partly present; its
                # length cannot be trusted to step over, so advance minimally.
                step = 1 if rec["truncated"] else max(1, rec["record_length"])
                lost = rec.get("lost_leading_columns", 0)
                reliable = rec.get("reliable_columns")
                # Compare against the live rows on whatever part of this record
                # was decoded reliably. Matching on the whole tuple would report
                # an overflow row — whose tail is on another page and therefore
                # decodes as padding — as a deletion, even though it is still
                # sitting in the table.
                if lost:
                    fingerprint = self._fingerprint(rec["values"][lost:])
                    is_live = any(live[n].has_suffix(lost, fingerprint) for n in fits)
                elif reliable is not None and reliable < len(rec["values"]):
                    fingerprint = self._fingerprint(rec["values"][:reliable])
                    is_live = any(live[n].has_prefix(reliable, fingerprint) for n in fits)
                else:
                    fingerprint = self._fingerprint(rec["values"])
                    is_live = any(live[n].has_prefix(len(rec["values"]), fingerprint)
                                  for n in fits)
                if is_live or fingerprint in seen_fp:
                    off += step
                    continue
                seen_fp.add(fingerprint)
                primary = fits[0]
                cols = targets[primary]["columns"]
                implausible = self._implausible_columns(
                    rec["values"], cols, enum_domains.get(primary) or {})
                # Two independent claims, reported separately:
                #   extent  — do we know where this record began and ended?
                #   values  — do the decoded fields sit in the right columns?
                # An anchored partial record scores high on the first and only
                # "inferred" on the second, and a value outside its column's
                # observed domain drops the second to "low" regardless.
                extent_conf = "high" if (not lost or rec.get("anchored")) else "medium"
                if implausible:
                    value_conf = "low"
                elif lost:
                    value_conf = "inferred"
                else:
                    value_conf = "high"
                recovered.append({
                    "candidate_tables": fits,
                    "table": primary if len(fits) == 1 else None,
                    "ambiguous": len(fits) > 1,
                    "columns": cols,
                    "values": [_printable(v) for v in rec["values"]],
                    "row": {c: _printable(v) for c, v in zip(cols, rec["values"])},
                    "truncated": rec["truncated"],
                    "partial": bool(lost),
                    "lost_leading_columns": cols[:lost] if lost else [],
                    "overflow": bool(rec.get("overflow")),
                    "fields_decoded": reliable if reliable is not None else len(cols),
                    # "high" means the record's EXTENT was confirmed structurally:
                    # its header was intact, or its end lined up exactly with the
                    # next freed cell. "medium" means the field boundaries were
                    # inferred and could be off. It says nothing about whether the
                    # values landed in the right columns — read `value_confidence`
                    # for that, and never present `confidence: high` alone as
                    # "these values are reliable".
                    "confidence": extent_conf,
                    "extent_confidence": extent_conf,
                    "value_confidence": value_conf,
                    "implausible_columns": implausible,
                    "pool": region.pool,
                    "page": region.page_no,
                    "file_offset": region.file_base + off,
                    "source_file": os.path.basename(region.source),
                    "column_count": len(rec["serial_types"]),
                })
                pools[region.pool] = pools.get(region.pool, 0) + 1
                off += step

        by_table: Dict[str, int] = {}
        for r in recovered:
            key = r["table"] or "ambiguous"
            by_table[key] = by_table.get(key, 0) + 1
        return {
            "records": recovered,
            "notes": self.notes,
            "summary": {
                "database": os.path.basename(self.db_path),
                "sha256": hash_file(self.db_path),
                "page_size": self.page_size,
                "page_count": self.page_count,
                "freelist_pages": self.freelist_count,
                "wal_present": bool(self.wal_path),
                "journal_present": bool(self.journal_path),
                "secure_delete_reader_default": self.secure_delete_reader_default(),
                # Evidence-based, unlike the pragma: if anything came back, this
                # database plainly did not zero its freed content.
                "freed_content_retained": len(recovered) > 0,
                "regions_scanned": regions_scanned,
                "recovered_count": len(recovered),
                "truncated_count": sum(1 for r in recovered if r["truncated"]),
                "partial_count": sum(1 for r in recovered if r["partial"]),
                "ambiguous_count": sum(1 for r in recovered if r["ambiguous"]),
                # Extent-confident but with a field outside its column's observed
                # domain: the row is really there, its columns are probably shifted.
                "value_suspect_count": sum(1 for r in recovered
                                           if r["value_confidence"] == "low"),
                "values_fully_decoded_count": sum(1 for r in recovered
                                                  if r["value_confidence"] == "high"),
                "by_pool": pools,
                "by_table": by_table,
                "tables_targeted": sorted(targets),
            },
        }

    # ---- value-plausibility, learned from the live table ----
    #
    # The affinity check validates serial *types*, so an INTEGER column accepts any
    # integer however absurd: a misaligned partial record was reporting
    # `show_on_history = 84521` for a column that can only hold 0 or 1, while being
    # graded "high" because its extent was structurally confirmed. Extent
    # confidence and value confidence are different claims and are now reported
    # separately, with this check backing the second one.
    #
    # The domain is learned from the rows the table still holds rather than
    # hard-coded, and only for columns whose live values form a narrow enum/boolean
    # set. Anything wider is left alone: a deleted row may legitimately carry a
    # timestamp or an amount outside the surviving range, and flagging that would
    # discard real evidence.
    MAX_ENUM_CARDINALITY = 8
    ENUM_VALUE_CEILING = 16

    def _live_enum_domains(self, table: str) -> Dict[int, set]:
        """{column index -> permitted values} for boolean/enum-like columns."""
        try:
            with SQLiteReader(self.db_path) as db:
                cols = db.columns(table)
                if not cols:
                    return {}
                rows = db.conn.execute(f'SELECT * FROM "{table}"').fetchall()
        except Exception:
            return {}
        if len(rows) < 4:                     # too few rows to infer a domain
            return {}
        domains: Dict[int, set] = {}
        for i in range(len(cols)):
            seen = set()
            ok = True
            for r in rows:
                v = r[i] if i < len(r) else None
                if v is None:
                    continue
                if not isinstance(v, int) or isinstance(v, bool) or abs(v) > self.ENUM_VALUE_CEILING:
                    ok = False
                    break
                seen.add(v)
                if len(seen) > self.MAX_ENUM_CARDINALITY:
                    ok = False
                    break
            if ok and seen:
                domains[i] = seen
        return domains

    def _implausible_columns(self, values: Sequence[Any], columns: Sequence[str],
                             domains: Dict[int, set]) -> List[str]:
        out: List[str] = []
        for i, v in enumerate(values):
            if v is None or i not in domains or i >= len(columns):
                continue
            if isinstance(v, int) and not isinstance(v, bool) and v not in domains[i]:
                out.append(columns[i])
        return out

    # ---- live-row comparison ----
    def _live_fingerprints(self, table: str) -> "_LiveIndex":
        """Index of the rows still in the table, so an intact row is never
        reported as a recovered deletion."""
        rows: List[List[Any]] = []
        try:
            with SQLiteReader(self.db_path) as db:
                for row in db.conn.execute(f'SELECT * FROM "{table}"'):
                    rows.append(list(row))
        except Exception:
            pass
        return _LiveIndex(rows, self._fingerprint, self.MAX_LOST_LEADING_COLUMNS)

    @staticmethod
    def _fingerprint(values: Sequence[Any]) -> Tuple:
        out = []
        for v in values:
            if isinstance(v, (bytes, bytearray, memoryview)):
                out.append(bytes(v)[:64])
            elif isinstance(v, float):
                out.append(round(v, 6))
            else:
                out.append(v)
        return tuple(out)


class _LiveIndex:
    """Membership tests against the rows still present in a table.

    A carved record cannot always be decoded in full — an overflow payload leaves
    its tail on another page, and a damaged header costs the leading field — so
    "is this row still live?" has to be answerable on a prefix or a suffix, not
    only on the whole tuple. Sets are built for the widths actually asked for.
    """

    def __init__(self, rows: List[List[Any]], fingerprint, max_lost: int):
        self._rows = rows
        self._fp = fingerprint
        self._max_lost = max_lost
        self._prefix: Dict[int, set] = {}
        self._suffix: Dict[int, set] = {}

    def has_suffix(self, k: int, fp: Tuple) -> bool:
        if k not in self._suffix:
            self._suffix[k] = {self._fp(r[k:]) for r in self._rows}
        return fp in self._suffix[k]

    def has_prefix(self, n: int, fp: Tuple) -> bool:
        if n not in self._prefix:
            self._prefix[n] = {self._fp(r[:n]) for r in self._rows}
        return fp in self._prefix[n]


def _printable(value: Any) -> Any:
    """Render a decoded value for the UI / JSON without losing what it was."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8")
            if text.isprintable() or "\n" in text:
                return text
        except UnicodeDecodeError:
            pass
        return {"_blob_size": len(raw), "_hex_preview": raw[:48].hex()}
    return value


def carve_database(db_path: str, tables: Optional[Sequence[str]] = None,
                   max_records: int = 20_000) -> Dict[str, Any]:
    """Carve one database, picking up its -wal / -journal automatically."""
    return SQLiteCarver(
        db_path,
        wal_path=db_path + "-wal",
        journal_path=db_path + "-journal",
    ).carve(tables=tables, max_records=max_records)
