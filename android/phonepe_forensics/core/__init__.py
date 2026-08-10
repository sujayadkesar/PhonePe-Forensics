"""
PhonePe Forensics — Core Parsing Engine
=======================================
Split by platform so the shared engine can be maintained in one place:

    core.common    platform-neutral — SQLiteReader, evidence snapshots,
                   timestamps, hashing, transaction-ID decoding, small helpers
    core.ios       Apple container formats — plist, binarycookies,
                   NSKeyedArchiver, the iOS AppDomain layout
    core.android   the com.phonepe.app layout, JSON payloads, shared_prefs

Everything is re-exported here, so ``from phonepe_forensics.core import X``
continues to work regardless of which module X ended up in.
"""
from __future__ import annotations

from .common import (  # noqa: F401
    APPLE_EPOCH_OFFSET,
    DISPLAY_TZ,
    EPOCH_MS_MAX,
    EPOCH_S_MAX,
    FAILED_STATES,
    NSDATE_REASONABLE_MAX,
    NSDATE_REASONABLE_MIN,
    PENDING_STATES,
    SUCCESS_STATES,
    TXN_ID_TZ_CAVEAT,
    EvidenceSnapshot,
    SQLiteReader,
    _to_dt,
    _ts_dict,
    amount_to_rupees,
    decode_txn_id,
    evidence_manifest,
    evidence_warnings,
    file_size,
    find_files,
    first_match,
    fmt_ts,
    hash_file,
    normalise_state,
    normalize_timestamp,
    safe_float,
    safe_int,
    tri_bool,
    schema_gaps,
    snapshot_database,
)

# iOS parsing is optional: an Android-only deployment need not carry plistlib
# formats, and a failure to import them must not take the shared engine down.
try:
    from .ios import (  # noqa: F401
        BinaryCookieReader,
        CasePaths,
        decode_nskeyedarchiver,
        flatten_plist,
        read_plist,
        safe_decode_blob,
    )
except ImportError:  # pragma: no cover - only if plistlib is unavailable
    BinaryCookieReader = CasePaths = None  # type: ignore
    decode_nskeyedarchiver = flatten_plist = read_plist = safe_decode_blob = None  # type: ignore
