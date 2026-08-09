"""
PhonePe Android Forensics — core primitives (compatibility shim)
================================================================
The Android primitives now live in ``phonepe_forensics.core.android`` alongside
the shared and iOS layers, so all three sit under one package and this build can
take upstream fixes without vendoring its own copy of the engine.

This module re-exports them so existing imports keep working.
"""
from __future__ import annotations

from phonepe_forensics.core.android import (  # noqa: F401
    EPOCH_S_MAX,
    PACKAGE,
    SUCCESS_STATES,
    AndroidCasePaths,
    SQLiteReader,
    _ts_dict,
    amount_to_rupees,
    chromium_ts,
    decode_json_blob,
    decode_txn_id,
    evidence_manifest,
    evidence_warnings,
    first_or_dict,
    hash_file,
    normalize_timestamp,
    pick,
    read_shared_pref,
    safe_float,
    safe_int,
    tri_bool,
)
