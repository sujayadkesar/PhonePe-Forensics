"""Forensic provenance envelope builder."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import __version__
from .core import sha256_bytes


def build_envelope(
    *,
    source_db: str,
    source_table: str,
    source_row_pk: int | None,
    source_id_column: str | None,
    source_id_value: str | None,
    source_blob: bytes | None,
    decode_path: str,
    case_id: str | None,
) -> dict[str, Any]:
    """Build the forensic-provenance envelope attached to every raw record."""
    return {
        "source_db": source_db,
        "source_table": source_table,
        "source_row_pk": source_row_pk,
        "source_id_column": source_id_column,
        "source_id_value": source_id_value,
        "sha256_of_source_blob": sha256_bytes(source_blob),
        "decode_path": decode_path,
        "decoded_at_utc": datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "case_id": case_id,
        "tool": "phonepe-forensics",
        "tool_version": __version__,
    }
