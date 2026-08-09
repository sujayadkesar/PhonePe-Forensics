"""
PhonePe Android Forensics
=========================
Android-specific parsing layer for the PhonePe forensics toolkit.

Design: the platform-agnostic layer (correlator, hunt, reports, the Flask GUI) lives in
``phonepe_forensics`` and is REUSED unchanged. This package only provides the Android-specific
pieces — path resolution, JSON-blob decoding, and extractors that emit the SAME normalized
data contract documented in ``phonepe-android-port/CONTRACT.md``.

Android storage facts (see ANDROID-FINDINGS.md):
  * Plain unencrypted SQLite (Android Room), mostly consolidated in ``phonepe_core``.
  * BLOB payloads are PLAIN JSON strings (not archived or encrypted).
  * Timestamps are Unix-ms; amounts in paise; txn IDs ``T<YYMMDDhhmmss>...``.
"""

__version__ = "0.1.0-scaffold"
