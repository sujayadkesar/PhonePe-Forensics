"""
PhonePe Android Forensics — Case Orchestrator
=========================================
A `Case` represents one acquisition. It coordinates extraction, caches the
results in memory, and exposes them to the UI / report layer.

Usage:
    from phonepe_forensics.case import Case
    c = Case("/path/to/acquisition")
    c.run_full_extraction()      # runs every module
    c.timeline()                 # unified timeline
    c.social_graph()             # social graph
    c.findings()                 # heuristic flags
    c.export_all("./exports")    # write all artifacts
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
from typing import Any, Dict, List, Optional

from . import __version__ as TOOL_VERSION
from .reports import TOOL_NAME

from .core import (
    evidence_manifest, evidence_warnings, hash_file, normalize_timestamp, schema_gaps,
)
from .correlator import (
    build_corroboration_index,
    build_counterparty_profile,
    build_social_graph,
    build_unified_timeline,
    detect_suspicious_signals,
)
from .reports import export_all


# ---------------------------------------------------------------------------
# Case
# ---------------------------------------------------------------------------

class Case:
    """In-memory container for one forensic acquisition.

    Platform-agnostic: every derived view below reads only the normalized
    contract in ``self.data``. A concrete platform supplies its own path
    resolver and extractors — the base class no longer defaults to the iOS
    layout, which made "generic" code quietly Apple-shaped.
    """

    #: Path resolver for this platform. Subclasses set it (AndroidCasePaths, …).
    PATHS_CLASS: Any = None

    #: (name, fn) pairs run in order by run_full_extraction.
    EXTRACTORS: List = []

    def __init__(self, root: str):
        paths_class = self.PATHS_CLASS
        if paths_class is None:
            raise NotImplementedError(
                f"{type(self).__name__} must set PATHS_CLASS (or override __init__) "
                f"— Case itself is platform-neutral and has no layout of its own."
            )
        self._init_state(root, paths_class(os.path.abspath(root)))

    def _init_state(self, root: str, paths: Any, **meta) -> None:
        """Shared construction for every platform.

        Subclasses call this rather than reimplementing __init__, so a new derived
        view added here cannot go missing on one platform and AttributeError at
        runtime on the other.
        """
        self.root = os.path.abspath(root)
        self.paths = paths
        self.data: Dict[str, Any] = {
            "_meta": {
                "case_root": self.root,
                "loaded_at": int(time.time() * 1000),
                "containers": self.paths.summary(),
                **meta,
            },
        }
        self._extracted = False
        self._timeline: Optional[List[Dict[str, Any]]] = None
        self._social_graph: Optional[Dict[str, Any]] = None
        self._findings: Optional[List[Dict[str, Any]]] = None
        self._corroboration: Optional[Dict[str, Any]] = None
        self._hunt_indexes: Optional[Dict[str, List[Dict[str, Any]]]] = None

    # ---- validation ----
    # Concrete platforms (AndroidCase) override this with layout-specific checks.
    def validate(self) -> Dict[str, Any]:
        return {"valid": self.paths.is_valid(), "issues": [], "summary": self.paths.summary()}

    # ---- extraction ----
    def run_full_extraction(self, on_progress=None) -> Dict[str, Any]:
        for i, (name, fn) in enumerate(self.EXTRACTORS, start=1):
            if on_progress:
                try:
                    on_progress(name, i, len(self.EXTRACTORS))
                except Exception:
                    pass
            try:
                self.data[name] = fn(self.paths)
            except Exception as exc:
                self.data[name] = {"error": str(exc)}

        # Tag chat direction using the registered identity name (only known
        # AFTER both `identity` and `chat` extractions have run).
        self._tag_chat_self_direction()

        # Findings + timeline + graph
        self._findings = detect_suspicious_signals(self.data)
        self.data["findings"] = self._findings
        self.data["_meta"]["completed_at"] = int(time.time() * 1000)
        self._extracted = True
        return self.data

    def _tag_chat_self_direction(self) -> None:
        """Re-tag chat members + messages with `is_self` / direction now
        that we know the registered subject's name."""
        ident = self.data.get("identity", {}) or {}
        registered_name = (ident.get("registered_name") or "").strip().lower()
        if not registered_name:
            return
        chat = self.data.get("chat") or {}
        members = chat.get("members") or []
        # 1) Mark every member whose display_name matches the registered subject
        member_pk_to_self: Dict[Any, bool] = {}
        for m in members:
            dn = (m.get("display_name") or "").strip().lower()
            is_self = (dn == registered_name) if dn else bool(m.get("is_self"))
            m["is_self"] = is_self
            member_pk_to_self[m.get("z_pk")] = is_self

        # 2) Re-derive each message's direction + other_party from the
        #    refreshed self-flag.
        # We don't keep src/dst PKs on the message records, so instead
        # recompute via sender_name/receiver_name comparisons.
        for msg in chat.get("messages") or []:
            sn = (msg.get("sender_name") or "").strip().lower()
            rn = (msg.get("receiver_name") or "").strip().lower()
            sender_is_self = (sn == registered_name) if sn else None
            receiver_is_self = (rn == registered_name) if rn else None
            msg["sender_is_self"] = sender_is_self
            msg["receiver_is_self"] = receiver_is_self
            if sender_is_self is True:
                msg["direction"] = "OUT"
                msg["is_outgoing"] = True
                msg["other_party_name"] = msg.get("receiver_name") or msg.get("group_name")
                msg["other_party_phone"] = msg.get("receiver_phone_masked")
            elif sender_is_self is False:
                msg["direction"] = "IN"
                msg["is_outgoing"] = False
                msg["other_party_name"] = msg.get("sender_name") or msg.get("group_name")
                msg["other_party_phone"] = msg.get("sender_phone_masked")
            else:
                # Last-resort fallback when neither sender_name nor receiver_name
                # is the subject — leave whatever the extractor inferred.
                pass

    # ---- derived views (lazy) ----
    def timeline(self, limit: int = 5000) -> List[Dict[str, Any]]:
        if self._timeline is None:
            # Build without a cap so a dashboard call (limit=30) does not
            # poison subsequent timeline-page calls (limit=1500, 10000...).
            self._timeline = build_unified_timeline(self.data, limit=999_999)
        return self._timeline[:limit]

    def social_graph(self) -> Dict[str, Any]:
        if self._social_graph is None:
            self._social_graph = build_social_graph(self.data)
        return self._social_graph

    def findings(self) -> List[Dict[str, Any]]:
        if self._findings is None:
            self._findings = detect_suspicious_signals(self.data)
            self.data["findings"] = self._findings
        return self._findings

    def corroboration(self) -> Dict[str, Any]:
        # Rebuilding this walks every transaction, chat message and reward; it was
        # recomputed on every page load that touched a transaction.
        if self._corroboration is None:
            self._corroboration = build_corroboration_index(self.data)
        return self._corroboration

    def hunt_indexes(self) -> Dict[str, List[Dict[str, Any]]]:
        """Flattened PPQL indexes. Built once — materialising them re-walks and
        re-copies every record in the case, which was happening on each query."""
        if self._hunt_indexes is None:
            from .hunt import materialise_indexes
            self._hunt_indexes = materialise_indexes(
                self.data, self.timeline(), self.social_graph(), self.findings())
        return self._hunt_indexes

    # ---- extraction health ----
    def extraction_errors(self) -> List[Dict[str, Any]]:
        """Every module that failed or degraded, so the UI can say so.

        A hard-coded SELECT against a renamed column yields an empty evidence page
        that looks exactly like an acquisition with no such data. These have to be
        visible or an analyst reports "no transactions" when the truth is
        "transactions could not be read".
        """
        errors: List[Dict[str, Any]] = []
        for name, payload in self.data.items():
            if name.startswith("_") or not isinstance(payload, dict):
                continue
            if payload.get("error"):
                errors.append({"module": name, "severity": "failed",
                               "detail": str(payload["error"])})
            for msg in payload.get("errors") or []:
                errors.append({"module": name, "severity": "degraded", "detail": str(msg)})
        for gap in schema_gaps(self.root):
            errors.append({
                "module": gap["database"], "severity": "schema",
                "detail": f"{gap['table']}: columns absent from this acquisition — "
                          f"{', '.join(gap['missing_columns'])}. Fields backed by them "
                          f"are blank, not empty.",
            })
        inventory = self.data.get("database_inventory")
        if isinstance(inventory, list):
            for entry in inventory:
                if isinstance(entry, dict) and entry.get("error"):
                    errors.append({"module": "database_inventory", "severity": "failed",
                                   "detail": f"{entry.get('rel_path', '?')}: {entry['error']}"})
        return errors

    def evidence_manifest(self) -> List[Dict[str, Any]]:
        """Per-file SHA-256 of every database opened, hashed before parsing."""
        return evidence_manifest(self.root)

    def evidence_warnings(self) -> List[str]:
        """Integrity caveats that must appear on any report built from this case."""
        return evidence_warnings(self.root)

    def lookup_counterparty(self, identifier: str) -> Dict[str, Any]:
        return build_counterparty_profile(self.data, identifier)

    # ---- top-level dashboard summary ----
    def dashboard(self) -> Dict[str, Any]:
        ident = self.data.get("identity", {})
        txn_summary = self.data.get("transactions", {}).get("summary", {})
        chat_summary = self.data.get("chat", {}).get("summary", {})
        contacts_summary = self.data.get("contacts", {}).get("summary", {})
        analytics_summary = self.data.get("analytics", {}).get("summary", {})
        return {
            "case_root": self.root,
            "valid": self.paths.is_valid(),
            "containers": self.paths.summary(),
            "identity": {
                "name": ident.get("registered_name"),
                "upi_id": ident.get("upi_id"),
                "phones": ident.get("phones_seen", []),
                "location_hints": ident.get("location_hints", []),
            },
            "metrics": {
                "transactions": txn_summary.get("transaction_count", 0),
                "transactions_in": txn_summary.get("total_received_inr", 0),
                "transactions_out": txn_summary.get("total_sent_inr", 0),
                "groups": chat_summary.get("group_count", 0),
                "messages": chat_summary.get("message_count", 0),
                "phonebook_contacts": contacts_summary.get("phonebook_total", 0),
                "phonepe_contacts": contacts_summary.get("on_phonepe_count", 0),
                "kn_events": analytics_summary.get("kn_event_count", 0),
                "rewards": self.data.get("financial", {}).get("summary", {}).get("rewards_count", 0),
                "supported_banks": self.data.get("payment_infra", {}).get("summary", {}).get("supported_bank_count", 0),
            },
            "earliest_txn": txn_summary.get("earliest_txn"),
            "latest_txn": txn_summary.get("latest_txn"),
            "yearly_volume": txn_summary.get("yearly_volume_inr", {}),
            "top_counterparties": txn_summary.get("top_counterparties", []),
            "findings_count": len(self.findings()),
            "extraction_errors": self.extraction_errors(),
            # Scoped to THIS case's root. The snapshot cache is process-wide, so the
            # unscoped call put another open case's integrity warnings on this
            # case's dashboard — and an integrity warning attributed to the wrong
            # acquisition is worse than none.
            "evidence_warnings": self.evidence_warnings(),
        }

    # ---- export ----
    def custody_record(self, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Everything an exhibit needs to be attributable: who, what, when, which
        tool, and the hashes of the source files as they were before parsing."""
        meta = meta or {}
        return {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "case_name": meta.get("name"),
            "case_id": meta.get("id"),
            "investigator": meta.get("investigator"),
            "notes": meta.get("notes"),
            "evidence_root": self.root,
            "platform": (self.data.get("_meta") or {}).get("platform", "android"),
            "extraction_started_ms": (self.data.get("_meta") or {}).get("loaded_at"),
            "extraction_completed_ms": (self.data.get("_meta") or {}).get("completed_at"),
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "timestamps_are": "UTC",
            "manifest": self.evidence_manifest(),
            "evidence_warnings": self.evidence_warnings(),
            "extraction_errors": self.extraction_errors(),
        }

    def export_all(self, base_dir: str = "exports",
                   meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        out_dir = os.path.join(base_dir, _safe_name(os.path.basename(self.root) or "case"))
        return export_all(
            self.data, out_dir,
            timeline=self.timeline(),
            social_graph=self.social_graph(),
            case_root=self.root,
            custody=self.custody_record(meta),
        )


def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:80] or "case"
