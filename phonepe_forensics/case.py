"""
PhonePe iOS Forensics — Case Orchestrator
=========================================
A `Case` represents one acquisition. It coordinates extraction, caches the
results in memory, and exposes them to the UI / report layer.

Usage:
    from phonepe_forensics.case import Case
    c = Case("/path/with/AppDomain*")
    c.run_full_extraction()      # runs every module
    c.timeline()                 # unified timeline
    c.social_graph()             # social graph
    c.findings()                 # heuristic flags
    c.export_all("./exports")    # write all artifacts
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from . import extractors as ex
from .core import CasePaths, hash_file, normalize_timestamp
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
    """In-memory container for one forensic acquisition."""

    EXTRACTORS = [
        ("identity", ex.extract_identity),
        ("transactions", ex.extract_transactions),
        ("contacts", ex.extract_contacts),
        ("chat", ex.extract_chat),
        ("notifications", ex.extract_notifications),
        ("analytics", ex.extract_analytics),
        ("financial", ex.extract_financial),
        ("travel", ex.extract_travel),
        ("payment_infra", ex.extract_payment_infra),
        ("config_state", ex.extract_config_state),
        ("recommendations", ex.extract_recommendations),
        ("media", ex.extract_media),
        ("search", ex.extract_search),
        ("webkit", ex.extract_webkit),
        ("audit", ex.extract_audit),
    ]

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.paths = CasePaths(self.root)
        self.data: Dict[str, Any] = {
            "_meta": {
                "case_root": self.root,
                "loaded_at": int(time.time() * 1000),
                "containers": self.paths.summary(),
            },
        }
        self._extracted = False
        self._timeline: Optional[List[Dict[str, Any]]] = None
        self._social_graph: Optional[Dict[str, Any]] = None
        self._findings: Optional[List[Dict[str, Any]]] = None

    # ---- validation ----
    def validate(self) -> Dict[str, Any]:
        ok = self.paths.is_valid()
        issues: List[str] = []
        if not self.paths.app_domain:
            issues.append(f"AppDomain-com.phonepe.PhonePeApp not found under {self.root}")
        if not self.paths.group_app:
            issues.append("AppDomainGroup-group.com.phonepe.PhonePeApp missing — chat/contacts unavailable")
        if not self.paths.group_shared:
            issues.append("AppDomainGroup-group.com.phonepe.shared missing — cross-app session data unavailable")
        return {"valid": ok, "issues": issues, "summary": self.paths.summary()}

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
        # Inventory snapshots
        try:
            self.data["database_inventory"] = ex.database_overview(self.paths)
        except Exception as exc:
            self.data["database_inventory"] = [{"error": str(exc)}]
        try:
            self.data["plist_inventory"] = ex.plist_overview(self.paths)
        except Exception as exc:
            self.data["plist_inventory"] = [{"error": str(exc)}]

        # Tag chat direction using the registered identity name (only known
        # AFTER both `identity` and `chat` extractions have run).
        self._tag_chat_self_direction()

        # v2 enrichment: merge Burble payment-cards (~170 historical rows
        # outside the 450-day TxnStore retention), fix classifier, decode
        # NPCI initiation codes, attribute TPAP from ConfigManagerKeyStore.
        try:
            from .v2_integration import enrich_case as _v2_enrich
            _v2_enrich(self)
        except Exception as exc:  # never break the upstream pipeline
            self.data["_v2_error"] = str(exc)

        # Findings + timeline + graph
        self._findings = detect_suspicious_signals(self.data)
        self.data["findings"] = self._findings
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
        return build_corroboration_index(self.data)

    def lookup_counterparty(self, identifier: str) -> Dict[str, Any]:
        return build_counterparty_profile(self.data, identifier)

    # ---- top-level dashboard summary ----
    def dashboard(self) -> Dict[str, Any]:
        ident = self.data.get("identity", {})
        txn_summary = self.data.get("transactions", {}).get("summary", {})
        chat_summary = self.data.get("chat", {}).get("summary", {})
        contacts_summary = self.data.get("contacts", {}).get("summary", {})
        analytics_summary = self.data.get("analytics", {}).get("summary", {})
        v2 = self.data.get("_v2") or {}
        v2_coverage = v2.get("coverage") or {}
        # Prefer v2 unique count when available (combines TxnStore + Burble),
        # falling back to upstream extractor's count for older acquisitions
        # where Burble or PaymentDataStore is missing.
        v2_total = v2_coverage.get("combined_unique")
        return {
            "case_root": self.root,
            "valid": self.paths.is_valid(),
            "containers": self.paths.summary(),
            "identity": {
                "name": ident.get("registered_name"),
                "upi_id": ident.get("upi_id"),
                "phones": ident.get("phones_seen", []),
                "location_hints": ident.get("location_hints", []),
                "session_id_updated_at": ident.get("sessions", {}).get("session_id_updated_at"),
            },
            "metrics": {
                "transactions": v2_total if v2_total is not None else txn_summary.get("transaction_count", 0),
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
            # v2-derived tiles (None when enrichment unavailable)
            "v2": {
                "available": bool(v2),
                "coverage": v2_coverage,
                "retention_days": v2.get("retention_days"),
                "owner_vpas": v2.get("owner_vpas", []),
                "phonepe_psps": v2.get("phonepe_psps", []),
                "by_app": v2.get("by_app", {}),
                "by_initiation": v2.get("by_initiation", {}),
                "qr_scan_count": v2.get("qr_scan_count", 0),
                "intent_count": v2.get("intent_count", 0),
                "failures_count": len(v2.get("failures", []) or []),
                "failures_chat_only": sum(1 for f in (v2.get("failures") or []) if f.get("is_failed_chat_only")),
                "refunds_count": len(v2.get("refunds", []) or []),
                "mandates_count": v2.get("mandates_count", 0),
                "tpap_map_size": v2.get("tpap_map_size", 0),
                "source_db_hashes": v2.get("source_db_hashes", {}),
                "subject_name": v2.get("owner_subject_name"),
                "account_no": v2.get("owner_account_no"),
                "bank_name": v2.get("owner_bank_name"),
                "ifsc": v2.get("owner_ifsc"),
            } if v2 else {"available": False},
        }

    # ---- export ----
    def export_all(self, base_dir: str = "exports") -> Dict[str, Any]:
        out_dir = os.path.join(base_dir, _safe_name(os.path.basename(self.root) or "case"))
        return export_all(
            self.data, out_dir,
            timeline=self.timeline(),
            social_graph=self.social_graph(),
            case_root=self.root,
        )


def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:80] or "case"
