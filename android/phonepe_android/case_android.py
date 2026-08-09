"""
PhonePe Android Forensics — Case orchestrator
=============================================
``AndroidCase`` implements the ``Case`` object interface that ``webapp.py`` /
``case_manager.py`` depend on, by SUBCLASSING ``phonepe_forensics.case.Case`` and
inheriting its platform-agnostic derived views:

    timeline() · social_graph() · findings() · corroboration() ·
    lookup_counterparty() · dashboard() · export_all()

…all of which operate purely over ``self.data`` (the normalized contract). We override only
the Android-specific pieces:

    __init__              → AndroidCasePaths (the com.phonepe.app data layout)
    EXTRACTORS            → the Android extractor functions
    run_full_extraction   → run the Android extractors
    validate              → Android layout validation

``dashboard()`` is inherited unchanged — it reads only the normalized contract.
``_tag_chat_self_direction`` is normalized-data logic and is reused as-is.
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from phonepe_forensics.case import Case
from phonepe_forensics.correlator import build_unified_timeline, detect_suspicious_signals

from . import extractors_android as aex
from .core_android import AndroidCasePaths

_SMS_AMOUNT_RX = re.compile(r"(?:rs\.?|inr|₹)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
_SMS_FIN_RX = re.compile(r"debit|credit|sent|received|paid|withdraw|spent|txn|transaction|a/c|upi", re.I)


def _rupees_to_paise(value: Any) -> Optional[int]:
    """Rupee amount → integer paise. Decimal, not float: `float('0.07') * 100`
    is 7.000000000000001, and rounding that is how an exact match silently misses."""
    if value is None:
        return None
    try:
        return int((Decimal(str(value).replace(",", "").strip()) * 100).to_integral_value())
    except (InvalidOperation, ValueError, TypeError):
        return None


class AndroidCase(Case):
    """In-memory container for one PhonePe Android acquisition."""

    PATHS_CLASS = AndroidCasePaths

    EXTRACTORS = [
        ("transactions", aex.extract_transactions),
        ("identity", aex.extract_identity),
        ("contacts", aex.extract_contacts),
        ("chat", aex.extract_chat),
        ("payment_infra", aex.extract_payment_infra),
        ("notifications", aex.extract_notifications),
        ("analytics", aex.extract_analytics),
        ("financial", aex.extract_financial),
        ("travel", aex.extract_travel),
        ("config_state", aex.extract_config_state),
        ("recommendations", aex.extract_recommendations),
        ("search", aex.extract_search),
        ("webkit", aex.extract_webkit),
        ("media", aex.extract_media),
        ("audit", aex.extract_audit),
        ("ledger", aex.extract_ledger),      # bill-splitting / shared expenses ("Split")
        ("sms", aex.extract_sms),            # Android-exclusive
        ("miniapps", aex.extract_miniapps),  # Android-exclusive (Nirvana RN services)
        # --- full-coverage layer: "parse everything, nothing skipped" ---
        ("files", aex.extract_files),                 # all files/ + DataStore protobuf + JSON
        ("shared_prefs", aex.extract_shared_prefs),   # all 176 shared_prefs/*.xml
        ("raw_tables", aex.extract_raw_tables),       # every row of every readable SQLite table
        ("encrypted_dbs", aex.extract_encrypted_dbs), # explicit record of unreadable encrypted DBs
        ("deleted_records", aex.extract_deleted_records),  # carved from freed space + WAL
    ]

    def __init__(self, root: str):
        self._init_state(root, AndroidCasePaths(os.path.abspath(root)), platform="android")

    def validate(self) -> Dict[str, Any]:
        ok = self.paths.is_valid()
        issues: List[str] = []
        if not self.paths.app_dir:
            issues.append(f"PhonePe app data dir (com.phonepe.app) not found under {self.root}")
        elif not self.paths.databases_dir:
            issues.append("databases/ directory not found in the app data dir")
        elif not self.paths.db("phonepe_core"):
            issues.append("phonepe_core database not found — this may not be a PhonePe Android extraction")
        if not self.paths.shared_prefs_dir:
            issues.append("shared_prefs/ missing — identity/token enrichment will be limited")
        return {"valid": ok, "issues": issues, "summary": self.paths.summary()}

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
        try:
            self.data["database_inventory"] = aex.database_overview(self.paths)
        except Exception as exc:
            self.data["database_inventory"] = [{"error": str(exc)}]

        # NOTE: chat direction/is_self/other_party are set directly in extract_chat using
        # per-topic ownMemberId (more reliable than name-matching), so we deliberately
        # do NOT call _tag_chat_self_direction here.
        # NOTE: no extra enrichment pass — the Android extractors are self-contained.

        self._findings = detect_suspicious_signals(self.data) + self._android_findings()
        self.data["findings"] = self._findings
        self.data["_meta"]["completed_at"] = int(time.time() * 1000)
        self._extracted = True
        return self.data

    # ---- Android-specific analysis (kept in this package, not the shared correlator) ----

    def timeline(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Unified timeline = shared correlator events + Android-only sources (SMS, ledger)."""
        if self._timeline is None:
            events = build_unified_timeline(self.data, limit=999_999)
            events.extend(self._android_timeline_events())
            events.sort(key=lambda e: e["when_ms"], reverse=True)
            self._timeline = events
        return self._timeline[:limit]

    def _android_timeline_events(self) -> List[Dict[str, Any]]:
        ev: List[Dict[str, Any]] = []
        for m in self.data.get("sms", {}).get("messages", []):
            ts = m.get("received_at")
            if ts:
                ev.append({"when_ms": ts["epoch_ms"], "when_iso": ts["iso"], "source": "SMS",
                           "kind": "SMS", "title": f"SMS from {m.get('address')}",
                           "detail": {"body": (m.get("body") or "")[:160]}, "link_id": None})
        for e in self.data.get("ledger", {}).get("expenses", []):
            ts = e.get("created_at")
            if ts:
                ev.append({"when_ms": ts["epoch_ms"], "when_iso": ts["iso"], "source": "Ledger",
                           "kind": "SPLIT_" + (e.get("type") or "EXPENSE"),
                           "title": f"Split: {e.get('payer') or '?'} paid ₹{e.get('amount_inr')}",
                           "detail": {"settlement_txn": e.get("settlement_txn_id")},
                           "link_id": e.get("settlement_txn_id"), "amount_inr": e.get("amount_inr")})
        return ev

    def sms_corroboration(self) -> Dict[str, Any]:
        """Cross-check the transaction ledger against ingested bank SMS.

        Surfaces: txns confirmed by an independent SMS, txns with no SMS (possible
        deletion), and financial SMS with no matching txn (activity outside the app).

        Matching is exact to the paise and one-to-one, assigned closest-in-time
        first. The previous ±₹1 tolerance with first-match-wins could pair a
        transaction with a different payment of a similar amount, and whichever
        transaction happened to be iterated first claimed the SMS — so the
        confirmed/uncorroborated counts that end up in a report depended on row
        order rather than on the evidence.
        """
        WINDOW_MS = 30 * 60 * 1000  # ±30 min
        txns = [t for t in self.data.get("transactions", {}).get("transactions", [])
                if t.get("amount_inr") is not None and t.get("created_at")]
        sms = []
        for m in self.data.get("sms", {}).get("messages", []):
            body = m.get("body") or ""
            am = _SMS_AMOUNT_RX.search(body)
            if not am or not _SMS_FIN_RX.search(body) or not m.get("received_at"):
                continue
            paise = _rupees_to_paise(am.group(1))
            if paise is None:
                continue
            sms.append({"paise": paise, "ms": m["received_at"]["epoch_ms"],
                        "sender": m.get("address"), "body": body})

        # Score every candidate pair, then assign greedily by smallest time gap so
        # the nearest SMS wins regardless of iteration order.
        by_paise: Dict[int, List[int]] = defaultdict(list)
        for i, s in enumerate(sms):
            by_paise[s["paise"]].append(i)
        candidates = []
        for ti, t in enumerate(txns):
            tms = t["created_at"]["epoch_ms"]
            tpaise = t.get("amount_paise")
            if tpaise is None:
                tpaise = _rupees_to_paise(t["amount_inr"])
            if tpaise is None:
                continue
            for si in by_paise.get(tpaise, ()):
                gap = abs(sms[si]["ms"] - tms)
                if gap <= WINDOW_MS:
                    candidates.append((gap, ti, si))
        candidates.sort()

        matches, used_sms, used_txn = [], set(), set()
        for gap, ti, si in candidates:
            if ti in used_txn or si in used_sms:
                continue
            used_txn.add(ti); used_sms.add(si)
            t, s = txns[ti], sms[si]
            matches.append({"txn_time": t["created_at"]["iso"], "amount_inr": t["amount_inr"],
                            "direction": t.get("direction"), "counterparty": t.get("counterparty"),
                            "sms_sender": s["sender"], "sms_snippet": s["body"][:120],
                            "delta_seconds": round(gap / 1000)})
        matches.sort(key=lambda m: m["txn_time"], reverse=True)
        return {
            "confirmed_count": len(used_txn),
            "uncorroborated_count": len(txns) - len(used_txn),
            "sms_only_count": len(sms) - len(used_sms),
            "financial_sms_count": len(sms),
            "match_rule": "exact paise, ±30 min, one-to-one, nearest in time first",
            "matches": matches,
        }

    def _android_findings(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        dev = self.data.get("identity", {}).get("device_identifiers", {})
        if dev.get("is_rooted") is True:
            out.append({"severity": "high", "category": "rooted_device",
                        "title": "Device is rooted", "detail": {"model": dev.get("device_model")}})
        deleted = self.data.get("deleted_records", {})
        recovered = (deleted.get("summary") or {}).get("recovered_count") or 0
        if recovered:
            by_table = (deleted["summary"].get("by_table") or {})
            headline = ", ".join(f"{n} {t}" for t, n in
                                 sorted(by_table.items(), key=lambda kv: -kv[1])[:3])
            # Deletion is the finding — what was removed, and from where.
            out.append({
                "severity": "high", "category": "recovered_deleted_records",
                "title": f"{recovered} deleted record(s) recovered from freed space "
                         f"({headline})",
                "detail": {k: deleted["summary"][k] for k in
                           ("by_table", "by_pool", "high_confidence", "partial", "ambiguous")
                           if k in deleted["summary"]},
            })
        carved_dbs = (deleted.get("summary") or {}).get("databases_carved") or []
        if carved_dbs and not recovered:
            out.append({
                "severity": "info", "category": "no_deleted_records_recovered",
                "title": f"No deleted records were recoverable from {len(carved_dbs)} "
                         f"database(s) — not evidence that nothing was deleted",
                "detail": {"databases": carved_dbs,
                           "note": "Freed space is reused over time, and a device with "
                                   "secure_delete enabled zeroes it on deletion."},
            })
        enc = self.data.get("encrypted_dbs", {}).get("encrypted", [])
        if enc:
            out.append({"severity": "info", "category": "encrypted_databases",
                        "title": f"{len(enc)} encrypted DB(s) present (not decryptable offline)",
                        "detail": {"names": [e["name"] for e in enc]}})
        try:
            corr = self.sms_corroboration()
            if corr["uncorroborated_count"] and corr["financial_sms_count"]:
                out.append({"severity": "info", "category": "sms_corroboration",
                            "title": f"{corr['confirmed_count']} txns confirmed by bank SMS; "
                                     f"{corr['sms_only_count']} financial SMS without a matching txn",
                            "detail": {k: corr[k] for k in ("confirmed_count", "uncorroborated_count", "sms_only_count")}})
        except Exception:
            pass
        return out
