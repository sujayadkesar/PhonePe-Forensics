"""
PhonePe iOS Forensics — Cross-DB Correlation Engine
==================================================
Fuses extracted evidence from multiple modules into investigation-grade artifacts:

    build_unified_timeline       chronologically merge all timestamped events
    build_social_graph           contact <-> transaction <-> chat linkage
    build_counterparty_profiles  per-counterparty aggregated dossier
    build_corroboration_index    proves a transaction with multiple sources
    detect_suspicious_signals    heuristic flags worth a forensic look
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Unified timeline
# ---------------------------------------------------------------------------

def build_unified_timeline(case_data: Dict[str, Any], limit: int = 5000) -> List[Dict[str, Any]]:
    """Merge events from every extracted module into one chronological list.

    Each event has shape:
        {when_ms, when_iso, source, kind, title, detail, link_id?, amount_inr?}
    """
    events: List[Dict[str, Any]] = []

    # Transactions
    for t in case_data.get("transactions", {}).get("transactions", []):
        ts = t.get("created_at")
        if not ts:
            # Fall back to the timestamp encoded in the global payment ID
            emb = t.get("id_embedded_ts") or {}
            if emb.get("embedded_epoch_ms"):
                ts = {"epoch_ms": emb["embedded_epoch_ms"], "iso": emb.get("embedded_iso", "")}
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "TransactionsStore",
            "kind": t.get("type") or "TRANSACTION",
            "title": _txn_title(t),
            "detail": {
                "state": t.get("state"),
                "direction": t.get("direction"),
                "counterparty": t.get("counterparty"),
                "category_code": t.get("category_code"),
                "amount_inr": t.get("amount_inr"),
                "global_payment_id": t.get("global_payment_id"),
            },
            "link_id": t.get("global_payment_id") or t.get("entity_id"),
            "amount_inr": t.get("amount_inr"),
        })

    # Chat messages (Burble)
    for m in case_data.get("chat", {}).get("messages", []):
        ts = m.get("created_at")
        if not ts:
            continue
        kind = m.get("type")
        title = (
            f"Chat payment ₹{m.get('amount_inr')}" if kind == "PAYMENT_INFO_CARD"
            else f"Chat: {kind}"
        )
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Burble",
            "kind": kind or "CHAT",
            "title": title,
            "detail": {
                "thread_id": m.get("thread_id"),
                "transaction_id": m.get("transaction_id"),
                "state": m.get("state") or m.get("payment_state"),
                "note": m.get("note"),
                "text": m.get("text_message"),
                "instrument": m.get("instrument"),
                "utr": m.get("utr"),
                "external_vpa": m.get("external_vpa"),
            },
            "link_id": m.get("transaction_id"),
            "amount_inr": m.get("amount_inr"),
        })

    # Notifications topics (PubSub) — using updated_at as proxy
    for t in case_data.get("notifications", {}).get("topics", []):
        ts = t.get("updated_at") or t.get("created_at")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "PubSubCore",
            "kind": "PUSH_TOPIC_" + (t.get("subsystem") or "?"),
            "title": f"Push topic active: {t.get('topic_id')}",
            "detail": {
                "subsystem": t.get("subsystem"),
                "subscription": t.get("subscription_status"),
                "raw_msg_count": t.get("raw_message_count"),
            },
            "link_id": t.get("topic_id"),
        })

    # KN analytics events
    for ev in case_data.get("analytics", {}).get("kn_events", []):
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "KN-Analytics",
            "kind": "EVENT_" + (ev.get("identifier") or "?"),
            "title": f"KN event: {ev.get('event_name')}",
            "detail": {"identifier": ev.get("identifier")},
        })

    # Foxtrot pending events
    for ev in case_data.get("analytics", {}).get("foxtrot_pending", [])[:1000]:
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Foxtrot-Queue",
            "kind": "ANALYTICS_PENDING",
            "title": f"Analytics event queued ({ev.get('data_size')} bytes)",
            "detail": {"failure_count": ev.get("failure_count")},
        })

    # Auth Foxtrot
    for ev in case_data.get("analytics", {}).get("auth_foxtrot_pending", []):
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "AuthFoxtrot",
            "kind": "AUTH_EVENT_PENDING",
            "title": "Auth event queued",
            "detail": {"failure_count": ev.get("failure_count")},
        })

    # Rewards
    for r in case_data.get("financial", {}).get("rewards", []):
        ts = r.get("created_at")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Rewards",
            "kind": "REWARD_" + (r.get("type") or "?"),
            "title": f"Reward: {r.get('title') or r.get('type')}",
            "detail": {
                "state": r.get("state"),
                "amount_inr": r.get("amount_inr"),
                "linked_transaction": r.get("linked_transaction"),
            },
            "link_id": r.get("linked_transaction"),
            "amount_inr": r.get("amount_inr"),
        })

    # Background sync (proves device active)
    for s in case_data.get("audit", {}).get("central_sync", []):
        ts = s.get("last_completed") or s.get("last_attempt")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "CentralSyncManager",
            "kind": "DEVICE_ACTIVE",
            "title": f"Sync: {s.get('system')}/{s.get('key')}",
            "detail": {"status": s.get("status"), "type": s.get("type")},
        })

    for s in case_data.get("audit", {}).get("bg_sync_items", []):
        ts = s.get("last_sync")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "BGFramework",
            "kind": "BACKGROUND_TASK",
            "title": f"Background task: {s.get('identifier')}",
            "detail": {},
        })

    # Recommendations signals
    for s in case_data.get("recommendations", {}).get("signals", []):
        ts = s.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Maximus",
            "kind": "RECOMMENDATION_" + (s.get("signal_type") or "?"),
            "title": f"Recommendation signal: {s.get('signal_type')}",
            "detail": {"synced": s.get("synced")},
        })

    # Search history
    for s in case_data.get("search", {}).get("recent_searches", []):
        ts = s.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "AppSearch",
            "kind": "SEARCH",
            "title": f"In-app search: {s.get('entity')}",
            "detail": {"entry_id": s.get("entry_id"), "field_id": s.get("field_id")},
        })

    # WebKit interactions
    for r in case_data.get("webkit", {}).get("resource_load_stats", []):
        ts = r.get("last_user_interaction")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "WebKit",
            "kind": "WEB_INTERACTION",
            "title": f"WebView interaction: {r.get('domain')}",
            "detail": {},
        })

    # Yatra journeys
    for j in case_data.get("travel", {}).get("journeys", []):
        ts = j.get("created_at") or j.get("updated_at")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Yatra",
            "kind": "JOURNEY_" + (j.get("state") or "?"),
            "title": f"Journey: {j.get('name')}",
            "detail": {"type": j.get("type"), "namespace": j.get("namespace")},
        })

    events.sort(key=lambda e: e["when_ms"], reverse=True)
    return events[:limit]


def _txn_title(t: Dict[str, Any]) -> str:
    cp = t.get("counterparty") or t.get("merchant_name") or "?"
    direction = t.get("direction") or "?"
    amount = t.get("amount_inr")
    arrow = "→" if direction == "OUT" else ("←" if direction == "IN" else "·")
    if amount is not None:
        return f"{direction} ₹{amount:,.2f} {arrow} {cp}"
    return f"{t.get('type')} {arrow} {cp}"


# ---------------------------------------------------------------------------
# Social graph
# ---------------------------------------------------------------------------

def build_social_graph(case_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build a counterparty-centric social graph.

    Strategy:
        * Index Sampark contacts by phone (E.164) and by VPA.
        * Walk transactions; resolve counterparty -> contact identity.
        * Walk chat groups & messages; aggregate per-counterparty.
    """
    by_phone: Dict[str, Dict[str, Any]] = {}
    by_vpa: Dict[str, Dict[str, Any]] = {}
    nodes: Dict[str, Dict[str, Any]] = {}

    contacts = case_data.get("contacts", {})
    for c in contacts.get("cyclops_contacts", []):
        node_id = (c.get("phone") or c.get("external_vpa") or c.get("connect_id") or "?").strip()
        node = {
            "node_id": node_id,
            "kind": "CONTACT",
            "name": c.get("verified_name") or c.get("external_vpa_name"),
            "phone": c.get("phone"),
            "vpa": c.get("external_vpa"),
            "on_phonepe": c.get("on_phonepe"),
            "upi_state": c.get("upi_state"),
            "txn_count_in": 0,
            "txn_count_out": 0,
            "txn_total_in": 0.0,
            "txn_total_out": 0.0,
            "chat_message_count": 0,
            "chat_payment_count": 0,
            "first_seen_iso": None,
            "last_seen_iso": None,
            "evidence_sources": ["SamparkV2"],
        }
        nodes[node_id] = node
        if c.get("phone"):
            by_phone[c["phone"]] = node
        if c.get("external_vpa"):
            by_vpa[c["external_vpa"]] = node

    # Phonebook backfill (full names for unmatched phones)
    for p in contacts.get("phonebook_contacts", []):
        normalized = p.get("normalized") or p.get("raw_number")
        if not normalized:
            continue
        node = by_phone.get(normalized)
        if node and not node.get("name") and p.get("full_name"):
            node["name"] = p["full_name"]
        else:
            # standalone phonebook node (no PhonePe match)
            if normalized in nodes:
                continue
            nodes[normalized] = {
                "node_id": normalized,
                "kind": "PHONEBOOK_ONLY",
                "name": p.get("full_name"),
                "phone": normalized,
                "vpa": None,
                "on_phonepe": False,
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "first_seen_iso": None, "last_seen_iso": None,
                "evidence_sources": ["Phonebook"],
            }

    # Transactions
    for t in case_data.get("transactions", {}).get("transactions", []):
        cp_phone = t.get("counterparty_phone")
        cp_vpa = t.get("counterparty_vpa")
        cp_name = t.get("counterparty")
        node = (cp_phone and by_phone.get(cp_phone)) or (cp_vpa and by_vpa.get(cp_vpa))
        if not node and (cp_phone or cp_vpa or cp_name):
            key = cp_phone or cp_vpa or cp_name
            node = nodes.setdefault(key, {
                "node_id": key,
                "kind": "TXN_DERIVED",
                "name": cp_name,
                "phone": cp_phone,
                "vpa": cp_vpa,
                "on_phonepe": None,
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "first_seen_iso": None, "last_seen_iso": None,
                "evidence_sources": ["TransactionsStore"],
            })
            if cp_phone and cp_phone not in by_phone:
                by_phone[cp_phone] = node
            if cp_vpa and cp_vpa not in by_vpa:
                by_vpa[cp_vpa] = node
        if not node:
            continue
        if "TransactionsStore" not in node["evidence_sources"]:
            node["evidence_sources"].append("TransactionsStore")
        amt = t.get("amount_inr") or 0.0
        if t.get("direction") == "IN":
            node["txn_count_in"] += 1
            if t.get("state") in ("COMPLETED", "SUCCESS"):
                node["txn_total_in"] += amt
        elif t.get("direction") == "OUT":
            node["txn_count_out"] += 1
            if t.get("state") in ("COMPLETED", "SUCCESS"):
                node["txn_total_out"] += amt
        ts = t.get("created_at")
        if ts:
            iso = ts["iso"]
            if not node["first_seen_iso"] or iso < node["first_seen_iso"]:
                node["first_seen_iso"] = iso
            if not node["last_seen_iso"] or iso > node["last_seen_iso"]:
                node["last_seen_iso"] = iso

    # Chat messages mapped to groups; group name often = counterparty name
    chat = case_data.get("chat", {})
    groups_by_id = {g.get("group_id"): g for g in chat.get("groups", [])}
    chat_buckets: Dict[str, Dict[str, Any]] = {}
    for m in chat.get("messages", []):
        thread = m.get("thread_id")
        g = groups_by_id.get(thread)
        cp_name = g.get("name") if g else thread
        if not cp_name:
            continue
        bucket = chat_buckets.setdefault(cp_name, {"messages": 0, "payments": 0, "amount": 0.0})
        bucket["messages"] += 1
        if m.get("type") == "PAYMENT_INFO_CARD":
            bucket["payments"] += 1
            bucket["amount"] += m.get("amount_inr") or 0.0

    # Merge chat data into nodes (matching by name where possible)
    name_to_node = {n["name"]: n for n in nodes.values() if n.get("name")}
    for cp_name, b in chat_buckets.items():
        node = name_to_node.get(cp_name)
        if not node:
            node = nodes.setdefault(f"chat::{cp_name}", {
                "node_id": f"chat::{cp_name}",
                "kind": "CHAT_DERIVED",
                "name": cp_name, "phone": None, "vpa": None,
                "on_phonepe": True,
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "first_seen_iso": None, "last_seen_iso": None,
                "evidence_sources": ["Burble"],
            })
        if "Burble" not in node["evidence_sources"]:
            node["evidence_sources"].append("Burble")
        # `=` not `+=` meant that when two contacts share a display name — and
        # name_to_node is a dict comprehension, so only the last one survives —
        # one node ended up carrying a single bucket's count while the other
        # showed zero. Accumulate so a collision over-counts visibly rather than
        # silently discarding a thread.
        node["chat_message_count"] = node.get("chat_message_count", 0) + b["messages"]
        node["chat_payment_count"] = node.get("chat_payment_count", 0) + b["payments"]
        node["chat_payment_total_inr"] = round(b["amount"], 2)

    nodes_list = list(nodes.values())
    nodes_list.sort(
        key=lambda n: (n.get("txn_count_in") + n.get("txn_count_out") + n.get("chat_message_count") / 5),
        reverse=True,
    )
    return {
        "nodes": nodes_list,
        "summary": {
            "total_nodes": len(nodes_list),
            "with_transactions": sum(1 for n in nodes_list if (n["txn_count_in"] + n["txn_count_out"]) > 0),
            "with_chat": sum(1 for n in nodes_list if n["chat_message_count"] > 0),
            "phone_index_size": len(by_phone),
            "vpa_index_size": len(by_vpa),
        },
    }


# ---------------------------------------------------------------------------
# Corroboration index
# ---------------------------------------------------------------------------

def build_corroboration_index(case_data: Dict[str, Any]) -> Dict[str, Any]:
    """For each transaction ID, list every database that references it.

    A transaction with high corroboration (>3 sources) is highly trustworthy.
    A transaction with only 1 source — especially if the source is non-canonical
    (e.g. Burble notification only) — may indicate tampering.
    """
    index: Dict[str, Dict[str, Any]] = {}

    for t in case_data.get("transactions", {}).get("transactions", []):
        for tid in (t.get("global_payment_id"), t.get("entity_id")):
            if not tid:
                continue
            entry = index.setdefault(tid, {
                "txn_id": tid,
                "sources": [],
                "amount_inr": t.get("amount_inr"),
                "counterparty": t.get("counterparty"),
                "earliest_iso": None,
            })
            entry["sources"].append("TransactionsStore")
            if t.get("created_at") and (
                entry["earliest_iso"] is None or t["created_at"]["iso"] < entry["earliest_iso"]
            ):
                entry["earliest_iso"] = t["created_at"]["iso"]

    for m in case_data.get("chat", {}).get("messages", []):
        for tid in (m.get("transaction_id"), m.get("receiver_txn_id"), m.get("sender_txn_id")):
            if not tid:
                continue
            entry = index.setdefault(tid, {"txn_id": tid, "sources": [], "amount_inr": m.get("amount_inr"), "counterparty": None, "earliest_iso": None})
            entry["sources"].append("Burble")
            if m.get("amount_inr") and not entry.get("amount_inr"):
                entry["amount_inr"] = m["amount_inr"]

    for r in case_data.get("financial", {}).get("rewards", []):
        tid = r.get("linked_transaction")
        if not tid:
            continue
        entry = index.setdefault(tid, {"txn_id": tid, "sources": [], "amount_inr": None, "counterparty": None, "earliest_iso": None})
        entry["sources"].append("Rewards")

    items = list(index.values())
    for it in items:
        it["sources"] = sorted(set(it["sources"]))
        it["corroboration_score"] = len(it["sources"])
    items.sort(key=lambda x: x["corroboration_score"], reverse=True)
    return {
        "items": items,
        "summary": {
            "total_unique_txn_ids": len(items),
            "max_corroboration": items[0]["corroboration_score"] if items else 0,
            "single_source_count": sum(1 for it in items if it["corroboration_score"] == 1),
        },
    }


# ---------------------------------------------------------------------------
# Suspicious-signal heuristics
# ---------------------------------------------------------------------------

def detect_suspicious_signals(case_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Lightweight heuristic flags. Each finding is informational, not conclusive.

    Categories:
        * High deletion intensity in critical DB
        * Failed/pending transactions concentrated near a specific time
        * Very large transactions
        * Money requests that expired without resolution
        * Foxtrot queue with high failure counts (events never reached server)
    """
    findings: List[Dict[str, Any]] = []

    # Deletion intensity
    for db_name in ("transactions", "contacts", "chat"):
        sigs = case_data.get(db_name, {}).get("summary", {}).get("deletion_signals", {})
        if not sigs and db_name in case_data:
            sigs = case_data[db_name].get("deletion_signals", {})
        if sigs and sigs.get("deletion_intensity") == "high":
            findings.append({
                "severity": "high",
                "category": "data_deletion",
                "title": f"High deletion intensity in {db_name} DB",
                "detail": sigs,
            })

    # Failed/pending transactions
    txns = case_data.get("transactions", {}).get("transactions", [])
    # PhonePe writes several failure words depending on the leg that failed, and
    # a state the list does not name produces no finding at all — a failed
    # payment that silently reads as unremarkable. Compared case-insensitively
    # because the casing is not consistent across tables.
    _FAILED_STATES = {
        "FAILED", "FAILURE", "ERRORED", "ERROR", "REJECTED", "DECLINED",
        "CANCELLED", "CANCELED", "TIMED_OUT", "EXPIRED",
        "PENDING", "IN_PROGRESS", "INITIATED",
    }
    failed = [t for t in txns
              if str(t.get("state") or "").strip().upper() in _FAILED_STATES]
    if failed:
        findings.append({
            "severity": "medium",
            "category": "failed_transactions",
            "title": f"{len(failed)} failed/pending transactions",
            "detail": {
                "count": len(failed),
                "sample_ids": [f.get("global_payment_id") for f in failed[:5]],
            },
        })

    # Very large transactions (> ₹50,000 in a single P2P)
    large = [t for t in txns if (t.get("amount_inr") or 0) >= 50_000 and t.get("state") in ("COMPLETED", "SUCCESS")]
    if large:
        findings.append({
            "severity": "info",
            "category": "high_value_transactions",
            "title": f"{len(large)} transactions ≥ ₹50,000",
            "detail": {
                "count": len(large),
                "biggest": max((t.get("amount_inr") or 0) for t in large),
                "sample": [
                    {"id": t.get("global_payment_id"), "amount_inr": t.get("amount_inr"),
                     "counterparty": t.get("counterparty")}
                    for t in sorted(large, key=lambda x: x.get("amount_inr") or 0, reverse=True)[:5]
                ],
            },
        })

    # Pending Foxtrot events with high failure count (analytics that never reached server)
    pending_fox = case_data.get("analytics", {}).get("foxtrot_pending", [])
    high_fail = [e for e in pending_fox if (e.get("failure_count") or 0) >= 3]
    if high_fail:
        findings.append({
            "severity": "info",
            "category": "analytics_loss",
            "title": f"{len(high_fail)} analytics events stuck in upload (≥3 retries)",
            "detail": {"count": len(high_fail)},
        })

    # Single-source transactions (no chat/reward corroboration)
    corr = build_corroboration_index(case_data)
    one_source = [it for it in corr["items"] if it["corroboration_score"] == 1 and "TransactionsStore" not in it["sources"]]
    if one_source:
        findings.append({
            "severity": "medium",
            "category": "uncorroborated_transactions",
            "title": f"{len(one_source)} txn IDs only seen outside the master ledger",
            "detail": {"sample": one_source[:5]},
        })

    # Wallet balance > 0 (relevant to investigation scope)
    wallet = case_data.get("payment_infra", {}).get("wallet")
    if wallet and (wallet.get("balance_inr") or 0) > 0:
        findings.append({
            "severity": "info",
            "category": "wallet_balance",
            "title": f"PhonePe Gift Voucher (eGV) wallet balance: ₹{wallet['balance_inr']}",
            "detail": wallet,
        })

    return findings


# ---------------------------------------------------------------------------
# Counterparty profile (per-contact dossier)
# ---------------------------------------------------------------------------

def build_counterparty_profile(case_data: Dict[str, Any], identifier: str) -> Dict[str, Any]:
    """Return everything we know about a counterparty (phone, VPA, or name)."""
    out: Dict[str, Any] = {
        "identifier": identifier,
        "matched_contacts": [],
        "transactions": [],
        "chat_messages": [],
        "rewards": [],
        "summary": {},
    }
    ident = identifier.lower()
    contacts = case_data.get("contacts", {})

    for c in contacts.get("cyclops_contacts", []):
        if (
            (c.get("phone") and ident in c["phone"].lower())
            or (c.get("verified_name") and ident in c["verified_name"].lower())
            or (c.get("external_vpa") and ident in c["external_vpa"].lower())
            or (c.get("external_vpa_name") and ident in c["external_vpa_name"].lower())
        ):
            out["matched_contacts"].append(c)

    for c in contacts.get("phonebook_contacts", []):
        if (
            (c.get("normalized") and ident in c["normalized"].lower())
            or (c.get("full_name") and ident in c["full_name"].lower())
            or (c.get("raw_number") and ident in c["raw_number"].lower())
        ):
            out["matched_contacts"].append(c)

    for t in case_data.get("transactions", {}).get("transactions", []):
        if (
            (t.get("counterparty") and ident in str(t["counterparty"]).lower())
            or (t.get("counterparty_phone") and ident in str(t["counterparty_phone"]).lower())
            or (t.get("counterparty_vpa") and ident in str(t["counterparty_vpa"]).lower())
            or (t.get("search_token") and ident in t["search_token"].lower())
        ):
            out["transactions"].append(t)

    chat = case_data.get("chat", {})
    groups_by_id = {g.get("group_id"): g for g in chat.get("groups", [])}
    for m in chat.get("messages", []):
        g = groups_by_id.get(m.get("thread_id"))
        if g and g.get("name") and ident in g["name"].lower():
            out["chat_messages"].append({**m, "group_name": g.get("name")})

    for r in case_data.get("financial", {}).get("rewards", []):
        if r.get("linked_transaction"):
            for t in out["transactions"]:
                if t.get("global_payment_id") == r["linked_transaction"]:
                    out["rewards"].append(r)
                    break

    total_in = sum(t.get("amount_inr") or 0 for t in out["transactions"] if t.get("direction") == "IN" and t.get("state") in ("COMPLETED", "SUCCESS"))
    total_out = sum(t.get("amount_inr") or 0 for t in out["transactions"] if t.get("direction") == "OUT" and t.get("state") in ("COMPLETED", "SUCCESS"))
    out["summary"] = {
        "matched_contact_count": len(out["matched_contacts"]),
        "transaction_count": len(out["transactions"]),
        "chat_message_count": len(out["chat_messages"]),
        "reward_count": len(out["rewards"]),
        "total_received_inr": round(total_in, 2),
        "total_sent_inr": round(total_out, 2),
        "net_inr": round(total_in - total_out, 2),
    }
    return out
