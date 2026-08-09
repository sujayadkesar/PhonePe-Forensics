"""
PhonePe Android Forensics — Cross-DB Correlation Engine
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

# Transaction-state vocabulary lives in the platform-neutral core so the parser and
# this module cannot disagree about what "succeeded" means. See core/common.py.
from .core import (  # noqa: F401
    FAILED_STATES, PENDING_STATES, SUCCESS_STATES, normalise_state,
)


def _state(txn: Dict[str, Any]) -> str:
    return normalise_state(txn.get("state"))


def is_success(txn: Dict[str, Any]) -> bool:
    """True when this transaction's state means money actually moved."""
    return _state(txn) in SUCCESS_STATES


def is_unsuccessful(txn: Dict[str, Any]) -> bool:
    """True for failed *or* still-pending payments."""
    s = _state(txn)
    return s in FAILED_STATES or s in PENDING_STATES


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
            "source": "Transactions",
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

    # Chat messages (Chat)
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
            "source": "Chat",
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
            "source": "Notifications",
            "kind": "PUSH_TOPIC_" + (t.get("subsystem") or "?"),
            "title": f"Push topic active: {t.get('topic_id')}",
            "detail": {
                "subsystem": t.get("subsystem"),
                "subscription": t.get("subscription_status"),
                "raw_msg_count": t.get("raw_message_count"),
            },
            "link_id": t.get("topic_id"),
        })

    # Delivered notifications. A topic's updated_at only says the channel was
    # active; these are the messages the user was actually shown, with their own
    # arrival times — and on a real device they reach years further back than the
    # transaction ledger does, so they carry much of the timeline's early history.
    for m in case_data.get("notifications", {}).get("raw_messages", []):
        if not m.get("is_notification"):
            continue                       # sync instructions are machine chatter
        ts = m.get("created_at") or m.get("sent_at")
        if not ts:
            continue
        title = m.get("title") or m.get("body") or "(no title)"
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Notification",
            "kind": "NOTIFICATION_SHOWN",
            "title": f"Notification: {title}",
            "detail": {"subtitle": m.get("subtitle"), "deeplink": m.get("deeplink"),
                       "template": m.get("template"), "topic_id": m.get("topic_id")},
            "link_id": m.get("message_id"),
        })

    # KN analytics events
    for ev in case_data.get("analytics", {}).get("kn_events", []):
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Analytics",
            "kind": "EVENT_" + (ev.get("identifier") or "?"),
            "title": f"KN event: {ev.get('event_name')}",
            "detail": {"identifier": ev.get("identifier")},
        })

    # Analytics pending events
    for ev in case_data.get("analytics", {}).get("foxtrot_pending", [])[:1000]:
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Analytics-Pending",
            "kind": "ANALYTICS_PENDING",
            "title": f"Analytics event queued ({ev.get('data_size')} bytes)",
            "detail": {"failure_count": ev.get("failure_count")},
        })

    # Auth Analytics
    for ev in case_data.get("analytics", {}).get("auth_foxtrot_pending", []):
        ts = ev.get("timestamp")
        if not ts:
            continue
        events.append({
            "when_ms": ts["epoch_ms"],
            "when_iso": ts["iso"],
            "source": "Auth-Events",
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
            "source": "Sync",
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
            "source": "Background",
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
            "source": "Recommendations",
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
        * Index contacts by phone (E.164) and by VPA.
        * Walk transactions; resolve counterparty -> contact identity.
        * Walk chat groups & messages; aggregate per-counterparty.
    """
    by_phone: Dict[str, Dict[str, Any]] = {}
    by_vpa: Dict[str, Dict[str, Any]] = {}
    by_connection: Dict[str, Dict[str, Any]] = {}
    nodes: Dict[str, Dict[str, Any]] = {}

    contacts = case_data.get("contacts", {})
    for pos, c in enumerate(contacts.get("cyclops_contacts", [])):
        identifier = (c.get("phone") or c.get("external_vpa") or c.get("connect_id") or "").strip()
        # A contact with no phone, VPA or connection id is still a distinct person.
        # Keying them all on a shared placeholder merged every unidentifiable
        # contact into one node carrying the first one's name.
        node_id = identifier or f"unidentified::{pos}"
        node = nodes.get(node_id) or {
            "node_id": node_id,
            "kind": "CONTACT" if identifier else "CONTACT_UNIDENTIFIED",
            "name": c.get("verified_name") or c.get("external_vpa_name"),
            "phone": c.get("phone"),
            "vpa": c.get("external_vpa"),
            "connection_id": c.get("connect_id"),
            "on_phonepe": c.get("on_phonepe"),
            "upi_state": c.get("upi_state"),
            "txn_count_in": 0,
            "txn_count_out": 0,
            "txn_total_in": 0.0,
            "txn_total_out": 0.0,
            "chat_message_count": 0,
            "chat_payment_count": 0,
            "chat_payment_total_inr": 0.0,
            "first_seen_iso": None,
            "last_seen_iso": None,
            "evidence_sources": ["phone_contacts"],
        }
        # Several contact tables can describe the same person; fill gaps rather
        # than letting the last row seen overwrite a better-populated one.
        for key, val in (("name", c.get("verified_name") or c.get("external_vpa_name")),
                         ("vpa", c.get("external_vpa")),
                         ("connection_id", c.get("connect_id")),
                         ("upi_state", c.get("upi_state"))):
            if val and not node.get(key):
                node[key] = val
        # `on_phonepe` cannot ride the gap-fill above, for two reasons. False is
        # falsy, so `not node.get(key)` reads a stored False as "no value yet";
        # and the rule is not gap-fill but *any-row-wins* — the one the contacts
        # page states in words ("true if any row for that person states it").
        # Without this the graph was first-row-wins, so for the 3 people whose
        # duplicate rows disagree, /contacts counted them on PhonePe while the
        # social graph said they were not: one exhibit contradicting itself.
        row_on_pp = c.get("on_phonepe")
        if row_on_pp is True:
            node["on_phonepe"] = True
        elif row_on_pp is False and node.get("on_phonepe") is None:
            node["on_phonepe"] = False
        nodes[node_id] = node
        if c.get("phone"):
            by_phone.setdefault(c["phone"], node)
        if c.get("external_vpa"):
            by_vpa.setdefault(c["external_vpa"], node)
        if c.get("connect_id"):
            by_connection.setdefault(c["connect_id"], node)

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
                "connection_id": None,
                # Not False: this node exists precisely because the phonebook entry
                # matched no PhonePe contact record, which is absence of evidence,
                # not evidence of absence. `kind: PHONEBOOK_ONLY` already carries
                # "no PhonePe record found" without asserting the person has none.
                "on_phonepe": None,
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "chat_payment_total_inr": 0.0,
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
                "connection_id": None,
                "on_phonepe": None,
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "chat_payment_total_inr": 0.0,
                "first_seen_iso": None, "last_seen_iso": None,
                "evidence_sources": ["Transactions"],
            })
            if cp_phone and cp_phone not in by_phone:
                by_phone[cp_phone] = node
            if cp_vpa and cp_vpa not in by_vpa:
                by_vpa[cp_vpa] = node
        if not node:
            continue
        if "Transactions" not in node["evidence_sources"]:
            node["evidence_sources"].append("Transactions")
        amt = t.get("amount_inr") or 0.0
        if t.get("direction") == "IN":
            node["txn_count_in"] += 1
            if is_success(t):
                node["txn_total_in"] += amt
        elif t.get("direction") == "OUT":
            node["txn_count_out"] += 1
            if is_success(t):
                node["txn_total_out"] += amt
        ts = t.get("created_at")
        if ts:
            iso = ts["iso"]
            if not node["first_seen_iso"] or iso < node["first_seen_iso"]:
                node["first_seen_iso"] = iso
            if not node["last_seen_iso"] or iso > node["last_seen_iso"]:
                node["last_seen_iso"] = iso

    # Chat messages, attributed by connection id.
    #
    # Display names are NOT identities: two contacts can share a name, and keying
    # chat activity on the name collapses both threads onto whichever node was
    # built last. Every chat member carries a connectionId (public_id) that is the
    # same identifier a contact row exposes as connect_id, so that is the join.
    # A message whose counterparty cannot be resolved to a connection is bucketed
    # by its thread and reported as thread-only rather than guessed onto a name.
    chat = case_data.get("chat", {})
    groups_by_id = {g.get("group_id"): g for g in chat.get("groups", [])}
    member_conn: Dict[Any, str] = {}
    member_display: Dict[Any, str] = {}
    member_on_phonepe: Dict[Any, bool] = {}
    for mem in chat.get("members", []):
        mid = mem.get("internal_id")
        if mid is None:
            continue
        if mem.get("public_id"):
            member_conn.setdefault(mid, mem["public_id"])
        if mem.get("display_name"):
            member_display.setdefault(mid, mem["display_name"])
        if mem.get("phonepe_user") is not None:
            member_on_phonepe.setdefault(mid, bool(mem["phonepe_user"]))
    # Threads with exactly one non-self member are 1:1, so every message in them
    # belongs to that connection even when the message rows carry no member id.
    solo_conn_by_thread: Dict[Any, str] = {}
    solo_name_by_thread: Dict[Any, str] = {}
    solo_on_phonepe_by_thread: Dict[Any, bool] = {}
    members_by_thread: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for mem in chat.get("members", []):
        members_by_thread[mem.get("group_id")].append(mem)
    for thread, mems in members_by_thread.items():
        others = [m for m in mems if not m.get("is_self")]
        if len(others) == 1 and others[0].get("public_id"):
            solo_conn_by_thread[thread] = others[0]["public_id"]
            solo_name_by_thread[thread] = others[0].get("display_name")
            if others[0].get("phonepe_user") is not None:
                solo_on_phonepe_by_thread[thread] = bool(others[0]["phonepe_user"])

    chat_buckets: Dict[str, Dict[str, Any]] = {}
    for m in chat.get("messages", []):
        thread = m.get("thread_id")
        other_member = (m.get("receiver_member_id") if m.get("sender_is_self") is True
                        else m.get("sender_member_id") if m.get("sender_is_self") is False
                        else None)
        conn = member_conn.get(other_member) if other_member is not None else None
        if not conn:
            conn = solo_conn_by_thread.get(thread)
        on_pp = member_on_phonepe.get(other_member)
        if on_pp is None:
            on_pp = solo_on_phonepe_by_thread.get(thread)
        if conn:
            key, resolved = f"conn::{conn}", True
            label = member_display.get(other_member) or solo_name_by_thread.get(thread)
        else:
            if not thread:
                continue
            key, resolved = f"thread::{thread}", False
            g = groups_by_id.get(thread)
            label = (g or {}).get("name") or thread
        bucket = chat_buckets.setdefault(key, {
            "messages": 0, "payments": 0, "amount": 0.0,
            "connection_id": conn, "resolved": resolved, "label": label,
            "on_phonepe": on_pp,
        })
        if bucket.get("on_phonepe") is None and on_pp is not None:
            bucket["on_phonepe"] = on_pp
        if not bucket.get("label") and label:
            bucket["label"] = label
        bucket["messages"] += 1
        if m.get("type") == "PAYMENT_INFO_CARD":
            bucket["payments"] += 1
            bucket["amount"] += m.get("amount_inr") or 0.0

    for key, b in chat_buckets.items():
        node = by_connection.get(b["connection_id"]) if b["connection_id"] else None
        if not node:
            node = nodes.setdefault(f"chat::{key}", {
                "node_id": f"chat::{key}",
                "kind": "CHAT_DERIVED" if b["resolved"] else "CHAT_THREAD_ONLY",
                "name": b.get("label"), "phone": None, "vpa": None,
                "connection_id": b["connection_id"],
                # Was hardcoded True on the reasoning that a chat counterparty must
                # be a PhonePe user. The chat member record already states it
                # (`topicMember.onPhonePe`), so read the evidence instead of
                # inferring it, and leave it unknown when no member row resolves —
                # a thread-only bucket has no member to speak for.
                "on_phonepe": b.get("on_phonepe"),
                "txn_count_in": 0, "txn_count_out": 0,
                "txn_total_in": 0.0, "txn_total_out": 0.0,
                "chat_message_count": 0, "chat_payment_count": 0,
                "chat_payment_total_inr": 0.0,
                "first_seen_iso": None, "last_seen_iso": None,
                "evidence_sources": ["Chat"],
            })
            if not b["resolved"]:
                node["attribution_note"] = (
                    "Thread has no resolvable connection id; counted against the thread, "
                    "not matched to a contact."
                )
        if "Chat" not in node["evidence_sources"]:
            node["evidence_sources"].append("Chat")
        node["chat_message_count"] = node.get("chat_message_count", 0) + b["messages"]
        node["chat_payment_count"] = node.get("chat_payment_count", 0) + b["payments"]
        node["chat_payment_total_inr"] = round(
            (node.get("chat_payment_total_inr") or 0.0) + b["amount"], 2)

    nodes_list = list(nodes.values())
    nodes_list.sort(
        key=lambda n: (n.get("txn_count_in", 0) + n.get("txn_count_out", 0)
                       + n.get("chat_message_count", 0) / 5),
        reverse=True,
    )
    return {
        "nodes": nodes_list,
        "summary": {
            "total_nodes": len(nodes_list),
            "with_transactions": sum(1 for n in nodes_list
                                     if (n.get("txn_count_in", 0) + n.get("txn_count_out", 0)) > 0),
            "with_chat": sum(1 for n in nodes_list if n.get("chat_message_count", 0) > 0),
            "phone_index_size": len(by_phone),
            "vpa_index_size": len(by_vpa),
            "connection_index_size": len(by_connection),
            "chat_threads_unattributed": sum(1 for b in chat_buckets.values() if not b["resolved"]),
        },
    }


# ---------------------------------------------------------------------------
# Corroboration index
# ---------------------------------------------------------------------------

# Which chat card type contributed an identifier, and therefore what the id IS.
# EXPENSE_CARD_V2 carries an *expense* id (a split line item) — a bookkeeping
# entity that never has a transaction_core row, because no money moved when it was
# created. Counting those as "payments missing from the master ledger" put 25
# non-payments into that finding on the test acquisition.
_CHAT_REF_KIND = {
    "PAYMENT_INFO_CARD": "chat_payment_card",
    "TRANSACTION_RECEIPT": "chat_receipt",
    "SETTLEMENT_CARD": "chat_settlement",
    "EXPENSE_CARD_V2": "split_expense",
    "GROUP_ACTION": "group_action",
}

# Reference kinds that assert an actual money movement, and so imply a
# transaction_core row ought to exist. Settlements are included: a settlement is
# paid, and its id is observed to match a global_payment_id in real data.
_PAYMENT_REF_KINDS = frozenset({
    "ledger_row", "chat_payment_card", "chat_receipt", "chat_settlement",
    "reward_link", "split_settlement",
})


def build_corroboration_index(case_data: Dict[str, Any]) -> Dict[str, Any]:
    """For each *transaction*, list every place in the acquisition that references it.

    One real payment carries several identifiers — the global payment id, the
    local entity id, the id echoed in a chat card. They are aliases, so they are
    folded onto a single entry: counting them separately would report one payment
    as two uncorroborated transactions.

    A payment referenced by several independent sources is well corroborated. One
    seen only outside the master ledger (e.g. a chat card with no matching
    transaction_core row) is worth a look — it can mean the ledger row was deleted.
    """
    entries: List[Dict[str, Any]] = []
    by_alias: Dict[str, Dict[str, Any]] = {}

    def _entry_for(alias_ids: List[Any], **seed) -> Dict[str, Any]:
        """Find (or create) the entry owning any of these ids, and merge the rest in."""
        aliases = [str(a) for a in alias_ids if a]
        if not aliases:
            return {}
        found = None
        for a in aliases:
            hit = by_alias.get(a)
            if hit is not None and hit is not found:
                if found is None:
                    found = hit
                else:
                    # Two entries turn out to be the same payment — merge them.
                    found["aliases"].update(hit["aliases"])
                    found["sources"].update(hit["sources"])
                    found["ref_kinds"].update(hit.get("ref_kinds") or ())
                    for k in ("amount_inr", "counterparty", "earliest_iso"):
                        if found.get(k) is None:
                            found[k] = hit.get(k)
                    for a2 in hit["aliases"]:
                        by_alias[a2] = found
                    if hit in entries:
                        entries.remove(hit)
        if found is None:
            found = {
                "txn_id": aliases[0],
                "aliases": set(),
                "sources": set(),
                # What KIND of identifier each reference was. A split expense id
                # and a payment id are both "an id seen in chat", but only one of
                # them is ever expected to have a transaction_core row, so the
                # distinction has to be carried, not inferred from the id's shape
                # (E… is an expense id in one card type and a transaction entity
                # id in another, so prefixes cannot decide it).
                "ref_kinds": set(),
                "amount_inr": seed.get("amount_inr"),
                "counterparty": seed.get("counterparty"),
                "earliest_iso": None,
            }
            entries.append(found)
        found["aliases"].update(aliases)
        for a in aliases:
            by_alias[a] = found
        return found

    for t in case_data.get("transactions", {}).get("transactions", []):
        entry = _entry_for(
            [t.get("global_payment_id"), t.get("entity_id")],
            amount_inr=t.get("amount_inr"), counterparty=t.get("counterparty"),
        )
        if not entry:
            continue
        entry["sources"].add("Transactions")
        entry["ref_kinds"].add("ledger_row")
        if entry.get("amount_inr") is None:
            entry["amount_inr"] = t.get("amount_inr")
        if entry.get("counterparty") is None:
            entry["counterparty"] = t.get("counterparty")
        ts = t.get("created_at")
        if ts and (entry["earliest_iso"] is None or ts["iso"] < entry["earliest_iso"]):
            entry["earliest_iso"] = ts["iso"]

    for m in case_data.get("chat", {}).get("messages", []):
        entry = _entry_for(
            [m.get("transaction_id"), m.get("receiver_txn_id"), m.get("sender_txn_id")],
            amount_inr=m.get("amount_inr"),
        )
        if not entry:
            continue
        entry["sources"].add("Chat")
        entry["ref_kinds"].add(_CHAT_REF_KIND.get(m.get("type"), "chat_other"))
        if entry.get("amount_inr") is None:
            entry["amount_inr"] = m.get("amount_inr")
        # Date the entry from the chat card too. Without this, any payment with no
        # transaction_core row has no date at all, and "is this older than the
        # ledger's retention window?" cannot be asked of exactly the entries the
        # question matters for.
        ts = m.get("created_at")
        if ts and (entry["earliest_iso"] is None or ts["iso"] < entry["earliest_iso"]):
            entry["earliest_iso"] = ts["iso"]
        if entry.get("counterparty") is None:
            entry["counterparty"] = m.get("other_party_name") or m.get("sender_name")

    for r in case_data.get("financial", {}).get("rewards", []):
        entry = _entry_for([r.get("linked_transaction")])
        if entry:
            entry["sources"].add("Rewards")
            entry["ref_kinds"].add("reward_link")

    for e in case_data.get("ledger", {}).get("expenses", []):
        entry = _entry_for([e.get("settlement_txn_id")], amount_inr=e.get("amount_inr"))
        if entry:
            entry["sources"].add("Ledger")
            entry["ref_kinds"].add("split_settlement")

    items = []
    for it in entries:
        it["sources"] = sorted(it["sources"])
        it["aliases"] = sorted(it["aliases"])
        it["ref_kinds"] = sorted(it["ref_kinds"])
        it["expects_ledger_row"] = any(k in _PAYMENT_REF_KINDS for k in it["ref_kinds"])
        it["corroboration_score"] = len(it["sources"])
        items.append(it)
    items.sort(key=lambda x: (x["corroboration_score"], x["txn_id"]), reverse=True)
    return {
        "items": items,
        "summary": {
            "total_unique_transactions": len(items),
            "distinct_identifiers": len(by_alias),
            "max_corroboration": items[0]["corroboration_score"] if items else 0,
            "single_source_count": sum(1 for it in items if it["corroboration_score"] == 1),
            "available_sources": ["Transactions", "Chat", "Rewards", "Ledger"],
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
        * Analytics queue with high failure counts (events never reached server)
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
    failed = [t for t in txns if is_unsuccessful(t)]
    if failed:
        by_state = Counter(_state(t) or "UNKNOWN" for t in failed)
        findings.append({
            "severity": "medium",
            "category": "failed_transactions",
            "title": f"{len(failed)} failed/pending transactions "
                     f"({', '.join(f'{n} {s}' for s, n in by_state.most_common())})",
            "detail": {
                "count": len(failed),
                "by_state": dict(by_state),
                "sample_ids": [f.get("global_payment_id") for f in failed[:5]],
            },
        })

    # A state this build has never seen is neither summed into the totals nor
    # flagged, so it has to be said out loud rather than silently ignored — that
    # is exactly how ERRORED went unreported until a real acquisition used it.
    unknown_states = Counter(
        _state(t) for t in txns
        if _state(t) and _state(t) not in SUCCESS_STATES
        and _state(t) not in FAILED_STATES and _state(t) not in PENDING_STATES
    )
    if unknown_states:
        findings.append({
            "severity": "medium",
            "category": "unrecognised_transaction_state",
            "title": f"{sum(unknown_states.values())} transaction(s) carry a state this "
                     f"build does not classify ({', '.join(sorted(unknown_states))}) — "
                     f"they are excluded from both the totals and the failed count",
            "detail": {"by_state": dict(unknown_states),
                       "known_success": sorted(SUCCESS_STATES),
                       "known_failed": sorted(FAILED_STATES | PENDING_STATES)},
        })

    # Very large transactions (> ₹50,000 in a single P2P)
    large = [t for t in txns
             if (t.get("amount_inr") or 0) >= 50_000 and is_success(t)]
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

    # Pending Analytics events with high failure count (analytics that never reached server)
    pending_fox = case_data.get("analytics", {}).get("foxtrot_pending", [])
    high_fail = [e for e in pending_fox if (e.get("failure_count") or 0) >= 3]
    if high_fail:
        findings.append({
            "severity": "info",
            "category": "analytics_loss",
            "title": f"{len(high_fail)} analytics events stuck in upload (≥3 retries)",
            "detail": {"count": len(high_fail)},
        })

    # Payments referenced somewhere in the app but absent from the master ledger —
    # a chat card or reward whose transaction_core row is gone is worth a look.
    corr = build_corroboration_index(case_data)
    # `expects_ledger_row` filters out identifiers that are not payments at all —
    # a split expense id has no transaction_core row by design, so its absence is
    # not evidence of anything.
    one_source = [it for it in corr["items"]
                  if it["corroboration_score"] == 1
                  and "Transactions" not in it["sources"]
                  and it.get("expects_ledger_row")]
    non_payment_refs = [it for it in corr["items"]
                        if it["corroboration_score"] == 1
                        and "Transactions" not in it["sources"]
                        and not it.get("expects_ledger_row")]
    if one_source:
        # Split by the live ledger's retention window before calling anything
        # suspicious. PhonePe prunes transaction_core locally while chat keeps its
        # payment cards far longer, so on a real device most "missing" payments are
        # simply older than the oldest row the ledger still holds — reporting that
        # as possible deletion overstates the evidence. Only a payment dated INSIDE
        # the window, where its sibling rows did survive, is genuinely anomalous.
        ledger_isos = sorted(t["created_at"]["iso"] for t in txns if t.get("created_at"))
        oldest_live = ledger_isos[0] if ledger_isos else None
        newest_live = ledger_isos[-1] if ledger_isos else None
        before_window, in_window, undated = [], [], []
        for it in one_source:
            iso = it.get("earliest_iso")
            if not iso:
                undated.append(it)
            elif oldest_live and iso < oldest_live:
                before_window.append(it)
            else:
                in_window.append(it)
        for it in one_source:
            it["retention_verdict"] = (
                "older than the oldest surviving ledger row" if it in before_window
                else "inside the ledger's retained period" if it in in_window
                else "undated")

        headline = (f"{len(one_source)} payment(s) referenced only outside the master ledger "
                    f"(no matching transaction_core row)")
        if oldest_live and before_window:
            headline += (f" — {len(before_window)} predate the oldest surviving ledger row "
                         f"({oldest_live[:10]}), so local retention explains them; "
                         f"{len(in_window)} fall inside the retained period")
        findings.append({
            # Only the in-window ones warrant a second look; when every one of them
            # predates the ledger's own retention this is informational.
            "severity": "medium" if (in_window or undated) else "info",
            "category": "uncorroborated_transactions",
            "title": headline,
            "detail": {
                "count": len(one_source),
                "live_ledger_range": {"oldest": oldest_live, "newest": newest_live,
                                      "rows": len(ledger_isos)},
                "predating_ledger_retention": len(before_window),
                "inside_retained_period": len(in_window),
                "undated": len(undated),
                "note": "A payment older than the oldest surviving transaction_core row is "
                        "most likely absent because the app pruned it locally, not because "
                        "it was deleted by a user. Check the Deleted Records page: a carved "
                        "transaction_core row matching one of these ids is direct evidence "
                        "the ledger row was removed rather than never retained.",
                "sample_inside_retained_period": in_window[:5],
                "sample": one_source[:5],
                "excluded_non_payment_references": len(non_payment_refs),
            },
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

def _searchable(value: Any) -> str:
    """Lower-cased text for substring matching. search_token is a joined string for
    single-token transactions but a set/list when several tokens exist, so it can
    never be assumed to be a str."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(str(v) for v in value).lower()
    return str(value).lower()


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
            or (ident in _searchable(t.get("search_token")))
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

    total_in = sum(t.get("amount_inr") or 0 for t in out["transactions"]
                   if t.get("direction") == "IN" and is_success(t))
    total_out = sum(t.get("amount_inr") or 0 for t in out["transactions"]
                    if t.get("direction") == "OUT" and is_success(t))
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
