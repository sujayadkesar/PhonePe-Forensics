"""
PhonePe Android Forensics — Hunting Query Language (PPQL)
=====================================================

A small, deterministic SPL-inspired query language for searching across
forensic indexes. Built specifically for forensic hunters who want to issue
fast filters / aggregations without writing SQL.

Grammar (informal):

    QUERY    := SOURCE PIPE_OP*
    SOURCE   := "search" STRING       — full-text across the merged index
              | "from" INDEX          — use a specific index
              | INDEX                 — alias for "from <index>"
    PIPE_OP  := "|" CMD ARG*
    CMD      := "where" CONDITION
              | "search" STRING       — second-stage full-text filter
              | "sort" FIELD ["asc"|"desc"]
              | "head" N | "tail" N | "limit" N
              | "table" FIELD ("," FIELD)*
              | "fields" FIELD ("," FIELD)*  — alias for table
              | "top" N FIELD
              | "rare" N FIELD
              | "stats" AGG ("by" FIELD)?
              | "dedup" FIELD
              | "rename" FIELD "as" FIELD
    AGG      := "count" | "sum(" FIELD ")" | "avg(" FIELD ")"
              | "min(" FIELD ")" | "max(" FIELD ")"
    CONDITION:= EXPR ( ("and" | "or") EXPR )*
    EXPR     := FIELD OP VALUE | "(" CONDITION ")" | "not" EXPR
    OP       := "=" | "==" | "!=" | "<" | "<=" | ">" | ">="
              | "like" | "matches" | "contains"
              | "startswith" | "endswith" | "in"
    VALUE    := STRING | NUMBER | "null" | "true" | "false"
              | "[" VALUE ("," VALUE)* "]"

Examples:

    search "UTR"
    search "UTR" | where amount_inr > 1000

    transactions
      | where direction = "OUT" and amount_inr > 5000
      | sort amount_inr desc
      | head 50
      | table created_at, counterparty, amount_inr, utr

    chat_messages
      | where sender_phone_masked like "*6259"
      | stats count by sender_name

    contacts
      | where on_phonepe = true
      | top 10 region

    transactions
      | where counterparty matches "[Bb]harath.*"
      | stats sum(amount_inr) by counterparty

    timeline
      | where source = "Chat" and when_iso > "2025-01-01"
      | head 200
"""
from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Index registry
# ---------------------------------------------------------------------------

INDEX_DEFS: Dict[str, Dict[str, Any]] = {
    "transactions": {
        "description": "Master transaction ledger (phonepe_core.transaction_core).",
        "fields": [
            "global_payment_id", "entity_id", "type", "state", "direction",
            "amount_inr", "amount_paise", "category_code", "received_in_type",
            "counterparty", "counterparty_phone", "counterparty_vpa",
            "counterparty_user_id", "counterparty_user_type", "counterparty_cbs_name",
            "classification", "counterparty_resolved", "counterparty_resolved_source",
            "counterparty_phone_full",
            "self_account_holder", "self_account_masked", "self_vpa", "self_ifsc",
            "instrument_id", "utr", "transfer_mode", "initiation_mode",
            "upi_initiation_mode", "is_qr_scan", "is_intent", "context_tag", "response_code",
            "merchant_id", "merchant_name", "biller_id", "biller_name",
            "recharge_number", "note", "group_id", "group_template", "search_token",
            "created_at_iso", "updated_at_iso", "dismissed", "is_internal",
        ],
    },
    "contacts": {
        "description": "PhonePe-verified contacts (phone_contacts / contactConnectionInfo).",
        "fields": [
            "phone", "verified_name", "external_vpa", "external_vpa_name",
            "on_phonepe", "upi_state", "country_code", "region", "last_synced_iso",
            "connect_id",
        ],
    },
    "phonebook": {
        "description": "Raw device address-book entries (phone_book_contacts).",
        "fields": [
            "raw_number", "normalized", "country_code", "region", "is_valid",
            "deleted", "full_name", "contact_id", "has_image", "image_size",
            "creation_time_iso",
        ],
    },
    "non_contacts": {
        "description": "phonepe_core.nonContact — connections interacted with that are NOT "
                       "saved contacts, including numbers searched for inside PhonePe.",
        "fields": [
            "connect_id", "use_case", "phone", "phone_last10", "known", "hidden",
            "is_phone_contact", "country_code", "region", "source",
        ],
    },
    "chat_messages": {
        "description": "Chat in-app chat messages (text + payment cards + images).",
        "fields": [
            "message_id", "thread_id", "type", "amount_inr", "transaction_id",
            "state", "payment_state", "instrument", "utr", "external_vpa",
            "external_bank", "note", "text_message", "gift_message",
            "sender_name", "sender_phone_masked", "sender_role",
            "receiver_name", "receiver_phone_masked", "receiver_role",
            "created_at_iso",
        ],
    },
    "chat_groups": {
        "description": "Chat groups (P2P conversations).",
        "fields": [
            "group_id", "name", "type", "subsystem", "subscription", "active",
            "member_count", "namespace", "created_at_iso", "updated_at_iso",
        ],
    },
    "chat_members": {
        "description": "Group participants with display names + masked phones.",
        "fields": [
            "group_id", "display_name", "masked_phone", "role", "state",
            "phonepe_user", "added_on_iso", "internal_id", "public_id",
        ],
    },
    "shared_bank_disclosures": {
        "description": "Bank account details shared as chat attachments.",
        "fields": [
            "type", "verified", "account_holder", "account_number", "bank_name",
            "ifsc", "phone", "vpa", "name",
        ],
    },
    "rewards": {
        "description": "Cashback / scratch card / coupon rewards.",
        "fields": [
            "reward_id", "type", "state", "amount_inr", "linked_transaction",
            "title", "coupon_code", "share_message", "display_message",
            "cashback_txn", "created_at_iso", "expires_at_iso", "claimed_at_iso",
        ],
    },
    "notifications": {
        "description": "Notifications Bullhorn topics (push channels).",
        "fields": [
            "topic_id", "subsystem", "storage_type", "subscription_status",
            "status", "raw_message_count", "single_use",
            "created_at_iso", "updated_at_iso", "last_sync_iso",
        ],
    },
    "notification_messages": {
        "description": "Delivered push/inbox messages decoded from "
                       "BullhornDatabase.messageDataStore — the notifications the "
                       "user was actually shown, plus sync instructions.",
        "fields": [
            "message_id", "topic_id", "kind", "title", "subtitle", "body",
            "deeplink", "template", "is_notification", "sync_key",
            "created_at_iso", "sent_at_iso", "expires_at_iso",
        ],
    },
    "consents": {
        "description": "Consent grants from BOTH stores (the standalone `consent` database "
                       "and phonepe_core.consent) — what the subject agreed to share, with "
                       "the store each record came from.",
        "fields": [
            "consent_id", "state", "accept_type", "destination", "subject_id",
            "subject_ref", "definition", "sync_state", "end_time_iso", "source",
        ],
    },
    "kn_events": {
        "description": "KN behavioural analytics events.",
        "fields": ["id", "event_name", "identifier", "primary_key", "timestamp_iso"],
    },
    "supported_banks": {
        "description": "Bank catalogue downloaded for UPI selection.",
        "fields": [
            "id", "name", "ifsc_prefix", "central_ifsc", "upi", "upi_mandate",
            "ccupi", "lite", "active", "partner",
        ],
    },
    "linked_cards": {
        "description": "Linked cards (accounts / cards tables).",
        "fields": [
            "card_id", "alias", "type", "issuer", "bank_code", "masked",
            "holder", "status", "cobranding", "updated_at_iso",
        ],
    },
    "linked_accounts": {
        "description": "Linked bank accounts (accounts table).",
        "fields": [
            "account_no_masked", "account_holder", "account_alias",
            "account_type", "is_primary", "updated_at_iso",
        ],
    },
    "travel_journeys": {
        "description": "Yatra travel journeys (booking workflows).",
        "fields": [
            "journey_id", "name", "description", "namespace", "type", "state",
            "entity_type", "created_at_iso", "updated_at_iso",
        ],
    },
    "config_keys": {
        "description": "ConfigManagerKeyStore feature flag values.",
        "fields": ["key", "team", "org", "is_json", "value_size", "value_preview"],
    },
    "experiments": {
        "description": "Athena A/B experiment buckets the user is in.",
        "fields": [
            "experiment_id", "activity_id", "client_id", "summary", "type",
            "state", "mode", "version", "started_iso", "ends_iso",
        ],
    },
    "search_history": {
        "description": "In-app search history (AppSearch FTS).",
        "fields": ["unique_id", "entity", "field_id", "entry_id", "timestamp_iso"],
    },
    "webkit_domains": {
        "description": "WebKit ResourceLoadStatistics observed domains.",
        "fields": [
            "domain", "had_user_interaction", "last_user_interaction_iso", "last_seen_iso",
        ],
    },
    "cookies": {
        "description": "WebView cookies from the Chromium cookie store (app_webview).",
        "fields": ["domain", "name", "path", "value", "creation_iso", "expiry_iso", "flags"],
    },
    "timeline": {
        "description": "Unified chronological event stream across every DB.",
        "fields": ["when_iso", "source", "kind", "title", "amount_inr", "link_id"],
    },
    "findings": {
        "description": "Heuristic suspicious-signal flags.",
        "fields": ["severity", "category", "title"],
    },
    "central_sync": {
        "description": "Sync history (proves device active).",
        "fields": [
            "system", "key", "type", "status", "last_attempt_iso", "last_completed_iso",
        ],
    },
    # ---- Android-exclusive sources ----
    "sms": {
        "description": "Device SMS ingested by PhonePe for transaction inference "
                       "(inference_data_provider.sms_buffer). Android-exclusive.",
        "fields": ["id", "address", "body", "received_at_iso", "received_at_epoch_ms"],
    },
    "ledger_expenses": {
        "description": "PhonePe 'Split' shared expenses, with payer and settlement linkage.",
        "fields": [
            "expense_id", "name", "type", "ledger_id", "state", "amount_inr",
            "payer", "created_by", "settlement_txn_id", "created_at_iso",
        ],
    },
    "ledger_balances": {
        "description": "Per-member outstanding balances in each shared-expense ledger.",
        "fields": ["name", "is_self", "ledger_id", "to_give_inr", "to_receive_inr"],
    },
    "miniapps": {
        "description": "Installed Nirvana mini-apps (RN/PWA services) and their merchants.",
        "fields": [
            "dir_id", "app_id", "app_unique_id", "name", "version", "merchant_name",
            "micro_app_type", "category", "installation_type", "updated_at_iso",
        ],
    },
    "shared_prefs": {
        "description": "Every shared_prefs/*.xml key/value, flattened to one row per key.",
        "fields": ["file", "key", "value", "value_type"],
    },
    "deleted_records": {
        "description": "Rows carved back out of freed space, WAL frames and rollback "
                       "journals. These are reconstructions, not live rows.",
        "fields": [
            "database", "table", "confidence", "extent_confidence",
            "value_confidence", "implausible_columns", "partial", "truncated",
            "ambiguous", "pool", "page", "file_offset", "source_file",
            "recovered_text",
        ],
    },
    "raw_tables": {
        "description": "Inventory of every readable SQLite table (name, row count, columns). "
                       "Row bodies are loaded on demand from the Raw Tables page.",
        "fields": ["database", "table", "row_count", "columns", "captured"],
    },
}


# ---------------------------------------------------------------------------
# Index materialiser
# ---------------------------------------------------------------------------

def _ts_iso(v: Any) -> Optional[str]:
    if isinstance(v, dict):
        return v.get("iso") or v.get("display")
    return v


def _flatten_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Materialise nested timestamp dicts into _iso suffixes."""
    out = {}
    for k, v in rec.items():
        if isinstance(v, dict) and "iso" in v and "epoch_ms" in v:
            out[k + "_iso"] = v["iso"]
            out[k + "_epoch_ms"] = v["epoch_ms"]
        else:
            out[k] = v
    return out


def materialise_indexes(case_data: Dict[str, Any], timeline: List[Dict[str, Any]],
                        social_graph: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Convert the case's nested records into flat searchable dicts."""
    idx: Dict[str, List[Dict[str, Any]]] = {}

    idx["transactions"] = [_flatten_record(t) for t in case_data.get("transactions", {}).get("transactions", [])]
    idx["contacts"] = [_flatten_record(c) for c in case_data.get("contacts", {}).get("cyclops_contacts", [])]
    idx["phonebook"] = [_flatten_record(c) for c in case_data.get("contacts", {}).get("phonebook_contacts", [])]
    idx["non_contacts"] = [_flatten_record(c) for c in case_data.get("contacts", {}).get("non_contacts", [])]
    idx["chat_messages"] = [_flatten_record(m) for m in case_data.get("chat", {}).get("messages", [])]
    idx["chat_groups"] = [_flatten_record(g) for g in case_data.get("chat", {}).get("groups", [])]
    idx["chat_members"] = [_flatten_record(m) for m in case_data.get("chat", {}).get("members", [])]
    idx["shared_bank_disclosures"] = list(case_data.get("chat", {}).get("shared_contacts", []))
    idx["rewards"] = [_flatten_record(r) for r in case_data.get("financial", {}).get("rewards", [])]
    idx["notifications"] = [_flatten_record(t) for t in case_data.get("notifications", {}).get("topics", [])]
    # Decoded payloads are dropped from the index: the searchable content is
    # already flattened into title/subtitle/body/deeplink, and carrying the nested
    # payload would put a second copy of every notification into the index.
    idx["notification_messages"] = [
        _flatten_record({k: v for k, v in m.items() if k != "payload"})
        for m in case_data.get("notifications", {}).get("raw_messages", [])]
    idx["kn_events"] = [_flatten_record(e) for e in case_data.get("analytics", {}).get("kn_events", [])]
    idx["supported_banks"] = list(case_data.get("payment_infra", {}).get("supported_banks", []))
    idx["linked_cards"] = [_flatten_record(c) for c in case_data.get("payment_infra", {}).get("linked_cards", [])]
    idx["linked_accounts"] = [_flatten_record(a) for a in case_data.get("payment_infra", {}).get("linked_accounts", [])]
    idx["travel_journeys"] = [_flatten_record(j) for j in case_data.get("travel", {}).get("journeys", [])]
    idx["config_keys"] = list(case_data.get("config_state", {}).get("config_keys", []))
    idx["experiments"] = [_flatten_record(e) for e in case_data.get("config_state", {}).get("experiments", [])]
    idx["search_history"] = [_flatten_record(s) for s in case_data.get("search", {}).get("recent_searches", [])]
    idx["webkit_domains"] = [_flatten_record(r) for r in case_data.get("webkit", {}).get("resource_load_stats", [])]
    idx["cookies"] = list(case_data.get("webkit", {}).get("cookies", []))
    idx["central_sync"] = [_flatten_record(s) for s in case_data.get("audit", {}).get("central_sync", [])]
    idx["consents"] = [_flatten_record(c) for c in case_data.get("audit", {}).get("consents", [])]

    # Android-exclusive sources. These are the differentiators of this build, so
    # not indexing them meant the one evidence class you cannot get from an iOS
    # acquisition was also the one class you could not hunt across.
    idx["sms"] = [_flatten_record(m) for m in case_data.get("sms", {}).get("messages", [])]
    idx["ledger_expenses"] = [_flatten_record(e) for e in case_data.get("ledger", {}).get("expenses", [])]
    idx["ledger_balances"] = [_flatten_record(b) for b in case_data.get("ledger", {}).get("balances", [])]
    idx["miniapps"] = [_flatten_record(a) for a in case_data.get("miniapps", {}).get("apps", [])]
    idx["shared_prefs"] = [
        {"file": fname, "key": key, "value": value,
         "value_type": type(value).__name__}
        for fname, prefs in (case_data.get("shared_prefs", {}).get("prefs", {}) or {}).items()
        if isinstance(prefs, dict)
        for key, value in prefs.items()
    ]
    idx["deleted_records"] = [
        {"database": r.get("database"),
         "table": r.get("table") or "/".join(r.get("candidate_tables") or []),
         "confidence": r.get("confidence"),
         "extent_confidence": r.get("extent_confidence"),
         "value_confidence": r.get("value_confidence"),
         "implausible_columns": "; ".join(r.get("implausible_columns") or []),
         "partial": r.get("partial"),
         "truncated": r.get("truncated"), "ambiguous": r.get("ambiguous"),
         "pool": r.get("pool"), "page": r.get("page"),
         "file_offset": r.get("file_offset"), "source_file": r.get("source_file"),
         # One searchable blob so `deleted_records | search "..."` reaches the
         # recovered content regardless of which table the row came from.
         "recovered_text": " ".join(str(v) for v in (r.get("row") or {}).values()
                                    if v is not None),
         **{k: v for k, v in (r.get("row") or {}).items() if v is not None}}
        for r in (case_data.get("deleted_records", {}).get("records", []) or [])
    ]
    idx["raw_tables"] = [
        {"database": db_name, "table": tname,
         "row_count": tinfo.get("row_count"), "columns": tinfo.get("columns"),
         "captured": tinfo.get("captured")}
        for db_name, tables in (case_data.get("raw_tables", {}).get("databases", {}) or {}).items()
        if isinstance(tables, dict)
        for tname, tinfo in tables.items()
        if isinstance(tinfo, dict) and not tname.startswith("_")
    ]

    idx["timeline"] = list(timeline or [])
    idx["findings"] = list(findings or [])
    return idx


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RX = re.compile(r"""
    \s+                                  # whitespace (skipped)
    | "((?:\\.|[^"\\])*)"                # double-quoted string
    | '((?:\\.|[^'\\])*)'                # single-quoted string
    | (\|)                               # pipe
    | (\(|\)|\[|\]|,)                    # punctuation
    | (==|!=|<=|>=|=|<|>)                # operators
    | ([A-Za-z_][\w.]*)                  # identifier
    | (-?\d+(?:\.\d+)?)                  # number
""", re.VERBOSE)


def _tokenize(query: str) -> List[Tuple[str, Any]]:
    tokens: List[Tuple[str, Any]] = []
    pos = 0
    while pos < len(query):
        m = _TOKEN_RX.match(query, pos)
        if not m:
            raise SyntaxError(f"Unexpected character at {pos}: {query[pos:pos+12]!r}")
        pos = m.end()
        if m.group().isspace():
            continue
        if m.group(1) is not None:
            tokens.append(("STR", m.group(1)))
        elif m.group(2) is not None:
            tokens.append(("STR", m.group(2)))
        elif m.group(3) is not None:
            tokens.append(("PIPE", "|"))
        elif m.group(4) is not None:
            tokens.append(("PUNCT", m.group(4)))
        elif m.group(5) is not None:
            tokens.append(("OP", m.group(5)))
        elif m.group(6) is not None:
            tokens.append(("ID", m.group(6)))
        elif m.group(7) is not None:
            num = m.group(7)
            tokens.append(("NUM", float(num) if "." in num else int(num)))
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    KEYWORDS = {
        "search", "from", "where", "and", "or", "not", "sort", "asc", "desc",
        "head", "tail", "limit", "table", "fields", "top", "rare", "stats",
        "by", "dedup", "rename", "as", "in", "like", "matches", "contains",
        "startswith", "endswith", "true", "false", "null",
    }

    def __init__(self, tokens: List[Tuple[str, Any]]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> Optional[Tuple[str, Any]]:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> Tuple[str, Any]:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def expect(self, kind: str, value: Optional[str] = None):
        t = self.peek()
        if t is None or t[0] != kind or (value is not None and t[1] != value):
            raise SyntaxError(f"Expected {kind} {value!r}, got {t!r}")
        return self.take()

    def at_keyword(self, *kws: str) -> bool:
        t = self.peek()
        return bool(t and t[0] == "ID" and t[1] in kws)

    def _count(self) -> int:
        """A row count for head/tail/top/rare. Rejects negatives outright: Python
        slicing turns `head -2` into a silent truncation and `tail 0` into
        `rows[-0:]`, which is every row — the opposite of what was asked."""
        n = int(self.expect("NUM")[1])
        if n < 0:
            raise SyntaxError(f"row count must be zero or greater, got {n}")
        return n

    def parse(self) -> Dict[str, Any]:
        q = {"source": self._parse_source(), "ops": []}
        while self.peek() and self.peek()[0] == "PIPE":
            self.take()  # consume |
            q["ops"].append(self._parse_op())
        if self.peek():
            raise SyntaxError(f"Trailing tokens: {self.peek()!r}")
        return q

    def _parse_source(self) -> Dict[str, Any]:
        t = self.peek()
        if not t:
            raise SyntaxError("Empty query")
        if t[0] == "ID" and t[1] == "search":
            self.take()
            term = self.expect("STR")[1]
            return {"kind": "search", "term": term}
        if t[0] == "ID" and t[1] == "from":
            self.take()
            name = self.expect("ID")[1]
            return {"kind": "index", "name": name}
        if t[0] == "ID":
            name = self.take()[1]
            return {"kind": "index", "name": name}
        raise SyntaxError(f"Bad source: {t!r}")

    def _parse_op(self) -> Dict[str, Any]:
        t = self.expect("ID")
        cmd = t[1]
        if cmd == "where":
            return {"cmd": "where", "expr": self._parse_or()}
        if cmd == "search":
            term = self.expect("STR")[1]
            return {"cmd": "search", "term": term}
        if cmd in ("sort", "order"):
            field = self.expect("ID")[1]
            direction = "asc"
            if self.at_keyword("asc", "desc"):
                direction = self.take()[1]
            return {"cmd": "sort", "field": field, "direction": direction}
        if cmd in ("head", "tail", "limit"):
            return {"cmd": cmd, "n": self._count()}
        if cmd in ("table", "fields"):
            cols = [self.expect("ID")[1]]
            while self.peek() and self.peek()[0] == "PUNCT" and self.peek()[1] == ",":
                self.take()
                cols.append(self.expect("ID")[1])
            return {"cmd": "table", "fields": cols}
        if cmd == "top":
            n = self._count()
            field = self.expect("ID")[1]
            return {"cmd": "top", "n": n, "field": field}
        if cmd == "rare":
            n = self._count()
            field = self.expect("ID")[1]
            return {"cmd": "rare", "n": n, "field": field}
        if cmd == "stats":
            agg = self._parse_agg()
            by = None
            if self.at_keyword("by"):
                self.take()
                by = self.expect("ID")[1]
            return {"cmd": "stats", "agg": agg, "by": by}
        if cmd == "dedup":
            field = self.expect("ID")[1]
            return {"cmd": "dedup", "field": field}
        if cmd == "rename":
            old = self.expect("ID")[1]
            self.expect("ID", "as")
            new = self.expect("ID")[1]
            return {"cmd": "rename", "old": old, "new": new}
        raise SyntaxError(f"Unknown command: {cmd}")

    def _parse_agg(self) -> Dict[str, Any]:
        t = self.expect("ID")
        name = t[1]
        if name == "count":
            return {"fn": "count"}
        # function form: sum(field) — parser allowed because '(' is punct
        if self.peek() and self.peek() == ("PUNCT", "("):
            self.take()  # (
            fld = self.expect("ID")[1]
            self.expect("PUNCT", ")")
            return {"fn": name, "field": fld}
        # bare form: sum field
        fld = self.expect("ID")[1]
        return {"fn": name, "field": fld}

    # boolean expression
    def _parse_or(self) -> Dict[str, Any]:
        node = self._parse_and()
        while self.at_keyword("or"):
            self.take()
            node = {"op": "or", "lhs": node, "rhs": self._parse_and()}
        return node

    def _parse_and(self) -> Dict[str, Any]:
        node = self._parse_not()
        while self.at_keyword("and"):
            self.take()
            node = {"op": "and", "lhs": node, "rhs": self._parse_not()}
        return node

    def _parse_not(self) -> Dict[str, Any]:
        if self.at_keyword("not"):
            self.take()
            return {"op": "not", "expr": self._parse_not()}
        return self._parse_atom()

    def _parse_atom(self) -> Dict[str, Any]:
        t = self.peek()
        if t == ("PUNCT", "("):
            self.take()
            inner = self._parse_or()
            self.expect("PUNCT", ")")
            return inner
        # field op value
        fld = self.expect("ID")[1]
        op_tok = self.peek()
        if op_tok and op_tok[0] == "OP":
            op = self.take()[1]
        elif op_tok and op_tok[0] == "ID" and op_tok[1] in (
            "like", "matches", "contains", "startswith", "endswith", "in"
        ):
            op = self.take()[1]
        else:
            raise SyntaxError(f"Expected operator after field {fld!r}, got {op_tok!r}")
        value = self._parse_value()
        return {"op": "cmp", "field": fld, "operator": op, "value": value}

    def _parse_value(self):
        t = self.peek()
        if not t:
            raise SyntaxError("Expected value")
        if t == ("PUNCT", "["):
            self.take()
            items = []
            if self.peek() != ("PUNCT", "]"):
                items.append(self._parse_value())
                while self.peek() == ("PUNCT", ","):
                    self.take()
                    items.append(self._parse_value())
            self.expect("PUNCT", "]")
            return items
        if t[0] in ("STR", "NUM"):
            return self.take()[1]
        if t[0] == "ID" and t[1] in ("true", "false", "null"):
            self.take()
            return {"true": True, "false": False, "null": None}[t[1]]
        if t[0] == "ID":
            # Bareword treated as string (so users can do `where foo = bar`)
            return self.take()[1]
        raise SyntaxError(f"Bad value: {t!r}")


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def _coerce_pair(a: Any, b: Any) -> Tuple[Any, Any]:
    """Best-effort numeric/string coercion for comparisons."""
    if isinstance(b, (int, float)) and isinstance(a, str):
        try:
            return float(a), float(b)
        except (TypeError, ValueError):
            return a, str(b)
    if isinstance(a, (int, float)) and isinstance(b, str):
        try:
            return float(a), float(b)
        except (TypeError, ValueError):
            return str(a), b
    return a, b


def _sort_key(value: Any, descending: bool = False) -> Tuple[int, float, str]:
    """Total order over a column that mixes types.

    Evidence columns are not type-clean — the same field can be an int in one row,
    a string in the next and null in a third — and Python refuses to compare those,
    which turned `| sort <field>` into a runtime error on real data. Numbers first,
    then everything else as text, and nulls always last.

    `descending` exists because the caller reverses the whole sort: a fixed
    "nulls rank highest" key puts them last ascending and *first* descending, so
    `sort amount_inr desc | head 5` returned five rows with no amount — the rows
    that legitimately have none (a P2P_ENRICHMENT metadata sibling carries no
    amount) crowded out every real payment. Ranking nulls lowest when the sort is
    about to be reversed keeps them last either way.
    """
    null_rank = -1 if descending else 2
    if value is None:
        return (null_rank, 0.0, "")
    if isinstance(value, bool):
        return (1, 0.0, str(value))
    if isinstance(value, (int, float)):
        return (0, float(value), "")
    return (1, 0.0, str(_group_key(value)))


def _group_key(value: Any) -> Any:
    """A hashable key for grouping/dedup. Several indexed fields hold decoded JSON
    (dicts and lists), which cannot go into a set or a Counter."""
    if isinstance(value, (dict, list, set, tuple, bytearray)):
        try:
            return json.dumps(value, default=str, sort_keys=True)
        except Exception:
            return str(value)
    return value


# Patterns are compiled once per query rather than once per record; a 100k-row
# index previously recompiled the same regex 100k times.
_MAX_PATTERN_LEN = 200
_regex_cache: Dict[Tuple[str, str], Optional[re.Pattern]] = {}


def _compiled(pattern: str, kind: str) -> Optional[re.Pattern]:
    key = (kind, pattern)
    if key in _regex_cache:
        return _regex_cache[key]
    compiled: Optional[re.Pattern]
    if len(pattern) > _MAX_PATTERN_LEN:
        compiled = None          # oversized patterns are the ReDoS vector
    else:
        try:
            source = fnmatch.translate(pattern) if kind == "glob" else pattern
            compiled = re.compile(source, re.IGNORECASE)
        except re.error:
            compiled = None
    if len(_regex_cache) > 512:
        _regex_cache.clear()
    _regex_cache[key] = compiled
    return compiled


def _glob_to_regex(pat: str) -> Optional[re.Pattern]:
    return _compiled(pat, "glob")


def _evaluate_atom(atom: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    field = atom["field"]
    op = atom["operator"]
    value = atom["value"]
    actual = rec.get(field)
    if op in ("=", "==", "!="):
        try:
            a, b = _coerce_pair(actual, value)
            res = a == b
        except Exception:
            res = actual == value
        return res if op != "!=" else not res
    if op in ("<", "<=", ">", ">="):
        if actual is None:
            return False
        try:
            a, b = _coerce_pair(actual, value)
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        except (TypeError, ValueError):
            return False
    if op == "like":
        if actual is None:
            return False
        rx = _glob_to_regex(str(value))
        return bool(rx.fullmatch(str(actual))) if rx else False
    if op == "matches":
        if actual is None:
            return False
        rx = _compiled(str(value), "regex")
        return bool(rx.search(str(actual))) if rx else False
    if op == "contains":
        if actual is None:
            return False
        return str(value).lower() in str(actual).lower()
    if op == "startswith":
        if actual is None:
            return False
        return str(actual).lower().startswith(str(value).lower())
    if op == "endswith":
        if actual is None:
            return False
        return str(actual).lower().endswith(str(value).lower())
    if op == "in":
        if not isinstance(value, list):
            return False
        return actual in value
    return False


def _evaluate(expr: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    op = expr.get("op")
    if op == "cmp":
        return _evaluate_atom(expr, rec)
    if op == "and":
        return _evaluate(expr["lhs"], rec) and _evaluate(expr["rhs"], rec)
    if op == "or":
        return _evaluate(expr["lhs"], rec) or _evaluate(expr["rhs"], rec)
    if op == "not":
        return not _evaluate(expr["expr"], rec)
    return False


def _full_text_match(rec: Dict[str, Any], term: str) -> bool:
    needle = term.lower()
    for v in rec.values():
        if v is None:
            continue
        if isinstance(v, (dict, list)):
            try:
                if needle in json.dumps(v, default=str).lower():
                    return True
            except Exception:
                pass
        else:
            if needle in str(v).lower():
                return True
    return False


def _agg_value(records: List[Dict[str, Any]], agg: Dict[str, Any]) -> Any:
    fn = agg["fn"]
    if fn == "count":
        return len(records)
    field = agg["field"]
    vals = [r.get(field) for r in records if r.get(field) is not None]
    nums: List[float] = []
    for v in vals:
        try:
            nums.append(float(v))
        except (TypeError, ValueError):
            pass
    if not nums:
        return None
    if fn == "sum":
        return round(sum(nums), 2)
    if fn == "avg":
        return round(sum(nums) / len(nums), 4)
    if fn == "min":
        return min(nums)
    if fn == "max":
        return max(nums)
    if fn == "distinct_count":
        return len({_group_key(v) for v in vals})
    return None


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

def run_query(query: str, indexes: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Parse and run a PPQL query against the indexes."""
    if not query or not query.strip():
        return {"error": "empty query", "rows": [], "columns": [], "count": 0}
    try:
        tokens = _tokenize(query)
        plan = _Parser(tokens).parse()
    except SyntaxError as exc:
        return {"error": f"parse error: {exc}", "rows": [], "columns": [], "count": 0}

    # Source
    src = plan["source"]
    if src["kind"] == "search":
        # full-text across every index
        rows: List[Dict[str, Any]] = []
        term = src["term"]
        for idx_name, items in indexes.items():
            for r in items:
                if _full_text_match(r, term):
                    rec = dict(r)
                    rec["_index"] = idx_name
                    rows.append(rec)
        index_used = "_all"
    else:
        idx_name = src["name"]
        if idx_name not in indexes:
            return {"error": f"unknown index: {idx_name}",
                    "rows": [], "columns": [], "count": 0,
                    "available_indexes": sorted(indexes.keys())}
        rows = [dict(r) for r in indexes[idx_name]]
        index_used = idx_name

    # Pipe ops
    derived_columns: Optional[List[str]] = None
    rename_map: Dict[str, str] = {}
    aggregated: Optional[List[Dict[str, Any]]] = None
    try:
        for op in plan["ops"]:
            cmd = op["cmd"]
            if cmd == "where":
                rows = [r for r in rows if _evaluate(op["expr"], r)]
            elif cmd == "search":
                rows = [r for r in rows if _full_text_match(r, op["term"])]
            elif cmd == "sort":
                rev = op["direction"] == "desc"
                rows.sort(key=lambda r, f=op["field"]: _sort_key(r.get(f), rev),
                          reverse=rev)
            elif cmd in ("head", "limit"):
                rows = rows[: op["n"]]
            elif cmd == "tail":
                # rows[-0:] is the whole list, so zero has to be special-cased.
                rows = rows[-op["n"]:] if op["n"] else []
            elif cmd == "table":
                derived_columns = list(op["fields"])
                rows = [{k: r.get(k) for k in derived_columns} for r in rows]
            elif cmd == "top":
                cnt = Counter(_group_key(r.get(op["field"])) for r in rows
                              if r.get(op["field"]) is not None)
                rows = [{op["field"]: k, "count": v} for k, v in cnt.most_common(op["n"])]
                derived_columns = [op["field"], "count"]
            elif cmd == "rare":
                cnt = Counter(_group_key(r.get(op["field"])) for r in rows
                              if r.get(op["field"]) is not None)
                tail = cnt.most_common()[-op["n"]:] if op["n"] else []
                rows = [{op["field"]: k, "count": v} for k, v in tail]
                derived_columns = [op["field"], "count"]
            elif cmd == "stats":
                if op["by"]:
                    groups: Dict[Any, List[Dict[str, Any]]] = {}
                    for r in rows:
                        groups.setdefault(_group_key(r.get(op["by"])), []).append(r)
                    agg_label = _agg_label(op["agg"])
                    rows = sorted(
                        [{op["by"]: k, agg_label: _agg_value(v, op["agg"])} for k, v in groups.items()],
                        key=lambda x: (x[agg_label] is None, -(x[agg_label] or 0) if isinstance(x[agg_label], (int, float)) else 0),
                    )
                    derived_columns = [op["by"], agg_label]
                else:
                    agg_label = _agg_label(op["agg"])
                    rows = [{agg_label: _agg_value(rows, op["agg"])}]
                    derived_columns = [agg_label]
                aggregated = rows
            elif cmd == "dedup":
                seen = set(); out = []
                for r in rows:
                    v = _group_key(r.get(op["field"]))
                    if v in seen:
                        continue
                    seen.add(v)
                    out.append(r)
                rows = out
            elif cmd == "rename":
                rename_map[op["old"]] = op["new"]
                for r in rows:
                    if op["old"] in r:
                        r[op["new"]] = r.pop(op["old"])
                if derived_columns and op["old"] in derived_columns:
                    derived_columns = [op["new"] if c == op["old"] else c for c in derived_columns]
    except Exception as exc:
        return {"error": f"runtime error: {exc}", "rows": [], "columns": [], "count": 0}

    if derived_columns is None:
        # Build a default column order from the union of keys, capped.
        seen_cols: List[str] = []
        for r in rows[:200]:
            for k in r.keys():
                if k not in seen_cols:
                    seen_cols.append(k)
        derived_columns = seen_cols[:25]

    return {
        "rows": rows,
        "columns": derived_columns,
        "count": len(rows),
        "index_used": index_used,
        "is_aggregated": aggregated is not None,
    }


def _agg_label(agg: Dict[str, Any]) -> str:
    if agg["fn"] == "count":
        return "count"
    return f"{agg['fn']}({agg['field']})"


# ---------------------------------------------------------------------------
# Suggestion helpers (for the UI)
# ---------------------------------------------------------------------------

def list_indexes_help() -> List[Dict[str, Any]]:
    """Returns rich metadata about every index for the help sidebar."""
    return [
        {"name": k, "description": v["description"], "fields": v["fields"]}
        for k, v in INDEX_DEFS.items()
    ]
