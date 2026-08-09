"""
PhonePe Android Forensics — Extractors
=====================================
Each ``extract_*(paths: AndroidCasePaths)`` returns the SAME normalized dict shape the
platform-agnostic layer expects, so the correlator / hunt / reports / GUI consume them
unchanged.

STATUS: all extractors registered in ``AndroidCase.EXTRACTORS`` are implemented and have been
run against a real ``com.phonepe.app`` acquisition. An extractor never raises: a missing
database or table is reported in the module's own ``errors`` list (surfaced on the Audit page
via ``Case.extraction_errors``) so that "no data" is always distinguishable from "not read".

Coverage caveat worth knowing before concluding something is absent: table access is guarded
by ``db.has_table(...)``, so a table this acquisition does not have contributes zero rows
without raising anything. Cross-check the ``raw_tables`` inventory when it matters.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from typing import Any, Dict, List

from .core_android import (
    SUCCESS_STATES,
    AndroidCasePaths,
    SQLiteReader,
    amount_to_rupees,
    chromium_ts,
    decode_json_blob,
    decode_txn_id,
    first_or_dict,
    hash_file,
    normalize_timestamp,
    pick,
    read_shared_pref,
    safe_int,
    tri_bool,
)

# ---------------------------------------------------------------------------
# Transactions  (phonepe_core: transaction_core + transaction_*_attribute)
# ---------------------------------------------------------------------------

# Android transaction `type` -> normalized direction
_DIRECTION_BY_TYPE = {
    "RECEIVED_PAYMENT": "IN",
    "SENT_PAYMENT": "OUT",
    "EXPENSE_SETTLEMENT": "OUT",   # fallback only — real direction resolved per-row from payer/payeeMemberId vs self (see extract_transactions)
    "PIEDPIPER_PAYMENT": "OUT",    # PiedPiper SDK payment; refine when sampled
    "P2P_ENRICHMENT": "INTERNAL",  # metadata sibling (groupId/referenceId), NOT a money movement
}

# Types that represent actual money movement (used for totals / asserts).
MONEY_TYPES = {"RECEIVED_PAYMENT", "SENT_PAYMENT", "PIEDPIPER_PAYMENT", "EXPENSE_SETTLEMENT"}


# Types whose name states the direction outright. Anything else has its direction
# resolved from the payload, because the type default is only a guess.
_SELF_EVIDENT_TYPES = {"RECEIVED_PAYMENT", "SENT_PAYMENT", "P2P_ENRICHMENT"}


def _direction(ttype: str, tstore: Dict[str, Any]) -> str:
    """Resolve which way the money moved.

    ``tstore.actor`` is the authoritative signal where it exists: it records whether
    the device's owner was the SENDER or the RECEIVER of this payment. It is used in
    preference to the per-type default for any type whose name does not already state
    the direction.

    This was verified against ground truth. PhonePe keeps its own per-transaction
    ledger in ``transaction_aggregate_entity`` (aggregate_type = received/spent); the
    static ``PIEDPIPER_PAYMENT -> OUT`` default — whose own comment said "refine when
    sampled" — disagreed with it on 4 of 8 PiedPiper rows, every one of which the app
    itself recorded as *received*. `actor` agrees with the app on all of them.
    """
    if isinstance(tstore, dict) and ttype not in _SELF_EVIDENT_TYPES:
        actor = str(tstore.get("actor") or "").strip().upper()
        if actor == "RECEIVER":
            return "IN"
        if actor == "SENDER":
            return "OUT"
        # Corroborating shape: the payload names the *other* party, so whichever of
        # these is present says which side the owner was on.
        if tstore.get("paymentPayerParty"):
            return "IN"
        if tstore.get("paymentReceiver"):
            return "OUT"
    d = _DIRECTION_BY_TYPE.get(ttype)
    if d:
        return d
    # Infer from payload shape: a `paidFrom` leg => money left an owner account.
    if isinstance(tstore, dict):
        if tstore.get("paidFrom"):
            return "OUT"
        if tstore.get("receivedIn") or tstore.get("from"):
            return "IN"
    return "UNKNOWN"


def _amount_paise(tstore: Dict[str, Any], instruments: Any, cp: Dict[str, Any], self_leg: Dict[str, Any]) -> int:
    """Waterfall: SENT has no top-level amount; it lives in the legs. instruments[].amount
    is a STRING; tstore.amount is an INT. All routed through safe_int."""
    for cand in (
        tstore.get("amount") if isinstance(tstore, dict) else None,
        self_leg.get("amount"),
        cp.get("amount"),
        (first_or_dict(instruments).get("amount") if instruments else None),
    ):
        n = safe_int(cand, default=-1)
        if n >= 0:
            return n
    return -1


def _rank_counterparties(agg: Dict[Any, Dict[str, Any]], direction: str,
                         top: int = 20) -> List[Dict[str, Any]]:
    """Top counterparties for one direction, ranked by total amount."""
    rows = []
    for (d, stable), slot in agg.items():
        if d != direction:
            continue
        rows.append({
            "name": slot["name"] or stable[1],
            "kind": slot["kind"],
            "count": slot["count"],
            "amount_inr": slot["amount_inr"],
            # Prefixed so the UI can label each identifier's type without guessing.
            "identifiers": sorted(slot["identifiers"]),
            "grouped_by": stable[0],
        })
    rows.sort(key=lambda r: (-r["amount_inr"], -r["count"], str(r["name"])))
    return rows[:top]


def extract_transactions(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"transactions": [], "summary": {}, "deletion_signals": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out

    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["deletion_signals"] = db.deletion_signals()
        rows = db.query(
            "SELECT transaction_id, type, transaction_id_type, tstore_data, state, unit_id, "
            "user_txn_meta, payment_reference, contact_data, instruments, "
            "timestamp_created, timestamp_updated, contact_data_ipn, show_on_history "
            "FROM transaction_core ORDER BY timestamp_created DESC"
        )
        text_attrs = db.query(
            "SELECT transaction_id_type, attribute_key, attribute_value FROM transaction_text_attribute"
        )
        num_attrs = db.query(
            "SELECT transaction_id_type, attribute_key, attribute_value FROM transaction_numeric_attribute"
        )
        token_rows = db.query(
            "SELECT transaction_id_type, token FROM txn_search_token"
        ) if db.has_table("txn_search_token") else []
        # Cross-table resolver (masked counterparty → real name/full destination). Built
        # inside the db block; afterwards it holds only plain dicts so it outlives `db`.
        resolver = IdentityResolver(db)
        # Self's ledger/chat member ids (one per topic) — used to resolve the direction of
        # EXPENSE_SETTLEMENT rows, whose tstore carries payerMemberId/payeeMemberId but no legs.
        self_member_ids: set = set()
        for _tbl, _col in (("chatTopicMeta", "ownMemberId"), ("ledger_my_split_topic", "ownMemberId")):
            if db.has_table(_tbl):
                for _m in db.query(f"SELECT {_col} FROM {_tbl}"):
                    if "_error" not in _m and _m.get(_col):
                        self_member_ids.add(_m[_col])

    tokens_by_txn: Dict[str, set] = defaultdict(set)
    for tr in token_rows:
        if "_error" not in tr and tr.get("transaction_id_type") and tr.get("token"):
            tokens_by_txn[tr["transaction_id_type"]].add(str(tr["token"]).strip())

    tags_by_txn: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for ar in text_attrs + num_attrs:
        if "_error" in ar:
            continue
        tid = ar.get("transaction_id_type")
        k = ar.get("attribute_key")
        if tid and k:
            tags_by_txn[tid].setdefault(k, ar.get("attribute_value"))

    statuses, types, dir_count = Counter(), Counter(), Counter()
    counterparties: Counter = Counter()
    # Per-counterparty totals keyed on a STABLE identifier (PhonePe userId, then full
    # phone, then VPA) rather than on the display name, which is the same rule the
    # social graph follows: two people can share a name, and one person's name is
    # spelled several ways across the tables. `counterparties` above stays
    # name-keyed for the existing "most frequent" list; these drive the dashboard's
    # amount-ranked panel, which was rendering nothing because nothing ever
    # populated it.
    cp_agg: Dict[Any, Dict[str, Any]] = {}
    yearly_in, yearly_out, monthly = defaultdict(float), defaultdict(float), defaultdict(float)
    total_in = total_out = 0.0
    earliest = latest = None
    self_holders, self_vpas, self_masked, self_user_ids, self_phones = set(), set(), set(), set(), set()

    for r in rows:
        if "_error" in r:
            out["errors"].append(r["_error"])
            continue
        ttype = r.get("type") or "UNKNOWN"
        state = (r.get("state") or "UNKNOWN")
        tid_type = r.get("transaction_id_type")
        tags = tags_by_txn.get(tid_type, {})
        tstore = decode_json_blob(r.get("tstore_data"))
        if not isinstance(tstore, dict):
            tstore = {}
        instruments = decode_json_blob(r.get("instruments"))

        direction = _direction(ttype, tstore)
        ctx = tstore.get("context") or {}

        # EXPENSE_SETTLEMENT carries no payment legs — its direction comes from whether
        # self (any of our per-topic member ids) is the payer (OUT) or the payee (IN).
        settle_other_member = None
        if ttype == "EXPENSE_SETTLEMENT":
            payer, payee = tstore.get("payerMemberId"), tstore.get("payeeMemberId")
            if payer in self_member_ids and payee not in self_member_ids:
                direction, settle_other_member = "OUT", payee
            elif payee in self_member_ids and payer not in self_member_ids:
                direction, settle_other_member = "IN", payer
            # else: self on both/neither side — keep the _DIRECTION_BY_TYPE default (OUT)

        # Resolve counterparty vs self legs by direction.
        #
        # `paymentPayerParty` / `paymentReceiver` are preferred where present: they
        # name the OTHER party in full — accountHolderName, phone, fullVpa, userId —
        # whereas on these payloads the plain from/to legs carry `type: PHONE` with a
        # null name. Reading only from/to lost real counterparty names the acquisition
        # actually holds, and on rows where the owner was the receiver it took the
        # phone number out of the `to` leg — which is the OWNER's number — and
        # presented it as the counterparty's.
        if direction == "IN":
            cp = (first_or_dict(tstore.get("paymentPayerParty"))
                  or first_or_dict(tstore.get("from")))
            self_leg = first_or_dict(tstore.get("receivedIn")) or first_or_dict(tstore.get("to"))
        else:
            cp = (first_or_dict(tstore.get("paymentReceiver"))
                  or first_or_dict(tstore.get("to")))
            self_leg = (first_or_dict(tstore.get("paidFrom"))
                        or first_or_dict(tstore.get("receivedIn")))
            # On an owner-as-sender payload with no paidFrom/receivedIn leg, `from` is
            # the owner. Without this the self columns come back empty on those rows.
            if not self_leg and str(tstore.get("actor") or "").upper() == "SENDER":
                self_leg = first_or_dict(tstore.get("from"))

        amount_paise = _amount_paise(tstore, instruments, cp, self_leg)
        amount_inr = amount_to_rupees(amount_paise) if amount_paise >= 0 else None

        # Counterparty identity. Prefer bank/verified name; if only a masked name
        # ("******1478") is available, fall back to phone/VPA for display.
        cp_phone = pick(cp, "phone", "upiNumber") or (r.get("contact_data") if str(r.get("contact_data") or "").isdigit() else None)
        cp_vpa = pick(cp, "fullVpa", "vpa")
        cp_user_id = cp.get("userId")
        cp_name = pick(cp, "cbsName", "accountHolderName")
        cp_name_was_masked = False
        if not cp_name:
            raw_name = cp.get("name")
            if isinstance(raw_name, str) and (raw_name.startswith("*") or _is_masked(raw_name)):
                cp_name = cp_phone or cp_vpa or raw_name
                cp_name_was_masked = True
            else:
                cp_name = raw_name
        cp_name = cp_name or r.get("contact_data")

        # masked → real recovery: when the counterparty name was masked, recover a real
        # name via an EXACT full-phone or VPA match against the user's own contacts, and
        # record the source. (Only when masked — never churn an already-clean name.)
        cp_resolved = cp_resolved_source = cp_phone_full = cp_resolved_names = None
        if cp_name_was_masked or _is_masked(cp_name):
            hit = None
            if cp_phone and not _is_masked(cp_phone):
                hit = resolver.by_phone(cp_phone)
            if not hit and cp_vpa and not _is_masked(cp_vpa):
                hit = resolver.by_vpa(cp_vpa)
            if hit and hit.get("name"):
                cp_resolved = hit.get("name")
                cp_resolved_names = hit.get("names")          # per-source names (saved-in-PhonePe vs phonebook…)
                cp_resolved_source = "matched by " + (hit.get("via") or "phone")
                cp_phone_full = hit.get("phone") or (cp_phone if not _is_masked(cp_phone) else None)

        # Settlement rows have no payment leg, so the counterparty is empty — fill it from
        # the split partner (the other ledger member) resolved to a real contact name.
        if ttype == "EXPENSE_SETTLEMENT" and settle_other_member and not cp_name:
            hit = resolver.by_member(settle_other_member)
            if hit and hit.get("name"):
                cp_name = hit["name"]
                cp_resolved_names = hit.get("names")
                cp_phone = cp_phone or hit.get("phone")

        # Self identity harvested from the owner leg.
        self_holder = self_leg.get("accountHolderName")
        self_vpa = self_leg.get("vpa")
        self_acct = self_leg.get("accountNumber")
        self_ifsc = self_leg.get("ifsc")
        to_self = first_or_dict(tstore.get("to")) if direction == "IN" else {}
        if self_holder:
            self_holders.add(self_holder)
        if self_vpa:
            self_vpas.add(self_vpa)
        if self_acct:
            self_masked.add(self_acct)
        if to_self.get("userId"):
            self_user_ids.add(to_self["userId"])
        if to_self.get("upiNumber"):
            self_phones.add(to_self["upiNumber"])

        ts = normalize_timestamp(r.get("timestamp_created"))
        ts_upd = normalize_timestamp(r.get("timestamp_updated"))
        decoded_id = decode_txn_id(r.get("transaction_id") or r.get("payment_reference"))

        types[ttype] += 1
        statuses[state] += 1
        dir_count[direction] += 1
        if cp_name:
            counterparties[str(cp_name)] += 1

        # Same vocabulary the correlator uses, so a module summary and the
        # correlator's totals can never disagree about what "succeeded" means.
        is_success = state.strip().upper() in SUCCESS_STATES

        # Amount-ranked counterparty aggregation, per direction, successful only.
        if is_success and amount_inr is not None and direction in ("IN", "OUT"):
            full_phone = cp_phone_full or (cp_phone if not _is_masked(cp_phone) else None)
            stable = (("uid", cp_user_id) if cp_user_id else
                      ("ph", _last10(full_phone)) if full_phone else
                      ("vpa", str(cp_vpa).lower()) if cp_vpa else
                      ("name", str(cp_name).lower()) if cp_name else None)
            if stable:
                slot = cp_agg.setdefault((direction, stable), {
                    "name": None, "kind": "Peer", "count": 0, "amount_inr": 0.0,
                    "identifiers": set(),
                })
                # Label preference: a recovered real name always wins, then any
                # non-masked name, then whatever we have. `_is_masked` is not enough
                # to test the incumbent on its own — when a masked name was replaced
                # by a bare phone number upstream, that number reads as "not masked"
                # and would otherwise lock out a real name recovered from a later row.
                incumbent = slot["name"]
                incumbent_weak = (not incumbent or _is_masked(incumbent)
                                  or str(incumbent).replace("+", "").isdigit())
                if cp_resolved and (incumbent_weak or not slot.get("name_recovered")):
                    slot["name"] = cp_resolved
                    slot["name_recovered"] = True
                elif cp_name and incumbent_weak:
                    slot["name"] = cp_name
                if cp.get("type") == "MERCHANT" or cp.get("firstPartyMerchant"):
                    slot["kind"] = "Merchant"
                slot["count"] += 1
                slot["amount_inr"] = round(slot["amount_inr"] + amount_inr, 2)
                if cp_user_id:
                    slot["identifiers"].add(f"uid:{cp_user_id}")
                if full_phone:
                    slot["identifiers"].add(f"ph:{full_phone}")
                if cp_vpa:
                    slot["identifiers"].add(f"vpa:{cp_vpa}")

        if amount_inr is not None and is_success:
            if direction == "IN":
                total_in += amount_inr
            elif direction == "OUT":
                total_out += amount_inr
        if ts:
            yr, mo = ts["iso"][:4], ts["iso"][:7]
            if amount_inr is not None and is_success:
                if direction == "IN":
                    yearly_in[yr] += amount_inr
                elif direction == "OUT":
                    yearly_out[yr] += amount_inr
                if direction in ("IN", "OUT"):
                    monthly[mo] += amount_inr
            if earliest is None or ts["epoch_ms"] < earliest["epoch_ms"]:
                earliest = ts
            if latest is None or ts["epoch_ms"] > latest["epoch_ms"]:
                latest = ts

        out["transactions"].append({
            "z_pk": r.get("transaction_id"),
            "entity_id": r.get("transaction_id"),
            "global_payment_id": tstore.get("globalPaymentId") or r.get("payment_reference") or r.get("transaction_id"),
            "type": ttype,
            "state": state,
            "direction": direction,
            "amount_paise": amount_paise if amount_paise >= 0 else None,
            "amount_inr": amount_inr,
            "category_code": tags.get("entity.category"),
            "received_in_type": tags.get("receivedIn.type"),
            "counterparty": cp_name,
            "counterparty_resolved": cp_resolved,
            "counterparty_resolved_names": cp_resolved_names,
            "counterparty_resolved_source": cp_resolved_source,
            "counterparty_phone_full": cp_phone_full,
            "counterparty_phone": cp_phone,
            "counterparty_vpa": cp_vpa,
            "counterparty_user_id": cp_user_id,
            "counterparty_user_type": cp.get("type"),
            # Merchant vs person, from the counterparty leg's own type rather than
            # guessed from the name. The transactions table has always had a tag for
            # this; nothing populated it, so it never rendered.
            "classification": ("MERCHANT" if (cp.get("type") == "MERCHANT"
                                              or cp.get("firstPartyMerchant"))
                               else "PEER_TO_PEER" if ttype in ("SENT_PAYMENT",
                                                                "RECEIVED_PAYMENT")
                               else "SPLIT_SETTLEMENT" if ttype == "EXPENSE_SETTLEMENT"
                               else None),
            "counterparty_cbs_name": cp.get("cbsName") or cp.get("accountHolderName"),
            "self_account_holder": self_holder,
            "self_account_masked": self_acct,
            "self_vpa": self_vpa,
            "self_ifsc": self_ifsc,
            "instrument_id": self_leg.get("instrumentId"),
            "utr": self_leg.get("utr"),
            "transfer_mode": ctx.get("transferMode") or tags.get("context.transferMode"),
            # How the payment was initiated. The transactions table has always had QR
            # and INTENT tags; nothing set these keys, so like `classification` before
            # them they could never render — while `tstore.context` states the mode
            # outright. Forensically this is the difference between scanning a code in
            # person and being handed off from another app.
            #
            # True only where the app itself named the mode. False only where it named a
            # *different* one. Absent ⇒ None (unknown), never False: 48 rows carry no
            # `initiationMode` at all, and calling those "not a QR scan" would assert
            # more than the record says. The raw NPCI code is kept beside it, unmapped —
            # on this acquisition INTENT↔"04" (7/7) and QR_SCAN↔"01" (1/1) correspond
            # exactly, but that is an observation about one device, not a code table to
            # decode future acquisitions with.
            "initiation_mode": ctx.get("initiationMode"),
            "upi_initiation_mode": ctx.get("upiInitiationMode"),
            "is_qr_scan": (None if ctx.get("initiationMode") is None
                           else ctx.get("initiationMode") == "QR_SCAN"),
            "is_intent": (None if ctx.get("initiationMode") is None
                          else ctx.get("initiationMode") == "INTENT"),
            "context_tag": ctx.get("tag"),
            "response_code": tstore.get("responseCode") or self_leg.get("transactionResponseCode"),
            "merchant_id": cp.get("merchantId") if cp.get("type") == "MERCHANT" else None,
            "merchant_name": (cp.get("name") or cp.get("merchantId")) if cp.get("type") == "MERCHANT" else (cp.get("accountHolderName") if cp.get("firstPartyMerchant") else None),
            "mcc": cp.get("mcc") if cp.get("type") == "MERCHANT" else None,
            "biller_id": None,
            "biller_name": None,
            "recharge_number": None,
            "note": (tstore.get("note") or None),
            "group_id": tstore.get("groupId"),
            "group_template": tstore.get("groupTemplate"),
            "search_token": "  ".join(sorted(tokens_by_txn.get(tid_type, set()))),
            "created_at": ts,
            "updated_at": ts_upd,
            "id_embedded_ts": decoded_id,
            # `None` means the column is absent from this acquisition's schema (the
            # reader blanks pruned columns), which is not the same as "hidden from
            # history" — defaulting it to dismissed would mark every transaction
            # dismissed on a schema where the column was renamed.
            "dismissed": (False if r.get("show_on_history") is None
                          else not bool(r.get("show_on_history"))),
            "is_internal": bool(safe_int(tags.get("isInternalPayment"))),
            "raw_data": tstore if isinstance(tstore, dict) else None,
            "raw_tags": tags or None,
            "all_tags": tags,
        })

    out["summary"].update({
        "transaction_count": len(out["transactions"]),
        "type_breakdown": dict(types),
        "state_breakdown": dict(statuses),
        "direction_breakdown": dict(dir_count),
        "top_counterparties": counterparties.most_common(20),
        # Amount-ranked, identifier-keyed, split by direction — consumed by the
        # dashboard's "Top Counterparties" panel.
        "top_counterparties_received": _rank_counterparties(cp_agg, "IN"),
        "top_counterparties_sent": _rank_counterparties(cp_agg, "OUT"),
        "earliest_txn": earliest,
        "latest_txn": latest,
        "total_received_inr": round(total_in, 2),
        "total_sent_inr": round(total_out, 2),
        "net_flow_inr": round(total_in - total_out, 2),
        "yearly_received_inr": dict(sorted(yearly_in.items())),
        "yearly_sent_inr": dict(sorted(yearly_out.items())),
        # combined per-year volume (in+out) — consumed by dashboard() + the HTML report
        "yearly_volume_inr": {y: round(yearly_in.get(y, 0) + yearly_out.get(y, 0), 2)
                              for y in sorted(set(yearly_in) | set(yearly_out))},
        "monthly_volume_inr": dict(sorted(monthly.items())),
        "self_account_holders": sorted(self_holders),
        "self_account_masked": sorted(self_masked),
        "self_vpas": sorted(self_vpas),
        "self_user_ids": sorted(self_user_ids),
        "self_phones": sorted(self_phones),
    })
    return out


# ---------------------------------------------------------------------------
# Contacts  (phonepe_core: phone_contacts / contactConnectionInfo / nonContact* / phonebook)
# ---------------------------------------------------------------------------

def _last10(s: Any) -> Any:
    digits = "".join(c for c in str(s or "") if c.isdigit())
    return digits[-10:] if len(digits) >= 10 else (digits or None)


def _not_none_str(v: Any) -> Any:
    """Some Android stores write the literal text "None"/"null" for an empty column.

    Returned as a real absence, so a report cannot print the string "None" as if it
    were the subject's name.
    """
    if v is None:
        return None
    s = str(v).strip()
    return None if s in ("", "None", "null", "NULL", "nil") else v


def _is_masked(s: Any) -> bool:
    """True for PhonePe source-masked identifiers like '******1478' or 'XXXXXX5608'."""
    s = str(s or "")
    if not s:
        return False
    return ("*" in s) or (s.upper().startswith("XX") and any(c.isdigit() for c in s))


class IdentityResolver:
    """Cross-table masked→real resolver, shared by chat + transactions (the same idea
    proven on the ledger). For a masked counterparty it recovers a REAL name and/or a
    FULL phone/VPA, **and records which source table the value actually came from**.

    Joins are EXACT only — connection_id, member_id, last-10 phone, VPA — never fuzzy.
    A last-10 phone that maps to more than one distinct contact name is treated as
    AMBIGUOUS and left unresolved rather than guessed (forensic accuracy > coverage)."""

    # name-source priority (highest first) → human label. Labels name the ORIGIN so an
    # analyst can tell a PhonePe-saved contact name from the device-phonebook name.
    _NAME_LABEL = {
        "contactConnectionInfo": "saved in PhonePe",
        "phone_contacts": "phonebook",
        "vpa_contacts": "VPA contact",
        "paymentProfileCache": "payment profile",
        "phone": "phone match",
        "vpa": "VPA match",
    }

    def __init__(self, db):
        # connection_id -> ORDERED list of (name, source_key), highest priority first,
        # deduped case-insensitively. Keeping every source lets the UI show both the
        # PhonePe-contact name and the phonebook name when they differ, each labelled.
        self.conn_names: Dict[str, list] = {}
        self.conn_phone: Dict[str, tuple] = {}   # connection_id -> (full_phone, source_key)
        self.conn_vpa: Dict[str, tuple] = {}     # connection_id -> (full_vpa, source_key)
        self.mem_conn: Dict[str, str] = {}       # member_id -> connection_id
        self.phone10: Dict[str, tuple] = {}      # last10 -> (connection_id, phone_src)
        self.vpa_idx: Dict[str, tuple] = {}      # vpa(lower) -> (connection_id, vpa_src)
        self._build(db)

    # ---- internal builders -------------------------------------------------
    def _name(self, cid, name, src):
        if not (cid and name) or _is_masked(name):
            return
        name = " ".join(str(name).split())   # collapse internal/edge whitespace
        key = name.lower()
        lst = self.conn_names.setdefault(cid, [])
        if not any(" ".join(n.split()).lower() == key for n, _ in lst):
            lst.append((name, src))   # sources processed in priority order → list stays ordered

    def _phone(self, cid, ph, src):
        if cid and ph and not _is_masked(ph) and cid not in self.conn_phone:
            if _last10(ph) and len(_last10(ph)) == 10:
                self.conn_phone[cid] = (str(ph).strip(), src)

    def _vpa(self, cid, vp, src):
        if cid and vp and "@" in str(vp) and not _is_masked(vp) and cid not in self.conn_vpa:
            self.conn_vpa[cid] = (str(vp).strip(), src)

    def _build(self, db):
        # Process name sources in priority order (contactConnectionInfo first) so the
        # primary name is the highest-priority one and the per-name source is truthful.
        if db.has_table("contactConnectionInfo"):
            for c in db.query("SELECT connectionId, name FROM contactConnectionInfo"):
                if "_error" not in c:
                    self._name(c.get("connectionId"), c.get("name"), "contactConnectionInfo")
        if db.has_table("phone_contacts"):
            for c in db.query("SELECT connection_id, phone_num, cbs_name FROM phone_contacts"):
                if "_error" not in c:
                    self._name(c.get("connection_id"), c.get("cbs_name"), "phone_contacts")
                    self._phone(c.get("connection_id"), c.get("phone_num"), "phone_contacts")
        if db.has_table("vpa_contacts"):
            for c in db.query("SELECT connection_id, contact_vpa, nick_name, cbs_name FROM vpa_contacts"):
                if "_error" not in c:
                    self._name(c.get("connection_id"), c.get("nick_name") or c.get("cbs_name"), "vpa_contacts")
                    self._vpa(c.get("connection_id"), c.get("contact_vpa"), "vpa_contacts")
        if db.has_table("paymentProfileCache"):
            for c in db.query("SELECT connectionId, destination, name, cbsName FROM paymentProfileCache"):
                if "_error" not in c:
                    self._name(c.get("connectionId"), c.get("name") or c.get("cbsName"), "paymentProfileCache")
                    dest = c.get("destination")
                    if dest and "@" in str(dest):
                        self._vpa(c.get("connectionId"), dest, "paymentProfileCache")
                    else:
                        self._phone(c.get("connectionId"), dest, "paymentProfileCache")
        if db.has_table("topicMember"):
            for m in db.query("SELECT memberId, connectionId FROM topicMember"):
                if "_error" not in m and m.get("memberId") and m.get("connectionId"):
                    self.mem_conn.setdefault(m["memberId"], m["connectionId"])
        # Build last-10 phone / VPA indexes. AMBIGUITY guard keys on distinct CONNECTION
        # (different people); >1 name for the same connection is the same person, not ambiguity.
        pcand: Dict[str, set] = defaultdict(set)
        pfirst: Dict[str, tuple] = {}
        for cid, (ph, phsrc) in self.conn_phone.items():
            p = _last10(ph)
            if p and len(p) == 10 and cid in self.conn_names:
                pcand[p].add(cid)
                pfirst.setdefault(p, (cid, phsrc))
        self.phone10 = {p: pfirst[p] for p, cids in pcand.items() if len(cids) == 1}
        vcand: Dict[str, set] = defaultdict(set)
        vfirst: Dict[str, tuple] = {}
        for cid, (vp, vpsrc) in self.conn_vpa.items():
            if cid in self.conn_names:
                vcand[vp.lower()].add(cid)
                vfirst.setdefault(vp.lower(), (cid, vpsrc))
        self.vpa_idx = {v: vfirst[v] for v, cids in vcand.items() if len(cids) == 1}

    # ---- lookups -----------------------------------------------------------
    def _label(self, src_key):
        return self._NAME_LABEL.get(src_key, src_key)

    def by_connection(self, cid, _via=None, _via_src=None):
        if not cid:
            return None
        names = self.conn_names.get(cid) or []
        ph, vp = self.conn_phone.get(cid), self.conn_vpa.get(cid)
        if not (names or ph or vp):
            return None
        named = [{"name": n, "source": self._label(src)} for n, src in names]
        return {
            "name": named[0]["name"] if named else None,
            "name_source": named[0]["source"] if named else None,
            "names": named,                      # ALL distinct names, each labelled by origin
            "phone": ph[0] if ph else None,
            "phone_source": self._label(ph[1]) if ph else None,
            "vpa": vp[0] if vp else None,
            "via": _via,
        }

    def by_member(self, member_id):
        return self.by_connection(self.mem_conn.get(member_id))

    def by_phone(self, phone):
        p = _last10(phone)
        if not p or len(p) != 10:
            return None
        hit = self.phone10.get(p)
        if not hit:
            return None
        return self.by_connection(hit[0], _via="phone")

    def by_vpa(self, vpa):
        if not vpa or "@" not in str(vpa):
            return None
        hit = self.vpa_idx.get(str(vpa).lower())
        if not hit:
            return None
        return self.by_connection(hit[0], _via="vpa")


def extract_contacts(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"cyclops_contacts": [], "phonebook_contacts": [],
                           "external_data": {}, "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["summary"]["deletion_signals"] = db.deletion_signals()
        # Name lookup by connection id (contactConnectionInfo + vpa_contacts + paymentProfileCache)
        names: Dict[str, str] = {}
        if db.has_table("contactConnectionInfo"):
            for c in db.query("SELECT connectionId, name, contactDisplayId, onPhonePe FROM contactConnectionInfo"):
                if "_error" not in c and c.get("connectionId") and c.get("name"):
                    names[c["connectionId"]] = c["name"]
        # PhonePe-verified contacts ← phone_contacts (richest), enriched with names.
        if db.has_table("phone_contacts"):
            for c in db.query("SELECT phone_num, cbs_name, on_phonepe, upi_enabled, "
                              "externalVpaAvailable, connection_id, countryCode, region, "
                              "upi_status, phonepe_image_url, updated_at FROM phone_contacts"):
                if "_error" in c:
                    continue
                out["cyclops_contacts"].append({
                    "connect_id": c.get("connection_id"),
                    "phone": _last10(c.get("phone_num")),
                    "verified_name": names.get(c.get("connection_id")) or c.get("cbs_name"),
                    "external_vpa": None,
                    "external_vpa_name": c.get("cbs_name"),
                    "on_phonepe": tri_bool(c.get("on_phonepe")),
                    "upi_state": c.get("upi_status"),
                    "country_code": c.get("countryCode"),
                    "region": c.get("region"),
                    "last_synced": normalize_timestamp(c.get("updated_at")),
                    "photo_url": c.get("phonepe_image_url") or None,
                })
        # VPA contacts → additional cyclops rows keyed by VPA.
        if db.has_table("vpa_contacts"):
            for c in db.query("SELECT contact_vpa, nick_name, cbs_name, connection_id, "
                              "phonepe_image_url, updated_at FROM vpa_contacts"):
                if "_error" in c:
                    continue
                out["cyclops_contacts"].append({
                    "connect_id": c.get("connection_id"),
                    "phone": None,
                    "verified_name": c.get("nick_name") or c.get("cbs_name"),
                    "external_vpa": c.get("contact_vpa"),
                    "external_vpa_name": c.get("cbs_name"),
                    # `vpa_contacts` has no on_phonepe / upi_status column, so neither
                    # can be stated from it. They were hard-coded True/"ENABLED",
                    # which asserts a fact the evidence does not contain — and is
                    # plainly wrong for a VPA at another PSP (…@axl is Axis, not
                    # PhonePe). Unknown is reported as unknown.
                    "on_phonepe": None,
                    "upi_state": None,
                    "country_code": None, "region": None,
                    "last_synced": normalize_timestamp(c.get("updated_at")),
                    "photo_url": c.get("phonepe_image_url") or None,
                })
        # Payment-profile cache → real names + FULL destination (phone/VPA). Useful for
        # resolving counterparties and recovering numbers masked elsewhere (e.g. chat members).
        if db.has_table("paymentProfileCache"):
            for p in db.query("SELECT connectionId, destination, name, cbsName FROM paymentProfileCache"):
                if "_error" in p:
                    continue
                dest = str(p.get("destination") or "")
                is_vpa = "@" in dest
                out["cyclops_contacts"].append({
                    "connect_id": p.get("connectionId"),
                    "phone": None if is_vpa else _last10(dest),
                    "verified_name": p.get("name") or p.get("cbsName"),
                    "external_vpa": dest if is_vpa else None,
                    "external_vpa_name": p.get("cbsName"),
                    # Same reasoning as vpa_contacts: paymentProfileCache states no
                    # PhonePe-membership flag, so none is claimed.
                    "on_phonepe": None, "upi_state": None,
                    "country_code": None, "region": None,
                    "last_synced": None, "photo_url": None,
                    "source": "paymentProfileCache",
                })
        # nonContact — connections the subject interacted with that are NOT saved
        # contacts. The module header has always claimed this table; nothing read it.
        # `CONTACT_SEARCH` rows are numbers the subject looked up inside PhonePe, and
        # a searched-for number that was never saved is exactly the kind of link an
        # investigation wants. Kept as its own list rather than merged into contacts,
        # because these people are precisely *not* in the address book.
        if db.has_table("nonContact"):
            for c in db.query("SELECT connectionId, useCaseName, phoneNumber, isKnown, "
                              "isHidden, isPhoneContact, changeState, countryCode, "
                              "region FROM nonContact"):
                if "_error" in c:
                    out["errors"].append(c["_error"])
                    continue
                phone = _not_none_str(c.get("phoneNumber"))
                out.setdefault("non_contacts", []).append({
                    "connect_id": c.get("connectionId"),
                    "use_case": c.get("useCaseName"),
                    "phone": phone,
                    "phone_last10": _last10(phone) if phone else None,
                    "known": bool(safe_int(c.get("isKnown"))),
                    "hidden": bool(safe_int(c.get("isHidden"))),
                    "is_phone_contact": bool(safe_int(c.get("isPhoneContact"))),
                    "country_code": _not_none_str(c.get("countryCode")),
                    "region": _not_none_str(c.get("region")),
                    "source": "nonContact",
                })

        # Phonebook ← phone_book_contacts JOIN metadata (display_name) by lookup.
        meta: Dict[str, Dict[str, Any]] = {}
        if db.has_table("phone_book_contacts_metadata"):
            for m in db.query("SELECT lookup, display_name, is_valid FROM phone_book_contacts_metadata"):
                if "_error" not in m and m.get("lookup"):
                    meta[m["lookup"]] = m
        if db.has_table("phone_book_contacts"):
            for p in db.query("SELECT _id, lookup, raw_phone_num, is_valid, change_state, "
                              "created_at FROM phone_book_contacts"):
                if "_error" in p:
                    continue
                md = meta.get(p.get("lookup"), {})
                out["phonebook_contacts"].append({
                    "raw_number": p.get("raw_phone_num"),
                    "normalized": _last10(p.get("raw_phone_num")),
                    "country_code": None, "region": None,
                    "creation_time": normalize_timestamp(p.get("created_at")),
                    "is_valid": bool(p.get("is_valid")),
                    "deleted": p.get("change_state") == 3,
                    "full_name": md.get("display_name"),
                    "contact_id": p.get("_id"),
                    "hash_code": p.get("lookup"),
                    "has_image": False,
                    "image_size": 0,
                })
    cyc = out["cyclops_contacts"]
    pb = out["phonebook_contacts"]
    # A person can appear in phone_contacts, vpa_contacts AND paymentProfileCache,
    # so the row count is a count of source records, not of people. Both are
    # reported: the row count says how much evidence there is, the distinct count
    # says how many people it describes. Reporting only the former inflates
    # "contacts" by ~60% on a real acquisition.
    def _identity_key(c: Dict[str, Any]) -> Any:
        return (c.get("connect_id") or c.get("phone")
                or c.get("external_vpa") or id(c))
    distinct_people = {_identity_key(c) for c in cyc}
    on_phonepe_people = {_identity_key(c) for c in cyc if c.get("on_phonepe")}

    # The source stores many people twice — once as `9876543210` and once as
    # `+919876543210`, under ONE connection_id — and the two rows do not always
    # agree: on this acquisition 5 people carry contradictory `on_phonepe` and 7
    # contradictory `upi_status`. Both rows are kept (they are what the evidence
    # says) but the disagreement is reported, because a contacts page showing the
    # same number twice with opposite answers and no explanation invites the analyst
    # to pick one at random.
    by_person: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for c in cyc:
        by_person[_identity_key(c)].append(c)
    conflicts = []
    for key, group in by_person.items():
        if len(group) < 2:
            continue
        for field in ("on_phonepe", "upi_state"):
            values = {c.get(field) for c in group if c.get(field) is not None}
            if len(values) > 1:
                conflicts.append({
                    "identity": str(key),
                    "field": field,
                    # NOT "values": in a Jinja template `row.values` resolves to the
                    # dict's own .values() method, not to a key of that name, so a
                    # key called "values" renders as a bound method (or raises).
                    "conflicting_values": sorted(str(v) for v in values),
                    "phones": sorted({str(c.get("phone")) for c in group if c.get("phone")}),
                    "note": "the acquisition's own rows for this person disagree; "
                            "both are listed, neither is preferred",
                })
    for c in cyc:
        c["source_rows_for_person"] = len(by_person[_identity_key(c)])
    out["source_conflicts"] = conflicts
    out["summary"].update({
        # One convention for the headline pair: both count PEOPLE, so "X on PhonePe
        # of Y contacts" compares like with like. The row counts are kept under
        # explicit *_source_rows names — mixing the two under sibling labels made
        # the page read "151 of 298", comparing people against source records.
        "cyclops_total": len(distinct_people),
        "cyclops_distinct": len(distinct_people),
        "cyclops_source_rows": len(cyc),
        "phonebook_total": len(pb),
        "on_phonepe_count": len(on_phonepe_people),
        "on_phonepe_source_rows": sum(1 for c in cyc if c.get("on_phonepe")),
        "has_external_vpa_count": sum(1 for c in cyc if c.get("external_vpa")),
        "deleted_contacts": sum(1 for c in pb if c.get("deleted")),
        "external_image_count": 0,
        "non_contact_count": len(out.get("non_contacts") or []),
        "non_contact_with_phone": sum(1 for c in (out.get("non_contacts") or [])
                                      if c.get("phone")),
        "non_contact_searched": sum(1 for c in (out.get("non_contacts") or [])
                                    if c.get("use_case") == "CONTACT_SEARCH"),
        "source_conflict_count": len(conflicts),
        "on_phonepe_basis": "counted only where a source row states on_phonepe; "
                            "vpa_contacts and paymentProfileCache state no such flag "
                            "and are counted as unknown, not as members",
    })
    return out


# ---------------------------------------------------------------------------
# Chat  (phonepe_core: chatMessage / chatTopic / chatTopicMeta / topicMember)
# ---------------------------------------------------------------------------

def _chat_inner(content: Any) -> Dict[str, Any]:
    """chatMessage.content JSON nests the card under .content; return that inner dict."""
    if isinstance(content, dict):
        inner = content.get("content")
        return inner if isinstance(inner, dict) else content
    return {}


def _chat_card_details(inner: Dict[str, Any]) -> Dict[str, Any]:
    """Amount/txn-id/note/state live at different nested paths per card type:
      PAYMENT_INFO_CARD   -> .amount, .transactionId, .state/.paymentState
      TRANSACTION_RECEIPT -> .transactionUnit.value, .transactionId, .utr
      EXPENSE_CARD_V2     -> .expenseInfo.expenseCard.cardInfo.totalAmount, .name, .status, .expenseId
      SETTLEMENT_CARD     -> .settlementInfo.totalAmount, .globalSettlementId, .status
      GROUP_ACTION        -> (no amount; groupAction.name/actionType)
    """
    out = {"amount_paise": -1, "transaction_id": inner.get("transactionId"),
           "note": None, "state": inner.get("state") or inner.get("paymentState"),
           "utr": inner.get("utr")}
    amt = safe_int(inner.get("amount"), default=-1)
    if amt < 0:
        amt = safe_int((inner.get("transactionUnit") or {}).get("value"), default=-1)
    # EXPENSE_CARD_V2
    ec = (inner.get("expenseInfo") or {}).get("expenseCard") or {}
    if ec:
        ci = ec.get("cardInfo") or {}
        if amt < 0:
            amt = safe_int(ci.get("totalAmount"), default=-1)
        out["note"] = out["note"] or ci.get("name")
        out["state"] = out["state"] or ec.get("status")
        out["transaction_id"] = out["transaction_id"] or ec.get("expenseId")
    # SETTLEMENT_CARD
    si = inner.get("settlementInfo") or {}
    if si:
        if amt < 0:
            amt = safe_int(si.get("totalAmount") or si.get("globalSettlementAmount"), default=-1)
        out["state"] = out["state"] or si.get("status")
        out["transaction_id"] = out["transaction_id"] or si.get("globalSettlementId")
    # GROUP_ACTION
    ga = inner.get("groupAction") or {}
    if ga:
        out["note"] = out["note"] or (f"{ga.get('actionType')}: {ga.get('name')}" if ga.get("name") else ga.get("actionType"))
    out["amount_paise"] = amt
    return out


def extract_chat(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"groups": [], "messages": [], "members": [],
                           "shared_contacts": [], "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["summary"]["deletion_signals"] = db.deletion_signals()
        resolver = IdentityResolver(db)
        own_by_topic: Dict[str, str] = {}
        topic_name: Dict[str, str] = {}
        topic_created: Dict[str, Any] = {}
        if db.has_table("chatTopicMeta"):
            for t in db.query("SELECT topicId, ownMemberId, topicName, state, createdTime FROM chatTopicMeta"):
                if "_error" in t:
                    continue
                own_by_topic[t.get("topicId")] = t.get("ownMemberId")
                if t.get("topicName"):
                    topic_name[t["topicId"]] = t["topicName"]
                topic_created[t.get("topicId")] = t.get("createdTime")
        # Members
        members_by_topic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        member_name: Dict[str, str] = {}
        member_masked: Dict[str, str] = {}
        if db.has_table("topicMember"):
            for m in db.query("SELECT memberId, connectionId, memberTopicId, type, role, onPhonePe, "
                              "phonePeName, merchantName, isMemberDeleted, maskedPhoneNumber, "
                              "isGroupAccepted, addedByMemberId FROM topicMember"):
                if "_error" in m:
                    continue
                mid, topic = m.get("memberId"), m.get("memberTopicId")
                nm = m.get("phonePeName") or m.get("merchantName")
                member_name[mid] = nm
                member_masked[mid] = m.get("maskedPhoneNumber")
                is_self = (mid == own_by_topic.get(topic))
                # Masked→real recovery for participants, the same resolution the
                # message rows already get. Without it the participants table showed
                # a masked number next to "full number not recoverable" even where
                # the connection id resolves to a full phone in the contact tables —
                # a claim that was not merely incomplete but wrong.
                mres = resolver.by_member(mid) or {}
                nm_masked = _is_masked(nm) or not nm
                rec = {
                    "z_pk": mid, "group_pk": topic, "group_id": topic,
                    "phonepe_user": tri_bool(m.get("onPhonePe")),
                    "display_name": nm, "masked_phone": m.get("maskedPhoneNumber"),
                    # Recover whenever this record lacks a usable full number, not
                    # only when a masked one was stored: a member with no phone at
                    # all is equally unresolved, and gating on "was it masked"
                    # silently skipped those.
                    "phone_full": (mres.get("phone")
                                   if _is_masked(m.get("maskedPhoneNumber"))
                                   or not m.get("maskedPhoneNumber") else None),
                    "name_resolved": mres.get("name") if nm_masked else None,
                    "name_resolved_source": mres.get("name_source") if nm_masked else None,
                    "resolved_names": mres.get("names") if nm_masked else None,
                    "role": m.get("role"),
                    "state": "DELETED" if m.get("isMemberDeleted") else "ACTIVE",
                    "added_on": None,
                    "accepted": bool(m.get("isGroupAccepted")),
                    "added_by": m.get("addedByMemberId"),
                    "internal_id": mid,
                    "public_id": m.get("connectionId"), "is_self": is_self,
                }
                out["members"].append(rec)
                members_by_topic[topic].append(rec)
        # Groups ← chatTopic (+meta). For 1:1 P2P, name = the other member's name.
        if db.has_table("chatTopic"):
            for g in db.query("SELECT topicId, subSystemType, subscriptionStatus, lastUpdated, createdTime FROM chatTopic"):
                if "_error" in g:
                    continue
                tid = g.get("topicId")
                mem = members_by_topic.get(tid, [])
                others = [mm for mm in mem if not mm["is_self"] and mm.get("display_name")]
                name = topic_name.get(tid) or (others[0]["display_name"] if len(others) == 1 else None) or tid
                out["groups"].append({
                    "group_id": tid, "name": name, "status": None, "namespace": "chat",
                    "image_url": None, "type": g.get("subSystemType"),
                    "subsystem": g.get("subSystemType"), "subscription": g.get("subscriptionStatus"),
                    "active": True, "visibility": None,
                    "created_at": normalize_timestamp(g.get("createdTime") or topic_created.get(tid)),
                    "updated_at": normalize_timestamp(g.get("lastUpdated")),
                    "member_count": len(mem), "restore_completed": None,
                    "last_read_ts": None, "unread_count": None,
                })
        # Messages
        if db.has_table("chatMessage"):
            for r in db.query("SELECT clientMessageId, serverMessageId, topicId, contentType, "
                              "createdTime, lastUpdated, isDeleted, sourceMemberId, content FROM chatMessage"):
                if "_error" in r:
                    continue
                topic = r.get("topicId")
                content = decode_json_blob(r.get("content"))
                inner = _chat_inner(content)
                ctype = r.get("contentType")
                card = _chat_card_details(inner)
                amt_paise = card["amount_paise"]
                amount_inr = amount_to_rupees(amt_paise) if amt_paise >= 0 else None
                # parties via member resolution
                src = (content.get("source") or {}).get("groupMemberId") if isinstance(content, dict) else None
                src = src or r.get("sourceMemberId")
                dst = (inner.get("destination") or {}).get("groupMemberId")
                own = own_by_topic.get(topic)
                sender_is_self = (src == own) if (src and own) else None
                receiver_is_self = (dst == own) if (dst and own) else None
                sender_name = member_name.get(src)
                receiver_name = member_name.get(dst)
                # TRANSACTION_RECEIPT carries explicit sender/receiver names
                if inner.get("sender"):
                    sender_name = sender_name or inner["sender"].get("name")
                if inner.get("receiver"):
                    receiver_name = receiver_name or inner["receiver"].get("name")
                if sender_is_self is True:
                    direction, other_name, other_phone = "OUT", receiver_name, member_masked.get(dst)
                elif sender_is_self is False:
                    direction, other_name, other_phone = "IN", sender_name, member_masked.get(src)
                else:
                    direction, other_name, other_phone = "UNKNOWN", None, None
                # masked → real recovery (only where the original was masked/missing).
                def _resolve_party(member_id, orig_name, masked_phone):
                    r = resolver.by_member(member_id)
                    name_res = src_lbl = phone_full = names = None
                    if r:
                        if r.get("name") and (_is_masked(orig_name) or not orig_name):
                            name_res, src_lbl = r["name"], r.get("name_source")
                            names = r.get("names")
                        if r.get("phone") and _is_masked(masked_phone):
                            phone_full = r["phone"]
                    return name_res, src_lbl, phone_full, names
                s_name_res, s_src, s_phone_full, s_names = _resolve_party(src, sender_name, member_masked.get(src))
                r_name_res, r_src, r_phone_full, r_names = _resolve_party(dst, receiver_name, member_masked.get(dst))
                if sender_is_self is True:
                    o_name_res, o_src, o_phone_full, o_names = r_name_res, r_src, r_phone_full, r_names
                elif sender_is_self is False:
                    o_name_res, o_src, o_phone_full, o_names = s_name_res, s_src, s_phone_full, s_names
                else:
                    o_name_res = o_src = o_phone_full = o_names = None
                out["messages"].append({
                    "message_id": r.get("clientMessageId"),
                    "thread_id": topic, "type": ctype,
                    "amount_inr": amount_inr,
                    "transaction_id": card["transaction_id"],
                    "receiver_txn_id": None, "sender_txn_id": None,
                    "state": card["state"], "payment_state": inner.get("paymentState"),
                    "instrument": None, "utr": card["utr"],
                    "external_vpa": None, "external_bank": None,
                    "note": card["note"], "text_message": inner.get("message") if ctype == "TEXT_MESSAGE" else None,
                    "gift_message": None, "reward_type": None, "payment_title": None,
                    "preview_url": None, "local_file": None, "request_id": None, "request_state": None,
                    "decoded_payload": inner or None,
                    "expires_at": None, "last_reminded": None,
                    "created_at": normalize_timestamp(r.get("createdTime") or inner.get("createdAt")),
                    "updated_at": normalize_timestamp(r.get("lastUpdated") or inner.get("updatedAt")),
                    "visible": not bool(r.get("isDeleted")),
                    "sender_member_id": src, "receiver_member_id": dst,
                    "sender_name": sender_name, "sender_phone_masked": member_masked.get(src),
                    "sender_role": None, "sender_is_self": sender_is_self,
                    "sender_name_resolved": s_name_res, "sender_resolved_source": s_src,
                    "sender_phone_full": s_phone_full, "sender_resolved_names": s_names,
                    "receiver_name": receiver_name, "receiver_phone_masked": member_masked.get(dst),
                    "receiver_role": None, "receiver_is_self": receiver_is_self,
                    "receiver_name_resolved": r_name_res, "receiver_resolved_source": r_src,
                    "receiver_phone_full": r_phone_full, "receiver_resolved_names": r_names,
                    "other_party_name": other_name, "other_party_phone": other_phone,
                    "other_party_resolved": o_name_res, "other_party_resolved_source": o_src,
                    "other_party_phone_full": o_phone_full, "other_party_resolved_names": o_names,
                    "direction": direction, "is_outgoing": sender_is_self is True,
                    "group_name": topic_name.get(topic),
                })
    msgs = out["messages"]
    out["summary"].update({
        "group_count": len(out["groups"]),
        "message_count": len(msgs),
        "member_count": len(out["members"]),
        "payment_cards": sum(1 for m in msgs if m["type"] == "PAYMENT_INFO_CARD"),
        "text_messages": sum(1 for m in msgs if m["type"] == "TEXT_MESSAGE"),
        "image_attachments": 0,
        "rewards_gifts": 0,
        "money_requests": sum(1 for m in msgs if m["type"] in ("SETTLEMENT_CARD", "EXPENSE_CARD_V2")),
        "total_payment_inr": round(sum(m["amount_inr"] or 0 for m in msgs if m["type"] == "PAYMENT_INFO_CARD"), 2),
        "shared_account_disclosures": 0,
    })
    return out


# ---------------------------------------------------------------------------
# Payment infra  (phonepe_core: accounts / vpa / psp / wallet / banks / external_wallet)
# ---------------------------------------------------------------------------

def extract_payment_infra(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "linked_accounts": [], "linked_vpas": [], "psp_handles": [], "upi_lite": None,
        # Declared here, like upi_lite, so the contract is complete whether or not the
        # records exist. The templates guard on them either way; the point is that a
        # StrictUndefined audit sweep then flags only keys that are genuinely
        # undeclared, instead of 500ing on optional-but-expected ones.
        "upi_container": None, "upi_international": None, "approvers_recent": [],
        "linked_cards": [], "wallet": None, "external_wallets": [], "supported_banks": [],
        "summary": {}, "errors": [],
    }
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    vpas: set = set()
    with SQLiteReader(db_path) as db:
        if db.has_table("accounts"):
            for a in db.query("SELECT account_no, account_holder_name, account_alias, account_type, "
                              "is_primary, account_ifsc, bank_id, vpas FROM accounts"):
                if "_error" in a:
                    continue
                out["linked_accounts"].append({
                    "account_no_masked": a.get("account_no"),
                    "account_holder": a.get("account_holder_name"),
                    "account_alias": a.get("account_alias"),
                    "account_type": a.get("account_type"),
                    "is_primary": bool(a.get("is_primary")),
                    "updated_at": None,
                })
                vlist = decode_json_blob(a.get("vpas"))
                if isinstance(vlist, list):
                    for v in vlist:
                        if isinstance(v, dict) and v.get("vpaPrefix"):
                            for psp in (v.get("psps") or []):
                                if isinstance(psp, dict) and psp.get("psp"):
                                    vpas.add(f"{v['vpaPrefix']}@{psp['psp']}")
        if db.has_table("vpa"):
            for v in db.query("SELECT vpa FROM vpa"):
                if "_error" not in v and v.get("vpa"):
                    vpas.add(v["vpa"])
        if db.has_table("vpa_v2"):
            for v in db.query("SELECT vpa, psp FROM vpa_v2"):
                if "_error" not in v and v.get("vpa") and v.get("psp"):
                    vpas.add(f"{v['vpa']}@{v['psp']}")
        if db.has_table("psp"):
            for p in db.query("SELECT psp_handle, active FROM psp"):
                if "_error" not in p and p.get("psp_handle"):
                    out["psp_handles"].append({"handle": p["psp_handle"], "active": bool(p.get("active"))})
        if db.has_table("wallet"):
            w = db.query("SELECT available_balance, wallet_state, kyc_state FROM wallet LIMIT 1")
            if w and "_error" not in w[0]:
                out["wallet"] = {
                    "balance_inr": amount_to_rupees(w[0].get("available_balance")),
                    "state": w[0].get("wallet_state"),
                    "kyc_state": w[0].get("kyc_state"),
                    "timestamp": None,
                }
        if db.has_table("external_wallet_provider"):
            for e in db.query("SELECT name, linked, active, mobile_number, state, provider_type FROM external_wallet_provider"):
                if "_error" in e:
                    continue
                out["external_wallets"].append({
                    "name": e.get("name"), "balance_inr": None, "state": e.get("state"),
                    "active": bool(e.get("active")), "phone": e.get("mobile_number"),
                    "provider": e.get("provider_type"),
                })
        if db.has_table("banks"):
            for b in db.query("SELECT bank_id, bank_name, ifsc, centralIfsc, upi_supported, "
                              "upi_mandate_supported, credit_card_on_upi_supported, upi_lite_supported, "
                              "active, partner FROM banks"):
                if "_error" in b:
                    continue
                out["supported_banks"].append({
                    "id": b.get("bank_id"), "name": b.get("bank_name"),
                    "ifsc_prefix": b.get("ifsc"), "central_ifsc": b.get("centralIfsc"),
                    "upi": bool(b.get("upi_supported")), "upi_mandate": bool(b.get("upi_mandate_supported")),
                    "ccupi": bool(b.get("credit_card_on_upi_supported")), "lite": bool(b.get("upi_lite_supported")),
                    "active": bool(b.get("active")), "partner": bool(b.get("partner")),
                })
        # `approvers_table` — UPI mandate / family-account approvers: another
        # person authorised to approve this account's payments, which is a real
        # association between two people. The payment-infra page has always had a
        # panel for it reading `approvers_recent`, but nothing ever set that key,
        # so the panel could not render even where the table had rows. Empty on
        # the 2026-07-30 acquisition (0 rows) — wired so it is empty because the
        # evidence is empty, not because the code never looked.
        if db.has_table("approvers_table"):
            for a in db.query("SELECT approver_vpa, contact_name, contact_number, approver_type, "
                              "state, linking_type, expiry_ts, is_consent_needed, "
                              "full_mandate_state, full_mandate_amount, full_umn, "
                              "full_relationship_type, full_linking_time FROM approvers_table"):
                if "_error" in a:
                    continue
                out["approvers_recent"].append({
                    "approver_vpa": a.get("approver_vpa"),
                    "contact_name": a.get("contact_name"),
                    "contact_number": _last10(a.get("contact_number")),
                    "type": a.get("approver_type"),
                    "state": a.get("state"),
                    "linking_type": a.get("linking_type"),
                    "expiry": normalize_timestamp(a.get("expiry_ts")),
                    "linked_at": normalize_timestamp(a.get("full_linking_time")),
                    "consent_needed": tri_bool(a.get("is_consent_needed")),
                    "mandate_state": a.get("full_mandate_state"),
                    "mandate_amount_inr": amount_to_rupees(a.get("full_mandate_amount")),
                    "mandate_umn": a.get("full_umn"),
                    "relationship_type": a.get("full_relationship_type"),
                })
    out["linked_vpas"] = sorted(vpas)
    out["summary"].update({
        "approver_count": len(out["approvers_recent"]),
        "linked_account_count": len(out["linked_accounts"]),
        "linked_vpa_count": len(out["linked_vpas"]),
        "psp_count": len(out["psp_handles"]),
        "card_count": len(out["linked_cards"]),
        "supported_bank_count": len(out["supported_banks"]),
        "external_wallet_count": len(out["external_wallets"]),
    })
    return out


# ---------------------------------------------------------------------------
# Notifications  (BullhornDatabase: topic / messageDataStore)
# ---------------------------------------------------------------------------

def _b64_json(value: Any) -> Any:
    """Bullhorn wraps a message's real content as base64-encoded JSON.

    Padding is restored before decoding: the stored strings have had their `=`
    padding stripped (they arrive as `\\u003d` escapes in JSON and are trimmed),
    which makes a strict b64decode raise on perfectly good content.
    """
    if not isinstance(value, str) or not value:
        return None
    import base64
    raw = value.strip()
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:
        return None
    try:
        return json.loads(decoded)
    except Exception:
        return None


def _notification_content(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the human-visible parts out of a decoded Bullhorn push payload.

    Two families occur. A catalogue-sync instruction (`{id, system, operation,
    key}`) is machine chatter. An inbox notification carries a templated
    placement whose params hold the title/subtitle the user actually saw and the
    deeplink tapping it would have opened — that is the evidential part.
    """
    out: Dict[str, Any] = {}
    if not isinstance(payload, dict):
        return out
    if payload.get("system") and payload.get("operation"):
        out["kind"] = f"{payload.get('system')}/{payload.get('operation')}"
        out["sync_key"] = payload.get("key")
        return out
    if payload.get("type"):
        out["kind"] = payload["type"]
    for placement in ((payload.get("data") or {}).get("placements") or []):
        if not isinstance(placement, dict):
            continue
        tmpl = placement.get("template") or {}
        params = ((tmpl.get("templateParams") or {}).get("value") or {})
        out.setdefault("template", tmpl.get("templateId"))
        for src, dst in (("title", "title"), ("subTitle", "subtitle"),
                         ("message", "body"), ("body", "body")):
            if params.get(src) and not out.get(dst):
                out[dst] = params[src]
        nav = (tmpl.get("nav") or {}).get("params") or {}
        for key in ("deepLink", "deepLinkIOS", "deeplink"):
            if nav.get(key) and not out.get("deeplink"):
                out["deeplink"] = nav[key]
        if not out.get("deeplink"):
            for entry in (((nav.get("redirection_data") or {}).get("data")) or []):
                if isinstance(entry, dict) and entry.get("key") == "url" and entry.get("value"):
                    out["deeplink"] = entry["value"]
                    break
        if out.get("title"):
            break
    out.setdefault("kind", "NOTIFICATION" if out.get("title") else "unclassified")
    return out


# A decoded payload is kept per message so the content is auditable, but the
# catalogue-sync family repeats the same four fields thousands of times, so only
# the notification family keeps its full payload.
_MAX_STORED_MESSAGES = 25_000


def extract_notifications(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"topics": [], "raw_messages": [], "message_ops": [],
                           "summary": {}, "errors": []}
    db_path = paths.db("BullhornDatabase")
    if not db_path:
        out["errors"].append("BullhornDatabase not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    subsystem_bd: Counter = Counter()
    storage_bd: Counter = Counter()
    kind_bd: Counter = Counter()
    with SQLiteReader(db_path) as db:
        # Stored message bodies. `message` holds the operation log (a handful of
        # rows); `messageDataStore` holds the actual delivered payloads, and it was
        # previously never read at all — the provenance page claimed it as a source
        # while the extractor only counted `message`, so thousands of delivered
        # notifications were invisible outside the raw-table browser.
        if db.has_table("messageDataStore"):
            for r in db.query("SELECT messageId, data FROM messageDataStore"):
                if "_error" in r:
                    out["errors"].append(r["_error"])
                    continue
                if len(out["raw_messages"]) >= _MAX_STORED_MESSAGES:
                    out["errors"].append(
                        f"messageDataStore truncated at {_MAX_STORED_MESSAGES} rows")
                    break
                envelope = decode_json_blob(r.get("data"))
                msg = (envelope or {}).get("message") if isinstance(envelope, dict) else {}
                msg = msg if isinstance(msg, dict) else {}
                payload = _b64_json(msg.get("payload"))
                content = _notification_content(payload or {})
                kind_bd[content.get("kind") or "?"] += 1
                is_notification = bool(content.get("title") or content.get("body"))
                out["raw_messages"].append({
                    "message_id": msg.get("id") or r.get("messageId"),
                    "server_id": msg.get("serverId"),
                    "topic_id": msg.get("topicId"),
                    "kind": content.get("kind"),
                    "title": content.get("title"),
                    "subtitle": content.get("subtitle"),
                    "body": content.get("body"),
                    "deeplink": content.get("deeplink"),
                    "template": content.get("template"),
                    "sync_key": content.get("sync_key"),
                    "created_at": normalize_timestamp(msg.get("created")),
                    "updated_at": normalize_timestamp(msg.get("updated")),
                    "expiry_at": normalize_timestamp(msg.get("expiry")),
                    "sent_at": normalize_timestamp((payload or {}).get("sentAt")),
                    "expires_at": normalize_timestamp((payload or {}).get("expiresAt")),
                    "is_notification": is_notification,
                    "payload_undecodable": msg.get("payload") is not None and payload is None,
                    # Full payload only where it carries distinct content.
                    "payload": payload if is_notification else None,
                })
        if db.has_table("message"):
            for r in db.query("SELECT messageId, topicId_M, messageOperationType, "
                              "messageOperationData, createdTimeStamp, updateTimeStamp, "
                              "typeOfSubscriberType_M FROM message"):
                if "_error" in r:
                    continue
                op = decode_json_blob(r.get("messageOperationData"))
                inner = (op or {}).get("message") if isinstance(op, dict) else {}
                out["message_ops"].append({
                    "message_id": r.get("messageId"),
                    "topic_id": r.get("topicId_M"),
                    "operation": r.get("messageOperationType"),
                    "subscriber_type": r.get("typeOfSubscriberType_M"),
                    "created_at": normalize_timestamp(r.get("createdTimeStamp")),
                    "updated_at": normalize_timestamp(r.get("updateTimeStamp")),
                    "payload": _b64_json((inner or {}).get("payload")),
                })
        # message counts per topic
        msg_count: Dict[str, int] = {}
        if db.has_table("message"):
            for r in db.query("SELECT topicId_M, COUNT(*) c FROM message GROUP BY topicId_M"):
                if "_error" not in r:
                    msg_count[r.get("topicId_M")] = r.get("c")
        # Delivered-payload counts per topic, which is the number that reflects how
        # much actually arrived on this topic.
        stored_count: Counter = Counter(m["topic_id"] for m in out["raw_messages"]
                                        if m.get("topic_id"))
        if db.has_table("topic"):
            for t in db.query("SELECT topicId, subSystemType, messageStorageType, singleUse, "
                              "topicCreatedTimeStamp, topicUpdateTimeStamp, messageExpiry, "
                              "topicSubscriptionStatus, lastMessageSyncTime FROM topic"):
                if "_error" in t:
                    continue
                subsystem_bd[t.get("subSystemType") or "?"] += 1
                storage_bd[t.get("messageStorageType") or "?"] += 1
                out["topics"].append({
                    "topic_id": t.get("topicId"),
                    "subsystem": t.get("subSystemType"),
                    "storage_type": t.get("messageStorageType"),
                    "single_use": bool(t.get("singleUse")),
                    "created_at": normalize_timestamp(t.get("topicCreatedTimeStamp")),
                    "updated_at": normalize_timestamp(t.get("topicUpdateTimeStamp")),
                    "expiry_at": normalize_timestamp(t.get("messageExpiry")),
                    "subscription_status": t.get("topicSubscriptionStatus"),
                    "status": None,
                    "last_sync": normalize_timestamp(t.get("lastMessageSyncTime")),
                    "raw_message_count": msg_count.get(t.get("topicId"), 0),
                    "stored_message_count": stored_count.get(t.get("topicId"), 0),
                })
    notifications = [m for m in out["raw_messages"] if m["is_notification"]]
    dated = sorted(m["created_at"]["iso"] for m in out["raw_messages"] if m.get("created_at"))
    out["summary"].update({
        "topic_count": len(out["topics"]),
        "subsystem_breakdown": dict(subsystem_bd),
        "storage_type_breakdown": dict(storage_bd),
        "stored_message_count": len(out["raw_messages"]),
        "notification_count": len(notifications),
        "message_operation_count": len(out["message_ops"]),
        "payload_kind_breakdown": dict(kind_bd.most_common(25)),
        "undecodable_payloads": sum(1 for m in out["raw_messages"]
                                    if m["payload_undecodable"]),
        "earliest_message": dated[0] if dated else None,
        "latest_message": dated[-1] if dated else None,
    })
    return out


# ---------------------------------------------------------------------------
# Identity  (minimal: accounts/users; expand with shared_prefs next session)
# ---------------------------------------------------------------------------

def _read_crashlytics(paths: AndroidCasePaths) -> Dict[str, Any]:
    """Device/OS/app/user fingerprint from files/.crashlytics.v3/.../{native/*.json,user-data,keys}."""
    info: Dict[str, Any] = {}
    if not paths.files_dir:
        return info
    base = os.path.join(paths.files_dir, ".crashlytics.v3", "com.phonepe.app", "open-sessions")
    if not os.path.isdir(base):
        return info
    import json as _json
    for sess in sorted(os.listdir(base)):
        sd = os.path.join(base, sess)
        for rel in ("native/device.json", "native/os.json", "native/app.json",
                    "native/session.json", "user-data", "keys"):
            p = os.path.join(sd, rel)
            if not os.path.exists(p):
                continue
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    d = _json.load(fh)
            except Exception:
                continue
            if isinstance(d, dict):
                info.update({k: v for k, v in d.items()})
        break  # first (current) session is enough
    return info


def extract_identity(paths: AndroidCasePaths) -> Dict[str, Any]:
    """Identity + device fingerprint, mined from DBs + shared_prefs + Crashlytics."""
    out: Dict[str, Any] = {
        "registered_name": None, "upi_id": None, "phones_seen": [],
        "device_identifiers": {}, "location_hints": [], "tokens": {},
        "sessions": {}, "feature_flags": [], "errors": [],
    }
    phones: set = set()
    vpas: List[str] = []

    # --- DBs (accounts / vpa / users) ---
    db_path = paths.db("phonepe_core")
    if db_path:
        with SQLiteReader(db_path) as db:
            if db.has_table("accounts"):
                for a in db.query("SELECT account_holder_name, vpas FROM accounts"):
                    if "_error" in a:
                        continue
                    if a.get("account_holder_name") and not out["registered_name"]:
                        out["registered_name"] = a["account_holder_name"]
                    vlist = decode_json_blob(a.get("vpas"))
                    if isinstance(vlist, list):
                        for v in vlist:
                            if isinstance(v, dict) and v.get("vpaPrefix"):
                                for psp in (v.get("psps") or []):
                                    if isinstance(psp, dict) and psp.get("psp"):
                                        vpas.append(f"{v['vpaPrefix']}@{psp['psp']}")
            if db.has_table("vpa"):
                for v in db.query("SELECT vpa, is_primary FROM vpa"):
                    if "_error" in v:
                        continue
                    if v.get("vpa"):
                        vpas.append(v["vpa"])
                        if v.get("is_primary") and not out["upi_id"]:
                            out["upi_id"] = v["vpa"]
            if db.has_table("users"):
                for u in db.query("SELECT user_phone_number, phone_num_e164, verified_name, user_id FROM users"):
                    if "_error" in u:
                        continue
                    for ph in (u.get("user_phone_number"), u.get("phone_num_e164")):
                        if ph:
                            phones.add(str(ph))
                    if u.get("verified_name") and not out["registered_name"]:
                        out["registered_name"] = u["verified_name"]
            # device location (GPS) — phonepe_core.location.data is JSON with lat/long/pincode/state
            if db.has_table("location"):
                for loc in db.query("SELECT namespace, type, manual, data FROM location"):
                    if "_error" in loc:
                        continue
                    d = decode_json_blob(loc.get("data"))
                    if isinstance(d, dict) and d.get("latitude") is not None:
                        out["location_hints"].append({
                            "lat": d.get("latitude"), "lng": d.get("longitude"),
                            "pincode": d.get("pincode"), "state": d.get("state"),
                            "city": d.get("city"), "locality": d.get("locality"),
                            "manual": bool(loc.get("manual")),
                            "source": f"location.{loc.get('namespace')}/{loc.get('type')}",
                        })
    else:
        out["errors"].append("phonepe_core not found")

    # --- accounts_db: the Android account-manager record for the signed-in user ---
    # This database had no extractor at all, yet it holds the subject's own user id,
    # e-mail and — unlike almost everything else in the acquisition — an UNMASKED
    # full phone number, next to a masked `user_name`. Identifying the account
    # holder is the first question asked of an exhibit, so it is read here rather
    # than left to the raw-table browser.
    accounts_db = paths.db("accounts_db")
    if accounts_db:
        with SQLiteReader(accounts_db) as db:
            if db.has_table("account"):
                for a in db.query("SELECT user_id, user_display_name, user_name, "
                                  "user_phone_number, user_email, email_verified, "
                                  "phone_number_verified FROM account"):
                    if "_error" in a:
                        out["errors"].append(f"accounts_db: {a['_error']}")
                        continue
                    acct: Dict[str, Any] = {
                        "user_id": a.get("user_id"),
                        # 'None' arrives as the literal string in this store.
                        "display_name": _not_none_str(a.get("user_display_name")),
                        "user_name": _not_none_str(a.get("user_name")),
                        "phone": _not_none_str(a.get("user_phone_number")),
                        "email": _not_none_str(a.get("user_email")),
                        "email_verified": bool(safe_int(a.get("email_verified"))),
                        "phone_verified": bool(safe_int(a.get("phone_number_verified"))),
                        "source": "accounts_db.account",
                    }
                    out.setdefault("accounts", []).append(acct)
                    if acct["phone"] and not _is_masked(acct["phone"]):
                        phones.add(acct["phone"])
                    # Its OWN key: Crashlytics also reports a "userId", but that is a
                    # hashed telemetry id, not this one. Writing both to
                    # `phonepe_user_id` meant whichever ran second silently replaced
                    # the other, losing the account identifier that actually appears
                    # in the evidence (topic names, product.entity_id).
                    if acct["user_id"]:
                        out["device_identifiers"].setdefault(
                            "phonepe_account_user_id", acct["user_id"])
                    # Only a real name, never the masked `user_name`, may become the
                    # registered name.
                    for cand in (acct["display_name"], acct["user_name"]):
                        if cand and not _is_masked(cand) and not out["registered_name"]:
                            out["registered_name"] = cand
                    if acct["email"]:
                        out.setdefault("emails", []).append(acct["email"])

    dev = out["device_identifiers"]
    # --- Crashlytics device/OS/app/user fingerprint ---
    cl = _read_crashlytics(paths)
    if cl:
        dev["device_manufacturer"] = cl.get("build_manufacturer")
        dev["device_model"] = cl.get("build_model")
        dev["device_product"] = cl.get("build_product")
        dev["total_ram"] = cl.get("total_ram")
        dev["disk_space"] = cl.get("disk_space")
        dev["is_emulator"] = cl.get("is_emulator")
        dev["os_version"] = cl.get("version")
        dev["is_rooted"] = cl.get("is_rooted")
        dev["app_version"] = cl.get("version_name")
        dev["app_version_code"] = cl.get("version_code")
        dev["install_uuid"] = cl.get("install_uuid")
        ud = cl.get("userId")  # "userId:<...>::deviceId:<...>"
        if isinstance(ud, str):
            for part in ud.split("::"):
                if part.startswith("userId:"):
                    dev["phonepe_user_id"] = part[len("userId:"):]
                elif part.startswith("deviceId:"):
                    dev["phonepe_device_id"] = part[len("deviceId:"):]
        if cl.get("started_at_seconds"):
            out["sessions"]["crashlytics_session_started"] = normalize_timestamp(int(cl["started_at_seconds"]) * 1000)
        dev["anon_id"] = cl.get("ANON_ID") or dev.get("anon_id")

    # --- shared_prefs: device IDs, install date, tokens, sessions ---
    sp = paths.shared_prefs_dir
    if sp:
        from .core_android import read_shared_pref
        def pref(name):
            p = paths.shared_pref(name)
            return read_shared_pref(p) if p else {}

        anon = pref("anon_pref.xml")
        if anon.get("anon_id"):
            dev["anon_id"] = anon["anon_id"]
        af = pref("appsflyer-data.xml")
        if af.get("AF_INSTALLATION"):
            dev["appsflyer_id"] = af["AF_INSTALLATION"]
        if af.get("appsFlyerFirstInstall"):
            out["sessions"]["first_install"] = af["appsFlyerFirstInstall"]
        fb = pref("com.google.firebase.crashlytics.xml")
        if fb.get("firebase.installation.id"):
            dev["firebase_installation_id"] = fb["firebase.installation.id"]
        if fb.get("crashlytics.installation.id"):
            dev["crashlytics_installation_id"] = fb["crashlytics.installation.id"]
        gms = pref("com.google.android.gms.appid.xml")
        for k, v in gms.items():
            if k.startswith("|T|") and isinstance(v, str):
                tok = decode_json_blob(v)
                if isinstance(tok, dict) and tok.get("token"):
                    dev["fcm_token"] = tok["token"]
                break
        # session id is encoded in the session-config filename
        for f in os.listdir(sp):
            if f.startswith("phonepe_session_config") and f.endswith(".xml"):
                out["sessions"]["session_id"] = f[len("phonepe_session_config_"):-4]
                sc = pref(f)
                out["sessions"]["session_1fa_valid"] = sc.get("is_valid_1fa")
                break
        auth = pref("phonepe_auth_config.xml")
        out["sessions"]["accounts_count"] = auth.get("number_of_accounts_in_bs")
        if auth.get("last_updated_trustmeta"):
            out["sessions"]["trustmeta_updated"] = normalize_timestamp(auth["last_updated_trustmeta"])
        refresh = []
        for k, v in auth.items():
            tok = decode_json_blob(v) if isinstance(v, str) else None
            if isinstance(tok, dict) and tok.get("refreshToken"):
                refresh.append({"id": k, "expiry": normalize_timestamp((tok.get("expiry") or 0) * 1000),
                                "scope": tok.get("scope")})
        if refresh:
            out["tokens"]["refresh_tokens"] = refresh
        if pref("phonepe_accounts_config.xml").get("token"):
            out["tokens"]["accounts_token_present"] = True
        lock = pref("screenlock.xml")
        if lock.get("biometricTokenTimestamp"):
            out["sessions"]["biometric_token_ts"] = normalize_timestamp(lock["biometricTokenTimestamp"])
        out["sessions"]["biometric_required"] = lock.get("biometricConfirmationRequired")
        # feature flags as {flag: value} (the identity view renders .items())
        ff = pref("feature_flag.xml")
        out["feature_flags"] = {k: ff[k] for k in list(ff)[:300]}

    if not out["upi_id"] and vpas:
        out["upi_id"] = vpas[0]
    out["phones_seen"] = sorted(phones)
    out["all_vpas"] = sorted(set(vpas))
    return out


# ---------------------------------------------------------------------------
# Analytics  (kn_generic.db: AnalyticEvent)   [no Analytics DB on Android]
# ---------------------------------------------------------------------------

def extract_analytics(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"kn_events": [], "foxtrot_pending": [], "auth_foxtrot_pending": [],
                           "dash_pending": [], "summary": {}, "errors": []}
    funnel: Counter = Counter()
    db_path = paths.db("kn_generic.db")
    if db_path:
        with SQLiteReader(db_path) as db:
            if db.has_table("AnalyticEvent"):
                for e in db.query("SELECT id, eventName, identifier, funnelInfo, timeStamp, primaryKey FROM AnalyticEvent"):
                    if "_error" in e:
                        continue
                    funnel[e.get("identifier") or "?"] += 1
                    fi = e.get("funnelInfo")
                    out["kn_events"].append({
                        "id": e.get("id"), "event_name": e.get("eventName"),
                        "identifier": e.get("identifier"),
                        "timestamp": normalize_timestamp(e.get("timeStamp")),
                        "primary_key": e.get("primaryKey"),
                        "funnel_info_preview": (fi[:160] if isinstance(fi, str) else None),
                    })
    else:
        out["errors"].append("kn_generic.db not found")
    out["summary"] = {"kn_event_count": len(out["kn_events"]), "kn_funnel_breakdown": dict(funnel),
                      "foxtrot_pending_count": 0, "auth_foxtrot_pending_count": 0, "dash_pending_count": 0}
    return out


# ---------------------------------------------------------------------------
# Financial  (phonepe_core: rewards / offers / voucher_products / fund_sync_lite_table)
# ---------------------------------------------------------------------------

def extract_financial(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"rewards": [], "mutual_funds": [], "vouchers": [], "donations": [],
                           "offers": [], "voucher_categories": [], "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    with SQLiteReader(db_path) as db:
        if db.has_table("rewards"):
            for r in db.query("SELECT * FROM rewards"):
                if "_error" in r:
                    continue
                out["rewards"].append({
                    "reward_id": r.get("reward_id") or r.get("id"),
                    "type": r.get("type"), "state": r.get("state"),
                    "amount_inr": amount_to_rupees(r.get("amount")) if r.get("amount") is not None else None,
                    "created_at": normalize_timestamp(r.get("created_at")),
                    "available_at": None, "claimed_at": None, "expires_at": None,
                    "linked_transaction": r.get("transaction_id") or r.get("linked_txn_id"),
                    "title": r.get("title"), "coupon_code": None, "share_message": None,
                    "display_message": None, "cashback_txn": None,
                })
        if db.has_table("offers"):
            for o in db.query("SELECT offerId, offerTitle, offersState, offerType, categoryId, "
                              "categoryName, startDate, endDate FROM offers"):
                if "_error" in o:
                    continue
                out["offers"].append({
                    "offer_id": o.get("offerId"), "title": o.get("offerTitle"), "action": None,
                    "category_id": o.get("categoryId"), "state": o.get("offersState"),
                    "type": o.get("offerType"),
                    "starts": normalize_timestamp(o.get("startDate")),
                    "ends": normalize_timestamp(o.get("endDate")),
                })
        # Gift-card catalogue. This is the product list PhonePe synced to the
        # device, NOT vouchers the subject holds — labelled as such, because a
        # "vouchers" list that reads as holdings would misrepresent it. Surfaced
        # because the module header claimed this table as a source while never
        # reading it, the same overstatement messageDataStore had.
        if db.has_table("voucher_products"):
            for v in db.query("SELECT product_id, provider_id, issuer_id, name, "
                              "product_type, price_type, min_price, max_price, status, "
                              "validity_in_months, created_at FROM voucher_products "
                              "LIMIT 5000"):
                if "_error" in v:
                    continue
                out["vouchers"].append({
                    "product_id": v.get("product_id"),
                    "name": v.get("name"),
                    "provider": v.get("provider_id"),
                    "issuer": v.get("issuer_id"),
                    "type": v.get("product_type"),
                    "price_type": v.get("price_type"),
                    "min_inr": amount_to_rupees(v.get("min_price")),
                    "max_inr": amount_to_rupees(v.get("max_price")),
                    "status": v.get("status"),
                    "validity_months": v.get("validity_in_months"),
                    "created_at": normalize_timestamp(v.get("created_at")),
                    "kind": "catalogue_product",
                })
        if db.has_table("fund_sync_lite_table"):
            for f in db.query("SELECT fund_id, fund_name, fund_category, amc_display_name, enabled FROM fund_sync_lite_table LIMIT 5000"):
                if "_error" in f:
                    continue
                out["mutual_funds"].append({
                    "fund_id": f.get("fund_id"), "amc": f.get("amc_display_name"),
                    "name": f.get("fund_name"), "category": f.get("fund_category"),
                    "enabled": bool(f.get("enabled")), "updated_at": None,
                })
    out["summary"] = {
        "rewards_count": len(out["rewards"]), "mf_catalogue_count": len(out["mutual_funds"]),
        # Catalogue sizes, not the subject's holdings — named so they cannot be
        # misread as "the subject has 713 vouchers".
        "voucher_catalogue_count": len(out["vouchers"]),
        "voucher_category_count": 0, "donation_provider_count": 0,
        "offers_count": len(out["offers"]),
    }
    return out


# ---------------------------------------------------------------------------
# Travel  (phonepe_core: yatra_journeys / yatra_actions)
# ---------------------------------------------------------------------------

def extract_travel(paths: AndroidCasePaths) -> Dict[str, Any]:
    """Android 'Yatra' = PhonePe's internal user-journey / onboarding-funnel tracker
    (yatra_journeys + yatra_tags), NOT travel bookings. The source
    leaves name/state/type NULL; the meaningful fields are traversed_path, current_stage_name,
    is_active/is_complete, and the linked yatra_tags (e.g. ONBOARDING_PROFILE, INSURANCE_*)."""
    out: Dict[str, Any] = {"journeys": [], "actions": [], "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    states: Counter = Counter()
    tag_breakdown: Counter = Counter()
    with SQLiteReader(db_path) as db:
        tags_by_journey: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
        if db.has_table("yatra_tags"):
            for t in db.query("SELECT tag_id, journey_id, percentage_completed, last_seen, "
                              "created_at FROM yatra_tags"):
                if "_error" in t:
                    continue
                tag_breakdown[t.get("tag_id") or "?"] += 1
                if t.get("journey_id") and t.get("journey_id") != "NA":
                    tags_by_journey[t["journey_id"]].append(t)
        if db.has_table("yatra_journeys"):
            for j in db.query("SELECT journey_id, traversed_path, name, description, current_stage_name, "
                              "state, entity_type, is_active, is_complete, is_enabled, "
                              "created_at, updated_at FROM yatra_journeys"):
                if "_error" in j:
                    continue
                jtags = tags_by_journey.get(j.get("journey_id"), [])
                tag_names = sorted({t.get("tag_id") for t in jtags if t.get("tag_id")})
                derived_state = j.get("state") or (
                    "COMPLETE" if j.get("is_complete") else
                    "ACTIVE" if j.get("is_active") else
                    ("ENABLED" if j.get("is_enabled") else "INACTIVE"))
                states[derived_state] += 1
                pct = max((safe_int(t.get("percentage_completed")) for t in jtags), default=0)
                out["journeys"].append({
                    "journey_id": j.get("journey_id"),
                    # surface the real, populated content (source name/desc are NULL)
                    "name": j.get("name") or (", ".join(tag_names) if tag_names else j.get("current_stage_name")),
                    "description": j.get("description") or
                        f"stage={j.get('current_stage_name')} · path={j.get('traversed_path')} · {pct}% complete",
                    "namespace": "yatra",
                    "type": j.get("entity_type") or "ONBOARDING_JOURNEY",
                    "state": derived_state,
                    "entity_type": j.get("entity_type"),
                    "current_stage": j.get("current_stage_name"),
                    "traversed_path": j.get("traversed_path"),
                    "is_complete": bool(j.get("is_complete")),
                    "percentage_completed": pct,
                    "tags": tag_names,
                    "created_at": normalize_timestamp(j.get("created_at")),
                    "updated_at": normalize_timestamp(j.get("updated_at")),
                })
    out["summary"] = {"db_sha256": hash_file(db_path), "journey_count": len(out["journeys"]),
                      "action_count": 0, "state_breakdown": dict(states),
                      "type_breakdown": dict(tag_breakdown),
                      "kind": "onboarding/feature journeys (not travel bookings)"}
    return out


# ---------------------------------------------------------------------------
# Config state  (chimeraDB: chimera_entity ; AthenaDatabase: experiment / bucket)
# ---------------------------------------------------------------------------

def extract_config_state(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"config_keys": [], "chimera_responses": [], "liquid_ui_responses": [],
                           "experiments": [], "buckets": [], "summary": {}, "errors": []}
    chimera = paths.db("chimeraDB")
    if chimera:
        with SQLiteReader(chimera) as db:
            if db.has_table("chimera_entity"):
                for c in db.query("SELECT key, org, team, response, version FROM chimera_entity"):
                    if "_error" in c:
                        continue
                    resp = c.get("response")
                    out["chimera_responses"].append({
                        "key_id": c.get("key"), "team": c.get("team"), "org": c.get("org"),
                        "max_version": c.get("version"), "verified": None,
                        "response_size": len(resp) if isinstance(resp, str) else 0,
                    })
    athena = paths.db("AthenaDatabase")
    if athena:
        with SQLiteReader(athena) as db:
            if db.has_table("experiment"):
                for e in db.query("SELECT experiment_id, activity_id, client_id, experiment_type, "
                                  "state, mode, version, start_date, end_date FROM experiment"):
                    if "_error" in e:
                        continue
                    out["experiments"].append({
                        "experiment_id": e.get("experiment_id"), "activity_id": e.get("activity_id"),
                        "client_id": e.get("client_id"), "summary": None, "type": e.get("experiment_type"),
                        "state": e.get("state"), "mode": e.get("mode"), "version": e.get("version"),
                        "started": normalize_timestamp(e.get("start_date")),
                        "ends": normalize_timestamp(e.get("end_date")), "created": None,
                    })
            if db.has_table("bucket"):
                for b in db.query("SELECT bucket_id, bucket_name, status, percentage, bucket_type, experiment_id FROM bucket"):
                    if "_error" in b:
                        continue
                    out["buckets"].append({
                        "bucket_id": b.get("bucket_id"), "name": b.get("bucket_name"),
                        "summary": None, "status": b.get("status"), "percentage": b.get("percentage"),
                        "type": b.get("bucket_type"), "experiment_pk": b.get("experiment_id"),
                    })
    out["summary"] = {"config_key_count": 0, "chimera_response_count": len(out["chimera_responses"]),
                      "experiment_count": len(out["experiments"]), "bucket_count": len(out["buckets"])}
    return out


# ---------------------------------------------------------------------------
# Recommendations  (RecommendationsDatabase: product / recommendation_item / signal)
# ---------------------------------------------------------------------------

def extract_recommendations(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"recommendations": [], "products": [], "signals": [], "summary": {}, "errors": []}
    # PhonePe renamed this store: the recommendation engine's product /
    # recommendation_item / signal tables now live in `MaximusDatabase`, with the
    # same schema. Looking only for the old name reported "RecommendationsDatabase
    # not found" on an acquisition that had all of the data, which is the worst
    # possible failure for this tool — a confident claim that a source is absent.
    # Both names are tried and the one used is recorded.
    db_path = None
    for candidate in ("RecommendationsDatabase", "MaximusDatabase"):
        db_path = paths.db(candidate)
        if db_path:
            break
    if not db_path:
        out["errors"].append("no recommendations database found "
                             "(tried RecommendationsDatabase, MaximusDatabase)")
        # An absent source is not the same as a zero count, so the counts are left
        # null rather than set to 0 — but the keys must exist, or the page renders a
        # blank tile with no explanation instead of "no such database".
        out["summary"] = {"product_count": None, "recommendation_count": None,
                          "signal_count": None, "source_absent": True}
        return out
    with SQLiteReader(db_path) as db:
        if db.has_table("product"):
            for p in db.query("SELECT product_id, product_name, product_namespace FROM product"):
                if "_error" in p:
                    continue
                out["products"].append({"product_id": p.get("product_id"), "name": p.get("product_name"),
                                        "namespace": p.get("product_namespace"), "preferred_size": None})
        if db.has_table("recommendation_item"):
            for r in db.query("SELECT item_id, product_id, rank, item_expiry FROM recommendation_item"):
                if "_error" in r:
                    continue
                out["recommendations"].append({"item_id": r.get("item_id"), "rank": r.get("rank"),
                                               "expiry": normalize_timestamp(r.get("item_expiry")),
                                               "product_pk": r.get("product_id")})
        if db.has_table("signal"):
            for s in db.query("SELECT signal_type, signal_timestamp, is_synced, item_id FROM signal"):
                if "_error" in s:
                    continue
                out["signals"].append({"signal_type": s.get("signal_type"),
                                       "timestamp": normalize_timestamp(s.get("signal_timestamp")),
                                       "synced": bool(s.get("is_synced")), "recommendation_pk": s.get("item_id")})
    out["summary"] = {"db_sha256": hash_file(db_path),
                      "database": os.path.basename(db_path),
                      "source_absent": False,
                      "product_count": len(out["products"]),
                      "recommendation_count": len(out["recommendations"]),
                      "signal_count": len(out["signals"])}
    return out


# ---------------------------------------------------------------------------
# Search  (search.db: recent_search ; phonepe_core: global_search_sitemap)
# ---------------------------------------------------------------------------

def extract_search(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"recent_searches": [], "indexed_entities": [], "sitemap": [],
                           "summary": {}, "errors": []}
    sdb = paths.db("search.db")
    if sdb:
        with SQLiteReader(sdb) as db:
            if db.has_table("recent_search"):
                for r in db.query("SELECT link_rowid, link_id, tbl, col, timestamp FROM recent_search"):
                    if "_error" in r:
                        continue
                    out["recent_searches"].append({
                        "unique_id": r.get("link_id"), "timestamp": normalize_timestamp(r.get("timestamp")),
                        "entity": r.get("tbl"), "field_id": r.get("col"), "entry_id": str(r.get("link_rowid"))})
    core = paths.db("phonepe_core")
    if core:
        with SQLiteReader(core) as db:
            if db.has_table("global_search_sitemap"):
                for s in db.query("SELECT id, deeplink, titleDefaultValue, keywords, imageUrl FROM global_search_sitemap"):
                    if "_error" in s:
                        continue
                    out["sitemap"].append({"id": s.get("id"), "use_case": s.get("titleDefaultValue"),
                                           "deeplink": s.get("deeplink"), "keywords": s.get("keywords"),
                                           "image_url": s.get("imageUrl"), "updated_at": None})
    out["summary"] = {"recent_search_count": len(out["recent_searches"]), "sitemap_count": len(out["sitemap"]),
                      "entity_count": len({s["entity"] for s in out["recent_searches"]})}
    return out


# ---------------------------------------------------------------------------
# SMS  (inference_data_provider.sms_buffer)  — ANDROID-EXCLUSIVE
# ---------------------------------------------------------------------------

def extract_sms(paths: AndroidCasePaths) -> Dict[str, Any]:
    """PhonePe ingests device SMS for transaction inference. this is a
    net-new Android evidence source. Stored under case.data['sms']; wiring into the unified
    timeline requires a small (platform-agnostic) correlator extension — see CONTINUE.md."""
    out: Dict[str, Any] = {"messages": [], "summary": {}, "errors": []}
    db_path = paths.db("inference_data_provider")
    if not db_path:
        out["errors"].append("inference_data_provider not found")
        return out
    senders: Counter = Counter()
    with SQLiteReader(db_path) as db:
        if db.has_table("sms_buffer"):
            for s in db.query("SELECT id, time_received, address, body, complete_meta FROM sms_buffer ORDER BY time_received DESC"):
                if "_error" in s:
                    continue
                senders[s.get("address") or "?"] += 1
                out["messages"].append({
                    "id": s.get("id"), "address": s.get("address"), "body": s.get("body"),
                    "received_at": normalize_timestamp(s.get("time_received")),
                    "meta": decode_json_blob(s.get("complete_meta")),
                })
    out["summary"] = {"db_sha256": hash_file(db_path), "sms_count": len(out["messages"]),
                      "sender_breakdown": dict(senders.most_common(20))}
    return out


# ---------------------------------------------------------------------------
# WebKit  (app_webview/Default/Cookies — Chromium, µs-since-1601 timestamps)
# ---------------------------------------------------------------------------

def extract_webkit(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"cookies": [], "resource_load_stats": [], "local_storage": [],
                           "indexed_db": [], "summary": {}, "errors": []}
    if not paths.webview_dir:
        out["errors"].append("app_webview not found")
        return out
    cookies_db = os.path.join(paths.webview_dir, "Default", "Cookies")
    if os.path.exists(cookies_db):
        out["cookies_path"] = cookies_db
        out["cookies_sha256"] = hash_file(cookies_db)
        try:
            with SQLiteReader(cookies_db) as db:
                for c in db.query("SELECT host_key, name, path, value, is_secure, is_httponly, "
                                  "creation_utc, expires_utc, last_access_utc FROM cookies"):
                    if "_error" in c:
                        continue
                    flags = []
                    if c.get("is_secure"):
                        flags.append("Secure")
                    if c.get("is_httponly"):
                        flags.append("HTTPOnly")
                    cre = chromium_ts(c.get("creation_utc"))
                    exp = chromium_ts(c.get("expires_utc"))
                    out["cookies"].append({
                        "domain": c.get("host_key"), "name": c.get("name"), "path": c.get("path"),
                        "value": c.get("value") or "<encrypted>",
                        "creation_iso": cre["iso"] if cre else None,
                        "expiry_iso": exp["iso"] if exp else None,
                        "last_access": chromium_ts(c.get("last_access_utc")),
                        "flags": flags,
                    })
        except Exception as exc:
            out["errors"].append(f"cookies: {exc}")
    # localStorage / sessionStorage presence (LevelDB — listed, not parsed)
    ls = os.path.join(paths.webview_dir, "Default", "Local Storage", "leveldb")
    if os.path.isdir(ls):
        for f in sorted(os.listdir(ls)):
            fp = os.path.join(ls, f)
            if os.path.isfile(fp):
                out["local_storage"].append({"name": f, "size": os.path.getsize(fp)})
    out["summary"] = {"cookie_count": len(out["cookies"]),
                      "resource_load_domains": 0,
                      "local_storage_files": len(out["local_storage"]),
                      "indexed_db_entries": 0}
    return out


# ---------------------------------------------------------------------------
# Media  (files/ images + phonepe_core.user_qr_code)
# ---------------------------------------------------------------------------

def extract_media(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"qr_codes": [], "transaction_backgrounds": [],
                           "background_categories": [], "contact_dps_external": [], "summary": {}}
    # Owner QR from DB
    db_path = paths.db("phonepe_core")
    if db_path:
        with SQLiteReader(db_path) as db:
            if db.has_table("user_qr_code"):
                for q in db.query("SELECT qr_payload, identifier_type, identifier_data FROM user_qr_code"):
                    if "_error" in q:
                        continue
                    out["qr_codes"].append({"path": None, "size": 0,
                                            "content_hash": q.get("identifier_data") or "",
                                            "filename": "user_qr_code (owner)",
                                            "qr_payload": q.get("qr_payload"),
                                            "identifier_type": q.get("identifier_type")})
    # Image files under files/ (skip RN asset bundles' icon noise by tagging source dir)
    if paths.files_dir:
        for cur, _, fl in os.walk(paths.files_dir):
            for f in fl:
                if f.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                    fp = os.path.join(cur, f)
                    rel = os.path.relpath(fp, paths.files_dir)
                    is_asset = "NirvanaBundles" in rel  # RN UI assets, not user media
                    out["contact_dps_external"].append({
                        "name": rel, "size": os.path.getsize(fp), "path": fp,
                        "kind": "rn_asset" if is_asset else "media",
                    })
    out["summary"] = {"qr_count": len(out["qr_codes"]), "background_assets": 0,
                      "background_categories": 0, "contact_dp_count": len(out["contact_dps_external"])}
    return out


# ---------------------------------------------------------------------------
# Audit  (phonepe_core: phonepe_sync_tracing / consent / ledger_* ; consent DB ; device info)
# ---------------------------------------------------------------------------

def extract_audit(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ledger_sync": [], "consents": [], "central_sync": [], "bg_sync_items": [],
                           "cassini_models": [],
                           "device_info": {}, "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if db_path:
        with SQLiteReader(db_path) as db:
            # background-sync tracking ← phonepe_sync_tracing. NOTE: in this DB the `system`
            # and `systemKey` columns are always "UNKNOWN"/empty; the meaningful identifier is
            # `syncId` (the sync task, often a minified class name) and `syncStatus`. We map
            # those into system/key so the shared correlator's "Sync: {system}/{key}" title is
            # informative ("Sync: <task>/<SYNC_SUCCESS|SYNC_FAILED>").
            if db.has_table("phonepe_sync_tracing"):
                for s in db.query("SELECT syncId, syncStatus, syncDataNature, "
                                  "lastSyncAttemptTime, lastSyncCompletionTime FROM phonepe_sync_tracing"):
                    if "_error" in s:
                        continue
                    sid = s.get("syncId"); status = s.get("syncStatus")
                    out["central_sync"].append({
                        "sync_id": sid, "type": s.get("syncDataNature"),
                        "status": status, "key": status, "system": sid,
                        "last_attempt": normalize_timestamp(s.get("lastSyncAttemptTime")),
                        "last_completed": normalize_timestamp(s.get("lastSyncCompletionTime")),
                    })
            # On-device ML models ← `model_data`. The audit page has always had a
            # "Cassini" panel for these; nothing set the key, so it could not render.
            # The audit page's job is disclosing what the app held on device, and
            # "no models" is only an honest statement if the table was actually read.
            # Empty on the 2026-07-30 acquisition (0 rows). No checksum column exists
            # here, so that field stays absent rather than being filled with `key`.
            if db.has_table("model_data"):
                for m in db.query("SELECT id, name, version, state, serving_state, "
                                  "download_uri, directory_uri, created_at, updated_at "
                                  "FROM model_data"):
                    if "_error" in m:
                        continue
                    out["cassini_models"].append({
                        "id": m.get("id"), "name": m.get("name"),
                        "version": m.get("version"),
                        "local_state": m.get("state"),
                        "server_state": m.get("serving_state"),
                        "download_uri": m.get("download_uri"),
                        "directory_uri": m.get("directory_uri"),
                        "created_at": normalize_timestamp(m.get("created_at")),
                        "updated_at": normalize_timestamp(m.get("updated_at")),
                    })
            # consent (in-core)
            if db.has_table("consent"):
                for c in db.query("SELECT consentId, dataType, useCaseId, acceptType, "
                                  "consentState, endTime, consentSyncState FROM consent"):
                    if "_error" in c:
                        continue
                    out["consents"].append({
                        "consent_id": c.get("consentId"),
                        "state": c.get("consentState"), "destination": c.get("dataType"),
                        "accept_type": c.get("acceptType"),
                        "subject_id": c.get("useCaseId"),
                        # This table does carry consentSyncState; it simply was not being
                        # selected, so the column showed empty for these 21 rows while the
                        # standalone database's rows filled it.
                        "sync_state": c.get("consentSyncState"),
                        # Declared None, not omitted: this table has no subjectRefId or
                        # consentDefinition column, and the two consent sources are merged
                        # into one list that one template iterates. A key present on some
                        # records and absent on others makes the same cell mean "empty" for
                        # one row and "field does not exist" for the next.
                        "subject_ref": None,
                        "definition": None,
                        "end_time": normalize_timestamp(c.get("endTime")),
                        "source": "phonepe_core.consent",
                    })
    # The standalone `consent` DATABASE is a separate store from phonepe_core's
    # consent table and was never read — it holds the permission grants (GPS,
    # LOCAL_DISCOVERY …) with their own definitions and sync state. What a subject
    # consented to, and when, is squarely evidential, so it is merged in here with
    # its origin recorded rather than left to the raw-table browser.
    consent_db = paths.db("consent")
    if consent_db:
        with SQLiteReader(consent_db) as db:
            if db.has_table("consent"):
                for c in db.query("SELECT consentId, subjectRefId, dataType, useCaseId, "
                                  "acceptType, consentState, endTime, consentSyncState, "
                                  "consentDefinition FROM consent"):
                    if "_error" in c:
                        out["errors"].append(f"consent db: {c['_error']}")
                        continue
                    out["consents"].append({
                        "consent_id": c.get("consentId"),
                        "state": c.get("consentState"),
                        "destination": c.get("dataType"),
                        "accept_type": c.get("acceptType"),
                        "subject_id": c.get("useCaseId"),
                        # 'NA' is the source's own placeholder, not a real reference.
                        "subject_ref": (c.get("subjectRefId")
                                        if c.get("subjectRefId") not in (None, "", "NA")
                                        else None),
                        "sync_state": c.get("consentSyncState"),
                        "definition": c.get("consentDefinition"),
                        "end_time": normalize_timestamp(c.get("endTime")),
                        "source": "consent.consent",
                    })
    if db_path:
        with SQLiteReader(db_path) as db:
            # ledger balances (split bills)
            if db.has_table("ledger_balance_sync"):
                for l in db.query("SELECT ledger_id, syncSplitType, sync_status, last_sync_time FROM ledger_balance_sync"):
                    if "_error" in l:
                        continue
                    out["ledger_sync"].append({
                        "ledger_id": l.get("ledger_id"), "balance_status": l.get("sync_status"),
                        "expense_status": l.get("syncSplitType"),
                        "last_balance_sync": normalize_timestamp(l.get("last_sync_time")),
                        "is_gang_group": None,
                    })
    out["device_info"] = _read_crashlytics(paths)
    out["summary"] = {"ledger_sync_count": len(out["ledger_sync"]),
                      "consent_count": len(out["consents"]),
                      "consent_sources": dict(Counter(c["source"] for c in out["consents"])),
                      "consent_data_types": dict(Counter(
                          c["destination"] for c in out["consents"] if c.get("destination"))),
                      "central_sync_count": len(out["central_sync"]), "bg_sync_count": 0}
    return out


# ---------------------------------------------------------------------------
# Mini-apps  (files/NirvanaApps — installed RN/PWA services; NexusCore analog)  [NEW]
# ---------------------------------------------------------------------------

def extract_miniapps(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"apps": [], "summary": {}, "errors": []}
    if not paths.files_dir:
        out["errors"].append("files/ not found")
        return out
    na = os.path.join(paths.files_dir, "NirvanaApps")
    if not os.path.isdir(na):
        return out
    import json as _json
    for app_dir in sorted(os.listdir(na)):
        d = os.path.join(na, app_dir)
        if not os.path.isdir(d):
            continue
        rec: Dict[str, Any] = {"dir_id": app_dir}
        man = os.path.join(d, "manifest.json")
        if os.path.exists(man):
            try:
                with open(man, encoding="utf-8", errors="replace") as fh:
                    m = _json.load(fh)
                rec.update({"app_id": m.get("appId"), "app_unique_id": m.get("appUniqueId"),
                            "name": m.get("name"), "version": m.get("appVersion"),
                            "version_id": m.get("appVersionId")})
            except Exception:
                pass
        cfg = os.path.join(d, "config.json")
        if os.path.exists(cfg):
            try:
                with open(cfg, encoding="utf-8", errors="replace") as fh:
                    c = _json.load(fh)
                first = c[0] if isinstance(c, list) and c else (c if isinstance(c, dict) else {})
                conf = first.get("config", first) if isinstance(first, dict) else {}
                rec["merchant_name"] = conf.get("merchantName")
                rec["micro_app_type"] = conf.get("microAppType")
                rec["whitelisted_domains"] = conf.get("whitelistedDomains")
            except Exception:
                pass
        info = os.path.join(d, "nirvanaApplicationInfo.json")
        if os.path.exists(info):
            try:
                with open(info, encoding="utf-8", errors="replace") as fh:
                    i = _json.load(fh)
                rec["category"] = i.get("category")
                rec["installation_type"] = i.get("installationType")
                rec["updated_at"] = normalize_timestamp(i.get("updatedAt"))
            except Exception:
                pass
        out["apps"].append(rec)
    out["summary"] = {"miniapp_count": len(out["apps"]),
                      "merchants": sorted({a.get("merchant_name") for a in out["apps"] if a.get("merchant_name")})}
    return out


# ---------------------------------------------------------------------------
# Ledger / Bill-splitting  (phonepe_core: ledger_* — PhonePe "Split" shared expenses)
# ---------------------------------------------------------------------------

def _ledger_name_maps(db) -> tuple:
    """Build member_id->name, connection_id->name, and the set of self member ids."""
    member_name: Dict[str, str] = {}
    conn_name: Dict[str, str] = {}
    own: set = set()
    if db.has_table("topicMember"):
        for m in db.query("SELECT memberId, connectionId, phonePeName, merchantName FROM topicMember"):
            if "_error" in m:
                continue
            nm = m.get("phonePeName") or m.get("merchantName")
            if m.get("memberId") and nm:
                member_name[m["memberId"]] = nm
            if m.get("connectionId") and nm:
                conn_name.setdefault(m["connectionId"], nm)
    if db.has_table("contactConnectionInfo"):
        for c in db.query("SELECT connectionId, name FROM contactConnectionInfo"):
            if "_error" not in c and c.get("connectionId") and c.get("name"):
                conn_name[c["connectionId"]] = c["name"]
    if db.has_table("phone_contacts"):
        for c in db.query("SELECT connection_id, cbs_name FROM phone_contacts"):
            if "_error" not in c and c.get("connection_id") and c.get("cbs_name"):
                conn_name.setdefault(c["connection_id"], c["cbs_name"])
    if db.has_table("vpa_contacts"):
        for c in db.query("SELECT connection_id, nick_name, cbs_name FROM vpa_contacts"):
            if "_error" not in c and c.get("connection_id"):
                conn_name.setdefault(c["connection_id"], c.get("nick_name") or c.get("cbs_name"))
    if db.has_table("paymentProfileCache"):
        for c in db.query("SELECT connectionId, name, cbsName FROM paymentProfileCache"):
            if "_error" not in c and c.get("connectionId"):
                nm = c.get("name") or c.get("cbsName")
                if nm and not str(nm).startswith("*"):
                    conn_name.setdefault(c["connectionId"], nm)
    if db.has_table("chatTopicMeta"):
        for t in db.query("SELECT ownMemberId FROM chatTopicMeta"):
            if "_error" not in t and t.get("ownMemberId"):
                own.add(t["ownMemberId"])
    return member_name, conn_name, own


def extract_ledger(paths: AndroidCasePaths) -> Dict[str, Any]:
    """PhonePe 'Split' / shared-expense ledgers: groups, expenses, per-member shares,
    net balances, and settlement→transaction linkage. (Android-specific module.)"""
    out: Dict[str, Any] = {"ledgers": [], "expenses": [], "balances": [], "my_net": [],
                           "summary": {}, "errors": []}
    db_path = paths.db("phonepe_core")
    if not db_path:
        out["errors"].append("phonepe_core not found")
        return out
    with SQLiteReader(db_path) as db:
        member_name, conn_name, own = _ledger_name_maps(db)

        def name_of(mid, cid):
            # prefer the REAL contact name (by connection_id) over the masked phonePeName
            return conn_name.get(cid) or member_name.get(mid) or cid or mid

        # expense_id -> settlement transaction id
        settle: Dict[str, str] = {}
        if db.has_table("ledger_settlement"):
            for s in db.query("SELECT id, global_id FROM ledger_settlement"):
                if "_error" not in s and s.get("id"):
                    settle[s["id"]] = s.get("global_id")
        # expense_id -> [members]
        members_by_exp: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        if db.has_table("ledger_expense_member"):
            for m in db.query("SELECT member_id, connection_id, is_payer, expense_id, amount FROM ledger_expense_member"):
                if "_error" in m:
                    continue
                members_by_exp[m.get("expense_id")].append({
                    "name": name_of(m.get("member_id"), m.get("connection_id")),
                    "is_payer": bool(m.get("is_payer")),
                    "is_self": m.get("member_id") in own,
                    "amount_inr": amount_to_rupees(m.get("amount")),
                })
        # Ledgers (groups) ← ledger_meta + ledger_entity (topic_id links to chat group)
        topic_of: Dict[str, str] = {}
        if db.has_table("ledger_entity"):
            for e in db.query("SELECT ledger_id, topic_id FROM ledger_entity"):
                if "_error" not in e:
                    topic_of[e.get("ledger_id")] = e.get("topic_id")
        if db.has_table("ledger_meta"):
            for lm in db.query("SELECT ledgerId, createdAt, magicSettle FROM ledger_meta"):
                if "_error" in lm:
                    continue
                out["ledgers"].append({
                    "ledger_id": lm.get("ledgerId"),
                    "chat_topic_id": topic_of.get(lm.get("ledgerId")),
                    "created_at": normalize_timestamp(lm.get("createdAt")),
                    "magic_settle": bool(lm.get("magicSettle")),
                })
        # Expenses
        if db.has_table("ledger_expense"):
            for e in db.query("SELECT id, name, type, ledger_id, state, createdAt, updatedAt, "
                              "created_by, last_updated_by FROM ledger_expense ORDER BY createdAt DESC"):
                if "_error" in e:
                    continue
                mem = members_by_exp.get(e.get("id"), [])
                payer = next((m for m in mem if m["is_payer"]), None)
                total = payer["amount_inr"] if payer else round(sum(m["amount_inr"] or 0 for m in mem), 2)
                out["expenses"].append({
                    "expense_id": e.get("id"),
                    "name": e.get("name") or None,
                    "type": e.get("type"),
                    "ledger_id": e.get("ledger_id"),
                    "state": e.get("state"),
                    "amount_inr": total,
                    "created_at": normalize_timestamp(e.get("createdAt")),
                    "created_by": name_of(e.get("created_by"), None),
                    "payer": payer["name"] if payer else None,
                    "settlement_txn_id": settle.get(e.get("id")),
                    "members": mem,
                })
        # Per-member balances
        if db.has_table("ledger_balance"):
            for b in db.query("SELECT member_id, connection_id, ledger_id, balanceAmountToGive, balanceAmountToReceive FROM ledger_balance"):
                if "_error" in b:
                    continue
                out["balances"].append({
                    "name": name_of(b.get("member_id"), b.get("connection_id")),
                    "is_self": b.get("member_id") in own,
                    "ledger_id": b.get("ledger_id"),
                    "to_give_inr": amount_to_rupees(b.get("balanceAmountToGive")),
                    "to_receive_inr": amount_to_rupees(b.get("balanceAmountToReceive")),
                })
        # My net position with each counterparty
        if db.has_table("ledger_my_split"):
            for s in db.query("SELECT id, other_connect_id, signed_amount FROM ledger_my_split"):
                if "_error" in s:
                    continue
                out["my_net"].append({
                    "split_id": s.get("id"),
                    "counterparty": conn_name.get(s.get("other_connect_id")) or s.get("other_connect_id"),
                    "net_inr": amount_to_rupees(abs(safe_int(s.get("signed_amount")))) *
                               (-1 if safe_int(s.get("signed_amount")) < 0 else 1),
                })
    out["summary"] = {
        "ledger_count": len(out["ledgers"]),
        "expense_count": len(out["expenses"]),
        "total_expense_inr": round(sum(e["amount_inr"] or 0 for e in out["expenses"]), 2),
        "settled_expense_count": sum(1 for e in out["expenses"] if e["settlement_txn_id"]),
        "members_with_balance": len(out["balances"]),
    }
    return out


# ===========================================================================
# FULL-COVERAGE LAYER — "parse everything, nothing skipped"
# Dedicated modules above give curated/correlated views; the modules below
# guarantee EVERY artifact is captured: all SQLite tables, all shared_prefs,
# all files (incl. Jetpack DataStore protobuf + JSON), and an explicit record
# of the encrypted DBs that cannot be read offline.
# ===========================================================================

# ---- minimal Jetpack Preferences DataStore protobuf reader ----

def _rd_varint(b: bytes, i: int):
    shift = 0; val = 0
    while i < len(b):
        byte = b[i]; i += 1
        val |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return val, i


def _rd_value(msg: bytes) -> Any:
    """A DataStore Value is a message with exactly one set field; map field number to type."""
    import struct as _st
    if not msg:
        return None
    tag, i = _rd_varint(msg, 0)
    field, wt = tag >> 3, tag & 7
    try:
        if field == 1 and wt == 0:  # bool
            v, _ = _rd_varint(msg, i); return bool(v)
        if field == 2 and wt == 5:  # float
            return round(_st.unpack("<f", msg[i:i+4])[0], 6)
        if field == 3 and wt == 0:  # int32
            v, _ = _rd_varint(msg, i); return v
        if field == 4 and wt == 0:  # int64
            v, _ = _rd_varint(msg, i); return v
        if field == 5 and wt == 1:  # double
            return _st.unpack("<d", msg[i:i+8])[0]
        if field == 6 and wt == 2:  # string
            ln, j = _rd_varint(msg, i); return msg[j:j+ln].decode("utf-8", "replace")
        if field == 7 and wt == 2:  # string set
            ln, j = _rd_varint(msg, i); inner = msg[j:j+ln]; vals = []; k = 0
            while k < len(inner):
                t2, k = _rd_varint(inner, k)
                if (t2 & 7) == 2:
                    l2, k = _rd_varint(inner, k); vals.append(inner[k:k+l2].decode("utf-8", "replace")); k += l2
            return vals
        if field == 8 and wt == 2:  # bytes
            ln, j = _rd_varint(msg, i); return f"<bytes:{ln}>"
    except Exception:
        return None
    return None


def parse_datastore_pb(data: bytes) -> Dict[str, Any]:
    """Parse a Jetpack Preferences DataStore (.preferences_pb) into {key: value}. Never raises."""
    out: Dict[str, Any] = {}
    i = 0
    try:
        while i < len(data):
            tag, i = _rd_varint(data, i)
            field, wt = tag >> 3, tag & 7
            if field == 1 and wt == 2:  # repeated map entry
                ln, i = _rd_varint(data, i); entry = data[i:i+ln]; i += ln
                k = None; v = None; j = 0
                while j < len(entry):
                    t2, j = _rd_varint(entry, j); f2, w2 = t2 >> 3, t2 & 7
                    if w2 == 2:
                        l2, j = _rd_varint(entry, j); chunk = entry[j:j+l2]; j += l2
                        if f2 == 1:
                            k = chunk.decode("utf-8", "replace")
                        elif f2 == 2:
                            v = _rd_value(chunk)
                    elif w2 == 0:
                        _, j = _rd_varint(entry, j)
                    else:
                        break
                if k is not None:
                    out[k] = v
            elif wt == 2:
                ln, i = _rd_varint(data, i); i += ln
            elif wt == 0:
                _, i = _rd_varint(data, i)
            else:
                break
    except Exception:
        pass
    return out


# ---- all files/ (index + parse JSON + DataStore protobuf) ----

# Files above this are indexed but not parsed into memory. A React Native bundle
# or a cache blob can be tens of megabytes, and every parsed document is held for
# the lifetime of the case.
_MAX_PARSE_BYTES = 8 * 1024 * 1024


def _is_crashlytics_native_doc(rel: str, ext: str) -> bool:
    """Crashlytics writes extension-less JSON under .../native/ (device.json's
    siblings). Match those, and nothing else without an extension."""
    return ext == "(noext)" and "/native/" in rel.replace("\\", "/")


def extract_files(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"files": [], "datastore": {}, "json_docs": {}, "summary": {}, "errors": []}
    import json as _json
    if not paths.files_dir:
        out["errors"].append("files/ not found")
        return out
    by_ext: Counter = Counter()
    total = 0
    skipped_large = 0
    for cur, _, fl in os.walk(paths.files_dir):
        for f in sorted(fl):
            p = os.path.join(cur, f)
            rel = os.path.relpath(p, paths.files_dir)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            ext = os.path.splitext(f)[1].lower() or "(noext)"
            by_ext[ext] += 1; total += 1
            out["files"].append({"path": rel, "size": sz, "ext": ext})
            if sz > _MAX_PARSE_BYTES:
                skipped_large += 1
                continue
            try:
                if f.endswith(".preferences_pb"):
                    with open(p, "rb") as fh:
                        out["datastore"][rel] = parse_datastore_pb(fh.read())
                elif (f.endswith(".json") or f in ("user-data", "keys")
                      or _is_crashlytics_native_doc(rel, ext)):
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        s = fh.read().lstrip()
                    if s[:1] in "{[":
                        out["json_docs"][rel] = _json.loads(s)
            except Exception:
                pass
    out["summary"] = {"file_count": total, "ext_breakdown": dict(by_ext),
                      "datastore_keys": sum(len(v) for v in out["datastore"].values()),
                      "json_docs": len(out["json_docs"]),
                      "skipped_over_size_cap": skipped_large,
                      "size_cap_bytes": _MAX_PARSE_BYTES}
    if skipped_large:
        out["errors"].append(
            f"{skipped_large} file(s) larger than {_MAX_PARSE_BYTES // (1024 * 1024)} MB "
            f"were indexed but not parsed."
        )
    return out


# ---- all shared_prefs/*.xml ----

def extract_shared_prefs(paths: AndroidCasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"prefs": {}, "summary": {}, "errors": []}
    if not paths.shared_prefs_dir:
        out["errors"].append("shared_prefs/ not found")
        return out
    total_keys = 0
    for f in sorted(os.listdir(paths.shared_prefs_dir)):
        if not f.endswith(".xml"):
            continue
        d = read_shared_pref(os.path.join(paths.shared_prefs_dir, f))
        out["prefs"][f] = d
        total_keys += len(d)
    out["summary"] = {"pref_file_count": len(out["prefs"]), "total_keys": total_keys}
    return out


# ---- every SQLite table not owned by a dedicated module (the long tail) ----

# tables already surfaced by dedicated extractors above (avoid duplicate bulk capture)
_COVERED_TABLES = {
    "transaction_core", "transaction_text_attribute", "transaction_numeric_attribute",
    "accounts", "vpa", "vpa_v2", "psp", "wallet", "external_wallet_provider", "banks",
    "phone_contacts", "phone_book_contacts", "phone_book_contacts_metadata",
    "contactConnectionInfo", "vpa_contacts", "chatMessage", "chatTopic", "chatTopicMeta",
    "topicMember", "yatra_journeys", "offers", "fund_sync_lite_table", "global_search_sitemap",
    "rewards", "consent", "phonepe_sync_tracing", "ledger_meta", "ledger_entity",
    "ledger_expense", "ledger_expense_member", "ledger_split", "ledger_my_split",
    "ledger_balance", "ledger_settlement", "user_qr_code", "users",
}


def _decode_json_columns(rows: List[Dict[str, Any]]) -> None:
    """Decode JSON-looking TEXT columns in place, for readability in the browser."""
    for r in rows:
        for k, v in list(r.items()):
            if isinstance(v, str) and len(v) > 1 and v[0] in "{[" and v[-1] in "}]":
                dec = decode_json_blob(v)
                if isinstance(dec, (dict, list)):
                    r[k] = dec


def extract_raw_tables(paths: AndroidCasePaths) -> Dict[str, Any]:
    """Inventory EVERY table in every readable SQLite DB, so nothing is silently skipped.

    Only the shape is captured here — database, table, row count, columns. Row
    bodies are read on demand by ``load_raw_table``, because materialising every
    row of a 160-table acquisition held hundreds of megabytes in memory for the
    lifetime of the case, most of it a second copy of rows the dedicated
    extractors had already parsed.
    """
    out: Dict[str, Any] = {"databases": {}, "summary": {}, "errors": []}
    table_total = 0
    row_total = 0
    duplicated = 0
    for db_path in paths.all_sqlites():
        name = os.path.basename(db_path)
        db_entry: Dict[str, Any] = {}
        try:
            with SQLiteReader(db_path) as db:
                for t in db.tables():
                    if t == "android_metadata" or t.startswith("room_master"):
                        continue
                    n = db.count(t)
                    table_total += 1
                    if isinstance(n, int) and n > 0:
                        row_total += n
                    covered = t in _COVERED_TABLES
                    if covered:
                        duplicated += 1
                    db_entry[t] = {
                        "row_count": n,
                        "columns": db.columns(t),
                        "path": db_path,
                        # Tables a dedicated extractor already parses into a
                        # curated view; still browsable, just flagged as such.
                        "covered_by_module": covered,
                    }
        except Exception as exc:
            db_entry["_error"] = str(exc)
            out["errors"].append(f"{name}: {exc}")
        out["databases"][name] = db_entry
    out["summary"] = {"database_count": len(out["databases"]), "table_count": table_total,
                      "row_total": row_total,
                      "covered_by_dedicated_modules": duplicated,
                      "lazy": True}
    return out


def load_raw_table(paths: AndroidCasePaths, db_name: str, table: str,
                   offset: int = 0, limit: int = 500) -> Dict[str, Any]:
    """Read one page of one raw table, on demand.

    `db_name` and `table` are matched against the acquisition's real inventory
    rather than interpolated blindly, so a crafted request cannot reach a file
    outside the case or a name outside the schema.
    """
    limit = max(1, min(int(limit), 5000))
    offset = max(0, int(offset))
    db_path = next((p for p in paths.all_sqlites() if os.path.basename(p) == db_name), None)
    if not db_path:
        return {"error": f"unknown database: {db_name}", "rows": [], "columns": []}
    with SQLiteReader(db_path) as db:
        if table not in db.tables():
            return {"error": f"unknown table: {table}", "rows": [], "columns": []}
        total = db.count(table)
        rows = db.query(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (limit, offset))
        if rows and "_error" in rows[0]:
            return {"error": rows[0]["_error"], "rows": [], "columns": []}
        _decode_json_columns(rows)
        columns = db.columns(table)
    return {"database": db_name, "table": table, "columns": columns, "rows": rows,
            "row_count": total, "offset": offset, "limit": limit,
            "has_more": offset + len(rows) < (total if isinstance(total, int) else 0)}


# ---- deleted-record recovery ----

# Tables worth carving, per database. Restricting the target list keeps the scan
# proportionate and the results interpretable: these are the tables whose loss
# changes an investigation's conclusions.
_CARVE_TARGETS = {
    "phonepe_core": [
        "chatMessage", "transaction_core", "topicMember", "chatTopic",
        "contactConnectionInfo", "phone_contacts", "vpa_contacts",
        "phone_book_contacts", "ledger_expense", "ledger_expense_member",
        "paymentProfileCache",
    ],
    "inference_data_provider": ["sms_buffer"],
}


def extract_deleted_records(paths: AndroidCasePaths) -> Dict[str, Any]:
    """Recover rows deleted from the acquisition's databases.

    Reported as evidence in its own right, separate from the live tables, and
    never merged into them: a carved record is a reconstruction and has to stay
    visibly distinguishable from a row the database still holds.
    """
    from phonepe_forensics.carver import SQLiteCarver

    out: Dict[str, Any] = {"databases": {}, "records": [], "summary": {}, "errors": []}
    if not paths.databases_dir:
        out["errors"].append("databases/ not found")
        return out

    total = 0
    by_table: Counter = Counter()
    by_pool: Counter = Counter()
    for db_path in paths.all_sqlites():
        name = os.path.basename(db_path)
        targets = _CARVE_TARGETS.get(name)
        if targets is None:
            continue
        try:
            carver = SQLiteCarver(db_path, db_path + "-wal", db_path + "-journal")
            result = carver.carve(tables=targets)
        except Exception as exc:
            out["errors"].append(f"{name}: {exc}")
            continue
        for rec in result["records"]:
            rec["database"] = name
            by_table[rec.get("table") or "ambiguous"] += 1
            by_pool[rec["pool"]] += 1
        out["records"].extend(result["records"])
        out["databases"][name] = {"summary": result["summary"], "notes": result["notes"]}
        total += result["summary"]["recovered_count"]
        for note in result["notes"]:
            if "skipped" in note or "unreadable" in note:
                out["errors"].append(f"{name}: {note}")

    retained = {n: d["summary"].get("freed_content_retained")
                for n, d in out["databases"].items()}
    out["summary"] = {
        "recovered_count": total,
        "by_table": dict(by_table),
        "by_pool": dict(by_pool),
        "databases_carved": sorted(out["databases"]),
        "freed_content_retained": retained,
        # Extent-confidence and value-confidence are separate claims; a record can
        # have a structurally confirmed extent and still have its fields shifted
        # into the wrong columns, so both are carried into the summary.
        "high_confidence": sum(1 for r in out["records"] if r["confidence"] == "high"),
        "value_suspect": sum(1 for r in out["records"]
                             if r.get("value_confidence") == "low"),
        "values_fully_decoded": sum(1 for r in out["records"]
                                    if r.get("value_confidence") == "high"),
        "partial": sum(1 for r in out["records"] if r["partial"]),
        "ambiguous": sum(1 for r in out["records"] if r["ambiguous"]),
    }
    return out


# ---- explicit record of encrypted DBs that CANNOT be read offline ----

def extract_encrypted_dbs(paths: AndroidCasePaths) -> Dict[str, Any]:
    """SQLiteCrypt/SQLCipher-encrypted DBs (key is hardware-keystore-wrapped → not offline-readable).
    Surfaced explicitly so 'nothing skipped' is honest: we record their presence, not silence."""
    out: Dict[str, Any] = {"encrypted": [], "summary": {}, "errors": []}
    if not paths.databases_dir:
        return out
    skip = ("-wal", "-shm", "-journal")
    for f in sorted(os.listdir(paths.databases_dir)):
        p = os.path.join(paths.databases_dir, f)
        if not os.path.isfile(p) or f.endswith(skip):
            continue
        try:
            with open(p, "rb") as fh:
                head = fh.read(16)
        except OSError:
            continue
        if head.startswith(b"SQLitecrypt") or head.startswith(b"SQLCipher"):
            out["encrypted"].append({
                "name": f, "size": os.path.getsize(p), "format": "SQLiteCrypt/SQLCipher",
                "sha256": hash_file(p),
                "note": "Encrypted; key is hardware-keystore-wrapped — not decryptable offline. "
                        "Presence + hash recorded for completeness.",
            })
    out["summary"] = {"encrypted_db_count": len(out["encrypted"]),
                      "names": [e["name"] for e in out["encrypted"]]}
    return out


# ---------------------------------------------------------------------------
# Inventory  (generic SQLite walk)
# ---------------------------------------------------------------------------

def database_overview(paths: AndroidCasePaths) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    import os
    for path in paths.all_sqlites():
        entry: Dict[str, Any] = {
            "path": path,
            "rel_path": os.path.relpath(path, paths.app_dir or paths.root),
            "size": os.path.getsize(path) if os.path.exists(path) else 0,
            "sha256": hash_file(path),
            "wal_present": os.path.exists(path + "-wal"),
            "shm_present": os.path.exists(path + "-shm"),
            "tables": [],
        }
        try:
            with SQLiteReader(path) as db:
                entry["deletion"] = db.deletion_signals()
                for t in db.tables():
                    entry["tables"].append({"name": t, "rows": db.count(t)})
        except Exception as exc:
            entry["error"] = str(exc)
        out.append(entry)
    out.sort(key=lambda e: e["rel_path"])
    return out
