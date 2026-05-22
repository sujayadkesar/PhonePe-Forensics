"""Source reconciliation: TransactionsStore ⊎ Burble = single canonical Payment stream."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classify import (
    attribute_app,
    classify_transaction,
    decode_initiation,
    merchant_subtype,
    resolve_bank_name,
)
from .core import (
    case_db_path,
    first_or_dict,
    normalize_phone,
    normalize_timestamp_ms,
    ro_connect,
    safe_decode_blob,
    ts_ms_to_ist_str,
    ts_ms_to_utc_str,
)
from .data_layer import (
    DB_BURBLE,
    DB_TXNSTORE,
    load_avatars,
    load_bank_master,
    load_burble_messages,
    load_contacts,
    load_owner_identity,
    load_phonepe_psps,
    load_tpap_map,
)
from .provenance import build_envelope


PAYMENT_TYPES = (
    "SENT_PAYMENT",
    "RECEIVED_PAYMENT",
    "PHONE_RECHARGE",
    "EXTERNAL_PAYMENT",
    "SYMPHONY",
)
REQUEST_TYPES = (
    "USER_TO_USER_RECEIVED_REQUEST",
    "RECEIVED_MANDATE_CREATE_REQUEST",
    "SERVICE_MANDATE_CREATE",
    "P2P_ENRICHMENT",
)


@dataclass
class Payment:
    primary_id: str
    global_id: str | None
    data_source: str  # txnstore_full | burble_only
    entity_type: str | None  # ZTYPEVALUE
    state: str  # COMPLETED | FAILED | CREATED | PENDING | UNKNOWN
    is_failed_chat_only: bool
    failure_reason: str | None
    is_refund: bool
    direction: str  # SENT | RECEIVED | UNKNOWN
    amount_paise: int
    amount_inr: float
    timestamp_ms: int | None
    datetime_ist: str
    datetime_utc: str
    classification: str
    merchant_subtype: str | None
    counterparty_name: str
    counterparty_verified_name: str | None
    counterparty_cbs_name: str | None
    counterparty_phone: str | None
    counterparty_vpa: str | None
    counterparty_full_vpa: str | None
    receiver_vpa: str | None
    sender_vpa: str | None
    sender_app_label: str
    sender_app_source: str | None
    sender_app_icon_id: str | None
    receiver_app_label: str
    receiver_app_source: str | None
    receiver_app_icon_id: str | None
    sender_on_phonepe: bool
    receiver_on_phonepe: bool
    note: str
    utr: str | None
    bank_id: str | None
    ifsc: str | None
    bank_name: str
    mcc: str | None
    service_type: str | None
    merchant_id: str | None
    merchant_type: str | None
    merchant_genre: str | None
    merchant_identifier_type: str | None
    first_party_merchant: bool | None
    is_qr_scan: bool
    is_intent: bool
    intent_caller_url: str
    payment_initiation: str
    upi_initiation_mode: str
    transfer_mode: str
    decoded_blob: dict | None
    provenance: dict[str, Any] = field(default_factory=dict)
    # stable counterparty identifiers — used ONLY for cluster resolution,
    # never name-matching. Populated by the builders; cluster id assigned
    # later by resolve_counterparties().
    counterparty_user_id: str | None = None      # PhonePe global account id (U...)
    counterparty_connect_id: str | None = None   # Burble/Sampark contact id
    counterparty_cluster_id: str | None = None
    # device-phonebook saved name — the name the SUBJECT gave the contact
    # ("Akkaa", "Bharat @tcs"); distinct from bank-CBS and PhonePe-verified.
    counterparty_saved_name: str | None = None


@dataclass
class ReconcileResult:
    payments: list[Payment]
    mandates: list[dict]      # non-payment auxiliary rows (mandate-create / collect requests)
    txnstore_payment_count: int
    burble_payment_card_count: int
    overlap: int
    burble_only_count: int
    txnstore_only_count: int
    combined_unique_count: int


def reconcile(
    case_root: Path | str, *, case_id: str | None = None
) -> ReconcileResult:
    case_root = Path(case_root)
    txn_db = case_db_path(case_root, DB_TXNSTORE)
    burble_db = case_db_path(case_root, DB_BURBLE)

    bank_master = load_bank_master(str(case_root))
    phonepe_psps = load_phonepe_psps(str(case_root))
    tpap_key_map, tpap_info = load_tpap_map(str(case_root))
    contacts = load_contacts(str(case_root))
    owner = load_owner_identity(str(case_root))

    payments: dict[str, Payment] = {}  # keyed by primary_id
    id_to_primary: dict[str, str] = {}  # any-id -> primary_id (for matching Burble)
    mandates: list[dict] = []

    # -------- pass 1: TransactionsStore (rich source) --------
    # PhonePe stores multiple ZTRANSACTIONENTITY rows that describe the SAME
    # money movement, sharing a single ZGLOBALPAYMENTID. Examples:
    #   - SENT_PAYMENT + PHONE_RECHARGE  (Fastag/BBPS bill recharge)
    #   - SENT_PAYMENT + SYMPHONY        (in-app metro ticket)
    #   - SENT_PAYMENT + EXTERNAL_PAYMENT + USER_TO_USER_RECEIVED_REQUEST  (Saavn collect+pay)
    #   - RECEIVED_PAYMENT + P2P_ENRICHMENT  (split-bill metadata)
    # We pre-scan, group by ZGLOBALPAYMENTID, and pick a canonical row so the
    # same money is counted exactly once.
    # Priority: actual-money types beat metadata/receipt types.
    CANONICAL_PRIORITY = {
        "SENT_PAYMENT": 100,
        "RECEIVED_PAYMENT": 100,
        "PHONE_RECHARGE": 60,
        "SYMPHONY": 60,
        "EXTERNAL_PAYMENT": 50,
        "USER_TO_USER_RECEIVED_REQUEST": 30,
        "RECEIVED_MANDATE_CREATE_REQUEST": 30,
        "SERVICE_MANDATE_CREATE": 30,
        "P2P_ENRICHMENT": 10,
    }

    if txn_db:
        con = ro_connect(txn_db)
        all_rows = list(
            con.execute(
                "SELECT ZENTITYID, ZGLOBALPAYMENTID, ZTYPEVALUE, ZSTATEVALUE, "
                "ZCREATEDAT, ZUPDATEDAT, ZERRORCODE, ZDATA, Z_PK "
                "FROM ZTRANSACTIONENTITY"
            )
        )
        # Group by ZGLOBALPAYMENTID (treat NULL gpid as the row's own entity_id
        # so it stays a singleton).
        from collections import defaultdict
        groups: dict[str, list] = defaultdict(list)
        for row in all_rows:
            eid = row[0]
            gpid = row[1] or eid
            groups[gpid].append(row)

        dedup_dropped: list[dict] = []  # alias rows we collapsed
        for gpid, rows in groups.items():
            # Pick canonical (highest priority; ties broken by ZENTITYID)
            rows_sorted = sorted(
                rows,
                key=lambda r: (-CANONICAL_PRIORITY.get(r[2], 0), r[0] or ""),
            )
            canonical = rows_sorted[0]
            aliases = rows_sorted[1:]
            eid, gpid_c, ttype, state, created, updated, errcode, zdata, pk = canonical
            blob = safe_decode_blob(zdata)
            ts_ms = normalize_timestamp_ms(created, gpid_c)

            # Aliases — record them as collapsed-duplicates for forensic visibility,
            # but DON'T add them to payments OR to mandates (no double-count).
            for ar in aliases:
                a_eid, a_gpid, a_ttype, a_state, a_created, _, _, a_zdata, a_pk = ar
                dedup_dropped.append(
                    {
                        "alias_entity_id": a_eid,
                        "alias_type": a_ttype,
                        "alias_row_pk": a_pk,
                        "canonical_entity_id": eid,
                        "canonical_type": ttype,
                        "global_payment_id": gpid_c,
                        "reason": "shared ZGLOBALPAYMENTID — same money movement",
                    }
                )

            if ttype not in PAYMENT_TYPES:
                mandates.append(
                    _build_mandate_row(
                        case_id, eid, gpid_c, ttype, state, ts_ms, blob, pk, zdata
                    )
                )
                # still register id_to_primary so Burble matches can resolve
                id_to_primary[eid] = eid
                if gpid_c:
                    id_to_primary[gpid_c] = eid
                continue

            p = _build_payment_from_blob(
                primary_id=eid,
                global_id=gpid_c,
                entity_type=ttype,
                state_zsv=state,
                err_code=errcode,
                ts_ms=ts_ms,
                blob=blob,
                row_pk=pk,
                zdata=zdata,
                bank_master=bank_master,
                tpap_key_map=tpap_key_map,
                tpap_info=tpap_info,
                phonepe_psps=phonepe_psps,
                case_id=case_id,
            )
            # attach the dropped aliases so the provenance trail is preserved
            p.provenance["dedup_aliases"] = [
                {"entity_id": ar[0], "type": ar[2], "row_pk": ar[8]}
                for ar in aliases
            ]
            payments[eid] = p
            id_to_primary[eid] = eid
            if gpid_c:
                id_to_primary[gpid_c] = eid
            # Also map the alias entity_ids to this primary so Burble matches
            # resolve to the canonical row.
            for ar in aliases:
                if ar[0]:
                    id_to_primary[ar[0]] = eid
                if ar[1]:
                    id_to_primary[ar[1]] = eid
        con.close()

    # -------- pass 2: Burble payment cards --------
    # Only PAYMENT_INFO_CARD is a payment. TRANSACTION_RECEIPT, CONTACT,
    # REWARD_GIFT_CARD, IMAGE_ATTACHMENT, TEXT_MESSAGE etc. are chat content,
    # not money movements — they are shown in the conversation view but never
    # counted as transactions. (A TRANSACTION_RECEIPT can be e.g. a recharge
    # receipt; it carries no PAYMENT_INFO_CARD semantics.)
    burble_payment_ids: set[str] = set()
    if burble_db:
        msgs = load_burble_messages(str(case_root))
        for m in msgs:
            if m.content_type != "PAYMENT_INFO_CARD":
                continue
            cand_ids = [
                m.transaction_id,
                m.transaction_id_alt,
                m.sender_transaction_id,
                m.receiver_transaction_id,
            ]
            cand_ids = [c for c in cand_ids if c]
            if not cand_ids:
                continue
            primary = None
            for c in cand_ids:
                if c in id_to_primary:
                    primary = id_to_primary[c]
                    break
            if primary is None:
                # Burble-only payment — synthesize a lite payment
                primary = cand_ids[0]
                burble_payment_ids.add(primary)
                if primary in payments:
                    continue  # already added from a prior burble row
                payments[primary] = _build_payment_from_burble(
                    msg=m,
                    cand_ids=cand_ids,
                    bank_master=bank_master,
                    tpap_key_map=tpap_key_map,
                    tpap_info=tpap_info,
                    phonepe_psps=phonepe_psps,
                    case_id=case_id,
                    contacts=contacts,
                )
            else:
                # txnstore row already has the rich data — just record that Burble saw it
                burble_payment_ids.add(primary)

    overlap = len(burble_payment_ids & {p for p in payments if payments[p].data_source == "txnstore_full"})
    burble_only_count = len([p for p in payments.values() if p.data_source == "burble_only"])
    txnstore_only_count = len(
        [
            p
            for p in payments.values()
            if p.data_source == "txnstore_full" and p.primary_id not in burble_payment_ids
            and p.global_id not in burble_payment_ids
        ]
    )

    return ReconcileResult(
        payments=sorted(
            payments.values(),
            key=lambda x: x.timestamp_ms or 0,
            reverse=True,
        ),
        mandates=mandates,
        txnstore_payment_count=len(
            [p for p in payments.values() if p.data_source == "txnstore_full"]
        ),
        burble_payment_card_count=len(burble_payment_ids),
        overlap=overlap,
        burble_only_count=burble_only_count,
        txnstore_only_count=txnstore_only_count,
        combined_unique_count=len(payments),
    )


def _build_mandate_row(case_id, eid, gpid, ttype, state, ts_ms, blob, pk, zdata) -> dict:
    name = ""
    amount_paise = 0
    is_merchant_refund = False
    requester_type = None
    if isinstance(blob, dict):
        # SAAVN MANDATE shape: metaData.name; mandateAmount.amount
        meta = blob.get("metaData") or {}
        if isinstance(meta, dict):
            name = meta.get("name", "") or ""
        if not name:
            req = blob.get("requester") or {}
            if isinstance(req, dict):
                name = req.get("name", "") or ""
                requester_type = req.get("type")
        if not name:
            to_arr = blob.get("to")
            if isinstance(to_arr, list) and to_arr and isinstance(to_arr[0], dict):
                name = to_arr[0].get("name", "") or ""
            elif isinstance(to_arr, dict):
                name = to_arr.get("name", "") or ""
        fr = blob.get("from") if isinstance(blob.get("from"), dict) else {}
        if fr.get("type") == "MERCHANT":
            is_merchant_refund = True
            if not name:
                name = fr.get("name") or fr.get("cbsName") or ""
        ma = blob.get("mandateAmount") or {}
        if isinstance(ma, dict):
            amount_paise = ma.get("amount", 0) or 0
        if not amount_paise:
            amount_paise = blob.get("amount", 0) or 0
            if isinstance(amount_paise, dict):
                amount_paise = amount_paise.get("amount", 0) or 0
    return {
        "primary_id": eid,
        "global_id": gpid,
        "entity_type": ttype,
        "state": state,
        "timestamp_ms": ts_ms,
        "datetime_ist": ts_ms_to_ist_str(ts_ms),
        "name": name,
        "amount_paise": amount_paise,
        "amount_inr": (amount_paise or 0) / 100.0,
        "is_merchant_refund": is_merchant_refund,
        "requester_type": requester_type,
        "row_pk": pk,
        "decoded_blob": blob if isinstance(blob, (dict, list)) else None,
        "provenance": build_envelope(
            source_db="TransactionsStore.sqlite",
            source_table="ZTRANSACTIONENTITY",
            source_row_pk=pk,
            source_id_column="ZENTITYID",
            source_id_value=eid,
            source_blob=zdata,
            decode_path="ZDATA → bpylist2 → NSKeyedArchiver → dict",
            case_id=case_id,
        ),
    }


def _coalesce_state(zsv: str | None, blob: dict | None) -> str:
    """Pick a canonical payment_state from ZSTATEVALUE + decoded paymentState."""
    if zsv:
        if zsv == "ERRORED":
            return "FAILED"
        return zsv  # COMPLETED, etc.
    if isinstance(blob, dict):
        ps = blob.get("paymentState")
        if ps:
            return str(ps).upper()
    return "UNKNOWN"


def _build_payment_from_blob(
    *,
    primary_id,
    global_id,
    entity_type,
    state_zsv,
    err_code,
    ts_ms,
    blob,
    row_pk,
    zdata,
    bank_master,
    tpap_key_map,
    tpap_info,
    phonepe_psps,
    case_id,
) -> Payment:
    blob = blob if isinstance(blob, dict) else {}
    to = first_or_dict(blob.get("to"))
    fr = blob.get("from") if isinstance(blob.get("from"), dict) else {}
    received_in = first_or_dict(blob.get("receivedIn"))
    paid_from = first_or_dict(blob.get("paidFrom"))
    ctx = blob.get("context") or {}
    if not isinstance(ctx, dict):
        ctx = {}

    # direction
    has_paid_from = bool(paid_from)
    has_received_in = bool(received_in)
    has_from = bool(fr)
    has_to = bool(to)
    transfer_mode = ctx.get("transferMode", "")
    direction = "UNKNOWN"
    if "INCOMING" in str(transfer_mode).upper() or (has_from and has_received_in):
        direction = "RECEIVED"
    elif has_paid_from and has_to:
        direction = "SENT"
    elif has_from and has_to and not has_paid_from:
        direction = "RECEIVED"
    else:
        if entity_type == "RECEIVED_PAYMENT":
            direction = "RECEIVED"
        elif entity_type == "SENT_PAYMENT":
            direction = "SENT"
        # PHONE_RECHARGE / EXTERNAL_PAYMENT / SYMPHONY are service-receipt
        # records (Fastag/BBPS/metro). They have no counterparty VPA and
        # typically reference a separate T-prefix payment via
        # blob['paymentReference']. Leaving direction = UNKNOWN so they don't
        # pollute IN/OUT totals; the txn_kind field below tags them properly.
        elif entity_type in ("PHONE_RECHARGE", "EXTERNAL_PAYMENT", "SYMPHONY"):
            direction = "SERVICE"

    # amount
    amount_paise = 0
    if has_paid_from:
        amount_paise = paid_from.get("amount") or paid_from.get("actualAmount") or 0
    if not amount_paise and has_received_in:
        amount_paise = received_in.get("amount") or received_in.get("actualAmount") or 0
    if not amount_paise:
        amount_paise = blob.get("amount") or 0
    if isinstance(amount_paise, dict):
        amount_paise = amount_paise.get("amount", 0) or 0
    amount_paise = int(amount_paise or 0)

    # state + failure
    state = _coalesce_state(state_zsv, blob)
    failure_reason = None
    if state == "FAILED":
        failure_reason = blob.get("backendErrorCode") or err_code or None

    # refund
    is_refund = isinstance(fr, dict) and fr.get("type") == "MERCHANT"

    # counterparty fields
    if direction == "SENT":
        counterparty_vpa = to.get("vpa") or to.get("fullVpa") or ""
        counterparty_full_vpa = to.get("fullVpa") or to.get("vpa") or ""
        counterparty_name = to.get("name") or ""
        counterparty_phone = normalize_phone(to.get("phone")) or normalize_phone(
            to.get("upiNumber")
        )
        counterparty_user_id = to.get("userId") if isinstance(to, dict) else None
        receiver_vpa = counterparty_vpa
        sender_vpa = paid_from.get("vpa") or ""
    else:
        counterparty_vpa = fr.get("vpa") or ""
        counterparty_full_vpa = fr.get("vpa") or ""
        counterparty_name = fr.get("name") or fr.get("cbsName") or ""
        counterparty_phone = normalize_phone(fr.get("phone"))
        counterparty_user_id = fr.get("userId") if isinstance(fr, dict) else None
        receiver_vpa = received_in.get("vpa") or ""
        sender_vpa = counterparty_vpa

    # counterparty CBS name (the bank-side legal name of the counterparty, NOT the owner).
    # paid_from / received_in is the OWNER's leg — never the counterparty's.
    if direction == "RECEIVED":
        counterparty_cbs_name = fr.get("cbsName") if isinstance(fr, dict) else None
    elif direction == "SENT":
        counterparty_cbs_name = (
            (to.get("cbsName") if isinstance(to, dict) else None)
            or (to.get("accountHolderName") if isinstance(to, dict) else None)
        )
    else:
        counterparty_cbs_name = None

    # app attribution (authoritative -> bank-direct -> well-known inference -> unknown)
    sender_attr = attribute_app(sender_vpa, tpap_key_map, tpap_info, phonepe_psps, bank_master)
    receiver_attr = attribute_app(receiver_vpa, tpap_key_map, tpap_info, phonepe_psps, bank_master)

    # bank
    if direction == "SENT":
        bank_id = paid_from.get("bankId")
        ifsc = paid_from.get("ifsc")
    else:
        bank_id = received_in.get("bankId")
        ifsc = received_in.get("ifsc")
    bank_name = resolve_bank_name(bank_id, ifsc, bank_master)

    # merchant signals
    mcc = to.get("mcc") if isinstance(to, dict) else None
    merchant_id = to.get("merchantId")
    merchant_type = to.get("merchantType")
    merchant_genre = to.get("merchantGenreType")
    merchant_identifier_type = to.get("merchantIdentifierType")
    first_party = to.get("firstPartyMerchant") if isinstance(to, dict) else None
    service_type = (ctx.get("serviceContext") or {}).get("serviceType") if isinstance(ctx, dict) else None

    classification = classify_transaction(blob)
    subtype = (
        merchant_subtype(blob, phonepe_psps) if classification == "MERCHANT" else None
    )

    init = decode_initiation(blob)

    # note = the genuine user-typed message ONLY. context.tag ("MISC",
    # "miscellaneous") is PhonePe's auto-category, NOT a note — never use it
    # as the note. The decoded blob also carries note structures on some flows.
    note = ctx.get("message") or ""
    if not note:
        n = blob.get("note")
        if isinstance(n, str):
            note = n
        elif isinstance(n, dict):
            note = n.get("message") or n.get("text") or ""
    note = (note or "").strip()
    utr = paid_from.get("utr") or received_in.get("utr") or ""

    return Payment(
        primary_id=primary_id,
        global_id=global_id,
        data_source="txnstore_full",
        entity_type=entity_type,
        state=state,
        is_failed_chat_only=False,
        failure_reason=failure_reason,
        is_refund=is_refund,
        direction=direction,
        amount_paise=amount_paise,
        amount_inr=amount_paise / 100.0,
        timestamp_ms=ts_ms,
        datetime_ist=ts_ms_to_ist_str(ts_ms),
        datetime_utc=ts_ms_to_utc_str(ts_ms),
        classification=classification,
        merchant_subtype=subtype,
        counterparty_name=counterparty_name or "",
        counterparty_verified_name=None,  # join later
        counterparty_cbs_name=counterparty_cbs_name,
        counterparty_phone=counterparty_phone,
        counterparty_vpa=counterparty_vpa,
        counterparty_full_vpa=counterparty_full_vpa,
        receiver_vpa=receiver_vpa,
        sender_vpa=sender_vpa,
        sender_app_label=sender_attr["label"],
        sender_app_source=sender_attr["source"],
        sender_app_icon_id=sender_attr["icon_id"],
        receiver_app_label=receiver_attr["label"],
        receiver_app_source=receiver_attr["source"],
        receiver_app_icon_id=receiver_attr["icon_id"],
        sender_on_phonepe=(fr.get("type") == "INTERNAL_USER" if direction == "RECEIVED" else True),
        receiver_on_phonepe=receiver_attr["on_phonepe"],
        note=str(note) if note is not None else "",
        utr=utr or None,
        bank_id=bank_id,
        ifsc=ifsc,
        bank_name=bank_name,
        mcc=str(mcc) if mcc else None,
        service_type=service_type,
        merchant_id=merchant_id,
        merchant_type=merchant_type,
        merchant_genre=merchant_genre,
        merchant_identifier_type=merchant_identifier_type,
        first_party_merchant=bool(first_party) if first_party is not None else None,
        is_qr_scan=init["is_qr_scan"],
        is_intent=init["is_intent"],
        intent_caller_url=init["intent_caller_url"],
        payment_initiation=init["payment_initiation"],
        upi_initiation_mode=init["upi_initiation_mode"],
        transfer_mode=init["transfer_mode"],
        decoded_blob=blob,
        provenance=build_envelope(
            source_db="TransactionsStore.sqlite",
            source_table="ZTRANSACTIONENTITY",
            source_row_pk=row_pk,
            source_id_column="ZENTITYID",
            source_id_value=primary_id,
            source_blob=zdata,
            decode_path="ZDATA → bpylist2 → NSKeyedArchiver → dict",
            case_id=case_id,
        ),
        counterparty_user_id=counterparty_user_id,
    )


def _build_payment_from_burble(
    *,
    msg,
    cand_ids,
    bank_master,
    tpap_key_map,
    tpap_info,
    phonepe_psps,
    case_id,
    contacts,
) -> Payment:
    """Burble-only: amount + state + ts + counterparty hint.

    Direction is inferred from which transaction-id column carries data
    (same heuristic the upstream chat extractor uses):
        ZSENDERTRANSACTIONID set, ZRECEIVERTRANSACTIONID empty  -> owner SENT
        ZRECEIVERTRANSACTIONID set, ZSENDERTRANSACTIONID empty  -> owner RECEIVED
    """
    primary_id = cand_ids[0]
    amount_paise = msg.amount_paise or 0
    state = (msg.payment_state or "UNKNOWN").upper()
    is_chat_only_fail = state == "FAILED"
    # Try to enrich counterparty from external_vpa (when chat carries it)
    raw = msg.raw or {}
    ext_vpa = raw.get("external_vpa") or ""
    ext_name = raw.get("external_vpa_cbs_name") or ""
    counterparty_vpa = ext_vpa
    receiver_vpa = ""
    sender_vpa = ""
    sender_attr = attribute_app(sender_vpa, tpap_key_map, tpap_info, phonepe_psps, bank_master)
    receiver_attr = attribute_app(receiver_vpa, tpap_key_map, tpap_info, phonepe_psps, bank_master)
    # direction inference (chat-card uses sender_txn_id vs receiver_txn_id)
    has_sender = bool(msg.sender_transaction_id)
    has_receiver = bool(msg.receiver_transaction_id)
    if has_sender and not has_receiver:
        direction = "SENT"
    elif has_receiver and not has_sender:
        direction = "RECEIVED"
    else:
        direction = "UNKNOWN"
    return Payment(
        primary_id=primary_id,
        global_id=None,
        data_source="burble_only",
        entity_type=None,
        state=state,
        is_failed_chat_only=is_chat_only_fail,
        failure_reason=None,  # chat doesn't capture backendErrorCode
        is_refund=False,
        direction=direction,
        amount_paise=amount_paise,
        amount_inr=(amount_paise or 0) / 100.0,
        timestamp_ms=msg.created_at_ms,
        datetime_ist=ts_ms_to_ist_str(msg.created_at_ms),
        datetime_utc=ts_ms_to_utc_str(msg.created_at_ms),
        classification="UNKNOWN",
        merchant_subtype=None,
        counterparty_name=ext_name,
        counterparty_verified_name=None,
        counterparty_cbs_name=ext_name or None,
        counterparty_phone=None,
        counterparty_vpa=counterparty_vpa,
        counterparty_full_vpa=counterparty_vpa,
        receiver_vpa=receiver_vpa,
        sender_vpa=sender_vpa,
        sender_app_label=sender_attr["label"],
        sender_app_source=sender_attr["source"],
        sender_app_icon_id=sender_attr["icon_id"],
        receiver_app_label=receiver_attr["label"],
        receiver_app_source=receiver_attr["source"],
        receiver_app_icon_id=receiver_attr["icon_id"],
        sender_on_phonepe=False,
        receiver_on_phonepe=False,
        note=(msg.note or msg.text or "") or "",
        utr=raw.get("utr"),
        bank_id=None,
        ifsc=None,
        bank_name="",
        mcc=None,
        service_type=None,
        merchant_id=None,
        merchant_type=None,
        merchant_genre=None,
        merchant_identifier_type=None,
        first_party_merchant=None,
        is_qr_scan=False,
        is_intent=False,
        intent_caller_url="",
        payment_initiation="",
        upi_initiation_mode="",
        transfer_mode="",
        decoded_blob=None,
        provenance=build_envelope(
            source_db="Burble.sqlite",
            source_table="ZCONTENT",
            source_row_pk=msg.pk,
            source_id_column="ZTRANSACTIONID",
            source_id_value=primary_id,
            source_blob=None,
            decode_path="ZCONTENT row fields (chat-card; no NSKeyedArchiver blob)",
            case_id=case_id,
        ),
    )


def enrich_with_contacts(payments: list[Payment], contacts: dict) -> None:
    """In-place: fill counterparty_verified_name when we can match by phone."""
    for p in payments:
        if not p.counterparty_phone:
            continue
        c = contacts.get(p.counterparty_phone)
        if c and c.verified_name:
            p.counterparty_verified_name = c.verified_name


# ---------------------------------------------------------------------------
# Counterparty resolution — identifier-based union-find (NEVER name matching)
# ---------------------------------------------------------------------------

def _is_full_phone(phone: str | None) -> bool:
    """True only for an un-masked 10+ digit phone (no '*' characters)."""
    if not phone:
        return False
    s = str(phone)
    return "*" not in s and sum(c.isdigit() for c in s) >= 10


def _payment_identifiers(p: Payment) -> set[str]:
    """Strong, collision-free identifiers for one payment's counterparty.

    Deliberately excludes: counterparty name (display only) and masked phones
    (last-4 only — 4-digit suffix collides). A masked phone is used only as a
    weak secondary link inside resolve_counterparties when no strong id exists.
    """
    ids: set[str] = set()
    if p.counterparty_user_id:
        ids.add(f"uid:{p.counterparty_user_id}")
    if p.counterparty_connect_id:
        ids.add(f"cid:{p.counterparty_connect_id}")
    if _is_full_phone(p.counterparty_phone):
        ids.add(f"ph:{p.counterparty_phone}")
    vpa = (p.counterparty_vpa or p.counterparty_full_vpa or "").strip().lower()
    if vpa and "@" in vpa:
        ids.add(f"vpa:{vpa}")
    return ids


def resolve_counterparties(payments: list[Payment]) -> dict[str, dict]:
    """Union-find clustering of payments by shared counterparty identifiers.

    Mutates each Payment.counterparty_cluster_id in place. Returns
    {cluster_id: {display_name, identifiers, payment_count, kinds}}.

    Two payments are the same counterparty iff they share at least one strong
    identifier (userId / connectId / full phone / VPA). Payments with no strong
    identifier become their own singleton cluster keyed by primary_id (so they
    are NEVER merged into anyone else on a name guess).
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # 1. union every identifier of a payment together, and tie the payment
    #    node to its identifier set.
    for p in payments:
        ids = _payment_identifiers(p)
        pnode = f"pmt:{p.primary_id}"
        find(pnode)
        if not ids:
            continue
        id_list = sorted(ids)
        union(pnode, id_list[0])
        for other in id_list[1:]:
            union(id_list[0], other)

    # 2. weak secondary link: masked-phone last-4 suffix — only used to attach
    #    a payment that has NO strong identifier to a cluster that already
    #    owns the matching full phone. Never merges two strong clusters.
    full_suffix_to_root: dict[str, str] = {}
    for p in payments:
        if _is_full_phone(p.counterparty_phone):
            suffix = str(p.counterparty_phone)[-4:]
            full_suffix_to_root.setdefault(suffix, find(f"pmt:{p.primary_id}"))
    for p in payments:
        if _payment_identifiers(p):
            continue  # already has a strong id
        ph = str(p.counterparty_phone or "")
        if "*" in ph and len(ph) >= 4:
            suffix = ph[-4:]
            if suffix in full_suffix_to_root:
                union(full_suffix_to_root[suffix], f"pmt:{p.primary_id}")

    # 3. assign cluster ids + pick display name per cluster
    clusters: dict[str, dict] = {}
    for p in payments:
        root = find(f"pmt:{p.primary_id}")
        p.counterparty_cluster_id = root
        cl = clusters.setdefault(
            root,
            {
                "cluster_id": root,
                "display_name": "",
                "identifiers": set(),
                "payment_count": 0,
                "kinds": set(),
                # the four name variants — kept distinct, NEVER used to merge
                "names_verified": set(),  # PhonePe central verified name
                "names_cbs": set(),       # bank Core-Banking-System name
                "names_display": set(),   # PhonePe display / chat name
                "names_saved": set(),     # device-phonebook saved name (subject's own label)
                "masked_phones": set(),   # ******XXXX — chat retained only last 4
                "_name_candidates": [],
            },
        )
        cl["payment_count"] += 1
        cl["identifiers"].update(_payment_identifiers(p))
        cl["kinds"].add(p.classification)
        # masked phone — a real forensic artifact even though it is not a
        # strong (mergeable) identifier; surfaced on the counterparty page.
        _ph = str(p.counterparty_phone or "")
        if "*" in _ph:
            cl["masked_phones"].add(_ph)
        # collect every name variant separately
        for bucket, nm in (
            ("names_verified", p.counterparty_verified_name),
            ("names_cbs", p.counterparty_cbs_name),
            ("names_display", p.counterparty_name),
            ("names_saved", p.counterparty_saved_name),
        ):
            if nm and nm.strip():
                cl[bucket].add(" ".join(nm.split()))
        # canonical display_name = the LEGAL name (bank/verified) first, so a
        # forensic report leads with what's on bank records. The device-saved
        # name ("Akkaa") is surfaced separately as relationship context.
        for src, nm in (
            ("verified", p.counterparty_verified_name),
            ("cbs", p.counterparty_cbs_name),
            ("display", p.counterparty_name),
        ):
            if nm and nm.strip():
                cl["_name_candidates"].append((src, " ".join(nm.split())))

    _RANK = {"verified": 3, "cbs": 2, "display": 1}
    for cl in clusters.values():
        if cl["_name_candidates"]:
            best = sorted(
                cl["_name_candidates"],
                key=lambda t: (_RANK.get(t[0], 0), len(t[1])),
                reverse=True,
            )[0]
            cl["display_name"] = best[1]
        else:
            cl["display_name"] = "(unknown)"
        cl["identifiers"] = sorted(cl["identifiers"])
        cl["kinds"] = sorted(cl["kinds"])
        for b in ("names_verified", "names_cbs", "names_display",
                  "names_saved", "masked_phones"):
            cl[b] = sorted(cl[b])
        cl.pop("_name_candidates", None)
    return clusters
