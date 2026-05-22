"""Glue layer: enriches a Case (upstream) with v2 outputs.

Hooked into Case.run_full_extraction() once the upstream extractors have run.
Mutates `case.data` to add:

    case.data["_v2"] = {
        "coverage": {...},                  # 285 = 115 + 170, overlap=91, ...
        "retention_days": 450,
        "owner_vpas": [...],
        "phonepe_psps": [...],
        "tpap_map_size": 31,
        "tpap_app_size": 16,
        "source_db_hashes": {...},          # SHA-256 chain-of-custody
        "burble_only_payments": [...],      # 170 chat-card recoveries
        "mandates": [...],                  # autopay + collect + enrichment
        "by_app": {...},
        "by_initiation": {...},
        "failures": [...],
        "refunds": [...],
        "tpap_info": {...},                 # app_key -> {title, icon_id, handles}
    }

The existing `transactions["transactions"]` list is *augmented* in place with
the Burble-only records, and each entry gets v2-derived fields:

    classification          (MERCHANT / MERCHANT_REFUND / PEER_TO_PEER / MANDATE / OTHER)
    merchant_subtype        (MERCHANT_ON_PHONEPE / MERCHANT_THIRD_PARTY / None)
    payment_initiation      (DEFAULT / QR_GALLERY / SECURE_QR / INTENT / ...)
    is_qr_scan, is_intent, intent_caller_url
    sender_app, receiver_app   (DB-evidence only; "Unknown TPAP" otherwise)
    sender_on_phonepe, receiver_on_phonepe
    is_refund, is_failed_chat_only
    data_source             (txnstore_full | burble_only)

Existing fields are preserved; only adds.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .v2.data_layer import (
    collect_source_db_hashes,
    load_avatars,
    load_burble_conversations,
    load_burble_messages,
    load_contacts,
    load_owner_identity,
    load_phonepe_psps,
    load_tpap_map,
)
from .v2.reconcile import enrich_with_contacts, reconcile


_DIR_TO_LEGACY = {"SENT": "OUT", "RECEIVED": "IN", "UNKNOWN": "UNKNOWN"}


def _payment_to_legacy_txn(p) -> Dict[str, Any]:
    """Render a v2 Payment into the legacy `transactions[].transactions` row
    shape used by the upstream Flask templates so it shows up in /transactions."""
    return {
        # legacy-compatible fields (upstream uses IN/OUT, not RECEIVED/SENT)
        "global_payment_id": p.primary_id,
        "entity_id": p.primary_id,
        "type": p.entity_type or "PAYMENT",
        "state": p.state,
        "direction": _DIR_TO_LEGACY.get(p.direction, p.direction),
        "direction_v2": p.direction,
        "amount_inr": p.amount_inr,
        "category_code": p.mcc,
        "counterparty": p.counterparty_verified_name or p.counterparty_name,
        "counterparty_phone": p.counterparty_phone,
        "counterparty_vpa": p.counterparty_vpa,
        "counterparty_cbs_name": p.counterparty_cbs_name,
        "merchant_name": p.counterparty_name if p.classification == "MERCHANT" else None,
        "biller_name": None,
        "recharge_number": None,
        "note": p.note,
        "received_in_type": None,
        "group_id": None,
        "group_template": None,
        "id_embedded_ts": None,
        "search_token": None,
        # v2 enrichments — read by enhanced dashboard tiles
        "classification": p.classification,
        "merchant_subtype": p.merchant_subtype,
        "payment_initiation": p.payment_initiation,
        "is_qr_scan": p.is_qr_scan,
        "is_intent": p.is_intent,
        "intent_caller_url": p.intent_caller_url,
        "transfer_mode": p.transfer_mode,
        "sender_app": p.sender_app_label,
        "sender_app_icon": p.sender_app_icon_id,
        "receiver_app": p.receiver_app_label,
        "receiver_app_icon": p.receiver_app_icon_id,
        "sender_on_phonepe": p.sender_on_phonepe,
        "receiver_on_phonepe": p.receiver_on_phonepe,
        "is_refund": p.is_refund,
        "is_failed_chat_only": p.is_failed_chat_only,
        "data_source": p.data_source,
        "failure_reason": p.failure_reason,
        "bank_id": p.bank_id,
        "bank_name": p.bank_name,
        "ifsc": p.ifsc,
        "service_type": p.service_type,
        "utr": p.utr,
        "created_at": {
            "epoch_ms": p.timestamp_ms,
            "iso": p.datetime_ist,
            "display": p.datetime_ist,
            "source": "v2",
        }
        if p.timestamp_ms
        else None,
        # provenance (kept hidden; surfaced via /raw modal)
        "_v2_provenance": p.provenance,
    }


def enrich_case(case) -> None:
    """Run the v2 reconciliation against the same case_root and merge results
    into `case.data`. Idempotent: safe to call multiple times."""
    from pathlib import Path

    case_root = Path(case.root)
    case_id = (
        getattr(case, "case_id", None)
        or case_root.parent.name
        or "case"
    )

    # heavy lifting
    result = reconcile(case_root, case_id=case_id)
    contacts = load_contacts(str(case_root))
    enrich_with_contacts(result.payments, contacts)

    owner = load_owner_identity(str(case_root))
    phonepe_psps = load_phonepe_psps(str(case_root))
    tpap_key_map, tpap_info = load_tpap_map(str(case_root))
    source_hashes = collect_source_db_hashes(str(case_root))

    # ---- patch Burble-only payments using upstream chat extractor + Sampark.
    # Chain:
    #   ZCONTENT.ZTRANSACTIONID --> chat_msg.direction (via is_self)
    #                          \-> chat_msg.other_party_name (from ZGROUPMEMBER.ZPHONEPENAME)
    #                          \-> chat_msg.other_party_phone (MASKED ******XXXX in chat)
    #
    # To resolve the FULL phone, we use the connect-id chain:
    #   ZMESSAGE.ZGROUPMEMBERSOURCE/DESTINATION -> ZGROUPMEMBER -> ZGROUPMEMBERINFO.ZCONNECTID
    #   -> SamparkV2.ZCYCLOPSCONTACT.ZCONNECTID -> ZPHONENUMBER (full E.164)
    #
    # load_burble_conversations() already runs this join and stashes the
    # resolved phones on Conversation.member_phones. We then key by group_id.
    from .v2.data_layer import load_burble_conversations, load_contacts as _lc
    v2_convs = load_burble_conversations(str(case_root))
    gid_to_member_phones: Dict[str, List[str]] = {
        c.group_id: list(c.member_phones) for c in v2_convs
    }
    # group_id -> resolved counterparty identity (connectid + phone + names),
    # built from all 3 Sampark contact tables via the connectid chain.
    gid_to_other_party: Dict[str, Any] = {c.group_id: c for c in v2_convs}

    # Build chat-msg-id -> (direction, name, masked_phone, group_id) lookup.
    chat_msgs = (case.data.get("chat") or {}).get("messages") or []
    txn_id_to_chat: Dict[str, Dict[str, Any]] = {}
    for cm in chat_msgs:
        d = (cm.get("direction") or "").upper()
        v2_dir = "RECEIVED" if d == "IN" else ("SENT" if d == "OUT" else None)
        # The upstream extractor doesn't expose group_id per message in its
        # public structure, but transaction_id ties messages to ZCONTENT rows
        # which v2 load_burble_messages joined to ZGROUP. Use that mapping.
        for k in ("transaction_id", "receiver_txn_id", "sender_txn_id"):
            tid = cm.get(k)
            if tid:
                txn_id_to_chat.setdefault(
                    tid,
                    {
                        "direction": v2_dir,
                        "other_party_name": cm.get("other_party_name"),
                        "other_party_phone_masked": cm.get("other_party_phone"),
                        "note": cm.get("note") or cm.get("text_message"),
                    },
                )

    # txn_id -> group_id (from v2's Burble messages loader, which uses the
    # fixed ZCONTENT.Z_PK <- ZMESSAGE.ZCONTENT, ZMESSAGE.Z_PK <- ZPBCOREMESSAGE.ZPAYLOAD chain)
    from .v2.data_layer import load_burble_messages as _lbm
    burble_msgs = _lbm(str(case_root))
    txn_to_group: Dict[str, str] = {}
    for bm in burble_msgs:
        gid = bm.group_id
        if not gid:
            continue
        for tid in (bm.transaction_id, bm.transaction_id_alt,
                    bm.sender_transaction_id, bm.receiver_transaction_id):
            if tid:
                txn_to_group.setdefault(tid, gid)

    # SamparkV2 contacts: phone -> {verified_name, cbs_name}.
    sampark_contacts = _lc(str(case_root))
    # Also build phone-suffix -> cbsname history from rich TxnStore rows
    suffix_to_cbs: Dict[str, str] = {}
    for p in result.payments:
        if p.data_source == "txnstore_full" and p.counterparty_phone and p.counterparty_cbs_name:
            suffix_to_cbs.setdefault(p.counterparty_phone[-4:], p.counterparty_cbs_name)

    # Owner's E.164 phone — we exclude it from member_phones to find the
    # counterparty in a 1:1 chat. Derived from the registered identity.
    ident = case.data.get("identity") or {}
    owner_phones: set[str] = set()
    for ph in (ident.get("phones_seen") or []):
        digits = "".join(c for c in str(ph) if c.isdigit())
        if digits:
            owner_phones.add(digits[-10:])

    direction_patched = name_patched = phone_patched = full_phone_patched = 0
    cbs_patched = verified_patched = display_patched = masked_patched = 0
    for p in result.payments:
        chat_entry = None
        for candidate in (p.primary_id, p.global_id):
            if candidate and candidate in txn_id_to_chat:
                chat_entry = txn_id_to_chat[candidate]
                break
        # chat_entry is OPTIONAL. A Burble TRANSACTION_RECEIPT (and any payment
        # the upstream chat extractor never surfaced) has no chat_entry — but
        # its ZGROUP still resolves the counterparty. So we NEVER skip here;
        # the group-based resolution below runs for every payment.
        if chat_entry:
            # direction
            if p.direction not in ("RECEIVED", "SENT") and chat_entry["direction"]:
                p.direction = chat_entry["direction"]
                direction_patched += 1
            # counterparty name (from upstream chat via ZPHONEPENAME)
            if not (p.counterparty_name and p.counterparty_name.strip()) and chat_entry["other_party_name"]:
                p.counterparty_name = chat_entry["other_party_name"]
                name_patched += 1
        # resolve the chat group's counterparty identity (connectid chain across
        # all 3 Sampark tables) — gives connectid + full phone + verified/CBS
        # name + the PhonePe display name & masked phone from ZGROUPMEMBER.
        gid = txn_to_group.get(p.primary_id) or txn_to_group.get(p.global_id)
        conv = gid_to_other_party.get(gid) if gid else None
        if conv:
            if not p.counterparty_connect_id and conv.other_party_connect_id:
                p.counterparty_connect_id = conv.other_party_connect_id
            if not p.counterparty_verified_name and conv.other_party_verified_name:
                p.counterparty_verified_name = conv.other_party_verified_name
                verified_patched += 1
            if not p.counterparty_cbs_name and conv.other_party_cbs_name:
                p.counterparty_cbs_name = conv.other_party_cbs_name
                cbs_patched += 1
            # PhonePe display name (the counterparty's own chat-card name) —
            # often the ONLY name when the counterparty has no SamparkV2 row.
            if not (p.counterparty_name and p.counterparty_name.strip()) and conv.other_party_display_name:
                p.counterparty_name = conv.other_party_display_name
                display_patched += 1
        # phone — prefer full E.164 (connectid-resolved) over any masked form
        if not p.counterparty_phone:
            full_phone = None
            if conv and conv.other_party_phone:
                full_phone = conv.other_party_phone
            elif gid:
                candidates = [
                    ph for ph in gid_to_member_phones.get(gid, [])
                    if ph and ph not in owner_phones
                ]
                if candidates:
                    full_phone = candidates[0]
            if full_phone:
                p.counterparty_phone = full_phone
                full_phone_patched += 1
            elif conv and conv.other_party_masked_phone:
                # ZGROUPMEMBER profileSnapshot masked form (******XXXX) — the
                # acquisition never retained the full number for this contact.
                p.counterparty_phone = str(conv.other_party_masked_phone)
                masked_patched += 1
            elif chat_entry and chat_entry["other_party_phone_masked"]:
                # last resort — upstream chat's masked ******XXXX form
                p.counterparty_phone = str(chat_entry["other_party_phone_masked"])
                phone_patched += 1
        # If we now have a full phone, hit SamparkV2 for verified-name + CBS-name
        if p.counterparty_phone and "*" not in p.counterparty_phone:
            sc = sampark_contacts.get(p.counterparty_phone)
            if sc:
                if not p.counterparty_verified_name and sc.verified_name:
                    p.counterparty_verified_name = sc.verified_name
                    verified_patched += 1
                if not p.counterparty_cbs_name and sc.cbs_name:
                    p.counterparty_cbs_name = sc.cbs_name
                    cbs_patched += 1
            # Also try 4-digit-suffix history map for cbsname
            if not p.counterparty_cbs_name:
                suffix = p.counterparty_phone[-4:]
                if suffix in suffix_to_cbs:
                    p.counterparty_cbs_name = suffix_to_cbs[suffix]
                    cbs_patched += 1
        # note
        if chat_entry and not (p.note and p.note.strip()) and chat_entry["note"]:
            p.note = str(chat_entry["note"]).strip()

    # ---- patch device-phonebook saved name (the subject's own label for the
    # ---- contact — "Akkaa", "Bharat @tcs") keyed by counterparty phone.
    from .v2.data_layer import load_phonebook_names
    phonebook_names = load_phonebook_names(str(case_root))
    saved_name_patched = 0
    for p in result.payments:
        if p.counterparty_saved_name:
            continue
        ph = p.counterparty_phone
        if ph and "*" not in str(ph):
            nm = phonebook_names.get(str(ph))
            if nm:
                p.counterparty_saved_name = nm
                saved_name_patched += 1
    case.data.setdefault("_v2_meta", {})["saved_name_patched"] = saved_name_patched

    # ---- resolve counterparty clusters by stable identifiers ----
    # Runs AFTER all phone/name/userid enrichment so the union-find sees the
    # fullest identifier set. Mutates Payment.counterparty_cluster_id.
    from .v2.reconcile import resolve_counterparties
    clusters = resolve_counterparties(result.payments)

    case.data.setdefault("_v2_meta", {}).update(
        {
            "burble_direction_patched": direction_patched,
            "burble_name_patched": name_patched,
            "burble_display_name_patched": display_patched,
            "burble_full_phone_patched": full_phone_patched,
            "burble_masked_phone_only": phone_patched + masked_patched,
            "burble_cbs_patched": cbs_patched,
            "burble_verified_name_patched": verified_patched,
            "suffix_to_cbs_history_size": len(suffix_to_cbs),
            "counterparty_clusters": len(clusters),
        }
    )

    # ---- enrich /contacts rows with per-contact txn IN/OUT activity ----
    # Build phone -> {cluster_id, recv/sent counts + amounts} from the payment
    # stream, then stamp it onto every cyclops + phonebook contact so the
    # contacts page can show transaction activity and link to the cluster.
    phone_activity: Dict[str, Dict[str, Any]] = {}
    for p in result.payments:
        ph = p.counterparty_phone
        if not ph or "*" in str(ph):
            continue
        # contact activity counts/amounts = COMPLETED payments only
        if p.state != "COMPLETED":
            continue
        a = phone_activity.setdefault(
            str(ph),
            {
                "cluster_id": p.counterparty_cluster_id,
                "txn_in": 0, "txn_out": 0,
                "recv_inr": 0.0, "sent_inr": 0.0,
            },
        )
        if p.direction == "RECEIVED":
            a["txn_in"] += 1
            a["recv_inr"] += p.amount_inr
        elif p.direction == "SENT":
            a["txn_out"] += 1
            a["sent_inr"] += p.amount_inr

    contacts_block = case.data.get("contacts") or {}
    enriched_contacts = 0
    for bucket in ("cyclops_contacts", "phonebook_contacts"):
        for ct in contacts_block.get(bucket, []) or []:
            ph = ct.get("phone") or ct.get("normalized") or ct.get("raw_number")
            norm = "".join(c for c in str(ph or "") if c.isdigit())[-10:]
            act = phone_activity.get(norm)
            if act:
                ct["v2_txn_in"] = act["txn_in"]
                ct["v2_txn_out"] = act["txn_out"]
                ct["v2_recv_inr"] = round(act["recv_inr"], 2)
                ct["v2_sent_inr"] = round(act["sent_inr"], 2)
                ct["v2_cluster_id"] = act["cluster_id"]
                ct["v2_has_txns"] = (act["txn_in"] + act["txn_out"]) > 0
                enriched_contacts += 1
            else:
                ct["v2_txn_in"] = 0
                ct["v2_txn_out"] = 0
                ct["v2_has_txns"] = False
    case.data["_v2_meta"]["contacts_with_txns"] = enriched_contacts

    # ---- augment the existing /transactions list ----
    txn_block = case.data.setdefault("transactions", {})
    legacy_txns: List[Dict[str, Any]] = txn_block.get("transactions") or []
    # index existing txns by ID for in-place upgrade
    existing_by_id = {
        (t.get("entity_id") or t.get("global_payment_id")): t for t in legacy_txns
    }
    enriched: List[Dict[str, Any]] = []
    for p in result.payments:
        new_row = _payment_to_legacy_txn(p)
        # if the upstream already has this row, merge so we keep their fields
        # and overlay our v2 ones (v2 wins on conflicts where our value is non-null).
        existing = existing_by_id.get(p.primary_id)
        if existing:
            for k, v in new_row.items():
                if v is not None and v != "":
                    existing[k] = v
            enriched.append(existing)
        else:
            enriched.append(new_row)
    txn_block["transactions"] = enriched

    # ---- enrich existing chat messages with v2 routing data ----
    # Build a txn_id -> v2.Payment lookup once.
    payments_by_id: Dict[str, Any] = {}
    for p in result.payments:
        if p.primary_id:
            payments_by_id[p.primary_id] = p
        if p.global_id:
            payments_by_id[p.global_id] = p
    chat_block = case.data.setdefault("chat", {})
    messages = chat_block.get("messages") or []
    for msg in messages:
        tid = (
            msg.get("transaction_id")
            or msg.get("receiver_txn_id")
            or msg.get("sender_txn_id")
        )
        if not tid:
            continue
        p = payments_by_id.get(tid)
        if not p:
            continue
        is_self_out = msg.get("direction") == "OUT"
        if is_self_out:
            owner_vpa = p.sender_vpa
            owner_app = p.sender_app_label
            owner_app_icon = p.sender_app_icon_id
            owner_on_phonepe = p.sender_vpa and (p.sender_vpa.split("@")[-1].lower() in phonepe_psps)
            counterparty_vpa = p.receiver_vpa
            counterparty_app = p.receiver_app_label
            counterparty_app_icon = p.receiver_app_icon_id
        else:
            owner_vpa = p.receiver_vpa
            owner_app = p.receiver_app_label
            owner_app_icon = p.receiver_app_icon_id
            owner_on_phonepe = p.receiver_on_phonepe
            counterparty_vpa = p.sender_vpa
            counterparty_app = p.sender_app_label
            counterparty_app_icon = p.sender_app_icon_id
        msg["v2"] = {
            "data_source": p.data_source,
            "classification": p.classification,
            "merchant_subtype": p.merchant_subtype,
            "payment_initiation": p.payment_initiation,
            "is_qr_scan": p.is_qr_scan,
            "is_intent": p.is_intent,
            "intent_caller_url": p.intent_caller_url,
            "is_refund": p.is_refund,
            "is_failed_chat_only": p.is_failed_chat_only,
            "owner_vpa": owner_vpa,
            "owner_app": owner_app,
            "owner_app_icon": owner_app_icon,
            "owner_on_phonepe": owner_on_phonepe,
            "owner_psp": (owner_vpa.split("@")[-1].lower() if owner_vpa and "@" in owner_vpa else None),
            "counterparty_vpa": counterparty_vpa,
            "counterparty_app": counterparty_app,
            "counterparty_app_icon": counterparty_app_icon,
            "counterparty_psp": (counterparty_vpa.split("@")[-1].lower() if counterparty_vpa and "@" in counterparty_vpa else None),
            "counterparty_phone": p.counterparty_phone,
            "counterparty_verified_name": p.counterparty_verified_name,
            "counterparty_cbs_name": p.counterparty_cbs_name,
            "state": p.state,
            "failure_reason": p.failure_reason,
            "bank_name": p.bank_name,
            "bank_id": p.bank_id,
        }

    # ---- enrich each Burble GROUP + its members with the FULL counterparty
    # ---- phone. The upstream chat extractor only carries the masked
    # ---- ******XXXX form (ZGROUPMEMBER.ZMATTRIBUTES); the real number is
    # ---- recovered two ways and shown in the conversation UI instead:
    # ----   1. connectid -> SamparkV2 contact tables (load_burble_conversations)
    # ----   2. the group's own payment cards -> Payment.counterparty_phone
    # ----      (decoded from the TransactionsStore transaction blob)
    groups = chat_block.get("groups") or []
    members = chat_block.get("members") or []
    v2_convs = load_burble_conversations(str(case_root))

    group_cp_phone: Dict[str, str] = {}
    # source 1 — connectid chain (contacts that have a SamparkV2 record)
    for c in v2_convs:
        ph = c.other_party_phone
        if ph and "*" not in str(ph):
            group_cp_phone[c.group_id] = str(ph)
    # source 2 — payment stream (groups whose connectid had no SamparkV2
    # phone, but a payment card in the chat carries the full number)
    for p in result.payments:
        gid = txn_to_group.get(p.primary_id) or txn_to_group.get(p.global_id)
        if not gid or gid in group_cp_phone:
            continue
        ph = p.counterparty_phone
        if ph and "*" not in str(ph):
            group_cp_phone[gid] = str(ph)

    # a "masked label" is a name PhonePe never had a real value for — it is
    # literally the masked phone (e.g. "******NNNN"). Once the full number is
    # recovered it is a better display label than the stars.
    def _is_masked_label(s):
        s = (s or "").strip()
        return bool(s) and "*" in s and s.replace("*", "").isdigit()

    # counterparty masked phone + display name from the connectid resolver —
    # the last-resort label for a group PhonePe never named.
    conv_masked = {c.group_id: c.other_party_masked_phone for c in v2_convs}
    conv_disp = {c.group_id: c.other_party_display_name for c in v2_convs}
    conv_by_gid = {c.group_id: c for c in v2_convs}

    # link each chat group to its counterparty's identifier cluster so the
    # chat page can show the same identity panel as /v2/counterparty.
    ident_to_cluster: Dict[str, str] = {}
    for _ccid, _ccl in clusters.items():
        for _ident in _ccl.get("identifiers", []):
            ident_to_cluster.setdefault(_ident, _ccid)
    group_to_cluster: Dict[str, str] = {}
    for p in result.payments:
        gid = txn_to_group.get(p.primary_id) or txn_to_group.get(p.global_id)
        if gid and gid not in group_to_cluster and p.counterparty_cluster_id:
            group_to_cluster[gid] = p.counterparty_cluster_id
    for c in v2_convs:
        if c.group_id in group_to_cluster:
            continue
        for _key in (
            f"cid:{c.other_party_connect_id}" if c.other_party_connect_id else None,
            f"ph:{group_cp_phone.get(c.group_id)}" if group_cp_phone.get(c.group_id) else None,
        ):
            if _key and _key in ident_to_cluster:
                group_to_cluster[c.group_id] = ident_to_cluster[_key]
                break

    def _decompose_idents(idents):
        ph, vp, ui, ci = [], [], [], []
        for ident in idents:
            if ident.startswith("ph:"):
                ph.append(ident[3:])
            elif ident.startswith("vpa:"):
                vp.append(ident[4:])
            elif ident.startswith("uid:"):
                ui.append(ident[4:])
            elif ident.startswith("cid:"):
                ci.append(ident[4:])
        return ph, vp, ui, ci

    for g in groups:
        gid = g.get("group_id")
        full = group_cp_phone.get(gid or "")
        if full:
            g["v2_other_party_phone"] = full
        cl_id = group_to_cluster.get(gid)
        if cl_id:
            g["v2_cluster_id"] = cl_id
        cl = clusters.get(cl_id) if cl_id else None
        conv = conv_by_gid.get(gid)
        saved = phonebook_names.get(full) if full else None
        # best display label, most-trustworthy first — never the string "None".
        # A real human name (group name / bank-verified / phonebook-saved)
        # always beats a bare phone number.
        name = g.get("name")
        cluster_name = cl.get("display_name") if cl else None
        if name and not _is_masked_label(name):
            g["v2_display_name"] = name               # PhonePe's own group name
        elif cluster_name and cluster_name != "(unknown)":
            g["v2_display_name"] = cluster_name       # bank/verified/CBS name
        elif saved:
            g["v2_display_name"] = saved              # device phonebook label
        elif full:
            g["v2_display_name"] = full               # recovered full number
        elif name:
            g["v2_display_name"] = name               # masked name ******XXXX
        elif conv_disp.get(gid):
            g["v2_display_name"] = conv_disp[gid]
        elif conv_masked.get(gid):
            g["v2_display_name"] = conv_masked[gid]   # masked phone ******NNNN
        else:
            g["v2_display_name"] = None

        # full counterparty identity panel for the chat page — built from the
        # payment cluster when one exists (richest), otherwise from the
        # connectid resolver so chat-only / empty groups still show identity.
        if cl:
            ph, vp, ui, ci = _decompose_idents(cl.get("identifiers", []))
            g["v2_counterparty"] = {
                "cluster_id": cl_id,
                "display_name": cl.get("display_name") or g["v2_display_name"] or "(unknown)",
                "names_verified": cl.get("names_verified", []),
                "names_cbs": cl.get("names_cbs", []),
                "names_display": cl.get("names_display", []),
                "names_saved": cl.get("names_saved", []),
                "masked_phones": cl.get("masked_phones", []),
                "phones": ph, "vpas": vp, "user_ids": ui, "connect_ids": ci,
                "is_merchant": "MERCHANT" in cl.get("kinds", []),
                "source": "payment cluster",
            }
        elif conv:
            g["v2_counterparty"] = {
                "cluster_id": None,
                "display_name": g["v2_display_name"] or "(unknown)",
                "names_verified": [conv.other_party_verified_name] if conv.other_party_verified_name else [],
                "names_cbs": [conv.other_party_cbs_name] if conv.other_party_cbs_name else [],
                "names_display": [conv.other_party_display_name] if conv.other_party_display_name else [],
                "names_saved": [saved] if saved else [],
                "masked_phones": [conv.other_party_masked_phone] if (conv.other_party_masked_phone and not full) else [],
                "phones": [full] if full else [],
                "vpas": [], "user_ids": [],
                "connect_ids": [conv.other_party_connect_id] if conv.other_party_connect_id else [],
                "is_merchant": False,
                "source": "chat (no payment recorded with this counterparty)",
            }

    # members: resolve each member's FULL phone, corroborated by the masked
    # ******XXXX last-4 so the wrong number is never attributed.
    def _match_masked(masked, candidates):
        m4 = "".join(c for c in str(masked or "") if c.isdigit())[-4:]
        if len(m4) < 4:
            return None
        for cand in candidates:
            if str(cand)[-4:] == m4:
                return str(cand)
        return None

    # owner candidate phones: every phone seen + every owner-VPA local part
    owner_candidates = set(owner_phones)
    for v in (owner.vpas or []):
        d = "".join(c for c in (v.vpa or "").split("@")[0] if c.isdigit())
        if len(d) >= 10:
            owner_candidates.add(d[-10:])

    member_full_phone_patched = 0
    for mem in members:
        masked = mem.get("masked_phone")
        if mem.get("is_self"):
            full = _match_masked(masked, owner_candidates)
        else:
            cand = group_cp_phone.get(mem.get("group_id") or "")
            # corroborate against the masked last-4 when the chat kept one
            full = cand if (cand and (not masked or _match_masked(masked, [cand]))) else None
        if full:
            mem["v2_full_phone"] = full
            member_full_phone_patched += 1
        # display label — swap a masked name for the resolved number
        mem["v2_display_name"] = (
            full if (_is_masked_label(mem.get("display_name")) and full)
            else mem.get("display_name")
        )
    case.data.setdefault("_v2_meta", {})["member_full_phone_patched"] = member_full_phone_patched

    # messages: resolve the per-message counterparty label + phone (the All
    # Messages table shows m.other_party_name / m.other_party_phone, masked
    # for number-only contacts). Keyed by the message's group.
    group_display = {g.get("group_id"): g.get("v2_display_name") for g in groups}
    for msg in messages:
        gid = msg.get("thread_id")
        full = group_cp_phone.get(gid or "")
        if full:
            msg["v2_other_party_phone"] = full
            if _is_masked_label(msg.get("other_party_name")):
                msg["v2_other_party_display"] = group_display.get(gid) or full

    # ---- refresh transactions["summary"] so the existing /transactions view
    # ---- and dashboard tiles reflect the merged 285-row truth, not the 147
    # ---- TxnStore-only count the upstream extractor wrote.
    summary = txn_block.setdefault("summary", {})

    # Money amounts count COMPLETED payments only. A FAILED payment carries an
    # amount but no money moved — summing it would inflate every total (a few
    # failed retries of the same payment can add a large phantom sum).
    def _completed(p):
        return p.state == "COMPLETED"

    total_in = sum(p.amount_inr for p in result.payments if p.direction == "RECEIVED" and _completed(p))
    total_out = sum(p.amount_inr for p in result.payments if p.direction == "SENT" and _completed(p))
    # counts: keep full direction counts, but track completed + failed separately
    in_count = sum(1 for p in result.payments if p.direction == "RECEIVED")
    out_count = sum(1 for p in result.payments if p.direction == "SENT")
    unknown_count = sum(1 for p in result.payments if p.direction not in ("RECEIVED", "SENT"))
    failed_count = sum(1 for p in result.payments if p.state == "FAILED")
    completed_count = sum(1 for p in result.payments if _completed(p))
    timestamps = [p.timestamp_ms for p in result.payments if p.timestamp_ms]

    # yearly_volume — COMPLETED only, rebuilt from MERGED payments so 2020-2023
    # history surfaces.
    from datetime import datetime, timezone
    yearly_in: Dict[str, float] = {}
    yearly_out: Dict[str, float] = {}
    for p in result.payments:
        if not p.timestamp_ms or not _completed(p):
            continue
        yr = datetime.fromtimestamp(p.timestamp_ms / 1000, tz=timezone.utc).year
        ystr = str(yr)
        if p.direction == "RECEIVED":
            yearly_in[ystr] = round(yearly_in.get(ystr, 0) + p.amount_inr, 2)
        elif p.direction == "SENT":
            yearly_out[ystr] = round(yearly_out.get(ystr, 0) + p.amount_inr, 2)

    # top_counterparties split by DIRECTION (received-from / sent-to).
    # Aggregation key is the IDENTIFIER-BASED counterparty_cluster_id assigned
    # by resolve_counterparties() — never the name. Two payments are the same
    # counterparty only if they share a userId / phone / connectId / VPA.
    from collections import Counter, defaultdict

    # counts + amounts are COMPLETED-only so the "Txns" and "Total ₹" columns
    # stay consistent (a failed payment is neither counted nor summed here).
    recv_count: Counter = Counter()
    recv_amount: defaultdict = defaultdict(float)
    sent_count: Counter = Counter()
    sent_amount: defaultdict = defaultdict(float)

    for p in result.payments:
        cid = p.counterparty_cluster_id
        if not cid or not _completed(p):
            continue
        if p.direction == "RECEIVED":
            recv_count[cid] += 1
            recv_amount[cid] += p.amount_inr
        elif p.direction == "SENT":
            sent_count[cid] += 1
            sent_amount[cid] += p.amount_inr

    def _rows(counter, amount, top_n=20):
        # Rank by TOTAL AMOUNT moved (descending) — the forensically
        # significant ordering — not by transaction count.
        out = []
        for cid in sorted(counter, key=lambda k: amount.get(k, 0.0), reverse=True):
            cl = clusters.get(cid, {})
            kinds = cl.get("kinds", [])
            is_merchant = "MERCHANT" in kinds
            out.append(
                {
                    "name": cl.get("display_name", "(unknown)"),
                    "count": counter[cid],
                    "amount_inr": round(amount[cid], 2),
                    "kind": "Merchant" if is_merchant else "Personal",
                    "cluster_id": cid,
                    "identifiers": cl.get("identifiers", []),
                }
            )
        return out[:top_n]

    top_received = _rows(recv_count, recv_amount)
    top_sent = _rows(sent_count, sent_amount)
    # legacy personal/merchant split kept for backward-compat consumers
    top_personal = [r for r in (top_received + top_sent) if r["kind"] == "Personal"][:15]
    top_merchants = [r for r in (top_received + top_sent) if r["kind"] == "Merchant"][:15]

    summary.update(
        {
            "transaction_count": result.combined_unique_count,
            # COMPLETED-only money totals (failed payments excluded)
            "total_received_inr": round(total_in, 2),
            "total_sent_inr": round(total_out, 2),
            "net_flow_inr": round(total_in - total_out, 2),
            "completed_count": completed_count,
            "failed_count": failed_count,
            "amounts_basis": "COMPLETED payments only — FAILED/CREATED excluded from sums",
            "direction_breakdown": {
                "IN": in_count,
                "OUT": out_count,
                "UNKNOWN": unknown_count,
            },
            "earliest_txn": min(timestamps) if timestamps else summary.get("earliest_txn"),
            "latest_txn": max(timestamps) if timestamps else summary.get("latest_txn"),
            # v2 refreshed: yearly volume + top counterparties (by direction)
            "yearly_received_inr": yearly_in,
            "yearly_sent_inr": yearly_out,
            "top_counterparties": [(c["name"], c["count"]) for c in (top_received + top_sent)[:15]],
            "top_counterparties_received": top_received,
            "top_counterparties_sent": top_sent,
            "top_counterparties_personal": top_personal,
            "top_counterparties_merchants": top_merchants,
            "v2_coverage": {
                "txnstore_payments": result.txnstore_payment_count,
                "burble_only": result.burble_only_count,
                "overlap": result.overlap,
                "combined_unique": result.combined_unique_count,
            },
        }
    )

    # v2 summary stats — read by dashboard
    by_app: Dict[str, int] = {}
    by_init: Dict[str, int] = {}
    for p in result.payments:
        for label in (p.sender_app_label, p.receiver_app_label):
            if label and label != "No VPA":
                by_app[label] = by_app.get(label, 0) + 1
        if p.payment_initiation:
            by_init[p.payment_initiation] = by_init.get(p.payment_initiation, 0) + 1

    failures = [
        {
            "primary_id": p.primary_id,
            "amount_inr": p.amount_inr,
            "datetime_ist": p.datetime_ist,
            "counterparty": p.counterparty_name,
            "data_source": p.data_source,
            "failure_reason": p.failure_reason,
            "is_failed_chat_only": p.is_failed_chat_only,
        }
        for p in result.payments
        if p.state == "FAILED"
    ]
    refunds = [
        {
            "primary_id": p.primary_id,
            "amount_inr": p.amount_inr,
            "datetime_ist": p.datetime_ist,
            "counterparty": p.counterparty_name,
            "kind": "payment_refund",
        }
        for p in result.payments
        if p.is_refund
    ] + [
        {
            "primary_id": m["primary_id"],
            "amount_inr": m["amount_inr"],
            "datetime_ist": m["datetime_ist"],
            "counterparty": m["name"],
            "kind": "request_from_merchant",
        }
        for m in result.mandates
        if m.get("is_merchant_refund")
    ]

    case.data["_v2"] = {
        "coverage": {
            "txnstore_payments": result.txnstore_payment_count,
            "burble_payment_cards": result.burble_payment_card_count,
            "overlap": result.overlap,
            "txnstore_only": result.txnstore_only_count,
            "burble_only": result.burble_only_count,
            "combined_unique": result.combined_unique_count,
        },
        "retention_days": owner.duration_of_download_days,
        "owner_vpas": [
            {
                "vpa": v.vpa,
                "psp": v.psp,
                "is_phonepe_psp": v.is_phonepe_psp,
                "account_number": v.account_number,
                "ifsc": v.ifsc,
                "bank_id": v.bank_id,
            }
            for v in owner.vpas
        ],
        "owner_subject_name": owner.account_holder,
        "owner_account_no": owner.account_no,
        "owner_bank_name": owner.bank_name,
        "owner_ifsc": owner.ifsc,
        "owner_user_id": owner.user_id,
        "phonepe_psps": sorted(phonepe_psps),
        "tpap_map_size": len(tpap_key_map),
        "tpap_app_size": len(tpap_info),
        "tpap_info": {
            k: {"title": v.title, "icon_id": v.icon_id, "handles": v.handles}
            for k, v in tpap_info.items()
        },
        "source_db_hashes": source_hashes,
        "by_app": by_app,
        "by_initiation": by_init,
        "qr_scan_count": sum(1 for p in result.payments if p.is_qr_scan),
        "intent_count": sum(1 for p in result.payments if p.is_intent),
        "failures": failures,
        "refunds": refunds,
        "mandates_count": len(result.mandates),
        "mandates": [
            {
                "primary_id": m["primary_id"],
                "entity_type": m["entity_type"],
                "name": m["name"],
                "amount_inr": m["amount_inr"],
                "state": m["state"],
                "datetime_ist": m["datetime_ist"],
                "is_merchant_refund": m.get("is_merchant_refund", False),
            }
            for m in result.mandates
        ],
        # keep the full reconcile result for the offline HTML export route
        "_reconcile_result": result,
        # identifier-based counterparty clusters (for the stable /v2/counterparty page)
        "clusters": clusters,
    }


def render_offline_html(case, output_path) -> str:
    """Build the single-file offline evidence HTML for the active case."""
    from pathlib import Path
    from .v2.static_export import build_static_report

    v2 = case.data.get("_v2") or {}
    result = v2.get("_reconcile_result")
    if result is None:
        # not yet enriched — do it now
        enrich_case(case)
        result = case.data["_v2"]["_reconcile_result"]
    case_id = (
        getattr(case, "case_id", None) or Path(case.root).parent.name or "case"
    )
    p = build_static_report(
        result=result,
        case_root=Path(case.root),
        case_id=case_id,
        output_path=Path(output_path),
    )
    return str(p)
