"""
PhonePe iOS Forensics — Extraction Modules
==========================================
Each module turns a raw artifact into structured forensic evidence:

    extract_identity              account, devices, sessions, location
    extract_transactions          master ledger from TransactionsStore
    extract_contacts              SamparkV2 phone-to-VPA social graph
    extract_chat                  Burble groups, messages, payment cards
    extract_notifications         PubSubCore Bullhorn topics
    extract_analytics             Foxtrot, KN, Dash batched events
    extract_financial             rewards, MF, vouchers, donations
    extract_travel                Yatra journeys
    extract_payment_infra         banks, UPI VPAs, instruments
    extract_config_state          Chimera, Experimentation, ConfigManager
    extract_recommendations       Maximus, Athena
    extract_media                 QR + transaction backgrounds + DPs
    extract_search                AppSearch FTS recents, sitemap
    extract_webkit                ResourceLoadStatistics + cookies
    extract_audit                 Chitragupt + Chronicle + Samsara + sync gaps
    extract_app_state             generic plist & 222-key main pref dump
"""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from .core import (
    APPLE_EPOCH_OFFSET,
    BinaryCookieReader,
    CasePaths,
    SQLiteReader,
    amount_to_rupees,
    decode_nskeyedarchiver,
    decode_txn_id,
    fmt_ts,
    flatten_plist,
    hash_file,
    normalize_timestamp,
    read_plist,
    safe_decode_blob,
    safe_int,
)

# ---------------------------------------------------------------------------
# Identity, account & device fingerprint
# ---------------------------------------------------------------------------

PHONE_RX = re.compile(r"(?:\+91[-\s]?|\+91|0?91)?([6-9]\d{9})\b")
UPI_RX = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+")
LAT_LON_RX = re.compile(r'"(?:lat|latitude)"\s*:\s*([\-0-9.]+).*?"(?:lng|long|longitude)"\s*:\s*([\-0-9.]+)', re.S)


def _looks_like_phone(s: str) -> bool:
    """Indian mobile = 10 digits starting with 6-9, optionally +91 prefix."""
    if not s:
        return False
    digits = re.sub(r"[^\d]", "", s)
    if len(digits) == 10 and digits[0] in "6789":
        return True
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        return True
    if len(digits) == 13 and digits.startswith("091") and digits[3] in "6789":
        return True
    return False


def _scan_value_for_phones(value: Any, sink: set) -> None:
    if isinstance(value, (str, bytes)):
        s = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
        for match in PHONE_RX.findall(s):
            # match groups capture the 10-digit core
            sink.add(match)
    elif isinstance(value, dict):
        for v in value.values():
            _scan_value_for_phones(v, sink)
    elif isinstance(value, list):
        for v in value:
            _scan_value_for_phones(v, sink)


def extract_identity(case: CasePaths) -> Dict[str, Any]:
    """User identity fingerprint pulled from many plists.

    Forensic relevance: pins the ownership of the device + UPI account.
    Combines:
      * widget cache plist           -> primary UPI ID
      * help customDataStore plist   -> userName + refreshToken
      * ads sdk plist                -> location (lat/lon/state/pincode)
      * AdSupport / Firebase / AppsFlyer plists -> persistent identifiers
      * Chimera / Nexus catalogue    -> last sync timestamps
    """
    profile: Dict[str, Any] = {
        "registered_name": None,
        "upi_id": None,
        "phones_seen": [],
        "device_identifiers": {},
        "sessions": {},
        "tokens": {},
        "location_hints": [],
        "permissions": {},
        "feature_flags": {},
        "raw_account_plist": {},
    }

    # widget cache: home page typically embeds the user's primary UPI ID
    p = case.resolve("Library", "Preferences", "com.phonepe.widgetxii.datacache.plist")
    if p:
        d = read_plist(p) or {}
        home = d.get("homePage", {}) if isinstance(d, dict) else {}
        if isinstance(home, dict):
            profile["upi_id"] = home.get("UPI_ID")
            if "P2P_UNREAD_INDICATOR" in home:
                profile["feature_flags"]["p2p_unread_indicator"] = home.get("P2P_UNREAD_INDICATOR")

    # help SDK customDataStore: contains plain-text userName & refreshToken
    p = case.resolve("Library", "Preferences", "com.phonepe.help.customDataStore.plist")
    if p:
        d = read_plist(p) or {}
        opt = d.get("optimus_auth_headers", {}) if isinstance(d, dict) else {}
        if isinstance(opt, dict):
            profile["registered_name"] = opt.get("userName")
            profile["tokens"]["help_refresh_token"] = opt.get("refreshToken")
            profile["tokens"]["help_optimus_token"] = opt.get("optimusToken")

    # account plist: token expiry + fetch
    p = case.resolve("Library", "Preferences", "com.phonepe.account.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            profile["raw_account_plist"] = flatten_plist(d)
            for k, v in d.items():
                if "token.expiry" in k.lower():
                    profile["sessions"]["token_expiry_at"] = normalize_timestamp(v)
                if "token.fetched" in k.lower():
                    profile["sessions"]["token_fetched_at"] = normalize_timestamp(v)

    # main app pref: 222 keys, mine for key signals
    p = case.resolve("Library", "Preferences", "com.phonepe.PhonePeApp.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            profile["sessions"]["session_id_updated_at"] = normalize_timestamp(d.get("com.phonepe.app.sessionIDUpdatedAt"))
            profile["device_identifiers"]["appsflyer_user_id"] = d.get("AppsFlyerUserId")
            profile["device_identifiers"]["localization_diff_version"] = d.get("LocalizationUserDefault.app_diffVersion")
            for k in d:
                if k.startswith("chimera.quick-"):
                    profile["feature_flags"][k] = d[k]
            # token blobs (preview only)
            bolt = d.get("BoltV2.boltToken")
            if isinstance(bolt, dict) and "token" in bolt:
                profile["tokens"]["bolt_v2_token_preview"] = str(bolt["token"])[:48] + "..."

    # ads SDK plist: location is gold
    p = case.resolve("Library", "Preferences", "com.phonepe.ads.sdk.plist")
    if p:
        d = read_plist(p) or {}
        last_req = d.get("lastConfigRequest") if isinstance(d, dict) else None
        if isinstance(last_req, (bytes, bytearray)):
            text = last_req.decode("utf-8", "replace")
            m = re.search(r'"lat":([\-0-9.]+),"pinCode":"([^"]*)","state":"([^"]*)"', text)
            if m:
                profile["location_hints"].append({
                    "lat": float(m.group(1)),
                    "pincode": m.group(2),
                    "state": m.group(3),
                    "source": "ads_sdk_lastConfigRequest",
                })
            m = re.search(r'"lng":([\-0-9.]+)', text)
            if m and profile["location_hints"]:
                profile["location_hints"][-1]["lng"] = float(m.group(1))
            profile["device_identifiers"]["ads_user_agent"] = (d.get("adssdk.phonepe.userAgent") or "")[:200] if isinstance(d, dict) else None

    # Apple AdSupport
    p = case.resolve("Library", "Preferences", "com.apple.AdSupport.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            profile["device_identifiers"]["adsupport_enforcement"] = d.get("ShouldEnforceATP")
            ts = d.get("LastRegionalEnforcementCheck")
            if ts is not None:
                profile["device_identifiers"]["adsupport_last_check"] = str(ts)

    # Firebase install
    p = case.resolve("Library", "Preferences", "com.firebase.FIRInstallations.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            for k in d:
                if "FIRAPP_DEFAULT" in k:
                    profile["device_identifiers"]["firebase_install_id"] = k

    # Google Ads
    p = case.resolve("Library", "Preferences", "__gads__.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            profile["device_identifiers"]["gads_paid"] = d.get("paid")
            profile["device_identifiers"]["gads_paid_v2"] = d.get("paid_v2")

    # AppsFlyer remote control
    p = case.resolve("Library", "Preferences", "group.com.phonepe.PhonePeApp.appsflyer.remotecontrol.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, dict):
                    profile["device_identifiers"][f"appsflyer_{k}"] = {
                        kk: (str(vv)[:64] + "...") if isinstance(vv, (bytes, bytearray)) else vv
                        for kk, vv in v.items()
                    }

    # Nexus catalogue: last sync evidence (proves device active at certain times)
    p = case.resolve("Library", "Preferences", "com.phonepe.nexus.catalogue.plist")
    if p:
        d = read_plist(p) or {}
        if isinstance(d, dict):
            for k, v in d.items():
                if "sync.last.seen" in k:
                    norm = normalize_timestamp(v)
                    if norm:
                        profile["sessions"][k] = norm

    # phone numbers seen anywhere in account-related plists
    phones: set = set()
    for fname in ["com.phonepe.PhonePeApp.plist", "com.phonepe.account.plist",
                  "com.phonepe.help.customDataStore.plist"]:
        p = case.resolve("Library", "Preferences", fname)
        if p:
            d = read_plist(p)
            if d is not None:
                _scan_value_for_phones(d, phones)
    profile["phones_seen"] = sorted(phones)[:20]

    # group container shared plist
    if case.group_shared:
        p = os.path.join(case.group_shared, "Library", "Preferences", "group.com.phonepe.shared.plist")
        if os.path.exists(p):
            d = read_plist(p) or {}
            if isinstance(d, dict):
                for k, v in d.items():
                    if "token.expiry" in k:
                        profile["sessions"]["shared_token_expiry"] = normalize_timestamp(v)
                    if "token.fetched" in k:
                        profile["sessions"]["shared_token_fetched"] = normalize_timestamp(v)

    return profile


# ---------------------------------------------------------------------------
# Transactions (master ledger)
# ---------------------------------------------------------------------------

# Tag keys observed in ZTRANSACTIONTAGENTITY (ZKEY column)
TXN_TAG_KEYS = {
    "amount", "category", "status", "sentTo", "receivedFrom", "receiverName", "senderName",
    "receivedIn.type", "vpa", "merchantId", "merchantName", "note", "remarks",
    "groupId", "groupTemplate", "billerId", "billerName", "rechargeNumber",
}


_DIRECTION_MAP = {
    "RECEIVED_PAYMENT": "IN",
    "USER_TO_USER_RECEIVED_REQUEST": "IN",
    "RECEIVED_MANDATE_CREATE_REQUEST": "IN",
    "P2P_ENRICHMENT": "META",  # not a money movement, just metadata enrichment
    "SENT_PAYMENT": "OUT",
    "EXTERNAL_PAYMENT": "OUT",
    "PHONE_RECHARGE": "OUT",
    "BILL_PAYMENT": "OUT",
    "SERVICE_MANDATE_CREATE": "OUT",
    "SYMPHONY": "META",
}


def _direction_for(ttype: str) -> str:
    if not ttype:
        return "UNKNOWN"
    if ttype in _DIRECTION_MAP:
        return _DIRECTION_MAP[ttype]
    upper = ttype.upper()
    if "RECEIVED" in upper or "CREDIT" in upper or "REFUND" in upper:
        return "IN"
    if "SENT" in upper or "DEBIT" in upper or "PAYMENT" in upper or "BILL" in upper or "RECHARGE" in upper:
        return "OUT"
    return "UNKNOWN"


def _extract_counterparty_from_zdata(zdata: Any, direction: str) -> Dict[str, Any]:
    """Pull counterparty fields from the rich NSKeyedArchiver-decoded ZDATA.

    For RECEIVED transactions, counterparty is in `from`.
    For SENT transactions, counterparty is in `to` or one of `paidTo`.
    """
    out = {
        "name": None, "cbs_name": None, "phone": None, "vpa": None,
        "user_id": None, "user_type": None, "account_holder_self": None,
        "self_account_masked": None, "self_account_id": None, "ifsc": None,
        "instrument_id": None, "utr": None, "transfer_mode": None,
        "response_code": None, "amount_paise": None, "actual_amount": None,
        "self_vpa": None, "self_upi_number": None, "self_user_id": None,
        "tag": None, "service_context": None,
    }
    if not isinstance(zdata, dict):
        return out

    # Amount + response
    out["amount_paise"] = zdata.get("amount")
    out["response_code"] = zdata.get("responseCode")
    ctx = zdata.get("context") or {}
    if isinstance(ctx, dict):
        out["transfer_mode"] = ctx.get("transferMode")
        out["tag"] = ctx.get("tag")

    # Determine which side is the counterparty
    if direction == "IN":
        cp = zdata.get("from") or {}
        self_side = zdata.get("to") or {}
    else:
        cp = zdata.get("to") or zdata.get("paidTo") or {}
        self_side = zdata.get("from") or {}

    if isinstance(cp, dict):
        out["name"] = cp.get("name")
        out["cbs_name"] = cp.get("cbsName")
        out["phone"] = cp.get("phone")
        out["user_id"] = cp.get("userId")
        out["user_type"] = cp.get("type")
        out["vpa"] = cp.get("vpa") or cp.get("upiNumber")

    if isinstance(self_side, dict):
        out["self_user_id"] = self_side.get("userId")
        out["self_upi_number"] = self_side.get("upiNumber")
        out["self_vpa"] = self_side.get("vpa")

    # Self account info from receivedIn / paidFrom
    received_in = zdata.get("receivedIn") or zdata.get("paidFrom") or []
    if isinstance(received_in, list) and received_in:
        first = received_in[0]
        if isinstance(first, dict):
            out["account_holder_self"] = first.get("accountHolderName")
            out["self_account_masked"] = first.get("accountNumber")
            out["self_account_id"] = first.get("accountId")
            out["self_vpa"] = out["self_vpa"] or first.get("vpa")
            out["ifsc"] = first.get("ifsc")
            out["instrument_id"] = first.get("instrumentId")
            out["utr"] = first.get("utr")
            if not out["amount_paise"]:
                out["amount_paise"] = first.get("amount")

    return out


def extract_transactions(case: CasePaths) -> Dict[str, Any]:
    """Extract the master transaction ledger.

    Source: TransactionsStore.sqlite (ZTRANSACTIONENTITY + ZTRANSACTIONTAGENTITY).
    The Z_PK-keyed ZTAGSDATA BLOB and ZDATA BLOB carry the actual amount,
    counterparty details, UTR, IFSC, and instrument metadata; the small
    ZTRANSACTIONTAGENTITY rows hold the same data flattened for indexing.
    """
    out: Dict[str, Any] = {
        "transactions": [],
        "summary": {},
        "deletion_signals": {},
        "errors": [],
    }
    db_path = case.resolve(
        "Documents", "TransactionsStore", "Database", "TransactionsStore", "TransactionsStore.sqlite"
    )
    if not db_path:
        out["errors"].append("TransactionsStore.sqlite not found")
        return out

    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["deletion_signals"] = db.deletion_signals()
        rows = db.query("""
            SELECT Z_PK, ZCREATEDAT, ZUPDATEDAT, ZENTITYID, ZGLOBALPAYMENTID,
                   ZSTATEVALUE, ZTYPEVALUE, ZSEARCHTOKEN, ZDISMISSED,
                   ZISINTERNALTRANSACTION, ZISUNSUPPORTEDTYPE, ZDATA, ZTAGSDATA
            FROM ZTRANSACTIONENTITY
            ORDER BY ZCREATEDAT DESC
        """)
        tag_rows = db.query("""
            SELECT ZTRANSACTION, ZKEY, ZVALUE, ZTYPEVALUE
            FROM ZTRANSACTIONTAGENTITY
        """)
        tags_by_txn: Dict[Any, Dict[str, str]] = defaultdict(dict)
        for tr in tag_rows:
            if "_error" in tr:
                continue
            tid = tr.get("ZTRANSACTION")
            key = tr.get("ZKEY")
            if tid is None or key is None:
                continue
            if key not in tags_by_txn[tid] or not tags_by_txn[tid].get(key):
                tags_by_txn[tid][key] = tr.get("ZVALUE")

    statuses = Counter()
    types = Counter()
    direction_count = Counter()
    counterparties = Counter()
    yearly_in: Dict[str, float] = defaultdict(float)
    yearly_out: Dict[str, float] = defaultdict(float)
    monthly_volume: Dict[str, float] = defaultdict(float)
    total_in = 0.0
    total_out = 0.0
    earliest = None
    latest = None
    self_account_holders: set = set()
    self_account_masked: set = set()
    self_vpas: set = set()
    self_user_ids: set = set()
    self_phones: set = set()

    for r in rows:
        if "_error" in r:
            out["errors"].append(r["_error"])
            continue
        zpk = r.get("Z_PK")
        tags = tags_by_txn.get(zpk, {})
        ts = normalize_timestamp(r.get("ZCREATEDAT"))
        ts_updated = normalize_timestamp(r.get("ZUPDATEDAT"))
        decoded_id = decode_txn_id(r.get("ZGLOBALPAYMENTID") or r.get("ZENTITYID"))
        zdata = safe_decode_blob(r.get("ZDATA"))
        ztags = safe_decode_blob(r.get("ZTAGSDATA"))

        ttype = r.get("ZTYPEVALUE") or "UNKNOWN"
        state = r.get("ZSTATEVALUE") or "UNKNOWN"
        types[ttype] += 1
        statuses[state] += 1

        direction = _direction_for(ttype)
        cp_info = _extract_counterparty_from_zdata(zdata, direction)

        # Amount: prefer ZTAGSDATA.amount, then cp_info, then sentTo tag (rare)
        amount_paise = None
        if isinstance(ztags, dict) and ztags.get("amount") is not None:
            amount_paise = safe_int(ztags["amount"], default=-1)
        if amount_paise is None or amount_paise < 0:
            if cp_info.get("amount_paise") is not None:
                amount_paise = safe_int(cp_info["amount_paise"], default=-1)
        if amount_paise is None or amount_paise < 0:
            amount_paise = safe_int(tags.get("amount"), default=-1)
        amount_inr = amount_to_rupees(amount_paise) if amount_paise >= 0 else None

        # Track self identity from any txn record
        if cp_info.get("account_holder_self"):
            self_account_holders.add(cp_info["account_holder_self"])
        if cp_info.get("self_account_masked"):
            self_account_masked.add(cp_info["self_account_masked"])
        if cp_info.get("self_vpa"):
            self_vpas.add(cp_info["self_vpa"])
        if cp_info.get("self_user_id"):
            self_user_ids.add(cp_info["self_user_id"])
        if cp_info.get("self_upi_number"):
            self_phones.add(cp_info["self_upi_number"])

        # Counterparty for display & ranking
        cp_name = cp_info.get("name") or cp_info.get("cbs_name") or tags.get("sentTo")
        cp_phone = cp_info.get("phone") or (tags.get("sentTo") if tags.get("sentTo") and str(tags.get("sentTo")).isdigit() else None)
        cp_vpa = cp_info.get("vpa") or (tags.get("sentTo") if tags.get("sentTo") and "@" in str(tags.get("sentTo")) else None)

        if cp_name:
            counterparties[str(cp_name)] += 1

        direction_count[direction] += 1

        if amount_inr is not None and state.upper() in ("COMPLETED", "SUCCESS", "SETTLED"):
            if direction == "IN":
                total_in += amount_inr
            elif direction == "OUT":
                total_out += amount_inr

        if ts:
            year = ts["iso"][:4]
            month = ts["iso"][:7]
            if amount_inr is not None and state.upper() in ("COMPLETED", "SUCCESS"):
                if direction == "IN":
                    yearly_in[year] += amount_inr
                elif direction == "OUT":
                    yearly_out[year] += amount_inr
                if direction in ("IN", "OUT"):
                    monthly_volume[month] += amount_inr
            if earliest is None or ts["epoch_ms"] < earliest["epoch_ms"]:
                earliest = ts
            if latest is None or ts["epoch_ms"] > latest["epoch_ms"]:
                latest = ts

        out["transactions"].append({
            "z_pk": zpk,
            "entity_id": r.get("ZENTITYID"),
            "global_payment_id": r.get("ZGLOBALPAYMENTID"),
            "type": ttype,
            "state": state,
            "direction": direction,
            "amount_paise": amount_paise if amount_paise is not None and amount_paise >= 0 else None,
            "amount_inr": amount_inr,
            "category_code": tags.get("category"),
            "received_in_type": tags.get("receivedIn.type") or (ztags.get("receivedIn.type") if isinstance(ztags, dict) else None),
            "counterparty": cp_name,
            "counterparty_phone": cp_phone,
            "counterparty_vpa": cp_vpa,
            "counterparty_user_id": cp_info.get("user_id"),
            "counterparty_user_type": cp_info.get("user_type"),
            "counterparty_cbs_name": cp_info.get("cbs_name"),
            "self_account_holder": cp_info.get("account_holder_self"),
            "self_account_masked": cp_info.get("self_account_masked"),
            "self_vpa": cp_info.get("self_vpa"),
            "self_ifsc": cp_info.get("ifsc"),
            "instrument_id": cp_info.get("instrument_id"),
            "utr": cp_info.get("utr"),
            "transfer_mode": cp_info.get("transfer_mode"),
            "context_tag": cp_info.get("tag"),
            "response_code": cp_info.get("response_code"),
            "merchant_id": tags.get("merchantId"),
            "merchant_name": tags.get("merchantName"),
            "biller_id": tags.get("billerId"),
            "biller_name": tags.get("billerName"),
            "recharge_number": tags.get("rechargeNumber"),
            "note": tags.get("note") or tags.get("remarks"),
            "group_id": tags.get("groupId"),
            "group_template": tags.get("groupTemplate"),
            "search_token": (r.get("ZSEARCHTOKEN") or "").strip(),
            "created_at": ts,
            "updated_at": ts_updated,
            "id_embedded_ts": decoded_id,
            "dismissed": bool(r.get("ZDISMISSED")),
            "is_internal": bool(r.get("ZISINTERNALTRANSACTION")),
            "raw_data": zdata if isinstance(zdata, (dict, list)) else None,
            "raw_tags": ztags if isinstance(ztags, (dict, list)) else None,
            "all_tags": tags,
        })

    out["summary"].update({
        "transaction_count": len(out["transactions"]),
        "type_breakdown": dict(types),
        "state_breakdown": dict(statuses),
        "direction_breakdown": dict(direction_count),
        "top_counterparties": counterparties.most_common(20),
        "earliest_txn": earliest,
        "latest_txn": latest,
        "total_received_inr": round(total_in, 2),
        "total_sent_inr": round(total_out, 2),
        "net_flow_inr": round(total_in - total_out, 2),
        "yearly_received_inr": dict(sorted(yearly_in.items())),
        "yearly_sent_inr": dict(sorted(yearly_out.items())),
        "monthly_volume_inr": dict(sorted(monthly_volume.items())),
        "self_account_holders": sorted(self_account_holders),
        "self_account_masked": sorted(self_account_masked),
        "self_vpas": sorted(self_vpas),
        "self_user_ids": sorted(self_user_ids),
        "self_phones": sorted(self_phones),
    })
    return out


# ---------------------------------------------------------------------------
# Contacts (SamparkV2 social graph)
# ---------------------------------------------------------------------------

def extract_contacts(case: CasePaths) -> Dict[str, Any]:
    """Build the social-financial graph from SamparkV2.

    Pulls from three tables:
        ZCYCLOPSCONTACT      — PhonePe-side normalized contacts (1800 entries)
        ZPHONEBOOKCONTACT    — raw device address-book (2900+ entries)
        ZPHONEBOOKCONTACTMETADATA — per-contact full name + image BLOB
    """
    out: Dict[str, Any] = {
        "cyclops_contacts": [],
        "phonebook_contacts": [],
        "summary": {},
        "errors": [],
    }
    db_path = None
    if case.group_app:
        cand = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "SamparkV2", "SamparkV2.sqlite")
        if os.path.exists(cand):
            db_path = cand
    if not db_path:
        out["errors"].append("SamparkV2.sqlite not found")
        return out

    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["summary"]["deletion_signals"] = db.deletion_signals()
        cyclops = db.query("""
            SELECT Z_PK, ZCONNECTID, ZPHONENUMBER, ZVERIFIEDNAME, ZONPHONEPE,
                   ZEXTERNALVPA, ZEXTERNALVPANAME, ZUPISTATEVALUE, ZTIMESTAMP,
                   ZCOUNTRYCODE, ZREGION, ZPHOTO
            FROM ZCYCLOPSCONTACT
            ORDER BY ZTIMESTAMP DESC
        """)
        # Phonebook with metadata join
        phonebook = db.query("""
            SELECT pb.Z_PK, pb.ZRAWPHONENUMBER, pb.ZSELFNORMALISEDNUMBER,
                   pb.ZCOUNTRYCODE, pb.ZREGION, pb.ZCREATIONTIME, pb.ZISVALID,
                   pb.ZDIDDELETE, md.ZFULLNAME, md.ZCONTACTID, md.ZHASHCODE,
                   length(md.ZIMAGEDATA) as image_size
            FROM ZPHONEBOOKCONTACT pb
            LEFT JOIN ZPHONEBOOKCONTACTMETADATA md ON pb.ZMETADATA = md.Z_PK
        """)

    on_phonepe = 0
    has_vpa = 0
    deleted = 0
    out_cyclops: List[Dict[str, Any]] = []
    for r in cyclops:
        if "_error" in r:
            continue
        if r.get("ZONPHONEPE"):
            on_phonepe += 1
        if r.get("ZEXTERNALVPA"):
            has_vpa += 1
        out_cyclops.append({
            "connect_id": r.get("ZCONNECTID"),
            "phone": r.get("ZPHONENUMBER"),
            "verified_name": r.get("ZVERIFIEDNAME"),
            "external_vpa": r.get("ZEXTERNALVPA"),
            "external_vpa_name": r.get("ZEXTERNALVPANAME"),
            "on_phonepe": bool(r.get("ZONPHONEPE")),
            "upi_state": r.get("ZUPISTATEVALUE"),
            "country_code": r.get("ZCOUNTRYCODE"),
            "region": r.get("ZREGION"),
            "last_synced": normalize_timestamp(r.get("ZTIMESTAMP")),
            "photo_url": r.get("ZPHOTO"),
        })
    out["cyclops_contacts"] = out_cyclops

    out_phonebook: List[Dict[str, Any]] = []
    for r in phonebook:
        if "_error" in r:
            continue
        if r.get("ZDIDDELETE"):
            deleted += 1
        out_phonebook.append({
            "raw_number": r.get("ZRAWPHONENUMBER"),
            "normalized": r.get("ZSELFNORMALISEDNUMBER"),
            "country_code": r.get("ZCOUNTRYCODE"),
            "region": r.get("ZREGION"),
            "creation_time": normalize_timestamp(r.get("ZCREATIONTIME")),
            "is_valid": bool(r.get("ZISVALID")),
            "deleted": bool(r.get("ZDIDDELETE")),
            "full_name": r.get("ZFULLNAME"),
            "contact_id": r.get("ZCONTACTID"),
            "hash_code": r.get("ZHASHCODE"),
            "has_image": bool(r.get("image_size") and r.get("image_size") > 0),
            "image_size": r.get("image_size"),
        })
    out["phonebook_contacts"] = out_phonebook

    # Profile picture EXTERNAL_DATA folder
    ext_folder = None
    if case.group_app:
        cand = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "SamparkV2",
                            ".SamparkV2_SUPPORT", "_EXTERNAL_DATA")
        if os.path.isdir(cand):
            ext_folder = cand
    image_files = []
    if ext_folder:
        for n in os.listdir(ext_folder):
            full = os.path.join(ext_folder, n)
            if os.path.isfile(full):
                image_files.append({"name": n, "size": os.path.getsize(full), "path": full})
    out["external_data"] = {
        "folder": ext_folder,
        "image_count": len(image_files),
        "images": image_files,
    }

    out["summary"].update({
        "cyclops_total": len(out_cyclops),
        "phonebook_total": len(out_phonebook),
        "on_phonepe_count": on_phonepe,
        "has_external_vpa_count": has_vpa,
        "deleted_contacts": deleted,
        "external_image_count": len(image_files),
    })
    return out


# ---------------------------------------------------------------------------
# Chat & Groups (Burble = the actual P2P messaging system)
# ---------------------------------------------------------------------------

def _resolve_member_blob(blob: Any) -> Dict[str, Any]:
    """Decode the ZMATTRIBUTES profileSnapshot bplist.

    Returns: {phonepeName, maskedPhoneNumber, phonepe_flag}
    """
    if not blob:
        return {}
    decoded = safe_decode_blob(blob)
    if not isinstance(decoded, dict):
        return {}
    snapshot = decoded.get("profileSnapshot") or decoded
    if isinstance(snapshot, dict):
        return {
            "phonepe_name": snapshot.get("phonepeName"),
            "masked_phone": snapshot.get("maskedPhoneNumber"),
            "phonepe_flag": snapshot.get("phonepe"),
        }
    return {}


def _sanitize_payload(obj: Any, depth: int = 0) -> Any:
    """Recursively coerce a decoded bplist into template-safe primitives."""
    if depth > 12:
        return "…"
    if isinstance(obj, dict):
        return {str(k): _sanitize_payload(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_payload(v, depth + 1) for v in obj]
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _decode_chat_payload(blob: Any) -> Optional[Dict[str, Any]]:
    """Decode a ZCONTENT.ZCONTENT payload bplist into a plain dict.

    Every Burble chat row — whatever its content type — carries a structured
    NSKeyedArchiver payload in this column. Decoding it generically means no
    field of any card type (CONTACT bank details, TRANSACTION_RECEIPT recharge
    info, or a future type the flat-column extractor never anticipated) is
    silently dropped from the conversation view.
    """
    if not blob:
        return None
    decoded = safe_decode_blob(blob)
    if not isinstance(decoded, dict):
        return None
    return _sanitize_payload(decoded)


def extract_chat(case: CasePaths) -> Dict[str, Any]:
    """Burble.sqlite: groups (P2P conversations), messages, payment cards.

    Each ZGROUP = a 1:1 or many-party conversation (named after counterparty).
    ZMESSAGE entries are linked to ZCONTENT (payload) and to
    ZGROUPMEMBERSOURCE / ZGROUPMEMBERDESTINATION (party identifiers). The
    actual party display name + masked phone live in ZGROUPMEMBER as a
    NSKeyedArchiver `profileSnapshot` BLOB in ZMATTRIBUTES.
    """
    out: Dict[str, Any] = {
        "groups": [],
        "messages": [],
        "shared_contacts": [],
        "members": [],
        "summary": {},
        "errors": [],
    }
    db_path = None
    if case.group_app:
        cand = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "Burble", "Burble.sqlite")
        if os.path.exists(cand):
            db_path = cand
    if not db_path:
        out["errors"].append("Burble.sqlite not found")
        return out

    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        out["summary"]["deletion_signals"] = db.deletion_signals()
        groups = db.query("""
            SELECT gm.ZGROUPID, gm.ZNAME, gm.ZGROUPSTATUSVALUE, gm.ZNAMESPACE,
                   gm.ZIMAGEURL, gm.ZCREATEDAT, gm.ZUPDATEDAT, gm.ZACTIVE,
                   gm.ZVISIBILITYVALUE, g.ZGROUPTYPE, g.ZSUBSYSTEMTYPE, g.ZSUBSCRIPTIONSTATUS,
                   gm.Z_PK as meta_pk, g.Z_PK as group_pk,
                   cm.ZRESTORECOMPLETED, cm.ZLASTREADTIMESTAMP, cm.ZUNREADMESSAGECOUNT
            FROM ZGROUPMETA gm
            LEFT JOIN ZGROUP g ON gm.ZGROUP = g.Z_PK
            LEFT JOIN ZGROUPCLIENTMETA cm ON cm.ZGROUP = g.Z_PK
            ORDER BY gm.ZCREATEDAT DESC
        """)

        # Member directory: ZGROUPMEMBER holds the human-readable name and the
        # NSKeyedArchiver profileSnapshot. ZMEMBERSOURCE / ZMEMBERDESTINATION
        # are FKs into ZGROUPMEMBERSOURCE / ZGROUPMEMBERDESTINATION which the
        # ZMESSAGE row references. We index by both source-PK and dest-PK
        # so we can resolve sender + receiver in O(1).
        members = db.query("""
            SELECT Z_PK, ZGROUP, ZADDEDON, ZGROUPACCEPTED, ZPHONEPE, ZPHONEPENAME,
                   ZID, ZPUBLICID, ZROLEVALUE, ZMEMBERSTATEVALUE,
                   ZMEMBERSOURCE, ZMEMBERDESTINATION, ZMATTRIBUTES,
                   ZADDEDBY
            FROM ZGROUPMEMBER
        """)
        member_by_source: Dict[Any, Dict[str, Any]] = {}
        member_by_dest: Dict[Any, Dict[str, Any]] = {}
        member_records: List[Dict[str, Any]] = []
        # We'll need group-pk -> group-id mapping shortly
        groupid_by_pk = {r.get("group_pk"): r.get("ZGROUPID") for r in groups if "_error" not in r}

        for m in members:
            if "_error" in m:
                continue
            attrs = _resolve_member_blob(m.get("ZMATTRIBUTES"))
            display_name = m.get("ZPHONEPENAME") or attrs.get("phonepe_name")
            phonepe_user = bool(m.get("ZPHONEPE"))
            # Burble convention: the device owner ("self") is stored as a
            # member row with NO display name and phonepe_user=False — the
            # app derives identity from the auth token rather than denormalising
            # it here. Counterparties always have a name + phonepe flag.
            is_self = (display_name is None and not phonepe_user)
            rec = {
                "z_pk": m.get("Z_PK"),
                "group_pk": m.get("ZGROUP"),
                "group_id": groupid_by_pk.get(m.get("ZGROUP")),
                "phonepe_user": phonepe_user,
                "display_name": display_name,
                "masked_phone": attrs.get("masked_phone"),
                "role": m.get("ZROLEVALUE"),
                "state": m.get("ZMEMBERSTATEVALUE"),
                "added_on": normalize_timestamp(m.get("ZADDEDON")),
                "accepted": bool(m.get("ZGROUPACCEPTED")),
                "added_by": m.get("ZADDEDBY"),
                "internal_id": m.get("ZID"),
                "public_id": m.get("ZPUBLICID"),
                "is_self": is_self,
            }
            member_records.append(rec)
            src = m.get("ZMEMBERSOURCE")
            dst = m.get("ZMEMBERDESTINATION")
            if src is not None:
                member_by_source[src] = rec
            if dst is not None:
                member_by_dest[dst] = rec

        out["members"] = member_records

        # Group member counts (PHONE-typed members only — those are real parties)
        member_counts = db.query("""
            SELECT ZGROUPID, COUNT(DISTINCT ZGROUPMEMBERID) as member_count
            FROM ZGROUPMEMBERDESTINATION WHERE ZTYPEVALUE='PHONE' GROUP BY ZGROUPID
        """)
        mc_by_group = {r.get("ZGROUPID"): r.get("member_count") for r in member_counts if "_error" not in r}

        messages = db.query("""
            SELECT M.Z_PK as msg_pk, M.ZMESSAGEID, M.ZTHREADID, M.ZISVISIBLE,
                   M.ZGROUPMEMBERSOURCE, M.ZGROUPMEMBERDESTINATION,
                   C.ZCONTENTTYPEVALUE, C.ZCONTENT as PAYLOAD_BLOB,
                   C.ZTEXT, C.ZAMOUNT, C.ZCREATEDAT,
                   C.ZTRANSACTIONID, C.ZNOTE, C.ZSTATEVALUE, C.ZPAYMENTSTATEVALUE,
                   C.ZRECEIVERTRANSACTIONID, C.ZSENDERTRANSACTIONID, C.ZINSTRUMENTUSEDVALUE,
                   C.ZUTR, C.ZEXTERNALVPA, C.ZEXTERNALVPACBSNAME,
                   C.ZGIFTMESSAGE, C.ZREWARDTYPE, C.ZTEXTMESSAGE, C.ZMESSAGESTRING,
                   C.ZPAYMENTTITLE, C.ZPAYMENTSTATE, C.ZPREVIEWURL, C.ZLOCALFILEURL,
                   C.ZASPECTRATIO, C.ZACTIONTYPE, C.ZHOMEACTIONTYPE,
                   C.ZREQUESTID, C.ZREQUESTSTATEVALUE,
                   C.ZAMOUNT1, C.ZAMOUNT2, C.ZEXPIRESAT, C.ZLASTREMINDEDTIMESTAMP,
                   C.ZRECEIVER, C.ZSENDER, C.ZNOTE1,
                   P.ZCREATEDAT as PB_CREATEDAT, P.ZUPDATEDAT as PB_UPDATEDAT,
                   P.ZID as PB_ID, P.ZSERVERID as PB_SERVERID
            FROM ZMESSAGE M
            LEFT JOIN ZCONTENT C ON M.ZCONTENT = C.Z_PK
            LEFT JOIN ZPBCOREMESSAGE P ON M.ZPUBSUBMESSAGE = P.Z_PK
            ORDER BY COALESCE(P.ZCREATEDAT, C.ZCREATEDAT, 0) DESC
        """)
        shared = db.query("SELECT * FROM ZSHAREDCONTACT")

    out_groups: List[Dict[str, Any]] = []
    for r in groups:
        if "_error" in r:
            continue
        out_groups.append({
            "group_id": r.get("ZGROUPID"),
            "name": r.get("ZNAME"),
            "status": r.get("ZGROUPSTATUSVALUE"),
            "namespace": r.get("ZNAMESPACE"),
            "image_url": r.get("ZIMAGEURL"),
            "type": r.get("ZGROUPTYPE"),
            "subsystem": r.get("ZSUBSYSTEMTYPE"),
            "subscription": r.get("ZSUBSCRIPTIONSTATUS"),
            "active": bool(r.get("ZACTIVE")),
            "visibility": r.get("ZVISIBILITYVALUE"),
            "created_at": normalize_timestamp(r.get("ZCREATEDAT")),
            "updated_at": normalize_timestamp(r.get("ZUPDATEDAT")),
            "member_count": mc_by_group.get(r.get("ZGROUPID")),
            # ZGROUPCLIENTMETA — chat-restore / sync state. restore_completed=0
            # on a group with no messages means the group shell was synced but
            # its message history was never paged down to the device.
            "restore_completed": r.get("ZRESTORECOMPLETED"),
            "last_read_ts": normalize_timestamp(r.get("ZLASTREADTIMESTAMP")),
            "unread_count": r.get("ZUNREADMESSAGECOUNT"),
        })
    out["groups"] = out_groups

    payment_cards = 0
    text_messages = 0
    image_attachments = 0
    rewards_gifts = 0
    requests = 0
    total_payment_inr = 0.0
    msg_records: List[Dict[str, Any]] = []

    for r in messages:
        if "_error" in r:
            continue
        ctype = r.get("ZCONTENTTYPEVALUE") or "UNKNOWN"
        amount_paise = r.get("ZAMOUNT")
        amount_inr = amount_to_rupees(amount_paise) if amount_paise is not None else None
        if ctype == "PAYMENT_INFO_CARD":
            payment_cards += 1
            if amount_inr and (r.get("ZSTATEVALUE") or r.get("ZPAYMENTSTATEVALUE")) in ("COMPLETED", "SUCCESS", None):
                total_payment_inr += amount_inr
        elif ctype == "TEXT_MESSAGE":
            text_messages += 1
        elif ctype == "IMAGE_ATTACHMENT":
            image_attachments += 1
        elif "REWARD" in ctype.upper() or "GIFT" in ctype.upper():
            rewards_gifts += 1
        elif "REQUEST" in ctype.upper():
            requests += 1

        # Resolve party names via ZGROUPMEMBERSOURCE / ZGROUPMEMBERDESTINATION
        src_member = member_by_source.get(r.get("ZGROUPMEMBERSOURCE"))
        dst_member = member_by_dest.get(r.get("ZGROUPMEMBERDESTINATION"))
        sender_name = src_member.get("display_name") if src_member else None
        sender_phone = src_member.get("masked_phone") if src_member else None
        receiver_name = dst_member.get("display_name") if dst_member else None
        receiver_phone = dst_member.get("masked_phone") if dst_member else None

        text_content = (
            r.get("ZMESSAGESTRING") or r.get("ZTEXTMESSAGE") or r.get("ZTEXT")
        )

        # PubSubCore message has the canonical creation timestamp for ALL
        # message types (text, image, payment card, gift). The ZCONTENT.ZCREATEDAT
        # is only populated for some payload types (e.g. PAYMENT_INFO_CARD).
        ts_raw = r.get("PB_CREATEDAT") or r.get("ZCREATEDAT")
        updated_raw = r.get("PB_UPDATEDAT")

        # Direction marker: in Burble's data model the device owner ("self")
        # is stored as a member row with no display_name + phonepe_user=False.
        # If the source-side member is self, this is an outgoing message;
        # otherwise it's incoming. We fall back to txn-id heuristics if
        # the join didn't resolve a member.
        is_outgoing: Optional[bool] = None
        if src_member is not None:
            is_outgoing = bool(src_member.get("is_self"))
        elif dst_member is not None:
            is_outgoing = not bool(dst_member.get("is_self"))
        if is_outgoing is None:
            if r.get("ZSENDERTRANSACTIONID") and not r.get("ZRECEIVERTRANSACTIONID"):
                is_outgoing = True
            elif r.get("ZRECEIVERTRANSACTIONID") and not r.get("ZSENDERTRANSACTIONID"):
                is_outgoing = False

        # Resolve other-party name (the counterparty in the conversation),
        # which is whichever side ISN'T self. This is what UIs should show
        # as "from / to" in chat list views.
        if src_member and not src_member.get("is_self"):
            other_party_name = src_member.get("display_name")
            other_party_phone = src_member.get("masked_phone")
        elif dst_member and not dst_member.get("is_self"):
            other_party_name = dst_member.get("display_name")
            other_party_phone = dst_member.get("masked_phone")
        else:
            other_party_name = None
            other_party_phone = None

        msg_records.append({
            "message_id": r.get("ZMESSAGEID"),
            "thread_id": r.get("ZTHREADID"),
            "type": ctype,
            "amount_inr": amount_inr,
            "transaction_id": r.get("ZTRANSACTIONID"),
            "receiver_txn_id": r.get("ZRECEIVERTRANSACTIONID"),
            "sender_txn_id": r.get("ZSENDERTRANSACTIONID"),
            "state": r.get("ZSTATEVALUE"),
            "payment_state": r.get("ZPAYMENTSTATEVALUE") or r.get("ZPAYMENTSTATE"),
            "instrument": r.get("ZINSTRUMENTUSEDVALUE"),
            "utr": r.get("ZUTR"),
            "external_vpa": r.get("ZEXTERNALVPA"),
            "external_bank": r.get("ZEXTERNALVPACBSNAME"),
            "note": r.get("ZNOTE") or r.get("ZNOTE1"),
            "text_message": text_content,
            "gift_message": r.get("ZGIFTMESSAGE"),
            "reward_type": r.get("ZREWARDTYPE"),
            "payment_title": r.get("ZPAYMENTTITLE"),
            "preview_url": r.get("ZPREVIEWURL"),
            "local_file": r.get("ZLOCALFILEURL"),
            "request_id": r.get("ZREQUESTID"),
            "request_state": r.get("ZREQUESTSTATEVALUE"),
            # generically-decoded payload — every field of every card type,
            # so CONTACT / TRANSACTION_RECEIPT / unknown types are never blank
            "decoded_payload": _decode_chat_payload(r.get("PAYLOAD_BLOB")),
            "expires_at": normalize_timestamp(r.get("ZEXPIRESAT")),
            "last_reminded": normalize_timestamp(r.get("ZLASTREMINDEDTIMESTAMP")),
            "created_at": normalize_timestamp(ts_raw),
            "updated_at": normalize_timestamp(updated_raw),
            "visible": bool(r.get("ZISVISIBLE")) if r.get("ZISVISIBLE") is not None else None,
            "sender_name": sender_name,
            "sender_phone_masked": sender_phone,
            "sender_role": src_member.get("role") if src_member else None,
            "sender_is_self": src_member.get("is_self") if src_member else None,
            "receiver_name": receiver_name,
            "receiver_phone_masked": receiver_phone,
            "receiver_role": dst_member.get("role") if dst_member else None,
            "receiver_is_self": dst_member.get("is_self") if dst_member else None,
            "other_party_name": other_party_name,
            "other_party_phone": other_party_phone,
            "direction": "OUT" if is_outgoing is True else ("IN" if is_outgoing is False else None),
            "is_outgoing": is_outgoing,
        })

    # Enrich messages with group_name (counterparty header in 1:1 conversations)
    group_name_by_id = {g["group_id"]: g.get("name") for g in out_groups}
    for m in msg_records:
        m["group_name"] = group_name_by_id.get(m.get("thread_id"))
        # If the per-message resolver couldn't find a counterparty (NULL members
        # in some old chats), fall back to the group name itself.
        if not m.get("other_party_name"):
            m["other_party_name"] = m["group_name"]

    out["messages"] = msg_records

    out_shared: List[Dict[str, Any]] = []
    for r in shared:
        if "_error" in r:
            continue
        out_shared.append({
            "type": r.get("ZCONTACTTYPE"),
            "verified": bool(r.get("ZISVERIFIED")),
            "account_holder": r.get("ZACCOUNTHOLDERNAME"),
            "account_number": r.get("ZACCOUNTNUMBER"),
            "bank_id": r.get("ZBANKID"),
            "bank_name": r.get("ZBANKNAME"),
            "ifsc": r.get("ZIFSC"),
            "phone": r.get("ZPHONE"),
            "vpa": r.get("ZFULL_VPA"),
            "name": r.get("ZNAME") or r.get("ZNAME1") or r.get("ZNAME2"),
            "cbs_name": r.get("ZCBSNAME"),
        })
    out["shared_contacts"] = out_shared

    out["summary"].update({
        "group_count": len(out_groups),
        "message_count": len(msg_records),
        "member_count": len(member_records),
        "payment_cards": payment_cards,
        "text_messages": text_messages,
        "image_attachments": image_attachments,
        "rewards_gifts": rewards_gifts,
        "money_requests": requests,
        "total_payment_inr": round(total_payment_inr, 2),
        "shared_account_disclosures": len(out_shared),
    })
    return out


# ---------------------------------------------------------------------------
# Notifications & Push (PubSubCore Bullhorn)
# ---------------------------------------------------------------------------

def extract_notifications(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"topics": [], "raw_messages": [], "summary": {}, "errors": []}
    db_path = case.resolve(
        "Documents", "PubSubCore", "Database", "PubSubCoreBullhornDataStore",
        "PubSubCoreBullhornDataStore.sqlite",
    )
    if not db_path:
        out["errors"].append("PubSubCoreBullhornDataStore.sqlite not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        topics = db.query("""
            SELECT ZTOPICID, ZSUBSYSTEMTYPE, ZMESSAGESTORAGETYPE,
                   ZCREATEDDATE, ZUPDATEDDATE, ZMESSAGEEXPIRY, ZSINGLEUSE
            FROM ZTOPIC
            ORDER BY ZUPDATEDDATE DESC
        """)
        topic_meta = db.query("""
            SELECT ZTOPICID, ZSUBSYSTEM, ZSTATUS, ZSUBSCRIPTIONSTATUS,
                   ZLASTMESSAGESYNCTIME, ZLATESTPOINTER, ZOLDESTPOINTER
            FROM ZTOPICINTERNALMETA
        """)
        msg_count_per_topic = db.query("""
            SELECT ZTOPICID, COUNT(*) as cnt
            FROM ZMESSAGERAWENTITY GROUP BY ZTOPICID
        """)
        mr_counts = {r.get("ZTOPICID"): r.get("cnt") for r in msg_count_per_topic if "_error" not in r}
        meta_by_topic = {r.get("ZTOPICID"): r for r in topic_meta if "_error" not in r}

    subsystems = Counter()
    storage_types = Counter()
    for t in topics:
        if "_error" in t:
            continue
        sub = t.get("ZSUBSYSTEMTYPE") or "?"
        subsystems[sub] += 1
        storage_types[t.get("ZMESSAGESTORAGETYPE") or "?"] += 1
        meta = meta_by_topic.get(t.get("ZTOPICID"), {})
        out["topics"].append({
            "topic_id": t.get("ZTOPICID"),
            "subsystem": sub,
            "storage_type": t.get("ZMESSAGESTORAGETYPE"),
            "single_use": bool(t.get("ZSINGLEUSE")),
            "created_at": normalize_timestamp(t.get("ZCREATEDDATE")),
            "updated_at": normalize_timestamp(t.get("ZUPDATEDDATE")),
            "expiry_at": normalize_timestamp(t.get("ZMESSAGEEXPIRY")),
            "subscription_status": meta.get("ZSUBSCRIPTIONSTATUS"),
            "status": meta.get("ZSTATUS"),
            "last_sync": normalize_timestamp(meta.get("ZLASTMESSAGESYNCTIME")),
            "raw_message_count": mr_counts.get(t.get("ZTOPICID"), 0),
        })

    out["summary"].update({
        "topic_count": len(out["topics"]),
        "subsystem_breakdown": dict(subsystems),
        "storage_type_breakdown": dict(storage_types),
    })
    return out


# ---------------------------------------------------------------------------
# Behavioral Analytics (KN, Foxtrot, Dash)
# ---------------------------------------------------------------------------

def extract_analytics(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "kn_events": [], "foxtrot_pending": [], "auth_foxtrot_pending": [],
        "dash_pending": [], "summary": {}, "errors": [],
    }

    # KN analytics db
    db_path = case.resolve("Documents", "KN", "Databases", "kn_analytics_db.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            ev = db.query("""
                SELECT id, eventName, identifier, funnelInfo, timeStamp, primaryKey
                FROM AnalyticEvent ORDER BY id DESC LIMIT 5000
            """)
        kn_grouped = Counter()
        for r in ev:
            if "_error" in r:
                continue
            ts = normalize_timestamp(r.get("timeStamp"))
            kn_grouped[r.get("identifier") or "?"] += 1
            out["kn_events"].append({
                "id": r.get("id"),
                "event_name": r.get("eventName"),
                "identifier": r.get("identifier"),
                "timestamp": ts,
                "primary_key": r.get("primaryKey"),
                "funnel_info_preview": (r.get("funnelInfo") or "")[:200],
            })
        out["summary"]["kn_event_count"] = len(out["kn_events"])
        out["summary"]["kn_funnel_breakdown"] = dict(kn_grouped.most_common(20))

    # Foxtrot batched events (pending upload)
    fox_path = None
    if case.group_app:
        cand = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "FoxtrotEventsStore",
                            "FoxtrotEventsDB.sqlite")
        if os.path.exists(cand):
            fox_path = cand
    if fox_path:
        with SQLiteReader(fox_path) as db:
            fx = db.query("""
                SELECT Z_PK, ZID, ZTIMESTAMP, ZFAILURECOUNT, length(ZDATA) as data_size
                FROM ZPPBATCHEVENT ORDER BY ZTIMESTAMP DESC LIMIT 5000
            """)
        for r in fx:
            if "_error" in r:
                continue
            out["foxtrot_pending"].append({
                "id": r.get("ZID"),
                "timestamp": normalize_timestamp(r.get("ZTIMESTAMP")),
                "failure_count": r.get("ZFAILURECOUNT"),
                "data_size": r.get("data_size"),
            })
        out["summary"]["foxtrot_pending_count"] = len(out["foxtrot_pending"])

    # Auth Foxtrot
    auth_fox = case.resolve("Documents", "AuthFoxtrotEventsBatching", "PPAuthFoxtrotEventsDB.sqlite")
    if auth_fox:
        with SQLiteReader(auth_fox) as db:
            af = db.query("""
                SELECT Z_PK, ZID, ZTIMESTAMP, ZFAILURECOUNT, length(ZDATA) as data_size
                FROM ZPPBATCHEVENT ORDER BY ZTIMESTAMP DESC LIMIT 5000
            """)
        for r in af:
            if "_error" in r:
                continue
            out["auth_foxtrot_pending"].append({
                "id": r.get("ZID"),
                "timestamp": normalize_timestamp(r.get("ZTIMESTAMP")),
                "failure_count": r.get("ZFAILURECOUNT"),
                "data_size": r.get("data_size"),
            })
        out["summary"]["auth_foxtrot_pending_count"] = len(out["auth_foxtrot_pending"])

    # Dash
    dash = case.resolve("Documents", "Dash_Event_Batching", "Dash-Events.sqlite")
    if dash:
        with SQLiteReader(dash) as db:
            de = db.query("""
                SELECT ZID, ZTIMESTAMP, ZFAILURECOUNT, length(ZDATA) as data_size
                FROM ZPPBATCHEVENT ORDER BY ZTIMESTAMP DESC LIMIT 1000
            """)
        for r in de:
            if "_error" in r:
                continue
            out["dash_pending"].append({
                "id": r.get("ZID"),
                "timestamp": normalize_timestamp(r.get("ZTIMESTAMP")),
                "failure_count": r.get("ZFAILURECOUNT"),
                "data_size": r.get("data_size"),
            })
        out["summary"]["dash_pending_count"] = len(out["dash_pending"])

    return out


# ---------------------------------------------------------------------------
# Financial services (Rewards, MF, Vouchers, Donations, Offers)
# ---------------------------------------------------------------------------

def extract_financial(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "rewards": [], "mutual_funds": [], "vouchers": [], "donations": [],
        "offers": [], "summary": {}, "errors": [],
    }

    # Rewards
    db_path = case.resolve("Documents", "Rewards", "Database", "RewardsDataStore", "RewardsDataStore.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            rows = db.query("""
                SELECT ZREWARDID, ZTYPEVALUE, ZSTATEVALUE, ZREWARDAMOUNT,
                       ZCREATEDAT, ZAVAILABLEAT, ZAVAILEDAT, ZCLAIMEDAT, ZEXPIRESAT,
                       ZTRANSACTIONID, ZGLOBALPAYMENTID, ZOFFERTITLE, ZCOUPONTITLE,
                       ZCOUPONCODE, ZSHAREMESSAGE, ZDISPLAYMESSAGE,
                       ZBATCHID, ZCASHBACKTRANSACTIONID
                FROM ZREWARD ORDER BY ZCREATEDAT DESC
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["rewards"].append({
                "reward_id": r.get("ZREWARDID"),
                "type": r.get("ZTYPEVALUE"),
                "state": r.get("ZSTATEVALUE"),
                "amount_inr": amount_to_rupees(r.get("ZREWARDAMOUNT")),
                "created_at": normalize_timestamp(r.get("ZCREATEDAT")),
                "available_at": normalize_timestamp(r.get("ZAVAILABLEAT")),
                "claimed_at": normalize_timestamp(r.get("ZCLAIMEDAT")),
                "expires_at": normalize_timestamp(r.get("ZEXPIRESAT")),
                "linked_transaction": r.get("ZTRANSACTIONID") or r.get("ZGLOBALPAYMENTID"),
                "title": r.get("ZOFFERTITLE") or r.get("ZCOUPONTITLE"),
                "coupon_code": r.get("ZCOUPONCODE"),
                "share_message": r.get("ZSHAREMESSAGE"),
                "display_message": r.get("ZDISPLAYMESSAGE"),
                "cashback_txn": r.get("ZCASHBACKTRANSACTIONID"),
            })
        out["summary"]["rewards_count"] = len(out["rewards"])

    # MFDataStore
    db_path = case.resolve("Documents", "MutualFunds", "Database", "MFDataStore", "MFDataStore.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            rows = db.query("""
                SELECT ZFUNDID, ZAMCNAME, ZFUNDNAME, ZFUNDCATEGORYDISPLAYTYPE,
                       ZENABLE, ZLOCALUPDATEDAT
                FROM ZMFFUNDSLITE ORDER BY ZLOCALUPDATEDAT DESC
            """)
        for r in rows[:5000]:
            if "_error" in r:
                continue
            out["mutual_funds"].append({
                "fund_id": r.get("ZFUNDID"),
                "amc": r.get("ZAMCNAME"),
                "name": r.get("ZFUNDNAME"),
                "category": r.get("ZFUNDCATEGORYDISPLAYTYPE"),
                "enabled": bool(r.get("ZENABLE")),
                "updated_at": normalize_timestamp(r.get("ZLOCALUPDATEDAT")),
            })
        out["summary"]["mf_catalogue_count"] = len(out["mutual_funds"])

    # BrandVouchers
    db_path = case.resolve("Documents", "BrandVouchers", "Database", "BrandVouchersDataStore", "BrandVouchersDataStore.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            cats = db.query("SELECT ZCATEGORYID, ZDISPLAYNAME, ZSTATUSVALUE FROM ZBVCATEGORY")
        out["voucher_categories"] = [{
            "id": r.get("ZCATEGORYID"),
            "name": r.get("ZDISPLAYNAME"),
            "status": r.get("ZSTATUSVALUE"),
        } for r in cats if "_error" not in r]
        out["summary"]["voucher_category_count"] = len(out.get("voucher_categories") or [])

    # Donations
    db_path = case.resolve("Documents", "Donations", "Database", "DonationsDataStore", "DonationsDataStore.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            rows = db.query("""
                SELECT ZCAMPAIGNID, ZCATEGORYID, ZDISPLAYNAME, ZSUBDISPLAYNAME,
                       ZSTATUS, ZCREATEDAT, ZPRICE, ZISACTIVE
                FROM ZDNPROVIDERDETAILS ORDER BY ZCREATEDAT DESC
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["donations"].append({
                "campaign_id": r.get("ZCAMPAIGNID"),
                "category_id": r.get("ZCATEGORYID"),
                "name": r.get("ZDISPLAYNAME"),
                "subname": r.get("ZSUBDISPLAYNAME"),
                "status": r.get("ZSTATUS"),
                "price_inr": amount_to_rupees(r.get("ZPRICE")),
                "active": bool(r.get("ZISACTIVE")),
                "created_at": normalize_timestamp(r.get("ZCREATEDAT")),
            })
        out["summary"]["donation_provider_count"] = len(out["donations"])

    # Offers
    db_path = case.resolve("Documents", "Offers", "Database", "OffersDataStore", "OffersDataStore.sqlite")
    if db_path:
        with SQLiteReader(db_path) as db:
            rows = db.query("""
                SELECT ZOFFERID, ZACTIONTEXT, ZCATEGORYID, ZSTATEVALUE, ZTYPEVALUE,
                       ZSTARTDATE, ZENDDATE, ZLISTHEROTEXT, ZOFFERPROVIDERTITLE
                FROM ZGRANTINGOFFER ORDER BY ZSTARTDATE DESC
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["offers"].append({
                "offer_id": r.get("ZOFFERID"),
                "title": r.get("ZLISTHEROTEXT") or r.get("ZOFFERPROVIDERTITLE"),
                "action": r.get("ZACTIONTEXT"),
                "category_id": r.get("ZCATEGORYID"),
                "state": r.get("ZSTATEVALUE"),
                "type": r.get("ZTYPEVALUE"),
                "starts": normalize_timestamp(r.get("ZSTARTDATE")),
                "ends": normalize_timestamp(r.get("ZENDDATE")),
            })
        out["summary"]["offers_count"] = len(out["offers"])

    return out


# ---------------------------------------------------------------------------
# Travel (Yatra)
# ---------------------------------------------------------------------------

def extract_travel(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"journeys": [], "actions": [], "summary": {}, "errors": []}
    db_path = case.resolve("Documents", "Yatra", "Database", "YatraDataStore", "YatraDataModel.sqlite")
    if not db_path:
        out["errors"].append("YatraDataModel.sqlite not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        rows = db.query("""
            SELECT ZJOURNEYID, ZNAME, ZJDESCRIPTION, ZNAMESPACE, ZTYPE, ZSTATE,
                   ZENTITYTYPE, ZCREATEDAT, ZUPDATEDAT
            FROM ZCDYJOURNEY ORDER BY ZCREATEDAT DESC
        """)
        actions = db.query("""
            SELECT ZJOURNEY, ZNAME, ZTYPE, ZADESCRIPTION
            FROM ZCDYACTION
        """)
    state_breakdown = Counter()
    type_breakdown = Counter()
    for r in rows:
        if "_error" in r:
            continue
        state_breakdown[r.get("ZSTATE") or "?"] += 1
        type_breakdown[r.get("ZTYPE") or "?"] += 1
        out["journeys"].append({
            "journey_id": r.get("ZJOURNEYID"),
            "name": r.get("ZNAME"),
            "description": r.get("ZJDESCRIPTION"),
            "namespace": r.get("ZNAMESPACE"),
            "type": r.get("ZTYPE"),
            "state": r.get("ZSTATE"),
            "entity_type": r.get("ZENTITYTYPE"),
            "created_at": normalize_timestamp(r.get("ZCREATEDAT")),
            "updated_at": normalize_timestamp(r.get("ZUPDATEDAT")),
        })
    for r in actions:
        if "_error" in r:
            continue
        out["actions"].append({
            "journey_pk": r.get("ZJOURNEY"),
            "name": r.get("ZNAME"),
            "type": r.get("ZTYPE"),
            "description": r.get("ZADESCRIPTION"),
        })
    out["summary"].update({
        "journey_count": len(out["journeys"]),
        "action_count": len(out["actions"]),
        "state_breakdown": dict(state_breakdown),
        "type_breakdown": dict(type_breakdown),
    })
    return out


# ---------------------------------------------------------------------------
# Payment infrastructure (banks, UPI containers, VPAs)
# ---------------------------------------------------------------------------

def extract_payment_infra(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "linked_accounts": [], "linked_vpas": [], "psp_handles": [],
        "upi_lite": None, "linked_cards": [], "wallet": None,
        "supported_banks": [], "summary": {}, "errors": [],
    }
    db_path = case.resolve("Documents", "Payment", "Database", "PaymentDataStore", "PaymentDataStore.sqlite")
    if not db_path:
        out["errors"].append("PaymentDataStore.sqlite not found")
        return out
    out["summary"]["db_sha256"] = hash_file(db_path)
    with SQLiteReader(db_path) as db:
        accounts = db.query("""
            SELECT ZACCOUNTNO, ZACCOUNTHOLDERNAME, ZACCOUNTID, ZACCOUNTALIAS,
                   ZACCOUNTTYPEVALUE, ZUSAGEDOMAINVALUE, ZISPRIMARY, ZLOCALUPDATEDAT
            FROM ZPCDBANKACCOUNT
        """)
        vpas = db.query("SELECT ZVPAPREFIX FROM ZPCDUPIVPADETAIL")
        psps = db.query("SELECT ZPSPHANDLE, ZISACTIVE FROM ZPCDPHONEPEPSP")
        psp_details = db.query("SELECT ZPSP, ZISONBOARDED FROM ZPCDUPIPSPDETAIL")
        lite = db.query("""
            SELECT ZISUPILITEELIGIBLE, ZISAUTOTOPUPSUPPORTED, ZISWITHDRAWALSUPPORTED,
                   ZISUPIOFFLINEELIGIBLE
            FROM ZPCDUPILITE LIMIT 1
        """)
        cards = db.query("""
            SELECT ZCARDID, ZCARDALIAS, ZCARDTYPEVALUE, ZCARDISSUER, ZBANKCODE,
                   ZMASKEDCARDNUMBER, ZCARDHOLDERNAME, ZCARDSTATUSVALUE,
                   ZCOBRANDINGPARTNER, ZLOCALUPDATEDAT
            FROM ZPCDCARD
        """)
        wallet = db.query("SELECT ZBALANCE, ZTIMESTAMP FROM ZPCDEGV LIMIT 1")
        ext_wallet = db.query("""
            SELECT ZNAME, ZBALANCE, ZSTATEVALUE, ZISACTIVE, ZMOBILENUMBER, ZPROVIDERID
            FROM ZPCDEXTERNALWALLET
        """)
        banks = db.query("""
            SELECT ZID, ZNAME, ZIMAGEURL, ZCENTRALIFSC, ZIFSCPREFIX,
                   ZISUPISUPPORTED, ZISUPIMANDATESUPPORTED, ZISCREDITCARDONUPISUPPORTED,
                   ZISPARTNER, ZISACTIVE, ZUPILITESUPPORTED
            FROM ZPCDBANK ORDER BY ZNAME
        """)
        upi_container = db.query("""
            SELECT ZBANKID, ZACCOUNTIFSC, ZACCOUNTLIMIT, ZACCOUNTMAXLIMIT,
                   ZISACTIVE, ZISLINKED
            FROM ZPCDUPICONTAINER LIMIT 5
        """)
        intl = db.query("""
            SELECT ZACTIVE, ZELIGIBLE, ZPROCESSING FROM ZPCDUPIINTERNATIONALDETAIL LIMIT 1
        """)
        approvers = db.query("""
            SELECT ZAPPROVERVPA, ZCONTACTNAME, ZCONTACTNUMBER, ZAPPROVERTYPE,
                   ZLINKINGTYPE, ZEXPIRYTS, ZISCONSENTNEEDED
            FROM ZPCDAPPROVER
        """)

    for r in accounts:
        if "_error" in r:
            continue
        out["linked_accounts"].append({
            "account_no_masked": r.get("ZACCOUNTNO"),
            "account_holder": r.get("ZACCOUNTHOLDERNAME"),
            "account_alias": r.get("ZACCOUNTALIAS"),
            "account_type": r.get("ZACCOUNTTYPEVALUE"),
            "is_primary": bool(r.get("ZISPRIMARY")),
            "updated_at": normalize_timestamp(r.get("ZLOCALUPDATEDAT")),
        })
    out["linked_vpas"] = [r.get("ZVPAPREFIX") for r in vpas if "_error" not in r]
    out["psp_handles"] = [{
        "handle": r.get("ZPSPHANDLE"), "active": bool(r.get("ZISACTIVE"))
    } for r in psps if "_error" not in r]
    out["psp_onboarded"] = [{
        "psp": r.get("ZPSP"), "onboarded": bool(r.get("ZISONBOARDED"))
    } for r in psp_details if "_error" not in r]
    if lite and "_error" not in lite[0]:
        out["upi_lite"] = {
            "eligible": bool(lite[0].get("ZISUPILITEELIGIBLE")),
            "auto_topup": bool(lite[0].get("ZISAUTOTOPUPSUPPORTED")),
            "offline_eligible": bool(lite[0].get("ZISUPIOFFLINEELIGIBLE")),
            "withdrawal": bool(lite[0].get("ZISWITHDRAWALSUPPORTED")),
        }
    for r in cards:
        if "_error" in r:
            continue
        out["linked_cards"].append({
            "card_id": r.get("ZCARDID"),
            "alias": r.get("ZCARDALIAS"),
            "type": r.get("ZCARDTYPEVALUE"),
            "issuer": r.get("ZCARDISSUER"),
            "bank_code": r.get("ZBANKCODE"),
            "masked": r.get("ZMASKEDCARDNUMBER"),
            "holder": r.get("ZCARDHOLDERNAME"),
            "status": r.get("ZCARDSTATUSVALUE"),
            "cobranding": r.get("ZCOBRANDINGPARTNER"),
            "updated_at": normalize_timestamp(r.get("ZLOCALUPDATEDAT")),
        })
    if wallet and "_error" not in wallet[0]:
        out["wallet"] = {
            "balance_inr": amount_to_rupees(wallet[0].get("ZBALANCE")),
            "timestamp": normalize_timestamp(wallet[0].get("ZTIMESTAMP")),
        }
    out["external_wallets"] = [{
        "name": r.get("ZNAME"),
        "balance_inr": amount_to_rupees(r.get("ZBALANCE")),
        "state": r.get("ZSTATEVALUE"),
        "active": bool(r.get("ZISACTIVE")),
        "phone": r.get("ZMOBILENUMBER"),
        "provider": r.get("ZPROVIDERID"),
    } for r in ext_wallet if "_error" not in r]
    out["supported_banks"] = [{
        "id": r.get("ZID"), "name": r.get("ZNAME"),
        "ifsc_prefix": r.get("ZIFSCPREFIX"), "central_ifsc": r.get("ZCENTRALIFSC"),
        "upi": bool(r.get("ZISUPISUPPORTED")), "upi_mandate": bool(r.get("ZISUPIMANDATESUPPORTED")),
        "ccupi": bool(r.get("ZISCREDITCARDONUPISUPPORTED")),
        "lite": bool(r.get("ZUPILITESUPPORTED")),
        "active": bool(r.get("ZISACTIVE")), "partner": bool(r.get("ZISPARTNER")),
    } for r in banks if "_error" not in r]
    if upi_container and "_error" not in upi_container[0]:
        c = upi_container[0]
        out["upi_container"] = {
            "bank_id": c.get("ZBANKID"), "ifsc": c.get("ZACCOUNTIFSC"),
            "active": bool(c.get("ZISACTIVE")), "linked": bool(c.get("ZISLINKED")),
            "limit_paise": c.get("ZACCOUNTLIMIT"),
            "max_limit_paise": c.get("ZACCOUNTMAXLIMIT"),
        }
    if intl and "_error" not in intl[0]:
        out["upi_international"] = {
            "active": bool(intl[0].get("ZACTIVE")),
            "eligible": bool(intl[0].get("ZELIGIBLE")),
            "processing": bool(intl[0].get("ZPROCESSING")),
        }
    out["approvers_recent"] = [{
        "approver_vpa": r.get("ZAPPROVERVPA"),
        "contact_name": r.get("ZCONTACTNAME"),
        "contact_number": r.get("ZCONTACTNUMBER"),
        "type": r.get("ZAPPROVERTYPE"),
        "linking_type": r.get("ZLINKINGTYPE"),
        "expiry": normalize_timestamp(r.get("ZEXPIRYTS")),
        "consent_needed": bool(r.get("ZISCONSENTNEEDED")),
    } for r in approvers if "_error" not in r]
    out["summary"].update({
        "linked_account_count": len(out["linked_accounts"]),
        "linked_vpa_count": len(out["linked_vpas"]),
        "psp_count": len(out["psp_handles"]),
        "card_count": len(out["linked_cards"]),
        "supported_bank_count": len(out["supported_banks"]),
        "external_wallet_count": len(out.get("external_wallets") or []),
    })
    return out


# ---------------------------------------------------------------------------
# Configuration / experimentation snapshot
# ---------------------------------------------------------------------------

def extract_config_state(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "config_keys": [], "chimera_responses": [], "liquid_ui_responses": [],
        "experiments": [], "buckets": [], "summary": {}, "errors": [],
    }
    # Config Manager Key Store
    p = case.resolve("Documents", "ConfigManager", "Database", "ConfigManagerKeyStore", "ConfigManagerKeyStore.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("SELECT ZKEY, ZTEAM, ZORG, ZVALUE FROM ZKEYVALUESTORE ORDER BY ZKEY")
        for r in rows:
            if "_error" in r:
                continue
            out["config_keys"].append({
                "key": r.get("ZKEY"), "team": r.get("ZTEAM"), "org": r.get("ZORG"),
                "value_preview": (r.get("ZVALUE") or "")[:300],
                "value_size": len(r.get("ZVALUE") or ""),
                "is_json": bool(r.get("ZVALUE") and (r.get("ZVALUE") or "").lstrip().startswith(("{", "["))),
            })
        out["summary"]["config_key_count"] = len(out["config_keys"])

    # Chimera responses
    p = case.resolve("Documents", "ChimeraCore", "Database", "ChimeraCoreResponseStore", "ChimeraCoreResponseStore.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("""
                SELECT ZKEYID, ZTEAM, ZORG, ZMAXVERSION, ZISVERIFIED, length(ZRESPONSE) as size
                FROM ZKEYVALUERESPONSE ORDER BY ZKEYID
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["chimera_responses"].append({
                "key_id": r.get("ZKEYID"), "team": r.get("ZTEAM"), "org": r.get("ZORG"),
                "max_version": r.get("ZMAXVERSION"),
                "verified": r.get("ZISVERIFIED"),
                "response_size": r.get("size"),
            })
        out["summary"]["chimera_response_count"] = len(out["chimera_responses"])

    # LiquidUI responses
    p = case.resolve("Documents", "LiquidUI", "Database", "ChimeraCoreResponseStore", "ChimeraCoreResponseStore.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("""
                SELECT ZKEYID, ZTEAM, ZORG, ZMAXVERSION, length(ZRESPONSE) as size
                FROM ZKEYVALUERESPONSE ORDER BY ZKEYID
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["liquid_ui_responses"].append({
                "key_id": r.get("ZKEYID"), "team": r.get("ZTEAM"),
                "max_version": r.get("ZMAXVERSION"), "response_size": r.get("size"),
            })

    # Athena experiments
    p = case.resolve("Documents", "Athena", "Database", "AthenaStore", "AthenaStore.sqlite")
    if p:
        with SQLiteReader(p) as db:
            exps = db.query("""
                SELECT ZEXPERIMENTID, ZACTIVITYID, ZCLIENTID, ZSUMMARY, ZTYPEVALUE,
                       ZSTATEVALUE, ZMODEVALUE, ZVERSION, ZSTARTDATE, ZENDTIME,
                       ZCREATEDAT, ZUPDATEDAT
                FROM ZPPEXPERIMENT
            """)
            buckets = db.query("""
                SELECT ZBUCKETID, ZNAME, ZSUMMARY, ZSTATUS, ZPERCENTAGE, ZTYPEVALUE,
                       ZEXPERIMENT
                FROM ZPPBUCKET
            """)
        for r in exps:
            if "_error" in r:
                continue
            out["experiments"].append({
                "experiment_id": r.get("ZEXPERIMENTID"),
                "activity_id": r.get("ZACTIVITYID"),
                "client_id": r.get("ZCLIENTID"),
                "summary": r.get("ZSUMMARY"),
                "type": r.get("ZTYPEVALUE"),
                "state": r.get("ZSTATEVALUE"),
                "mode": r.get("ZMODEVALUE"),
                "version": r.get("ZVERSION"),
                "started": normalize_timestamp(r.get("ZSTARTDATE")),
                "ends": normalize_timestamp(r.get("ZENDTIME")),
                "created": normalize_timestamp(r.get("ZCREATEDAT")),
            })
        for r in buckets:
            if "_error" in r:
                continue
            out["buckets"].append({
                "bucket_id": r.get("ZBUCKETID"),
                "name": r.get("ZNAME"),
                "summary": r.get("ZSUMMARY"),
                "status": r.get("ZSTATUS"),
                "percentage": r.get("ZPERCENTAGE"),
                "type": r.get("ZTYPEVALUE"),
                "experiment_pk": r.get("ZEXPERIMENT"),
            })
    out["summary"]["experiment_count"] = len(out["experiments"])
    out["summary"]["bucket_count"] = len(out["buckets"])
    return out


# ---------------------------------------------------------------------------
# Recommendations (Maximus)
# ---------------------------------------------------------------------------

def extract_recommendations(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"recommendations": [], "products": [], "signals": [], "summary": {}, "errors": []}
    p = case.resolve("Documents", "Maximus", "Database", "MaximusDataStore", "MaximusDataModel.sqlite")
    if not p:
        out["errors"].append("MaximusDataModel.sqlite not found")
        return out
    out["summary"]["db_sha256"] = hash_file(p)
    with SQLiteReader(p) as db:
        prods = db.query("""
            SELECT ZPRODUCTID, ZPRODUCTNAME, ZNAMESPACE,
                   ZPREFERREDTEMPLATESIZE, ZNEWPREFERREDTEMPLATESIZE
            FROM ZCDPRODUCT
        """)
        recs = db.query("""
            SELECT ZITEMID, ZRANK, ZITEMEXPIRY, ZPRODUCT
            FROM ZCDRECOMMENDATION ORDER BY ZRANK ASC
        """)
        signals = db.query("""
            SELECT ZSIGNALTYPE, ZTIMESTAMP, ZISSYNCED, ZRECOMMENDATION
            FROM ZCDSIGNAL ORDER BY ZTIMESTAMP DESC
        """)
    out["products"] = [{
        "product_id": r.get("ZPRODUCTID"), "name": r.get("ZPRODUCTNAME"),
        "namespace": r.get("ZNAMESPACE"),
        "preferred_size": r.get("ZPREFERREDTEMPLATESIZE"),
    } for r in prods if "_error" not in r]
    out["recommendations"] = [{
        "item_id": r.get("ZITEMID"), "rank": r.get("ZRANK"),
        "expiry": normalize_timestamp(r.get("ZITEMEXPIRY")),
        "product_pk": r.get("ZPRODUCT"),
    } for r in recs if "_error" not in r]
    out["signals"] = [{
        "signal_type": r.get("ZSIGNALTYPE"),
        "timestamp": normalize_timestamp(r.get("ZTIMESTAMP")),
        "synced": bool(r.get("ZISSYNCED")),
        "recommendation_pk": r.get("ZRECOMMENDATION"),
    } for r in signals if "_error" not in r]
    out["summary"].update({
        "product_count": len(out["products"]),
        "recommendation_count": len(out["recommendations"]),
        "signal_count": len(out["signals"]),
    })
    return out


# ---------------------------------------------------------------------------
# Media (QR + Transaction backgrounds + Contact DPs)
# ---------------------------------------------------------------------------

def extract_media(case: CasePaths) -> Dict[str, Any]:
    """All visual artifacts: QR codes, P2P transaction backgrounds, profile pics."""
    out: Dict[str, Any] = {
        "qr_codes": [], "transaction_backgrounds": [],
        "background_categories": [], "contact_dps_external": [], "summary": {},
    }
    # QR codes
    docs = case.documents()
    if docs:
        for n in os.listdir(docs):
            if "qrcode" in n.lower() or n.startswith("qrCode"):
                full = os.path.join(docs, n)
                if os.path.isdir(full):
                    for sub in os.listdir(full):
                        sub_full = os.path.join(full, sub)
                        if os.path.isdir(sub_full):
                            for f in os.listdir(sub_full):
                                fp = os.path.join(sub_full, f)
                                out["qr_codes"].append({
                                    "path": fp,
                                    "size": os.path.getsize(fp),
                                    "content_hash": sub,  # SHA-256 of QR content
                                    "filename": f,
                                })

    # Transaction backgrounds
    if case.group_app:
        bg_root = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "P2P", "TransactionBackgrounds")
        if os.path.isdir(bg_root):
            for cat in os.listdir(bg_root):
                cat_path = os.path.join(bg_root, cat)
                if not os.path.isdir(cat_path):
                    continue
                category_assets: List[Dict[str, Any]] = []
                for variant in os.listdir(cat_path):
                    var_path = os.path.join(cat_path, variant)
                    if os.path.isfile(var_path):
                        category_assets.append({"variant": variant, "size": os.path.getsize(var_path), "path": var_path})
                    elif os.path.isdir(var_path):
                        for f in os.listdir(var_path):
                            fp = os.path.join(var_path, f)
                            if os.path.isfile(fp):
                                category_assets.append({"variant": variant + "/" + f, "size": os.path.getsize(fp), "path": fp})
                out["background_categories"].append({"category": cat, "assets": category_assets})
                out["transaction_backgrounds"].extend([{"category": cat, **a} for a in category_assets])

    # Sampark _EXTERNAL_DATA images
    if case.group_app:
        ext = os.path.join(case.group_app, "com.phonepe.PhonePeApp", "SamparkV2",
                           ".SamparkV2_SUPPORT", "_EXTERNAL_DATA")
        if os.path.isdir(ext):
            for f in os.listdir(ext):
                fp = os.path.join(ext, f)
                if os.path.isfile(fp):
                    out["contact_dps_external"].append({"name": f, "size": os.path.getsize(fp), "path": fp})

    out["summary"] = {
        "qr_count": len(out["qr_codes"]),
        "background_assets": len(out["transaction_backgrounds"]),
        "background_categories": len(out["background_categories"]),
        "contact_dp_count": len(out["contact_dps_external"]),
    }
    return out


# ---------------------------------------------------------------------------
# Search & navigation (AppSearch FTS, SitemapDB)
# ---------------------------------------------------------------------------

def extract_search(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {"recent_searches": [], "indexed_entities": [], "sitemap": [], "summary": {}, "errors": []}
    # AppSearch FTS
    p = case.resolve("Documents", "AppSearch", "Database", "FTS", "app_search_db.sqlite")
    if p:
        with SQLiteReader(p) as db:
            recents = db.query("""
                SELECT rs.uniqueId, rs.timestamp, rm.entity, rm.fieldId, rm.entryId
                FROM recent_searches rs LEFT JOIN result_map rm ON rs.uniqueId = rm.rowid
                ORDER BY rs.timestamp DESC
            """)
            entity_breakdown = db.query("""
                SELECT entity, COUNT(*) as cnt FROM result_map GROUP BY entity ORDER BY cnt DESC
            """)
        for r in recents:
            if "_error" in r:
                continue
            out["recent_searches"].append({
                "unique_id": r.get("uniqueId"),
                "timestamp": normalize_timestamp(r.get("timestamp")),
                "entity": r.get("entity"),
                "field_id": r.get("fieldId"),
                "entry_id": r.get("entryId"),
            })
        out["indexed_entities"] = [{
            "entity": r.get("entity"), "count": r.get("cnt"),
        } for r in entity_breakdown if "_error" not in r]

    # Sitemap
    p = case.resolve("Documents", "Sitemap", "Database", "SitemapDB", "SitemapDB.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("""
                SELECT ZID, ZUSECASEIDVALUE, ZDEEPLINK, ZIMAGEURL, ZKEYWORDS, ZLOCALUPDATEDAT
                FROM ZSITEMAPITEM ORDER BY ZUSECASEIDVALUE
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["sitemap"].append({
                "id": r.get("ZID"),
                "use_case": r.get("ZUSECASEIDVALUE"),
                "deeplink": r.get("ZDEEPLINK"),
                "keywords": r.get("ZKEYWORDS"),
                "image_url": r.get("ZIMAGEURL"),
                "updated_at": normalize_timestamp(r.get("ZLOCALUPDATEDAT")),
            })
    out["summary"] = {
        "recent_search_count": len(out["recent_searches"]),
        "sitemap_count": len(out["sitemap"]),
        "entity_count": len(out["indexed_entities"]),
    }
    return out


# ---------------------------------------------------------------------------
# WebKit + cookies
# ---------------------------------------------------------------------------

def extract_webkit(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "cookies": [], "resource_load_stats": [], "local_storage": [],
        "indexed_db": [], "summary": {},
    }
    cookie = case.cookies_path()
    if cookie:
        out["cookies_path"] = cookie
        out["cookies_sha256"] = hash_file(cookie)
        try:
            r = BinaryCookieReader(cookie)
            out["cookies"] = r.cookies
        except Exception as exc:
            out["cookies_error"] = str(exc)
    web_dir = case.webkit_dir()
    if web_dir:
        # observations.db
        obs = os.path.join(web_dir, "WebsiteData", "ResourceLoadStatistics", "observations.db")
        if os.path.exists(obs):
            try:
                with SQLiteReader(obs) as db:
                    if db.has_table("ObservedDomains"):
                        rows = db.query("""
                            SELECT registrableDomain, hadUserInteraction,
                                   mostRecentUserInteractionTime, lastSeen, grandfathered
                            FROM ObservedDomains ORDER BY mostRecentUserInteractionTime DESC LIMIT 500
                        """)
                        for r in rows:
                            if "_error" in r:
                                continue
                            out["resource_load_stats"].append({
                                "domain": r.get("registrableDomain"),
                                "had_user_interaction": bool(r.get("hadUserInteraction")),
                                "last_user_interaction": normalize_timestamp(r.get("mostRecentUserInteractionTime")),
                                "last_seen": normalize_timestamp(r.get("lastSeen")),
                                "grandfathered": bool(r.get("grandfathered")),
                            })
            except Exception as exc:
                out["resource_load_error"] = str(exc)
        # LocalStorage
        ls = os.path.join(web_dir, "WebsiteData", "LocalStorage")
        if os.path.isdir(ls):
            for n in os.listdir(ls):
                fp = os.path.join(ls, n)
                if os.path.isfile(fp):
                    out["local_storage"].append({"name": n, "size": os.path.getsize(fp)})
        # IndexedDB
        idb = os.path.join(web_dir, "WebsiteData", "IndexedDB")
        if os.path.isdir(idb):
            for n in os.listdir(idb):
                fp = os.path.join(idb, n)
                out["indexed_db"].append({"name": n, "is_dir": os.path.isdir(fp)})
    out["summary"] = {
        "cookie_count": len(out["cookies"]),
        "resource_load_domains": len(out["resource_load_stats"]),
        "local_storage_files": len(out["local_storage"]),
        "indexed_db_entries": len(out["indexed_db"]),
    }
    return out


# ---------------------------------------------------------------------------
# Audit & lifecycle (Chitragupt, Chronicle, Samsara, sync gaps)
# ---------------------------------------------------------------------------

def extract_audit(case: CasePaths) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ledger_sync": [], "consents": [], "central_sync": [], "bg_sync_items": [],
        "summary": {}, "errors": [],
    }

    # Chronicle ledger sync (94 rows!)
    p = case.resolve("Documents", "Chronicle", "Database", "Chronicle.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("""
                SELECT ZLEDGERID, ZBALANCESYNCSTATUS, ZEXPENSESYNCSTATUS,
                       ZFORWARDEXPENSEPOINTER, ZREVERSEEXPENSEPOINTER,
                       ZLASTBALANCESYNCTIME, ZISGANGGROUP
                FROM ZLEDGERSYNC ORDER BY ZLASTBALANCESYNCTIME DESC
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["ledger_sync"].append({
                "ledger_id": r.get("ZLEDGERID"),
                "balance_status": r.get("ZBALANCESYNCSTATUS"),
                "expense_status": r.get("ZEXPENSESYNCSTATUS"),
                "last_balance_sync": normalize_timestamp(r.get("ZLASTBALANCESYNCTIME")),
                "is_gang_group": bool(r.get("ZISGANGGROUP")),
            })

    # Consent
    p = case.resolve("Documents", "Consent", "Consent.sqlite")
    if p:
        with SQLiteReader(p) as db:
            user = db.query("""
                SELECT ZUSERID, ZPHONENUMBER, ZDEVICEFINGERPRINT FROM ZCONSENTUSER LIMIT 5
            """)
            consents = db.query("""
                SELECT ZCONSENTSTATE, ZDESTINATION, ZSUBJECTID, ZENDTIME FROM ZCONSENTACCEPTANCE
            """)
            infos = db.query("SELECT ZCONSENTDEFINITION, ZUSECASE, ZDATASOURCE, ZMAPPINGID FROM ZCONSENTINFO")
        if user and "_error" not in user[0]:
            u = user[0]
            out["consent_user"] = {
                "user_id": u.get("ZUSERID"),
                "phone": u.get("ZPHONENUMBER"),
                "device_fingerprint": u.get("ZDEVICEFINGERPRINT"),
            }
        for r in consents:
            if "_error" in r:
                continue
            out["consents"].append({
                "state": r.get("ZCONSENTSTATE"),
                "destination": r.get("ZDESTINATION"),
                "subject_id": r.get("ZSUBJECTID"),
                "end_time": normalize_timestamp(r.get("ZENDTIME")),
            })
        out["consent_definitions"] = [{
            "definition": r.get("ZCONSENTDEFINITION"),
            "use_case": r.get("ZUSECASE"),
            "data_source": r.get("ZDATASOURCE"),
            "mapping_id": r.get("ZMAPPINGID"),
        } for r in infos if "_error" not in r]

    # CentralSyncManager
    p = case.resolve("Documents", "CentralSyncManager", "Database", "CentralSyncManager.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("""
                SELECT ZSYNCID, ZSYNCINFOTYPE, ZSYNCSTATUS, ZSYNCDATANATURE,
                       ZKEY, ZSYSTEM, ZLASTSYNCATTEMPTTIME, ZLASTSYNCCOMPLETIONTIME
                FROM ZCDSYNCINFO ORDER BY ZLASTSYNCCOMPLETIONTIME DESC
            """)
        for r in rows:
            if "_error" in r:
                continue
            out["central_sync"].append({
                "sync_id": r.get("ZSYNCID"),
                "type": r.get("ZSYNCINFOTYPE"),
                "status": r.get("ZSYNCSTATUS"),
                "key": r.get("ZKEY"),
                "system": r.get("ZSYSTEM"),
                "last_attempt": normalize_timestamp(r.get("ZLASTSYNCATTEMPTTIME")),
                "last_completed": normalize_timestamp(r.get("ZLASTSYNCCOMPLETIONTIME")),
            })

    # BG framework
    p = case.resolve("Documents", "BGFramework", "Database", "BGFrameworkDataStore", "BGFrameworkDataModel.sqlite")
    if p:
        with SQLiteReader(p) as db:
            rows = db.query("SELECT ZIDENTIFIER, ZLASTSYNCTIME FROM ZCDSYNCITEM ORDER BY ZLASTSYNCTIME DESC")
        for r in rows:
            if "_error" in r:
                continue
            out["bg_sync_items"].append({
                "identifier": r.get("ZIDENTIFIER"),
                "last_sync": normalize_timestamp(r.get("ZLASTSYNCTIME")),
            })

    # Cassini ML
    p = case.resolve("Documents", "Cassini", "Cassini.sqlite")
    if p:
        with SQLiteReader(p) as db:
            mi = db.query("SELECT ZID, ZNAME, ZCHECKSUM, ZDOWNLOADURL, ZLOCALSTATE, ZSERVERSTATE, ZUPDATEDAT FROM ZMODELINFO")
        for r in mi:
            if "_error" in r:
                continue
            out.setdefault("cassini_models", []).append({
                "id": r.get("ZID"), "name": r.get("ZNAME"), "checksum": r.get("ZCHECKSUM"),
                "url": r.get("ZDOWNLOADURL"), "local_state": r.get("ZLOCALSTATE"),
                "server_state": r.get("ZSERVERSTATE"),
                "updated_at": normalize_timestamp(r.get("ZUPDATEDAT")),
            })

    out["summary"] = {
        "ledger_sync_count": len(out["ledger_sync"]),
        "consent_count": len(out["consents"]),
        "central_sync_count": len(out["central_sync"]),
        "bg_sync_count": len(out["bg_sync_items"]),
    }
    return out


# ---------------------------------------------------------------------------
# Database overview
# ---------------------------------------------------------------------------

def database_overview(case: CasePaths) -> List[Dict[str, Any]]:
    """Return SHA-256 + table/row counts for every SQLite + WebKit observations."""
    out: List[Dict[str, Any]] = []
    for path in case.all_sqlites():
        info = {
            "path": path,
            "rel_path": os.path.relpath(path, case.root),
            "size": os.path.getsize(path),
            "sha256": hash_file(path),
            "tables": [],
            "wal_present": os.path.exists(path + "-wal"),
            "shm_present": os.path.exists(path + "-shm"),
        }
        try:
            with SQLiteReader(path) as db:
                info["deletion"] = db.deletion_signals()
                for t in db.tables():
                    info["tables"].append({"name": t, "rows": db.count(t)})
        except Exception as exc:
            info["error"] = str(exc)
        out.append(info)
    out.sort(key=lambda d: d.get("rel_path", ""))
    return out


def plist_overview(case: CasePaths) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path in case.all_plists():
        info = {
            "path": path,
            "rel_path": os.path.relpath(path, case.root),
            "size": os.path.getsize(path),
            "sha256": hash_file(path),
        }
        d = read_plist(path)
        if isinstance(d, dict):
            info["top_level_key_count"] = len(d)
            info["top_level_keys"] = list(d.keys())[:50]
        elif isinstance(d, list):
            info["list_length"] = len(d)
        out.append(info)
    out.sort(key=lambda d: d.get("rel_path", ""))
    return out
