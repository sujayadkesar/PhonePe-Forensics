"""Acquisition-aware loaders. All reads strictly read-only."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .core import (
    case_db_path,
    find_case_root,
    normalize_phone,
    ro_connect,
    safe_decode_blob,
    sha256_file,
)

# ---------- relative paths inside an acquisition ----------
DB_TXNSTORE = (
    "AppDomain-com.phonepe.PhonePeApp/Documents/TransactionsStore/"
    "Database/TransactionsStore/TransactionsStore.sqlite"
)
DB_PAYMENTSTORE = (
    "AppDomain-com.phonepe.PhonePeApp/Documents/Payment/"
    "Database/PaymentDataStore/PaymentDataStore.sqlite"
)
DB_BURBLE = (
    "AppDomainGroup-group.com.phonepe.PhonePeApp/com.phonepe.PhonePeApp/"
    "Burble/Burble.sqlite"
)
DB_SAMPARK = (
    "AppDomainGroup-group.com.phonepe.PhonePeApp/com.phonepe.PhonePeApp/"
    "SamparkV2/SamparkV2.sqlite"
)
DB_P2P = (
    "AppDomainGroup-group.com.phonepe.PhonePeApp/com.phonepe.PhonePeApp/"
    "P2P/P2P.sqlite"
)
DB_CONFIG = (
    "AppDomain-com.phonepe.PhonePeApp/Documents/ConfigManager/"
    "Database/ConfigManagerKeyStore/ConfigManagerKeyStore.sqlite"
)


# ---------- dataclasses ----------
@dataclass
class BankInfo:
    zid: str
    name: str
    ifsc_prefix: str | None = None
    central_ifsc: str | None = None
    is_upi_supported: bool = False
    is_active: bool = True


@dataclass
class AppInfo:
    app_key: str
    title: str
    tpap: str
    icon_id: str
    handles: list[str] = field(default_factory=list)


@dataclass
class OwnerVPA:
    vpa: str
    psp: str
    account_number: str | None
    ifsc: str | None
    bank_id: str | None
    is_phonepe_psp: bool


@dataclass
class OwnerIdentity:
    user_id: str | None
    account_holder: str | None
    account_no: str | None
    ifsc: str | None
    bank_id: str | None
    bank_name: str | None
    duration_of_download_days: int | None
    view_version: str | None
    vpas: list[OwnerVPA] = field(default_factory=list)


@dataclass
class Contact:
    phone: str | None  # last-10-digits normalized
    raw_phone: str | None
    verified_name: str | None
    cbs_name: str | None
    on_phonepe: bool | None
    connect_id: str | None
    image_url: str | None


@dataclass
class Conversation:
    group_id: str
    group_pk: int
    name: str
    last_activity_ms: int | None
    unread_count: int
    member_phones: list[str] = field(default_factory=list)
    is_group: bool = False  # >2 members
    image_url: str | None = None
    # counterparty (non-owner) member identifiers, when resolvable
    other_party_connect_id: str | None = None
    other_party_phone: str | None = None       # full E.164-last10 if resolved
    other_party_verified_name: str | None = None
    other_party_cbs_name: str | None = None
    # PhonePe display name + masked phone recovered from ZGROUPMEMBER
    # (ZPHONEPENAME column + the ZMATTRIBUTES profileSnapshot bplist). These
    # survive even when the counterparty has no SamparkV2 record at all.
    other_party_display_name: str | None = None
    other_party_masked_phone: str | None = None


@dataclass
class Message:
    pk: int
    group_id: str | None
    content_type: str | None
    created_at_ms: int | None
    text: str | None
    amount_paise: int | None
    transaction_id: str | None
    transaction_id_alt: str | None
    sender_transaction_id: str | None
    receiver_transaction_id: str | None
    payment_state: str | None
    note: str | None
    sender_pointer: int | None
    receiver_pointer: int | None
    section_title: str | None
    raw: dict[str, Any] = field(default_factory=dict)


# ---------- generic helpers ----------
def _open_or_none(path: Path | None):
    if path is None:
        return None
    try:
        return ro_connect(path)
    except Exception:
        return None


# ---------- LOADERS ----------
@lru_cache(maxsize=8)
def load_bank_master(case_root_str: str) -> dict[str, BankInfo]:
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_PAYMENTSTORE)
    out: dict[str, BankInfo] = {}
    if db is None:
        # fallback to bundled JSON if present
        bundled = Path(__file__).parent / "data" / "ifsc_banks.json"
        if bundled.exists():
            for row in json.loads(bundled.read_text(encoding="utf-8")):
                out[row["zid"]] = BankInfo(
                    zid=row["zid"],
                    name=row["name"],
                    ifsc_prefix=row.get("ifsc_prefix"),
                    central_ifsc=row.get("central_ifsc"),
                    is_upi_supported=bool(row.get("is_upi_supported", 0)),
                    is_active=bool(row.get("is_active", 1)),
                )
        return out
    con = ro_connect(db)
    for r in con.execute(
        "SELECT ZID, ZNAME, ZIFSCPREFIX, ZCENTRALIFSC, ZISUPISUPPORTED, ZISACTIVE FROM ZPCDBANK"
    ):
        if not r[0]:
            continue
        out[r[0]] = BankInfo(
            zid=r[0],
            name=(r[1] or "").strip(),
            ifsc_prefix=r[2],
            central_ifsc=r[3],
            is_upi_supported=bool(r[4]),
            is_active=bool(r[5]),
        )
    con.close()
    return out


@lru_cache(maxsize=8)
def load_phonepe_psps(case_root_str: str) -> frozenset[str]:
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_PAYMENTSTORE)
    if db is None:
        return frozenset()
    con = ro_connect(db)
    psps = {
        r[0].lower()
        for r in con.execute(
            "SELECT ZPSPHANDLE FROM ZPCDPHONEPEPSP WHERE ZISACTIVE=1"
        )
        if r[0]
    }
    con.close()
    return frozenset(psps)


@lru_cache(maxsize=8)
def load_tpap_map(case_root_str: str) -> tuple[dict[str, str], dict[str, AppInfo]]:
    """Return (psp_to_app_key, app_key_to_AppInfo) parsed from
    ConfigManagerKeyStore.ZKEYVALUESTORE chatProperty JSON."""
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_CONFIG)
    if db is None:
        return {}, {}
    con = ro_connect(db)
    raw = None
    try:
        row = con.execute(
            "SELECT ZVALUE FROM ZKEYVALUESTORE WHERE ZKEY='chatProperty'"
        ).fetchone()
        if row and row[0]:
            raw = row[0] if isinstance(row[0], str) else row[0].decode("utf-8", "replace")
    finally:
        con.close()
    if not raw:
        return {}, {}

    key_map: dict[str, str] = {}
    app_info: dict[str, AppInfo] = {}

    # extract tpapKeyMap object
    m = re.search(r'"tpapKeyMap"\s*:\s*(\{[^}]+\})', raw)
    if m:
        try:
            km = json.loads(m.group(1))
            key_map = {k.lower(): v for k, v in km.items()}
        except json.JSONDecodeError:
            pass

    # extract tpapInfo object (find matching closing brace)
    idx = raw.find('"tpapInfo"')
    if idx >= 0:
        start = raw.find("{", idx)
        depth = 0
        end = start
        while end < len(raw):
            c = raw[end]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        try:
            info = json.loads(raw[start : end + 1])
            for app_key, meta in info.items():
                app_info[app_key] = AppInfo(
                    app_key=app_key,
                    title=meta.get("title", app_key),
                    tpap=meta.get("tpap", app_key),
                    icon_id=meta.get("iconId", app_key),
                    handles=[h.lower() for h in (meta.get("handle") or [])],
                )
        except json.JSONDecodeError:
            pass
    return key_map, app_info


@lru_cache(maxsize=8)
def load_owner_identity(case_root_str: str) -> OwnerIdentity:
    case_root = Path(case_root_str)
    txn = case_db_path(case_root, DB_TXNSTORE)
    pay = case_db_path(case_root, DB_PAYMENTSTORE)
    user_id = duration = view_version = None
    holder = account_no = ifsc = bank_id = bank_name = None
    if txn:
        con = ro_connect(txn)
        row = con.execute(
            "SELECT ZUSERID, ZDURATIONOFDOWNLOADINDAYS, ZVIEWVERSION FROM ZUSER LIMIT 1"
        ).fetchone()
        if row:
            user_id, duration, view_version = row
        con.close()
    if pay:
        con = ro_connect(pay)
        row = con.execute(
            "SELECT ZACCOUNTHOLDERNAME, ZACCOUNTNO, "
            "(SELECT ZACCOUNTIFSC FROM ZPCDUPICONTAINER LIMIT 1), "
            "(SELECT ZBANKID FROM ZPCDUPICONTAINER LIMIT 1) "
            "FROM ZPCDBANKACCOUNT LIMIT 1"
        ).fetchone()
        if row:
            holder, account_no, ifsc, bank_id = row
        con.close()
    if bank_id:
        bm = load_bank_master(case_root_str)
        bi = bm.get(bank_id)
        bank_name = bi.name if bi else None

    # collect every owner VPA from receivedIn/paidFrom across all txns
    vpas_by_key: dict[str, OwnerVPA] = {}
    if txn:
        con = ro_connect(txn)
        phonepe_psps = load_phonepe_psps(case_root_str)
        for (zdata,) in con.execute("SELECT ZDATA FROM ZTRANSACTIONENTITY"):
            d = safe_decode_blob(zdata)
            if not isinstance(d, dict):
                continue
            for key in ("receivedIn", "paidFrom"):
                arr = d.get(key) or []
                if isinstance(arr, list):
                    for it in arr:
                        if not isinstance(it, dict):
                            continue
                        v = it.get("vpa")
                        if not v or "@" not in str(v):
                            continue
                        psp = str(v).rsplit("@", 1)[1].lower()
                        ov = OwnerVPA(
                            vpa=str(v),
                            psp=psp,
                            account_number=it.get("accountNumber"),
                            ifsc=it.get("ifsc"),
                            bank_id=it.get("bankId"),
                            is_phonepe_psp=psp in phonepe_psps,
                        )
                        vpas_by_key.setdefault(str(v), ov)
        con.close()
    return OwnerIdentity(
        user_id=user_id,
        account_holder=holder,
        account_no=account_no,
        ifsc=ifsc,
        bank_id=bank_id,
        bank_name=bank_name,
        duration_of_download_days=duration,
        view_version=view_version,
        vpas=list(vpas_by_key.values()),
    )


@lru_cache(maxsize=8)
def load_contacts(case_root_str: str) -> dict[str, Contact]:
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_SAMPARK)
    out: dict[str, Contact] = {}
    if db is None:
        return out
    con = ro_connect(db)
    # ZCYCLOPSCONTACT — verified PhonePe central name + on-PhonePe flag
    for r in con.execute(
        "SELECT ZPHONENUMBER, ZVERIFIEDNAME, ZONPHONEPE, ZCONNECTID, ZEXTERNALVPA "
        "FROM ZCYCLOPSCONTACT WHERE ZPHONENUMBER IS NOT NULL"
    ):
        raw = r[0]
        norm = normalize_phone(raw)
        if not norm:
            continue
        out[norm] = Contact(
            phone=norm,
            raw_phone=raw,
            verified_name=r[1],
            cbs_name=None,
            on_phonepe=bool(r[2]) if r[2] is not None else None,
            connect_id=r[3],
            image_url=None,
        )
    # ZNONCONTACT — peers seen in chats not in phonebook (image URLs)
    for r in con.execute(
        "SELECT ZPHONENUMBER, ZCBSNAME, ZIMAGEURL, ZCONNECTID, ZISONPHONEPE "
        "FROM ZNONCONTACT"
    ):
        raw = r[0]
        norm = normalize_phone(raw) if raw else None
        if not norm:
            continue
        existing = out.get(norm)
        if existing:
            existing.cbs_name = existing.cbs_name or r[1]
            existing.image_url = existing.image_url or r[2]
            if existing.on_phonepe is None:
                existing.on_phonepe = bool(r[4]) if r[4] is not None else None
        else:
            out[norm] = Contact(
                phone=norm,
                raw_phone=raw,
                verified_name=None,
                cbs_name=r[1],
                on_phonepe=bool(r[4]) if r[4] is not None else None,
                connect_id=r[3],
                image_url=r[2],
            )
    con.close()
    return out


@lru_cache(maxsize=8)
def load_phonebook_names(case_root_str: str) -> dict[str, str]:
    """Map: normalized phone -> device-phonebook saved name.

    This is the name the SUBJECT chose for the contact in their phone
    ("Akkaa", "Bharat @tcs Hyd_ap") — forensically distinct from the bank-CBS
    name and PhonePe's verified name, because it carries the subject's own
    relationship/context labelling.

    Chain: ZPHONEBOOKCONTACT.ZMETADATA -> ZPHONEBOOKCONTACTMETADATA.ZFULLNAME
           ZPHONEBOOKCONTACT.ZSELFNORMALISEDNUMBER / ZRAWPHONENUMBER -> phone
    """
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_SAMPARK)
    out: dict[str, str] = {}
    if db is None:
        return out
    con = ro_connect(db)
    try:
        for r in con.execute(
            """
            SELECT pc.ZRAWPHONENUMBER, pc.ZSELFNORMALISEDNUMBER, m.ZFULLNAME
            FROM ZPHONEBOOKCONTACT pc
            JOIN ZPHONEBOOKCONTACTMETADATA m ON m.Z_PK = pc.ZMETADATA
            WHERE m.ZFULLNAME IS NOT NULL AND m.ZFULLNAME != ''
            """
        ):
            name = (r[2] or "").strip()
            if not name:
                continue
            norm = normalize_phone(r[1]) or normalize_phone(r[0])
            if norm:
                out.setdefault(norm, name)
    except Exception:
        pass
    con.close()
    return out


@lru_cache(maxsize=8)
def load_avatars(case_root_str: str) -> dict[str, bytes]:
    """Map: normalized phone -> JPEG bytes.

    The FK chain is:
        ZPHONEBOOKCONTACTMETADATA.Z_PK == ZPHONEBOOKCONTACT.ZMETADATA
        ZPHONEBOOKCONTACT.ZSELFNORMALISEDNUMBER -> phone
    """
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_SAMPARK)
    out: dict[str, bytes] = {}
    if db is None:
        return out
    con = ro_connect(db)

    # phonebook metadata pk -> normalized phone (via the back-reference)
    meta_pk_to_phone: dict[int, str] = {}
    for r in con.execute(
        "SELECT ZMETADATA, ZRAWPHONENUMBER, ZSELFNORMALISEDNUMBER "
        "FROM ZPHONEBOOKCONTACT WHERE ZMETADATA IS NOT NULL"
    ):
        meta_pk = r[0]
        norm = normalize_phone(r[2] or r[1])
        if meta_pk and norm:
            meta_pk_to_phone.setdefault(meta_pk, norm)

    for r in con.execute(
        "SELECT Z_PK, ZIMAGEDATA FROM ZPHONEBOOKCONTACTMETADATA "
        "WHERE ZIMAGEDATA IS NOT NULL"
    ):
        meta_pk, blob = r
        if not blob:
            continue
        phone = meta_pk_to_phone.get(meta_pk)
        if not phone:
            continue
        b = bytes(blob)
        idx = b.find(b"\xff\xd8\xff")
        if idx > 0:
            b = b[idx:]
        out.setdefault(phone, b)

    # Same FK pattern for ZPPABCONTACT/METADATA
    ppab_meta_pk_to_phone: dict[int, str] = {}
    for r in con.execute(
        "SELECT ZMETADATA, ZPHONENUMBER FROM ZPPABCONTACT WHERE ZMETADATA IS NOT NULL"
    ):
        norm = normalize_phone(r[1])
        if r[0] and norm:
            ppab_meta_pk_to_phone.setdefault(r[0], norm)
    for r in con.execute(
        "SELECT Z_PK, ZIMAGEDATA FROM ZPPABCONTACTMETADATA "
        "WHERE ZIMAGEDATA IS NOT NULL"
    ):
        meta_pk, blob = r
        if not blob:
            continue
        phone = ppab_meta_pk_to_phone.get(meta_pk)
        if not phone:
            continue
        b = bytes(blob)
        idx = b.find(b"\xff\xd8\xff")
        if idx > 0:
            b = b[idx:]
        out.setdefault(phone, b)

    con.close()
    return out


@lru_cache(maxsize=8)
def load_connectid_directory(case_root_str: str) -> dict[str, dict]:
    """connectid -> {phone, verified_name, cbs_name} built from ALL three
    SamparkV2 contact tables (ZCYCLOPSCONTACT, ZNONCONTACT, ZPPABCONTACT).

    A connectid can appear in any of them — checking only ZCYCLOPSCONTACT
    misses counterparties recorded as non-contacts or address-book contacts.
    """
    case_root = Path(case_root_str)
    samp_db = case_db_path(case_root, DB_SAMPARK)
    out: dict[str, dict] = {}
    if samp_db is None:
        return out
    sc = ro_connect(samp_db)
    sources = [
        ("ZCYCLOPSCONTACT", "ZVERIFIEDNAME", None),
        ("ZNONCONTACT", None, "ZCBSNAME"),
        ("ZPPABCONTACT", "ZVERIFIEDNAME", None),
    ]
    for tbl, vcol, ccol in sources:
        cols = ["ZCONNECTID", "ZPHONENUMBER"]
        cols.append(vcol or "NULL")
        cols.append(ccol or "NULL")
        try:
            rows = sc.execute(
                f"SELECT {', '.join(cols)} FROM {tbl} WHERE ZCONNECTID IS NOT NULL"
            ).fetchall()
        except Exception:
            continue
        for cid, phone, vname, cname in rows:
            if not cid:
                continue
            ent = out.setdefault(
                cid, {"phone": None, "verified_name": None, "cbs_name": None}
            )
            norm = normalize_phone(phone)
            if norm and not ent["phone"]:
                ent["phone"] = norm
            if vname and not ent["verified_name"]:
                ent["verified_name"] = vname.strip()
            if cname and not ent["cbs_name"]:
                ent["cbs_name"] = cname.strip()
    sc.close()
    return out


def _decode_member_profile(mattr: bytes | None) -> dict:
    """ZGROUPMEMBER.ZMATTRIBUTES is an NSKeyedArchiver bplist holding
    {profileSnapshot: {phonepeName, maskedPhoneNumber, phonepe}}.
    Returns {} when absent/undecodable."""
    dec = safe_decode_blob(mattr) if mattr else None
    if isinstance(dec, dict):
        ps = dec.get("profileSnapshot")
        if isinstance(ps, dict):
            return ps
    return {}


@lru_cache(maxsize=8)
def load_burble_conversations(case_root_str: str) -> list[Conversation]:
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_BURBLE)
    if db is None:
        return []
    con = ro_connect(db)

    cid_dir = load_connectid_directory(case_root_str)

    # Per group: every member, with its connectid + the PhonePe display name
    # and masked phone recovered from ZGROUPMEMBER itself:
    #   ZPHONEPENAME  — column, the chat display name
    #   ZMATTRIBUTES  — bplist {profileSnapshot:{phonepeName, maskedPhoneNumber}}
    # A member with NO SamparkV2 contact row still yields a name + masked phone
    # from these two fields — so a chat counterparty is never fully "(unknown)".
    # Soft-deleted members are kept (an old member is still the counterparty).
    members_by_group: dict[int, list[dict]] = {}
    try:
        rows = con.execute(
            """
            SELECT mem.ZGROUP, mem.Z_PK, mem.ZPHONEPENAME, mem.ZMATTRIBUTES,
                   mi.ZCONNECTID
            FROM ZGROUPMEMBER mem
            LEFT JOIN ZGROUPMEMBERINFO mi ON mi.ZMEMBER = mem.Z_PK
            """
        ).fetchall()
    except Exception:
        rows = []
    for grp, mpk, ppname, mattr, cid in rows:
        snap = _decode_member_profile(mattr)
        members_by_group.setdefault(grp, []).append(
            {
                "member_pk": mpk,
                "connect_id": cid,
                "display_name": snap.get("phonepeName") or ppname or None,
                "masked_phone": snap.get("maskedPhoneNumber") or None,
            }
        )

    # Owner = the identity present in (almost) every group. Resolved by BOTH
    # connectid frequency and masked-phone frequency — they corroborate.
    from collections import Counter
    cid_freq: Counter = Counter()
    masked_freq: Counter = Counter()
    for mems in members_by_group.values():
        for c in {m["connect_id"] for m in mems if m["connect_id"]}:
            cid_freq[c] += 1
        for mp in {m["masked_phone"] for m in mems if m["masked_phone"]}:
            masked_freq[mp] += 1
    owner_cid = cid_freq.most_common(1)[0][0] if cid_freq else None
    owner_masked = masked_freq.most_common(1)[0][0] if masked_freq else None

    def _is_owner(m: dict) -> bool:
        # connectid is authoritative; masked phone only when no connectid.
        if m["connect_id"]:
            return m["connect_id"] == owner_cid
        return owner_masked is not None and m["masked_phone"] == owner_masked

    convs: list[Conversation] = []
    for r in con.execute(
        """
        SELECT g.Z_PK, gm.ZGROUPID, gm.ZNAME, gm.ZIMAGEURL,
               COALESCE(gc.ZLASTREADTIMESTAMP,0) AS last_read,
               COALESCE(gc.ZUNREADMESSAGECOUNT,0) AS unread
        FROM ZGROUP g
        JOIN ZGROUPMETA gm ON gm.ZGROUP=g.Z_PK
        LEFT JOIN ZGROUPCLIENTMETA gc ON gc.ZGROUP=g.Z_PK
        """
    ):
        gpk = r[0]
        member_count = con.execute(
            "SELECT COUNT(*) FROM ZGROUPMEMBER WHERE ZGROUP=? AND COALESCE(ZDELETEDSOFT,0)=0",
            (gpk,),
        ).fetchone()[0]
        mems = members_by_group.get(gpk, [])
        # counterparty member(s) = everyone who isn't the owner
        others = [m for m in mems if not _is_owner(m)]
        # never drop the counterparty: if the heuristic excluded everyone,
        # fall back to any member whose connectid differs from the owner's.
        if not others and mems:
            others = [m for m in mems if m["connect_id"] != owner_cid] or mems
        primary = others[0] if others else {}
        other_cid = primary.get("connect_id")
        resolved = cid_dir.get(other_cid or "", {})
        phones = []
        for m in others:
            ph = cid_dir.get(m["connect_id"] or "", {}).get("phone")
            if ph:
                phones.append(ph)
        convs.append(
            Conversation(
                group_pk=gpk,
                group_id=r[1],
                name=r[2] or "(unnamed)",
                image_url=r[3],
                last_activity_ms=int(r[4]) if r[4] else None,
                unread_count=int(r[5] or 0),
                is_group=member_count > 2,
                member_phones=list(dict.fromkeys(phones)),
                other_party_connect_id=other_cid,
                other_party_phone=resolved.get("phone"),
                other_party_verified_name=resolved.get("verified_name"),
                other_party_cbs_name=resolved.get("cbs_name"),
                other_party_display_name=primary.get("display_name"),
                other_party_masked_phone=primary.get("masked_phone"),
            )
        )
    con.close()
    convs.sort(key=lambda c: c.last_activity_ms or 0, reverse=True)
    return convs


@lru_cache(maxsize=8)
def load_burble_messages(case_root_str: str) -> list[Message]:
    case_root = Path(case_root_str)
    db = case_db_path(case_root, DB_BURBLE)
    if db is None:
        return []
    con = ro_connect(db)
    out: list[Message] = []
    # ZPBCOREMESSAGE has timestamps + group; ZCONTENT has typed payload.
    # The link is: ZCONTENT.Z_PK <-> ZPBCOREMESSAGE.ZPAYLOAD or similar; in this
    # schema we observed Z_PK alignment 1:1 by ordinal. Use ZGROUP from
    # ZPBCOREMESSAGE for grouping.
    rows = con.execute(
        """
        SELECT c.Z_PK,
               c.ZCONTENTTYPEVALUE,
               COALESCE(pb.ZCREATEDAT, c.ZCREATEDAT, c.ZCREATEDAT1, c.ZCREATEDAT2, c.ZCREATEDAT3) AS ts,
               c.ZTEXT, c.ZTEXTMESSAGE, c.ZMESSAGESTRING,
               COALESCE(c.ZAMOUNT, c.ZAMOUNT1, c.ZAMOUNT2),
               c.ZTRANSACTIONID, c.ZTRANSACTIONID1,
               c.ZSENDERTRANSACTIONID, c.ZRECEIVERTRANSACTIONID,
               c.ZPAYMENTSTATEVALUE,
               c.ZNOTE, c.ZNOTE1,
               c.ZSENDER, c.ZRECEIVER,
               pb.ZGROUP, gm.ZGROUPID, pb.ZMONTHYEARSECTIONTITLE,
               c.ZUTR,
               c.ZGIFTMESSAGE,
               c.ZEXTERNALVPA,
               c.ZEXTERNALVPACBSNAME,
               c.ZPAYMENTTITLE,
               c.ZDEELINK, c.ZDEELINK1,
               c.ZASSETID,
               c.ZLOCALFILEURL, c.ZPREVIEWURL,
               c.ZTITLE, c.ZDESCRIPTIONVALUE
        FROM ZCONTENT c
        -- ZCONTENT.Z_PK <- ZMESSAGE.ZCONTENT, ZMESSAGE.Z_PK <- ZPBCOREMESSAGE.ZPAYLOAD,
        -- ZPBCOREMESSAGE.ZGROUP -> ZGROUP.Z_PK -> ZGROUPMETA.ZGROUP
        LEFT JOIN ZMESSAGE msg ON msg.ZCONTENT = c.Z_PK
        LEFT JOIN ZPBCOREMESSAGE pb ON pb.ZPAYLOAD = msg.Z_PK
        LEFT JOIN ZGROUPMETA gm ON gm.ZGROUP = pb.ZGROUP
        """
    ).fetchall()
    for r in rows:
        ts = r[2]
        ts_ms = int(ts) if ts else None
        raw = {
            "pk": r[0],
            "content_type": r[1],
            "created_at_ms": ts_ms,
            "text": r[3] or r[4] or r[5],
            "amount_paise": int(r[6]) if r[6] else None,
            "transaction_id": r[7],
            "transaction_id_alt": r[8],
            "sender_transaction_id": r[9],
            "receiver_transaction_id": r[10],
            "payment_state": r[11],
            "note": r[12] or r[13],
            "sender_pointer": r[14],
            "receiver_pointer": r[15],
            "group_pk": r[16],
            "group_id": r[17],
            "section_title": r[18],
            "utr": r[19],
            "gift_message": r[20],
            "external_vpa": r[21],
            "external_vpa_cbs_name": r[22],
            "payment_title": r[23],
            "deeplink": r[24] or r[25],
            "asset_id": r[26],
            "local_file_url": r[27],
            "preview_url": r[28],
            "title": r[29],
            "description": r[30],
        }
        out.append(
            Message(
                pk=r[0],
                group_id=r[17],
                content_type=r[1],
                created_at_ms=ts_ms,
                text=raw["text"],
                amount_paise=raw["amount_paise"],
                transaction_id=r[7],
                transaction_id_alt=r[8],
                sender_transaction_id=r[9],
                receiver_transaction_id=r[10],
                payment_state=r[11],
                note=raw["note"],
                sender_pointer=r[14],
                receiver_pointer=r[15],
                section_title=r[18],
                raw=raw,
            )
        )
    con.close()
    return out


def collect_source_db_hashes(case_root_str: str) -> dict[str, dict]:
    """Return {logical_name: {path, sha256, size}} for every source DB present."""
    case_root = Path(case_root_str)
    out: dict[str, dict] = {}
    for logical, rel in {
        "TransactionsStore": DB_TXNSTORE,
        "PaymentDataStore": DB_PAYMENTSTORE,
        "Burble": DB_BURBLE,
        "SamparkV2": DB_SAMPARK,
        "P2P": DB_P2P,
        "ConfigManagerKeyStore": DB_CONFIG,
    }.items():
        p = case_db_path(case_root, rel)
        if p is None:
            continue
        out[logical] = {
            "path": rel,
            "sha256": sha256_file(p),
            "size_bytes": p.stat().st_size,
        }
    return out
