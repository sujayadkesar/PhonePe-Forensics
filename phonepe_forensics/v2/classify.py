"""Merchant/P2P/Mandate classifier + UPI initiation decoder + TPAP attribution."""
from __future__ import annotations

from typing import Any

from .core import first_or_dict
from .data_layer import AppInfo

# NPCI standard UPI Initiation Mode codes
UPI_INIT_MODE = {
    "00": "DEFAULT",       # manual VPA / number entry
    "01": "STATIC_QR",
    "02": "DYNAMIC_QR",
    "03": "INTENT",
    "04": "QR_GALLERY",    # QR scanned from saved image
    "05": "SECURE_QR",     # camera / Bharat QR
    "06": "NFC",
    "08": "AADHAAR",
    "09": "COLLECT",
    "10": "FOREIGN_INWARD",
    "11": "TOKENISED",
}


def classify_transaction(blob: dict[str, Any] | None) -> str:
    """Return one of: MERCHANT | MERCHANT_REFUND | PEER_TO_PEER | MANDATE | OTHER.

    Uses every merchant signal available in the decoded ZDATA blob.
    """
    if not isinstance(blob, dict):
        return "OTHER"
    t = first_or_dict(blob.get("to"))
    fr = blob.get("from") if isinstance(blob.get("from"), dict) else {}
    ctx = blob.get("context") or {}
    if not isinstance(ctx, dict):
        ctx = {}
    transfer_mode = ctx.get("transferMode", "")

    # 1. context.transferMode is PhonePe's own authoritative classification.
    #    It MUST win over every downstream heuristic — a PEER_TO_PEER payment
    #    to a person can still carry an mcc/firstPartyMerchant field, and a
    #    heuristic that ignores transferMode mis-files the person as a merchant.
    if transfer_mode == "PEER_TO_MERCHANT":
        return "MERCHANT"
    if transfer_mode == "PEER_TO_PEER":
        return "PEER_TO_PEER"

    # 2. Mandate / autopay shape
    if "mandateAmount" in blob or "mandateId" in blob or "mandateRequestNote" in blob:
        return "MANDATE"

    # 3. Any merchant signal on the payee (heuristic — only reached when
    #    transferMode is absent or ambiguous, e.g. INTENT / RESPONSE flows).
    mcc = t.get("mcc") if isinstance(t, dict) else None
    merchant_signals = (
        (isinstance(t, dict) and t.get("type") == "MERCHANT")
        or (isinstance(t, dict) and t.get("merchantId"))
        or (isinstance(t, dict) and t.get("merchantType"))
        or (isinstance(t, dict) and t.get("merchantIdentifierType"))
        # firstPartyMerchant: True means PhonePe-owned merchant. False means
        # explicitly NOT a merchant — must NOT be treated as a positive signal.
        or (isinstance(t, dict) and t.get("firstPartyMerchant") is True)
        or (isinstance(t, dict) and t.get("subMerchantId"))
        or (mcc and str(mcc) != "0000")
        or ((ctx.get("serviceContext") or {}).get("serviceType"))
        or ctx.get("merchantOrderId")
    )
    if merchant_signals:
        return "MERCHANT"

    # 4. Incoming refund/cashback from a merchant
    if isinstance(fr, dict) and fr.get("type") == "MERCHANT":
        return "MERCHANT_REFUND"

    # 5. P2P signals (either direction)
    p2p_types = {"VPA", "PHONE", "INTERNAL_USER", "EXTERNAL_USER"}
    if (
        (isinstance(t, dict) and t.get("type") in p2p_types)
        or (isinstance(fr, dict) and fr.get("type") in p2p_types)
    ):
        return "PEER_TO_PEER"

    return "OTHER"


def merchant_subtype(blob: dict | None, phonepe_psps: frozenset[str]) -> str | None:
    """Return MERCHANT_ON_PHONEPE | MERCHANT_THIRD_PARTY | None."""
    if not isinstance(blob, dict):
        return None
    t = first_or_dict(blob.get("to"))
    if not isinstance(t, dict):
        return None
    # firstPartyMerchant: True == PhonePe-owned merchant (BBPS, in-app, etc.) —
    # decisive regardless of VPA shape.
    if t.get("firstPartyMerchant") is True:
        return "MERCHANT_ON_PHONEPE"
    vpa = (t.get("vpa") or t.get("fullVpa") or "").lower()
    if "@" in vpa:
        psp = vpa.rsplit("@", 1)[1]
        if psp in phonepe_psps:
            return "MERCHANT_ON_PHONEPE"
        return "MERCHANT_THIRD_PARTY"
    # Merchant identified by merchantId / userId without a standard vpa@psp
    # (e.g. HYDMETROINAPP, BBPSBP). If onboarded as a PhonePe in-app merchant
    # treat as on-PhonePe; otherwise it's a third-party merchant we can't pin
    # to a PSP — label THIRD_PARTY so the row is never left blank.
    mtype = (t.get("merchantType") or "").upper()
    if "INAPP" in mtype or "AGGREGATOR" in mtype:
        return "MERCHANT_ON_PHONEPE"
    if t.get("merchantId") or t.get("type") == "MERCHANT":
        return "MERCHANT_THIRD_PARTY"
    return None


def decode_initiation(blob: dict | None) -> dict:
    """Return {payment_initiation, is_qr_scan, is_intent, intent_caller_url, transfer_mode,
    upi_initiation_mode, raw_initiation_mode}."""
    out = {
        "payment_initiation": "",
        "is_qr_scan": False,
        "is_intent": False,
        "intent_caller_url": "",
        "transfer_mode": "",
        "upi_initiation_mode": "",
        "raw_initiation_mode": "",
    }
    if not isinstance(blob, dict):
        return out
    ctx = blob.get("context") or {}
    if not isinstance(ctx, dict):
        return out
    uim = str(ctx.get("upiInitiationMode") or "")
    rim = str(ctx.get("initiationMode") or "")
    out["upi_initiation_mode"] = uim
    out["raw_initiation_mode"] = rim
    out["transfer_mode"] = str(ctx.get("transferMode") or "")
    out["intent_caller_url"] = str(ctx.get("refUrl") or "")
    out["payment_initiation"] = UPI_INIT_MODE.get(uim, f"UNKNOWN_{uim}" if uim else "")
    out["is_qr_scan"] = uim in ("01", "02", "04", "05")
    out["is_intent"] = (uim == "03") or (rim == "INTENT")
    return out


# ---------- TPAP attribution ----------
# Tier-2 fallback: well-known PSP suffixes that PhonePe's own tpapKeyMap
# doesn't include. Sourced from public NPCI TPAP registry. Always marked
# 'source: inference' in the output so investigators know it's not from
# the acquired DB itself.
_WELLKNOWN_TPAP = {
    "yescred":   {"label": "CRED",       "icon_id": "cred"},
    "axisb":     {"label": "CRED",       "icon_id": "cred"},
    "ptybl":     {"label": "Paytm",      "icon_id": "paytm"},
    "okbizicici": {"label": "Google Pay","icon_id": "gpay"},
    "okhdfcbank": {"label": "Google Pay","icon_id": "gpay"},
    "axisbnk":   {"label": "Axis Pay",   "icon_id": "axispay"},
    "abfspay":   {"label": "Aditya Birla Pay", "icon_id": "upi"},
    "freecharge":{"label": "Freecharge", "icon_id": "upi"},
    "jupiteraxis":{"label": "Jupiter",    "icon_id": "upi"},
    "fbl":       {"label": "Federal Bank","icon_id": "upi"},
}

# Tier-3 fallback: PSP suffixes that ARE bank shortcodes/aliases. We
# resolve them via the in-acquisition bank master (ZPCDBANK) to the
# bank name. Marked 'source: bank-master' — still DB-evidence, just
# a different table.
_PSP_TO_BANK_ID = {
    # VPA suffix -> ZPCDBANK.ZID
    "hdfcbank": "HDFC",
    "sbi":      "SBIN",
    "icici":    "ICIC",
    "axisbank": "UTIB",
    "kotak":    "KKBK",
    "rbl":      "RATN",
    "kvb":      "KVBL",
    "indus":    "INDB",
    "pnb":      "PUNB",
    "boi":      "BKID",
    "canara":   "CNRB",
    "idfcbank": "IDFB",
    "yesbank":  "YESB",
    "uboi":     "UBIN",
    "barb":     "BARB",
}


def attribute_app(
    vpa: str | None,
    tpap_key_map: dict[str, str],
    tpap_info: dict[str, AppInfo],
    phonepe_psps: frozenset[str],
    bank_master: dict | None = None,
) -> dict:
    """Strict-first, fall-back-with-disclosed-source app attribution.

    Resolution order (each level records its `source` in the result):
      1. ConfigManagerKeyStore.tpapKeyMap (authoritative — PhonePe's own config)
      2. ZPCDBANK bank-master (bank-direct app via VPA suffix -> ZID match)
      3. Well-known TPAP suffix map  (inference — public NPCI registry)
      4. Unknown TPAP
    """
    if not vpa or "@" not in str(vpa):
        return {
            "label": "No VPA",
            "source": None,
            "icon_id": None,
            "psp": None,
            "on_phonepe": False,
        }
    psp = str(vpa).rsplit("@", 1)[1].lower()
    on_pp = psp in phonepe_psps

    # 1. authoritative from PhonePe's own production config
    if psp in tpap_key_map:
        app_key = tpap_key_map[psp]
        info = tpap_info.get(app_key)
        return {
            "label": info.title if info else app_key,
            "source": "authoritative (ConfigManagerKeyStore.tpapKeyMap)",
            "icon_id": info.icon_id if info else None,
            "psp": psp,
            "on_phonepe": on_pp,
        }

    # 2. bank-direct app — VPA suffix maps to a bank shortcode in ZPCDBANK
    if bank_master and psp in _PSP_TO_BANK_ID:
        zid = _PSP_TO_BANK_ID[psp]
        bi = bank_master.get(zid)
        if bi:
            return {
                "label": f"{bi.name} (bank-direct)",
                "source": "bank-master (PaymentDataStore.ZPCDBANK)",
                "icon_id": None,
                "psp": psp,
                "on_phonepe": on_pp,
            }

    # 3. well-known TPAP — public NPCI registry, marked 'inference'
    if psp in _WELLKNOWN_TPAP:
        wk = _WELLKNOWN_TPAP[psp]
        return {
            "label": f"{wk['label']} (inference)",
            "source": "inference (well-known NPCI TPAP suffix; not in acquisition's tpapKeyMap)",
            "icon_id": wk["icon_id"],
            "psp": psp,
            "on_phonepe": on_pp,
        }

    return {
        "label": f"Unknown TPAP (@{psp})",
        "source": None,
        "icon_id": None,
        "psp": psp,
        "on_phonepe": on_pp,
    }


def resolve_bank_name(
    bank_id: str | None, ifsc: str | None, bank_master: dict
) -> str:
    """Return bank display name. Order: bankId → ifsc[:4] → full IFSC prefix match."""
    if bank_id and bank_id in bank_master:
        return bank_master[bank_id].name
    if ifsc:
        prefix = ifsc[:4]
        if prefix in bank_master:
            return bank_master[prefix].name
        # try full IFSC against ZIFSCPREFIX
        for bi in bank_master.values():
            if bi.ifsc_prefix and bi.ifsc_prefix == ifsc:
                return bi.name
    if ifsc:
        return f"{ifsc[:4]} Bank"
    if bank_id:
        return f"{bank_id} Bank"
    return ""
