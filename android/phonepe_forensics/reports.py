"""
PhonePe Android Forensics — Report Exporter
=======================================
Produces deliverable evidence artifacts:

    export_csv     flat CSV per evidence type (transactions, contacts, chats, ...)
    export_json    structured master JSON of the full case
    export_html    self-contained HTML evidence report (no external deps)
    export_all     run all of the above into ./exports/<case_name>/
"""
from __future__ import annotations

import csv
import datetime as _dt
import html
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from . import __version__ as TOOL_VERSION

TOOL_NAME = "PhonePe Android Forensics"


def _ts_text(epoch_ms: Any) -> str:
    try:
        return _dt.datetime.fromtimestamp(
            int(epoch_ms) / 1000.0, tz=_dt.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"

# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

# Leading characters that make a spreadsheet treat a cell as a formula rather
# than as text. Counterparty names, chat notes and SMS bodies are all controlled
# by the suspect, so an unescaped export turns evidence into code that runs on
# the examiner's workstation when they open the CSV.
_CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")

# A plain signed number is not a formula, and quoting it would turn every
# negative amount in an export into text a spreadsheet will not sum.
_PLAIN_NUMBER_RX = re.compile(r"^[+-]?\d+(\.\d+)?$")


def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in one cell, losslessly."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in _CSV_FORMULA_LEADERS and not _PLAIN_NUMBER_RX.match(value):
        return "'" + value
    return value


def safe_filename(name: str, fallback: str = "export.csv") -> str:
    """Strip anything that could break out of a Content-Disposition header or a
    path. Werkzeug rejects headers containing newlines outright (a 500), and a
    quote or slash would let a caller-supplied id rewrite the filename."""
    cleaned = "".join(c for c in str(name or "") if c.isalnum() or c in "-_. ").strip()
    cleaned = cleaned.lstrip(".")
    return cleaned[:120] or fallback


def _write_csv(path: str, fieldnames: List[str], rows: Iterable[Dict[str, Any]]):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: csv_safe(_stringify(r.get(k))) for k in fieldnames})


def _stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):
        return v.get("iso") or v.get("display") or json.dumps(v, default=str)
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v)
    return str(v)


def export_transactions_csv(case_data: Dict[str, Any], out_dir: str) -> str:
    rows = case_data.get("transactions", {}).get("transactions", [])
    cols = [
        "created_at", "updated_at", "global_payment_id", "entity_id",
        "type", "state", "direction", "amount_inr", "category_code",
        "counterparty", "counterparty_phone", "counterparty_vpa",
        "merchant_name", "biller_name", "recharge_number", "note",
        "received_in_type", "group_id", "group_template",
        "id_embedded_ts", "search_token",
    ]
    path = os.path.join(out_dir, "transactions.csv")
    _write_csv(path, cols, rows)
    return path


def export_contacts_csv(case_data: Dict[str, Any], out_dir: str) -> List[str]:
    contacts = case_data.get("contacts", {})
    a = os.path.join(out_dir, "contacts_phonepe.csv")
    _write_csv(a, [
        "phone", "verified_name", "external_vpa", "external_vpa_name",
        "on_phonepe", "upi_state", "country_code", "region", "last_synced",
    ], contacts.get("cyclops_contacts", []))
    b = os.path.join(out_dir, "contacts_phonebook.csv")
    _write_csv(b, [
        "normalized", "raw_number", "full_name", "country_code", "region",
        "creation_time", "is_valid", "deleted", "has_image", "image_size",
    ], contacts.get("phonebook_contacts", []))
    return [a, b]


def export_chat_csv(case_data: Dict[str, Any], out_dir: str) -> List[str]:
    chat = case_data.get("chat", {})
    a = os.path.join(out_dir, "chat_groups.csv")
    _write_csv(a, [
        "group_id", "name", "type", "subscription", "active", "member_count",
        "created_at", "updated_at",
    ], chat.get("groups", []))
    b = os.path.join(out_dir, "chat_messages.csv")
    _write_csv(b, [
        "created_at", "thread_id", "type", "amount_inr", "transaction_id",
        "state", "payment_state", "instrument", "utr", "external_vpa",
        "external_bank", "note", "text_message", "reward_type", "request_id",
    ], chat.get("messages", []))
    c = os.path.join(out_dir, "chat_shared_account_disclosures.csv")
    _write_csv(c, [
        "type", "verified", "account_holder", "account_number", "bank_name",
        "ifsc", "phone", "vpa", "name",
    ], chat.get("shared_contacts", []))
    return [a, b, c]


def export_payment_infra_csv(case_data: Dict[str, Any], out_dir: str) -> List[str]:
    pi = case_data.get("payment_infra", {})
    a = os.path.join(out_dir, "linked_accounts.csv")
    _write_csv(a, [
        "account_no_masked", "account_holder", "account_alias", "account_type",
        "is_primary", "updated_at",
    ], pi.get("linked_accounts", []))
    b = os.path.join(out_dir, "linked_cards.csv")
    _write_csv(b, [
        "card_id", "alias", "type", "issuer", "bank_code", "masked",
        "holder", "status", "cobranding", "updated_at",
    ], pi.get("linked_cards", []))
    return [a, b]


def export_deleted_records_csv(case_data: Dict[str, Any], out_dir: str) -> str:
    records = (case_data.get("deleted_records", {}) or {}).get("records", [])
    rows = [{
        "table": r.get("table") or "/".join(r.get("candidate_tables") or []),
        "confidence": r.get("confidence"),
        "extent_confidence": r.get("extent_confidence"),
        "value_confidence": r.get("value_confidence"),
        "implausible_columns": "; ".join(r.get("implausible_columns") or []),
        "partial": r.get("partial"),
        "truncated": r.get("truncated"),
        "ambiguous": r.get("ambiguous"),
        "pool": r.get("pool"),
        "database": r.get("database"),
        "source_file": r.get("source_file"),
        "page": r.get("page"),
        "file_offset": r.get("file_offset"),
        "type_lost_for": "; ".join(r.get("lost_leading_columns") or []),
        "recovered_values": json.dumps(r.get("row", {}), default=str),
    } for r in records]
    path = os.path.join(out_dir, "recovered_deleted_records.csv")
    _write_csv(path, ["table", "confidence", "extent_confidence", "value_confidence",
                      "implausible_columns", "partial", "truncated", "ambiguous", "pool",
                      "database", "source_file", "page", "file_offset", "type_lost_for",
                      "recovered_values"], rows)
    return path


def export_notification_messages_csv(case_data: Dict[str, Any], out_dir: str) -> str:
    """Delivered push/inbox notifications — the content the subject was shown.

    Exported as its own exhibit because these reach years further back than the
    local transaction ledger does, so they carry much of the early timeline.
    """
    rows = (case_data.get("notifications", {}) or {}).get("raw_messages", [])
    path = os.path.join(out_dir, "notification_messages.csv")
    _write_csv(path, ["created_at", "sent_at", "kind", "title", "subtitle", "body",
                      "deeplink", "template", "topic_id", "message_id", "expires_at",
                      "is_notification"], rows)
    return path


def export_consents_csv(case_data: Dict[str, Any], out_dir: str) -> str:
    """Consent grants from both stores.

    Its own exhibit because "what did the subject agree to share, and when" is a
    question asked directly of an acquisition, and the answer spans two separate
    databases — so each row names the store it came from.
    """
    rows = (case_data.get("audit", {}) or {}).get("consents", [])
    path = os.path.join(out_dir, "consents.csv")
    _write_csv(path, ["source", "destination", "accept_type", "state", "subject_id",
                      "subject_ref", "definition", "sync_state", "consent_id",
                      "end_time"], rows)
    return path


def export_identity_accounts_csv(case_data: Dict[str, Any], out_dir: str) -> str:
    """The signed-in account record — the acquisition's most direct attribution of
    the account to a phone number (accounts_db keeps it unmasked)."""
    rows = (case_data.get("identity", {}) or {}).get("accounts", [])
    path = os.path.join(out_dir, "identity_accounts.csv")
    _write_csv(path, ["user_id", "display_name", "user_name", "phone",
                      "phone_verified", "email", "email_verified", "source"], rows)
    return path


def export_timeline_csv(timeline: List[Dict[str, Any]], out_dir: str) -> str:
    path = os.path.join(out_dir, "unified_timeline.csv")
    cols = ["when_iso", "source", "kind", "title", "amount_inr", "link_id"]
    _write_csv(path, cols, timeline)
    return path


def export_social_graph_csv(graph: Dict[str, Any], out_dir: str) -> str:
    path = os.path.join(out_dir, "social_graph.csv")
    cols = [
        "node_id", "kind", "name", "phone", "vpa", "on_phonepe",
        "txn_count_in", "txn_count_out", "txn_total_in", "txn_total_out",
        "chat_message_count", "chat_payment_count", "first_seen_iso", "last_seen_iso",
        "evidence_sources",
    ]
    _write_csv(path, cols, graph.get("nodes", []))
    return path


# ---------------------------------------------------------------------------
# JSON master export
# ---------------------------------------------------------------------------

def export_master_json(case_data: Dict[str, Any], out_dir: str) -> str:
    path = os.path.join(out_dir, "case_master.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(case_data, fh, default=str, indent=2)
    return path


# ---------------------------------------------------------------------------
# HTML evidence report (self-contained)
# ---------------------------------------------------------------------------

_HTML_REPORT_TMPL = """<!doctype html>
<html><head>
<meta charset="utf-8">
<title>PhonePe Android Forensics Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0c0e16;color:#e5e7eb;margin:0;padding:0}}
header{{background:linear-gradient(120deg,#5b21b6,#7e22ce);padding:32px 48px;border-bottom:1px solid #1f2937}}
header h1{{margin:0 0 6px;font-size:28px;letter-spacing:-.4px}}
header p{{margin:0;color:#e9d5ff}}
main{{padding:32px 48px;max-width:1280px;margin:0 auto}}
section{{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:22px 26px;margin:22px 0}}
section h2{{margin:0 0 16px;font-size:18px;color:#a78bfa;letter-spacing:.3px;text-transform:uppercase;font-weight:600}}
nav.tabs{{display:flex;flex-wrap:wrap;gap:6px;padding:0 48px;background:#0c0e16;border-bottom:1px solid #1f2937;position:sticky;top:0;z-index:9}}
nav.tabs button{{background:none;border:0;border-bottom:2px solid transparent;color:#9ca3af;padding:13px 14px;font:600 13px/1 inherit;cursor:pointer}}
nav.tabs button:hover{{color:#e5e7eb}}
nav.tabs button.on{{color:#c4b5fd;border-bottom-color:#8b5cf6}}
nav.tabs .count{{color:#6b7280;font-weight:400;margin-left:5px}}
.tfilter{{margin:0 0 10px}}
.tfilter input{{width:100%;max-width:340px;padding:7px 11px;border-radius:8px;border:1px solid #374151;background:#0c0e16;color:#e5e7eb;font:13px inherit}}
.tw{{overflow-x:auto}}
table.sortable th{{cursor:pointer;user-select:none;white-space:nowrap}}
table.sortable th:hover{{color:#c4b5fd}}
table.sortable th.asc::after{{content:' \\2191';color:#8b5cf6}}
table.sortable th.desc::after{{content:' \\2193';color:#8b5cf6}}
tr.hid{{display:none}}
.avatar{{width:30px;height:30px;border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:7px}}
.noscript{{background:#3f2d0b;border:1px solid #a16207;border-radius:10px;padding:10px 14px;margin:14px 48px;color:#fde68a;font-size:13px}}
@media print{{nav.tabs{{display:none}} section{{break-inside:avoid}} .tfilter{{display:none}}}}
.kv{{display:grid;grid-template-columns:240px 1fr;gap:8px 16px}}
.kv b{{color:#9ca3af;font-weight:500}}
.kv span{{color:#f9fafb}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #1f2937;vertical-align:top}}
th{{color:#9ca3af;text-transform:uppercase;font-size:11px;letter-spacing:.6px;font-weight:600}}
tr:hover{{background:#1f2937}}
.tag{{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.3px;background:#312e81;color:#c4b5fd}}
.tag.in{{background:#064e3b;color:#6ee7b7}}
.tag.out{{background:#7f1d1d;color:#fca5a5}}
.tag.failed{{background:#78350f;color:#fcd34d}}
.tag.high{{background:#7f1d1d;color:#fecaca}}
.tag.med{{background:#78350f;color:#fde68a}}
.tag.info{{background:#1e3a8a;color:#bfdbfe}}
.amount{{font-family:'SF Mono',Menlo,monospace;font-weight:700}}
.amount.pos{{color:#34d399}}
.amount.neg{{color:#f87171}}
.muted{{color:#6b7280}}
.tag-row{{display:flex;flex-wrap:wrap;gap:6px}}
small{{color:#6b7280}}
.metric-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}
.metric{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px}}
.metric .v{{font-size:24px;font-weight:700;color:#fff;font-family:'SF Mono',Menlo,monospace}}
.metric .l{{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}}
</style>
</head>
<body>
<header>
<h1>PhonePe Android Forensics — Evidence Report</h1>
<p>{case_name} · Generated {generated} · {tool}</p>
<p>Evidence root: {case_root}</p>
<p>All timestamps are UTC.</p>
</header>
<nav class="tabs" id="tabs" data-order='{tab_order}'></nav>
<noscript><div class="noscript">Scripting is off, so the tab bar, filters and
column sorting are inactive — every section is still present below, in full.</div></noscript>
<main>
{body}
</main>
</body></html>
"""


def export_html_report(case_data: Dict[str, Any], out_dir: str, case_root: str = "",
                       custody: Optional[Dict[str, Any]] = None) -> str:
    parts: List[str] = []
    custody = custody or {}

    # Chain of custody — first section, because a deliverable that cannot say
    # which acquisition it describes, who produced it, with what tool version, or
    # what the source hashes were is not usable as an exhibit.
    meta = case_data.get("_meta", {}) or {}
    parts.append(_section("Chain of Custody", _kv_block({
        "Case name": custody.get("case_name") or "—",
        "Case ID": custody.get("case_id") or "—",
        "Investigator": custody.get("investigator") or "—",
        "Evidence root": case_root or meta.get("case_root") or "—",
        "Platform": meta.get("platform", "android"),
        "Tool": f"{TOOL_NAME} {TOOL_VERSION}",
        "Extraction started": _ts_text(meta.get("loaded_at")),
        "Extraction completed": _ts_text(meta.get("completed_at")),
        "Report generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Notes": custody.get("notes") or "—",
    })))

    manifest = custody.get("manifest") or []
    if manifest:
        parts.append(_section(
            f"Acquisition Hash Manifest ({len(manifest)} database(s))",
            "<p class='muted'>SHA-256 computed before any parsing. Databases carrying a "
            "write-ahead log are recovered against a scratch copy so WAL-resident records "
            "are included; the evidence files themselves are never written to.</p>"
            + _table([{
                "database": m.get("original"),
                "sha256": m.get("sha256"),
                "opened_via": m.get("opened_via"),
                "wal": ("applied" if m.get("wal_applied")
                        else "EXCLUDED" if m.get("wal_present") else "none"),
                "sidecars": "; ".join(f"{k}={v}" for k, v in (m.get("sidecar_hashes") or {}).items()) or "—",
            } for m in manifest],
                ["database", "sha256", "opened_via", "wal", "sidecars"])))

    warnings = custody.get("evidence_warnings") or []
    if warnings:
        parts.append(_section("Evidence Integrity Warnings", _table(
            [{"warning": w} for w in warnings], ["warning"])))

    problems = custody.get("extraction_errors") or []
    if problems:
        parts.append(_section(
            f"Extraction Problems ({len(problems)})",
            "<p class='muted'>Modules that failed or degraded. Any section below that "
            "is backed by one of these is incomplete rather than empty.</p>"
            + _table(problems, ["severity", "module", "detail"])))

    # Identity
    ident = case_data.get("identity", {})
    parts.append(_section("Identity",
        _kv_block({
            "Registered name": ident.get("registered_name") or "—",
            "Primary UPI ID": ident.get("upi_id") or "—",
            "Phones seen": ", ".join(ident.get("phones_seen", [])) or "—",
            "AppsFlyer ID": ident.get("device_identifiers", {}).get("appsflyer_id") or "—",
            "Firebase Install ID": ident.get("device_identifiers", {}).get("firebase_installation_id") or "—",
            "Anon ID": ident.get("device_identifiers", {}).get("anon_id") or "—",
        })
    ))

    # Headline metrics
    txn_summary = case_data.get("transactions", {}).get("summary", {})
    chat_summary = case_data.get("chat", {}).get("summary", {})
    contacts_summary = case_data.get("contacts", {}).get("summary", {})
    parts.append(_section("Forensic Snapshot",
        _metric_grid({
            "Transactions": txn_summary.get("transaction_count", 0),
            "Total Received (₹)": _money(txn_summary.get("total_received_inr")),
            "Total Sent (₹)": _money(txn_summary.get("total_sent_inr")),
            "Chat Groups": chat_summary.get("group_count", 0),
            "Chat Messages": chat_summary.get("message_count", 0),
            "Phonebook Contacts": contacts_summary.get("phonebook_total", 0),
            "PhonePe Contacts": contacts_summary.get("on_phonepe_count", 0),
            "Profile Pictures": contacts_summary.get("external_image_count", 0),
        })
    ))

    # Yearly volume
    yearly = txn_summary.get("yearly_volume_inr", {})
    if yearly:
        rows = [{"year": y, "volume_inr": _money(v)} for y, v in yearly.items()]
        parts.append(_section("Yearly Transaction Volume", _table(rows, ["year", "volume_inr"])))

    # Recent transactions
    txns = case_data.get("transactions", {}).get("transactions", [])[:50]
    parts.append(_section("Recent Transactions (top 50)", _txn_table(txns)))

    # Top counterparties, ranked by amount and keyed on a STABLE identifier.
    #
    # The exhibit is where the grouping rule matters most, and it was the last place
    # still ranking by frequency of a display NAME — the very thing this tool refuses
    # to treat as an identity elsewhere (two people can share a name, and one person's
    # name is spelled several ways across the tables). Received and sent are reported
    # separately, because a net figure hides which direction the money went.
    for label, key in (("Received from", "top_counterparties_received"),
                       ("Sent to", "top_counterparties_sent")):
        entries = txn_summary.get(key) or []
        if not entries:
            continue
        rows = [{
            "name": e.get("name"),
            "type": e.get("kind"),
            "identifiers": "; ".join(e.get("identifiers") or []) or "—",
            "grouped_by": e.get("grouped_by"),
            "txn_count": e.get("count"),
            "total_inr": _money(e.get("amount_inr")),
        } for e in entries]
        parts.append(_section(
            f"Top Counterparties · {label} (by total amount)",
            "<p class='muted'>Grouped by a stable identifier — PhonePe userId, then full "
            "phone, then VPA — and never by display name. <b>grouped_by</b> states which "
            "identifier keyed each row. Successful transactions only.</p>"
            + _table(rows, ["name", "type", "identifiers", "grouped_by",
                            "txn_count", "total_inr"])))

    # Frequency ranking kept as a secondary view, explicitly labelled as name-keyed
    # so it cannot be mistaken for the identifier-keyed tables above.
    top_cp = txn_summary.get("top_counterparties", [])
    if top_cp:
        parts.append(_section("Most Frequent Counterparty Names",
            "<p class='muted'>Ranked by number of transactions and keyed on the display "
            "name as stored, so rows here may merge two people who share a name or split "
            "one person whose name is spelled differently across tables. Use the "
            "amount-ranked tables above for attribution.</p>"
            + _table([{"name": n, "txn_count": c} for n, c in top_cp],
                     ["name", "txn_count"])))

    # Linked accounts
    pi = case_data.get("payment_infra", {})
    if pi.get("linked_accounts"):
        parts.append(_section("Linked Bank Accounts", _table(pi["linked_accounts"], [
            "account_no_masked", "account_holder", "account_alias", "account_type",
            "is_primary", "updated_at",
        ])))
    if pi.get("linked_vpas"):
        parts.append(_section("Registered UPI VPAs",
            "<p>" + " ".join(f"<span class='tag'>{html.escape(str(v))}</span>" for v in pi["linked_vpas"]) + "</p>"))
    if pi.get("supported_banks"):
        parts.append(_section(f"PSP-supported banks ({len(pi['supported_banks'])})",
            f"<p class='muted'>Bank catalogue downloaded for UPI selection. See exported CSVs for full list.</p>"))

    # Chat groups
    if case_data.get("chat", {}).get("groups"):
        parts.append(_section("Chat Groups (top 30)", _table(
            case_data["chat"]["groups"][:30],
            ["name", "type", "active", "member_count", "created_at"],
        )))

    # Travel
    if case_data.get("travel", {}).get("journeys"):
        parts.append(_section("Travel Journeys",
            _table(case_data["travel"]["journeys"][:30],
                   ["name", "type", "state", "namespace", "created_at"])))

    # Recovered deleted records
    deleted = case_data.get("deleted_records", {}) or {}
    drecs = deleted.get("records", [])
    if drecs:
        dsum = deleted.get("summary", {})
        rows = [{
            "table": r.get("table") or "/".join(r.get("candidate_tables") or []),
            "extent": r.get("extent_confidence") or r.get("confidence"),
            "values": (r.get("value_confidence") or "")
                      + (f" (check {', '.join(r['implausible_columns'])})"
                         if r.get("implausible_columns") else ""),
            "pool": r.get("pool"),
            "provenance": f"{r.get('source_file')} page {r.get('page')} @ {r.get('file_offset')}",
            "recovered": "; ".join(f"{k}={v}" for k, v in (r.get("row") or {}).items()
                                   if v is not None)[:400],
        } for r in drecs[:200]]
        parts.append(_section(
            f"Recovered Deleted Records ({dsum.get('recovered_count', len(drecs))})",
            "<p class='muted'>Rows carved from freed pages, released cells, WAL frames and "
            "rollback journals — data the app deleted that the database had not yet "
            "overwritten. Each is a <b>reconstruction</b>, excluded from the live tables and "
            "listed only where it is absent from them. Two separate judgements are reported: "
            "<b>extent</b> is high where the record's start and end were confirmed "
            "structurally and medium where the field boundaries were inferred, while "
            "<b>values</b> says whether the decoded fields can be trusted to sit in the "
            "right columns — <i>low</i> marks a row holding a value outside the range its "
            "column uses in the live table, which means the fields are probably shifted. "
            "A high extent is not a claim that the values are right. An empty result is not "
            "proof nothing was deleted: freed space is reused over time, and secure_delete "
            "zeroes it immediately.</p>"
            + (f"<p class='muted'>Showing the first 200 of {len(drecs)}; the full set is in "
               f"recovered_deleted_records.csv.</p>" if len(drecs) > 200 else "")
            + _table(rows, ["table", "extent", "values", "pool", "provenance",
                            "recovered"])))

    # Findings
    findings = case_data.get("findings", [])
    if findings:
        rows_html = "<table><tr><th>Severity</th><th>Category</th><th>Title</th></tr>"
        for f in findings:
            sev_cls = {"high": "high", "medium": "med"}.get(f.get("severity"), "info")
            rows_html += f"<tr><td><span class='tag {sev_cls}'>{html.escape(str(f.get('severity','')))}</span></td><td>{html.escape(str(f.get('category','')))}</td><td>{html.escape(str(f.get('title','')))}</td></tr>"
        rows_html += "</table>"
        parts.append(_section("Suspicious Signals", rows_html))

    body = "\n".join(parts)
    html_doc = _HTML_REPORT_TMPL.format(
        generated=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        case_name=html.escape(str(custody.get("case_name") or "Unnamed case")),
        tool=html.escape(f"{TOOL_NAME} {TOOL_VERSION}"),
        case_root=html.escape(case_root or "—"),
        tab_order=html.escape(json.dumps(_TAB_ORDER), quote=False).replace("'", "&#39;"),
        body=body + _REPORT_JS,
    )
    path = os.path.join(out_dir, "evidence_report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return path


# The report's behaviour, appended to the body rather than embedded in the
# template: str.format() would choke on every brace in it.
_REPORT_JS = """<script>
(function () {
  // Tabs. Sections are tagged with data-tab and all remain in the document; this
  // only toggles visibility, so browser find, print and copy still see the whole
  // report. "All" is offered because an examiner reading end-to-end should not
  // have to click through seven panes.
  var secs = [].slice.call(document.querySelectorAll('section[data-tab]'));
  var nav  = document.getElementById('tabs');
  if (nav && secs.length) {
    var order = JSON.parse(nav.getAttribute('data-order') || '[]');
    var present = order.filter(function (t) {
      return secs.some(function (s) { return s.getAttribute('data-tab') === t[0]; });
    });
    function show(key) {
      secs.forEach(function (s) {
        s.style.display = (key === '*' || s.getAttribute('data-tab') === key) ? '' : 'none';
      });
      [].forEach.call(nav.children, function (b) {
        b.classList.toggle('on', b.getAttribute('data-key') === key);
      });
    }
    function add(key, label, n) {
      var b = document.createElement('button');
      b.setAttribute('data-key', key);
      b.innerHTML = label + (n !== null ? ' <span class="count">' + n + '</span>' : '');
      b.onclick = function () { show(key); };
      nav.appendChild(b);
    }
    add('*', 'All', secs.length);
    present.forEach(function (t) {
      add(t[0], t[1], secs.filter(function (s) {
        return s.getAttribute('data-tab') === t[0];
      }).length);
    });
    show('*');
  }

  // Per-table filter.
  [].forEach.call(document.querySelectorAll('input[data-filter]'), function (inp) {
    var tbl = inp.parentNode.nextElementSibling.querySelector('table');
    if (!tbl) return;
    var rows = [].slice.call(tbl.tBodies[0].rows);
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase();
      rows.forEach(function (r) {
        r.classList.toggle('hid', !!q && r.textContent.toLowerCase().indexOf(q) < 0);
      });
    });
  });

  // Click-to-sort. Numbers and dates sort as values, everything else as text;
  // comparing a number against a string would otherwise order by digit.
  [].forEach.call(document.querySelectorAll('table.sortable'), function (tbl) {
    [].forEach.call(tbl.tHead.rows[0].cells, function (th, i) {
      th.addEventListener('click', function () {
        var body = tbl.tBodies[0];
        var rows = [].slice.call(body.rows);
        var desc = th.classList.contains('asc');
        [].forEach.call(tbl.tHead.rows[0].cells, function (c) {
          c.classList.remove('asc', 'desc');
        });
        th.classList.add(desc ? 'desc' : 'asc');
        function val(r) {
          var t = (r.cells[i] ? r.cells[i].textContent : '').trim();
          var n = parseFloat(t.replace(/[^0-9.eE+-]/g, ''));
          return (t !== '' && !isNaN(n) && /[0-9]/.test(t)) ? n : t.toLowerCase();
        }
        rows.sort(function (a, b) {
          var x = val(a), y = val(b);
          if (typeof x === 'number' && typeof y === 'number') return x - y;
          return String(x) < String(y) ? -1 : String(x) > String(y) ? 1 : 0;
        });
        if (desc) rows.reverse();
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
  });
})();
</script>
"""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

# Which tab each section lands in, matched on a distinctive word in its title.
# Kept as a table rather than an argument at all 17 call sites so that adding a
# section does not mean touching two places — an untagged one simply falls into
# Overview, which is the right default.
_TAB_ORDER = [
    ("overview",     "Overview"),
    ("transactions", "Transactions"),
    ("chat",         "Chat & Contacts"),
    ("identity",     "Identity & Accounts"),
    ("findings",     "Findings"),
    ("recovery",     "Deleted Records"),
    ("custody",      "Custody & Integrity"),
]
_TAB_RULES = [
    ("custody",      ("custody", "hash manifest", "integrity", "extraction problem")),
    ("transactions", ("transaction", "counterpart", "yearly", "volume", "ledger")),
    ("chat",         ("chat", "contact", "conversation", "message")),
    ("identity",     ("identity", "account", "vpa", "bank", "device", "payment")),
    ("recovery",     ("deleted", "carved", "recovered")),
    ("findings",     ("signal", "finding", "suspicious")),
]


def _tab_for(title: str) -> str:
    low = title.lower()
    for tab, needles in _TAB_RULES:
        if any(n in low for n in needles):
            return tab
    return "overview"


def _section(title: str, body: str, tab: Optional[str] = None) -> str:
    """One report section, tagged with the tab it belongs to.

    Tabs are a presentation layer over one file: every section is always present
    in the document and the nav only controls which are visible. That keeps the
    report searchable with the browser's own find, printable in full, and
    readable with scripting disabled — none of which holds for a report that
    loads its panes on demand.
    """
    tab = tab or _tab_for(title)
    return (f'<section data-tab="{html.escape(tab)}">'
            f"<h2>{html.escape(title)}</h2>{body}</section>")


def _kv_block(kv: Dict[str, Any]) -> str:
    rows = "".join(
        f"<b>{html.escape(str(k))}</b><span>{html.escape(str(v))}</span>"
        for k, v in kv.items()
    )
    return f"<div class='kv'>{rows}</div>"


def _metric_grid(kv: Dict[str, Any]) -> str:
    cells = "".join(
        f"<div class='metric'><div class='v'>{html.escape(str(v))}</div><div class='l'>{html.escape(str(k))}</div></div>"
        for k, v in kv.items()
    )
    return f"<div class='metric-grid'>{cells}</div>"


def _table(rows: List[Dict[str, Any]], cols: List[str]) -> str:
    if not rows:
        return "<p class='muted'>No records.</p>"
    # A filter box appears above any table long enough to need one. Sorting is
    # click-to-sort on the header. Both are inert without scripting, and the rows
    # remain plain <tr> so the table still prints and copies as a table.
    head = "".join(f"<th data-col='{i}'>{html.escape(c)}</th>" for i, c in enumerate(cols))
    body = []
    for r in rows:
        cells = []
        for c in cols:
            v = r.get(c)
            cells.append(f"<td>{html.escape(_stringify(v))}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    filt = ("<div class='tfilter'><input type='search' placeholder='Filter these "
            f"{len(rows)} rows…' data-filter></div>" if len(rows) > 8 else "")
    return (filt + "<div class='tw'><table class='sortable'><thead><tr>"
            f"{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>")


def _txn_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<p class='muted'>No transactions found.</p>"
    body = []
    for t in rows:
        d = t.get("direction") or ""
        cls = "in" if d == "IN" else "out" if d == "OUT" else ""
        amount = t.get("amount_inr")
        amt_html = (
            f"<span class='amount {('pos' if d=='IN' else 'neg' if d=='OUT' else '')}'>₹ {amount:,.2f}</span>"
            if amount is not None else "<span class='muted'>—</span>"
        )
        when = (t.get("created_at") or {}).get("display", "")
        body.append(
            "<tr>"
            f"<td>{html.escape(when)}</td>"
            f"<td><span class='tag {cls}'>{html.escape(d or '?')}</span></td>"
            f"<td>{amt_html}</td>"
            f"<td>{html.escape(str(t.get('counterparty') or '—'))}</td>"
            f"<td><small>{html.escape(str(t.get('type') or ''))}</small></td>"
            f"<td>{html.escape(str(t.get('state') or ''))}</td>"
            f"<td><small>{html.escape((t.get('note') or '')[:60])}</small></td>"
            f"<td><small>{html.escape(str(t.get('global_payment_id') or '')[:20])}</small></td>"
            "</tr>"
        )
    # This is the table an examiner spends most time in, so it gets the same
    # filter and click-to-sort as the generic ones. It builds its own markup for
    # the direction tag and amount colouring, which is why it has to opt in here
    # rather than inheriting from _table().
    head_cells = "".join(
        f"<th data-col='{i}'>{c}</th>" for i, c in enumerate(
            ["When", "Direction", "Amount", "Counterparty", "Type", "State", "Note", "ID"]))
    filt = ("<div class='tfilter'><input type='search' placeholder='Filter these "
            f"{len(rows)} transactions…' data-filter></div>" if len(rows) > 8 else "")
    return (filt + "<div class='tw'><table class='sortable'><thead><tr>"
            f"{head_cells}</tr></thead><tbody>{''.join(body)}</tbody></table></div>")


def _money(v: Any) -> str:
    try:
        return f"₹ {float(v):,.2f}"
    except Exception:
        return "—"


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

def export_all(case_data: Dict[str, Any], out_dir: str, timeline: List[Dict[str, Any]] = None,
               social_graph: Dict[str, Any] = None, case_root: str = "",
               custody: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    out: Dict[str, Any] = {"directory": out_dir, "files": []}
    if custody:
        manifest_path = os.path.join(out_dir, "chain_of_custody.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(custody, fh, default=str, indent=2)
        out["files"].append(manifest_path)
    out["files"].append(export_master_json(case_data, out_dir))
    out["files"].append(export_transactions_csv(case_data, out_dir))
    out["files"].extend(export_contacts_csv(case_data, out_dir))
    out["files"].extend(export_chat_csv(case_data, out_dir))
    out["files"].extend(export_payment_infra_csv(case_data, out_dir))
    if (case_data.get("deleted_records", {}) or {}).get("records"):
        out["files"].append(export_deleted_records_csv(case_data, out_dir))
    if (case_data.get("notifications", {}) or {}).get("raw_messages"):
        out["files"].append(export_notification_messages_csv(case_data, out_dir))
    if (case_data.get("audit", {}) or {}).get("consents"):
        out["files"].append(export_consents_csv(case_data, out_dir))
    if (case_data.get("identity", {}) or {}).get("accounts"):
        out["files"].append(export_identity_accounts_csv(case_data, out_dir))
    if timeline is not None:
        out["files"].append(export_timeline_csv(timeline, out_dir))
    if social_graph is not None:
        out["files"].append(export_social_graph_csv(social_graph, out_dir))
    out["files"].append(export_html_report(case_data, out_dir, case_root, custody=custody))
    return out
