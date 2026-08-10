"""
PhonePe iOS Forensics — Report Exporter
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
from typing import Any, Dict, Iterable, List

# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def _write_csv(path: str, fieldnames: List[str], rows: Iterable[Dict[str, Any]]):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _stringify(r.get(k)) for k in fieldnames})


_CSV_INJECT = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection.

    Evidence is suspect-controlled: a display name or chat note of
    `=cmd|' /C calc'!A1` executes when the examiner opens the export in Excel. A
    leading apostrophe makes the cell literal text without changing what is read.
    The HTML report already escapes correctly; this is the CSV path.
    """
    if value[:1] in _CSV_INJECT:
        return "'" + value
    return value


def _stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):
        return csv_safe(v.get("iso") or v.get("display") or json.dumps(v, default=str))
    if isinstance(v, (list, tuple)):
        return csv_safe("; ".join(str(x) for x in v))
    return csv_safe(str(v))


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
<title>PhonePe iOS Forensics Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0c0e16;color:#e5e7eb;margin:0;padding:0}}
header{{background:linear-gradient(120deg,#5b21b6,#7e22ce);padding:32px 48px;border-bottom:1px solid #1f2937}}
header h1{{margin:0 0 6px;font-size:28px;letter-spacing:-.4px}}
header p{{margin:0;color:#e9d5ff}}
main{{padding:32px 48px;max-width:1280px;margin:0 auto}}
section{{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:22px 26px;margin:22px 0}}
section h2{{margin:0 0 16px;font-size:18px;color:#a78bfa;letter-spacing:.3px;text-transform:uppercase;font-weight:600}}
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
<h1>PhonePe iOS Forensics — Evidence Report</h1>
<p>Generated {generated} · Case: {case_root}</p>
</header>
<main>
{body}
</main>
</body></html>
"""


def export_html_report(case_data: Dict[str, Any], out_dir: str, case_root: str = "") -> str:
    parts: List[str] = []

    # Identity
    ident = case_data.get("identity", {})
    parts.append(_section("Identity",
        _kv_block({
            "Registered name": ident.get("registered_name") or "—",
            "Primary UPI ID": ident.get("upi_id") or "—",
            "Phones seen": ", ".join(ident.get("phones_seen", [])) or "—",
            "AppsFlyer User ID": ident.get("device_identifiers", {}).get("appsflyer_user_id") or "—",
            "Firebase Install ID": ident.get("device_identifiers", {}).get("firebase_install_id") or "—",
            "Google Ads paid_v2": ident.get("device_identifiers", {}).get("gads_paid_v2") or "—",
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

    # Top counterparties
    top_cp = txn_summary.get("top_counterparties", [])
    if top_cp:
        parts.append(_section("Top Counterparties",
            _table([{"name": n, "txn_count": c} for n, c in top_cp], ["name", "txn_count"])))

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
        generated=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        case_root=html.escape(case_root or "—"),
        body=body,
    )
    path = os.path.join(out_dir, "evidence_report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return path


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _section(title: str, body: str) -> str:
    return f"<section><h2>{html.escape(title)}</h2>{body}</section>"


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
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = []
    for r in rows:
        cells = []
        for c in cols:
            v = r.get(c)
            cells.append(f"<td>{html.escape(_stringify(v))}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _txn_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<p class='muted'>No transactions found.</p>"
    head = "<th>When</th><th>Direction</th><th>Amount</th><th>Counterparty</th><th>Type</th><th>State</th><th>Note</th><th>ID</th>"
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
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _money(v: Any) -> str:
    try:
        return f"₹ {float(v):,.2f}"
    except Exception:
        return "—"


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

def export_all(case_data: Dict[str, Any], out_dir: str, timeline: List[Dict[str, Any]] = None,
               social_graph: Dict[str, Any] = None, case_root: str = "") -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    out: Dict[str, Any] = {"directory": out_dir, "files": []}
    out["files"].append(export_master_json(case_data, out_dir))
    out["files"].append(export_transactions_csv(case_data, out_dir))
    out["files"].extend(export_contacts_csv(case_data, out_dir))
    out["files"].extend(export_chat_csv(case_data, out_dir))
    out["files"].extend(export_payment_infra_csv(case_data, out_dir))
    if timeline is not None:
        out["files"].append(export_timeline_csv(timeline, out_dir))
    if social_graph is not None:
        out["files"].append(export_social_graph_csv(social_graph, out_dir))
    out["files"].append(export_html_report(case_data, out_dir, case_root))
    return out
