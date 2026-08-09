"""
PhonePe Android Forensics — Web UI (multi-case)
===========================================
Flask front-end. Cases are managed by `CaseManager` (see case_manager.py).
At any time at most one case is "active" — that's the case the dashboard
+ all evidence views render against.

Run:
    python -m phonepe_forensics.webapp [host:port]
or via run.py:
    python run.py [host:port]
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from jinja2 import Undefined

from flask import (
    Flask, Response, abort, jsonify, redirect, render_template, request,
    send_file, session, url_for, flash,
)

from .case import Case
from .case_manager import manager
from .reports import csv_safe, safe_filename
from . import hunt


log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False
# Re-read templates from disk on every request even though the server runs
# with debug=False — otherwise Jinja caches the compiled template and UI
# edits only appear after a full server restart.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
# A shipped default secret is a known signing key, so anyone can forge a session
# cookie for a workstation that never set the env var. Fall back to a per-process
# random key instead: sessions then end with the process, which for a local
# single-analyst tool is the right trade.
app.secret_key = os.environ.get("PP_FORENSICS_SECRET") or secrets.token_hex(32)

# ── Android build ───────────────────────────────────────────────────────────
# Fully-Android distribution: there is no platform picker and every case is an
# Android acquisition. The flag is read by the routes/context-processor below.
ANDROID_ONLY = True


# ---------------------------------------------------------------------------
# Request guards
# ---------------------------------------------------------------------------

@app.before_request
def _guard_state_changing_requests():
    """Reject cross-origin state changes.

    The server binds to localhost, but any page the analyst has open in the same
    browser can POST to it. Without this check a visited web page could delete
    the case registry or pop the evidence-folder chooser on the workstation.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    source = origin or referer
    if not source:
        # No Origin on a same-origin form post from some older clients; a request
        # with neither header cannot have come from a cross-site fetch.
        return None
    parsed = urlsplit(source)
    if f"{parsed.hostname}:{parsed.port}" != f"{urlsplit(request.host_url).hostname}:{urlsplit(request.host_url).port}":
        log.warning("Rejected cross-origin %s %s from %s", request.method, request.path, source)
        return jsonify({"ok": False, "error": "cross-origin request rejected"}), 403
    return None


# ---------------------------------------------------------------------------
# Helpers / filters
# ---------------------------------------------------------------------------

def _active() -> Case:
    case = manager.get_active_case()
    if case is None:
        abort(503, description="No case is currently loaded.")
    return case


def _int_arg(name: str, default: int, minimum: int = 0, maximum: int = 1_000_000) -> int:
    """Read an integer query parameter without letting `?limit=abc` become a 500."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _safe_get(d: Any, *path, default=None) -> Any:
    cur = d
    for k in path:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
        if cur is None:
            return default
    return cur


@app.template_filter("inr")
def _filter_inr(value: Any) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    return f"₹ {v:,.2f}"


@app.template_filter("ts")
def _filter_ts(value: Any) -> str:
    if isinstance(value, dict):
        return value.get("display") or value.get("iso") or ""
    return value or ""


@app.template_filter("yes_no")
def _filter_yes_no(value: Any) -> str:
    # Absent is not "No". A missing column or JSON key rendered as "No" states a
    # negative fact the evidence does not hold — the same class of error as the
    # hardcoded "on PhonePe: Yes" tile. Undefined arrives here whenever a template
    # reads a key the extractor never set, so it must be caught alongside None.
    if value is None or isinstance(value, Undefined):
        return "—"
    # Sources are not uniformly typed: shared_prefs XML and some JSON payloads
    # store booleans as the strings "true"/"false"/"0", and every non-empty string
    # is truthy, so "false" would read as "Yes".
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return "Yes"
        if v in ("false", "no", "0"):
            return "No"
        # Empty is unknown, not false — same rule as core.tri_bool, so a value
        # rendered here and a value stored in case.data cannot disagree.
        if not v:
            return "—"
        return value
    return "Yes" if value else "No"


@app.template_filter("count")
def _filter_count(value: Any) -> int:
    try:
        return len(value)
    except Exception:
        return 0


@app.context_processor
def _inject():
    case = manager.get_active_case()
    if case:
        ident = case.data.get("identity", {})
        _plat = (case.data.get("_meta") or {}).get("platform", "android")
        return {
            "case_loaded": True,
            "platform": _plat,
            # ui_platform drives branding + theme; an active case always wins over
            # the picker selection so the GUI matches the data being shown.
            "ui_platform": _plat,
            "case_root": case.root,
            "containers": case.paths.summary(),
            "active_case_id": manager.active_id,
            "active_case_name": (manager.get_meta(manager.active_id) or {}).get("name", ""),
            "subject_name": ident.get("registered_name"),
            "subject_upi": ident.get("upi_id"),
            "nav_metrics": {
                "transactions": _safe_get(case.data, "transactions", "summary", "transaction_count", default=0),
                "messages": _safe_get(case.data, "chat", "summary", "message_count", default=0),
                "contacts": _safe_get(case.data, "contacts", "summary", "phonebook_total", default=0),
                "findings": len(case.findings()),
            },
        }
    # No active case: branding/theme follow the picker selection (session). In the
    # standalone Android build there is no picker, so default the workspace to Android.
    sel = session.get("platform") or ("android" if ANDROID_ONLY else None)
    return {
        "case_loaded": False,
        "platform": sel or "android",
        "ui_platform": sel,
        "active_case_id": None,
        "active_case_name": "",
    }


@app.context_processor
def _inject_flags():
    return {"android_only": ANDROID_ONLY}


# ---------------------------------------------------------------------------
# CSV export helpers
# ---------------------------------------------------------------------------

def _csv_response(rows: List[Dict[str, Any]], columns: List[str], filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        out = {}
        for c in columns:
            v = r.get(c)
            if isinstance(v, dict):
                v = v.get("iso") or v.get("display") or json.dumps(v, default=str)
            elif isinstance(v, (list, tuple)):
                v = "; ".join(str(x) for x in v)
            out[c] = csv_safe(v if v is not None else "")
        writer.writerow(out)
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename(filename)}"'},
    )


def _row_blob(row: Dict[str, Any]) -> str:
    """Lower-cased searchable text for one row.

    Scalars are stringified directly and only nested structures go through
    json.dumps; serialising every row in full was the dominant cost of filtering
    a large table, and most columns are scalars.
    """
    parts = []
    for v in row.values():
        if v is None:
            continue
        if isinstance(v, (dict, list, tuple, set)):
            parts.append(json.dumps(v, default=str))
        else:
            parts.append(str(v))
    return " ".join(parts).lower()


def _filter_table(rows: List[Dict[str, Any]], q: str = "", filters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Server-side table filter: full-text + per-column equals."""
    active_filters = {k: v for k, v in (filters or {}).items() if v}
    if not q and not active_filters:
        return rows
    needle = q.lower().strip() if q else None
    filters = active_filters
    out = []
    for r in rows:
        if needle and needle not in _row_blob(r):
            continue
        if filters:
            ok = True
            for k, v in filters.items():
                if not v:
                    continue
                actual = r.get(k)
                if actual is None or str(v).lower() not in str(actual).lower():
                    ok = False
                    break
            if not ok:
                continue
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------------

@app.route("/start")
def page_start():
    """No platform picker in the standalone Android build — go straight to cases."""
    session["platform"] = "android"
    return redirect(url_for("page_cases"))


@app.route("/start/<platform>")
def page_start_select(platform: str):
    if platform not in ("ios", "android"):
        abort(404)
    if ANDROID_ONLY:
        platform = "android"
    session["platform"] = platform
    # Entering a platform workspace de-activates the current case so the GUI
    # (theme + filtered case list) follows the freshly-chosen platform rather
    # than whatever case happened to be open. The case stays cached, so
    # re-opening it from the filtered list is instant (no re-extraction).
    manager.active_id = None
    return redirect(url_for("page_cases"))


@app.route("/cases")
def page_cases():
    return render_template("cases_list.html", cases=manager.list_cases())


@app.route("/cases/new", methods=["GET", "POST"])
def page_case_new():
    if request.method == "POST":
        try:
            meta = manager.create_case(
                name=request.form.get("name", ""),
                mode="single_root",
                single_root=request.form.get("single_root") or None,
                investigator=request.form.get("investigator") or None,
                notes=request.form.get("notes") or None,
                platform="android",
            )
            flash(f"Case '{meta['name']}' created. Click Process to extract evidence.", "ok")
            return redirect(url_for("page_case_detail", case_id=meta["id"]))
        except Exception as exc:
            flash(str(exc), "err")
            return render_template("case_new.html", form=request.form, new_platform="android")
    return render_template("case_new.html", form={}, new_platform="android")


@app.route("/cases/<case_id>")
def page_case_detail(case_id: str):
    meta = manager.get_meta(case_id)
    if not meta:
        abort(404)
    return render_template("case_detail.html", meta=meta, is_active=(manager.active_id == case_id))


@app.route("/cases/<case_id>/process", methods=["POST"])
def page_case_process(case_id: str):
    try:
        manager.load_case(case_id)
        flash("Evidence extraction complete.", "ok")
        return redirect(url_for("page_dashboard"))
    except Exception as exc:
        flash(f"Processing failed: {exc}", "err")
        return redirect(url_for("page_case_detail", case_id=case_id))


@app.route("/cases/<case_id>/activate", methods=["POST"])
def page_case_activate(case_id: str):
    try:
        manager.load_case(case_id)
        return redirect(url_for("page_dashboard"))
    except Exception as exc:
        flash(f"Activation failed: {exc}", "err")
        return redirect(url_for("page_cases"))


@app.route("/cases/<case_id>/delete", methods=["POST"])
def page_case_delete(case_id: str):
    manager.delete_case(case_id)
    flash("Case removed from registry (folders left untouched).", "ok")
    return redirect(url_for("page_cases"))


@app.route("/cases/browse-test", methods=["POST"])
def api_case_validate():
    """Quick pre-flight validation of a path before submitting the form."""
    path = request.json.get("path") if request.is_json else request.form.get("path")
    if not path:
        return jsonify({"ok": False, "error": "path required"}), 400
    if not os.path.isdir(path):
        return jsonify({"ok": False, "error": "not a directory"})
    listing = sorted(os.listdir(path))[:30]
    # Android detection: the com.phonepe.app data dir (has databases/) or its parent.
    looks_android = "databases" in listing or "com.phonepe.app" in listing
    return jsonify({
        "ok": True,
        "listing": listing,
        "looks_like_android": looks_android,
    })




@app.route("/cases/browse-folder", methods=["POST"])
def api_browse_folder():
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", True)
        initial = (request.json or {}).get("initial", os.path.expanduser("~"))
        folder = filedialog.askdirectory(parent=root, initialdir=initial, title="Select Evidence Folder")
        root.destroy()
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)})
    if not folder:
        return jsonify({"ok": False, "cancelled": True})
    return jsonify({"ok": True, "path": os.path.normpath(folder)})

# ---------------------------------------------------------------------------
# Pages (require active case)
# ---------------------------------------------------------------------------

@app.route("/")
def page_dashboard():
    if manager.get_active_case() is None:
        # No case loaded → Android build goes straight to the case list (no picker).
        if ANDROID_ONLY:
            return redirect(url_for("page_cases"))
        return redirect(url_for("page_start"))
    case = _active()
    return render_template(
        "dashboard.html",
        dashboard=case.dashboard(),
        findings=case.findings(),
        timeline=case.timeline(limit=30),
        identity=case.data.get("identity", {}),
        transactions_summary=case.data.get("transactions", {}).get("summary", {}),
    )


@app.route("/identity")
def page_identity():
    case = _active()
    return render_template(
        "identity.html",
        identity=case.data.get("identity", {}),
        txn_summary=case.data.get("transactions", {}).get("summary", {}),
        payment_infra=case.data.get("payment_infra", {}),
        audit=case.data.get("audit", {}),
    )


# ---------------------------------------------------------------------------
# Android-only views (rendered for android cases; backed by AndroidCase modules)
# ---------------------------------------------------------------------------

@app.route("/ledger")
def page_ledger():
    case = _active()
    return render_template("ledger.html", ledger=case.data.get("ledger", {}))


@app.route("/sms")
def page_sms():
    case = _active()
    # SMS↔transaction corroboration (Android-specific analysis lives on AndroidCase)
    corr = case.sms_corroboration() if hasattr(case, "sms_corroboration") else {}
    return render_template("sms.html", sms=case.data.get("sms", {}), corr=corr)


@app.route("/miniapps")
def page_miniapps():
    case = _active()
    return render_template("miniapps.html", miniapps=case.data.get("miniapps", {}))


@app.route("/raw-tables")
def page_raw_tables():
    case = _active()
    return render_template("raw_tables.html", raw=case.data.get("raw_tables", {}),
                           encrypted=case.data.get("encrypted_dbs", {}))


RAW_TABLE_PAGE_SIZE = 500
RAW_TABLE_CSV_CAP = 100_000


def _load_raw_table(case: Case, db: str, table: str, offset: int, limit: int) -> Dict[str, Any]:
    from phonepe_android.extractors_android import load_raw_table
    return load_raw_table(case.paths, db, table, offset=offset, limit=limit)


@app.route("/raw-tables/<db>/<table>")
def page_raw_table_browse(db: str, table: str):
    case = _active()
    offset = _int_arg("offset", 0, maximum=RAW_TABLE_CSV_CAP * 100)
    page = _load_raw_table(case, db, table, offset, RAW_TABLE_PAGE_SIZE)
    if page.get("error"):
        abort(404)
    return render_template("raw_table_detail.html", page=page)


@app.route("/raw-tables/<db>/<table>.csv")
def page_raw_table_csv(db: str, table: str):
    case = _active()
    page = _load_raw_table(case, db, table, 0, RAW_TABLE_CSV_CAP)
    if page.get("error"):
        abort(404)
    rows = page["rows"]
    cols = page["columns"] or sorted({k for r in rows for k in r.keys()})
    return _csv_response(rows, cols, f"{db}.{table}.csv")


def _deleted_view(case: Case):
    deleted = case.data.get("deleted_records", {}) or {}
    records = deleted.get("records", [])
    q = (request.args.get("q") or "").strip()
    table_filter = request.args.get("table", "")
    if table_filter:
        records = [r for r in records
                   if r.get("table") == table_filter
                   or table_filter in (r.get("candidate_tables") or [])]
    if q:
        records = _filter_table(records, q=q)
    tables = sorted({r.get("table") for r in deleted.get("records", []) if r.get("table")})
    return deleted, records, tables, q, table_filter


@app.route("/deleted")
def page_deleted():
    case = _active()
    deleted, records, tables, q, table_filter = _deleted_view(case)
    return render_template("deleted.html", deleted=deleted, records=records[:2000],
                           tables=tables, q=q, table_filter=table_filter)


@app.route("/deleted/export.csv")
def export_deleted_csv():
    case = _active()
    _, records, _, _, _ = _deleted_view(case)
    rows = []
    for r in records:
        row = {
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
        }
        # Recovered values go in one column so a single CSV can carry rows from
        # tables with different shapes without inventing a common schema.
        row["recovered_values"] = json.dumps(r.get("row", {}), default=str)
        rows.append(row)
    cols = ["table", "confidence", "extent_confidence", "value_confidence",
            "implausible_columns", "partial", "truncated", "ambiguous", "pool",
            "database", "source_file", "page", "file_offset", "type_lost_for",
            "recovered_values"]
    return _csv_response(rows, cols, "recovered_deleted_records.csv")


@app.route("/prefs")
def page_prefs():
    case = _active()
    return render_template("prefs.html", prefs=case.data.get("shared_prefs", {}))


@app.route("/files")
def page_files():
    case = _active()
    return render_template("files.html", files=case.data.get("files", {}))


@app.route("/provenance")
def page_provenance():
    _active()
    from phonepe_android.provenance_android import get_provenance
    return render_template("provenance.html", prov=get_provenance())


def _filter_transactions(txns: List[Dict[str, Any]], args) -> Dict[str, Any]:
    """Rich server-side filter for transactions with date / amount range,
    text search, multi-select facets, and sort."""
    q = (args.get("q") or "").strip()
    direction = args.get("direction", "")
    state = args.get("state", "")
    txn_type = args.get("type", "")
    instrument = args.get("instrument", "")
    counterparty = (args.get("counterparty") or "").strip()
    date_from = args.get("date_from", "")  # YYYY-MM-DD
    date_to = args.get("date_to", "")
    amount_min = args.get("amount_min", "")
    amount_max = args.get("amount_max", "")
    sort = args.get("sort", "date_desc")  # date_desc, date_asc, amount_desc, amount_asc

    def _epoch_ms(dt_str: str, end_of_day: bool = False) -> Optional[int]:
        if not dt_str:
            return None
        try:
            from datetime import datetime, timezone
            dt = datetime.strptime(dt_str.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999000)
            return int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            return None

    df_ms = _epoch_ms(date_from, end_of_day=False)
    dt_ms = _epoch_ms(date_to, end_of_day=True)
    try:
        amin = float(amount_min) if amount_min else None
    except (TypeError, ValueError):
        amin = None
    try:
        amax = float(amount_max) if amount_max else None
    except (TypeError, ValueError):
        amax = None

    out = []
    needle = q.lower() if q else None
    counterparty_needle = counterparty.lower() if counterparty else None
    for t in txns:
        if direction and (t.get("direction") or "").upper() != direction.upper():
            continue
        if state and (t.get("state") or "").upper() != state.upper():
            continue
        if txn_type and txn_type not in (t.get("type") or ""):
            continue
        if instrument and instrument not in (t.get("received_in_type") or t.get("transfer_mode") or ""):
            continue
        if counterparty_needle:
            cp_blob = " ".join(str(x) for x in (
                t.get("counterparty"), t.get("counterparty_phone"),
                t.get("counterparty_vpa"), t.get("counterparty_cbs_name"),
                t.get("counterparty_resolved"), t.get("counterparty_phone_full"),
            ) if x).lower()
            if counterparty_needle not in cp_blob:
                continue
        if df_ms is not None or dt_ms is not None:
            ts = (t.get("created_at") or {}).get("epoch_ms")
            if ts is None:
                continue
            if df_ms is not None and ts < df_ms:
                continue
            if dt_ms is not None and ts > dt_ms:
                continue
        if amin is not None or amax is not None:
            amt = t.get("amount_inr")
            if amt is None:
                continue
            if amin is not None and amt < amin:
                continue
            if amax is not None and amt > amax:
                continue
        if needle:
            blob = json.dumps(t, default=str).lower()
            if needle not in blob:
                continue
        out.append(t)

    # Sort
    if sort == "date_asc":
        out.sort(key=lambda t: (t.get("created_at") or {}).get("epoch_ms") or 0)
    elif sort == "amount_desc":
        out.sort(key=lambda t: t.get("amount_inr") or 0, reverse=True)
    elif sort == "amount_asc":
        out.sort(key=lambda t: t.get("amount_inr") if t.get("amount_inr") is not None else float("inf"))
    elif sort == "counterparty":
        out.sort(key=lambda t: (t.get("counterparty") or "").lower())
    else:  # date_desc default
        out.sort(key=lambda t: (t.get("created_at") or {}).get("epoch_ms") or 0, reverse=True)

    return {
        "rows": out,
        "filters": {
            "q": q, "direction": direction, "state": state, "type": txn_type,
            "instrument": instrument, "counterparty": counterparty,
            "date_from": date_from, "date_to": date_to,
            "amount_min": amount_min, "amount_max": amount_max,
            "sort": sort,
        },
    }


@app.route("/transactions")
def page_transactions():
    case = _active()
    txns = case.data.get("transactions", {}).get("transactions", [])
    summary = case.data.get("transactions", {}).get("summary", {})
    res = _filter_transactions(txns, request.args)

    # Build dropdown facets from the unfiltered list
    types_seen = sorted({t.get("type") for t in txns if t.get("type")})
    states_seen = sorted({t.get("state") for t in txns if t.get("state")})
    instruments_seen = sorted({t.get("received_in_type") or t.get("transfer_mode")
                               for t in txns if t.get("received_in_type") or t.get("transfer_mode")})

    # Filtered totals
    total_in = sum(t.get("amount_inr") or 0 for t in res["rows"] if t.get("direction") == "IN")
    total_out = sum(t.get("amount_inr") or 0 for t in res["rows"] if t.get("direction") == "OUT")

    return render_template(
        "transactions.html",
        transactions=res["rows"],
        total_count=len(txns),
        summary=summary,
        filters=res["filters"],
        types=types_seen,
        states=states_seen,
        instruments=instruments_seen,
        filtered_total_in=total_in,
        filtered_total_out=total_out,
    )


@app.route("/transactions/export.csv")
def export_transactions_csv():
    case = _active()
    txns = case.data.get("transactions", {}).get("transactions", [])
    res = _filter_transactions(txns, request.args)
    cols = [
        "created_at", "global_payment_id", "type", "state", "direction",
        "amount_inr", "counterparty", "counterparty_resolved",
        "counterparty_resolved_source", "counterparty_phone_full",
        "counterparty_phone", "counterparty_vpa",
        "counterparty_cbs_name", "self_account_holder", "self_account_masked",
        "self_vpa", "self_ifsc", "utr", "transfer_mode", "initiation_mode",
        "upi_initiation_mode", "is_qr_scan", "is_intent", "category_code",
        "received_in_type", "merchant_name", "biller_name", "recharge_number",
        "note", "search_token",
    ]
    return _csv_response(res["rows"], cols, "transactions.csv")


@app.route("/transactions/<path:txn_id>")
def page_transaction_detail(txn_id: str):
    case = _active()
    for t in case.data.get("transactions", {}).get("transactions", []):
        if t.get("global_payment_id") == txn_id or t.get("entity_id") == txn_id:
            corr = case.corroboration()
            # Match on the entry's full alias set: a payment's identifiers are all
            # folded onto one entry, and txn_id is only the first of them.
            wanted = {str(x) for x in (t.get("global_payment_id"), t.get("entity_id")) if x}
            corr_entry = next((it for it in corr["items"]
                               if wanted & set(it.get("aliases") or [it["txn_id"]])), None)
            related_chat = []
            for m in case.data.get("chat", {}).get("messages", []):
                if t.get("global_payment_id") and m.get("transaction_id") == t.get("global_payment_id"):
                    related_chat.append(m)
            return render_template("transaction_detail.html", txn=t, corroboration=corr_entry, chat_messages=related_chat)
    abort(404)


def _contact_chat_map(case: Case) -> Dict[str, str]:
    """Map a contact's connection_id → the chat group_id to open for them.

    Chat members (topicMember) carry public_id (=connectionId) + group_id (=memberTopicId).
    A contact's `connect_id` is that same connectionId, so we can deep-link the contact's
    name straight to /chat/<group_id>. When a connection appears in several groups we prefer
    the smallest (a 1:1 direct chat over a big group). Android-shaped data only."""
    chat = case.data.get("chat", {})
    members = chat.get("members", [])
    if not members:
        return {}
    # group_id -> member_count (to prefer the most direct/1:1 chat)
    gsize = {g.get("group_id"): (g.get("member_count") or 99)
             for g in chat.get("groups", [])}
    best: Dict[str, str] = {}
    best_sz: Dict[str, int] = {}
    for m in members:
        if m.get("is_self"):
            continue
        cid, gid = m.get("public_id"), m.get("group_id")
        if not cid or not gid:
            continue
        sz = gsize.get(gid, 99)
        if cid not in best or sz < best_sz[cid]:
            best[cid], best_sz[cid] = gid, sz
    return best


@app.route("/contacts")
def page_contacts():
    case = _active()
    contacts = case.data.get("contacts", {})
    platform = (case.data.get("_meta") or {}).get("platform", "android")
    q = request.args.get("q", "")
    if q:
        contacts = dict(contacts)
        contacts["cyclops_contacts"] = _filter_table(contacts.get("cyclops_contacts", []), q=q)
        contacts["phonebook_contacts"] = _filter_table(contacts.get("phonebook_contacts", []), q=q)
    # Android: deep-link each contact's name to that person's chat thread.
    if platform == "android":
        cmap = _contact_chat_map(case)
        if cmap:
            contacts = dict(contacts)
            for key in ("cyclops_contacts", "phonebook_contacts"):
                rows = []
                for c in contacts.get(key, []):
                    gid = cmap.get(c.get("connect_id"))
                    rows.append({**c, "chat_group_id": gid} if gid else c)
                contacts[key] = rows
    return render_template("contacts.html", contacts=contacts, q=q)


@app.route("/contacts/cyclops.csv")
def export_contacts_cyclops_csv():
    case = _active()
    rows = _filter_table(case.data.get("contacts", {}).get("cyclops_contacts", []),
                         q=request.args.get("q", ""))
    cols = ["phone", "verified_name", "external_vpa", "external_vpa_name",
            "on_phonepe", "upi_state", "country_code", "region", "last_synced", "connect_id"]
    return _csv_response(rows, cols, "contacts_phonepe.csv")


@app.route("/contacts/phonebook.csv")
def export_contacts_phonebook_csv():
    case = _active()
    rows = _filter_table(case.data.get("contacts", {}).get("phonebook_contacts", []),
                         q=request.args.get("q", ""))
    cols = ["full_name", "normalized", "raw_number", "country_code", "region",
            "creation_time", "is_valid", "deleted", "has_image", "image_size"]
    return _csv_response(rows, cols, "phonebook.csv")


@app.route("/social-graph")
def page_social_graph():
    case = _active()
    sg = case.social_graph()
    q = request.args.get("q", "")
    kind = request.args.get("kind", "")
    nodes = sg["nodes"]
    if q or kind:
        nodes = _filter_table(nodes, q=q, filters={"kind": kind})
    return render_template("social_graph.html", graph={"summary": sg["summary"], "nodes": nodes},
                           q=q, kind=kind, total=len(sg["nodes"]))


@app.route("/social-graph/export.csv")
def export_social_graph_csv():
    case = _active()
    sg = case.social_graph()
    rows = _filter_table(sg["nodes"], q=request.args.get("q", ""), filters={"kind": request.args.get("kind", "")})
    cols = ["node_id", "kind", "name", "phone", "vpa", "on_phonepe",
            "txn_count_in", "txn_count_out", "txn_total_in", "txn_total_out",
            "chat_message_count", "chat_payment_count",
            "first_seen_iso", "last_seen_iso", "evidence_sources"]
    return _csv_response(rows, cols, "social_graph.csv")


@app.route("/chat")
def page_chat():
    case = _active()
    chat = case.data.get("chat", {})
    q = request.args.get("q", "")
    type_filter = request.args.get("type", "")
    msgs = chat.get("messages", [])
    if q or type_filter:
        msgs = _filter_table(msgs, q=q, filters={"type": type_filter})
    return render_template("chat.html",
                           chat={**chat, "messages_filtered": msgs},
                           q=q, type_filter=type_filter, total_messages=len(chat.get("messages", [])))


@app.route("/chat/messages.csv")
def export_chat_messages_csv():
    case = _active()
    chat = case.data.get("chat", {})
    msgs = _filter_table(chat.get("messages", []),
                         q=request.args.get("q", ""),
                         filters={"type": request.args.get("type", "")})
    cols = ["created_at", "thread_id", "type", "amount_inr", "transaction_id",
            "state", "payment_state", "instrument", "utr", "external_vpa", "external_bank",
            "sender_name", "sender_phone_masked", "sender_role",
            "receiver_name", "receiver_phone_masked",
            "note", "text_message", "gift_message", "reward_type"]
    return _csv_response(msgs, cols, "chat_messages.csv")


@app.route("/chat/groups.csv")
def export_chat_groups_csv():
    case = _active()
    rows = case.data.get("chat", {}).get("groups", [])
    cols = ["group_id", "name", "type", "subsystem", "subscription", "active",
            "member_count", "namespace", "created_at", "updated_at"]
    return _csv_response(rows, cols, "chat_groups.csv")


@app.route("/chat/<group_id>/export.csv")
def export_chat_group_csv(group_id: str):
    case = _active()
    chat = case.data.get("chat", {})
    msgs = [m for m in chat.get("messages", []) if m.get("thread_id") == group_id]
    msgs.sort(key=lambda m: (m.get("created_at") or {}).get("epoch_ms") or 0)
    cols = ["created_at", "type", "sender_name", "sender_phone_masked",
            "receiver_name", "amount_inr", "transaction_id", "utr", "state",
            "instrument", "note", "text_message"]
    # group_id comes straight off the URL; unsanitised it can inject a newline or
    # a quote into Content-Disposition, which Werkzeug refuses to serialise.
    slug = safe_filename(group_id[:16], fallback="thread")
    return _csv_response(msgs, cols, f"chat_thread_{slug}.csv")


@app.route("/chat/<group_id>")
def page_chat_group(group_id: str):
    case = _active()
    chat = case.data.get("chat", {})
    group = next((g for g in chat.get("groups", []) if g.get("group_id") == group_id), None)
    if not group:
        abort(404)
    msgs = [m for m in chat.get("messages", []) if m.get("thread_id") == group_id]
    msgs.sort(key=lambda m: (m.get("created_at") or {}).get("epoch_ms") or 0)
    members = [m for m in chat.get("members", []) if m.get("group_id") == group_id]
    self_name = case.data.get("identity", {}).get("registered_name", "")
    return render_template("chat_group.html", group=group, messages=msgs,
                           members=members, self_name=self_name,
                           counterparty=None)


@app.route("/notifications")
def page_notifications():
    case = _active()
    notifs = case.data.get("notifications", {})
    q = request.args.get("q", "")
    sub = request.args.get("subsystem", "")
    topics = notifs.get("topics", [])
    if q or sub:
        topics = _filter_table(topics, q=q, filters={"subsystem": sub})
    # Delivered notification bodies (messageDataStore). Only the ones the user was
    # actually shown are tabled; sync instructions are counted but not listed.
    messages = [m for m in notifs.get("raw_messages", []) if m.get("is_notification")]
    if q:
        messages = _filter_table(messages, q=q)
    messages.sort(key=lambda m: (m.get("created_at") or {}).get("epoch_ms") or 0,
                  reverse=True)
    return render_template("notifications.html",
                           notifications={**notifs, "topics_view": topics,
                                          "messages_view": messages[:3000]},
                           q=q, sub=sub, total_topics=len(notifs.get("topics", [])))


@app.route("/notifications/messages.csv")
def export_notification_messages_csv():
    case = _active()
    rows = [m for m in case.data.get("notifications", {}).get("raw_messages", [])
            if m.get("is_notification") or not request.args.get("shown_only")]
    rows = _filter_table(rows, q=request.args.get("q", ""))
    cols = ["created_at", "sent_at", "kind", "title", "subtitle", "body", "deeplink",
            "template", "topic_id", "message_id", "expires_at"]
    return _csv_response(rows, cols, "notification_messages.csv")


@app.route("/notifications/export.csv")
def export_notifications_csv():
    case = _active()
    rows = _filter_table(case.data.get("notifications", {}).get("topics", []),
                         q=request.args.get("q", ""),
                         filters={"subsystem": request.args.get("subsystem", "")})
    cols = ["topic_id", "subsystem", "subscription_status", "status",
            "raw_message_count", "single_use", "created_at", "updated_at",
            "last_sync", "expiry_at", "storage_type"]
    return _csv_response(rows, cols, "notifications.csv")


@app.route("/analytics")
def page_analytics():
    return render_template("analytics.html", analytics=_active().data.get("analytics", {}))


@app.route("/analytics/kn.csv")
def export_kn_events_csv():
    case = _active()
    rows = case.data.get("analytics", {}).get("kn_events", [])
    cols = ["id", "event_name", "identifier", "primary_key", "timestamp", "funnel_info_preview"]
    return _csv_response(rows, cols, "kn_events.csv")


@app.route("/financial")
def page_financial():
    return render_template("financial.html", financial=_active().data.get("financial", {}))


@app.route("/financial/<kind>.csv")
def export_financial_csv(kind: str):
    case = _active()
    fin = case.data.get("financial", {})
    if kind == "rewards":
        cols = ["created_at", "type", "state", "amount_inr", "title", "coupon_code",
                "linked_transaction", "expires_at", "claimed_at", "share_message"]
        return _csv_response(fin.get("rewards", []), cols, "rewards.csv")
    if kind == "donations":
        cols = ["name", "subname", "category_id", "campaign_id", "status", "active", "price_inr", "created_at"]
        return _csv_response(fin.get("donations", []), cols, "donations.csv")
    if kind == "offers":
        cols = ["title", "type", "state", "action", "starts", "ends", "category_id", "offer_id"]
        return _csv_response(fin.get("offers", []), cols, "offers.csv")
    if kind == "mf":
        cols = ["amc", "name", "fund_id", "category", "enabled", "updated_at"]
        return _csv_response(fin.get("mutual_funds", []), cols, "mutual_funds.csv")
    abort(404)


@app.route("/travel")
def page_travel():
    return render_template("travel.html", travel=_active().data.get("travel", {}))


@app.route("/travel/export.csv")
def export_travel_csv():
    case = _active()
    rows = case.data.get("travel", {}).get("journeys", [])
    cols = ["journey_id", "name", "description", "namespace", "type", "state",
            "entity_type", "created_at", "updated_at"]
    return _csv_response(rows, cols, "travel_journeys.csv")


@app.route("/payment-infra")
def page_payment_infra():
    return render_template("payment_infra.html", pi=_active().data.get("payment_infra", {}))


@app.route("/payment-infra/banks.csv")
def export_payment_banks_csv():
    case = _active()
    rows = case.data.get("payment_infra", {}).get("supported_banks", [])
    cols = ["id", "name", "ifsc_prefix", "central_ifsc", "upi", "upi_mandate",
            "ccupi", "lite", "active", "partner"]
    return _csv_response(rows, cols, "supported_banks.csv")


@app.route("/payment-infra/cards.csv")
def export_payment_cards_csv():
    case = _active()
    rows = case.data.get("payment_infra", {}).get("linked_cards", [])
    cols = ["card_id", "alias", "type", "issuer", "bank_code", "masked",
            "holder", "status", "cobranding", "updated_at"]
    return _csv_response(rows, cols, "linked_cards.csv")


@app.route("/config")
def page_config():
    return render_template("config_state.html", config=_active().data.get("config_state", {}))


@app.route("/config/<kind>.csv")
def export_config_csv(kind: str):
    case = _active()
    cs = case.data.get("config_state", {})
    if kind == "keys":
        cols = ["key", "team", "org", "is_json", "value_size", "value_preview"]
        return _csv_response(cs.get("config_keys", []), cols, "config_keys.csv")
    if kind == "experiments":
        cols = ["experiment_id", "activity_id", "summary", "type", "state", "mode",
                "version", "started", "ends", "client_id"]
        return _csv_response(cs.get("experiments", []), cols, "experiments.csv")
    if kind == "buckets":
        cols = ["bucket_id", "name", "summary", "status", "percentage", "type", "experiment_pk"]
        return _csv_response(cs.get("buckets", []), cols, "buckets.csv")
    abort(404)


@app.route("/recommendations")
def page_recommendations():
    return render_template("recommendations.html", recs=_active().data.get("recommendations", {}))


@app.route("/media")
def page_media():
    return render_template("media.html", media=_active().data.get("media", {}))


@app.route("/search")
def page_search():
    return render_template("search.html", search=_active().data.get("search", {}))


@app.route("/search/sitemap.csv")
def export_search_sitemap_csv():
    case = _active()
    rows = case.data.get("search", {}).get("sitemap", [])
    cols = ["id", "use_case", "deeplink", "keywords", "image_url", "updated_at"]
    return _csv_response(rows, cols, "sitemap.csv")


@app.route("/webkit")
def page_webkit():
    return render_template("webkit.html", webkit=_active().data.get("webkit", {}))


@app.route("/webkit/cookies.csv")
def export_cookies_csv():
    case = _active()
    rows = case.data.get("webkit", {}).get("cookies", [])
    cols = ["domain", "name", "path", "value", "creation_iso", "expiry_iso", "flags"]
    return _csv_response(rows, cols, "cookies.csv")


@app.route("/webkit/domains.csv")
def export_webkit_domains_csv():
    case = _active()
    rows = case.data.get("webkit", {}).get("resource_load_stats", [])
    cols = ["domain", "had_user_interaction", "last_user_interaction", "last_seen", "grandfathered"]
    return _csv_response(rows, cols, "webkit_domains.csv")


@app.route("/audit")
def page_audit():
    case = _active()
    return render_template("audit.html",
                           audit=case.data.get("audit", {}),
                           extraction_errors=case.extraction_errors(),
                           evidence_warnings=case.evidence_warnings(),
                           manifest=case.evidence_manifest(),
                           case_root=case.root)


@app.route("/audit/consents.csv")
def export_consents_csv_route():
    case = _active()
    rows = _filter_table(case.data.get("audit", {}).get("consents", []),
                         q=request.args.get("q", ""))
    cols = ["source", "destination", "accept_type", "state", "subject_id",
            "subject_ref", "definition", "sync_state", "consent_id", "end_time"]
    return _csv_response(rows, cols, "consents.csv")


@app.route("/timeline")
def page_timeline():
    case = _active()
    limit = _int_arg("limit", 5000, minimum=1)
    q = request.args.get("q", "")
    src = request.args.get("source", "")
    # The true total comes from the uncapped timeline, never from the capped slice.
    # Reading `total` off the already-limited list reported the cap as the total, so
    # the page claimed to show everything while silently dropping the oldest events
    # — which is what happened as soon as decoded notifications pushed the event
    # count past the default limit.
    full = case.timeline(limit=999_999)
    total = len(full)
    events = _filter_table(full, q=q, filters={"source": src}) if (q or src) else full
    matched = len(events)
    return render_template("timeline.html", events=events[:limit], q=q, src=src,
                           total=total, matched=matched, limit=limit,
                           truncated=matched > limit)


@app.route("/timeline/export.csv")
def export_timeline_csv():
    case = _active()
    rows = case.timeline(limit=_int_arg("limit", 5000, minimum=1))
    rows = _filter_table(rows, q=request.args.get("q", ""), filters={"source": request.args.get("source", "")})
    cols = ["when_iso", "source", "kind", "title", "amount_inr", "link_id"]
    return _csv_response(rows, cols, "unified_timeline.csv")


@app.route("/findings")
def page_findings():
    return render_template("findings.html", findings=_active().findings())


@app.route("/findings/export.csv")
def export_findings_csv():
    cols = ["severity", "category", "title"]
    return _csv_response(_active().findings(), cols, "findings.csv")


@app.route("/database-browser")
def page_db_browser():
    case = _active()
    return render_template("database_browser.html",
                           inventory=case.data.get("database_inventory", []))


SQL_ROW_LIMIT = 1000


def _case_database_paths(case: Case) -> Dict[str, str]:
    """realpath → declared path for every database belonging to the active case."""
    allowed: Dict[str, str] = {}
    for entry in case.data.get("database_inventory", []) or []:
        p = entry.get("path")
        if p:
            allowed[os.path.realpath(p)] = p
    return allowed


@app.route("/database-browser/sql", methods=["GET"])
def page_db_sql():
    case = _active()
    db_path = request.args.get("db")
    sql = request.args.get("sql", "")
    result = None
    columns: List[str] = []
    error = None
    truncated = False
    if db_path and sql:
        allowed = _case_database_paths(case)
        sql_stripped = sql.strip().rstrip(";")
        if os.path.realpath(db_path) not in allowed:
            # Without this the console is an arbitrary-file SQLite reader: any
            # path on the workstation, including another investigation's case.
            error = "That database is not part of this case."
        elif not sql_stripped.upper().startswith(("SELECT", "PRAGMA", "EXPLAIN", "WITH")):
            error = "Only SELECT / PRAGMA / EXPLAIN / WITH queries are allowed."
        elif ";" in sql_stripped:
            error = "Multiple statements are not allowed."
        else:
            try:
                from .core import SQLiteReader
                with SQLiteReader(db_path) as db:
                    # Row-capping happens at fetch time. Appending " LIMIT 1000"
                    # to the analyst's SQL is a syntax error for PRAGMA, for
                    # EXPLAIN, and for any query that already has its own LIMIT.
                    result, columns, truncated = db.query_rows(
                        sql_stripped, max_rows=SQL_ROW_LIMIT)
            except Exception as exc:
                error = str(exc)
    return render_template("database_sql.html",
                           inventory=case.data.get("database_inventory", []),
                           db_path=db_path, sql=sql, row_limit=SQL_ROW_LIMIT,
                           result=result, columns=columns, error=error,
                           truncated=truncated)


@app.route("/counterparty")
def page_counterparty():
    case = _active()
    q = request.args.get("q", "").strip()
    profile = case.lookup_counterparty(q) if q else None
    return render_template("counterparty.html", q=q, profile=profile)


# ---------------------------------------------------------------------------
# Hunting dashboard (PPQL)
# ---------------------------------------------------------------------------

@app.route("/hunt")
def page_hunt():
    case = _active()
    query = request.args.get("q", "")
    result = None
    if query:
        result = hunt.run_query(query, case.hunt_indexes())
    return render_template(
        "hunt.html",
        query=query,
        result=result,
        indexes_help=hunt.list_indexes_help(),
    )


@app.route("/hunt/export.csv")
def export_hunt_csv():
    case = _active()
    query = request.args.get("q", "")
    if not query:
        abort(400)
    result = hunt.run_query(query, case.hunt_indexes())
    if result.get("error"):
        return _csv_response([], ["error"], "hunt_error.csv")
    cols = result["columns"] or list(result["rows"][0].keys()) if result["rows"] else ["_empty"]
    return _csv_response(result["rows"], cols, "hunt_result.csv")


# ---------------------------------------------------------------------------
# Research document (in-app)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Exports page
# ---------------------------------------------------------------------------

@app.route("/exports")
def page_exports():
    return render_template("exports.html",
                           exports_dir=os.path.join("exports"),
                           existing=_existing_exports())


def _existing_exports() -> List[Dict[str, Any]]:
    base = os.path.join(os.getcwd(), "exports")
    if not os.path.isdir(base):
        return []
    out = []
    for d in sorted(os.listdir(base)):
        full = os.path.join(base, d)
        if os.path.isdir(full):
            files = []
            for f in os.listdir(full):
                fp = os.path.join(full, f)
                if os.path.isfile(fp):
                    files.append({"name": f, "size": os.path.getsize(fp), "path": fp})
            out.append({"case": d, "dir": full, "files": files})
    return out


@app.route("/api/export", methods=["POST"])
def api_export():
    case = _active()
    info = case.export_all(base_dir=os.path.join(os.getcwd(), "exports"),
                           meta=manager.get_meta(manager.active_id) or {})
    return jsonify({"ok": True, **info})


# ---------------------------------------------------------------------------
# Misc API
# ---------------------------------------------------------------------------

@app.route("/api/file")
def api_file():
    p = request.args.get("p")
    if not p or not os.path.isfile(p):
        abort(404)
    case = _active()
    real = os.path.realpath(p)
    allowed_roots = [os.path.realpath(case.root)]
    # getattr so this works regardless of the CasePaths shape (Android uses
    # app_dir/databases_dir/…; the iOS-era app_domain/group_* may be absent).
    for attr in ("app_dir", "databases_dir", "shared_prefs_dir", "files_dir",
                 "webview_dir", "app_domain", "group_app", "group_shared"):
        d = getattr(case.paths, attr, None)
        if d:
            allowed_roots.append(os.path.realpath(d))
    allowed_roots.append(os.path.realpath(os.path.join(os.getcwd(), "exports")))
    if not any(_is_within(real, r) for r in allowed_roots):
        abort(403)
    return send_file(real)


def _is_within(path: str, root: str) -> bool:
    """True when `path` is `root` or lives underneath it.

    A prefix test is not containment: `/cases/acme` is a prefix of
    `/cases/acme-OTHER`, so startswith() serves files from a sibling case.
    """
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


@app.route("/api/blob")
def api_blob():
    case = _active()
    tid = request.args.get("id", "")
    for t in case.data.get("transactions", {}).get("transactions", []):
        if t.get("global_payment_id") == tid or t.get("entity_id") == tid:
            return jsonify({
                "raw_data": t.get("raw_data"),
                "raw_tags": t.get("raw_tags"),
                "all_tags": t.get("all_tags"),
            })
    abort(404)


@app.route("/api/timeline")
def api_timeline():
    return jsonify(_active().timeline(limit=_int_arg("limit", 5000, minimum=1)))


@app.route("/api/findings")
def api_findings():
    return jsonify(_active().findings())


@app.route("/api/hunt", methods=["POST"])
def api_hunt():
    case = _active()
    payload = request.get_json(silent=True) or {}
    query = payload.get("q", "")
    return jsonify(hunt.run_query(query, case.hunt_indexes()))


@app.errorhandler(503)
def _err_503(e):
    return redirect(url_for("page_cases"))


@app.errorhandler(404)
def _err_404(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def _err_500(e):
    # str(e) here is the raw exception: filesystem paths, SQL text, evidence
    # values. Log it for the analyst's console, show the page a generic message.
    log.exception("Unhandled error serving %s", request.path)
    return render_template(
        "error.html", code=500,
        message="Internal error. See the server console for details.",
    ), 500


# /avatar and /app-icon are gone. Android acquisitions store no local profile
# photos keyed by phone (the contacts table holds remote URLs only) and no icon
# assets ship with the tool, so both endpoints could only ever 404 — one request
# per contact, per page load. The templates render initials directly instead.




# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = argv or sys.argv[1:]
    host_port = argv[0] if argv else "127.0.0.1:5000"
    host, _, port = host_port.partition(":")
    print(f"[*] Starting PhonePe Forensics on http://{host or '127.0.0.1'}:{port or '5000'}/")
    app.run(host=host or "127.0.0.1", port=int(port or "5000"), debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
