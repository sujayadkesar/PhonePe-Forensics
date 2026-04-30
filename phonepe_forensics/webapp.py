"""
PhonePe iOS Forensics — Web UI (multi-case)
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
import os
import sys
from typing import Any, Dict, List, Optional

from flask import (
    Flask, Response, abort, jsonify, redirect, render_template, request,
    send_file, url_for, flash,
)

from .case import Case
from .case_manager import manager
from . import hunt
from . import research_data


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False
app.secret_key = os.environ.get("PP_FORENSICS_SECRET", "phonepe-forensics-local-dev")


# ---------------------------------------------------------------------------
# Helpers / filters
# ---------------------------------------------------------------------------

def _active() -> Case:
    case = manager.get_active_case()
    if case is None:
        abort(503, description="No case is currently loaded.")
    return case


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
        return {
            "case_loaded": True,
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
    return {
        "case_loaded": False,
        "active_case_id": None,
        "active_case_name": "",
    }


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
            out[c] = v if v is not None else ""
        writer.writerow(out)
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _filter_table(rows: List[Dict[str, Any]], q: str = "", filters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Server-side table filter: full-text + per-column equals."""
    if not q and not filters:
        return rows
    needle = q.lower().strip() if q else None
    out = []
    for r in rows:
        if needle:
            blob = json.dumps(r, default=str).lower()
            if needle not in blob:
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

@app.route("/cases")
def page_cases():
    cases = manager.list_cases()
    return render_template("cases_list.html", cases=cases)


@app.route("/cases/new", methods=["GET", "POST"])
def page_case_new():
    if request.method == "POST":
        try:
            mode = request.form.get("mode", "single_root")
            meta = manager.create_case(
                name=request.form.get("name", ""),
                mode=mode,
                single_root=request.form.get("single_root") or None,
                app_domain=request.form.get("app_domain") or None,
                group_app=request.form.get("group_app") or None,
                group_shared=request.form.get("group_shared") or None,
                investigator=request.form.get("investigator") or None,
                notes=request.form.get("notes") or None,
            )
            flash(f"Case '{meta['name']}' created. Click Process to extract evidence.", "ok")
            return redirect(url_for("page_case_detail", case_id=meta["id"]))
        except Exception as exc:
            flash(str(exc), "err")
            return render_template("case_new.html", form=request.form)
    return render_template("case_new.html", form={})


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
    has_app_domain = any(n == "AppDomain-com.phonepe.PhonePeApp" for n in listing)
    has_group_app = any(n == "AppDomainGroup-group.com.phonepe.PhonePeApp" for n in listing)
    has_group_shared = any(n == "AppDomainGroup-group.com.phonepe.shared" for n in listing)
    return jsonify({
        "ok": True,
        "listing": listing,
        "has_app_domain": has_app_domain,
        "has_group_app": has_group_app,
        "has_group_shared": has_group_shared,
        "looks_like_single_root": has_app_domain,
    })


# ---------------------------------------------------------------------------
# Pages (require active case)
# ---------------------------------------------------------------------------

@app.route("/")
def page_dashboard():
    if manager.get_active_case() is None:
        return redirect(url_for("page_cases"))
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
        "amount_inr", "counterparty", "counterparty_phone", "counterparty_vpa",
        "counterparty_cbs_name", "self_account_holder", "self_account_masked",
        "self_vpa", "self_ifsc", "utr", "transfer_mode", "category_code",
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
            corr_entry = next((it for it in corr["items"] if it["txn_id"] in (t.get("global_payment_id"), t.get("entity_id"))), None)
            related_chat = []
            for m in case.data.get("chat", {}).get("messages", []):
                if t.get("global_payment_id") and m.get("transaction_id") == t.get("global_payment_id"):
                    related_chat.append(m)
            return render_template("transaction_detail.html", txn=t, corroboration=corr_entry, chat_messages=related_chat)
    abort(404)


@app.route("/contacts")
def page_contacts():
    case = _active()
    contacts = case.data.get("contacts", {})
    q = request.args.get("q", "")
    if q:
        contacts = dict(contacts)
        contacts["cyclops_contacts"] = _filter_table(contacts.get("cyclops_contacts", []), q=q)
        contacts["phonebook_contacts"] = _filter_table(contacts.get("phonebook_contacts", []), q=q)
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
    return _csv_response(msgs, cols, f"chat_thread_{group_id[:8]}.csv")


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
    return render_template("chat_group.html", group=group, messages=msgs, members=members, self_name=self_name)


@app.route("/notifications")
def page_notifications():
    case = _active()
    notifs = case.data.get("notifications", {})
    q = request.args.get("q", "")
    sub = request.args.get("subsystem", "")
    topics = notifs.get("topics", [])
    if q or sub:
        topics = _filter_table(topics, q=q, filters={"subsystem": sub})
    return render_template("notifications.html",
                           notifications={**notifs, "topics_view": topics},
                           q=q, sub=sub, total_topics=len(notifs.get("topics", [])))


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
    return render_template("audit.html", audit=_active().data.get("audit", {}))


@app.route("/timeline")
def page_timeline():
    case = _active()
    limit = int(request.args.get("limit", 1500))
    q = request.args.get("q", "")
    src = request.args.get("source", "")
    events = case.timeline(limit=limit)
    if q or src:
        events = _filter_table(events, q=q, filters={"source": src})
    return render_template("timeline.html", events=events, q=q, src=src, total=len(case.timeline(limit=limit)))


@app.route("/timeline/export.csv")
def export_timeline_csv():
    case = _active()
    rows = case.timeline(limit=int(request.args.get("limit", 5000)))
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
                           inventory=case.data.get("database_inventory", []),
                           plists=case.data.get("plist_inventory", []))


@app.route("/database-browser/sql", methods=["GET"])
def page_db_sql():
    case = _active()
    db_path = request.args.get("db")
    sql = request.args.get("sql", "")
    result = None
    columns: List[str] = []
    error = None
    if db_path and sql:
        sql_stripped = sql.strip().rstrip(";")
        if not sql_stripped.upper().startswith(("SELECT", "PRAGMA", "EXPLAIN", "WITH")):
            error = "Only SELECT / PRAGMA / EXPLAIN / WITH queries are allowed."
        elif ";" in sql_stripped:
            error = "Multiple statements are not allowed."
        else:
            try:
                from .core import SQLiteReader
                with SQLiteReader(db_path) as db:
                    rows = db.query(sql_stripped + " LIMIT 1000")
                if rows and "_error" in rows[0]:
                    error = rows[0]["_error"]
                else:
                    result = rows[:1000]
                    columns = list(result[0].keys()) if result else []
            except Exception as exc:
                error = str(exc)
    return render_template("database_sql.html",
                           inventory=case.data.get("database_inventory", []),
                           db_path=db_path, sql=sql,
                           result=result, columns=columns, error=error)


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
        idx = hunt.materialise_indexes(case.data, case.timeline(), case.social_graph(), case.findings())
        result = hunt.run_query(query, idx)
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
    idx = hunt.materialise_indexes(case.data, case.timeline(), case.social_graph(), case.findings())
    result = hunt.run_query(query, idx)
    if result.get("error"):
        return _csv_response([], ["error"], "hunt_error.csv")
    cols = result["columns"] or list(result["rows"][0].keys()) if result["rows"] else ["_empty"]
    return _csv_response(result["rows"], cols, "hunt_result.csv")


# ---------------------------------------------------------------------------
# Research document (in-app)
# ---------------------------------------------------------------------------

@app.route("/research")
def page_research():
    return render_template("research.html",
                           sections=research_data.RESEARCH_SECTIONS,
                           toc=[(s["slug"], s["title"]) for s in research_data.RESEARCH_SECTIONS])


@app.route("/research/<slug>")
def page_research_section(slug: str):
    section = next((s for s in research_data.RESEARCH_SECTIONS if s["slug"] == slug), None)
    if not section:
        abort(404)
    return render_template("research_section.html",
                           section=section,
                           toc=[(s["slug"], s["title"]) for s in research_data.RESEARCH_SECTIONS])


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
    info = case.export_all(base_dir=os.path.join(os.getcwd(), "exports"))
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
    if case.paths.app_domain:
        allowed_roots.append(os.path.realpath(case.paths.app_domain))
    if case.paths.group_app:
        allowed_roots.append(os.path.realpath(case.paths.group_app))
    if case.paths.group_shared:
        allowed_roots.append(os.path.realpath(case.paths.group_shared))
    allowed_roots.append(os.path.realpath(os.path.join(os.getcwd(), "exports")))
    if not any(real.startswith(r) for r in allowed_roots):
        abort(403)
    return send_file(real)


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
    return jsonify(_active().timeline(limit=int(request.args.get("limit", 5000))))


@app.route("/api/findings")
def api_findings():
    return jsonify(_active().findings())


@app.route("/api/hunt", methods=["POST"])
def api_hunt():
    case = _active()
    payload = request.get_json(silent=True) or {}
    query = payload.get("q", "")
    idx = hunt.materialise_indexes(case.data, case.timeline(), case.social_graph(), case.findings())
    return jsonify(hunt.run_query(query, idx))


@app.errorhandler(503)
def _err_503(e):
    return redirect(url_for("page_cases"))


@app.errorhandler(404)
def _err_404(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def _err_500(e):
    return render_template("error.html", code=500, message=str(e)), 500


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
