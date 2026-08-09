#!/usr/bin/env python3
"""Build a SYNTHETIC PhonePe Android acquisition, for documentation screenshots.

Why this exists
---------------
The README screenshots must never show a real person's financial history, and an
acquisition cannot be "anonymised" reliably — a PhonePe case root holds names,
phone numbers, VPAs, account numbers and chat text across ~14 databases and 180
shared_prefs, and one missed field is a disclosure. So the demo case is built from
nothing instead: real table SHAPES (notes/demo_schema.sql, CREATE statements only)
filled with invented rows.

Using the real schema is the point. A mock would render a screenshot that proves
nothing about the tool; this fixture goes through the same extractors, correlator,
carver and templates as evidence does, so the screenshots show real behaviour.

Safety rules this file follows, and any edit must keep
------------------------------------------------------
1. Every identifier is unmistakably fake: `Test Subject`, `Demo Payee One`,
   `9876543210`-style numbers reserved for documentation, `demo@upi` handles.
   Plausible-looking real-world names are avoided on purpose — a reader cannot
   tell those from genuine ones, which defeats the labelling.
2. No value is copied from any acquisition. Nothing here is read from a case root.
3. The output directory is created fresh and is safe to delete.
4. Amounts are round and small so no screenshot implies a real financial position.

An empty panel in a demo screenshot is honest. A fabricated panel that looks
plausible is the thing to avoid — so this fixture populates the tables behind the
pages worth showing and deliberately leaves the rest empty.

Usage
-----
    python notes/make_demo_acquisition.py /tmp/demo-case
    # -> /tmp/demo-case/com.phonepe.app/databases/...

Then point the tool at /tmp/demo-case/com.phonepe.app (or its parent).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "demo_schema.sql")

# ---------------------------------------------------------------------------
# The synthetic cast. Deliberately labelled, deliberately boring.
# ---------------------------------------------------------------------------

SUBJECT = {
    "name": "Test Subject",
    "phone": "9876543210",
    "vpa": "testsubject@demo",
    "user_id": "DEMOUSER0000000000001",
    "account_no": "XXXXXXXX1234",
    "ifsc": "DEMO0000001",
}

# member ids / connection ids are opaque strings in the real schema; keep them
# obviously synthetic so a screenshot cannot be mistaken for evidence.
PEOPLE = [
    # name,               phone,        connection_id,    vpa
    ("Demo Payee One",    "9876500001", "DEMOCONN000001", "payeeone@demo"),
    ("Demo Payee Two",    "9876500002", "DEMOCONN000002", "payeetwo@demo"),
    ("Demo Merchant Ltd", "9876500003", "DEMOCONN000003", "merchant@demo"),
    ("Demo Contact Four", "9876500004", "DEMOCONN000004", None),
]

# 2026-03-02T09:00:00Z onward, in ms — a fixed clock so screenshots are stable
# across regenerations rather than drifting with today's date.
T0 = 1772442000000
MIN = 60_000
HOUR = 3_600_000
DAY = 86_400_000


def _leg(kind, name=None, phone=None, vpa=None, account=None, amount=None):
    """One payment leg, in the shape the extractor's `first_or_dict` expects."""
    d = {"type": kind}
    if name:
        d["accountHolderName"] = name
    if phone:
        d["phone"] = phone
    if vpa:
        d["fullVpa"] = vpa
    if account:
        d["accountNumber"] = account
        d["ifsc"] = SUBJECT["ifsc"]
    if amount is not None:
        d["amount"] = amount
    return d


def _self_leg(amount=None):
    return _leg("ACCOUNT", SUBJECT["name"], account=SUBJECT["account_no"], amount=amount)


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def transactions():
    """A spread that exercises the branches the tool is judged on: money out, money
    in, a merchant payment with an initiation mode, a failed payment, and a split
    settlement with no payment leg."""
    rows = []
    name, phone, conn, vpa = PEOPLE[0]
    # OUT — subject is the sender; counterparty named in paymentReceiver
    rows.append(dict(
        transaction_id="DEMOTXN00000000000001", type="SENT_PAYMENT",
        transaction_id_type="DEMOTXN00000000000001_SENT_PAYMENT",
        state="COMPLETED", unit_id="DEMOUNIT01",
        timestamp_created=T0, timestamp_updated=T0 + MIN, show_on_history=1,
        payment_reference="DEMOREF0000001", contact_data=phone,
        tstore_data=json.dumps({
            "actor": "SENDER", "note": "Demo payment for documentation",
            "paymentReceiver": _leg("PHONE", name, phone=phone, vpa=vpa),
            "paidFrom": [_self_leg(120000)],
            "context": {"transferMode": "PEER_TO_PEER", "tag": "P2P"},
            "responseCode": "SUCCESS",
        }),
        instruments=json.dumps([{"amount": "120000", "type": "ACCOUNT"}]),
    ))
    # IN — subject is the receiver; counterparty named in paymentPayerParty.
    # This is the shape whose direction was being read backwards before the fix.
    name2, phone2, conn2, vpa2 = PEOPLE[1]
    rows.append(dict(
        transaction_id="DEMOTXN00000000000002", type="RECEIVED_PAYMENT",
        transaction_id_type="DEMOTXN00000000000002_RECEIVED_PAYMENT",
        state="COMPLETED", unit_id="DEMOUNIT02",
        timestamp_created=T0 + 2 * HOUR, timestamp_updated=T0 + 2 * HOUR + MIN,
        show_on_history=1, payment_reference="DEMOREF0000002", contact_data=phone2,
        tstore_data=json.dumps({
            "actor": "RECEIVER", "amount": 50000, "note": "Demo refund received",
            "paymentPayerParty": _leg("PHONE", name2, phone=phone2, vpa=vpa2),
            "receivedIn": [_self_leg()],
            "context": {"transferMode": "PEER_TO_PEER"},
        }),
    ))
    # OUT to a merchant, initiated by QR scan — the tag that could never render
    # before this pass.
    name3, phone3, conn3, vpa3 = PEOPLE[2]
    rows.append(dict(
        transaction_id="DEMOTXN00000000000003", type="SENT_PAYMENT",
        transaction_id_type="DEMOTXN00000000000003_SENT_PAYMENT",
        state="COMPLETED", unit_id="DEMOUNIT03",
        timestamp_created=T0 + 6 * HOUR, timestamp_updated=T0 + 6 * HOUR + MIN,
        show_on_history=1, payment_reference="DEMOREF0000003",
        tstore_data=json.dumps({
            "actor": "SENDER", "note": "Demo merchant purchase",
            "paymentReceiver": dict(_leg("MERCHANT", name3, vpa=vpa3),
                                    **{"type": "MERCHANT", "merchantId": "DEMOMERCH01",
                                       "name": name3, "mcc": "5812"}),
            "paidFrom": [_self_leg(35000)],
            "context": {"initiationMode": "QR_SCAN", "upiInitiationMode": "01",
                        "transferMode": "PEER_TO_MERCHANT"},
        }),
    ))
    # An INTENT payment — the other initiation mode.
    rows.append(dict(
        transaction_id="DEMOTXN00000000000004", type="SENT_PAYMENT",
        transaction_id_type="DEMOTXN00000000000004_SENT_PAYMENT",
        state="COMPLETED", unit_id="DEMOUNIT04",
        timestamp_created=T0 + DAY, timestamp_updated=T0 + DAY + MIN,
        show_on_history=1, payment_reference="DEMOREF0000004",
        tstore_data=json.dumps({
            "actor": "SENDER", "note": "Demo in-app handoff",
            "paymentReceiver": _leg("MERCHANT", name3, vpa=vpa3),
            "paidFrom": [_self_leg(15000)],
            "context": {"initiationMode": "INTENT", "upiInitiationMode": "04",
                        "transferMode": "INTENT"},
        }),
    ))
    # A failed payment — so the failed_transactions finding has something to find.
    rows.append(dict(
        transaction_id="DEMOTXN00000000000005", type="SENT_PAYMENT",
        transaction_id_type="DEMOTXN00000000000005_SENT_PAYMENT",
        state="ERRORED", unit_id="DEMOUNIT05",
        timestamp_created=T0 + DAY + 3 * HOUR, timestamp_updated=T0 + DAY + 3 * HOUR + MIN,
        show_on_history=1, payment_reference="DEMOREF0000005",
        tstore_data=json.dumps({
            "actor": "SENDER", "note": "Demo failed payment",
            "paymentReceiver": _leg("PHONE", name2, phone=phone2),
            "paidFrom": [_self_leg(9900)],
            "responseCode": "ZM",
        }),
    ))
    # Split settlement: no payment leg at all, counterparty comes from the ledger.
    rows.append(dict(
        transaction_id="DEMOTXN00000000000006", type="EXPENSE_SETTLEMENT",
        transaction_id_type="DEMOTXN00000000000006_EXPENSE_SETTLEMENT",
        state="COMPLETED", unit_id="DEMOUNIT06",
        timestamp_created=T0 + 2 * DAY, timestamp_updated=T0 + 2 * DAY + MIN,
        show_on_history=1, payment_reference="DEMOREF0000006",
        tstore_data=json.dumps({
            "amount": 60000, "groupId": "DEMOLEDGER01",
            "note": "Demo split settlement",
            "paidFrom": [_self_leg(60000)],
        }),
    ))
    return rows


def aggregates():
    """PhonePe's own per-transaction bookkeeping — the table that served as ground
    truth for the direction audit. Included so the demo can be cross-checked the
    same way."""
    return [
        ("DEMOTXN00000000000001_SENT_PAYMENT", "spent", "2026-03", 120000, T0),
        ("DEMOTXN00000000000002_RECEIVED_PAYMENT", "received", "2026-03", 50000, T0 + 2 * HOUR),
        ("DEMOTXN00000000000003_SENT_PAYMENT", "spent", "2026-03", 35000, T0 + 6 * HOUR),
        ("DEMOTXN00000000000004_SENT_PAYMENT", "spent", "2026-03", 15000, T0 + DAY),
        ("DEMOTXN00000000000006_EXPENSE_SETTLEMENT", "spent", "2026-03", 60000, T0 + 2 * DAY),
    ]


# `topicMember.memberId` is the primary key, so the same person in two threads has
# two member rows with different ids — which is exactly why the tool joins chat to
# contacts on `connectionId` and never on the member id or the display name.
THREADS = [
    ("DEMOTOPIC0000000000001", "Demo Payee One", [0]),
    ("DEMOTOPIC0000000000002", "Demo Trip Group", [0, 1, 3]),
]


def _member_id(person_index, thread_index):
    return f"DEMOMEMBER{person_index}T{thread_index}"


def _self_member_id(thread_index):
    return f"DEMOMEMBERSELFT{thread_index}"


def chat_rows():
    """One 1:1 thread and one group, with a payment card so the chat↔ledger
    corroboration index has something to correlate."""
    topics, metas, members, messages = [], [], [], []
    for ti, (topic, label, cast) in enumerate(THREADS):
        topics.append((topic, "P2P", "SUBSCRIBED", T0 + 3 * DAY, T0))
        metas.append((topic, _self_member_id(ti), label, "ACTIVE", T0))
        members.append((_self_member_id(ti), "DEMOCONNSELF", _self_member_id(ti), topic,
                        "PHONE", "CREATOR", 1, SUBJECT["name"], None, None, 0,
                        "******3210", None, 1, None))
        for pi in cast:
            name, phone, conn, vpa = PEOPLE[pi]
            mid = _member_id(pi, ti)
            members.append((mid, conn, mid, topic, "PHONE", "MEMBER", 1,
                            name, None, None, 0, "******" + phone[-4:], None, 1,
                            _self_member_id(ti)))
    # 1:1 thread — a text message and a payment card referencing a real demo txn
    messages.append((
        "DEMOMSG0000000000001", "DEMOSRV0000000000001", THREADS[0][0], "TEXT_MESSAGE",
        T0 + 30 * MIN, T0 + 30 * MIN, 0, _self_member_id(0),
        json.dumps({"source": {"groupMemberId": _self_member_id(0)},
                    "content": {"message": "Sent it across — demo message.",
                                "destination": {"groupMemberId": _member_id(0, 0)}}}),
    ))
    messages.append((
        "DEMOMSG0000000000002", "DEMOSRV0000000000002", THREADS[0][0], "PAYMENT_INFO_CARD",
        T0 + 31 * MIN, T0 + 31 * MIN, 0, _self_member_id(0),
        json.dumps({"source": {"groupMemberId": _self_member_id(0)},
                    "content": {"amount": 120000, "state": "COMPLETED",
                                "transactionId": "DEMOTXN00000000000001",
                                "destination": {"groupMemberId": _member_id(0, 0)}}}),
    ))
    messages.append((
        "DEMOMSG0000000000003", "DEMOSRV0000000000003", THREADS[0][0], "TEXT_MESSAGE",
        T0 + 40 * MIN, T0 + 40 * MIN, 0, _member_id(0, 0),
        json.dumps({"source": {"groupMemberId": _member_id(0, 0)},
                    "content": {"message": "Got it, thanks.",
                                "destination": {"groupMemberId": _self_member_id(0)}}}),
    ))
    # A payment card in the group referencing a transaction that is NOT in
    # transaction_core — the "referenced only outside the master ledger" case.
    messages.append((
        "DEMOMSG0000000000004", "DEMOSRV0000000000004", THREADS[1][0], "PAYMENT_INFO_CARD",
        T0 + 3 * DAY, T0 + 3 * DAY, 0, _member_id(1, 1),
        json.dumps({"source": {"groupMemberId": _member_id(1, 1)},
                    "content": {"amount": 25000, "state": "COMPLETED",
                                "transactionId": "DEMOTXN0000000000ABSENT",
                                "destination": {"groupMemberId": _self_member_id(1)}}}),
    ))
    messages.append((
        "DEMOMSG0000000000005", "DEMOSRV0000000000005", THREADS[1][0], "TEXT_MESSAGE",
        T0 + 3 * DAY + MIN, T0 + 3 * DAY + MIN, 0, _member_id(3, 1),
        json.dumps({"source": {"groupMemberId": _member_id(3, 1)},
                    "content": {"message": "Splitting the demo bill four ways.",
                                "destination": {"groupMemberId": _self_member_id(1)}}}),
    ))
    return topics, metas, members, messages


def ledger_rows():
    """One shared-expense ledger with a settled expense, so the split pages and the
    subject's net position render."""
    entity = [("DEMOLEDGER01", "DEMOTOPIC0000000000002")]
    # `ledger_expense` carries no amount column — the expense total is the sum of its
    # members' shares in `ledger_expense_member`, which is why the ledger page's totals
    # are computed rather than read.
    expense = [
        ("DEMOEXPENSE01", "Demo dinner split", "EXPENSE", "DEMOLEDGER01", "SETTLED",
         T0 + 2 * DAY - HOUR, _self_member_id(1)),
        ("DEMOEXPENSE02", "Demo taxi split", "EXPENSE", "DEMOLEDGER01", "PENDING",
         T0 + 3 * DAY, _member_id(1, 1)),
    ]
    member = [
        (_self_member_id(1), "DEMOCONNSELF", 1, "DEMOEXPENSE01", 60000),
        (_member_id(0, 1), PEOPLE[0][2], 0, "DEMOEXPENSE01", 60000),
        (_member_id(1, 1), PEOPLE[1][2], 0, "DEMOEXPENSE01", 60000),
        (_member_id(3, 1), PEOPLE[3][2], 0, "DEMOEXPENSE01", 60000),
        (_member_id(1, 1), PEOPLE[1][2], 1, "DEMOEXPENSE02", 40000),
        (_self_member_id(1), "DEMOCONNSELF", 0, "DEMOEXPENSE02", 40000),
    ]
    balance = [
        (_self_member_id(1), "DEMOCONNSELF", "DEMOLEDGER01", 40000, 0),
        (_member_id(0, 1), PEOPLE[0][2], "DEMOLEDGER01", 0, 60000),
        (_member_id(1, 1), PEOPLE[1][2], "DEMOLEDGER01", 0, 20000),
    ]
    my_split = [("DEMOSPLIT01", PEOPLE[1][2], -40000)]
    settlement = [("DEMOEXPENSE01", "DEMOTXN00000000000006")]
    # The ledger list itself comes from `ledger_meta`, not `ledger_entity` — the latter
    # only maps a ledger to its chat topic.
    meta = [("DEMOLEDGER01", T0 - DAY, 0, 1, None)]
    return entity, expense, member, balance, my_split, settlement, meta


def contact_rows():
    phone_contacts, conn_info, vpa_contacts, non_contacts = [], [], [], []
    for i, (name, phone, conn, vpa) in enumerate(PEOPLE):
        on_pp = 1 if i < 3 else 0
        phone_contacts.append((phone, on_pp, 1 if on_pp else 0, 1 if vpa else 0,
                               T0, conn, name, "IN", "ACTIVE" if on_pp else None))
        conn_info.append((conn, name, "NONE"))
        if vpa:
            vpa_contacts.append((vpa, name, T0, T0, "NONE", "SYNCED"))
    non_contacts.append(("DEMOCONN000009", "CONTACT_SEARCH", "DEMOBATCH01", "NONE",
                         "SYNCED", 0, 0, "9876500009"))
    return phone_contacts, conn_info, vpa_contacts, non_contacts


def sms_rows():
    """Bank SMS that corroborates one demo transaction to the paise, and one that
    corroborates nothing — the two outcomes the SMS matcher reports."""
    meta = json.dumps({"demo": True})
    return [
        (1, T0 + MIN, "DEMO-BANK",
         "Rs.1200.00 debited from A/c XXXXXXXX1234 on 02-03-26. Ref DEMOREF0000001. "
         "Not you? Call demo helpline.", meta),
        (2, T0 + 5 * DAY, "DEMO-BANK",
         "Rs.310.00 debited from A/c XXXXXXXX1234 on 07-03-26. Ref DEMOREF0000099.", meta),
    ]


def payment_infra_rows():
    """Column names here match the extractors' SELECTs exactly (`account_no`,
    `account_ifsc`, `centralIfsc`…), because a fixture that renames a column would
    silently exercise the schema-drift path instead of the normal one."""
    accounts = [(SUBJECT["user_id"], SUBJECT["account_no"], SUBJECT["name"],
                 "Demo Savings", "SAVINGS", 1, SUBJECT["ifsc"], "DEMOBANK01",
                 SUBJECT["vpa"], "DEMOACCT01")]
    vpas = [(1, SUBJECT["vpa"], 1), (2, "testsubject.demo@demo", 0)]
    banks = [("DEMOBANK01", 1, "Demo Bank", "DEMO", "DEMO0000001", 1, 1, 0, 1, 1, 0),
             ("DEMOBANK02", 2, "Second Demo Bank", "DEMO2", "DEMO0000002", 1, 0, 0, 0, 1, 0)]
    return accounts, vpas, banks


def audit_rows():
    consents = [
        ("DEMOCONSENT01", "LOCATION", "DEMO_USE_CASE", "EXPLICIT", "ACCEPTED",
         T0 + 30 * DAY, "SYNCED"),
        ("DEMOCONSENT02", "CONTACTS", "DEMO_USE_CASE_2", "EXPLICIT", "ACCEPTED",
         T0 + 30 * DAY, "SYNCED"),
    ]
    sync = [("TRANSACTION", "DemoSyncTask", "COMPLETED", "", "UNKNOWN", "UPSERT",
             T0, T0 + MIN)]
    return consents, sync


def notification_rows():
    """Bullhorn stores a push payload as base64-encoded JSON nested inside JSON."""
    import base64
    topics = [("DEMOBHTOPIC01", "TRANSACTION", T0, T0 + DAY, T0 + DAY, 1, "USER")]
    # An inbox notification is a templated "placement": the title/subtitle the user
    # actually saw live in templateParams, and the deeplink is what tapping it would
    # have opened. Anything shallower is catalogue chatter, which is why the extractor
    # counts a row as a notification only when it yields a title or body.
    payload = {
        "type": "PAYMENT_UPDATE",
        "data": {"placements": [{"template": {
            "templateId": "DEMO_TEMPLATE_1",
            "templateParams": {"value": {
                "title": "Demo payment successful",
                "subTitle": "You paid Rs.1,200.00 to Demo Payee One",
            }},
            "nav": {"params": {"deepLink": "phonepe://demo/transaction/DEMOTXN00000000000001"}},
        }}]},
    }
    inner = {"message": {
        "id": "DEMOBHMSG01", "serverId": "DEMOBHSRV01", "topicId": "DEMOBHTOPIC01",
        "created": T0 + MIN,
        "payload": base64.b64encode(json.dumps(payload).encode()).decode().rstrip("="),
    }}
    store = [("DEMOBHMSG01", json.dumps(inner))]
    message = [("DEMOROWKEY01", "DEMOBHMSG01", "DEMOBHTOPIC01", "UPSERT", 1, "USER")]
    return topics, message, store


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def _split_schema(text):
    """notes/demo_schema.sql is one file holding several databases, separated by
    `--@DB <name>` markers."""
    parts = re.split(r"--@DB (\S+)\n", text)
    out = {}
    for i in range(1, len(parts), 2):
        stmts = [s.strip() for s in parts[i + 1].split(";\n")
                 if s.strip().upper().startswith("CREATE")]
        out[parts[i]] = stmts
    return out


def _insert(con, table, rows, columns=None):
    """Insert rows, filling any NOT NULL column this file did not name.

    PhonePe's Room schemas mark plumbing columns NOT NULL (`topicType`, `topicInfo`,
    sync bookkeeping…) that say nothing an examiner reads. Naming all of them here
    would triple the size of this file and drift the moment the schema does, so the
    required ones that were not given a meaningful value are filled with a neutral
    placeholder derived from the declared type. Anything the tool actually displays
    is set explicitly above — never left to this.
    """
    if not rows:
        return 0
    info = [(r[1], (r[2] or "").upper(), r[3]) for r in con.execute(f'PRAGMA table_info("{table}")')]
    required = {name: decl for name, decl, notnull in info if notnull}

    def _filler(name, decl):
        if "INT" in decl:
            return 0
        if any(k in decl for k in ("REAL", "FLOA", "DOUB", "NUM", "DEC")):
            return 0
        return f"DEMO_{name}"

    dicts = []
    for row in rows:
        if isinstance(row, dict):
            d = dict(row)
        else:
            cols = columns or [n for n, _, _ in info][:len(row)]
            d = dict(zip(cols, row))
        for name, decl in required.items():
            if name not in d:
                d[name] = _filler(name, decl)
        dicts.append(d)

    for d in dicts:
        cols = list(d.keys())
        con.execute(f'INSERT INTO "{table}" ({",".join(chr(34) + c + chr(34) for c in cols)}) '
                    f'VALUES ({",".join("?" * len(cols))})', [d[c] for c in cols])
    return len(dicts)


def build(dest):
    if not os.path.exists(SCHEMA):
        sys.exit(f"missing {SCHEMA}")
    app = os.path.join(dest, "com.phonepe.app")
    if os.path.exists(app):
        shutil.rmtree(app)
    dbdir = os.path.join(app, "databases")
    os.makedirs(dbdir)
    os.makedirs(os.path.join(app, "shared_prefs"))
    os.makedirs(os.path.join(app, "files"))

    schema = _split_schema(open(SCHEMA).read())
    counts = {}
    for dbname, stmts in schema.items():
        con = sqlite3.connect(os.path.join(dbdir, dbname))
        for s in stmts:
            con.execute(s)
        con.commit()
        if dbname == "phonepe_core":
            counts["transaction_core"] = _insert(con, "transaction_core", transactions())
            counts["transaction_aggregate_entity"] = _insert(
                con, "transaction_aggregate_entity", aggregates(),
                ["transaction_id_type", "aggregate_type", "year_month", "amount", "created_at"])
            topics, metas, members, messages = chat_rows()
            counts["chatTopic"] = _insert(con, "chatTopic", topics,
                ["topicId", "subSystemType", "subscriptionStatus", "lastUpdated", "createdTime"])
            counts["chatTopicMeta"] = _insert(con, "chatTopicMeta", metas,
                ["topicId", "ownMemberId", "topicName", "state", "createdTime"])
            counts["topicMember"] = _insert(con, "topicMember", members,
                ["memberId", "connectionId", "id", "memberTopicId", "type", "role",
                 "onPhonePe", "phonePeName", "merchantName", "storeName", "isMemberDeleted",
                 "maskedPhoneNumber", "merchantImageId", "isGroupAccepted", "addedByMemberId"])
            counts["chatMessage"] = _insert(con, "chatMessage", messages,
                ["clientMessageId", "serverMessageId", "topicId", "contentType",
                 "createdTime", "lastUpdated", "isDeleted", "sourceMemberId", "content"])
            pc, ci, vc, nc = contact_rows()
            counts["phone_contacts"] = _insert(con, "phone_contacts", pc,
                ["phone_num", "on_phonepe", "upi_enabled", "externalVpaAvailable",
                 "created_at", "connection_id", "cbs_name", "region", "upi_status"])
            counts["contactConnectionInfo"] = _insert(con, "contactConnectionInfo", ci,
                ["connectionId", "name", "imageType"])
            counts["vpa_contacts"] = _insert(con, "vpa_contacts", vc,
                ["contact_vpa", "cbs_name", "created_at", "updated_at",
                 "change_state", "sync_state"])
            counts["nonContact"] = _insert(con, "nonContact", nc,
                ["connectionId", "useCaseName", "batchId", "changeState", "syncState",
                 "isKnown", "isHidden", "phoneNumber"])
            ent, exp, mem, bal, mysplit, settle, lmeta = ledger_rows()
            counts["ledger_entity"] = _insert(con, "ledger_entity", ent,
                ["ledger_id", "topic_id"])
            counts["ledger_expense"] = _insert(con, "ledger_expense", exp,
                ["id", "name", "type", "ledger_id", "state", "createdAt", "created_by"])
            counts["ledger_expense_member"] = _insert(con, "ledger_expense_member", mem,
                ["member_id", "connection_id", "is_payer", "expense_id", "amount"])
            counts["ledger_balance"] = _insert(con, "ledger_balance", bal,
                ["member_id", "connection_id", "ledger_id", "balanceAmountToGive",
                 "balanceAmountToReceive"])
            counts["ledger_my_split"] = _insert(con, "ledger_my_split", mysplit,
                ["id", "other_connect_id", "signed_amount"])
            counts["ledger_settlement"] = _insert(con, "ledger_settlement", settle,
                ["id", "global_id"])
            counts["ledger_meta"] = _insert(con, "ledger_meta", lmeta,
                ["ledgerId", "createdAt", "magicSettle", "magicSettleToggleable",
                 "magicSettleResponseCode"])
            accounts, vpas, banks = payment_infra_rows()
            counts["accounts"] = _insert(con, "accounts", accounts,
                ["user_id", "account_no", "account_holder_name", "account_alias",
                 "account_type", "is_primary", "account_ifsc", "bank_id", "vpas",
                 "account_id"])
            counts["vpa"] = _insert(con, "vpa", vpas, ["_id", "vpa", "is_primary"])
            counts["banks"] = _insert(con, "banks", banks,
                ["bank_id", "_id", "bank_name", "ifsc", "centralIfsc", "upi_supported",
                 "upi_mandate_supported", "credit_card_on_upi_supported",
                 "upi_lite_supported", "active", "partner"])
            consents, sync = audit_rows()
            counts["consent"] = _insert(con, "consent", consents,
                ["consentId", "dataType", "useCaseId", "acceptType", "consentState",
                 "endTime", "consentSyncState"])
            counts["phonepe_sync_tracing"] = _insert(con, "phonepe_sync_tracing", sync,
                ["syncDataNature", "syncId", "syncStatus", "systemKey", "system",
                 "operation", "lastSyncAttemptTime", "lastSyncCompletionTime"])
        elif dbname == "BullhornDatabase":
            topics, message, store = notification_rows()
            counts["bullhorn.topic"] = _insert(con, "topic", topics,
                ["topicId", "subSystemType", "topicCreatedTimeStamp", "topicUpdateTimeStamp",
                 "lastMessageSyncTime", "isRestoreSyncCompleted", "typeOfSubscriberType"])
            counts["messageDataStore"] = _insert(con, "messageDataStore", store,
                ["messageId", "data"])
            counts["bullhorn.message"] = _insert(con, "message", message,
                ["rowKey", "messageId", "topicId_M", "messageOperationType", "_id",
                 "typeOfSubscriberType_M"])
        elif dbname == "inference_data_provider":
            counts["sms_buffer"] = _insert(con, "sms_buffer", sms_rows(),
                ["id", "time_received", "address", "body", "complete_meta"])
        elif dbname == "accounts_db":
            counts["accounts_db.account"] = _insert(con, "account",
                [(SUBJECT["user_id"], SUBJECT["name"], "testsubject",
                  SUBJECT["phone"], "test.subject@demo.invalid", 0, 1)],
                ["user_id", "user_display_name", "user_name", "user_phone_number",
                 "user_email", "email_verified", "phone_number_verified"])
        con.commit()
        con.close()

    # A shared_prefs file, so the raw layer and identity page are not bare.
    with open(os.path.join(app, "shared_prefs", "demo_preferences.xml"), "w") as fh:
        fh.write('<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n<map>\n'
                 f'    <string name="user_id">{SUBJECT["user_id"]}</string>\n'
                 f'    <string name="registered_name">{SUBJECT["name"]}</string>\n'
                 f'    <string name="primary_vpa">{SUBJECT["vpa"]}</string>\n'
                 '    <boolean name="demo_fixture" value="true" />\n</map>\n')
    return app, counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dest", help="directory to create com.phonepe.app/ inside")
    args = ap.parse_args()
    app, counts = build(os.path.abspath(args.dest))
    print(f"synthetic acquisition -> {app}")
    for k in sorted(counts):
        print(f"  {k:<34} {counts[k]} rows")
    print("\nEvery value above is invented. Nothing was read from any acquisition.")


if __name__ == "__main__":
    main()
