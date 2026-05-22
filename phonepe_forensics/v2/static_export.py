"""Single-file offline shareable HTML evidence report.

Produces one self-contained .html file with every asset (avatars, bank/app logos,
gradient backgrounds, full payment + conversation data, raw JSON with provenance)
inlined via data: URIs and a JSON blob. Opens in any browser offline.
"""
from __future__ import annotations

import base64
import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .core import ts_ms_to_ist_str, ts_ms_to_utc_str
from .data_layer import (
    AppInfo,
    collect_source_db_hashes,
    load_avatars,
    load_burble_conversations,
    load_burble_messages,
    load_contacts,
    load_owner_identity,
    load_phonepe_psps,
    load_tpap_map,
)
from .reconcile import ReconcileResult


_HTML_TEMPLATE_HEAD = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__TITLE__</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
* { box-sizing: border-box; margin: 0; padding: 0 }
:root {
  --bg: #0f1217; --bg2: #161b22; --panel: #1c2230; --panel2: #232a3a;
  --border: #2a3142; --text: #e5e7eb; --muted: #9aa3b2; --accent: #8b5cf6;
  --green: #10b981; --red: #ef4444; --amber: #f59e0b; --blue: #3b82f6;
  --cyan: #06b6d4;
}
body { font: 13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background: var(--bg); color: var(--text); }
a { color: var(--cyan); text-decoration: none }
a:hover { text-decoration: underline }
button { background: var(--panel); border: 1px solid var(--border); color: var(--text);
         padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
button.primary { background: var(--accent); border-color: var(--accent); color: white; }
button:hover { background: var(--panel2); }
button.primary:hover { background: #7c4cf0; }
input, select, textarea { background: var(--bg2); color: var(--text);
                          border: 1px solid var(--border); border-radius: 6px;
                          padding: 6px 8px; font-size: 12px; }
input[type=checkbox] { width: 14px; height: 14px; }
.app { display: grid; grid-template-columns: 240px 1fr; min-height: 100vh; }
aside { background: var(--bg2); border-right: 1px solid var(--border);
        padding: 16px 12px; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
aside h1 { font-size: 14px; font-weight: 700; margin-bottom: 4px; }
aside .sub { color: var(--muted); font-size: 11px; margin-bottom: 16px; }
.case-card { background: var(--panel); border-radius: 8px; padding: 12px;
             margin-bottom: 16px; font-size: 11px; }
.case-card .lbl { color: var(--muted); font-size: 10px; text-transform: uppercase;
                  letter-spacing: 0.5px; margin-bottom: 2px; }
.case-card .v { font-weight: 600; margin-bottom: 6px; word-break: break-word; }
nav { display: flex; flex-direction: column; gap: 2px; }
nav a { padding: 8px 10px; border-radius: 6px; color: var(--text); font-size: 12px; }
nav a.active { background: var(--accent); color: white; }
nav a:hover { background: var(--panel); text-decoration: none; }
main { padding: 20px 28px; overflow-x: hidden; }
.page-title { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
.page-sub { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
.banner { background: var(--bg2); border: 1px solid var(--border);
          border-left: 3px solid var(--amber); padding: 10px 14px;
          border-radius: 6px; margin-bottom: 16px; font-size: 12px; color: var(--muted); }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
             gap: 14px; margin-bottom: 24px; }
.stat { background: var(--panel); border-radius: 8px; padding: 16px; border: 1px solid var(--border); }
.stat .lbl { color: var(--muted); font-size: 11px; text-transform: uppercase;
             letter-spacing: 0.5px; margin-bottom: 6px; }
.stat .v { font-size: 24px; font-weight: 700; line-height: 1.1; }
.stat .v.green { color: var(--green); } .stat .v.red { color: var(--red); }
.stat .v.amber { color: var(--amber); } .stat .v.blue { color: var(--blue); }
.stat .v.accent { color: var(--accent); }
.stat .sub { font-size: 11px; color: var(--muted); margin-top: 6px; }
.filter-bar { background: var(--panel); border: 1px solid var(--border);
              border-radius: 8px; padding: 14px; margin-bottom: 16px;
              display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
              gap: 10px; }
.filter-bar .grp { display: flex; flex-direction: column; gap: 4px; }
.filter-bar label { font-size: 10px; color: var(--muted); text-transform: uppercase;
                    letter-spacing: 0.5px; }
.toolbar { display: flex; justify-content: space-between; align-items: center;
           margin-bottom: 10px; gap: 12px; }
.live-stats { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11px; color: var(--muted); }
.live-stats b { color: var(--text); margin-left: 4px; }
.live-stats .red { color: var(--red); } .live-stats .green { color: var(--green); }
table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 8px;
        overflow: hidden; border: 1px solid var(--border); }
th { background: var(--bg2); padding: 10px 8px; text-align: left;
     font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase;
     letter-spacing: 0.4px; border-bottom: 1px solid var(--border);
     cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: var(--panel2); }
th.sort-asc::after { content: ' ↑'; color: var(--accent); }
th.sort-desc::after { content: ' ↓'; color: var(--accent); }
td { padding: 9px 8px; border-bottom: 1px solid var(--border); font-size: 12px;
     vertical-align: top; max-width: 220px; overflow: hidden; text-overflow: ellipsis;
     white-space: nowrap; }
tr:hover { background: var(--panel2); }
tr.failed { background: rgba(239,68,68,0.07); }
tr.refund { background: rgba(245,158,11,0.07); }
.avatar { width: 28px; height: 28px; border-radius: 50%; vertical-align: middle;
          background: var(--panel2); display: inline-block; overflow: hidden;
          margin-right: 6px; }
.avatar img { width: 100%; height: 100%; object-fit: cover; }
.avatar.fallback { display: inline-flex; align-items: center; justify-content: center;
                   font-size: 11px; font-weight: 700; color: white; }
.logo { width: 18px; height: 18px; vertical-align: middle; margin-right: 4px;
        border-radius: 3px; object-fit: contain; }
.pill { display: inline-block; padding: 2px 7px; border-radius: 10px;
        font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
.pill.sent { background: rgba(245,158,11,0.2); color: var(--amber); }
.pill.received { background: rgba(16,185,129,0.2); color: var(--green); }
.pill.failed { background: rgba(239,68,68,0.2); color: var(--red); }
.pill.refund { background: rgba(245,158,11,0.3); color: var(--amber); }
.pill.completed { background: rgba(16,185,129,0.15); color: var(--green); }
.pill.merchant { background: rgba(139,92,246,0.2); color: var(--accent); }
.pill.p2p { background: rgba(59,130,246,0.2); color: var(--blue); }
.pill.mandate { background: rgba(6,182,212,0.2); color: var(--cyan); }
.pill.unknown { background: rgba(154,163,178,0.15); color: var(--muted); }
.pill.chat-only { background: rgba(245,158,11,0.15); color: var(--amber); }
.pill.txnstore { background: rgba(16,185,129,0.15); color: var(--green); }
.amt { font-weight: 600; font-variant-numeric: tabular-nums; white-space: nowrap; }
.amt.sent { color: var(--red); } .amt.received { color: var(--green); }
.amt.unknown { color: var(--muted); }
.btn-raw { background: transparent; border: 1px solid var(--border);
           padding: 2px 6px; font-size: 10px; color: var(--muted); border-radius: 4px;
           cursor: pointer; font-family: ui-monospace, monospace; }
.btn-raw:hover { background: var(--panel2); color: var(--text); }
.modal-back { position: fixed; inset: 0; background: rgba(0,0,0,0.7);
              display: none; align-items: center; justify-content: center; z-index: 100; }
.modal-back.open { display: flex; }
.modal { background: var(--bg2); border: 1px solid var(--border);
         border-radius: 10px; max-width: 90vw; max-height: 88vh; width: 900px;
         display: flex; flex-direction: column; overflow: hidden; }
.modal h3 { padding: 14px 18px; border-bottom: 1px solid var(--border);
            font-size: 14px; font-weight: 700; }
.modal .body { padding: 14px 18px; overflow: auto; flex: 1; }
.modal .close { float: right; cursor: pointer; color: var(--muted); }
.modal .close:hover { color: var(--text); }
.modal pre { background: var(--bg); padding: 12px; border-radius: 6px; font-size: 11px;
             font-family: ui-monospace, monospace; overflow: auto; }
.modal .prov { background: var(--panel); padding: 12px; border-radius: 6px;
               margin-bottom: 10px; }
.modal .prov b { color: var(--muted); display: inline-block; min-width: 150px; font-weight: 500; }
.modal .prov .v { font-family: ui-monospace, monospace; font-size: 11px;
                  color: var(--text); word-break: break-all; }
/* Conversations */
.chat-app { display: grid; grid-template-columns: 320px 1fr; gap: 14px; height: 78vh; }
.chat-list { background: var(--panel); border: 1px solid var(--border);
             border-radius: 8px; overflow-y: auto; }
.chat-row { padding: 10px 12px; border-bottom: 1px solid var(--border); cursor: pointer;
            display: grid; grid-template-columns: 36px 1fr auto; gap: 10px; align-items: center; }
.chat-row:hover { background: var(--panel2); }
.chat-row.active { background: var(--accent); }
.chat-row .name { font-weight: 600; font-size: 12px; }
.chat-row .preview { color: var(--muted); font-size: 11px; white-space: nowrap;
                     overflow: hidden; text-overflow: ellipsis; }
.chat-row .meta { font-size: 10px; color: var(--muted); }
.chat-row.active .preview, .chat-row.active .meta { color: rgba(255,255,255,0.85); }
.chat-stream { background: var(--panel); border: 1px solid var(--border);
               border-radius: 8px; overflow-y: auto; padding: 16px; }
.date-sep { text-align: center; color: var(--muted); font-size: 11px; margin: 14px 0; }
.msg { margin-bottom: 10px; max-width: 80%; }
.msg.right { margin-left: auto; }
.msg.bubble { background: var(--panel2); padding: 8px 12px; border-radius: 10px;
              display: inline-block; max-width: 100%; word-break: break-word; }
.msg.right .bubble { background: var(--accent); color: white; }
.msg .meta-line { font-size: 10px; color: var(--muted); margin-top: 2px; }
.card { padding: 12px 14px; border-radius: 10px; max-width: 280px;
        background: linear-gradient(135deg, #1a1f2e, #232a3a);
        border: 1px solid var(--border); margin-bottom: 4px; }
.card.right { margin-left: auto; }
.card.paid { background: linear-gradient(135deg, #2a1f3d, #3d2a55); }
.card.received { background: linear-gradient(135deg, #1f3d2a, #2a553d); }
.card .amt-big { font-size: 22px; font-weight: 700; }
.card .state-chip { display: inline-flex; align-items: center; gap: 4px;
                    font-size: 10px; color: var(--green); margin-top: 4px; }
.card.failed .state-chip { color: var(--red); }
.card .time-mini { color: var(--muted); font-size: 10px; margin-top: 4px; }
.card .view-raw { float: right; }
.gift-card { background: linear-gradient(135deg, #f59e0b, #ef4444); padding: 12px;
             border-radius: 10px; max-width: 280px; color: white; }
.contact-share { background: var(--panel2); padding: 10px 14px; border-radius: 10px;
                 max-width: 320px; }
.contact-share .h { font-weight: 600; font-size: 11px; color: var(--muted);
                    margin-bottom: 4px; }
.system-msg { text-align: center; color: var(--muted); font-size: 11px;
              margin: 8px 0; font-style: italic; }
/* Identity panel */
.identity { background: var(--panel); border: 1px solid var(--border);
            border-radius: 10px; padding: 18px; margin-bottom: 20px; }
.identity h2 { font-size: 11px; color: var(--muted); text-transform: uppercase;
               letter-spacing: 0.6px; margin-bottom: 8px; }
.identity .name { font-size: 26px; font-weight: 700; }
.identity .vpas { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.identity .vpa-chip { background: var(--bg2); border: 1px solid var(--border);
                      padding: 5px 10px; border-radius: 16px; font-size: 11px;
                      font-family: ui-monospace, monospace; }
.identity .vpa-chip.pp { border-color: var(--accent); }
.identity .vpa-chip.unknown { border-color: var(--amber); }
.identity .acct { color: var(--muted); font-size: 12px; margin-top: 10px; }
/* Export dialog */
.exp-dlg .row { margin-bottom: 12px; }
.exp-dlg .row b { display: block; margin-bottom: 6px; font-size: 11px; color: var(--muted);
                  text-transform: uppercase; letter-spacing: 0.4px; }
.exp-dlg label.opt { display: flex; align-items: center; gap: 6px; padding: 4px 0;
                     cursor: pointer; font-size: 12px; }
.exp-dlg .dates { display: flex; gap: 8px; }
.chip { display: inline-block; background: var(--accent); color: white;
        padding: 3px 9px; border-radius: 12px; font-size: 11px; margin-right: 6px;
        cursor: pointer; }
.chip:hover { background: #7c4cf0; }
.chip .x { margin-left: 4px; font-weight: 700; }
.row-actions { white-space: nowrap; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
.foot { color: var(--muted); font-size: 11px; padding: 24px 0 10px; text-align: center; }
</style>
</head>
<body>
<div class="modal-back" id="modal" onclick="if(event.target.id==='modal')closeModal()">
  <div class="modal">
    <h3><span id="mh">Raw Record</span><span class="close" onclick="closeModal()">×</span></h3>
    <div class="body" id="mb"></div>
  </div>
</div>
<div class="modal-back" id="exp-modal" onclick="if(event.target.id==='exp-modal')closeExp()">
  <div class="modal" style="width:520px">
    <h3>Export evidence <span class="close" onclick="closeExp()">×</span></h3>
    <div class="body exp-dlg">
      <div class="row"><b>Scope</b>
        <label class="opt"><input type="radio" name="scope" value="all" id="sc-all"> All records</label>
        <label class="opt"><input type="radio" name="scope" value="filtered" id="sc-filt" checked> Current filter (<span id="sc-fn">0</span>)</label>
        <label class="opt"><input type="radio" name="scope" value="date" id="sc-date"> Custom date range</label>
        <div class="dates" style="margin-left:22px;margin-top:6px">
          <input type="date" id="exp-from"> <input type="date" id="exp-to">
        </div>
      </div>
      <div class="row"><b>Format</b>
        <label class="opt"><input type="checkbox" id="fmt-csv" checked> CSV</label>
        <label class="opt"><input type="checkbox" id="fmt-jsonl"> JSON Lines (with raw + provenance)</label>
      </div>
      <div class="row"><b>Filename prefix</b><input id="exp-prefix" value="phonepe_evidence" style="width:100%"></div>
      <div style="text-align:right; margin-top:14px">
        <button onclick="closeExp()">Cancel</button>
        <button class="primary" onclick="doExport()">Download</button>
      </div>
    </div>
  </div>
</div>
"""

_HTML_BODY_SHELL = r"""
<div class="app">
<aside>
  <h1>PhonePe Forensics</h1>
  <div class="sub">Offline evidence report v__VERSION__</div>
  <div class="case-card">
    <div class="lbl">Subject</div><div class="v" id="meta-subject">—</div>
    <div class="lbl">Linked account</div><div class="v" id="meta-account">—</div>
    <div class="lbl">PhonePe userId</div><div class="v" id="meta-userid" style="font-family:ui-monospace,monospace;font-size:11px">—</div>
    <div class="lbl">Retention</div><div class="v" id="meta-retention">—</div>
  </div>
  <nav>
    <a href="#dashboard" class="nav-link" data-tab="dashboard">▢ Dashboard</a>
    <a href="#transactions" class="nav-link" data-tab="transactions">▤ Transactions</a>
    <a href="#conversations" class="nav-link" data-tab="conversations">▣ Conversations</a>
    <a href="#raw" class="nav-link" data-tab="raw">{ } Raw Records</a>
    <a href="#about" class="nav-link" data-tab="about">ⓘ About / Provenance</a>
  </nav>
</aside>
<main>

<section id="tab-dashboard" class="tab-pane">
  <div class="page-title">Forensic Dashboard</div>
  <div class="page-sub">Snapshot for the active acquisition. Counts are de-duplicated across TransactionsStore + Burble; amounts taken from the richer source per payment.</div>
  <div id="retention-banner" class="banner"></div>
  <div id="identity-panel"></div>
  <div class="stat-grid" id="stats"></div>
  <div class="stat-grid" id="stats2"></div>
</section>

<section id="tab-transactions" class="tab-pane" style="display:none">
  <div class="page-title">Transactions</div>
  <div class="page-sub">All payments visible in this acquisition. Use filters to narrow; click "raw" on any row to inspect decoded JSON + provenance.</div>
  <div class="filter-bar">
    <div class="grp"><label>Search (name / phone / VPA / ID)</label><input id="f-q"></div>
    <div class="grp"><label>Date from (IST)</label><input id="f-from" type="date"></div>
    <div class="grp"><label>Date to (IST)</label><input id="f-to" type="date"></div>
    <div class="grp"><label>Min ₹</label><input id="f-min" type="number"></div>
    <div class="grp"><label>Max ₹</label><input id="f-max" type="number"></div>
    <div class="grp"><label>Direction</label><select id="f-dir"><option value="">All</option><option>SENT</option><option>RECEIVED</option><option>UNKNOWN</option></select></div>
    <div class="grp"><label>Classification</label><select id="f-class"><option value="">All</option><option>MERCHANT</option><option>MERCHANT_REFUND</option><option>PEER_TO_PEER</option><option>MANDATE</option><option>OTHER</option><option>UNKNOWN</option></select></div>
    <div class="grp"><label>State</label><select id="f-state"><option value="">All</option><option>COMPLETED</option><option>FAILED</option><option>CREATED</option><option>PENDING</option><option>UNKNOWN</option></select></div>
    <div class="grp"><label>Source</label><select id="f-src"><option value="">All</option><option value="txnstore_full">TxnStore full</option><option value="burble_only">Chat-only</option></select></div>
    <div class="grp"><label>App attribution</label><select id="f-app"></select></div>
    <div class="grp"><label>Initiation</label><select id="f-init"><option value="">All</option></select></div>
    <div class="grp"><label>Bank</label><select id="f-bank"><option value="">All</option></select></div>
    <div class="grp"><label>Refund only</label><select id="f-refund"><option value="">All</option><option value="1">Refund only</option></select></div>
    <div class="grp" style="grid-column:1/-1;display:flex;flex-direction:row;align-items:end;gap:8px">
      <button onclick="resetTxnFilters()">Reset</button>
      <button class="primary" onclick="openExp()">Export →</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="live-stats" id="t-stats"></div>
    <div style="font-size:11px;color:var(--muted)">Showing <b id="t-shown">0</b> of <b id="t-total">0</b></div>
  </div>
  <div style="overflow:auto;max-height:72vh">
  <table id="t-table">
    <thead><tr>
      <th data-sort="datetime_ist">Date / Time (IST)</th>
      <th data-sort="direction">Type</th>
      <th>Counterparty</th>
      <th>Phone / VPA</th>
      <th data-sort="amount_inr" style="text-align:right">Amount</th>
      <th>App</th>
      <th>Bank</th>
      <th>Class</th>
      <th>Initiation</th>
      <th data-sort="state">State</th>
      <th>Source</th>
      <th>Note</th>
      <th>UTR</th>
      <th>Raw</th>
    </tr></thead>
    <tbody id="t-body"></tbody>
  </table>
  </div>
</section>

<section id="tab-conversations" class="tab-pane" style="display:none">
  <div class="page-title">Conversations</div>
  <div class="page-sub">Chat history reconstructed from <code>Burble.sqlite</code>. Click a thread to view messages; payment cards link back to the corresponding transaction.</div>
  <div class="filter-bar">
    <div class="grp"><label>Search chats</label><input id="c-q"></div>
    <div class="grp"><label>Content type</label><select id="c-type"><option value="">All</option></select></div>
    <div class="grp"><label>Date from</label><input id="c-from" type="date"></div>
    <div class="grp"><label>Date to</label><input id="c-to" type="date"></div>
    <div class="grp" style="display:flex;flex-direction:row;align-items:end;gap:8px"><button onclick="resetConvFilters()">Reset</button></div>
  </div>
  <div class="chat-app">
    <div class="chat-list" id="c-list"></div>
    <div class="chat-stream" id="c-stream"><div class="empty">Select a conversation →</div></div>
  </div>
</section>

<section id="tab-raw" class="tab-pane" style="display:none">
  <div class="page-title">Raw Records</div>
  <div class="page-sub">Every record carried by this report, with the forensic-provenance envelope. Click any row to view the full decoded JSON.</div>
  <div class="filter-bar">
    <div class="grp"><label>Search</label><input id="r-q"></div>
    <div class="grp"><label>Kind</label><select id="r-kind"><option value="">All</option></select></div>
    <div class="grp"><label>Source DB</label><select id="r-db"><option value="">All</option></select></div>
  </div>
  <div class="toolbar">
    <div style="font-size:11px;color:var(--muted)">Showing <b id="r-shown">0</b> of <b id="r-total">0</b></div>
  </div>
  <div style="overflow:auto;max-height:72vh">
  <table>
    <thead><tr>
      <th>Kind</th><th>Source DB</th><th>Table</th><th>Row PK</th>
      <th>ID</th><th>Date (IST)</th><th>Summary</th><th>Raw</th>
    </tr></thead>
    <tbody id="r-body"></tbody>
  </table>
  </div>
</section>

<section id="tab-about" class="tab-pane" style="display:none">
  <div class="page-title">About / Provenance</div>
  <div class="page-sub">This is a self-contained offline evidence file. Open it from disk; no network calls are made.</div>
  <div class="stat-grid">
    <div class="stat"><div class="lbl">Tool</div><div class="v" id="ab-tool">—</div></div>
    <div class="stat"><div class="lbl">Generated</div><div class="v" style="font-size:14px" id="ab-when">—</div></div>
    <div class="stat"><div class="lbl">Case id</div><div class="v" style="font-size:14px" id="ab-case">—</div></div>
  </div>
  <h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin:8px 0">Source DB hashes (SHA-256)</h3>
  <table>
    <thead><tr><th>Logical name</th><th>Relative path</th><th>Size</th><th>SHA-256</th></tr></thead>
    <tbody id="ab-srcs"></tbody>
  </table>
  <div class="foot">
    App attribution is sourced exclusively from <code>ConfigManagerKeyStore.sqlite::ZKEYVALUESTORE</code> key <code>chatProperty</code> (PhonePe's own production <code>tpapKeyMap</code>). Entries labelled "Unknown TPAP" indicate the PSP suffix is not present in the acquired backup's TPAP map; no inference is made.<br><br>
    Receiver VPA reflects the UPI handle active at transaction time. Sender intent cannot be inferred from this record alone.
  </div>
</section>

</main>
</div>
<script>
// ---------- inlined data ----------
"""

_HTML_JS_AND_TAIL = r"""
// ---------- end inlined data ----------

const $ = (s)=>document.querySelector(s);
const $$ = (s)=>[...document.querySelectorAll(s)];

function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtInr(n){ if(n==null) return ''; return '₹'+(Number(n)||0).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function ymd(s){ return (s||'').slice(0,10); }
function dirPill(d){ if(d==='SENT') return '<span class="pill sent">SENT</span>'; if(d==='RECEIVED') return '<span class="pill received">RECEIVED</span>'; return '<span class="pill unknown">'+escapeHtml(d||'?')+'</span>'; }
function statePill(s){ if(s==='COMPLETED') return '<span class="pill completed">'+s+'</span>'; if(s==='FAILED') return '<span class="pill failed">'+s+'</span>'; return '<span class="pill unknown">'+escapeHtml(s||'?')+'</span>'; }
function classPill(c){ const cls={MERCHANT:'merchant',MERCHANT_REFUND:'refund',PEER_TO_PEER:'p2p',MANDATE:'mandate'}[c]||'unknown'; return '<span class="pill '+cls+'">'+escapeHtml(c||'')+'</span>'; }
function srcPill(s){ return s==='burble_only' ? '<span class="pill chat-only">Chat-only</span>' : '<span class="pill txnstore">Full</span>'; }
function appLogoUrl(iconId){ return iconId && DATA.app_icons[iconId] ? DATA.app_icons[iconId] : null; }
function bankLogoUrl(bid){ return bid && DATA.bank_icons[bid] ? DATA.bank_icons[bid] : null; }
function avatarFor(phone, name){
  const a = phone && DATA.avatars[phone];
  if(a) return '<span class="avatar"><img src="'+a+'"></span>';
  const init = (name||'?').trim().split(/\s+/).map(w=>w[0]).slice(0,2).join('').toUpperCase()||'?';
  const hue = (init.charCodeAt(0)*31 + (init.charCodeAt(1)||7))%360;
  return '<span class="avatar fallback" style="background:hsl('+hue+',55%,45%)">'+escapeHtml(init)+'</span>';
}

// ---------- tab routing ----------
function showTab(name){
  $$('.tab-pane').forEach(p=>p.style.display='none');
  $$('.nav-link').forEach(a=>a.classList.toggle('active', a.dataset.tab===name));
  const pane = $('#tab-'+name);
  if(pane) pane.style.display='block';
  if(name==='transactions') renderTxns();
  if(name==='conversations') renderConvs();
  if(name==='raw') renderRaw();
}
window.addEventListener('hashchange', ()=>showTab(location.hash.slice(1)||'dashboard'));

// ---------- header & dashboard ----------
function renderHeader(){
  const m = DATA.meta;
  $('#meta-subject').textContent = m.subject_name || '—';
  $('#meta-account').textContent = m.account_no ? (m.account_no+' · '+(m.bank_name||'')) : '—';
  $('#meta-userid').textContent = m.user_id || '—';
  $('#meta-retention').textContent = (m.retention_days?m.retention_days+' days':'Unknown');
  // retention banner
  if(m.retention_days){
    $('#retention-banner').innerHTML = '⏳ TransactionsStore covers the last <b>'+m.retention_days+' days</b> (~'+(m.retention_days/30).toFixed(1)+' months) per <code>ZUSER.ZDURATIONOFDOWNLOADINDAYS</code>. Earlier history is recovered via Burble chat-card mining.';
  } else {
    $('#retention-banner').innerHTML = '⚠ Retention window unknown (ZUSER missing).';
  }
  // identity
  const owners = DATA.meta.owner_vpas||[];
  const chips = owners.map(o=>'<span class="vpa-chip '+(o.is_phonepe_psp?'pp':'unknown')+'">'+escapeHtml(o.vpa)+'</span>').join('');
  $('#identity-panel').innerHTML = '<div class="identity"><h2>Subject identity</h2><div class="name">'+escapeHtml(m.subject_name||'—')+'</div><div class="acct">Bank: '+escapeHtml(m.bank_name||'?')+' · A/C '+escapeHtml(m.account_no||'?')+' · IFSC '+escapeHtml(m.ifsc||'?')+'</div><div class="vpas">'+chips+'</div></div>';
}

function renderStats(){
  const p = DATA.payments;
  const total = p.length;
  const totalRecv = p.filter(x=>x.direction==='RECEIVED').reduce((a,b)=>a+(b.amount_inr||0),0);
  const totalSent = p.filter(x=>x.direction==='SENT').reduce((a,b)=>a+(b.amount_inr||0),0);
  const ts = p.filter(x=>x.data_source==='txnstore_full').length;
  const bo = p.filter(x=>x.data_source==='burble_only').length;
  const failed = p.filter(x=>x.state==='FAILED').length;
  const failedChat = p.filter(x=>x.is_failed_chat_only).length;
  const refunds = p.filter(x=>x.is_refund).length;
  const mandates = DATA.mandates.length;
  const qr = p.filter(x=>x.is_qr_scan).length;
  const intent = p.filter(x=>x.is_intent).length;
  $('#stats').innerHTML = [
    ['Transactions', total, 'union of TxnStore + Burble; de-duplicated', 'accent'],
    ['Total Received', fmtInr(totalRecv), p.filter(x=>x.direction==='RECEIVED').length+' txns', 'green'],
    ['Total Sent', fmtInr(totalSent), p.filter(x=>x.direction==='SENT').length+' txns', 'red'],
    ['By Source', ts+' / '+bo, 'TxnStore full · Chat-only', 'blue'],
    ['Failed payments', failed, '('+(failed-failedChat)+' from TxnStore · '+failedChat+' chat-only)', 'amber'],
    ['Refunds', refunds, 'incoming with from.type=MERCHANT', 'amber'],
  ].map(([l,v,s,c])=>'<div class="stat"><div class="lbl">'+l+'</div><div class="v '+c+'">'+v+'</div><div class="sub">'+s+'</div></div>').join('');
  $('#stats2').innerHTML = [
    ['QR / Scan', qr, 'NPCI codes 01/02/04/05', 'amber'],
    ['UPI Intent', intent, 'context.initiationMode=INTENT', 'blue'],
    ['Mandates / requests', mandates, 'autopay + collect requests + enrichment', 'accent'],
    ['Chat conversations', (DATA.conversations||[]).length, (DATA.messages||[]).length+' messages total', 'blue'],
  ].map(([l,v,s,c])=>'<div class="stat"><div class="lbl">'+l+'</div><div class="v '+c+'">'+v+'</div><div class="sub">'+s+'</div></div>').join('');
}

// ---------- transactions table ----------
let txnFilters = {};
let txnSort = {col:'datetime_ist', dir:'desc'};
function buildFilterOptions(){
  const apps = new Set(); const banks = new Set(); const inits = new Set();
  DATA.payments.forEach(p=>{ if(p.sender_app_label) apps.add(p.sender_app_label); if(p.receiver_app_label) apps.add(p.receiver_app_label); if(p.bank_name) banks.add(p.bank_name); if(p.payment_initiation) inits.add(p.payment_initiation); });
  $('#f-app').innerHTML = '<option value="">All</option>'+[...apps].sort().map(x=>'<option>'+escapeHtml(x)+'</option>').join('');
  $('#f-bank').innerHTML = '<option value="">All</option>'+[...banks].sort().map(x=>'<option>'+escapeHtml(x)+'</option>').join('');
  $('#f-init').innerHTML = '<option value="">All</option>'+[...inits].sort().map(x=>'<option>'+escapeHtml(x)+'</option>').join('');
}
function readTxnFilters(){
  txnFilters = {
    q: ($('#f-q').value||'').toLowerCase(),
    from: $('#f-from').value, to: $('#f-to').value,
    min: parseFloat($('#f-min').value)||0, max: parseFloat($('#f-max').value)||Infinity,
    dir: $('#f-dir').value, cls: $('#f-class').value, state: $('#f-state').value,
    src: $('#f-src').value, app: $('#f-app').value, init: $('#f-init').value,
    bank: $('#f-bank').value, refund: $('#f-refund').value,
  };
}
function applyTxnFilters(rows){
  const f = txnFilters;
  return rows.filter(p=>{
    if(f.q){
      const hay = (p.counterparty_name+' '+(p.counterparty_verified_name||'')+' '+(p.counterparty_cbs_name||'')+' '+(p.counterparty_phone||'')+' '+(p.counterparty_vpa||'')+' '+(p.primary_id||'')+' '+(p.utr||'')).toLowerCase();
      if(hay.indexOf(f.q)<0) return false;
    }
    if(f.from && ymd(p.datetime_ist) < f.from) return false;
    if(f.to && ymd(p.datetime_ist) > f.to) return false;
    const a = Number(p.amount_inr)||0;
    if(a < f.min || a > f.max) return false;
    if(f.dir && p.direction!==f.dir) return false;
    if(f.cls && p.classification!==f.cls) return false;
    if(f.state && p.state!==f.state) return false;
    if(f.src && p.data_source!==f.src) return false;
    if(f.app && p.sender_app_label!==f.app && p.receiver_app_label!==f.app) return false;
    if(f.init && p.payment_initiation!==f.init) return false;
    if(f.bank && p.bank_name!==f.bank) return false;
    if(f.refund==='1' && !p.is_refund) return false;
    return true;
  });
}
function renderTxns(){
  readTxnFilters();
  let rows = applyTxnFilters(DATA.payments).slice();
  rows.sort((a,b)=>{ const k=txnSort.col, dir=txnSort.dir==='asc'?1:-1;
    let va=a[k], vb=b[k]; if(va==null) va=''; if(vb==null) vb='';
    if(typeof va==='number'||typeof vb==='number'){ return ((+va)-(+vb))*dir; }
    return String(va).localeCompare(String(vb))*dir; });
  $('#t-total').textContent = DATA.payments.length;
  $('#t-shown').textContent = rows.length;
  // live stats
  const sent = rows.filter(x=>x.direction==='SENT').reduce((a,b)=>a+(b.amount_inr||0),0);
  const recv = rows.filter(x=>x.direction==='RECEIVED').reduce((a,b)=>a+(b.amount_inr||0),0);
  $('#t-stats').innerHTML = 'Filtered <b>'+rows.length+'</b> · Sent <b class="red">'+fmtInr(sent)+'</b> · Received <b class="green">'+fmtInr(recv)+'</b> · Net <b>'+fmtInr(recv-sent)+'</b> · Failed <b>'+rows.filter(x=>x.state==='FAILED').length+'</b>';
  const tb = $('#t-body'); tb.innerHTML='';
  rows.forEach(p=>{
    const tr = document.createElement('tr');
    if(p.state==='FAILED') tr.classList.add('failed');
    if(p.is_refund) tr.classList.add('refund');
    const appIcon = (p.direction==='SENT'?p.receiver_app_icon_id:p.sender_app_icon_id);
    const appLabel = (p.direction==='SENT'?p.receiver_app_label:p.sender_app_label);
    const appHtml = (appLogoUrl(appIcon) ? '<img class="logo" src="'+appLogoUrl(appIcon)+'">' : '') + escapeHtml(appLabel||'');
    const bankHtml = (bankLogoUrl(p.bank_id) ? '<img class="logo" src="'+bankLogoUrl(p.bank_id)+'">' : '') + escapeHtml(p.bank_name||'');
    const cpName = p.counterparty_verified_name || p.counterparty_name || p.counterparty_cbs_name || '—';
    const amtCls = p.direction==='SENT'?'sent':(p.direction==='RECEIVED'?'received':'unknown');
    const sign = p.direction==='SENT'?'-':(p.direction==='RECEIVED'?'+':'');
    tr.innerHTML = ''
      +'<td><div>'+escapeHtml(p.datetime_ist||'').slice(0,10)+'</div><div style="color:var(--muted);font-size:10px">'+escapeHtml(p.datetime_ist||'').slice(11,19)+'</div></td>'
      +'<td>'+dirPill(p.direction)+(p.is_qr_scan?' <span class="pill amber" style="background:rgba(245,158,11,0.25);color:var(--amber)">QR</span>':'')+(p.is_intent?' <span class="pill" style="background:rgba(59,130,246,0.25);color:var(--blue)">INT</span>':'')+'</td>'
      +'<td>'+avatarFor(p.counterparty_phone,cpName)+'<span title="'+escapeHtml(cpName)+'">'+escapeHtml(cpName)+'</span>'+(p.counterparty_verified_name && p.counterparty_name!==p.counterparty_verified_name ? '<div style="color:var(--muted);font-size:10px">↳ '+escapeHtml(p.counterparty_name||'')+'</div>':'')+'</td>'
      +'<td><span style="font-family:ui-monospace,monospace;font-size:11px">'+escapeHtml(p.counterparty_phone||p.counterparty_vpa||'—')+'</span></td>'
      +'<td style="text-align:right" class="amt '+amtCls+'">'+sign+fmtInr(p.amount_inr)+'</td>'
      +'<td>'+appHtml+'</td>'
      +'<td>'+bankHtml+'</td>'
      +'<td>'+classPill(p.classification)+(p.merchant_subtype?'<div style="font-size:10px;color:var(--muted)">'+escapeHtml(p.merchant_subtype)+'</div>':'')+'</td>'
      +'<td>'+escapeHtml(p.payment_initiation||'')+(p.intent_caller_url?'<div style="font-size:10px;color:var(--muted)">'+escapeHtml(p.intent_caller_url)+'</div>':'')+'</td>'
      +'<td>'+statePill(p.state)+(p.failure_reason?'<div style="font-size:10px;color:var(--red)">'+escapeHtml(p.failure_reason)+'</div>':'')+'</td>'
      +'<td>'+srcPill(p.data_source)+'</td>'
      +'<td title="'+escapeHtml(p.note||'')+'">'+escapeHtml((p.note||'').slice(0,30))+'</td>'
      +'<td><span style="font-family:ui-monospace,monospace;font-size:11px">'+escapeHtml(p.utr||'')+'</span></td>'
      +'<td class="row-actions"><button class="btn-raw" onclick="openRaw(\''+p.primary_id+'\')">{}</button></td>';
    tb.appendChild(tr);
  });
}
function resetTxnFilters(){ ['f-q','f-from','f-to','f-min','f-max'].forEach(i=>$('#'+i).value=''); ['f-dir','f-class','f-state','f-src','f-app','f-init','f-bank','f-refund'].forEach(i=>$('#'+i).value=''); renderTxns(); }
['#f-q','#f-from','#f-to','#f-min','#f-max','#f-dir','#f-class','#f-state','#f-src','#f-app','#f-init','#f-bank','#f-refund'].forEach(s=>{ document.addEventListener('DOMContentLoaded', ()=> $(s) && $(s).addEventListener('input', renderTxns)); });
document.addEventListener('DOMContentLoaded', ()=>{
  $$('#t-table th[data-sort]').forEach(th=>{
    th.addEventListener('click', ()=>{
      const col = th.dataset.sort;
      if(txnSort.col===col) txnSort.dir = txnSort.dir==='asc'?'desc':'asc';
      else { txnSort.col = col; txnSort.dir='asc'; }
      $$('#t-table th').forEach(x=>x.className='');
      th.className = 'sort-'+txnSort.dir;
      renderTxns();
    });
  });
});

// ---------- conversations ----------
let activeChat = null;
function renderConvs(){
  // build content type options once
  if($('#c-type').children.length<2){
    const types = new Set(); DATA.messages.forEach(m=>m.content_type&&types.add(m.content_type));
    $('#c-type').innerHTML = '<option value="">All</option>'+[...types].sort().map(t=>'<option>'+escapeHtml(t)+'</option>').join('');
  }
  const q = ($('#c-q').value||'').toLowerCase();
  const list = DATA.conversations.filter(c=>!q||c.name.toLowerCase().indexOf(q)>=0);
  const ul = $('#c-list'); ul.innerHTML='';
  if(!list.length){ ul.innerHTML='<div class="empty">No conversations</div>'; return; }
  list.forEach(c=>{
    const lastMsg = (DATA.messages.filter(m=>m.group_id===c.group_id).sort((a,b)=>(b.created_at_ms||0)-(a.created_at_ms||0))[0]) || {};
    const preview = lastMsg.content_type==='PAYMENT_INFO_CARD' ? '₹'+((lastMsg.amount_paise||0)/100) : (lastMsg.text || lastMsg.content_type || '');
    const row = document.createElement('div');
    row.className = 'chat-row' + (activeChat===c.group_id?' active':'');
    row.innerHTML = avatarFor(c.member_phones&&c.member_phones[0], c.name)
      +'<div><div class="name">'+escapeHtml(c.name||'?')+'</div><div class="preview">'+escapeHtml(preview||'')+'</div></div>'
      +'<div class="meta">'+(c.last_activity_ms?new Date(c.last_activity_ms).toLocaleDateString('en-IN'):'')+'</div>';
    row.onclick = ()=>{ activeChat = c.group_id; renderConvs(); renderStream(c.group_id); };
    ul.appendChild(row);
  });
  if(!activeChat) $('#c-stream').innerHTML = '<div class="empty">Select a conversation →</div>';
  else renderStream(activeChat);
}
function renderStream(gid){
  const ctype = $('#c-type').value;
  const from = $('#c-from').value, to=$('#c-to').value;
  let msgs = DATA.messages.filter(m=>m.group_id===gid)
    .filter(m=>!ctype||m.content_type===ctype)
    .filter(m=>{ if(!m.created_at_ms) return true;
                const d = new Date(m.created_at_ms).toISOString().slice(0,10);
                if(from && d<from) return false;
                if(to && d>to) return false;
                return true; })
    .sort((a,b)=>(a.created_at_ms||0)-(b.created_at_ms||0));
  const stream = $('#c-stream'); stream.innerHTML='';
  if(!msgs.length){ stream.innerHTML='<div class="empty">No messages match the filter</div>'; return; }
  let lastDate = '';
  msgs.forEach(m=>{
    const dt = m.created_at_ms ? new Date(m.created_at_ms) : null;
    const dStr = dt ? dt.toLocaleDateString('en-IN',{day:'numeric',month:'long',year:'numeric'}) : '';
    if(dStr && dStr !== lastDate){
      const d = document.createElement('div'); d.className='date-sep'; d.textContent = dStr;
      stream.appendChild(d); lastDate = dStr;
    }
    stream.appendChild(renderMessage(m));
  });
}
function renderMessage(m){
  const wrap = document.createElement('div');
  // direction: heuristic — incoming if has only receiver tx, outgoing if has sender_tx
  const isMine = !!m.sender_transaction_id && !m.receiver_transaction_id;
  const time = m.created_at_ms ? new Date(m.created_at_ms).toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'}) : '';
  let body = '';
  switch(m.content_type){
    case 'PAYMENT_INFO_CARD': {
      const amt = (m.amount_paise||0)/100;
      const failed = (m.payment_state||'')==='FAILED';
      const cls = isMine?'paid':'received';
      body = '<div class="card '+cls+(failed?' failed':'')+'"><div class="amt-big">'+fmtInr(amt)+'</div><div class="state-chip">'+(failed?'⚠ '+(m.payment_state||''):'✓ '+(m.payment_state||'PAID'))+'</div><div class="time-mini">'+time+'</div><button class="btn-raw view-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'TEXT_MESSAGE': {
      body = '<div class="msg bubble">'+escapeHtml(m.text||'')+'</div><div class="meta-line">'+time+' <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'REWARD_GIFT_CARD': {
      body = '<div class="gift-card">🎁 Gift card<br><small>'+escapeHtml(m.raw&&m.raw.gift_message||'')+'</small></div><div class="meta-line">'+time+' <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'REWARD_GIFT_STATE_UPDATE_CARD': {
      body = '<div class="system-msg">Gift state updated <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'CONTACT': {
      body = '<div class="contact-share"><div class="h">Shared bank account</div><div>'+escapeHtml(m.text||m.raw&&m.raw.title||'')+'</div></div><div class="meta-line">'+time+' <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'TRANSACTION_RECEIPT': {
      body = '<div class="card received"><div>Receipt</div><div class="amt-big">'+fmtInr((m.amount_paise||0)/100)+'</div><div class="time-mini">'+time+'</div><button class="btn-raw view-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    case 'IMAGE_ATTACHMENT': {
      body = '<div class="msg bubble">[Image — asset not in this acquisition]</div><div class="meta-line">'+time+' <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
      break;
    }
    default: {
      body = '<div class="system-msg">'+escapeHtml(m.content_type||'?')+' <button class="btn-raw" onclick="openRawMsg('+m.pk+')">{}</button></div>';
    }
  }
  wrap.className = 'msg' + (isMine?' right':'');
  wrap.innerHTML = body;
  return wrap;
}
function resetConvFilters(){ ['c-q','c-from','c-to'].forEach(i=>$('#'+i).value=''); $('#c-type').value=''; renderConvs(); }
document.addEventListener('DOMContentLoaded', ()=>{
  ['#c-q','#c-from','#c-to','#c-type'].forEach(s=>$(s)&&$(s).addEventListener('input', renderConvs));
});

// ---------- raw records tab ----------
function renderRaw(){
  // build kind / db filters
  if($('#r-kind').children.length<2){
    const kinds = new Set(); const dbs = new Set();
    DATA.raw.forEach(r=>{kinds.add(r.kind); dbs.add(r.provenance.source_db);});
    $('#r-kind').innerHTML = '<option value="">All</option>'+[...kinds].sort().map(k=>'<option>'+escapeHtml(k)+'</option>').join('');
    $('#r-db').innerHTML = '<option value="">All</option>'+[...dbs].sort().map(k=>'<option>'+escapeHtml(k)+'</option>').join('');
  }
  const q = ($('#r-q').value||'').toLowerCase();
  const kind = $('#r-kind').value, db = $('#r-db').value;
  let rows = DATA.raw.filter(r=>{
    if(kind && r.kind!==kind) return false;
    if(db && r.provenance.source_db!==db) return false;
    if(q){ const hay = JSON.stringify(r).toLowerCase(); if(hay.indexOf(q)<0) return false; }
    return true;
  });
  rows = rows.slice(0, 2000); // cap render for perf
  $('#r-total').textContent = DATA.raw.length;
  $('#r-shown').textContent = rows.length;
  $('#r-body').innerHTML = rows.map(r=>{
    return '<tr>'
      +'<td>'+escapeHtml(r.kind)+'</td>'
      +'<td>'+escapeHtml(r.provenance.source_db||'')+'</td>'
      +'<td>'+escapeHtml(r.provenance.source_table||'')+'</td>'
      +'<td>'+escapeHtml(String(r.provenance.source_row_pk||''))+'</td>'
      +'<td><span style="font-family:ui-monospace,monospace;font-size:11px">'+escapeHtml(r.provenance.source_id_value||'')+'</span></td>'
      +'<td>'+escapeHtml(r.summary_ts||'')+'</td>'
      +'<td>'+escapeHtml((r.summary||'').slice(0,60))+'</td>'
      +'<td><button class="btn-raw" onclick="openRawRaw('+r.idx+')">{}</button></td>'
      +'</tr>';
  }).join('');
}
document.addEventListener('DOMContentLoaded', ()=>{
  ['#r-q','#r-kind','#r-db'].forEach(s=>$(s)&&$(s).addEventListener('input', renderRaw));
});

// ---------- raw-JSON modal ----------
function openModal(title, prov, decoded){
  $('#mh').textContent = title;
  const provHtml = Object.entries(prov||{}).map(([k,v])=>'<div><b>'+escapeHtml(k)+'</b><span class="v">'+escapeHtml(String(v==null?'':v))+'</span></div>').join('');
  $('#mb').innerHTML = '<div class="prov">'+provHtml+'</div><pre>'+escapeHtml(JSON.stringify(decoded, null, 2))+'</pre>';
  $('#modal').classList.add('open');
}
function closeModal(){ $('#modal').classList.remove('open'); }
function openRaw(primaryId){
  const r = DATA.raw.find(x=>x.kind==='payment' && x.provenance.source_id_value===primaryId);
  if(!r){ alert('Raw not found'); return; }
  openModal('Payment · '+primaryId, r.provenance, r.decoded);
}
function openRawMsg(pk){
  const r = DATA.raw.find(x=>x.kind==='message' && x.provenance.source_row_pk===pk);
  if(!r){ alert('Raw not found'); return; }
  openModal('Message · pk='+pk, r.provenance, r.decoded);
}
function openRawRaw(idx){
  const r = DATA.raw[idx]; if(!r) return;
  openModal((r.kind+' · '+(r.provenance.source_id_value||r.provenance.source_row_pk||'')), r.provenance, r.decoded);
}
document.addEventListener('keydown', e=>{ if(e.key==='Escape'){ closeModal(); closeExp(); }});

// ---------- export dialog ----------
function openExp(){
  $('#sc-fn').textContent = applyTxnFilters(DATA.payments).length;
  $('#exp-modal').classList.add('open');
}
function closeExp(){ $('#exp-modal').classList.remove('open'); }
function doExport(){
  const scope = document.querySelector('input[name=scope]:checked').value;
  let rows;
  if(scope==='all') rows = DATA.payments.slice();
  else if(scope==='date'){
    const f = $('#exp-from').value, t = $('#exp-to').value;
    rows = DATA.payments.filter(p=>{ const d=ymd(p.datetime_ist); return (!f||d>=f) && (!t||d<=t); });
  } else rows = applyTxnFilters(DATA.payments);
  const prefix = ($('#exp-prefix').value||'phonepe_evidence').replace(/[^a-z0-9_\-.]/gi,'_');
  if($('#fmt-csv').checked){
    const cols = ['primary_id','data_source','direction','classification','amount_inr','state','is_refund','datetime_ist','counterparty_name','counterparty_verified_name','counterparty_phone','counterparty_vpa','sender_app_label','receiver_app_label','bank_name','payment_initiation','transfer_mode','note','utr'];
    const filterState = JSON.stringify(txnFilters);
    const lines = ['# Filter state: '+filterState, cols.join(',')];
    rows.forEach(r=>{ lines.push(cols.map(c=>{
      let v = r[c]; if(v==null) v=''; v=String(v).replace(/"/g,'""');
      return /[",\n]/.test(v) ? '"'+v+'"' : v;
    }).join(',')); });
    download(prefix+'.csv', lines.join('\n'), 'text/csv;charset=utf-8');
  }
  if($('#fmt-jsonl').checked){
    const lines = rows.map(r=>{
      const raw = DATA.raw.find(x=>x.kind==='payment' && x.provenance.source_id_value===r.primary_id);
      return JSON.stringify({ summary: r, raw: raw ? {provenance: raw.provenance, decoded: raw.decoded} : null });
    });
    download(prefix+'.jsonl', lines.join('\n'), 'application/x-ndjson');
  }
  closeExp();
}
function download(name, content, mime){
  const blob = new Blob([content], {type:mime});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click();
  setTimeout(()=>{ URL.revokeObjectURL(url); a.remove(); }, 200);
}

// ---------- about / provenance ----------
function renderAbout(){
  $('#ab-tool').textContent = (DATA.meta.tool||'')+' '+(DATA.meta.tool_version||'');
  $('#ab-when').textContent = DATA.meta.generated_at || '—';
  $('#ab-case').textContent = DATA.meta.case_id || '—';
  $('#ab-srcs').innerHTML = Object.entries(DATA.meta.source_db_hashes||{}).map(([k,v])=>{
    return '<tr><td>'+escapeHtml(k)+'</td><td style="font-family:ui-monospace,monospace;font-size:11px">'+escapeHtml(v.path||'')+'</td><td>'+(v.size_bytes||0).toLocaleString()+' B</td><td style="font-family:ui-monospace,monospace;font-size:10px;word-break:break-all">'+escapeHtml(v.sha256||'')+'</td></tr>';
  }).join('');
}

// ---------- boot ----------
document.addEventListener('DOMContentLoaded', ()=>{
  renderHeader();
  renderStats();
  buildFilterOptions();
  renderAbout();
  showTab(location.hash.slice(1)||'dashboard');
});
</script>
</body>
</html>
"""


def _b64_image(path: Path) -> str | None:
    if not path or not path.exists():
        return None
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"


def _jpeg_b64(blob: bytes) -> str:
    return "data:image/jpeg;base64," + base64.b64encode(blob).decode("ascii")


def build_static_report(
    *,
    result: ReconcileResult,
    case_root: Path,
    case_id: str | None,
    output_path: Path,
    subject_name_override: str | None = None,
) -> Path:
    """Produce the single-file offline HTML report at `output_path`."""
    case_root = Path(case_root)

    owner = load_owner_identity(str(case_root))
    contacts = load_contacts(str(case_root))
    avatars_bytes = load_avatars(str(case_root))
    conversations = load_burble_conversations(str(case_root))
    messages = load_burble_messages(str(case_root))
    tpap_key_map, tpap_info = load_tpap_map(str(case_root))
    phonepe_psps = load_phonepe_psps(str(case_root))
    source_db_hashes = collect_source_db_hashes(str(case_root))

    # avatars: subset only the phones we actually reference
    phones_used = {p.counterparty_phone for p in result.payments if p.counterparty_phone}
    for c in conversations:
        for ph in c.member_phones:
            phones_used.add(ph)
    avatars_inlined = {
        ph: _jpeg_b64(b) for ph, b in avatars_bytes.items() if ph in phones_used
    }

    # bank logos (only banks referenced)
    bank_logo_dir = Path(__file__).parent / "static" / "logos" / "banks"
    banks_used = {p.bank_id for p in result.payments if p.bank_id}
    bank_icons = {}
    for bid in banks_used:
        if not bid:
            continue
        png = bank_logo_dir / f"{bid}.png"
        b64 = _b64_image(png)
        if b64:
            bank_icons[bid] = b64

    # app logos (only iconIds referenced)
    app_logo_dir = Path(__file__).parent / "static" / "logos" / "apps"
    icon_ids = set()
    for p in result.payments:
        if p.sender_app_icon_id:
            icon_ids.add(p.sender_app_icon_id)
        if p.receiver_app_icon_id:
            icon_ids.add(p.receiver_app_icon_id)
    app_icons = {}
    for iid in icon_ids:
        if not iid:
            continue
        png = app_logo_dir / f"{iid}.png"
        b64 = _b64_image(png)
        if b64:
            app_icons[iid] = b64

    # payment rows (no decoded_blob/provenance — those go via raw[])
    def _payment_summary(p) -> dict:
        d = asdict(p)
        d.pop("decoded_blob", None)
        d.pop("provenance", None)
        return d

    payments_json = [_payment_summary(p) for p in result.payments]

    # mandates
    mandates_json = []
    for m in result.mandates:
        mandates_json.append(
            {
                "primary_id": m["primary_id"],
                "entity_type": m["entity_type"],
                "state": m["state"],
                "name": m["name"],
                "amount_inr": m["amount_inr"],
                "datetime_ist": m["datetime_ist"],
                "timestamp_ms": m["timestamp_ms"],
            }
        )

    # raw records (with provenance + decoded)
    raw_records = []
    for idx, p in enumerate(result.payments):
        raw_records.append(
            {
                "idx": len(raw_records),
                "kind": "payment",
                "summary": f"{p.direction} ₹{p.amount_inr:.2f} {p.counterparty_name}".strip(),
                "summary_ts": p.datetime_ist,
                "provenance": p.provenance,
                "decoded": p.decoded_blob,
            }
        )
    for m in result.mandates:
        raw_records.append(
            {
                "idx": len(raw_records),
                "kind": "mandate_or_request",
                "summary": f"{m['entity_type']} {m['name']} ₹{m['amount_inr']:.2f}",
                "summary_ts": m["datetime_ist"],
                "provenance": m["provenance"],
                "decoded": m["decoded_blob"],
            }
        )
    for msg in messages:
        raw_records.append(
            {
                "idx": len(raw_records),
                "kind": "message",
                "summary": f"{msg.content_type or '?'}: " + (msg.text or "")[:50],
                "summary_ts": ts_ms_to_ist_str(msg.created_at_ms) if msg.created_at_ms else "",
                "provenance": {
                    "source_db": "Burble.sqlite",
                    "source_table": "ZCONTENT",
                    "source_row_pk": msg.pk,
                    "source_id_column": "Z_PK",
                    "source_id_value": str(msg.pk),
                    "sha256_of_source_blob": None,
                    "decode_path": "ZCONTENT row direct (no NSKeyedArchiver blob)",
                    "decoded_at_utc": "",
                    "case_id": case_id,
                    "tool": "phonepe-forensics",
                    "tool_version": __version__,
                },
                "decoded": msg.raw,
            }
        )

    # conversations + messages (lite, for chat UI)
    conv_json = []
    for c in conversations:
        members = [
            ph
            for ph in c.member_phones
            if ph
        ]
        conv_json.append(
            {
                "group_id": c.group_id,
                "group_pk": c.group_pk,
                "name": c.name,
                "last_activity_ms": c.last_activity_ms,
                "unread_count": c.unread_count,
                "member_phones": members,
                "is_group": c.is_group,
            }
        )
    msg_json = []
    for m in messages:
        msg_json.append(
            {
                "pk": m.pk,
                "group_id": m.group_id,
                "content_type": m.content_type,
                "created_at_ms": m.created_at_ms,
                "text": m.text,
                "amount_paise": m.amount_paise,
                "transaction_id": m.transaction_id,
                "transaction_id_alt": m.transaction_id_alt,
                "sender_transaction_id": m.sender_transaction_id,
                "receiver_transaction_id": m.receiver_transaction_id,
                "payment_state": m.payment_state,
                "note": m.note,
                "section_title": m.section_title,
                "raw": m.raw,
            }
        )

    # owner VPAs
    owner_vpas_json = [
        {
            "vpa": v.vpa,
            "psp": v.psp,
            "is_phonepe_psp": v.is_phonepe_psp,
            "account_number": v.account_number,
            "ifsc": v.ifsc,
            "bank_id": v.bank_id,
        }
        for v in owner.vpas
    ]

    from datetime import datetime, timezone

    meta = {
        "case_id": case_id,
        "tool": "phonepe-forensics",
        "tool_version": __version__,
        "generated_at": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat(),
        "subject_name": subject_name_override or owner.account_holder or "(unknown)",
        "account_no": owner.account_no,
        "ifsc": owner.ifsc,
        "bank_id": owner.bank_id,
        "bank_name": owner.bank_name,
        "user_id": owner.user_id,
        "retention_days": owner.duration_of_download_days,
        "view_version": owner.view_version,
        "owner_vpas": owner_vpas_json,
        "source_db_hashes": source_db_hashes,
        "coverage": {
            "txnstore_payment_count": result.txnstore_payment_count,
            "burble_payment_card_count": result.burble_payment_card_count,
            "overlap": result.overlap,
            "burble_only_count": result.burble_only_count,
            "txnstore_only_count": result.txnstore_only_count,
            "combined_unique_count": result.combined_unique_count,
        },
    }

    data = {
        "meta": meta,
        "payments": payments_json,
        "mandates": mandates_json,
        "raw": raw_records,
        "conversations": conv_json,
        "messages": msg_json,
        "avatars": avatars_inlined,
        "bank_icons": bank_icons,
        "app_icons": app_icons,
        "tpap_info": {
            k: {"title": v.title, "icon_id": v.icon_id, "handles": v.handles}
            for k, v in tpap_info.items()
        },
    }

    title = f"PhonePe Forensics — {meta['subject_name'] or case_id or 'Evidence Report'}"
    head = _HTML_TEMPLATE_HEAD.replace("__TITLE__", html.escape(title))
    shell = _HTML_BODY_SHELL.replace("__VERSION__", __version__)
    payload = "window.DATA = " + json.dumps(data, ensure_ascii=False, default=str) + ";\n"

    output_path = Path(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(head)
        f.write(shell)
        f.write(payload)
        f.write(_HTML_JS_AND_TAIL)
    return output_path
