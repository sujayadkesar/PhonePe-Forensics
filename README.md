# 🔍 PhonePe Forensics
![](/assets/banner.png)

<div align="center">

<img src="https://img.shields.io/badge/Platform-iOS%20Forensics-blue?style=for-the-badge&logo=apple&logoColor=white" />
<img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Flask-Web%20UI-000000?style=for-the-badge&logo=flask&logoColor=white" />
<img src="https://img.shields.io/badge/SQLite-WAL%20Aware-003B57?style=for-the-badge&logo=sqlite&logoColor=white" />
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />


### *The definitive open-source DFIR toolkit for PhonePe iOS evidence extraction, cross-database correlation, and UPI fraud investigation*

<br/>

[![Blog Post](https://img.shields.io/badge/Blog-thelocalh0st.com-orange?style=flat-square&logo=hashnode)](https://thelocalh0st.com/posts/phonepe-forensics/)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg?style=flat-square)](https://www.python.org)
[![Flask](https://img.shields.io/badge/flask-2.x-black.svg?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![DFIR](https://img.shields.io/badge/category-DFIR-red?style=flat-square)](https://github.com/topics/dfir)
[![UPI](https://img.shields.io/badge/UPI-Fraud%20Analysis-purple?style=flat-square)](https://github.com/topics/upi)

<br/>

> **"What Chitragupt records in mythology, PhonePe records in SQLite. This tool reads both."**

</div>

---

## 📋 Table of Contents

- [🎯 What Is This?](#-what-is-this)
- [💡 Why It Matters](#-why-it-matters)
- [🏗️ Architecture](#%EF%B8%8F-architecture)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🧭 Usage](#-usage)
- [📁 Evidence Modules](#-evidence-modules-16-parsers)
- [🗄️ Supported Artifacts — The Full Map](#%EF%B8%8F-supported-artifacts--the-full-map-50-databases)
- [🧪 The Three Storage Domains](#-the-three-storage-domains)
- [🔎 PPQL — PhonePe Query Language](#-ppql--phonepe-query-language)
- [🕸️ Cross-Database Correlation Engine](#%EF%B8%8F-cross-database-correlation-engine)
- [⏱️ Unified Timeline & Suspicious Signal Detection](#%EF%B8%8F-unified-timeline--suspicious-signal-detection)
- [🧩 Timestamp Semantics — The Three Epochs](#-timestamp-semantics--the-three-epochs)
- [📤 Export Formats](#-export-formats)
- [🔬 Research Reference](#-research-reference)
- [🗂️ Project Structure](#%EF%B8%8F-project-structure)
- [🤝 Contributing](#-contributing)
- [⚖️ Legal & Ethics](#%EF%B8%8F-legal--ethics)
- [📚 References & Further Reading](#-references--further-reading)
- [👤 Author](#-author)

---

## 🎯 What Is This?

**PhonePe iOS Forensics** is a full-spectrum digital forensics workstation — packaged as a local Flask web application — purpose-built for extracting, correlating, and presenting evidence from PhonePe iOS app acquisitions.

It turns a raw iOS backup or filesystem extraction into a structured, investigator-ready case:

```
Raw Acquisition Folder
        │
        ▼
  ┌─────────────────────────────────────────────────────┐
  │          PhonePe iOS Forensics Engine               │
  │                                                     │
  │  16 Extraction Modules  ──►  Correlation Engine     │
  │  50+ SQLite Databases   ──►  Unified Timeline       │
  │  15+ Plist Files        ──►  Social Graph           │
  │  Binary Cookies         ──►  PPQL Hunt Interface    │
  │  NSKeyedArchiver blobs  ──►  Suspicious Signals     │
  │  WebKit data            ──►  Multi-format Reports   │
  └─────────────────────────────────────────────────────┘
        │
        ▼
  Structured Evidence + Exportable Reports
```

This is **not** a wrapper around commercial tools. Every parser is written from scratch, specifically for PhonePe's internal SDK architecture — handling the real column names, real BLOB encodings, real timestamp epochs, and real database schemas that published forensic write-ups consistently get wrong.

---

## 💡 Why It Matters

### The Problem with Existing PhonePe Forensics

Virtually every publicly available PhonePe forensic reference makes the same category of mistakes:

| Common Mistake | Reality |
|---|---|
| References a `ZTRANSACTION` table with columns like `ZAMOUNT`, `ZSENDERUPIID` | That table **does not exist**. The real table is `ZTRANSACTIONENTITY` |
| Reads amount directly from a column | Amounts are packed inside a **zlib-compressed JSON BLOB** in `ZDATA`, in **paise** (not rupees) |
| Uses Unix epoch for all timestamps | PhonePe iOS uses **three different epochs** interchangeably |
| Only reads the main AppDomain | Critical databases (chat, contacts, P2P) live in **AppDomainGroup** — invisible to AppDomain-only extraction |
| Ignores WAL files | Deleted records survive in SQLite **WAL pages** — critical for anti-tampering analysis |

This tool fixes all of the above.

### What the iOS App Actually Stores

Unlike server-side forensics (which requires legal process and is often delayed), the PhonePe iOS app locally preserves:

- 📊 **Every transaction** in a local SQLite ledger — including failed and abandoned payment attempts
- 👥 **Every contact** with their UPI IDs and cached profile photos
- 💬 **In-app chat messages** with bidirectional links to financial transactions
- 📲 **Sub-second behavioral logs** of every tap, screen view, and keyboard entry
- 🔔 **Push notification payloads** that survive even after transaction deletion
- ✈️ **Physical travel data** including PNR numbers, passenger identities, and co-traveler names
- 🤖 **ML-inferred financial patterns** that persist even after transaction deletion
- 🏦 **AutoPay mandates** (active and revoked) invisible in the current app UI

---

## 🏗️ Architecture

```
phonepe_forensics/
├── core.py           ← Parsing primitives (SQLite/WAL, plist, binarycookies,
│                       NSKeyedArchiver, timestamp normalization, hashing)
│
├── extractors.py     ← 16 forensic extraction modules
│                       (identity, transactions, contacts, chat, notifications,
│                        analytics, financial, travel, payment_infra, config_state,
│                        recommendations, media, search, webkit, audit, app_state)
│
├── correlator.py     ← Cross-database fusion engine
│                       (unified_timeline, social_graph, counterparty_profiles,
│                        corroboration_index, suspicious_signal_detection)
│
├── hunt.py           ← PPQL — PhonePe Query Language parser & executor
│                       (SPL-inspired query engine over merged forensic indexes)
│
├── case.py           ← Case orchestrator
│                       (coordinates extraction, caches results, exposes to UI)
│
├── case_manager.py   ← Multi-case registry
│                       (JSON-manifest backed, persist across restarts)
│
├── reports.py        ← Report exporter
│                       (CSV, JSON, HTML — self-contained, no external deps)
│
├── research_data.py  ← In-app reference documentation
│                       (every artifact, schema, and query — built-in)
│
├── webapp.py         ← Flask web UI (35+ routes, multi-case, full UI)
│
├── templates/        ← Jinja2 HTML templates
└── static/           ← CSS + JS
```

### Design Principles

- **Defensive parsing everywhere** — all parsers degrade gracefully on partial corruption, because forensic acquisitions frequently contain truncated or partially checkpointed databases
- **WAL-aware by default** — SQLite opened in `mode=ro&cache=private`, WAL contents automatically applied on open, uncommitted-but-checkpointed transactions are visible
- **Zero writes to evidence** — never touches the source folder; all processing is read-only
- **Multi-epoch timestamp normalization** — every timestamp column is automatically detected and normalized across Unix-ms, Unix-s, and Apple CoreData epochs
- **BLOB auto-detection** — `ZDATA` blobs are tried as raw JSON, then zlib-compressed JSON, then NSKeyedArchiver plist, before graceful fallback

---

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/thelocalh0st/phonepe-ios-forensics.git
cd phonepe-ios-forensics

# 2. Install
pip install flask

# 3. Launch
python run.py

# Opens http://127.0.0.1:5000 in your browser automatically
```

**That's it.** No config files. No API keys. No database setup. Open the Case Manager, point it at your acquisition folder, and click **Process Case**.

---

## 📦 Installation

### Requirements

| Component | Minimum |
|---|---|
| Python | 3.9+ |
| Flask | 2.x |
| OS | Windows · macOS · Linux |
| Disk | Enough for your acquisition + ~50MB working space |

### Standard Install

```bash
pip install flask
```

Flask is the only **hard** dependency. The tool uses Python's stdlib for everything else: `sqlite3`, `plistlib`, `hashlib`, `struct`, `zlib`, `re`, `json`, `csv`.

### Optional (recommended for development)

```bash
pip install flask werkzeug
```

### Virtual Environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate.bat       # Windows

pip install flask
python run.py
```

### Windows-Specific Notes

On Windows, the entry point auto-configures UTF-8 encoding for stdout/stderr — no manual `chcp 65001` needed:

```python
# run.py handles this automatically
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8")
```

---

## 🧭 Usage

### Starting the Server

```bash
# Default (127.0.0.1:5000)
python run.py

# Custom host:port
python run.py 0.0.0.0:8080

# Or as a module
python -m phonepe_forensics.webapp 127.0.0.1:5000
```

> 🔒 **Security Note:** The server binds to `127.0.0.1` by default. Do not expose to a network interface in a multi-user environment — this is a single-investigator local workstation tool.

### Creating a Case

Navigate to **Case Manager → New Case**. Two input modes are supported:

**Mode 1 — Single Root Folder** (most common)

Point to the parent directory that contains all three `AppDomain*` containers:

```
/path/to/extraction/
├── AppDomain-com.phonepe.PhonePeApp/
├── AppDomainGroup-group.com.phonepe.PhonePeApp/
└── AppDomainGroup-group.com.phonepe.shared/
```

**Mode 2 — Three-Folder Mode** (split exports)

Explicitly point each of the three containers at a separate path — useful when an investigator has received partial exports from different acquisition sources.

### Processing a Case

After creation, click **Process Case** to run all 16 extraction modules sequentially. Processing is **fully parallelism-safe** — each module reads independently. Typical processing time on a full acquisition: **5–30 seconds** depending on database sizes.

Results are cached in memory and available immediately across all views.

### Navigating Evidence

The left sidebar provides one-click access to every evidence category:

| View | What You See |
|---|---|
| 🏠 Dashboard | Summary cards — transaction count, contact count, chat groups, findings |
| 👤 Identity | Registered name, UPI ID, device fingerprints, session tokens, location hints |
| 💸 Transactions | Full ledger with filtering by date, direction, state, amount, counterparty |
| 👥 Contacts | Cyclops-verified contacts + phonebook with UPI ID resolution |
| 🌐 Social Graph | Contact ↔ transaction ↔ chat linkage visualization |
| 💬 Chat | Burble group messages with linked transaction cards |
| 🔔 Notifications | PubSubCore push topic archive |
| 📊 Analytics | Foxtrot + KN + Dash behavioral event batches |
| 💰 Financial | Rewards, mutual funds, vouchers, donations |
| ✈️ Travel | Yatra booking PNRs, passenger names, co-travelers |
| 🏦 Payment Infra | Linked banks, UPI VPAs, payment instruments, AutoPay mandates |
| ⚙️ Config State | Chimera remote config, A/B test assignments, feature flags |
| 🎯 Recommendations | Maximus offers engine + Athena ML signals |
| 🖼️ Media | QR code artifacts, transaction backgrounds, profile photos |
| 🔍 Search | AppSearch FTS query history + NexusCore sitemap |
| 🌐 WebKit | ResourceLoadStatistics + binary cookies |
| 🕵️ Audit | Chitragupt + Chronicle + Samsara + sync gap analysis |
| ⏱️ Timeline | Unified chronological event stream across all databases |
| 🚨 Findings | Heuristic suspicious signal flags |
| 🗄️ DB Browser | Raw SQL interface against any parsed database |
| 🔎 Hunt (PPQL) | PhonePe Query Language search interface |
| 📖 Research | Built-in artifact reference documentation |

---

## 📁 Evidence Modules — 16 Parsers

Each module is a self-contained extractor that reads from specific databases and plists within the three storage domains.

### 🪪 `extract_identity`

Pins the ownership of the device + UPI account. Sources:

- `com.phonepe.widgetxii.datacache.plist` → primary UPI ID
- `com.phonepe.help.customDataStore.plist` → `userName` + `refreshToken`
- `com.phonepe.ads.sdk.plist` → GPS coordinates, pincode, state
- `com.apple.AdSupport.plist` → IDFA enforcement state
- `com.firebase.FIRInstallations.plist` → Firebase install ID
- `__gads__.plist` → Google Ads signals
- `com.phonepe.PhonePeApp.plist` (222 keys) → session IDs, BoltV2 token preview, Chimera quick-flags

**Forensic Output:**
```
registered_name     → KYC-verified legal name
upi_id              → Primary UPI VPA
phones_seen         → All phone numbers extracted from any source
device_identifiers  → AppsFlyer, Firebase, GADS, AdSupport IDs
location_hints      → [{ lat, lng, pincode, state, source }]
tokens              → Help refresh token, optimus token, BoltV2 preview
sessions            → Token expiry, fetch timestamps
feature_flags       → Active Chimera quick-flags
```

---

### 💸 `extract_transactions`

**Master ledger parser** — the highest-value module. Reads `TransactionsStore.sqlite` with full ZDATA blob decoding.

```
TransactionsStore.sqlite
├── ZTRANSACTIONENTITY      ← one row per transaction
│   └── ZDATA               ← zlib-compressed JSON with the actual payload
├── ZTRANSACTIONTAGENTITY   ← ~4 tags per transaction (payment_source, utr, etc.)
├── ZVIEWENTITY             ← display-optimized mirror (survives ZDATA corruption)
├── ZUSER                   ← device owner (1 row)
└── ZTRANSACTIONSEARCHRECENTS ← user's own search queries in transaction history
```

The `ZDATA` blob is automatically decoded through a waterfall:
1. Raw JSON
2. `zlib.decompress()` → JSON
3. NSKeyedArchiver plist
4. Graceful hex preview fallback

Amount unit detection handles the **paise trap** automatically: `"value": 50000, "unitType": "PAISA"` → ₹500.00.

**Transaction ID Embedded Timestamp Decoding:**
PhonePe transaction IDs embed a timestamp in their structure (e.g., `T2412190843728...`). The tool decodes this as an independent timestamp source — useful for detecting clock manipulation.

---

### 👥 `extract_contacts`

Reads `SamparkV2.sqlite` (group container) — PhonePe's proprietary contact intelligence system.

```
SCONTACT                   → Phone → UPI ID → name mapping (financial social graph)
SCONTACT_UPI_MAPPING       → Historical phone-to-VPA associations with timestamps
ZPHONEBOOKCONTACT          → Raw device address book (with deletion flags)
```

Key forensic outputs:
- **Name divergence detection** — `SDISPLAY_NAME` (PhonePe's view) vs `SDEVICE_CONTACT_NAME` (phonebook) — reveals contact renaming used to obscure payment recipients
- **Transaction frequency scores** — `SLAST_TRANSACTED_AT` + `STRANSACTION_COUNT` independent of `TransactionsStore`
- **Profile photo recovery** from `.SamparkV2_SUPPORT/_EXTERNAL_DATA/` — photos persist after contact deletion

---

### 💬 `extract_chat`

Parses `BurbleNotificationStore.sqlite` — the in-app P2P chat + payment notification system.

```
ZBURBLEGROUP          → Group containers with subscriber lists
ZBURLBEMESSAGE        → Individual messages (TEXT, PAYMENT_INFO_CARD, REWARD_CARD)
ZBANKACCOUNTCONTACT   → Shared bank account disclosures (account + IFSC + VPA)
```

Every `PAYMENT_INFO_CARD` message embeds: amount, UPI reference, instrument, UTR, payment state — creating a second independent transaction record inside the chat layer.

---

### 🔔 `extract_notifications`

Reads `PubSubCoreBullhornDataStore.sqlite` — the **most tamper-resistant evidence source** in the corpus.

Push notification payloads arrive from PhonePe's servers before any user interaction is possible. A user can delete a transaction from `TransactionsStore`. They **cannot** retroactively delete the push notification. The payload:

```json
{
  "transactionId": "T241119182327",
  "amount": "500",
  "sender": "rahul@phonepe",
  "status": "SUCCESS",
  "bankRefNo": "401234567890",
  "timestamp": "2024-11-19T18:23:27+05:30"
}
```

...is a server-pushed attestation of a successful transaction, logged independently of any user-controlled record.

---

### 📊 `extract_analytics`

Three sub-sources:

**Foxtrot** (`FoxtrotEventsDB.sqlite` — group container):
PhonePe's analytics batching pipeline. The critical distinction:

```
FUPLOAD_STATUS = 'UPLOADED'  →  Server-side records exist — obtainable via legal process
FUPLOAD_STATUS = 'PENDING'   →  EXCLUSIVELY local evidence — cannot be obtained via legal process
```

Events inside pending batches include geolocation coordinates: `{"latitude": 17.385, "longitude": 78.486}` — location data tied to transactions even when no explicit location column exists.

**KN Analytics** (`kn_analytics_db.sqlite`): Content interaction log — proves which merchants/offers a user was exposed to and clicked on before any payment.

**Dash** (`Dash-Events.sqlite`): Screen load latencies — implicitly prove specific screens were rendered at specific timestamps.

---

### 💰 `extract_financial`

Parses rewards, mutual funds, vouchers, and donations:

- `RewardsDataStore.sqlite` — scratch cards with `ZLINKED_TXN_ID` → independent transaction corroboration
- `MFDataStore.sqlite` — portfolio holdings + SIP mandates
- `BrandVouchersDataStore.sqlite` — merchant-specific spending patterns (Swiggy, Zomato, Amazon...)
- `DonationsDataStore.sqlite` — NGO payments, PM-CARES contributions
- `OffersDataStore.sqlite` — merchant offers shown and clicked, timestamped

**Scratch card forensic significance:** A scratch card is server-issued only on transaction success. Its existence independently proves the transaction completed — even if the `ZTRANSACTIONENTITY` row was deleted.

---

### ✈️ `extract_travel`

Reads `YatraDataModel.sqlite` — a **physical movement artifact**.

```
ZBOOKING       → Route, journey date, PNR, booking timestamp, amount
ZPASSENGER     → Legal name, age, ID proof type, ID proof number (Aadhaar/Passport)
```

`ZID_PROOF_NUMBER` is a direct Aadhaar or passport number. Co-passenger records prove physical co-location with named associates. PNR cross-reference with IRCTC/airline records builds a travel timeline that corroborates or contradicts alibi claims.

**Transaction Background Date Decoding:** Folder names in `P2P/TransactionBackgrounds/` embed the download date. The oldest folder = earliest PhonePe activity on this device. This survives complete transaction history deletion.

---

### 🏦 `extract_payment_infra`

Comprehensive payment infrastructure mapping:

```
AccountSharedDataModel.sqlite
├── ZUSERPROFILE        → KYC identity, Aadhaar/PAN link status
├── ZLINKEDBANKACCOUNT  → All banks ever linked (including delinked with ZDELINKED_AT)
└── ZUPIID              → All VPAs (active + deregistered)

PaymentDataStore.sqlite
├── ZPAYMENTINTENTENTITY    → "Ghost transactions" — initiated but never completed
├── ZPAYMENTGATEWAYRESPONSE → Raw bank gateway responses with NPCI trace IDs
├── ZUPILINKEDACCOUNT       → VPA-to-bank-account binding records
└── ZAUTOPAYMANDATE         → AutoPay mandates — including REVOKED with revoked_at
```

**Delinked bank accounts** (`ZDELINKED_AT` not null) are invisible in the current UI but fully preserved — historically linked financial instruments that may have been removed shortly before investigation.

**Ghost transactions** — `ZPAYMENTINTENTENTITY` rows created the instant a user initiates a payment flow, before any UPI call is made. Even if the user cancels after entering the amount, this record exists. Destroys "I never tried to send that amount" claims.

---

### ⚙️ `extract_config_state`

Reads Chimera's remote config cache and A/B test assignments:

```
ChimeraCoreResponseStore.sqlite → Exact UI specs served to this device at each timestamp
ExperimentationCoreStore.sqlite → Which A/B test variant the user was actually shown
ConfigManagerKeyStore.sqlite    → API endpoints, transaction limits, fraud detection toggles
```

If a defense argument is "the payment screen was confusing/misleading," Chimera's cache is the evidentiary record of the **exact UI the user saw at that time** — pinned to a specific server deployment version.

---

### 🎯 `extract_recommendations`

- `MaximusDataModel.sqlite` — promotions and offer engine state
- `AthenaStore.sqlite` — on-device ML recommendation model outputs and signals

---

### 🖼️ `extract_media`

- **QR code artifacts** — downloaded QR images with merchant embeddings
- **Transaction backgrounds** — PNG card assets with encoded download dates (first-use dating)
- **Profile photos** — contact display pictures from `_EXTERNAL_DATA/`

---

### 🔍 `extract_search`

- `AppSearch FTS recents` — user's in-app search queries
- `NXCoreDataStore.sqlite` — NexusCore mini-app sitemap

---

### 🌐 `extract_webkit`

- `ResourceLoadStatistics` — website interaction history
- `Cookies.binarycookies` — Apple binary cookie format, fully decoded:

```python
class BinaryCookieReader:
    # Parses Apple's proprietary binary cookie format
    # Header: "cook" magic + page count
    # Per-page: offset table → cookies with flags, domain, name, value, path, expiry
```

---

### 🕵️ `extract_audit`

Multi-source audit reconstruction:

- **Chitragupt** — sub-second UI behavioral log (tap → keyboard → screen → mPIN confirm)
- **Chronicle** — app timeline feed (orphaned references prove deleted transactions existed)
- **Samsara** — UPI payment state machine transitions (`INITIATED → PROCESSING → SUCCESS`)
- **BGFramework** — background task execution log (proves device was active at specific times)
- **CentralSyncManager** — sync gap analysis (uniform gap = offline period, seizure, or tampering)
- **AuthDataModel** — login history with success/failure flags and failure reasons

**KEYBOARD events in Chitragupt** prove an amount was typed manually (not auto-filled). The `mpin_confirm` TAP event proves the user explicitly authorized a payment. Together, these are the most powerful anti-repudiation evidence in the corpus.

---

## 🗄️ Supported Artifacts — The Full Map (50+ Databases)

### AppDomain-com.phonepe.PhonePeApp/Documents/

| Database | SDK | Forensic Role |
|---|---|---|
| `TransactionsStore.sqlite` | Core Financial | Master UPI transaction ledger |
| `PaymentDataStore.sqlite` | Payment Engine | In-flight payment state, ghost transactions, AutoPay mandates |
| `TransferDataStore.sqlite` | Transfer SDK | Recent payees, collect requests, payment frequency map |
| `AccountSharedDataModel.sqlite` | Account SDK | KYC identity, linked banks (including delinked), UPI VPAs |
| `AuthDataModel.sqlite` | Auth SDK | Session tokens, device binding, login history |
| `Consent.sqlite` | Privacy SDK | Consent grants and revocations with timestamps |
| `CustodianPrivacy.sqlite` | Privacy SDK | Data protection policy acceptance log |
| `ChatPlatform.sqlite` | Chat SDK | P2P conversation threads with transaction links |
| `PubSubCoreBullhornDataStore.sqlite` | PubSub SDK | Push notification payload archive (tamper-resistant) |
| `ChimeraCoreResponseStore.sqlite` | Chimera / LiquidUI | Remote UI config + feature flag cache |
| `ExperimentationCoreStore.sqlite` | Experimentation | A/B test variant assignments |
| `ConfigManagerKeyStore.sqlite` | ConfigManager | API endpoints, limits, fraud toggle state |
| `ChimeraCoreResponseStore.sqlite` (LiquidUI path) | LiquidUI | Screen definition cache |
| `Chitragupt.sqlite` | Chitragupt | Full behavioral audit ledger (sub-second) |
| `Chronicle.sqlite` | Chronicle | App timeline + notification history |
| `Dash-Events.sqlite` | Dash | Performance metrics (screen render timestamps) |
| `kn_analytics_db.sqlite` | KN Analytics | Content/merchant interaction log |
| `BGFrameworkDataModel.sqlite` | BGFramework | Background task execution log |
| `CentralSyncManager.sqlite` | Sync | Cross-module sync gap analysis |
| `SamsaraDataStore.sqlite` | Samsara | UPI payment state machine transitions |
| `AthenaStore.sqlite` | Athena | On-device ML recommendation engine |
| `Cassini.sqlite` | Cassini | Document classification (KYC/QR) |
| `MaximusDataModel.sqlite` | Maximus | Promotions and offer engine |
| `NXCoreDataStore.sqlite` | NexusCore | Mini-app catalogue + sitemap |
| `MFDataStore.sqlite` | Mutual Funds | Portfolio holdings + SIP mandates |
| `RewardsDataStore.sqlite` | Rewards | Scratch cards → independent transaction proof |
| `BrandVouchersDataStore.sqlite` | Brand Vouchers | Merchant-specific spending patterns |
| `DonationsDataStore.sqlite` | Donations | NGO/charity payment records |
| `OffersDataStore.sqlite` | Offers | Merchant offer exposure + click timestamps |
| `YatraDataModel.sqlite` | Yatra | Travel bookings + passenger PII + PNR |
| `PrepaidRechargeDataStore.sqlite` | Recharge | Mobile/DTH recharge history + saved numbers |
| `CRMDataModel.sqlite` | CRM | Support ticket transcripts + user-authored dispute text |
| `Pratikriya.sqlite` | Pratikriya | User ratings + free-text feedback linked to transaction IDs |
| `Gravity.sqlite` | Gravity | Feed/discovery ranking state |

### AppDomainGroup-group.com.phonepe.PhonePeApp/

| Database | Forensic Role |
|---|---|
| `P2P.sqlite` | Split-bill groups, expenses, money requests, payment backgrounds |
| `SamparkV2.sqlite` | Financial social graph — phone → UPI ID → name → profile photo |
| `FoxtrotEventsDB.sqlite` | Analytics upload queue (PENDING = exclusively local evidence) |

### AppDomain-com.phonepe.PhonePeApp/Library/

| Artifact | What It Contains |
|---|---|
| `Preferences/com.phonepe.PhonePeApp.plist` | 222 keys — session IDs, BoltV2 token, Chimera flags |
| `Preferences/com.phonepe.widgetxii.datacache.plist` | Primary UPI ID (home page cache) |
| `Preferences/com.phonepe.help.customDataStore.plist` | Registered name + auth tokens |
| `Preferences/com.phonepe.ads.sdk.plist` | GPS coordinates, pincode, state |
| `Preferences/com.phonepe.account.plist` | Token expiry + fetch timestamps |
| `Preferences/com.apple.AdSupport.plist` | IDFA enforcement |
| `Preferences/com.firebase.FIRInstallations.plist` | Firebase install ID |
| `Preferences/__gads__.plist` | Google Ads signals |
| `Cookies/Cookies.binarycookies` | Apple binary cookie format — decoded session cookies |
| `WebKit/ResourceLoadStatistics/` | Website interaction history |

---

## 🧪 The Three Storage Domains

PhonePe iOS sandboxes evidence across three containers with **different trust boundaries**. Missing any one domain means missing evidence.

```
iOS Filesystem
│
├── AppDomain-com.phonepe.PhonePeApp/
│   ├── Documents/          ← Core app databases (Transactions, Auth, Chat...)
│   └── Library/
│       ├── Preferences/    ← 15+ plist files (identity, tokens, location)
│       ├── Cookies/        ← Cookies.binarycookies
│       └── WebKit/         ← ResourceLoadStatistics, offline storage
│
├── AppDomainGroup-group.com.phonepe.PhonePeApp/
│   └── com.phonepe.PhonePeApp/
│       ├── P2P/            ← P2P.sqlite (split bills, money requests)
│       ├── SamparkV2/      ← SamparkV2.sqlite + profile photo BLOBs ⬅ MOST CRITICAL
│       └── FoxtrotEventsStore/  ← FoxtrotEventsDB.sqlite
│
└── AppDomainGroup-group.com.phonepe.shared/
    └── Library/Preferences/    ← Cross-process shared state
```

> ⚠️ **Critical:** Many investigations only include `AppDomain`. Without the group containers, **chat history, contact graph, and recent UPI events are unrecoverable** — they are physically stored in the group sandbox. Always verify all three containers are present before drawing conclusions.

### Acquisition Priority

```
1. Full filesystem (jailbroken / GrayKey / Cellebrite Premium)
   → All three containers + WAL files + free pages + temp files

2. Advanced Logical / AFC2 (jailbroken)
   → AppDomain + AppDomainGroup accessible

3. iTunes Encrypted Backup
   → AppDomain manifest-based; requires backup password

4. iTunes Unencrypted Backup
   → Limited; some fields protected by iOS Data Protection
```

### WAL File Analysis — Never Skip This

```
TransactionsStore.sqlite      ← committed, checkpointed data
TransactionsStore.sqlite-wal  ← recent uncommitted changes ← CRITICAL
TransactionsStore.sqlite-shm  ← shared memory WAL index
```

SQLite in WAL mode writes changes to the `-wal` file first. Deleted records are not immediately removed — they remain in WAL or free pages until SQLite reuses storage. The tool opens all databases in `mode=ro&cache=private` — WAL contents are automatically applied.

> ⚠️ **Never run** `PRAGMA wal_checkpoint(TRUNCATE)` on evidence. It destroys WAL contents and with them any recoverable deleted records.

---

## 🔎 PPQL — PhonePe Query Language

PPQL is a small, deterministic SPL-inspired query language built into the **Hunt** interface. Issue fast filters and aggregations across merged forensic indexes without writing SQL.

### Grammar

```
QUERY    := SOURCE PIPE_OP*
SOURCE   := "search" STRING       -- full-text across the merged index
          | "from" INDEX          -- use a specific index
          | INDEX                 -- alias for "from <index>"
PIPE_OP  := "|" CMD ARG*
CMD      := "where" CONDITION
          | "search" STRING       -- second-stage full-text filter
          | "sort"  FIELD ["asc"|"desc"]
          | "head" N | "tail" N | "limit" N
          | "table" FIELD ("," FIELD)*
          | "top" N FIELD
          | "rare" N FIELD
          | "stats" AGG ("by" FIELD)?
          | "dedup" FIELD
          | "rename" FIELD "as" FIELD
AGG      := "count" | "sum(" FIELD ")" | "avg(" FIELD ")"
          | "min(" FIELD ")" | "max(" FIELD ")"
```

### Available Indexes

| Index | Description |
|---|---|
| `transactions` | Master ledger — `ZTRANSACTIONENTITY` |
| `contacts` | PhonePe-verified Cyclops contacts |
| `phonebook` | Raw device address book |
| `chat_groups` | Burble group containers |
| `chat_messages` | Individual chat messages |
| `notifications` | PubSub push topic archive |
| `timeline` | Unified chronological event stream |

### Example Queries

**Find all outgoing transactions over ₹5,000 and sort by amount:**
```
transactions
  | where direction = "OUT" and amount_inr > 5000
  | sort amount_inr desc
  | head 50
  | table created_at, counterparty, amount_inr, utr
```

**Reconstruct a specific phone number's payment history:**
```
transactions
  | where counterparty_phone = "9876543210"
  | stats count by state
```

**Find all senders in chat who match a partial masked number:**
```
chat_messages
  | where sender_phone_masked like "*6259"
  | stats count by sender_name
```

**Top 10 regions of PhonePe contacts:**
```
contacts
  | where on_phonepe = true
  | top 10 region
```

**Regex match — find transactions to merchants containing "Bharath":**
```
transactions
  | where counterparty matches "[Bb]harath.*"
  | stats sum(amount_inr) by counterparty
```

**Timeline after a specific date from Burble:**
```
timeline
  | where source = "Burble" and when_iso > "2025-01-01"
  | head 200
```

**Full-text search across all indexes:**
```
search "UTR401234567890"
search "UTR" | where amount_inr > 1000
```

**Find failed transactions in a date range:**
```
transactions
  | where state = "FAILED"
  | where created_at_iso > "2024-01-01" and created_at_iso < "2024-12-31"
  | sort created_at_iso desc
  | table created_at_iso, counterparty, amount_inr, response_code
```

---

## 🕸️ Cross-Database Correlation Engine

`correlator.py` fuses evidence from all 16 modules into investigation-grade artifacts.

### `build_unified_timeline`

Merges every timestamped event across every module into one chronological stream. Sources fused:

```
TransactionsStore    → UPI transaction events
Burble               → Chat messages + payment cards
PubSubCore           → Push notification arrivals
Foxtrot              → Analytics batch uploads
Chitragupt           → UI behavioral events (taps, keyboard, screen views)
Chronicle            → App timeline + notification history
Samsara              → UPI state machine transitions
Yatra                → Travel booking timestamps
Analytics            → KN content interactions
Recommendations      → ML signal timestamps
```

Each event carries: `{ when_ms, when_iso, source, kind, title, detail, link_id?, amount_inr? }`

### `build_social_graph`

Builds a counterparty-centric social graph by fusing:
- Contacts (`SamparkV2`) — who is in the phonebook + UPI IDs
- Transactions (`TransactionsStore`) — who money moved to/from
- Chat (`Burble`) — who messages were exchanged with

Output: per-counterparty summary with transaction count, total amount, chat message count, shared groups, and last interaction timestamp.

### `build_counterparty_profile`

Given any identifier (phone, VPA, or name), produces a comprehensive dossier:
- All transactions (in + out)
- All chat interactions
- Contact record details
- Financial relationship metrics
- Timeline of interactions

### `build_corroboration_index`

For each transaction ID, maps every database that references it:

```
Transaction T241119182327:
  ✓ TransactionsStore    → ZTRANSACTIONENTITY row
  ✓ RewardsStore         → ZSCRATCH_CARD with ZLINKED_TXN_ID
  ✓ PubSubCore           → Push notification payload
  ✓ Chronicle            → Timeline item (even if TransactionsStore row deleted)
  ✓ Burble               → Chat PAYMENT_INFO_CARD

Corroboration Score: 5/5 — cannot be disputed as non-existent
```

A score of 1 with the single source being outside `TransactionsStore` is a **red flag** — it means a transaction ID exists in satellite evidence but the master ledger row is missing (possible deletion).

---

## ⏱️ Unified Timeline & Suspicious Signal Detection

### Heuristic Signal Categories

The `detect_suspicious_signals` function produces investigator flags:

| Signal | Severity | Trigger |
|---|---|---|
| **High deletion intensity** | 🔴 High | `freelist_count / page_count > 0.20` in transactions/contacts/chat DB |
| **Failed/pending transactions** | 🟡 Medium | Any `FAILED`, `PENDING`, or `REJECTED` transactions |
| **High-value transactions** | 🔵 Info | Any success transaction ≥ ₹50,000 |
| **Analytics upload failures** | 🔵 Info | Foxtrot events with ≥ 3 failed upload retries |
| **Uncorroborated transaction IDs** | 🟡 Medium | TXN IDs visible in satellite DBs but absent from `TransactionsStore` |
| **Wallet balance present** | 🔵 Info | eGV wallet balance > 0 (relevant to investigation scope) |

### Deletion Intensity Analysis

```sql
-- Quick deletion check on any database
PRAGMA freelist_count;   -- Pages on freelist (deleted rows)
PRAGMA page_count;       -- Total pages

-- > 20% = active deletion — flag in report
```

The tool automatically runs this check and flags databases where deletion intensity suggests evidence tampering.

---

## 🧩 Timestamp Semantics — The Three Epochs

The most common error in published PhonePe forensic write-ups. PhonePe iOS uses three timestamp formats interchangeably.

| Value Range | Epoch | Example | Conversion |
|---|---|---|---|
| `~400M – 950M` | **Apple CoreData** (+ 978,307,200) | `721,692,800` → Nov 14, 2023 | `ts + 978307200` |
| `~1.4B – 1.8B` | **Unix seconds** | `1,700,000,000` → Nov 14, 2023 | Direct |
| `~1.4T – 1.8T` | **Unix milliseconds** (÷ 1000) | `1,700,000,000,000` → Nov 14, 2023 | `ts / 1000` |

The tool's `normalize_timestamp()` function **auto-detects the epoch** by value range:

```python
def normalize_timestamp(value: Any) -> Optional[Dict[str, Any]]:
    v = float(value)
    if v > 1e12:          # Unix milliseconds
        epoch_s = v / 1000.0
    elif v > 1e9:         # Unix seconds
        epoch_s = v
    elif NSDATE_REASONABLE_MIN < v < NSDATE_REASONABLE_MAX:
        epoch_s = v + APPLE_EPOCH_OFFSET   # CoreData
    # Returns { epoch_ms, iso, display, source }
```

Every extracted timestamp is returned as `{ epoch_ms, iso, display, source }` — the `source` field tells you which epoch was detected, so you can audit the conversion.

> ⚠️ A single miscategorized epoch shifts every date in the case by **31 years**. Always verify the epoch before reporting dates.

---

## 📤 Export Formats

All exports are available from the **Exports** page or per-view download buttons.

### CSV Exports (per evidence type)

| File | Contents |
|---|---|
| `transactions.csv` | Full ledger — all decoded fields including counterparty, UTR, amount |
| `contacts_phonepe.csv` | Cyclops contacts with UPI IDs |
| `contacts_phonebook.csv` | Raw device phonebook |
| `chat_groups.csv` | Burble group metadata |
| `chat_messages.csv` | All messages with linked transaction IDs |
| `chat_shared_contacts.csv` | Bank account disclosures shared in chat |
| `linked_accounts.csv` | All bank accounts ever linked |
| `linked_cards.csv` | All payment cards |
| `timeline.csv` | Full unified timeline |
| `findings.csv` | Suspicious signal flags |
| `social_graph.csv` | Contact ↔ transaction relationship map |

### JSON Export

Structured master JSON of the complete case — all modules, all correlation outputs, all metadata — suitable for integration with other DFIR tooling.

### HTML Report

Self-contained, single-file HTML evidence report with **no external dependencies** — fully renderable offline. Suitable for court submission or sharing with legal teams.

---

## 🔬 Research Reference

The **Research** tab inside the tool contains built-in reference documentation for every artifact — no internet required:

```
1. Architecture Overview        → Storage domains, acquisition hierarchy, SDK map
2. Core Financial DBs           → TransactionsStore, PaymentDataStore, P2P
3. Identity & Auth DBs          → AccountSharedDataModel, AuthDataModel
4. Social Graph                 → SamparkV2 schema, profile photo recovery
5. Chat & Notifications         → ChatPlatform, PubSubCore
6. Behavioral Analytics         → Chitragupt, Foxtrot, Dash, Chronicle
7. Server Config & A/B Testing  → Chimera, ExperimentationCore, ConfigManager
8. Financial Services           → MF, Rewards, Vouchers, Donations, Offers
9. Travel & Recharge            → Yatra, PrepaidRecharge
10. Infrastructure              → BGFramework, CentralSyncManager, Samsara
11. Specialty DBs               → Pratikriya, CRM, Gravity, Cassini
12. Plist Files                 → All 15+ plists with field-level documentation
13. WebKit & Cookies            → Binary cookie format, ResourceLoadStatistics
14. Timestamp Reference         → Three epochs, conversion formulas, detection guide
15. Corroboration Framework     → Cross-DB evidence matrix
16. Query Arsenal               → 30+ ready-to-run PPQL queries
```

---

## 🗂️ Project Structure

```
phonepe-ios-forensics/
│
├── run.py                          ← Entry point
│
├── phonepe_forensics/
│   ├── __init__.py                 ← Package init, version
│   ├── core.py                     ← Parsing primitives
│   ├── extractors.py               ← 16 extraction modules (~2,200 lines)
│   ├── correlator.py               ← Correlation engine
│   ├── hunt.py                     ← PPQL parser & executor
│   ├── case.py                     ← Case orchestrator
│   ├── case_manager.py             ← Multi-case registry
│   ├── reports.py                  ← Report exporter
│   ├── research_data.py            ← Built-in reference docs
│   ├── webapp.py                   ← Flask web UI (35+ routes)
│   │
│   ├── templates/
│   │   ├── base.html               ← Navigation + layout
│   │   ├── dashboard.html
│   │   ├── transactions.html       ← Filterable ledger
│   │   ├── transaction_detail.html
│   │   ├── contacts.html
│   │   ├── social_graph.html
│   │   ├── chat.html
│   │   ├── chat_group.html
│   │   ├── identity.html
│   │   ├── analytics.html
│   │   ├── financial.html
│   │   ├── travel.html
│   │   ├── payment_infra.html
│   │   ├── audit.html
│   │   ├── timeline.html
│   │   ├── hunt.html               ← PPQL query interface
│   │   ├── counterparty.html       ← Per-counterparty dossier
│   │   ├── database_browser.html   ← Raw SQL interface
│   │   ├── database_sql.html
│   │   ├── findings.html
│   │   ├── research.html           ← Built-in docs index
│   │   ├── research_section.html
│   │   ├── exports.html
│   │   ├── cases_list.html
│   │   ├── case_new.html
│   │   ├── case_detail.html
│   │   └── ...
│   │
│   └── static/
│       ├── css/app.css
│       └── js/app.js
│
├── .pp_forensics/                  ← Auto-created — case registry
│   └── cases.json
│
└── exports/                        ← Auto-created — export output
    └── <case_name>/
        ├── transactions.csv
        ├── contacts_phonepe.csv
        ├── timeline.csv
        ├── master.json
        └── report.html
```

---

## 🤝 Contributing

Contributions are warmly welcomed. PhonePe's app is actively developed — new databases and schema changes appear with each app update.

### Priority Areas

- 🆕 **New SDK parsers** — new databases added in recent PhonePe versions
- 🐛 **Schema corrections** — if you've found a real schema difference from your extraction
- 🔎 **PPQL extensions** — new operators, aggregations, index definitions
- 📊 **Correlation heuristics** — new suspicious signal categories
- 🌐 **Export formats** — JSONL, XLSX, court-ready PDF templates

### Development Setup

```bash
git clone https://github.com/thelocalh0st/phonepe-ios-forensics.git
cd phonepe-ios-forensics

python -m venv venv && source venv/bin/activate
pip install flask

# Run with auto-reload for development
FLASK_DEBUG=1 python run.py
```

### Submission Guidelines

1. **Fork** → feature branch → PR against `main`
2. New parsers go in `extractors.py` following the existing `extract_*` pattern
3. All parsers must handle `None`, empty tables, and partial corruption without raising exceptions
4. Include the specific SQLite path and table/column names for any new artifact
5. If correcting a schema error, cite the real column name and how you verified it

---

## ⚖️ Legal & Ethics

This tool is intended exclusively for:

- ✅ **Law enforcement** — criminal investigations with appropriate legal authority
- ✅ **Licensed digital forensic examiners** — working under professional mandate
- ✅ **Cybercrime investigators** — authorized UPI fraud case analysis
- ✅ **Legal/compliance professionals** — internal investigation with device owner consent
- ✅ **Security researchers** — academic/responsible disclosure contexts
- ✅ **Device owners** — analyzing your own device's data

**Always ensure you have legal authorization before examining any device.** Unauthorized access to a person's device data may violate the Computer Fraud and Abuse Act (CFAA), the IT Act 2000 (India), and equivalent legislation in your jurisdiction.

This tool is a **read-only forensic viewer**. It never writes to, modifies, or deletes any file in the evidence folder.

---

## 📚 References & Further Reading

| Resource | Link |
|---|---|
| 📝 Original Research Blog Post | [PhonePe Forensics in iOS — thelocalh0st.com](https://thelocalh0st.com/posts/phonepe-forensics/) |
| 📖 Apple Core Data SQLite Internals | [Apple Developer Documentation](https://developer.apple.com/documentation/coredata) |
| 🗃️ SQLite WAL Mode | [SQLite WAL Documentation](https://www.sqlite.org/wal.html) |
| 🍎 iOS App Sandbox Domains | [iOS Security Guide — Apple](https://support.apple.com/guide/security/welcome/web) |
| 💳 NPCI UPI Technical Specs | [NPCI — Unified Payments Interface](https://www.npci.org.in/what-we-do/upi/product-overview) |
| 🔑 NSKeyedArchiver Format | [Apple plist Format Reference](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/PropertyLists/Introduction/Introduction.html) |
| 🍪 Binary Cookie Format | [Satishb3 — Safari Binary Cookie Reader](http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/) |
| 📱 iOS DFIR Fundamentals | [SANS FOR585 — Smartphone Forensic Analysis](https://www.sans.org/cyber-security-courses/advanced-smartphone-mobile-device-forensics/) |



<div align="center">

### ⭐ If this tool helped your investigation, please star the repository

*Every star helps more forensic examiners discover this tool.*

---


<img src="https://img.shields.io/badge/Made%20for-Digital%20Forensics-red?style=for-the-badge&logo=target" />
<img src="https://img.shields.io/badge/Built%20with-Python%20%2B%20Flask-blue?style=for-the-badge&logo=python" />
<img src="https://img.shields.io/badge/Evidence-Tamper%20Proof%20Reads-green?style=for-the-badge&logo=shield" />

</div>
