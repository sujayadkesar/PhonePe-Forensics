# STATE — PhonePe Android Forensics

Master journal. Single source of truth. Read this first when resuming, then
`CONTINUE.md` for the next concrete action, then the latest file in
`notes/sessions/`.

Absolute dates throughout. All tool-emitted timestamps are UTC by design.

---

## 1. What this project is

A local, read-only DFIR web tool (Flask, `python run.py 127.0.0.1:8754`) that parses a
**PhonePe Android** acquisition — the `com.phonepe.app` app-data directory from a rooted /
full-filesystem extraction — and presents transactions, chat, contacts, the split ledger,
identity + device fingerprint, a unified timeline, social graph, suspicious-signal findings,
carved deleted records, and a raw layer (every table, every shared_pref, a SQL console), with
per-field provenance.

Vendored from upstream `github.com/sujayadkesar/PhonePe-Forensics` at commit `007473a` and
reduced to an Android-only distribution. **Fixes made upstream after that commit are NOT
here** — the parser and engine were copied, not submoduled. The README states the intent to
merge this Android build back into the upstream repo so one tool handles both platforms.

Only runtime dependency: `Flask>=2.2`. Verified working on Python 3.14.4 / Flask 3.1.3.

## 2. Architecture — how data actually flows

```
com.phonepe.app/  ──►  AndroidCasePaths          resolve databases/ shared_prefs/ files/ app_webview/
                       (core/android.py)         valid ⇔ databases/phonepe_core exists

                  ──►  23 extract_*(paths)       phonepe_android/extractors_android.py
                       (EXTRACTORS list in       each returns a NORMALIZED dict, keyed into
                        case_android.py)         case.data[<module>]; failures land in
                                                 case.data[m]["error"] / ["errors"], never raise

                  ──►  case.data                 the platform-agnostic "contract".
                                                 EVERYTHING downstream reads only this.

                  ──►  correlator.py             timeline · social graph · corroboration index ·
                                                 suspicious signals · counterparty profile
                       carver.py                 deleted-record recovery (its own extractor)
                       hunt.py                   PPQL indexes + query engine
                       reports.py                CSV / master JSON / self-contained HTML + custody

                  ──►  webapp.py (76 rules)      Flask views + CSV exports, one active case
                       case_manager.py           JSON registry at ./.pp_forensics/cases.json,
                                                 LRU of 3 loaded cases
```

**Why the split matters:** `phonepe_forensics/` is the platform-agnostic engine (shared with
upstream iOS); `phonepe_android/` is the only Android-shaped code. `Case` (base) raises if a
subclass doesn't set `PATHS_CLASS` — deliberately, so "generic" code can't quietly be
Apple-shaped. `phonepe_forensics/core/__init__.py` re-exports common+ios+android, so
`from phonepe_forensics.core import X` works regardless of which module X lives in.
`phonepe_android/core_android.py` is a pure re-export shim for backward-compatible imports.

### Android-only pieces (not in the shared engine)
- `AndroidCase.timeline()` extends the shared timeline with SMS + ledger events.
- `AndroidCase.sms_corroboration()` — bank-SMS ↔ transaction matching.
- `AndroidCase._android_findings()` — rooted device, carved deletions, encrypted DBs, SMS corroboration.
- Android deliberately does **not** call `_tag_chat_self_direction()`: chat direction comes
  from per-topic `ownMemberId`, which is more reliable than matching display names.

## 3. Forensic guarantees to preserve (the reason the code looks the way it does)

These are load-bearing. Do not "simplify" them away.

- **Read-only.** No WAL/journal ⇒ open in place with `immutable=1` (cannot create a `-shm`).
  WAL/journal present ⇒ copy DB + sidecars to a scratch dir and recover *there*; connection
  set `query_only` after the schema read. If staging fails, open immutable and raise a
  dashboard/audit/report warning that WAL content is **excluded**. Scratch dir is removed at exit.
- **Hash before parse.** SHA-256 of every DB and sidecar, cached per (path,size,mtime), scoped
  to the case root so a second case's manifest can't inherit the first's files.
- **Schema drift degrades, never blanks.** `_prune_absent_columns` intersects a hard-coded
  simple `SELECT a,b,c FROM t` against the real schema, records the gap (Audit page), and
  returns absent columns as `None`. *Limitation:* queries with aggregates/expressions bypass
  this and surface as `_error` rows instead (e.g. notifications' `COUNT(*)`).
- **UTC everywhere,** stated explicitly (`iso` has `+00:00`, `display` is suffixed `UTC`).
  Out-of-range (pre-1973 / post-2100) values are rejected, not rendered.
- **Txn-ID embedded clock is labelled unvalidated** — the issuing server's timezone is
  undocumented, so it is never treated as independent corroboration.
- **Masked→real recovery is exact-match only** (connection_id / member_id / last-10 phone /
  VPA), each recovered name labelled by origin ("saved in PhonePe" vs "phonebook"), and a
  last-10 phone mapping to >1 distinct *connection* is left unresolved rather than guessed.
- **Social graph attributes chat by connection id, never display name** (two people can share
  a name). Unresolvable threads are counted against the thread and flagged, not guessed.
- **SMS corroboration:** exact paise, ±30 min, one-to-one, nearest-in-time-first — so the
  confirmed/uncorroborated counts don't depend on row order. Rupee→paise via `Decimal`.
- **Carving honesty:** a record fitting several tables is reported against all and flagged
  ambiguous; rows still live are excluded; partial rows (freeblock header ate the first serial
  type) are flagged `partial` with `confidence: medium`; `high` only when the extent was
  confirmed structurally. Empty result is explicitly **not** proof nothing was deleted, and
  survival is reported empirically, not from `PRAGMA secure_delete` (per-connection — it would
  describe the examining machine).
- **Web hardening:** cross-origin state changes rejected; per-process random secret; SQL
  console restricted to this case's DBs and to SELECT/PRAGMA/EXPLAIN/WITH, single statement;
  `/api/file` confined to case roots via `commonpath` (not `startswith`); CSV formula-injection
  neutralised; `Content-Disposition` filenames sanitised; 500s log detail but show a generic page.

## 4. Known limitations (by design, recorded so they aren't re-investigated)

- Three DBs are SQLiteCrypt-encrypted (`AccountAggregatorDatabase`, `mdb`, a UUID-named DB).
  The AES key is not on disk: passphrase in `shared_prefs/common-encrypted-shared-pref.xml`
  (AndroidX EncryptedSharedPreferences) → Tink keyset → **Android Keystore master key in the
  TEE/StrongBox**. A static image cannot decrypt them. Recorded as present-but-unreadable.
- `extract_raw_tables` captures shape only (row counts + columns); bodies load on demand via
  `load_raw_table` (name-validated against the real inventory, so no path/table injection).
- Carving targets a fixed table list (`_CARVE_TARGETS`) — `phonepe_core` (11 tables) and
  `inference_data_provider.sms_buffer` — to keep the scan proportionate and interpretable.
- `files/` documents over 8 MB are indexed but not parsed (`_MAX_PARSE_BYTES`), reported.

## 5. Stale docs in the tree — do not trust these strings

- `extractors_android.py`'s header used to say "SCAFFOLD STATUS … everything else — TODO".
  **Corrected on 2026-07-30**: all 23 extractors registered in `AndroidCase.EXTRACTORS` are
  implemented and have been run against a real acquisition. The header now also carries the
  `has_table` coverage caveat.
- Docstrings reference `phonepe-android-port/CONTRACT.md`, `ANDROID-FINDINGS.md` and a
  `CONTINUE.md` "next session" note. The first two **do not exist in this repo**; `CONTINUE.md`
  now exists but is this project's resume pointer, not the file those comments meant.
- `provenance_android.py` cites `phonepe_forensics/core.py`; that module is now the
  `core/` package (`common.py` / `ios.py` / `android.py`).

## 6. Evidence under test (2026-07-30)

> **Rule for this file and `CONTINUE.md`: both are tracked by git, so neither may carry the
> subject's data.** No real amounts, totals, names, phone numbers, VPAs or account numbers, and
> not the acquisition's absolute path (it names the examiner's account). Findings are recorded
> here by their *shape* — "a four-figure sum was mis-signed", "all four money totals unchanged"
> — because the shape is what a future session needs. Exact figures live in
> `notes/sessions/`, which is gitignored for this reason. An earlier revision of this file did
> paste real totals; they were removed on 2026-07-30. Reproducible regression numbers belong to
> the **synthetic** fixture (`notes/make_demo_acquisition.py`), which is safe to quote freely.

Real acquisition supplied by the user, at a local path recorded only in the gitignored session
log (referred to below as `$ACQ`):

```
$ACQ/  →  .../files/data/data/com.phonepe.app/
```

59 MB · 396 files · 45 files in `databases/` · 180 `shared_prefs/*.xml` · 109 under `files/` ·
41 under `app_webview/`. `phonepe_core` 9.5 MB with an 86 KB `-wal` (so the WAL-copy path is
exercised, not just `immutable`). Also present: BullhornDatabase 12.3 MB, chimeraDB 10.5 MB,
search.db 2.2 MB, AthenaDatabase, accounts_db, ads_db, MaximusDatabase, consent,
inference_data_provider, kn_generic.db, and the three encrypted DBs.
**`RecommendationsDatabase` is absent** ⇒ `extract_recommendations` will report not-found; that
is an absent source, not a defect.

Pre-parse hash manifest of all 396 files: `<scratch>/before.sha256` (used to prove the tool
left the evidence byte-identical — re-hash and diff after any run).

### First real-evidence run — 2026-07-30 (details: `notes/sessions/2026-07-30.md`)

Healthy: **0 schema gaps** (every hard-coded SELECT matches this acquisition's Room schema),
8/8 derived views OK, 74/74 routes serve, export set complete, and all 396 evidence files
**verified byte-identical** afterwards. All 14 opened DBs had a `-wal`, so the
copy-to-scratch WAL path was exercised throughout, with no WAL-exclusion warnings.
Extraction 54.3 s, of which 53.9 s is carving — every other module is ≤ 0.08 s.

Strongest result: the carver recovered a **deleted `transaction_core` row** (high confidence,
from a freeblock) for a payment that only a chat card still referenced — the carver and the
corroboration index corroborate each other on real data.

### Issues found and fixed — 2026-07-30 (all ten, A–J; details in the session log)

| # | Issue | Fix |
|---|---|---|
| A | `ERRORED` — the state Android writes for a failed payment — was absent from the failed set, so 13 failed payments raised no finding. The success test was also case-sensitive in the correlator but not in the extractor. | One `SUCCESS_STATES` / `FAILED_STATES` / `PENDING_STATES` vocabulary in `correlator.py`, used by both, case-insensitive. Plus a new `unrecognised_transaction_state` finding so an unknown state can never again be silently neither-summed-nor-flagged. |
| B | PPQL `sort <field> desc` put NULLs first, so `sort amount_inr desc \| head 5` returned five rows with no amount. | `_sort_key` takes the sort direction and ranks nulls last either way. |
| C | The uncorroborated-payments finding implied deletion when the real cause is the ledger's local retention window. | Splits by the live ledger's date range and reports both; severity drops to `info` when every case predates retention. Chat cards now date their entries, which is what makes the question answerable. |
| D | Carved rows were graded `confidence: high` on extent alone, while a boolean column held `84521`. | Extent- and value-confidence are now separate. Value plausibility is learned from the live table's own enum/boolean domains, so a shifted field is flagged `values: low` with the offending columns named. Surfaced in UI, CSV and HTML report. |
| E | `messageDataStore` (5,706 rows) was claimed by the provenance page but never queried; `voucher_products` likewise. | Both are now read. 977 delivered notifications decoded (base64→JSON) with title/subtitle/deeplink/timestamps, added to the timeline, a new PPQL index, a CSV exhibit and the notifications page. Provenance corrected to match. |
| F | The corroboration index treated split-expense ids as payments, so 24 non-payments were reported as missing from the ledger. | Entries carry `ref_kinds`; only payment-bearing references expect a ledger row. Id shape cannot decide this (`E…` is an expense id in one card type and a transaction entity id in another), so the kind is recorded where it is known. |
| G | `dashboard()` called `evidence_warnings()` unscoped, so another open case's integrity warnings appeared on this case's dashboard. | Scoped to the case root. |
| H | `CaseManager._remember` abandoned eviction on the first protected entry, so the cache grew unbounded (7 full acquisitions resident with a 3-case limit). | Skips protected entries and keeps scanning. |
| I | Smaller: `safe_int(True)` made a boolean read as ₹0.01; `dismissed` defaulted to True when the column was absent; `_prune_absent_columns` recorded no schema gap when *every* column was missing; contact counts double-counted one person across three source tables. | All fixed; contacts report distinct people in the headline pair with the row counts kept under explicit `*_source_rows` names, so "N on PhonePe of M contacts" no longer compares people against source records. |
| J | Regression **caused by fix E**: decoding notifications took the timeline past `/timeline`'s default cap, and the page read its total off the already-capped list — so it showed a subset while labelling it the total. | The true total is computed from the uncapped timeline; the page now says "showing the most recent N of M" and the default cap was raised. |

The state vocabulary was also moved from `correlator.py` down into `core/common.py`. The parser
needs it too, and importing the correlator into the parser inverted the
parser → `case.data` → correlator direction that keeps upstream merges clean.

### Audit pass 3 — data fidelity (displayed vs stored)

Ground truth used: **PhonePe's own `transaction_aggregate_entity`** table records
`aggregate_type` (received/spent) and `amount` per transaction id — the app's own answer to the
two things this tool is most likely to get wrong. Reuse it on every acquisition.

Verified correct: all 10 module row counts exactly match `COUNT(*)`; money recomputed
independently from raw `tstore_data` matches to the paise; **0 field mismatches** across 233
chat messages, 192 SMS, 75 ledger expenses; payment infra and identity exact; **51/51 amounts**
match the app's own ledger.

Five defects found (X–AB, session log). The serious one: **`PIEDPIPER_PAYMENT` direction was
backwards on 4 of 8 rows** — the static default's own comment said "refine when sampled", and
the app's ledger recorded those as *received*. Direction now comes from `tstore.actor`. Effect:
**a four-figure rupee sum had been reported as sent when the app recorded it as received**, so
the net-flow error was twice that. The received total rose and the sent total fell by the same
amount. (Exact figures are in the gitignored session log, not here — see the note at the top of
§7.) On those same rows the **subject's own phone
number was shown as the counterparty's**, and real counterparty names (`accountHolderName` in
`paymentPayerParty`/`paymentReceiver`) were being discarded in favour of bare digits. Also:
`on_phonepe` was *asserted* for VPA/profile rows whose tables have no such column (count
151 → 143), and the source's own self-contradictions (103 people stored twice, 11 with
disagreeing flags) are now reported instead of silently shown as duplicate rows with opposite
answers. Coverage: `nonContact` (50 rows, incl. 6 numbers the subject searched for) now read,
and `ledger_my_split` — extracted but rendered nowhere — now reaches a page.

### Audit pass 4b — dead panels: eight template blocks that could never render (AF–AM)

Fixing the four payment-infra contract keys let the StrictUndefined lens see **past** them —
each raise had been aborting the render before the next undefined key was reached. Iterating
until the list stopped changing turned up eight template references that no code sets, i.e.
panels and tags that could not appear no matter what the evidence held. Route 500s under the
lens: **11 → 6**, and `/audit`, `/identity`, `/payment-infra`, `/transactions` are now clean.

Wired to a real source (the table existed; nothing read it):

- **AF — `approvers_recent`** ← `phonepe_core.approvers_table`. UPI mandate / family-account
  approvers: another person authorised to approve this account's payments — an association
  between two people, which is squarely evidential. 0 rows here, so nothing changes on this
  exhibit; the difference is that it is now empty *because the evidence is empty*.
- **AG — `cassini_models`** ← `phonepe_core.model_data` (on-device ML models). 0 rows here. The
  panel's "Checksum" column had no source column at all and was replaced with version and
  on-device path, which the table does have.
- **AH — `is_qr_scan` / `is_intent`** ← `tstore.context.initiationMode`. The transactions table
  has always had QR and INTENT tags and nothing set the keys. **7 INTENT and 1 QR_SCAN** now
  show. `initiation_mode` and the raw `upi_initiation_mode` NPCI code are exported and
  PPQL-indexed. The code is deliberately **not** mapped: on this device INTENT↔`04` (7/7) and
  QR_SCAN↔`01` (1/1) correspond exactly, but that is one device's behaviour, not a code table.
  Unknown stays `None` — 73 rows state no mode and calling those "not a QR scan" would claim
  more than the record says.
- **AI — `consent.sync_state`** — `phonepe_core.consent` *has* a `consentSyncState` column that
  the SELECT simply omitted, so it read empty for those 21 rows while the standalone database's
  17 rows filled it. Now 38/38 populated, and the two consent sources produce one identical
  record shape (a key present on some records and absent on others makes the same cell mean
  "empty" for one row and "field does not exist" for the next).

Removed rather than implemented, because no Android source exists and inventing one would
fabricate a claim:

- **AJ — "Consent Subject" card** (`consent_user`: user id / phone / device fingerprint),
  present **twice** — `/audit` and `/identity`. The consent database's only subject field is
  `subjectRefId`, already shown and exported as "Subject ref".
- **AK — "Consent Definitions" table** (`consent_definitions`). The consent database holds
  exactly one table; each row's `consentDefinition` already rides on the consent record.
- **AL — counterparty "payment app" line** (`receiver_app`/`sender_app`). Naming the app means
  mapping the VPA handle to a PSP, and that table is both incomplete and easy to get wrong
  (`@ybl` is PhonePe-via-Yes-Bank, `@okaxis` is Google-Pay-via-Axis) — a wrong app name would
  be a fabricated claim about which app the counterparty used. The VPA is displayed directly
  above it; the inference is the examiner's to make.
- **AM — "Chat-only" tag** (`data_source == 'burble_only'`) and **"REFUND" tag** (`is_refund`).
  Neither has a producer anywhere, and chat-only cannot apply by construction: the table lists
  `transaction_core` rows, so a payment known only from a chat card is not in it (those are the
  `uncorroborated_transactions` finding). No refund marker exists anywhere in the payloads. An
  absent tag reads as "no refunds" / "no chat-only payments", which the page cannot know.

While removing the chat-only tag I narrowed its enclosing guard to `t.classification` alone,
which would have hidden the QR/INTENT tags on rows carrying no classification. Caught by
checking rather than reading: 0 rows on this acquisition are affected, but the guard now lists
every tag inside it.

**Money is untouched by all of pass 4** — transaction count and all four money totals are
identical to pass-3 end, verified by diffing the two runs' `--json` output. The only count that
moved in the whole pass is the new `approver_count: 0`.

### Audit pass 4 — review follow-up: unsupported claims, both polarities (AC–AE)

Pass 3 fixed a hardcoded "on PhonePe: Yes" tile. This pass hunted the *same defect class
elsewhere*, including the version that asserts a negative — which is easier to miss because a
"No" looks like a measurement.

- **AC — `yes_no` turned absent into "No".** The filter was `"Yes" if value else "No"`, so any
  missing column or JSON key reaching one of the 41 template sites rendered as a positive claim
  that the thing is false. Now renders `—` for `None`/`Undefined`. It also mis-read stringified
  booleans (every non-empty string is truthy, so `"false"` → **Yes**); `"true"/"false"/"1"/"0"`
  are now parsed. No live case on this acquisition — every field reaching `yes_no` here is a
  real `bool`, and the eight absent keys are all `{% if %}`-guarded — so this is a correctness
  fix for future acquisitions, not a change to the current exhibit.
- **AD — chat-derived graph nodes hardcoded `on_phonepe: True`.** Defensible as an inference
  (you cannot be in a PhonePe chat otherwise) but it was presented as stored fact — and the
  evidence states it directly in `topicMember.onPhonePe`, already extracted as `phonepe_user`.
  Now read from the member record; the one `CHAT_THREAD_ONLY` bucket, which has no member row to
  speak for it, is `None`. The 12 resolvable nodes are still `True` — the inference was right,
  it is just sourced now.
- **AE — phonebook-only nodes hardcoded `on_phonepe: False`.** Absence of a matching PhonePe
  contact record is not evidence the person has no PhonePe account. `kind: PHONEBOOK_ONLY`
  already carries "no PhonePe record found" without over-claiming; the field is now `None`.
- **AC2 — `bool(row.get(flag))` erased "unknown" upstream of every fix above.** Both
  `on_phonepe` and `phonepe_user` were coerced with `bool()`, which collapses a NULL column, an
  absent JSON key and a stored `0` into False — so AD's new "only read it if the record states
  it" guard could never be false, and a manufactured False would flow into the graph node
  regardless. New `core.tri_bool()` keeps the three states distinct (and parses stringified
  booleans, since a non-empty `"false"` is truthy). No live case here — `topicMember.onPhonePe`
  has **0 NULLs** and the single stored `0` is a real VPA-type member — but the guard the fix
  depends on was structurally unreachable until this.
- **AC3 — the social graph and `/contacts` disagreed about the same people.** The node builder's
  gap-fill loop covers `name`/`vpa`/`connection_id`/`upi_state` but never `on_phonepe`, so the
  graph was first-row-wins while the contacts page states — in words, on the page — that it is
  any-row-wins. For the **3 people** whose duplicate rows contradict each other, `/contacts`
  counted them on PhonePe while the graph said they were not. Now both read 143. `on_phonepe`
  cannot ride the gap-fill loop at all: `False` is falsy, so `not node.get(key)` treats a stored
  False as "no value yet".

Also verified in this pass, having skipped it during pass 3 (my own rule, in `CONTINUE.md`
technique 4): **module-count diff run10 → run13** moved only `transactions` (the intended money
corrections), `contacts` (151 → 143 on-PhonePe plus the new non-contact/conflict counts),
`social_graph` (212 → 211 nodes) and `hunt_indexes` (+1). Nothing unexplained. And the pass-3
counterparty-leg change, though written for `PIEDPIPER_PAYMENT`, runs for every transaction — a
`Counter` over `(type, keys_present)` proved `paymentPayerParty`/`paymentReceiver` exist on
**only** those 8 rows, so `EXPENSE_SETTLEMENT`/`RECEIVED_PAYMENT`/`SENT_PAYMENT` never enter the
new branch. Blast radius confirmed empirically rather than argued.

### Audit pass 2 — eight more issues (K–R), all fixed

Found by two techniques worth reusing: rendering every page with Jinja's `StrictUndefined`
(turns a silently blank cell into a raised error — 12 references, 3 real defects), and listing
every SQLite file in the acquisition that **no extractor opens**, then looking inside.

| # | Issue | Fix |
|---|---|---|
| K | PhonePe renamed `RecommendationsDatabase` → **`MaximusDatabase`**. Only the old name was tried, so the tool reported the source *absent* while the acquisition held 23 products, 57 recommendation items and 17 timestamped signals. | Both names tried; `summary.database` records which was used. This is the failure mode to watch for generally: a hard-coded database name plus a confident "not found". |
| L | **`accounts_db` had no extractor** — it holds the signed-in account's id, e-mail, verified flags and an **unmasked full phone** beside a masked `user_name`. | Read into `identity.accounts` with a new Identity panel. |
| M | The Crashlytics hashed telemetry `userId` and the real account `user_id` collided on one `device_identifiers` key, so one silently overwrote the other. | Separate keys. |
| N | The **standalone `consent` database** was never read (only `phonepe_core.consent`). | Merged in with a per-record `source`; consents 21 → 38, including GPS/SMS/credit-bureau grants. |
| O | Chat participants showed *"full number not recoverable"* while the resolver could recover it by connection id — a false claim, not just an omission. | Members now carry `phone_full` / `name_resolved` with origin labels: 30 numbers and 57 names recovered here. |
| P | The dashboard's entire amount-ranked "Top Counterparties" panel never rendered — nothing produced its data. | Produced, keyed on stable identifier (userId → phone → VPA) exactly as the panel's own caption promises; totals reconcile with the summary. |
| Q | An absent source left `summary: {}`, so metric tiles rendered blank with no explanation. | Keys exist with `None` (an absent source is not a measured zero) plus `source_absent`, and the page says so. |
| R | `transaction.classification` had a UI tag with nothing populating it. | Set from the counterparty leg's type (Merchant / P2P / split settlement). |

Five follow-ups closed on review (S–W, session log): fix M was verified only after being
flagged as unverified; **`STATE.md` itself was asserting two false things** (a stale
"SCAFFOLD STATUS" claim and 24 extractors when there are 23); the new consent/account evidence
was reachable only from one page, so it now has a PPQL index and CSV exhibits like every other
source; the **HTML report** was the last place ranking counterparties by display name and is now
identifier-keyed; and two gates tested the wrong condition (participant phone recovery, and a
counterparty label that a bare phone number could lock).

After K, **`degradations` is 0**: every source this build looks for is present and read on the
test acquisition. Evidence re-hashed byte-identical after ten full runs, and module counts were
diffed against every earlier baseline with all money totals unchanged.

Verified after the fixes: harness exits 0 — 0 module failures, 0 schema gaps, 0 derived
failures, 73/73 routes serving, and the 396 evidence files still byte-identical after seven
full runs. Every module count was diffed against the pre-fix baseline: only the four modules
the fixes touch changed, and **every money total is identical** (transaction count, received,
sent, net flow, ledger total, chat messages). See `CONTINUE.md` for the regression baseline.

Coverage caveat established this session: **"0 schema gaps" does not prove every module read
its data.** Table access outside `transaction_core` sits behind `db.has_table(...)`, so an
absent table contributes zero indistinguishably from an empty one; and
`_prune_absent_columns` returns early without recording a gap when *every* requested column
is absent. Verified for this acquisition by cross-checking every `has_table` name against the
`raw_tables` inventory: no referenced table is missing, and the only empty one is `rewards`
(so `rewards_count=0` is honest). Redo that cross-check on any new acquisition.

Case-specific numbers stay in `notes/sessions/` (gitignored — they quote real values out of
the acquisition).
