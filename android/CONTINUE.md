# CONTINUE — next concrete action

**Read order on resume:** `STATE.md` → this file → newest in `notes/sessions/`.

---

## Next action

**All forty-one issues found on 2026-07-30 (four audit passes plus review follow-ups)
are fixed and verified against
the real acquisition** (details: `notes/sessions/2026-07-30.md`). Nothing is outstanding.

*The count is A–J (10) + K–R (8) + S–W (5) + X–AB (5) + AC–AE (3) + AC2/AC3 (2) + AF–AM (8)
= 41. Count the letter ranges before writing a total here; an earlier revision of this line
said "twenty-seven" against 28 recorded defects.*

Suggested next steps, in order of value:

1. **Committed** on branch `forensic-fidelity-audit-2026-07-30` (27 files, +2,558 / −147).
   Not pushed and no PR opened — that is the next call if it is wanted. `notes/sessions/` is
   gitignored, so the session log lives only in the working tree; it quotes real subject values.
2. **Chase the one real lead the fixes exposed:** exactly one payment reference now falls
   inside the live ledger's retained period yet has no `transaction_core` row — the single
   case local retention does not explain, down from a headline of 81. It is named in the
   `uncorroborated_transactions` finding's `sample_inside_retained_period`, and in the
   gitignored session log.
3. Consider whether `search.db`'s FTS index (`fts_search` / `idx_mapper`, 8,416 docs each)
   is worth surfacing. Deliberately left alone: it is an app-built index over app content,
   not user search history — `recent_search` (1 row) is the user's actual searches. It is
   reachable through the raw-table browser meanwhile.
4. Consider a notifications section in the HTML report. The 977 decoded notifications are in
   `notification_messages.csv`, the master JSON, the timeline and PPQL, but the HTML exhibit
   does not summarise them. Same for the 38 consents (now in `consents.csv` + PPQL).
5. `ads_db.ad_response` (34 impressions with request times) is still unread — timestamped
   device-activity events if that is ever wanted; advertising plumbing otherwise.

**Do not read "0 schema gaps" as "everything was read"** — see the coverage caveat in
`STATE.md` §6 and re-run the `has_table`-vs-`raw_tables` cross-check on any new acquisition.

## Audit techniques that actually found bugs (reuse these)

1. **Render every page with `app.jinja_env.undefined = jinja2.StrictUndefined`.** A template
   reference to a key the data contract never provides otherwise renders as an empty cell,
   indistinguishable from "no data". This found a whole dashboard panel that never rendered and
   a participants table making a false "not recoverable" claim.
2. **List every SQLite file in the acquisition that no extractor opens, then look inside.** This
   found `accounts_db` (the account's unmasked phone) and the standalone `consent` database.
3. **Cross-check `has_table` names against the `raw_tables` inventory** — but note this only
   catches tables, not *databases*: `RecommendationsDatabase` → `MaximusDatabase` was invisible
   to it because the extractor never got as far as a table. When an extractor reports a database
   absent, check whether its tables exist somewhere else under a different database name.
4. **Diff module counts before/after any change** (`--json` output of two runs). Money totals
   must not move unless that is the point of the change.
5. **Use the app's own bookkeeping as ground truth.**
   `phonepe_core.transaction_aggregate_entity` holds PhonePe's own per-transaction
   `aggregate_type` (received/spent) and `amount` — join it on
   `<entity_id>_<type>` and compare. That is what proved `PIEDPIPER_PAYMENT`'s direction was
   backwards; amounts agreed 51/51, so a direction disagreement stood out cleanly.
6. **Reconcile row counts against `COUNT(*)` and recompute money from the raw JSON** rather
   than trusting the module summaries.
7. Beware a dict key named `values` reaching a template: Jinja resolves `row.values` to the
   dict's method, not the key. It 500s the page.
8. **Grep for hardcoded booleans in the correlator's node/edge builders.** `on_phonepe: True`
   on chat-derived nodes and `on_phonepe: False` on phonebook-only nodes were both *inferences
   presented as stored facts*. The chat one was even readable from evidence
   (`topicMember.onPhonePe`, already extracted as `phonepe_user`) — it just was not being read.
9. **Check every boolean-rendering filter for how it treats absent.** `yes_no` was
   `"Yes" if value else "No"`, so a missing column or JSON key rendered as a positive claim of
   "No". Same defect class as a hardcoded `True`, facing the other way. Also check for
   stringified booleans: every non-empty string is truthy, so `"false"` read as **Yes**.
10. **When a change touches a shared code path, check the payload keys it reads across *all*
    record types, not just the type you were fixing.** The `paymentPayerParty`/`paymentReceiver`
    counterparty preference was written for `PIEDPIPER_PAYMENT` but runs for every transaction;
    a `Counter` over `(type, present_keys)` proved those keys exist on **only** the 8
    PiedPiper rows, so the blast radius really was what it was meant to be. Cheaper than
    reasoning about it.

11. **Run the StrictUndefined lens to a fixed point, not once.** Every undefined key raises and
    *aborts that render*, so one dead panel hides the next one further down the same page. The
    sweep went 11 → 10 → 9 → 7 → 6 route-500s across five iterations, and each round revealed
    keys the previous round had masked (`upi_container` hid `approvers_recent`, which hid
    `consent_definitions`, which hid `cassini_models`). Stop when the key list repeats.
12. **A template key with zero setters is a panel that can never render — check for a source
    table before deleting it.** Eight such references existed; four had a real source table
    nobody read (`approvers_table`, `model_data`, `tstore.context.initiationMode`,
    `consent.consentSyncState`) and four had none. Wire the first kind; delete the second kind
    rather than inventing the data — see AL in `STATE.md` for the VPA-handle→app mapping that
    was deliberately *not* written.

### StrictUndefined: the stable 5 (do not chase as new)

After iterating to a fixed point, the sweep 500s on 6 routes over exactly 5 keys —
`amount_inr`, `blob`, `category`, `chat_group_id`, `normalized`. These are genuine **per-row**
optionals, guarded in-template by `{% if %}` or `or`, so under the production Undefined they
render as honest blanks: a chat message with no amount, a provenance source with no blob note,
a mini-app with no category, a contact with no chat thread, a phonebook row with no normalised
number. Forcing them into every dict would be noise. StrictUndefined is an **audit lens, not
the production config** — treat any *sixth* name as the signal.

Clean under the lens as of pass 4: `/audit`, `/identity`, `/payment-infra`, `/transactions`.

## Regression baseline (2026-07-30, post-fix)

`python notes/smoke_test.py <root>` exits **0** with: 0 module failures, 0 degradations,
0 schema gaps, 0 derived failures, 74/74 routes serving. Extraction ~55 s, of which ~54 s is
carving. Expect these findings:

| finding | expected |
|---|---|
| `failed_transactions` | 13 ERRORED |
| degradations / schema gaps | **0** (every source found and read) |
| `uncorroborated_transactions` | 57 refs; 56 predate retention, 1 in-window; 24 non-payment ids excluded |
| `recovered_deleted_records` | 982 recovered |
| `encrypted_databases` | 3 |
| `sms_corroboration` | 2 confirmed, 98 SMS-only |
| `high_value_transactions` | 1 |
| ground truth (`transaction_aggregate_entity`) | 51/51 amounts **and** directions agree |
| totals | recorded in the gitignored session log — compare `--json` output run-to-run, do not paste subject figures into a tracked file |
| `initiation_mode` | 7 INTENT · 1 QR_SCAN · 73 unstated (`None`, not False) |
| consents | 38 records, one uniform shape, `sync_state` 38/38 |
| `approver_count` / `cassini_models` | 0 / 0 — source tables read and genuinely empty |

Evidence re-hashed after **twenty-six** full runs: all 396 files byte-identical
(`diff before.sha256 final8.sha256`).
Timeline **2,180** events. Contacts report 186 distinct people from 298 source rows.

Social graph: **211 nodes** — CONTACT 189 (140 on-PhonePe / 38 not / 11 unknown),
CHAT_DERIVED 12 (all on-PhonePe, now sourced from `topicMember.onPhonePe` rather than assumed),
TXN_DERIVED 8 (unknown), CHAT_THREAD_ONLY 1 (unknown), PHONEBOOK_ONLY 1 (unknown).
The three `unknown` kinds must stay `None`, not `False` — see technique 8.

## Synthetic fixture — the baseline that is safe to quote

`python notes/make_demo_acquisition.py <dir>` builds a fabricated acquisition from
`notes/demo_schema.sql` (PhonePe's real table shapes, no data) and invented rows. It is what
the README screenshots are taken from, and unlike the real acquisition its numbers can be
pasted anywhere:

| expected | value |
|---|---|
| harness | exit 0, 74/74 routes, 3 degradations (absent sources this fixture omits) |
| extraction | ~1.2 s (no carving to do) |
| transactions | 6 — 1 IN, 5 OUT, one `ERRORED`, one `EXPENSE_SETTLEMENT` with no payment leg |
| `initiation_mode` | 1 QR_SCAN, 1 INTENT, rest unstated |
| chat | 2 threads, 5 messages, 2 payment cards (one referencing a txn absent from `transaction_core`) |
| ledger | 1 ledger, 2 expenses, 3 members with balances |
| timeline | 18 events across 6 sources |
| findings | 4, including the uncorroborated-payment case the fixture is built to trigger |

It deliberately recovers **0** deleted records: the databases are freshly created, so nothing
has been deleted. That is the honest result, and it exercises the
`no_deleted_records_recovered` finding that states an empty carve is not proof of nothing.

## How to test against the real acquisition

Evidence root (user's, read-only — never write into it). The absolute path is in the
gitignored session log, not here — this file is tracked, and the path names the examiner's
account. Export it once per shell:

```bash
export ACQ=...   # the com.phonepe.app directory; see notes/sessions/2026-07-30.md
```

Headless, everything at once (this is the fast way; the 74 routes are the slow way):

```bash
python notes/smoke_test.py \
  $ACQ \
  --export /tmp/pp-exports --json /tmp/pp-result.json
```

`--no-web` skips the Flask route sweep. The real test result is step 3
(`extraction_errors()` + `schema_gaps()`): a renamed Room column otherwise renders an
empty page that looks exactly like an acquisition with no such data.

The GUI, when a human should look at it:

```bash
PP_FORENSICS_NOBROWSER=1 python run.py 127.0.0.1:8754
# + New Case → point at the path above → Process
```

## Prove the evidence was not modified

The tool's read-only guarantee should be verified, not assumed, after any run:

```bash
P=$ACQ
find "$P" -type f -exec sha256sum {} \; | sort -k2 > after.sha256
diff before.sha256 after.sha256 && echo "evidence byte-identical"
```

A pre-run manifest of all 396 files was taken on 2026-07-30 (see the session log for the
result of this diff).

## If a *bare* database file is supplied instead of the app dir

Nothing in the tool accepts a loose DB file — `AndroidCasePaths` needs a directory
containing `databases/`, `is_valid()` is `bool(db("phonepe_core"))`, and `paths.db()` is an
exact filename join (so `phonepe_core.db` / `.sqlite` will **not** resolve). Stage it
outside the repo:

```
<scratch>/case01/com.phonepe.app/databases/phonepe_core        # exact name, no extension
                                          phonepe_core-wal     # if supplied — carver needs it
```

Note `.gitignore` covers `*.db`/`*.sqlite` but **not** a bare `phonepe_core`, which is why
staging belongs outside the working tree.

## Standing constraints

- Never commit acquisitions, exports, or `.pp_forensics/` — real financial + identity PII.
- Don't refactor extractors to match a schema you haven't seen; report mismatches from
  `extraction_errors()` / `schema_gaps()` and let the user set scope.
