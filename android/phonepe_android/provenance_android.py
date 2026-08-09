"""
PhonePe Android Forensics — Provenance registry
===============================================
For every forensically-important field the tool surfaces, this records EXACTLY where it came
from in the acquisition: database → table → column, or the JSON path inside a payload blob.

Purpose: make "is this value real / where did it come from?" answerable at a glance — the
chain-of-custody / data-fidelity map an investigator (or a defence challenge) needs. The source
strings below describe the actual extraction in `extractors_android.py`, verified against the
real sample. `get_provenance()` is rendered by the /provenance GUI page.

Notation: `db.table.column`; `→` = fallback waterfall; `JSON:` = path inside a decoded blob.
"""
from __future__ import annotations

from typing import Any, Dict

PROVENANCE: Dict[str, Dict[str, Any]] = {
    "_evidence_handling": {
        "source": "phonepe_forensics/core.py — SQLiteReader / snapshot_database",
        "fields": {
            "read-only guarantee": "Evidence files are never written to. Every database and its "
                                   "-wal/-shm/-journal sidecars are SHA-256 hashed BEFORE parsing. "
                                   "A database with no WAL opens in place with immutable=1, which "
                                   "cannot create or modify any file. One carrying a WAL is copied "
                                   "with its sidecars to a scratch directory and recovered there, so "
                                   "WAL-resident records are visible without touching the original. "
                                   "The connection is set query_only once the schema is read.",
            "WAL exclusion warning": "If the scratch copy cannot be staged (e.g. no disk), the "
                                     "database is opened immutable in place and a warning is raised "
                                     "on the dashboard, audit page and exported report stating that "
                                     "-wal content is NOT included.",
            "hash manifest": "Audit page + exports/chain_of_custody.json — per-file SHA-256 of "
                             "every database opened, with the sidecar hashes.",
            "timezone": "Every timestamp this tool emits is UTC. `iso` is ISO-8601 with an explicit "
                        "+00:00 offset; `display` is suffixed 'UTC'. Values that would fall outside "
                        "1973–2100 are rejected rather than rendered.",
            "schema drift": "Requested columns are intersected with the acquisition's real schema. A "
                            "renamed column narrows the projection and is reported on the Audit page "
                            "as a schema gap, instead of failing the query and rendering an empty page.",
        },
    },
    "transactions": {
        "source": "phonepe_core.transaction_core  ⋈  transaction_text_attribute / "
                  "transaction_numeric_attribute (joined on transaction_id_type)",
        "blob": "transaction_core.tstore_data and .instruments are PLAIN JSON strings.",
        "fields": {
            "global_payment_id": "tstore_data JSON:globalPaymentId → transaction_core.payment_reference → .transaction_id",
            "type": "transaction_core.type",
            "state": "transaction_core.state",
            "direction": "RECEIVED_PAYMENT→IN, SENT_PAYMENT→OUT, P2P_ENRICHMENT→INTERNAL are taken from .type. Every OTHER type — PIEDPIPER_PAYMENT included — is resolved per row from the payload instead: tstore_data JSON:actor (RECEIVER→IN, SENDER→OUT), then the presence of paymentPayerParty (→IN) or paymentReceiver (→OUT). Typing PIEDPIPER_PAYMENT as OUT was wrong on half of them, checked against the app's own transaction_aggregate_entity ledger. EXPENSE_SETTLEMENT carries no payment leg, so its direction comes from tstore_data JSON:payerMemberId/payeeMemberId against the self member ids in chatTopicMeta.ownMemberId / ledger_my_split_topic.ownMemberId; self on both or neither side falls back to OUT.",
            "amount_inr": "tstore_data JSON:amount → paidFrom[0].amount → to[0].amount → instruments[0].amount  (paise ÷ 100)",
            "counterparty": "IN: tstore_data JSON:from.cbsName|accountHolderName|name · OUT: to[0].cbsName|accountHolderName|name · fallback transaction_core.contact_data (masked names fall back to phone)",
            "counterparty_resolved / _resolved_source / _phone_full": "MASKED→REAL recovery: when .name is source-masked, the full leg phone/VPA is matched EXACTLY (last-10 / VPA) against the user's own contacts (contactConnectionInfo ▸ phone_contacts ▸ vpa_contacts ▸ paymentProfileCache) to recover the real name; _resolved_source names the originating table + match key. Ambiguous last-10 phones (>1 distinct contact) are left unresolved.",
            "counterparty_phone": "tstore_data JSON:{from|to[0]}.phone|upiNumber → transaction_core.contact_data",
            "counterparty_vpa": "tstore_data JSON:{from|to[0]}.fullVpa|vpa",
            "self_account_holder": "tstore_data JSON:{receivedIn|paidFrom}[0].accountHolderName",
            "self_account_masked": "tstore_data JSON:{receivedIn|paidFrom}[0].accountNumber",
            "self_ifsc": "tstore_data JSON:{receivedIn|paidFrom}[0].ifsc  (NOTE: credit-card-on-UPI legs carry a synthetic placeholder IFSC, e.g. HDCC0000001 — not a branch IFSC)",
            "utr": "tstore_data JSON:{receivedIn|paidFrom}[0].utr",
            "transfer_mode": "tstore_data JSON:context.transferMode → text_attr 'context.transferMode'",
            "response_code": "tstore_data JSON:responseCode → {leg}.transactionResponseCode",
            "created_at / updated_at": "transaction_core.timestamp_created / timestamp_updated (Unix ms)",
            "category_code": "transaction_text_attribute 'entity.category'",
            "id_embedded_ts": "decoded from the transaction_id (T<YYMMDDhhmmss>…) itself. CAVEAT: the "
                              "timezone the PhonePe server stamps into the ID is undocumented and has "
                              "NOT been validated against a ground-truth transaction (IST is plausible). "
                              "The wall-clock digits are reported as-is; the epoch conversion assumes UTC "
                              "and is labelled 'UTC (unvalidated)'. Do not treat it as an independent "
                              "corroboration of created_at without checking a known transaction first.",
        },
    },
    "identity": {
        "source": "phonepe_core.accounts/vpa/users + shared_prefs/*.xml + files/.crashlytics.v3/…",
        "fields": {
            "registered_name": "phonepe_core.accounts.account_holder_name → users.verified_name",
            "upi_id / all_vpas": "phonepe_core.vpa.vpa (is_primary), vpa_v2, accounts.vpas(JSON:vpaPrefix+psps)",
            "device_model / manufacturer / os_version / is_rooted": "files/.crashlytics.v3/com.phonepe.app/open-sessions/<id>/native/device.json + os.json",
            "phonepe_user_id / phonepe_device_id": "files/.crashlytics.v3/.../user-data  (userId:<…>::deviceId:<…>)",
            "anon_id": "shared_prefs/anon_pref.xml:anon_id (corroborated in crashlytics keys ANON_ID)",
            "appsflyer_id / first_install": "shared_prefs/appsflyer-data.xml: AF_INSTALLATION / appsFlyerFirstInstall",
            "firebase_installation_id": "shared_prefs/com.google.firebase.crashlytics.xml: firebase.installation.id",
            "fcm_token": "shared_prefs/com.google.android.gms.appid.xml: |T|… (JSON:token)",
            "session_id": "filename of shared_prefs/phonepe_session_config_<SESSIONID>.xml",
            "refresh_tokens (expiry)": "shared_prefs/phonepe_auth_config.xml: <uuid> JSON:{expiry,refreshToken,scope}",
            "biometric_token_ts": "shared_prefs/screenlock.xml: biometricTokenTimestamp",
        },
    },
    "payment_infra": {
        "source": "phonepe_core.accounts / vpa / vpa_v2 / psp / wallet / external_wallet_provider / banks",
        "fields": {
            "linked_accounts": "phonepe_core.accounts (account_no, account_holder_name, account_type, is_primary)",
            "linked_vpas": "phonepe_core.vpa.vpa + vpa_v2(vpa@psp) + accounts.vpas(JSON)",
            "psp_handles": "phonepe_core.psp (psp_handle, active)",
            "wallet.balance_inr": "phonepe_core.wallet.available_balance (paise ÷ 100)",
            "supported_banks": "phonepe_core.banks (bank_id, bank_name, ifsc, upi_supported, …)",
            "bank name for an IFSC/bankId": "phonepe_core.banks (e.g. HDCC → 'HDFC Bank Credit Card')",
        },
    },
    "contacts": {
        "source": "phonepe_core.phone_contacts / contactConnectionInfo / nonContact(+Attributes) / "
                  "phone_book_contacts(+metadata) / vpa_contacts",
        "fields": {
            "phonepe contacts": "phone_contacts (phone_num, cbs_name, on_phonepe, upi_status) + name from contactConnectionInfo by connection_id",
            "phonebook contacts": "phone_book_contacts ⋈ phone_book_contacts_metadata (display_name) on lookup",
            "vpa contacts": "vpa_contacts (contact_vpa, nick_name, cbs_name)",
        },
    },
    "chat": {
        "source": "phonepe_core.chatMessage / chatTopic / chatTopicMeta / topicMember",
        "blob": "chatMessage.content is JSON; the card payload is nested at content.content.",
        "fields": {
            "direction / is_self": "sender = content.source.groupMemberId vs chatTopicMeta.ownMemberId (per topic)",
            "sender/receiver name": "topicMember.phonePeName by memberId (TRANSACTION_RECEIPT also carries sender/receiver.name)",
            "sender/receiver/other_party _resolved / _resolved_source / _phone_full": "MASKED→REAL recovery: when the member's phonePeName/maskedPhoneNumber is masked, resolve via topicMember.memberId→connectionId then the contact name tables (source recorded). Full phone recovered from phone_contacts.phone_num / paymentProfileCache.destination by connection_id.",
            "amount_inr (PAYMENT_INFO_CARD)": "content.content.amount",
            "amount_inr (TRANSACTION_RECEIPT)": "content.content.transactionUnit.value",
            "amount_inr (EXPENSE_CARD_V2)": "content.content.expenseInfo.expenseCard.cardInfo.totalAmount",
            "amount_inr (SETTLEMENT_CARD)": "content.content.settlementInfo.totalAmount|globalSettlementAmount",
            "transaction_id": "content.content.transactionId → expenseInfo…expenseId → settlementInfo.globalSettlementId",
            "note (split name)": "content.content.expenseInfo.expenseCard.cardInfo.name / groupAction.name",
        },
    },
    "ledger": {
        "source": "phonepe_core.ledger_meta / ledger_entity / ledger_expense / ledger_expense_member / "
                  "ledger_balance / ledger_my_split / ledger_settlement",
        "fields": {
            "expense amount / payer / members": "ledger_expense + ledger_expense_member (member_id, is_payer, amount paise)",
            "member name": "resolved via topicMember.phonePeName / contactConnectionInfo / phone_contacts by member_id|connection_id",
            "settlement_txn_id": "ledger_settlement.global_id (links the expense to its EXPENSE_SETTLEMENT transaction)",
            "net balances": "ledger_balance (balanceAmountToGive / balanceAmountToReceive, paise)",
            "chat link": "ledger_entity.topic_id (the split group is also a chat topic)",
        },
    },
    "identity_account_record": {
        "source": "accounts_db.account  (Android account-manager store — previously "
                  "read by no extractor at all)",
        "fields": {
            "user_id": "accounts_db.account.user_id — the PhonePe account id that also appears "
                       "as Bullhorn topic suffixes (CONSUMER_<user_id>@…) and as "
                       "MaximusDatabase.product.entity_id. Reported as "
                       "device_identifiers.phonepe_account_user_id, kept SEPARATE from the "
                       "Crashlytics hashed telemetry userId.",
            "phone": "accounts_db.account.user_phone_number — UNMASKED, unlike the sibling "
                     "user_name column which is source-masked (******0961)",
            "email / verified flags": "accounts_db.account.{user_email, email_verified, "
                                      "phone_number_verified}",
            "registered_name": "accounts_db.account.user_display_name → .user_name, but only "
                               "when not source-masked; otherwise from phonepe_core "
                               "accounts.account_holder_name / users.verified_name",
        },
    },
    "consent": {
        "source": "consent.consent (standalone database)  +  phonepe_core.consent",
        "fields": {
            "note": "Two separate stores. The standalone `consent` database was previously "
                    "unread; each record now carries a `source` naming which store it came "
                    "from, so a consent record is attributable.",
            "data type / use case / accept type / state": "consent.{dataType, useCaseId, "
                                                          "acceptType, consentState}",
            "definition / sync state": "consent.{consentDefinition, consentSyncState}",
            "subject_ref": "consent.subjectRefId, with the source's own 'NA' placeholder "
                           "reported as absent rather than as a value",
        },
    },
    "recommendations": {
        "source": "MaximusDatabase (preferred) → RecommendationsDatabase (older name): "
                  "product / recommendation_item / signal",
        "fields": {
            "note": "PhonePe renamed this store. Only the old name was tried, so an "
                    "acquisition carrying all of the data reported the source as absent. "
                    "Both names are tried and summary.database records which was used.",
            "products / recommendations": "product.{product_id, product_name, "
                                          "product_namespace}; recommendation_item.{item_id, "
                                          "product_id, rank, item_expiry}",
            "signals": "signal.{signal_type, signal_timestamp (Unix ms), is_synced, item_id} "
                       "— IMPRESSION/CLICK events, which reach the unified timeline",
        },
    },
    "notifications": {
        "source": "BullhornDatabase.topic  ⋈  messageDataStore (delivered payloads) "
                  "+ message (operation log)",
        "blob": "messageDataStore.data is JSON whose .message.payload is base64-encoded "
                "JSON — the notification template the user was shown.",
        "fields": {
            "subsystem / storage_type / subscription_status": "BullhornDatabase.topic.{subSystemType, messageStorageType, topicSubscriptionStatus}",
            "created/updated/expiry": "topic.{topicCreatedTimeStamp, topicUpdateTimeStamp, messageExpiry} (Unix ms)",
            "raw_message_count": "COUNT(*) of BullhornDatabase.message by topicId_M — the "
                                 "operation log, which on real devices is near-empty and is "
                                 "NOT a count of what was delivered",
            "stored_message_count": "COUNT of messageDataStore rows whose decoded .message.topicId is this topic",
            "title / subtitle / deeplink / template": "messageDataStore.data JSON:message.payload "
                                                      "(base64→JSON) :data.placements[].template."
                                                      "{templateParams.value.{title,subTitle}, "
                                                      "templateId, nav.params.{deepLink*, "
                                                      "redirection_data.data[key=url].value}}",
            "kind": "derived: <system>/<operation> for sync instructions "
                    "(e.g. CATALOGUE/SYNC), payload .type where present, else NOTIFICATION "
                    "when a title/body is present",
            "created_at / sent_at / expires_at": "messageDataStore payload envelope "
                                                 ".message.created / .updated, and payload "
                                                 ".sentAt / .expiresAt (Unix ms)",
        },
    },
    "sms": {
        "source": "inference_data_provider.sms_buffer  (Android-only)",
        "fields": {
            "address / body / received_at": "sms_buffer.address / body / time_received (Unix ms)",
            "corroboration": "computed: sms amount (regex on body) matched to transaction amount within ±30 min",
        },
    },
    "travel": {
        "source": "phonepe_core.yatra_journeys (+ yatra_tags)  — onboarding/feature journeys, NOT travel bookings",
        "fields": {
            "name / tags": "yatra_tags.tag_id joined by journey_id (e.g. ONBOARDING_PROFILE, INSURANCE_HP_ACTIONS_V3)",
            "stage / path / state": "yatra_journeys.current_stage_name / traversed_path / is_active|is_complete",
        },
    },
    "audit": {
        "source": "phonepe_core.phonepe_sync_tracing / consent / ledger_balance_sync + crashlytics device info",
        "fields": {
            "sync task / status / time": "phonepe_sync_tracing.syncId / syncStatus / lastSyncAttemptTime|lastSyncCompletionTime  (system column is always 'UNKNOWN' in this DB)",
            "consents": "phonepe_core.consent (consentState, dataType, useCaseId, endTime)",
        },
    },
    "miniapps": {
        "source": "files/NirvanaApps/<uuid>/{manifest,config,nirvanaApplicationInfo}.json",
        "fields": {
            "merchant / type / domains / updated_at": "config.json (merchantName, microAppType, whitelistedDomains) + manifest.json + nirvanaApplicationInfo.json",
        },
    },
    "deleted_records": {
        "source": "phonepe_forensics/carver.py — freed pages, released cells, page slack, "
                  "WAL frames and rollback-journal pre-images of every carved database",
        "fields": {
            "recovery method": "Unallocated space is scanned for SQLite record headers; "
                               "candidates are matched to a table by column count and column "
                               "affinity, then DISCARDED if the same row is still present in "
                               "the live table (a stale page copy is not a deletion).",
            "pools": "freelist (released page) · freeblock (released cell in a live page) · "
                     "page-slack (a page's unallocated middle) · pre-wal-image / "
                     "wal-superseded (a page version the WAL replaced) · journal (rollback "
                     "pre-image). Each record records its pool, page number and byte offset.",
            "partial / confidence": "Freeing a cell writes a 4-byte freeblock header over the "
                                    "record's start, taking its first serial type. Such rows are "
                                    "marked `partial`; the lost field's boundary is solved for "
                                    "and the value reported as reconstructed. Confidence is "
                                    "`high` only where the record's extent was confirmed "
                                    "structurally (intact header, or an end abutting the next "
                                    "freed cell), `medium` where boundaries were inferred.",
            "ambiguity": "A record whose shape fits several tables is reported against ALL of "
                         "them and flagged ambiguous — never silently assigned to one.",
            "negative result": "An empty recovery is NOT evidence that nothing was deleted. "
                               "Freed space is reused over time and secure_delete zeroes it on "
                               "deletion. Whether freed content survived is reported from what "
                               "was recovered, not from PRAGMA secure_delete (per-connection, "
                               "so it describes the examining build, not the phone).",
        },
    },
    "encrypted_dbs": {
        "source": "databases/ files with a SQLiteCrypt/SQLCipher header",
        "fields": {
            "not parseable": "AccountAggregatorDatabase / mdb / <uuid> are encrypted (hardware-keystore-wrapped key). Only name + size + SHA-256 recorded — NOT decryptable offline.",
        },
    },
}


def get_provenance() -> Dict[str, Any]:
    return PROVENANCE
