"""
PhonePe iOS Forensics — In-App Research Document
================================================

Structured reference data describing every artifact this tool understands:
the database, its tables, the columns we read, the forensic value we
attribute to it, and example queries the investigator can run.

Each section is self-contained and rendered by templates/research.html.
"""
from __future__ import annotations

from typing import Any, Dict, List


# Helper for shorter cells
def _row(name: str, kind: str, location: str, what_we_read: str,
         forensic_value: str, sample_query: str = "") -> Dict[str, str]:
    return {
        "name": name, "kind": kind, "location": location,
        "what_we_read": what_we_read, "forensic_value": forensic_value,
        "sample_query": sample_query,
    }


RESEARCH_SECTIONS: List[Dict[str, Any]] = [
    # -----------------------------------------------------------------------
    {
        "slug": "overview",
        "title": "1. Architecture Overview",
        "intro": (
            "PhonePe is built as a four-layer architecture: payment microapps, "
            "application framework (LiquidUI / Crayons / WidgetX), the PhonePe "
            "kernel (Auth / Config / PubSub), and platform capabilities "
            "(SQLite / Keychain / Preferences / Network). On iOS this maps to "
            "three sandboxed storage domains."
        ),
        "blocks": [
            {
                "heading": "Storage domains",
                "body": (
                    "Every PhonePe iOS acquisition contains three top-level "
                    "containers. The tool always treats them as the canonical "
                    "input."
                ),
                "list": [
                    "AppDomain-com.phonepe.PhonePeApp — the main app sandbox. "
                    "Holds Documents/ (the SQLite databases) and Library/ "
                    "(Preferences, Cookies, WebKit, Application Support).",
                    "AppDomainGroup-group.com.phonepe.PhonePeApp — group "
                    "container shared between the app and its extensions. "
                    "Holds the highest-value databases: P2P, Burble (chat), "
                    "SamparkV2 (contacts) and the Foxtrot pending-events queue.",
                    "AppDomainGroup-group.com.phonepe.shared — cross-app "
                    "shared preferences (consumed by PhonePe Business / "
                    "Pulse and other PhonePe-family apps).",
                ],
            },
            {
                "heading": "Why three layers matter forensically",
                "body": (
                    "Many investigations only ship the `AppDomain` directory. "
                    "Without the group containers, chat history, contact "
                    "graph and recent UPI events are unrecoverable from the "
                    "device because they are physically stored in the group "
                    "sandbox, not the app sandbox. Always verify that all "
                    "three containers are present before drawing conclusions."
                ),
            },
            {
                "heading": "Timestamp semantics",
                "body": (
                    "PhonePe iOS uses three different epochs interchangeably:"
                ),
                "list": [
                    "Unix milliseconds (~1.6e12) — the dominant format in "
                    "user-data tables (ZTRANSACTIONENTITY.ZCREATEDAT, etc.)",
                    "Unix seconds float — Foxtrot batch timestamps and a few "
                    "JSON blobs.",
                    "Apple Core Data / NSDate seconds (~6e8 – ~9e8) — used "
                    "in some Core Data internal columns and Cookies. "
                    "Convert with `epoch_unix = nsdate + 978307200`.",
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "transactions",
        "title": "2. Master Transaction Ledger",
        "intro": (
            "The single most important artifact: every UPI / wallet / "
            "merchant transaction the user ever touched on this device, "
            "stored as Apple Core Data entities with a NSKeyedArchiver "
            "BLOB carrying the full UPI gateway response."
        ),
        "blocks": [
            {
                "heading": "TransactionsStore.sqlite",
                "body": (
                    "Path: Documents/TransactionsStore/Database/"
                    "TransactionsStore/TransactionsStore.sqlite"
                ),
            },
            {
                "heading": "Tables of interest",
                "rows": [
                    _row(
                        "ZTRANSACTIONENTITY", "Core Data row",
                        "TransactionsStore.sqlite",
                        "ZCREATEDAT, ZUPDATEDAT, ZGLOBALPAYMENTID, ZTYPEVALUE, "
                        "ZSTATEVALUE, ZSEARCHTOKEN, ZDATA (bplist), ZTAGSDATA (bplist), "
                        "ZDISMISSED, ZISINTERNALTRANSACTION",
                        "One row per transaction. ZDATA holds the UPI gateway "
                        "response (counterparty name, phone, VPA, UTR, IFSC, "
                        "instrumentId, accountId, both-sides VPA). ZSEARCHTOKEN "
                        "is plain-text full-text-search bait that often "
                        "contains contact names + phones even when the BLOB "
                        "is corrupted.",
                        "transactions | where direction = \"OUT\" and amount_inr > 5000 | sort amount_inr desc",
                    ),
                    _row(
                        "ZTRANSACTIONTAGENTITY", "Tag index",
                        "TransactionsStore.sqlite",
                        "ZTRANSACTION (FK), ZKEY, ZVALUE",
                        "Flattened key/value index used by PhonePe's UI for "
                        "filtering. Frequently observed keys: amount, status, "
                        "category, sentTo, receivedIn.type, instrumentType, "
                        "context.transferMode. Useful when the BLOB is "
                        "unreadable.",
                        "(SQL) SELECT ZKEY, ZVALUE FROM ZTRANSACTIONTAGENTITY WHERE ZTRANSACTION = ?",
                    ),
                ],
            },
            {
                "heading": "Direction inference",
                "body": (
                    "Direction is determined from ZTYPEVALUE: RECEIVED_PAYMENT / "
                    "USER_TO_USER_RECEIVED_REQUEST / RECEIVED_MANDATE_CREATE_REQUEST → IN. "
                    "SENT_PAYMENT / EXTERNAL_PAYMENT / PHONE_RECHARGE / "
                    "BILL_PAYMENT / SERVICE_MANDATE_CREATE → OUT. "
                    "P2P_ENRICHMENT and SYMPHONY are metadata-only and have "
                    "no money movement."
                ),
            },
            {
                "heading": "Counterparty resolution from ZDATA",
                "body": (
                    "For RECEIVED_*, the counterparty is in zdata['from']; "
                    "for SENT_*, it is in zdata['to'] (or zdata['paidTo']). "
                    "Self-side data is in zdata['receivedIn']/['paidFrom'] "
                    "which yields self account holder, masked account "
                    "number, IFSC, UTR and instrument id."
                ),
            },
            {
                "heading": "Forensic queries to run",
                "list": [
                    "Top 5 outgoing transactions by value: `transactions | where direction = \"OUT\" | sort amount_inr desc | head 5`",
                    "All transactions to a specific phone: `transactions | where counterparty_phone = \"9491508461\"`",
                    "All ERRORED transactions: `transactions | where state = \"ERRORED\"`",
                    "Total received per year: `transactions | where direction = \"IN\" and state = \"COMPLETED\" | stats sum(amount_inr) by created_at_iso`",
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "chat",
        "title": "3. In-App Chat (Burble)",
        "intro": (
            "PhonePe's in-app chat looks superficially like WhatsApp: 1:1 and "
            "group threads, image attachments, payment cards and money "
            "requests. Burble is the engine. Understanding Burble's three-way "
            "relational model — message ↔ content ↔ member-source/destination "
            "— is essential to reconstructing who said what to whom."
        ),
        "blocks": [
            {
                "heading": "Burble.sqlite",
                "body": (
                    "Path (group container): com.phonepe.PhonePeApp/Burble/Burble.sqlite"
                ),
            },
            {
                "heading": "Relational model",
                "body": (
                    "ZMESSAGE references ZCONTENT (the payload), and points "
                    "to a ZGROUPMEMBERSOURCE row + ZGROUPMEMBERDESTINATION row "
                    "via Z_PK FKs. ZGROUPMEMBER joins those two source/dest "
                    "rows back to the human-readable display name and "
                    "masked phone (from ZMATTRIBUTES.profileSnapshot bplist)."
                ),
            },
            {
                "heading": "Key tables",
                "rows": [
                    _row("ZGROUPMETA", "group descriptor", "Burble.sqlite",
                         "ZGROUPID, ZNAME, ZIMAGEURL, ZGROUPSTATUSVALUE, ZNAMESPACE",
                         "One row per chat thread. The thread name = the "
                         "counterparty's PhonePe display name.", ""),
                    _row("ZGROUP", "group config", "Burble.sqlite",
                         "ZGROUPTYPE, ZSUBSCRIPTIONSTATUS, ZSUBSYSTEMTYPE",
                         "Indicates the kind of conversation (P2P / GANG / "
                         "MERCHANT) and whether the user is still subscribed.", ""),
                    _row("ZGROUPMEMBER", "participant", "Burble.sqlite",
                         "ZPHONEPENAME, ZROLEVALUE, ZMEMBERSTATEVALUE, "
                         "ZMATTRIBUTES (bplist with profileSnapshot)",
                         "Human-readable name and masked phone of every "
                         "participant. Critical for attributing message "
                         "authorship.", ""),
                    _row("ZGROUPMEMBERSOURCE / ZGROUPMEMBERDESTINATION", "FK bridge",
                         "Burble.sqlite",
                         "ZGROUPID, ZGROUPMEMBERID, ZTYPEVALUE",
                         "Bridge tables that link ZMESSAGE to a sender / "
                         "receiver. Type=PHONE for human members, USER_ID "
                         "and ACCOUNT for system / merchant identities.", ""),
                    _row("ZMESSAGE", "message envelope", "Burble.sqlite",
                         "ZMESSAGEID, ZTHREADID, ZGROUPMEMBERSOURCE, "
                         "ZGROUPMEMBERDESTINATION, ZISVISIBLE, ZCONTENT",
                         "The chat message; ZTHREADID = group_id; "
                         "ZGROUPMEMBERSOURCE/DESTINATION resolve to a "
                         "ZGROUPMEMBER through the bridge tables.", ""),
                    _row("ZCONTENT", "payload", "Burble.sqlite",
                         "ZCONTENTTYPEVALUE (PAYMENT_INFO_CARD / TEXT_MESSAGE "
                         "/ IMAGE_ATTACHMENT / GIFT_RECEIVED), ZAMOUNT, "
                         "ZTRANSACTIONID, ZUTR, ZINSTRUMENTUSEDVALUE, "
                         "ZEXTERNALVPA, ZEXTERNALVPACBSNAME, ZNOTE, "
                         "ZTEXT, ZTEXTMESSAGE, ZMESSAGESTRING, ZGIFTMESSAGE, "
                         "ZPREVIEWURL",
                         "Per content-type the meaningful fields differ. "
                         "TEXT_MESSAGE almost always uses ZMESSAGESTRING for "
                         "the actual body (we tried ZTEXT first, but it is "
                         "frequently NULL).", ""),
                    _row("ZSHAREDCONTACT", "attachment", "Burble.sqlite",
                         "ZACCOUNTHOLDERNAME, ZACCOUNTNUMBER, ZBANKNAME, "
                         "ZIFSC, ZFULL_VPA, ZPHONE, ZNAME",
                         "When a user shares a bank account or contact card "
                         "in chat, the entire bank-account record is stored "
                         "verbatim. Strong forensic evidence.", ""),
                ],
            },
            {
                "heading": "Hunting the chat",
                "list": [
                    "All TEXT messages from a specific person: `chat_messages | where sender_name = \"Bharath Kalyan\" and type = \"TEXT_MESSAGE\"`",
                    "Find a UTR mentioned in chat: `chat_messages | where utr = \"905177669040\"`",
                    "Money requests still pending: `chat_messages | where request_state = \"PENDING\"`",
                    "Bank disclosures shared as attachments: `shared_bank_disclosures | where verified = false`",
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "contacts",
        "title": "4. Contacts & Social Graph (SamparkV2)",
        "intro": (
            "Sampark (Sanskrit for 'contact / connection') is PhonePe's "
            "contacts intelligence layer. It deduplicates the user's "
            "phonebook against the PhonePe directory and caches every "
            "contact's profile picture as an external BLOB."
        ),
        "blocks": [
            {
                "heading": "SamparkV2.sqlite + _EXTERNAL_DATA",
                "body": (
                    "Path (group container): com.phonepe.PhonePeApp/SamparkV2/SamparkV2.sqlite. "
                    "Profile pictures live in the sibling .SamparkV2_SUPPORT/_EXTERNAL_DATA "
                    "directory as raw JPEG/PNG blobs."
                ),
            },
            {
                "heading": "Tables we read",
                "rows": [
                    _row("ZCYCLOPSCONTACT", "PhonePe-side directory", "SamparkV2.sqlite",
                         "ZCONNECTID, ZPHONENUMBER, ZVERIFIEDNAME, ZONPHONEPE, "
                         "ZEXTERNALVPA, ZUPISTATEVALUE, ZTIMESTAMP, ZPHOTO",
                         "Every contact PhonePe has resolved server-side. "
                         "ZVERIFIEDNAME is the PhonePe-side ground truth name. "
                         "ZUPISTATEVALUE = ENABLED / DISABLED tells whether "
                         "they can currently receive UPI.", ""),
                    _row("ZPHONEBOOKCONTACT", "device address book", "SamparkV2.sqlite",
                         "ZRAWPHONENUMBER, ZSELFNORMALISEDNUMBER (E.164), "
                         "ZCREATIONTIME, ZISVALID, ZDIDDELETE, ZMETADATA (FK)",
                         "The user's local phonebook entries that PhonePe "
                         "imported. ZDIDDELETE = soft-deleted contact.", ""),
                    _row("ZPHONEBOOKCONTACTMETADATA", "name + DP", "SamparkV2.sqlite",
                         "ZFULLNAME, ZCONTACTID, ZHASHCODE, ZIMAGEDATA",
                         "Holds the contact's display name from the device "
                         "address book and a *binary image* (JPEG/PNG) of "
                         "their photo. The matching file lives at "
                         "_EXTERNAL_DATA/<Z_PK>.", ""),
                ],
            },
            {
                "heading": "Hunts",
                "list": [
                    "All contacts on PhonePe: `contacts | where on_phonepe = true | sort verified_name`",
                    "Disabled UPI accounts (potentially blocked): `contacts | where upi_state = \"DISABLED\"`",
                    "External VPA known: `contacts | where external_vpa matches \".+@.+\"`",
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "p2p",
        "title": "5. P2P Backgrounds & Transaction Themes",
        "intro": (
            "PhonePe lets users theme P2P transactions with category-specific "
            "background art (DINING, TRAVEL, BIRTHDAY, BILL, GIFT, etc.). "
            "These themed PNGs cache locally and are themselves forensic "
            "evidence — they reveal *categorical context* of payments even "
            "when the user-entered note is empty."
        ),
        "blocks": [
            {
                "heading": "P2P.sqlite",
                "body": (
                    "Path (group container): com.phonepe.PhonePeApp/P2P/P2P.sqlite. "
                    "Tables: ZTRANSACTIONBACKGROUNDCATEGORY, "
                    "ZTRANSACTIONBACKGROUNDASSET, ZPAYMENTDESTINATIONMAPPING."
                ),
            },
            {
                "heading": "Background asset folder",
                "body": (
                    "On disk the PNGs live under TransactionBackgrounds/<category>/<variant>. "
                    "Folder names encode date codes (e.g. BILL_GENERIC_A22120100... → "
                    "December 1, 2022) which gives an earliest-use-of-feature signal."
                ),
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "payment-infra",
        "title": "6. Payment Infrastructure (PaymentDataStore)",
        "intro": (
            "Catalogue of every banking primitive the user has touched: "
            "bank accounts, UPI VPAs, registered PSPs, linked cards, "
            "wallets, UPI Lite + International configuration, and the "
            "supported-bank list downloaded from PhonePe's central catalogue."
        ),
        "blocks": [
            {
                "heading": "PaymentDataStore.sqlite",
                "body": "Path: Documents/Payment/Database/PaymentDataStore/PaymentDataStore.sqlite",
            },
            {
                "heading": "Tables",
                "rows": [
                    _row("ZPCDBANKACCOUNT", "linked account", "PaymentDataStore.sqlite",
                         "ZACCOUNTNO (masked), ZACCOUNTHOLDERNAME, "
                         "ZACCOUNTID, ZACCOUNTALIAS, ZISPRIMARY",
                         "User's own bank account(s) linked to PhonePe. "
                         "Holder name pinned by the bank (CBS-side).", ""),
                    _row("ZPCDUPIVPADETAIL / ZPCDUPIVPAPSPDETAIL", "VPAs", "PaymentDataStore.sqlite",
                         "ZVPAPREFIX, ZPSP, ZCREATEDAT, ZISACTIVATED",
                         "All UPI VPA prefixes the user has registered "
                         "(@ybl, @oksbi, @ibl, etc.). One phone number can "
                         "be mapped to many VPAs across PSPs.", ""),
                    _row("ZPCDPHONEPEPSP / ZPCDUPIPSPDETAIL", "PSP onboarding",
                         "PaymentDataStore.sqlite",
                         "ZPSPHANDLE, ZISACTIVE, ZISONBOARDED",
                         "Which PSPs (UPI service providers) the user is "
                         "onboarded with — proves UPI registration history.", ""),
                    _row("ZPCDCARD / ZPCDPGCONTAINER", "linked cards", "PaymentDataStore.sqlite",
                         "ZMASKEDCARDNUMBER, ZCARDHOLDERNAME, ZCARDISSUER, "
                         "ZBANKCODE, ZCARDTYPEVALUE, ZCARDSTATUSVALUE",
                         "Tokenised card-on-file records. Masked PAN, "
                         "issuer, BIN-derived bank code.", ""),
                    _row("ZPCDUPILITE / ZPCDUPILITEBOUNDDETAIL", "UPI Lite",
                         "PaymentDataStore.sqlite",
                         "ZISUPILITEELIGIBLE, ZISAUTOTOPUPSUPPORTED, "
                         "ZONLINEACTIVE, ZACCOUNTREFERENCENUMBER",
                         "Whether the user has opted into UPI Lite (offline "
                         "small-payments wallet) and which account backs it.", ""),
                    _row("ZPCDUPIINTERNATIONALDETAIL", "UPI International",
                         "PaymentDataStore.sqlite",
                         "ZACTIVE, ZELIGIBLE, ZPROCESSING",
                         "UPI-International activation status — relevant "
                         "for cross-border payment investigations.", ""),
                    _row("ZPCDBANK", "bank catalogue", "PaymentDataStore.sqlite",
                         "ZID, ZNAME, ZIFSCPREFIX, ZISUPISUPPORTED, "
                         "ZISUPIMANDATESUPPORTED, ZISCREDITCARDONUPISUPPORTED",
                         "PhonePe's master list of banks (864 entries). "
                         "Useful as a reference for IFSC validation.", ""),
                    _row("ZPCDAPPROVER", "mandate approvers", "PaymentDataStore.sqlite",
                         "ZAPPROVERVPA, ZCONTACTNAME, ZCONTACTNUMBER, "
                         "ZAPPROVERTYPE, ZLINKINGTYPE, ZEXPIRYTS",
                         "UPI Circle / Family approvers — third parties "
                         "who can approve payments for this account.", ""),
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "identity-plists",
        "title": "7. Identity Plists",
        "intro": (
            "Library/Preferences/ holds plist files. Many are decisive identity "
            "evidence — they tie the device to a specific PhonePe account, IDFA, "
            "Firebase Installation ID and AppsFlyer attribution ID."
        ),
        "blocks": [
            {
                "heading": "Plist files we mine",
                "rows": [
                    _row("com.phonepe.help.customDataStore.plist", "auth tokens", "Library/Preferences",
                         "optimus_auth_headers (userName, refreshToken, optimusToken)",
                         "Plain-text userName! Combined with the refreshToken "
                         "this is the strongest identity proof on the device.", ""),
                    _row("com.phonepe.widgetxii.datacache.plist", "widget cache", "Library/Preferences",
                         "homePage.UPI_ID",
                         "User's primary UPI VPA cached for the iOS home-screen widget.", ""),
                    _row("com.phonepe.PhonePeApp.plist", "main prefs", "Library/Preferences",
                         "com.phonepe.app.sessionIDUpdatedAt, AppsFlyerUserId, "
                         "BoltV2.boltToken, chimera.quick-* (feature flags)",
                         "222 keys including session timestamps, Bolt SDK "
                         "token, AppsFlyer install ID, every quickly-cached "
                         "Chimera feature flag the user is bucketed into.", ""),
                    _row("com.phonepe.account.plist", "token expiry", "Library/Preferences",
                         "com.phonepe.networkclient.token.expiry.time / fetched.time",
                         "When the network client last refreshed its bearer "
                         "token. Pins the device's last successful login.", ""),
                    _row("com.phonepe.ads.sdk.plist", "location", "Library/Preferences",
                         "lastConfigRequest (lat, lng, pinCode, state)",
                         "GPS-grade location pulled from the Ads SDK config "
                         "request — often the only authoritative location "
                         "evidence for the device.", ""),
                    _row("com.firebase.FIRInstallations.plist", "Firebase ID", "Library/Preferences",
                         "1:412209864940:ios:<install_id>",
                         "Firebase Installation ID — pivots into Firebase "
                         "Analytics (Google) and FCM logs server-side.", ""),
                    _row("com.apple.AdSupport.plist", "IDFA", "Library/Preferences",
                         "ShouldEnforceATP, LastRegionalEnforcementCheck",
                         "Apple advertising identifier policy state.", ""),
                    _row("__gads__.plist", "Google Ads", "Library/Preferences",
                         "paid (UUID), paid_v2 (UUID), paid_timestamp",
                         "Google ad-tracking IDs — high-cardinality "
                         "cross-app pivot points.", ""),
                    _row("com.phonepe.dt.sdk.plist", "Device Trust", "Library/Preferences",
                         "<DeviceTrust UUID> = true",
                         "Marker that the PhonePe Device Trust SDK has "
                         "registered this device. Hash points to a server "
                         "device record.", ""),
                    _row("group.com.phonepe.PhonePeApp.appsflyer.remotecontrol.plist",
                         "AppsFlyer install attribution", "Library/Preferences",
                         "id1170055821 + AppsFlyerConfigurationData (bplist)",
                         "AppsFlyer install attribution data: install date, "
                         "campaign ID, referrer.", ""),
                    _row("NxAppState.plist", "Nexus catalogue sync", "Library/Preferences",
                         "NEXUS_CATALOGUE.* lastSyncVersion timestamps",
                         "Sync version timestamps for every catalogue. "
                         "Useful as alibi evidence — proves the app "
                         "successfully synced at a given time.", ""),
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "auth-config",
        "title": "8. Auth, Config & Experiments",
        "intro": (
            "PhonePe distinguishes auth events from generic events for "
            "isolation; both are queued before upload. Configuration and "
            "feature flags live in three places that all need to be examined "
            "together for a complete state snapshot."
        ),
        "blocks": [
            {
                "heading": "Auth events",
                "rows": [
                    _row("ZPPBATCHEVENT", "auth event queue",
                         "AuthFoxtrotEventsBatching/PPAuthFoxtrotEventsDB.sqlite",
                         "ZID, ZTIMESTAMP, ZFAILURECOUNT, ZDATA (bplist of payload)",
                         "Authentication-related events queued before upload. "
                         "Events here that have ZFAILURECOUNT > 0 never "
                         "reached PhonePe servers and exist *only* on device.",
                         "auth_foxtrot_pending | where failure_count > 0"),
                    _row("ZPPBATCHEVENT", "general event queue",
                         "FoxtrotEventsStore/FoxtrotEventsDB.sqlite (group container)",
                         "Same shape as above",
                         "Behavioural analytics events (screen views, taps, "
                         "search queries) queued for upload. Same forensic "
                         "implications.", ""),
                ],
            },
            {
                "heading": "Configuration & A/B testing",
                "rows": [
                    _row("ZKEYVALUESTORE", "feature flags",
                         "ConfigManager/Database/ConfigManagerKeyStore/ConfigManagerKeyStore.sqlite",
                         "ZKEY, ZVALUE (often JSON), ZTEAM, ZORG",
                         "Server-driven configuration keys (chatProperty, "
                         "p2pConfig, txnConfirmationConfig, etc.). Reveals "
                         "which features were enabled for this user.", ""),
                    _row("ZKEYVALUERESPONSE", "Chimera responses",
                         "ChimeraCore/Database/ChimeraCoreResponseStore/ChimeraCoreResponseStore.sqlite",
                         "ZKEYID, ZRESPONSE (JSON), ZMAXVERSION, ZTEAM, ZORG",
                         "Cached server-driven UI specs (homePage, "
                         "nxTravelHome, mutual-fund category pages, KYC "
                         "video config). Confirms which UI version the user "
                         "saw at a point in time.", ""),
                    _row("ZPPEXPERIMENT / ZPPBUCKET", "Athena A/B",
                         "Athena/Database/AthenaStore/AthenaStore.sqlite",
                         "ZEXPERIMENTID, ZBUCKETID, ZSTATEVALUE, "
                         "ZPERCENTAGE, ZSUMMARY, ZSTARTDATE, ZENDTIME",
                         "Active A/B experiments and which bucket the user "
                         "is in. Useful in disputes about which version of "
                         "a flow the user actually saw.", ""),
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "intelligence",
        "title": "9. Intelligence & On-Device ML",
        "intro": (
            "PhonePe ships an on-device document classification model "
            "(Cassini) and a recommendation engine (Maximus). Both leave "
            "useful evidence — when a model fired, what it classified, and "
            "which recommendations it served."
        ),
        "blocks": [
            {
                "heading": "Cassini.sqlite + .mlmodel",
                "body": (
                    "Path: Documents/Cassini/Cassini.sqlite plus "
                    "Documents/Cassini/document_classification/<uuid>/coreML_doc_classification_model_vN.mlmodel. "
                    "ZMODELINFO holds the deployed model's checksum and "
                    "download URL; ZUSECASE the use cases enabled "
                    "(typically KYC document classification)."
                ),
            },
            {
                "heading": "Maximus (Recommendations)",
                "rows": [
                    _row("ZCDPRODUCT", "product", "Maximus/Database/MaximusDataStore/MaximusDataModel.sqlite",
                         "ZPRODUCTID, ZPRODUCTNAME, ZNAMESPACE, "
                         "ZPREFERREDTEMPLATESIZE",
                         "Recommendable products / surfaces available for "
                         "this user.", ""),
                    _row("ZCDRECOMMENDATION", "served recs",
                         "MaximusDataModel.sqlite",
                         "ZITEMID, ZRANK, ZITEMEXPIRY",
                         "Specific item recommendations the user has been "
                         "shown.", ""),
                    _row("ZCDSIGNAL", "user signals", "MaximusDataModel.sqlite",
                         "ZSIGNALTYPE, ZTIMESTAMP, ZISSYNCED, ZRECOMMENDATION (FK)",
                         "Behavioural signals (impression, click, dismiss) "
                         "the user generated against recommendations.", ""),
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "lifecycle",
        "title": "10. Lifecycle, Sync & Compliance",
        "intro": (
            "These tables don't carry payment data themselves but provide "
            "alibi evidence (when did the device last sync?), the user's "
            "consent state (which data the user opted into) and the "
            "background-task log."
        ),
        "blocks": [
            {
                "heading": "Tables",
                "rows": [
                    _row("ZCDSYNCINFO", "sync history",
                         "CentralSyncManager/Database/CentralSyncManager.sqlite",
                         "ZSYNCID, ZSYNCSTATUS, ZLASTSYNCATTEMPTTIME, "
                         "ZLASTSYNCCOMPLETIONTIME",
                         "Per-module sync attempts and completions. Gaps "
                         "in this log reveal offline periods.", ""),
                    _row("ZCDSYNCITEM", "background tasks",
                         "BGFramework/Database/BGFrameworkDataStore/BGFrameworkDataModel.sqlite",
                         "ZIDENTIFIER, ZLASTSYNCTIME",
                         "Each registered background task with its last "
                         "execution time — proves the device was awake on "
                         "the network at that moment.", ""),
                    _row("ZCONSENTACCEPTANCE / ZCONSENTUSER", "consent",
                         "Consent/Consent.sqlite",
                         "ZCONSENTSTATE, ZDESTINATION, ZSUBJECTID, "
                         "ZDEVICEFINGERPRINT, ZPHONENUMBER, ZUSERID",
                         "Per-data-source consent given by the user. "
                         "ZCONSENTUSER also stores the device fingerprint "
                         "used in PhonePe's risk model.", ""),
                    _row("ZLEDGERSYNC", "Chronicle ledger sync",
                         "Chronicle/Database/Chronicle.sqlite",
                         "ZLEDGERID, ZBALANCESYNCSTATUS, ZEXPENSESYNCSTATUS, "
                         "ZLASTBALANCESYNCTIME",
                         "Sync state for split-bill ledgers (Chronicle is "
                         "PhonePe's group-expenses module).", ""),
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "webkit",
        "title": "11. WebKit, Cookies & Web Sessions",
        "intro": (
            "PhonePe uses iOS WKWebView for KYC, payment-gateway redirection "
            "and merchant mini-apps. Cookies, observed domains and IndexedDB "
            "stores are all worth examining."
        ),
        "blocks": [
            {
                "heading": "Cookies.binarycookies",
                "body": (
                    "Path: Library/Cookies/Cookies.binarycookies. Apple's "
                    "binary cookie format. We parse magic / page count / "
                    "page sizes / cookies; expiry and creation use NSDate "
                    "(seconds since 2001-01-01)."
                ),
            },
            {
                "heading": "ResourceLoadStatistics observations.db",
                "body": (
                    "Path: Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db. "
                    "WebKit ITP tracks which domains the user *interacted "
                    "with* (had_user_interaction = 1). For a forensic case, "
                    "this tells you which third-party sites were visited "
                    "via PhonePe's WebView."
                ),
            },
            {
                "heading": "LocalStorage / IndexedDB",
                "body": (
                    "Library/WebKit/WebsiteData/LocalStorage and "
                    "Library/WebKit/WebsiteData/IndexedDB directories — "
                    "if a merchant mini-app has stored state, it lives here."
                ),
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "deletion",
        "title": "12. Deleted Data Recovery",
        "intro": (
            "SQLite never zeroes out free pages. The Database Inventory "
            "view exposes the freelist ratio per database — high "
            "deletion intensity (>20%) is a signal of recent purges. "
            "WAL files (-wal) carry committed-but-not-checkpointed pages "
            "and should always be acquired alongside the main DB."
        ),
        "blocks": [
            {
                "heading": "What we read",
                "list": [
                    "PRAGMA freelist_count + PRAGMA page_count → ratio",
                    "Existence of `-wal` and `-shm` companions",
                    "Soft-delete flags: ZDIDDELETE in ZPHONEBOOKCONTACT, "
                    "ZDISMISSED in ZTRANSACTIONENTITY, "
                    "ZSOFTDELETED in ZGRAVITYFILEINFO, etc.",
                ],
            },
            {
                "heading": "Recovery priority order",
                "list": [
                    "TransactionsStore.sqlite-wal — most-recently committed transactions",
                    "P2P.sqlite-wal — pending P2P metadata",
                    "Burble.sqlite-wal + free pages — chat messages",
                    "FoxtrotEventsDB.sqlite — analytics events about deleted txns may survive here",
                    "Burble notifications and Bullhorn raw_message — push-payload copies",
                    "kn_analytics_db.sqlite — impression events",
                ],
            },
        ],
    },
    # -----------------------------------------------------------------------
    {
        "slug": "ppql",
        "title": "13. Hunting Query Language (PPQL) Reference",
        "intro": (
            "PPQL is a small, SPL-inspired language for searching across "
            "every materialised index in this tool. The Hunting Dashboard "
            "page is its UI; the syntax is documented below."
        ),
        "blocks": [
            {
                "heading": "Syntax",
                "list": [
                    "search \"term\" — full-text across every index",
                    "from <index> | … or just <index> | … — pick a specific index",
                    "| where field op value [and/or …] — filter",
                    "| sort field [asc|desc] — order results",
                    "| head N / | tail N / | limit N — slice",
                    "| top N field — top-N values + counts",
                    "| rare N field — bottom-N values",
                    "| stats count|sum(f)|avg(f)|min(f)|max(f) [by field] — aggregate",
                    "| dedup field — unique by field",
                    "| table f1, f2, … (or | fields …) — choose columns",
                    "| rename old as new — rename a column",
                ],
            },
            {
                "heading": "Operators",
                "list": [
                    "= == != < <= > >= — equality / numeric comparison",
                    "like — glob (case-insensitive, * and ? wildcards)",
                    "matches — Python regex",
                    "contains / startswith / endswith — substring",
                    "in [a, b, c] — set membership",
                    "and / or / not / parentheses — boolean composition",
                ],
            },
            {
                "heading": "Worked examples",
                "list": [
                    "search \"UTR\"",
                    "search \"UTR\" | where amount_inr < 2000",
                    "transactions | where direction = \"OUT\" and amount_inr > 5000 | sort amount_inr desc | head 50 | table created_at_iso, counterparty, amount_inr, utr",
                    "chat_messages | where text_message like \"*petrol*\"",
                    "transactions | where counterparty matches \"[Bb]harath.*\" | stats sum(amount_inr) by counterparty",
                    "contacts | where on_phonepe = true | top 10 region",
                    "timeline | where source = \"Burble\" and when_iso > \"2025-01-01\" | head 200",
                ],
            },
        ],
    },
]
