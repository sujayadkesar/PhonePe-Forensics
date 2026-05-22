"""phonepe_forensics.v2 — coverage, classification, conversation & provenance pipeline.

Separate sub-package so it can be developed and shipped alongside the upstream
PhonePe-Forensics modules without colliding (their `core.py` and `reports.py`
predate this work and remain authoritative for the existing Flask app).

Modules:
    core           bplist, timestamps, UTF-8 stdout, SHA-256
    data_layer     bank master, PhonePe-PSPs, owner, contacts, avatars,
                   conversations, messages, TPAP map, db hashes
    classify       merchant/P2P/mandate classifier + initiation decoder + TPAP
    provenance     forensic provenance envelope
    reconcile      TransactionsStore (+) Burble payment merge with de-dup
    reports        CSV/XLSX/JSONL writers for v2 outputs
    static_export  single-file offline HTML evidence report
"""
__version__ = "1.0.0"
