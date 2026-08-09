#!/usr/bin/env python3
"""Headless end-to-end test of one PhonePe Android acquisition.

Exercises the whole pipeline without a browser, because the 74 Flask routes are
the slow way to find a parsing problem:

    1. AndroidCase(root).validate()
    2. run_full_extraction()  — per-extractor wall time
    3. extraction_errors() + schema_gaps()   <- THE test result. These exist
       precisely for "PhonePe renamed a Room column, so the page renders empty
       as though the data were never there".
    4. derived views: dashboard / timeline / findings / social_graph /
       corroboration / hunt_indexes / sms_corroboration
    5. export_all() into a scratch dir
    6. every parameterless GET route through app.test_client()

Usage:
    python notes/smoke_test.py <case_root> [--export DIR] [--no-web] [--json OUT]

<case_root> is the directory that CONTAINS com.phonepe.app/databases/phonepe_core
(or the com.phonepe.app dir itself). A bare database file is NOT accepted by the
tool — stage it first; see CONTINUE.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _hr(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_root")
    ap.add_argument("--export", default=None, help="export_all() into this dir")
    ap.add_argument("--no-web", action="store_true", help="skip the route sweep")
    ap.add_argument("--json", default=None, help="write the machine-readable result here")
    args = ap.parse_args()

    root = os.path.abspath(args.case_root)
    result = {"case_root": root}

    from phonepe_android.case_android import AndroidCase
    from phonepe_forensics.core import schema_gaps

    # ---- 1. layout validation -------------------------------------------------
    _hr("1. LAYOUT")
    case = AndroidCase(root)
    v = case.validate()
    print(json.dumps(v, indent=2, default=str))
    result["validate"] = v
    if not v["valid"]:
        print("\n!! layout invalid — phonepe_core not found. Stage the DB first "
              "(see CONTINUE.md). Aborting.")
        return 2

    # ---- 2. extraction, timed per module -------------------------------------
    _hr("2. EXTRACTION")
    timings = {}
    state = {"name": None, "t0": None}

    def on_progress(name, i, total):
        now = time.perf_counter()
        if state["name"]:
            timings[state["name"]] = round(now - state["t0"], 3)
        state["name"], state["t0"] = name, now
        print(f"  [{i:>2}/{total}] {name}", flush=True)

    t_all = time.perf_counter()
    case.run_full_extraction(on_progress=on_progress)
    if state["name"]:
        timings[state["name"]] = round(time.perf_counter() - state["t0"], 3)
    total_s = round(time.perf_counter() - t_all, 2)
    print(f"\n  total {total_s}s — slowest modules:")
    for name, secs in sorted(timings.items(), key=lambda kv: -kv[1])[:8]:
        print(f"    {secs:>8.3f}s  {name}")
    result["timings_s"] = timings
    result["total_s"] = total_s

    # ---- 3. health: what failed or degraded ----------------------------------
    _hr("3. EXTRACTION HEALTH  (empty = every module read cleanly)")
    errors = case.extraction_errors()
    for e in errors:
        print(f"  [{e['severity']:>8}] {e['module']}: {e['detail'][:220]}")
    print(f"  -> {len(errors)} issue(s)")
    result["extraction_errors"] = errors

    gaps = schema_gaps(case.root)
    print(f"\n  schema gaps (requested column absent from THIS acquisition): {len(gaps)}")
    for g in gaps:
        print(f"    {g['database']}.{g['table']}: {', '.join(g['missing_columns'])}")
    result["schema_gaps"] = gaps

    warn = case.evidence_warnings()
    print(f"\n  evidence warnings (WAL excluded etc.): {len(warn)}")
    for w in warn:
        print(f"    {w}")
    result["evidence_warnings"] = warn

    print(f"\n  manifest (hashed before parsing): {len(case.evidence_manifest())} file(s)")
    for m in case.evidence_manifest():
        print(f"    {os.path.basename(m['original'])}  {m['sha256'][:16]}…  "
              f"{m['opened_via']}  wal={m['wal_present']}")

    # ---- 4. per-module row counts --------------------------------------------
    _hr("4. WHAT WAS PARSED")
    counts = {}
    for mod, payload in sorted(case.data.items()):
        if mod.startswith("_") or not isinstance(payload, dict):
            continue
        summary = payload.get("summary")
        if isinstance(summary, dict) and summary:
            counts[mod] = {k: v for k, v in summary.items()
                           if isinstance(v, (int, float)) and not isinstance(v, bool)}
    for mod, c in counts.items():
        if c:
            print(f"  {mod:<18} " + "  ".join(f"{k}={v}" for k, v in list(c.items())[:6]))
    result["module_counts"] = counts

    # ---- 5. derived views ----------------------------------------------------
    _hr("5. DERIVED VIEWS")
    derived = {}
    for label, fn in (
        ("dashboard", lambda: case.dashboard()),
        ("timeline", lambda: case.timeline(limit=999999)),
        ("findings", lambda: case.findings()),
        ("social_graph", lambda: case.social_graph()),
        ("corroboration", lambda: case.corroboration()),
        ("hunt_indexes", lambda: case.hunt_indexes()),
        ("sms_corroboration", lambda: case.sms_corroboration()),
        ("custody_record", lambda: case.custody_record({"name": "smoke-test"})),
    ):
        t0 = time.perf_counter()
        try:
            out = fn()
            secs = round(time.perf_counter() - t0, 3)
            if isinstance(out, list):
                size = f"{len(out)} rows"
            elif isinstance(out, dict) and "nodes" in out:
                size = f"{len(out['nodes'])} nodes"
            elif isinstance(out, dict) and "items" in out:
                size = f"{len(out['items'])} items"
            elif isinstance(out, dict):
                size = f"{len(out)} keys"
            else:
                size = type(out).__name__
            print(f"  OK   {label:<18} {size:<16} {secs}s")
            derived[label] = {"ok": True, "size": size, "seconds": secs}
        except Exception as exc:
            print(f"  FAIL {label:<18} {type(exc).__name__}: {exc}")
            traceback.print_exc()
            derived[label] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    result["derived"] = derived

    print("\n  findings:")
    for f in case.findings():
        print(f"    [{f.get('severity'):>6}] {f.get('category')}: {str(f.get('title'))[:150]}")

    print("\n  PPQL indexes:")
    for name, rows in sorted(case.hunt_indexes().items()):
        print(f"    {name:<24} {len(rows)}")

    # ---- 6. a couple of real PPQL queries ------------------------------------
    _hr("6. PPQL")
    from phonepe_forensics import hunt
    for q in ('transactions | stats count by direction',
              'transactions | sort amount_inr desc | head 5 | table created_at_iso, counterparty, amount_inr, direction',
              'timeline | stats count by source',
              'deleted_records | stats count by table'):
        try:
            r = hunt.run_query(q, case.hunt_indexes())
            if r.get("error"):
                print(f"  ERR  {q}\n       {r['error']}")
            else:
                print(f"  OK   {q}  -> {len(r['rows'])} row(s)")
                for row in r["rows"][:5]:
                    print(f"         {row}")
        except Exception as exc:
            print(f"  FAIL {q}: {type(exc).__name__}: {exc}")

    # ---- 7. export -----------------------------------------------------------
    if args.export:
        _hr("7. EXPORT")
        t0 = time.perf_counter()
        info = case.export_all(base_dir=args.export, meta={"name": "smoke-test",
                                                           "investigator": "smoke_test.py"})
        print(json.dumps(info, indent=2, default=str)[:2000])
        print(f"  {round(time.perf_counter() - t0, 2)}s")
        result["export"] = info

    # ---- 8. route sweep ------------------------------------------------------
    if not args.no_web:
        _hr("8. ROUTES  (Flask test client, active case injected)")
        from phonepe_forensics.case_manager import manager
        from phonepe_forensics.webapp import app
        manager._cache["smoke"] = case
        manager.active_id = "smoke"

        # Parameterised routes need real ids from the parsed case.
        subs = {}
        txns = case.data.get("transactions", {}).get("transactions", [])
        if txns:
            subs["txn_id"] = txns[0].get("global_payment_id") or txns[0].get("entity_id")
        groups = case.data.get("chat", {}).get("groups", [])
        if groups:
            subs["group_id"] = groups[0].get("group_id")
        raw = case.data.get("raw_tables", {}).get("databases", {})
        for dbn, tables in raw.items():
            live = [t for t, info in tables.items()
                    if isinstance(info, dict) and (info.get("row_count") or 0) > 0]
            if live:
                subs["db"], subs["table"] = dbn, live[0]
                break
        subs.setdefault("kind", "rewards")
        subs.setdefault("platform", "android")

        # Endpoints that need a value the generic substitution cannot guess: a
        # per-endpoint <kind>, or a required query parameter without which the
        # route correctly answers 400/404. Supplying them is the difference
        # between testing the endpoint and testing its argument validation.
        endpoint_args = {
            "export_config_csv": {"kind": "keys"},
            "export_financial_csv": {"kind": "rewards"},
        }
        endpoint_query = {
            "api_blob": f"id={subs.get('txn_id', '')}",
            "api_file": f"p={case.paths.db('phonepe_core') or ''}",
            "export_hunt_csv": "q=transactions+%7C+head+3",
        }

        failures = []
        checked = 0
        with app.test_client() as client:
            for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
                if "GET" not in rule.methods or rule.endpoint == "static":
                    continue
                values = {**subs, **endpoint_args.get(rule.endpoint, {})}
                try:
                    url = rule.build(
                        {a: values[a] for a in rule.arguments if a in values},
                        append_unknown=False)[1] if rule.arguments else str(rule)
                except Exception:
                    print(f"  skip {rule} (no substitution for {sorted(rule.arguments)})")
                    continue
                if any(a not in values for a in rule.arguments):
                    print(f"  skip {rule} (missing "
                          f"{sorted(a for a in rule.arguments if a not in values)}"
                          f"{'; covered by step 9' if rule.endpoint == 'page_case_detail' else ''})")
                    continue
                query = endpoint_query.get(rule.endpoint)
                if query:
                    url = f"{url}?{query}"
                # Re-assert the active case before every request: /start and
                # /start/<platform> deliberately clear manager.active_id, which
                # otherwise makes every later page redirect to /cases and look
                # like a failure.
                manager.active_id = "smoke"
                try:
                    resp = client.get(url)
                except Exception as exc:
                    failures.append((url, f"raised {type(exc).__name__}: {exc}"))
                    print(f"  RAISE {url}: {exc}")
                    continue
                checked += 1
                flag = "OK  " if resp.status_code < 400 else "FAIL"
                if resp.status_code >= 400:
                    failures.append((url, resp.status_code))
                print(f"  {flag} {resp.status_code} {url}")
            # the two query-driven pages
            for url in ("/hunt?q=transactions+%7C+head+5",
                        "/counterparty?q=a",
                        "/timeline?limit=100",
                        "/transactions?direction=OUT&sort=amount_desc",
                        "/transactions/export.csv",
                        "/deleted/export.csv",
                        "/timeline/export.csv"):
                manager.active_id = "smoke"
                resp = client.get(url)
                checked += 1
                if resp.status_code >= 400:
                    failures.append((url, resp.status_code))
                print(f"  {'OK  ' if resp.status_code < 400 else 'FAIL'} "
                      f"{resp.status_code} {url}")
        print(f"\n  {checked} route(s) checked, {len(failures)} failure(s)")
        for url, why in failures:
            print(f"    {why}  {url}")
        result["route_failures"] = [{"url": u, "why": str(w)} for u, w in failures]

        # ---- 9. the registry path a human actually uses --------------------
        # "+ New Case -> point at the folder -> Process" goes through
        # create_case() validation, the cases.json write, load_case() (a SECOND
        # full extraction) and _patch_meta(). Injecting into manager._cache
        # bypasses all of it, so it has to be exercised explicitly.
        # NOTE: this re-extracts, so it roughly doubles the run time.
        _hr("9. REGISTRY PATH  (create -> process -> activate -> delete)")
        print(f"  .pp_forensics/ will be written under cwd: {os.getcwd()}")
        reg = {}
        try:
            meta = manager.create_case(name="smoke-test", single_root=root,
                                       investigator="smoke_test.py")
            print(f"  created  id={meta['id']} status={meta['status']} "
                  f"valid={meta['validation']['valid']} issues={meta['validation']['issues']}")
            loaded = manager.load_case(meta["id"])
            print(f"  loaded   txns={len(loaded.data.get('transactions', {}).get('transactions', []))}")
            after = manager.get_meta(meta["id"])
            print(f"  registry status={after.get('status')} subject_set="
                  f"{bool(after.get('subject_name'))} metrics_keys={len(after.get('metrics') or {})}")
            with app.test_client() as cl:
                for url in ("/cases", f"/cases/{meta['id']}", "/"):
                    r = cl.get(url)
                    print(f"  {'OK  ' if r.status_code < 400 else 'FAIL'} "
                          f"{r.status_code} {url}")
                    if r.status_code >= 400:
                        result.setdefault("route_failures", []).append(
                            {"url": url, "why": r.status_code})
            reg = {"ok": True, "case_id": meta["id"],
                   "validation": meta["validation"], "registry_after": after}
        except Exception as exc:
            print(f"  FAIL {type(exc).__name__}: {exc}")
            traceback.print_exc()
            reg = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            try:
                if reg.get("case_id"):
                    manager.delete_case(reg["case_id"])
                    print(f"  deregistered {reg['case_id']} "
                          f"(evidence folders untouched)")
            except Exception as exc:
                print(f"  cleanup failed: {exc}")
        result["registry_path"] = reg

    _hr("SUMMARY")
    # Absent-source degradations ("RecommendationsDatabase not found") are facts
    # about the acquisition, not defects, so they must not make a healthy run
    # report failure — otherwise the signal gets trained away.
    hard_errors = [e for e in result.get("extraction_errors", [])
                   if e.get("severity") == "failed"]
    bad = (len(hard_errors)
           + len(result.get("route_failures", []))
           + sum(1 for d in result.get("derived", {}).values() if not d.get("ok"))
           + (0 if result.get("registry_path", {"ok": True}).get("ok") else 1))
    print(f"  module failures   : {len(hard_errors)}  (hard)")
    print(f"  degradations      : "
          f"{len(result.get('extraction_errors', [])) - len(hard_errors)}  "
          f"(absent sources / schema gaps — informational)")
    print(f"  schema gaps       : {len(result.get('schema_gaps', []))}")
    print(f"  derived failures  : {sum(1 for d in result.get('derived', {}).values() if not d.get('ok'))}")
    print(f"  route failures    : {len(result.get('route_failures', []))}")
    print(f"  extraction time   : {total_s}s")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"\n  machine-readable result -> {args.json}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
