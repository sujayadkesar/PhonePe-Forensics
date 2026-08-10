"""
PhonePe Android Forensics — Multi-case Manager
=========================================

Provides a JSON-manifest backed registry of forensic cases. Each case is a
named investigation pointing at a directory (or a curated bundle of three
container directories). Cases are loaded into memory on demand.

Design goals:
    * No tight coupling to the workspace folder — cases can live anywhere.
    * A case points at one com.phonepe.app data directory (single-root mode).
    * Cases persist across restarts via .pp_forensics/cases.json
"""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from .case import Case


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _config_dir() -> str:
    base = os.path.join(os.getcwd(), ".pp_forensics")
    os.makedirs(base, exist_ok=True)
    return base


def _registry_path() -> str:
    return os.path.join(_config_dir(), "cases.json")


# ---------------------------------------------------------------------------
# Registry I/O
# ---------------------------------------------------------------------------

def _load_registry() -> Dict[str, Any]:
    p = _registry_path()
    if not os.path.exists(p):
        return {"cases": []}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"cases": []}


def _save_registry(reg: Dict[str, Any]) -> None:
    with open(_registry_path(), "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CaseManager:
    """Manages all known forensic cases and the currently active one."""

    # A loaded case holds the whole parsed acquisition in memory. Without a bound
    # an analyst who opens six cases in a session keeps all six resident.
    MAX_CACHED_CASES = 3

    def __init__(self):
        self._cache: "OrderedDict[str, Case]" = OrderedDict()
        self.active_id: Optional[str] = None

    def _remember(self, case_id: str, case: Case) -> None:
        self._cache[case_id] = case
        self._cache.move_to_end(case_id)
        # Evict least-recently-used, skipping the two cases that must stay: the one
        # being viewed and the one just loaded. Scanning past a protected entry
        # matters — abandoning eviction on the first one (which is what a `break`
        # here did) left the cache unbounded whenever the LRU-oldest case was the
        # active one, so a session that opened six cases kept all six parsed
        # acquisitions resident.
        protected = {self.active_id, case_id}
        while len(self._cache) > self.MAX_CACHED_CASES:
            victim = next((cid for cid in self._cache if cid not in protected), None)
            if victim is None:
                break            # everything left is protected; nothing to drop
            del self._cache[victim]

    # ---- registry queries ----
    def list_cases(self) -> List[Dict[str, Any]]:
        return _load_registry().get("cases", [])

    def get_meta(self, case_id: str) -> Optional[Dict[str, Any]]:
        for c in self.list_cases():
            if c.get("id") == case_id:
                return c
        return None

    # ---- create / delete ----
    def create_case(
        self,
        name: str,
        mode: str = "single_root",
        single_root: Optional[str] = None,
        investigator: Optional[str] = None,
        notes: Optional[str] = None,
        platform: str = "android",
    ) -> Dict[str, Any]:
        """Validate the supplied path, register a case, and return its meta.

        platform: always "android" in this build.
        mode: "single_root" -> the com.phonepe.app data directory.
        """
        case_id = uuid.uuid4().hex[:12]
        meta: Dict[str, Any] = {
            "id": case_id,
            "name": name.strip() or "Untitled case",
            "investigator": investigator or "",
            "notes": notes or "",
            "platform": "android",
            "mode": "single_root",
            "created_at_ms": int(time.time() * 1000),
            "single_root": os.path.abspath(single_root) if single_root else None,
            "status": "registered",
            "validation": {},
        }

        # Validate
        valid, issues, summary = self._validate(meta)
        meta["validation"] = {"valid": valid, "issues": issues, "summary": summary}
        if not valid:
            raise ValueError("Case validation failed: " + "; ".join(issues))

        # Persist
        reg = _load_registry()
        reg["cases"].append(meta)
        _save_registry(reg)
        return meta

    def delete_case(self, case_id: str) -> bool:
        reg = _load_registry()
        before = len(reg.get("cases", []))
        reg["cases"] = [c for c in reg.get("cases", []) if c.get("id") != case_id]
        _save_registry(reg)
        # Forget cached
        self._cache.pop(case_id, None)
        if self.active_id == case_id:
            self.active_id = None
        return len(reg["cases"]) < before

    # ---- load / activate ----
    def load_case(self, case_id: str, on_progress=None) -> Case:
        if case_id in self._cache:
            self.active_id = case_id
            self._cache.move_to_end(case_id)
            return self._cache[case_id]
        meta = self.get_meta(case_id)
        if not meta:
            raise KeyError(f"Unknown case: {case_id}")
        case = self._build_case(meta)
        case.run_full_extraction(on_progress=on_progress)
        # Remember derived metrics on the registry entry
        try:
            d = case.dashboard()
            self._patch_meta(case_id, {
                "status": "loaded",
                "loaded_at_ms": int(time.time() * 1000),
                "metrics": d.get("metrics", {}),
                "subject_name": d.get("identity", {}).get("name"),
                "subject_upi_id": d.get("identity", {}).get("upi_id"),
            })
        except Exception:
            pass
        self.active_id = case_id
        self._remember(case_id, case)
        return case

    def get_active_case(self) -> Optional[Case]:
        if not self.active_id:
            return None
        return self._cache.get(self.active_id)

    def unload_case(self, case_id: str) -> None:
        self._cache.pop(case_id, None)
        if self.active_id == case_id:
            self.active_id = None

    # ---- internals ----
    def _build_case(self, meta: Dict[str, Any]) -> Case:
        # The Android backend is a self-contained Case subclass. Lazy-import to
        # avoid a hard dependency / import cycle at module load.
        from phonepe_android.case_android import AndroidCase
        return AndroidCase(meta["single_root"])

    def _validate(self, meta: Dict[str, Any]) -> tuple:
        issues: List[str] = []
        root = meta.get("single_root")
        if not root or not os.path.isdir(root):
            issues.append(f"Data path is not a directory: {root}")
            return False, issues, {}
        from phonepe_android.core_android import AndroidCasePaths
        ap = AndroidCasePaths(root)
        if not ap.app_dir:
            issues.append("com.phonepe.app data dir (with databases/) not found under the supplied path.")
        elif not ap.db("phonepe_core"):
            issues.append("phonepe_core database not found — not a PhonePe Android extraction.")
        if not ap.shared_prefs_dir:
            issues.append("shared_prefs/ missing — identity/token enrichment will be limited.")
        return (ap.is_valid()), issues, ap.summary()

    def _patch_meta(self, case_id: str, patch: Dict[str, Any]) -> None:
        reg = _load_registry()
        for c in reg.get("cases", []):
            if c.get("id") == case_id:
                c.update(patch)
                break
        _save_registry(reg)


# Singleton manager (one process = one workstation)
manager = CaseManager()
