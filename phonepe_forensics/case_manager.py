"""
PhonePe iOS Forensics — Multi-case Manager
=========================================

Provides a JSON-manifest backed registry of forensic cases. Each case is a
named investigation pointing at a directory (or a curated bundle of three
container directories). Cases are loaded into memory on demand.

Design goals:
    * No tight coupling to the workspace folder — cases can live anywhere.
    * Two modes for case creation:
        1. Single-root mode: pick the parent directory containing all three
           AppDomain* containers (the typical iOS extraction layout).
        2. Three-folder mode: explicitly point each of the three containers
           at a path (useful when the investigator has split exports).
    * Cases persist across restarts via .pp_forensics/cases.json
"""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from typing import Any, Dict, List, Optional

from .case import Case
from .core import CasePaths


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

    def __init__(self):
        self._cache: Dict[str, Case] = {}
        self.active_id: Optional[str] = None

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
        mode: str,
        single_root: Optional[str] = None,
        app_domain: Optional[str] = None,
        group_app: Optional[str] = None,
        group_shared: Optional[str] = None,
        investigator: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate the supplied paths, register a case, and return its meta.

        mode:
            "single_root" -> parent directory containing all three containers
            "three_paths" -> three explicit container paths
        """
        case_id = uuid.uuid4().hex[:12]
        meta: Dict[str, Any] = {
            "id": case_id,
            "name": name.strip() or "Untitled case",
            "investigator": investigator or "",
            "notes": notes or "",
            "mode": mode,
            "created_at_ms": int(time.time() * 1000),
            "single_root": os.path.abspath(single_root) if single_root else None,
            "app_domain": os.path.abspath(app_domain) if app_domain else None,
            "group_app": os.path.abspath(group_app) if group_app else None,
            "group_shared": os.path.abspath(group_shared) if group_shared else None,
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
        self._cache[case_id] = case
        self.active_id = case_id
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
        if meta["mode"] == "single_root":
            return Case(meta["single_root"])
        # three_paths: synthesize a virtual root by symlinking — but symlinks
        # are dicey on Windows. Easier: create a CasePaths-compatible Case.
        return _ThreePathCase(
            meta["app_domain"], meta["group_app"], meta["group_shared"]
        )

    def _validate(self, meta: Dict[str, Any]) -> tuple:
        issues: List[str] = []
        if meta["mode"] == "single_root":
            if not meta["single_root"] or not os.path.isdir(meta["single_root"]):
                issues.append(f"Single-root path is not a directory: {meta['single_root']}")
                return False, issues, {}
            paths = CasePaths(meta["single_root"])
            if not paths.app_domain:
                issues.append(
                    "AppDomain-com.phonepe.PhonePeApp not found inside the supplied root."
                )
            if not paths.group_app:
                issues.append(
                    "AppDomainGroup-group.com.phonepe.PhonePeApp not found — chat & contacts will be unavailable."
                )
            if not paths.group_shared:
                issues.append(
                    "AppDomainGroup-group.com.phonepe.shared not found — cross-app session data will be unavailable."
                )
            return (paths.app_domain is not None), issues, paths.summary()
        else:
            if not meta["app_domain"] or not os.path.isdir(meta["app_domain"]):
                issues.append(f"App domain path is not a directory: {meta['app_domain']}")
            if meta["group_app"] and not os.path.isdir(meta["group_app"]):
                issues.append(f"Group-app path is not a directory: {meta['group_app']}")
            if meta["group_shared"] and not os.path.isdir(meta["group_shared"]):
                issues.append(f"Group-shared path is not a directory: {meta['group_shared']}")
            summary = {
                "app_domain": meta["app_domain"],
                "group_app": meta["group_app"],
                "group_shared": meta["group_shared"],
            }
            return (meta["app_domain"] and os.path.isdir(meta["app_domain"])), issues, summary

    def _patch_meta(self, case_id: str, patch: Dict[str, Any]) -> None:
        reg = _load_registry()
        for c in reg.get("cases", []):
            if c.get("id") == case_id:
                c.update(patch)
                break
        _save_registry(reg)


# ---------------------------------------------------------------------------
# Three-path Case (no single root)
# ---------------------------------------------------------------------------

class _ThreePathCasePaths(CasePaths):
    """CasePaths variant used when the investigator supplies all three
    container paths separately (so there is no shared parent directory)."""

    def __init__(self, app_domain: str, group_app: Optional[str], group_shared: Optional[str]):
        # Skip parent constructor; populate fields directly
        self.root = os.path.dirname(app_domain) if app_domain else os.getcwd()
        self.app_domain = os.path.abspath(app_domain) if app_domain else None
        self.group_app = os.path.abspath(group_app) if group_app else None
        self.group_shared = os.path.abspath(group_shared) if group_shared else None


class _ThreePathCase(Case):
    def __init__(self, app_domain: str, group_app: Optional[str], group_shared: Optional[str]):
        # Synthesize a CasePaths and skip the file-system probe in Case.__init__
        self.root = os.path.dirname(app_domain) if app_domain else os.getcwd()
        self.paths = _ThreePathCasePaths(app_domain, group_app, group_shared)
        self.data: Dict[str, Any] = {
            "_meta": {
                "case_root": self.root,
                "loaded_at": int(time.time() * 1000),
                "containers": self.paths.summary(),
                "three_path_mode": True,
            }
        }
        self._extracted = False
        self._timeline = None
        self._social_graph = None
        self._findings = None


# Singleton manager (one process = one workstation)
manager = CaseManager()
