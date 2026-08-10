"""
PhonePe Forensics — iOS-only parsing primitives
===============================================
Apple container formats. None of this is reachable from an Android acquisition;
it is kept separate so the Android build does not carry it and an upstream fix to
either platform does not disturb the other.

    read_plist / flatten_plist   Apple plist (binary + XML)
    BinaryCookieReader           Library/Cookies/Cookies.binarycookies
    decode_nskeyedarchiver       NSKeyedArchiver bplist -> Python structures
    safe_decode_blob             best-effort BLOB decode (bplist / JSON / text)
    CasePaths                    the three iOS AppDomain containers
"""
from __future__ import annotations

import os
import plistlib
import struct
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from .common import (
    APPLE_EPOCH_OFFSET, NSDATE_REASONABLE_MAX, NSDATE_REASONABLE_MIN,
    _to_dt, find_files,
)

# ---------------------------------------------------------------------------
# Plist reader (binary + XML)
# ---------------------------------------------------------------------------

def read_plist(path: str) -> Optional[Any]:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def flatten_plist(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Flatten a possibly-nested plist into dotted keys, scalars only."""
    if out is None:
        out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten_plist(v, key, out)
    elif isinstance(value, list):
        for idx, v in enumerate(value):
            flatten_plist(v, f"{prefix}[{idx}]", out)
    elif isinstance(value, (bytes, bytearray)):
        # try secondary bplist decode
        try:
            decoded = plistlib.loads(bytes(value))
            flatten_plist(decoded, prefix + ".__bplist", out)
        except Exception:
            out[prefix] = f"<bytes:{len(value)}>"
    elif isinstance(value, datetime):
        out[prefix] = value.strftime("%Y-%m-%d %H:%M:%S")
    else:
        out[prefix] = value
    return out


# ---------------------------------------------------------------------------
# Cookies.binarycookies parser (Apple binary cookie format)
# ---------------------------------------------------------------------------

class BinaryCookieReader:
    """Parser for Apple Library/Cookies/Cookies.binarycookies.

    Format reference: a public reverse-engineered spec. We implement a robust
    subset: magic, page count, page sizes, page header, cookies. Each cookie
    has cookie size, flags, url-offset, name-offset, path-offset, value-offset,
    expiry (Mac absolute time), creation (Mac absolute time), and four CSTRINGs.
    """

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.cookies: List[Dict[str, Any]] = []
        self._parse()

    def _read_cstring(self, offset: int) -> str:
        end = self.data.index(b"\x00", offset)
        return self.data[offset:end].decode("utf-8", errors="replace")

    def _parse(self):
        if len(self.data) < 12 or self.data[:4] != b"cook":
            return
        num_pages = struct.unpack(">I", self.data[4:8])[0]
        page_sizes = [
            struct.unpack(">I", self.data[8 + 4 * i: 8 + 4 * i + 4])[0] for i in range(num_pages)
        ]
        cursor = 8 + 4 * num_pages
        for size in page_sizes:
            page = self.data[cursor:cursor + size]
            cursor += size
            self._parse_page(page)

    def _parse_page(self, page: bytes):
        if len(page) < 12 or page[:4] != b"\x00\x00\x01\x00":
            return
        num_cookies = struct.unpack("<I", page[4:8])[0]
        cookie_offsets = [
            struct.unpack("<I", page[8 + 4 * i: 8 + 4 * i + 4])[0] for i in range(num_cookies)
        ]
        for off in cookie_offsets:
            self._parse_cookie(page, off)

    def _parse_cookie(self, page: bytes, offset: int):
        if offset + 56 > len(page):
            return
        size = struct.unpack("<I", page[offset:offset + 4])[0]
        if offset + size > len(page):
            return
        flags = struct.unpack("<I", page[offset + 8:offset + 12])[0]
        url_off = struct.unpack("<I", page[offset + 16:offset + 20])[0]
        name_off = struct.unpack("<I", page[offset + 20:offset + 24])[0]
        path_off = struct.unpack("<I", page[offset + 24:offset + 28])[0]
        value_off = struct.unpack("<I", page[offset + 28:offset + 32])[0]
        # 8 reserved bytes here in spec, then 8-byte expiry double, 8-byte creation double
        expiry = struct.unpack("<d", page[offset + 40:offset + 48])[0]
        creation = struct.unpack("<d", page[offset + 48:offset + 56])[0]

        def _safe_cstr(rel: int) -> str:
            try:
                end = page.index(b"\x00", offset + rel)
                return page[offset + rel:end].decode("utf-8", errors="replace")
            except ValueError:
                return ""

        flag_names = []
        if flags & 0x1: flag_names.append("Secure")
        if flags & 0x4: flag_names.append("HTTPOnly")

        self.cookies.append({
            "domain": _safe_cstr(url_off),
            "name": _safe_cstr(name_off),
            "path": _safe_cstr(path_off),
            "value": _safe_cstr(value_off),
            "flags": flag_names,
            "expiry_iso": _to_dt(expiry + APPLE_EPOCH_OFFSET).strftime("%Y-%m-%d %H:%M:%S") if NSDATE_REASONABLE_MIN < expiry < NSDATE_REASONABLE_MAX else None,
            "creation_iso": _to_dt(creation + APPLE_EPOCH_OFFSET).strftime("%Y-%m-%d %H:%M:%S") if NSDATE_REASONABLE_MIN < creation < NSDATE_REASONABLE_MAX else None,
            "expiry_epoch": expiry,
            "creation_epoch": creation,
        })


# ---------------------------------------------------------------------------
# NSKeyedArchiver bplist decoder
# ---------------------------------------------------------------------------

class _Uid:
    __slots__ = ("value",)

    def __init__(self, v):
        self.value = v


def _resolve(obj: Any, objects: List[Any], seen: Optional[set] = None) -> Any:
    if seen is None:
        seen = set()
    if isinstance(obj, plistlib.UID):
        if obj.data in seen:
            return f"<cycle:{obj.data}>"
        seen = seen | {obj.data}
        return _resolve(objects[obj.data], objects, seen)
    if isinstance(obj, dict):
        if "$class" in obj and "NS.keys" in obj and "NS.objects" in obj:
            keys = [_resolve(k, objects, seen) for k in obj["NS.keys"]]
            vals = [_resolve(v, objects, seen) for v in obj["NS.objects"]]
            return dict(zip(keys, vals))
        if "$class" in obj and "NS.objects" in obj:
            return [_resolve(v, objects, seen) for v in obj["NS.objects"]]
        if "$class" in obj and "NS.string" in obj:
            return _resolve(obj["NS.string"], objects, seen)
        return {k: _resolve(v, objects, seen) for k, v in obj.items() if k != "$class"}
    if isinstance(obj, list):
        return [_resolve(v, objects, seen) for v in obj]
    if isinstance(obj, bytes):
        # try nested bplist
        try:
            inner = plistlib.loads(obj)
            if isinstance(inner, dict) and inner.get("$archiver") == "NSKeyedArchiver":
                return decode_nskeyedarchiver(obj)
        except Exception:
            pass
        return obj
    return obj


def decode_nskeyedarchiver(blob: bytes) -> Any:
    """Decode an NSKeyedArchiver bplist BLOB into a plain Python structure."""
    if not blob:
        return None
    try:
        plist = plistlib.loads(bytes(blob))
    except Exception:
        return None
    if not isinstance(plist, dict) or plist.get("$archiver") != "NSKeyedArchiver":
        return plist
    objects = plist.get("$objects", [])
    top = plist.get("$top", {})
    if not isinstance(top, dict):
        return plist
    root_uid = top.get("root")
    if isinstance(root_uid, plistlib.UID):
        return _resolve(root_uid, objects)
    return _resolve(top, objects)


def safe_decode_blob(blob: Any) -> Any:
    """Safely decode a SQLite BLOB column.

    Tries (in order): NSKeyedArchiver, regular bplist, JSON, raw text.
    Returns the Python representation or a {'_raw': len, '_hex': preview} stub.
    """
    if blob is None:
        return None
    if isinstance(blob, str):
        # already string — try JSON
        s = blob.strip()
        if s and s[0] in "{[":
            try:
                import json
                return json.loads(s)
            except Exception:
                return blob
        return blob
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return blob
    raw = bytes(blob)
    if not raw:
        return None
    # NSKeyedArchiver?
    if raw[:8] == b"bplist00":
        decoded = decode_nskeyedarchiver(raw)
        if decoded is not None:
            return decoded
        try:
            return plistlib.loads(raw)
        except Exception:
            pass
    # JSON?
    try:
        return _try_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    # Last-resort hex preview
    return {"_raw_size": len(raw), "_hex_preview": raw[:64].hex()}


def _try_json(text: str) -> Any:
    import json
    text = text.strip()
    if not text:
        return text
    if text[0] in "{[":
        return json.loads(text)
    return text


# ---------------------------------------------------------------------------
# Path resolver
# ---------------------------------------------------------------------------

class CasePaths:
    """Locate the three iOS containers and resolve known artifact paths.

    Initialise with the parent directory containing the AppDomain* folders
    (or pass the AppDomain folder directly). The resolver finds the three
    canonical containers regardless of the parent's casing/structure.
    """

    AD = "AppDomain-com.phonepe.PhonePeApp"
    ADG_APP = "AppDomainGroup-group.com.phonepe.PhonePeApp"
    ADG_SHARED = "AppDomainGroup-group.com.phonepe.shared"

    def __init__(self, root: str):
        root = os.path.abspath(root)
        self.root = root
        self.app_domain = self._find_container(root, self.AD)
        self.group_app = self._find_container(root, self.ADG_APP)
        self.group_shared = self._find_container(root, self.ADG_SHARED)

    @staticmethod
    def _find_container(root: str, name: str) -> Optional[str]:
        # Direct path
        cand = os.path.join(root, name)
        if os.path.isdir(cand):
            return cand
        # Walk one level up
        parent = os.path.dirname(root)
        if parent and parent != root:
            cand = os.path.join(parent, name)
            if os.path.isdir(cand):
                return cand
        # Walk from root
        for entry in os.listdir(root) if os.path.isdir(root) else []:
            full = os.path.join(root, entry)
            if entry == name and os.path.isdir(full):
                return full
        return None

    def is_valid(self) -> bool:
        return all([self.app_domain, self.group_app or self.group_shared])

    def documents(self) -> Optional[str]:
        return os.path.join(self.app_domain, "Documents") if self.app_domain else None

    def preferences(self) -> Optional[str]:
        return os.path.join(self.app_domain, "Library", "Preferences") if self.app_domain else None

    def cookies_path(self) -> Optional[str]:
        if not self.app_domain:
            return None
        p = os.path.join(self.app_domain, "Library", "Cookies", "Cookies.binarycookies")
        return p if os.path.exists(p) else None

    def webkit_dir(self) -> Optional[str]:
        if not self.app_domain:
            return None
        p = os.path.join(self.app_domain, "Library", "WebKit")
        return p if os.path.isdir(p) else None

    def resolve(self, *parts: str) -> Optional[str]:
        if not self.app_domain:
            return None
        path = os.path.join(self.app_domain, *parts)
        return path if os.path.exists(path) else None

    def group(self, *parts: str) -> Optional[str]:
        if not self.group_app:
            return None
        path = os.path.join(self.group_app, *parts)
        return path if os.path.exists(path) else None

    def all_sqlites(self) -> List[str]:
        out: List[str] = []
        for base in (self.app_domain, self.group_app, self.group_shared):
            if base:
                out.extend(find_files(base, [".sqlite", ".db"]))
        return out

    def all_plists(self) -> List[str]:
        out: List[str] = []
        for base in (self.app_domain, self.group_app, self.group_shared):
            if base:
                out.extend(find_files(base, [".plist"]))
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "app_domain": self.app_domain,
            "group_app": self.group_app,
            "group_shared": self.group_shared,
            "valid": self.is_valid(),
            "sqlite_count": len(self.all_sqlites()),
            "plist_count": len(self.all_plists()),
        }
