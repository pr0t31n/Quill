"""Storage Analysis phase — inspect app data for insecure storage and residual data."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from phases.base import GateType, Phase, PhaseResult, UserGate

_SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\b'), "password"),
    (re.compile(r'(?i)(access_?token|auth_?token|bearer|jwt)\b'), "auth token"),
    (re.compile(r'(?i)(session_?id|session_?key|session_?token)\b'), "session token"),
    (re.compile(r'(?i)(api_?key|api_?secret|client_?secret)\b'), "API key"),
    (re.compile(r'(?i)(private_?key|signing_?key|encryption_?key)\b'), "private key"),
    (re.compile(r'(?i)(ssn|social_?security)\b'), "SSN"),
    (re.compile(r'(?i)(credit_?card|card_?number|cvv|ccnum)\b'), "credit card"),
    (re.compile(r'(?i)(refresh_?token)\b'), "refresh token"),
    (re.compile(r'(?i)(pin_?code|passcode|mfa_?code|otp)\b'), "PIN/MFA code"),
    (re.compile(r'(?i)(secret|credential)\b'), "credential"),
]

_SENSITIVE_VALUES = [
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),  # JWT
    re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}'),  # bearer token
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # base64 long enough to be a key
]

_SENSITIVE_SQLITE_COLS = {
    "password", "passwd", "pwd", "token", "access_token", "auth_token",
    "refresh_token", "session_id", "session_token", "api_key", "api_secret",
    "secret", "private_key", "ssn", "credit_card", "card_number", "cvv",
    "pin", "otp", "mfa_code", "bearer", "jwt", "credential",
}


class StoragePhase(Phase):

    @property
    def name(self) -> str:
        return "storage"

    @property
    def display_name(self) -> str:
        return "Storage Analysis"

    @property
    def description(self) -> str:
        return ("Pull and inspect the app's data directory for insecure "
                "storage, plaintext credentials, and residual data after logout.")

    @property
    def order(self) -> int:
        return 400

    @property
    def requires_device(self) -> bool:
        return True

    @property
    def requires_root(self) -> bool:
        return True

    def __init__(self):
        super().__init__()
        self._baseline_size: int = 0
        self._post_auth_snapshot: Optional[Path] = None
        self._auth_token_keys: set[str] = set()

    def _get_data_dir_size(self) -> int:
        data_dir = self._device.get_app_data_dir(self.package)
        if not data_dir:
            return 0
        rc, out, _ = self._device.shell(f"du -s {data_dir}", root=True, timeout=15)
        if rc == 0 and out.strip():
            try:
                return int(out.strip().split()[0])
            except (ValueError, IndexError):
                pass
        return 0

    def _check_data_grew(self) -> bool:
        current = self._get_data_dir_size()
        return current > self._baseline_size + 4

    def _check_auth_gone(self) -> bool:
        if not self._auth_token_keys or not self._device:
            return False
        data_dir = self._device.get_app_data_dir(self.package)
        if not data_dir:
            return False
        for key in self._auth_token_keys:
            rc, out, _ = self._device.shell(
                f"grep -rl '{key}' {data_dir}/shared_prefs/ 2>/dev/null",
                root=True, timeout=10)
            if rc == 0 and out.strip():
                return False
        return True

    def pre_gates(self) -> list[UserGate]:
        self._baseline_size = self._get_data_dir_size()
        return [UserGate(
            instruction=(
                "Log into the app and use it normally — navigate key "
                "features, enter data, grant permissions if prompted. "
                "Press Done when ready for the post-auth snapshot."
            ),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=self._check_data_grew,
            auto_detect_interval=5.0,
            auto_detect_timeout=300.0,
            prompt_id="storage_post_auth",
        )]

    def post_gates(self) -> list[UserGate]:
        return [UserGate(
            instruction=(
                "Log OUT of the app now. Press Done when the logout "
                "is complete."
            ),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=self._check_auth_gone,
            auto_detect_interval=5.0,
            auto_detect_timeout=180.0,
            prompt_id="storage_post_logout",
        )]

    def run(self) -> PhaseResult:
        findings = 0
        out_dir = self.phase_dir()

        self.status("Storage Analysis", "running", "post-auth snapshot")
        self.log("[storage] Taking post-auth snapshot...")
        self._post_auth_snapshot = self._device.snapshot_app_data(
            self.package, str(out_dir), label="post_auth")
        if not self._post_auth_snapshot:
            self.err("[storage] Failed to snapshot app data directory")
            return PhaseResult(phase_name=self.name, success=False,
                               error="Cannot pull app data directory")

        self.log(f"[storage] Post-auth snapshot at {self._post_auth_snapshot}")
        self.check_pause()

        self.status("Storage Analysis", "running", "shared preferences")
        findings += self._inspect_shared_prefs(self._post_auth_snapshot, out_dir)
        self.check_pause()

        self.status("Storage Analysis", "running", "SQLite databases")
        findings += self._inspect_databases(self._post_auth_snapshot, out_dir)
        self.check_pause()

        self.status("Storage Analysis", "running", "file permissions")
        findings += self._check_file_permissions(out_dir)
        self.check_pause()

        self.status("Storage Analysis", "running", "cache inspection")
        findings += self._inspect_cache(self._post_auth_snapshot, out_dir)
        self.check_pause()

        self._context["_storage_post_auth"] = str(self._post_auth_snapshot)
        self._context["_storage_auth_keys"] = list(self._auth_token_keys)

        return PhaseResult(phase_name=self.name, success=True,
                           findings_count=findings)

    def teardown(self) -> None:
        if not self._post_auth_snapshot or not self._device:
            return
        out_dir = self.phase_dir()
        self.status("Storage Analysis", "running", "post-logout snapshot")
        self.log("[storage] Taking post-logout snapshot...")
        post_logout = self._device.snapshot_app_data(
            self.package, str(out_dir), label="post_logout")
        if post_logout and self._post_auth_snapshot:
            count = self._diff_snapshots(
                self._post_auth_snapshot, post_logout, out_dir)
            if count:
                self.log(f"[storage] {count} residual data finding(s) after logout")

    # ── shared_prefs ──────────────────────────────────────────────────

    def _inspect_shared_prefs(self, snapshot: Path, out_dir: Path) -> int:
        findings = 0
        prefs_dir = self._find_subdir(snapshot, "shared_prefs")
        if not prefs_dir:
            if self.platform == "ios":
                prefs_dir = self._find_subdir(snapshot, "Library/Preferences")
            if not prefs_dir:
                self.log("[storage] No shared_prefs / Preferences directory found")
                return 0

        for f in prefs_dir.rglob("*"):
            if not f.is_file():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel = str(f.relative_to(snapshot))
            hits: list[tuple[str, str]] = []

            if f.suffix == ".xml":
                hits.extend(self._scan_xml_prefs(text, rel))
            elif f.suffix == ".plist":
                hits.extend(self._scan_plist(text, rel))
            else:
                hits.extend(self._scan_text(text, rel))

            for matched_type, evidence in hits:
                ev_file = out_dir / f"evidence_{f.stem}_{matched_type}.txt"
                ev_file.write_text(evidence, encoding="utf-8")
                if "password" in matched_type or "credential" in matched_type:
                    self.finding(
                        title="Credentials Stored in Plaintext",
                        severity="CRITICAL",
                        description=(
                            f"Plaintext {matched_type} found in {rel}. "
                            f"Credentials stored without encryption can be "
                            f"extracted by any process with local access."
                        ),
                        catalogue_id="QUILL-STR-006",
                        output_file=str(ev_file.relative_to(self._output_dir)),
                        affected=rel,
                    )
                    findings += 1
                else:
                    self.finding(
                        title="Sensitive Data in Shared Preferences",
                        severity="HIGH",
                        description=(
                            f"{matched_type.title()} found in {rel}. "
                            f"Shared preferences are stored as plaintext XML "
                            f"readable by any process with root access."
                        ),
                        catalogue_id="QUILL-STR-001",
                        output_file=str(ev_file.relative_to(self._output_dir)),
                        affected=rel,
                    )
                    findings += 1
                    if "token" in matched_type or "session" in matched_type:
                        self._auth_token_keys.add(matched_type)

        return findings

    def _scan_xml_prefs(self, text: str, source: str) -> list[tuple[str, str]]:
        hits = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return self._scan_text(text, source)
        for elem in root.iter():
            key = elem.get("name", "")
            val = elem.text or ""
            for pat, label in _SENSITIVE_PATTERNS:
                if pat.search(key):
                    hits.append((label, f"File: {source}\nKey: {key}\nValue: {val[:200]}"))
                    break
            if not hits or hits[-1][1].split("\n")[1].split(":")[1].strip() != key:
                for vpat in _SENSITIVE_VALUES:
                    if vpat.search(val):
                        hits.append(("auth token", f"File: {source}\nKey: {key}\nValue: {val[:200]}"))
                        break
        return hits

    def _scan_plist(self, text: str, source: str) -> list[tuple[str, str]]:
        return self._scan_text(text, source)

    def _scan_text(self, text: str, source: str) -> list[tuple[str, str]]:
        hits = []
        for i, line in enumerate(text.splitlines()[:5000], 1):
            for pat, label in _SENSITIVE_PATTERNS:
                if pat.search(line):
                    hits.append((label, f"File: {source}\nLine {i}: {line[:300]}"))
                    break
        return hits

    # ── SQLite databases ──────────────────────────────────────────────

    def _inspect_databases(self, snapshot: Path, out_dir: Path) -> int:
        findings = 0
        for db_file in snapshot.rglob("*.db"):
            findings += self._check_single_db(db_file, snapshot, out_dir)
        for db_file in snapshot.rglob("*.sqlite"):
            findings += self._check_single_db(db_file, snapshot, out_dir)
        for db_file in snapshot.rglob("*.sqlite3"):
            findings += self._check_single_db(db_file, snapshot, out_dir)
        return findings

    def _check_single_db(self, db_file: Path, snapshot: Path, out_dir: Path) -> int:
        findings = 0
        rel = str(db_file.relative_to(snapshot))
        try:
            header = db_file.read_bytes()[:16]
        except Exception:
            return 0
        if header[:6] != b"SQLite":
            ev_file = out_dir / f"evidence_encrypted_{db_file.stem}.txt"
            ev_file.write_text(
                f"Database: {rel}\nHeader: {header.hex()}\n"
                f"The SQLite header is absent — the database may be encrypted "
                f"(SQLCipher or similar). This is a positive finding.",
                encoding="utf-8")
            self.log(f"[storage] {rel}: possibly encrypted (good)")
            return 0

        try:
            conn = sqlite3.connect(str(db_file))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
        except Exception as exc:
            self.log(f"[storage] Cannot open {rel}: {exc}")
            return 0

        sensitive_cols_found: list[tuple[str, str, str]] = []
        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info(`{table}`)")
                columns = [(r[1], r[2]) for r in cursor.fetchall()]
            except Exception:
                continue
            for col_name, col_type in columns:
                if col_name.lower() in _SENSITIVE_SQLITE_COLS:
                    try:
                        cursor.execute(
                            f"SELECT `{col_name}` FROM `{table}` LIMIT 5")
                        samples = [str(r[0]) for r in cursor.fetchall() if r[0]]
                    except Exception:
                        samples = []
                    if samples:
                        sensitive_cols_found.append((table, col_name,
                                                     "; ".join(samples[:3])))
        conn.close()

        if sensitive_cols_found:
            ev_text = f"Database: {rel}\nEncrypted: No (plaintext SQLite)\n\n"
            for table, col, samples in sensitive_cols_found:
                ev_text += f"Table: {table}, Column: {col}\n  Samples: {samples}\n"
            ev_file = out_dir / f"evidence_db_{db_file.stem}.txt"
            ev_file.write_text(ev_text, encoding="utf-8")

            self.finding(
                title="Unencrypted SQLite Database",
                severity="HIGH",
                description=(
                    f"Unencrypted SQLite database {rel} contains sensitive "
                    f"columns: {', '.join(c[1] for c in sensitive_cols_found)}. "
                    f"Data is readable by any process with root access. "
                    f"Use SQLCipher or equivalent to encrypt at rest."
                ),
                catalogue_id="QUILL-STR-002",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=rel,
            )
            findings += 1

        return findings

    # ── file permissions ──────────────────────────────────────────────

    def _check_file_permissions(self, out_dir: Path) -> int:
        if self.platform != "android":
            return 0
        findings = 0
        data_dir = self._device.get_app_data_dir(self.package)
        if not data_dir:
            return 0
        rc, out, _ = self._device.shell(
            f"find {data_dir} -type f -perm -o+r 2>/dev/null",
            root=True, timeout=20)
        if rc != 0 or not out.strip():
            self.log("[storage] No world-readable files found (good)")
            return 0
        world_readable = [l.strip() for l in out.strip().splitlines() if l.strip()]
        if world_readable:
            ev_file = out_dir / "evidence_world_readable.txt"
            ev_file.write_text(
                f"World-readable files in {data_dir}:\n" +
                "\n".join(world_readable[:100]),
                encoding="utf-8")
            self.finding(
                title="World-Readable File in App Data",
                severity="MEDIUM",
                description=(
                    f"{len(world_readable)} file(s) in the app's data "
                    f"directory are world-readable. Any app on the device "
                    f"can read them without root."
                ),
                catalogue_id="QUILL-STR-003",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=data_dir,
            )
            findings += 1
        return findings

    # ── cache ─────────────────────────────────────────────────────────

    def _inspect_cache(self, snapshot: Path, out_dir: Path) -> int:
        findings = 0
        cache_dir = self._find_subdir(snapshot, "cache")
        if not cache_dir:
            cache_dir = self._find_subdir(snapshot, "Library/Caches")
        if not cache_dir:
            self.log("[storage] No cache directory found")
            return 0

        sensitive_files: list[tuple[str, str]] = []
        for f in cache_dir.rglob("*"):
            if not f.is_file() or f.stat().st_size > 2 * 1024 * 1024:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel = str(f.relative_to(snapshot))
            for pat, label in _SENSITIVE_PATTERNS:
                if pat.search(text):
                    sensitive_files.append((rel, label))
                    break
            else:
                for vpat in _SENSITIVE_VALUES:
                    if vpat.search(text):
                        sensitive_files.append((rel, "auth token"))
                        break

        if sensitive_files:
            ev_file = out_dir / "evidence_cache.txt"
            ev_file.write_text(
                "Sensitive data found in cache:\n\n" +
                "\n".join(f"{path}: {kind}" for path, kind in sensitive_files[:50]),
                encoding="utf-8")
            self.finding(
                title="Sensitive Data in Cache",
                severity="MEDIUM",
                description=(
                    f"{len(sensitive_files)} cache file(s) contain sensitive "
                    f"data ({', '.join(set(k for _, k in sensitive_files))}). "
                    f"Cache files may persist across sessions and are "
                    f"accessible with root."
                ),
                catalogue_id="QUILL-STR-004",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected="cache directory",
            )
            findings += 1
        return findings

    # ── post-logout diff ──────────────────────────────────────────────

    def _diff_snapshots(self, pre: Path, post: Path, out_dir: Path) -> int:
        findings = 0
        residual: list[str] = []

        pre_files = {str(p.relative_to(pre)): p for p in pre.rglob("*") if p.is_file()}
        post_files = {str(p.relative_to(post)): p for p in post.rglob("*") if p.is_file()}

        for rel, pre_path in pre_files.items():
            post_path = post_files.get(rel)
            if not post_path:
                continue
            if "shared_prefs" not in rel and "Preferences" not in rel:
                continue
            try:
                pre_text = pre_path.read_text(encoding="utf-8", errors="replace")
                post_text = post_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat, label in _SENSITIVE_PATTERNS:
                if pat.search(pre_text) and pat.search(post_text):
                    pre_matches = pat.findall(pre_text)
                    post_matches = pat.findall(post_text)
                    if pre_matches and post_matches:
                        residual.append(f"{rel}: {label} persists after logout")
                        break
            for vpat in _SENSITIVE_VALUES:
                pre_m = vpat.findall(pre_text)
                post_m = vpat.findall(post_text)
                if pre_m and post_m:
                    overlap = set(pre_m) & set(post_m)
                    if overlap:
                        residual.append(f"{rel}: token/key value unchanged after logout")
                        break

        if residual:
            ev_file = out_dir / "evidence_residual_data.txt"
            ev_file.write_text(
                "Residual sensitive data after logout:\n\n" +
                "\n".join(residual[:100]),
                encoding="utf-8")
            self.finding(
                title="Session Data Persists After Logout",
                severity="HIGH",
                description=(
                    f"{len(residual)} sensitive item(s) persist in the app's "
                    f"data directory after the user logs out. An attacker "
                    f"with device access can recover session tokens and "
                    f"re-authenticate without credentials."
                ),
                catalogue_id="QUILL-STR-005",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected="app data directory",
            )
            findings += 1
        else:
            self.log("[storage] No residual sensitive data after logout (good)")

        return findings

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _find_subdir(base: Path, name: str) -> Optional[Path]:
        parts = name.split("/")
        candidate = base
        for p in parts:
            candidate = candidate / p
        if candidate.is_dir():
            return candidate
        for d in base.rglob(parts[-1]):
            if d.is_dir():
                return d
        return None
