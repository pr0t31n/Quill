#!/usr/bin/env python3
"""
Quill — Mobile application security analysis tool.

Supports iOS (IPA) and Android (APK) static analysis, plus optional
Frida-based dynamic analysis.

Token protocol (when CRUCIBLE_MANAGED=1):
  __CRUCIBLE_LOG__     <message>
  __CRUCIBLE_ERR__     <message>
  __CRUCIBLE_STATUS__  <json>
  __CRUCIBLE_FINDING__ <json>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None

try:
    import pr0t31n_event_log as _el
except ImportError:
    _el = None

try:
    from pr0t31n_pause import PauseManager as _PP
except ImportError:
    _PP = None

_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_findings: list = []

_RUN_DIR: Optional[Path] = None
_RUNLOG = None
_pause = None
_APP_TARGET = ""
_EXTRACT_BASE: Optional[Path] = None

_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]


def _check_pause():
    if _pause is not None and _pause.check_and_pause():
        sys.exit(42)


def _save_checkpoint():
    if _RUN_DIR is None:
        return
    try:
        cp = {
            "findings_count": len(_findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        (_RUN_DIR / "checkpoint.json").write_text(
            json.dumps(cp, indent=2), encoding="utf-8")
        log(f"[checkpoint] Saved — {len(_findings)} finding(s)")
    except Exception:
        pass


def _rel(p) -> str:
    if not p:
        return ""
    if _us is not None and _RUN_DIR is not None:
        try:
            r = _us.to_relative_output_file(p, str(_RUN_DIR))
            if r:
                return r
        except Exception:
            pass
    return str(p)


def _analysis_log(out_file, title: str, lines: list) -> None:
    try:
        body = "\n".join(f"# {ln}" for ln in lines)
        Path(str(out_file) + ".log").write_text(
            f"# Quill analysis transcript — {title}\n{body}\n", encoding="utf-8")
    except Exception:
        pass


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _tok(token: str, payload: str) -> None:
    if _MANAGED:
        print(f"{token}:{payload}", flush=True)
    else:
        print(f"[{_ts()}] {payload}", flush=True)


def log(msg: str) -> None:
    if _MANAGED:
        _tok("__CRUCIBLE_LOG__", json.dumps({
            "ts": datetime.now().isoformat(), "level": "INFO", "message": msg}))
    else:
        _tok("__CRUCIBLE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    if _MANAGED:
        _tok("__CRUCIBLE_ERR__", json.dumps({
            "ts": datetime.now().isoformat(), "level": "ERROR", "message": msg}))
    else:
        _tok("__CRUCIBLE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__CRUCIBLE_STATUS__",
         json.dumps({"phase": phase, "label": label, "state": state, "step": step,
                     "ts": datetime.now().isoformat()}))


def _clean_affected(val: str) -> str:
    if not val:
        return _APP_TARGET
    if _EXTRACT_BASE is not None:
        eb = str(_EXTRACT_BASE)
        if val.startswith(eb):
            val = val[len(eb):].lstrip("/")
    elif _RUN_DIR is not None:
        rd = str(_RUN_DIR)
        if val.startswith(rd):
            val = val[len(rd):].lstrip("/")
    return val or _APP_TARGET


def finding(*, title: str, severity: str, description: str,
             data: dict | None = None, output_file: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    affected = _clean_affected((data or {}).get("affected", ""))
    if _us is not None:
        rec = _us.make_finding(
            tool="quill", title=title, risk=severity.upper(),
            description=description, ip="", port=0,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=affected,
            remediation=(data or {}).get("remediation", ""),
            sources="quill", catalogue_id=(data or {}).get("catalogue_id", ""),
        )
    else:
        rec = {
            "id": str(uuid.uuid4()),
            "tool": "quill",
            "title": title,
            "risk": severity.upper(),
            "description": description,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "output_file": of_rel,
            "data": data or {},
        }
    _findings.append(rec)
    log(f"[finding] #{len(_findings)} [{severity.upper()}] {title}")
    _tok("__CRUCIBLE_FINDING__", json.dumps(rec))
    _flush_findings()


def _flush_findings():
    if _RUN_DIR is None:
        return
    try:
        if _us is not None:
            out = [_us.augment_finding(dict(f), tool="quill") for f in _findings]
            _us.atomic_write_json(_RUN_DIR / "findings.json", out)
        else:
            (_RUN_DIR / "findings.json").write_text(
                json.dumps(_findings, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── IPA extraction ────────────────────────────────────────────────────────────

def extract_ipa(ipa_path: Path, dest: Path) -> Optional[Path]:
    _check_pause()
    log(f"[extract] Extracting IPA archive: {ipa_path}")
    status("extract", "IPA extraction", "running")
    if not ipa_path.exists():
        err(f"IPA not found: {ipa_path}")
        status("extract", "IPA extraction", "error")
        return None
    ipa_size = ipa_path.stat().st_size
    log(f"[extract] IPA size: {ipa_size / 1048576:.1f} MB")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            members = z.namelist()
            log(f"[extract] Archive contains {len(members)} entries — extracting to {dest}")
            z.extractall(dest)
    except zipfile.BadZipFile as exc:
        err(f"Invalid IPA archive: {exc}")
        status("extract", "IPA extraction", "error")
        return None

    payload = dest / "Payload"
    if not payload.exists():
        err("Payload/ missing in IPA — not a standard iOS bundle")
        status("extract", "IPA extraction", "error")
        return None
    apps = [p for p in payload.iterdir() if p.is_dir() and p.suffix == ".app"]
    if not apps:
        err("No .app bundle found in Payload/")
        status("extract", "IPA extraction", "error")
        return None
    log(f"[extract] IPA extraction complete — app bundle: {apps[0].name}")
    status("extract", "IPA extraction", "complete")
    return apps[0]


def analyse_info_plist(app_dir: Path, output_dir: Path) -> dict:
    _check_pause()
    _save_checkpoint()
    log(f"[info_plist] Starting Info.plist analysis for {app_dir.name}...")
    status("info_plist", "Info.plist analysis", "running")
    plist_path = app_dir / "Info.plist"
    out_file = output_dir / "info_plist.json"
    if not plist_path.exists():
        err("Info.plist missing")
        status("info_plist", "Info.plist analysis", "error")
        return {}
    log(f"[info_plist] Parsing plist: {plist_path}")
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
    except Exception as exc:
        err(f"Info.plist parse error: {exc}")
        status("info_plist", "Info.plist analysis", "error")
        return {}
    out_file.write_text(json.dumps(data, default=str, indent=2), encoding="utf-8")
    log(f"[info_plist] Plist parsed — {len(data)} top-level keys")

    bundle_id = data.get("CFBundleIdentifier", "")
    version = data.get("CFBundleShortVersionString", "")
    log(f"[info_plist] Bundle: {bundle_id} v{version}")
    _analysis_log(out_file, "Info.plist analysis",
                  [f"source: {plist_path}",
                   f"bundle: {bundle_id} v{version}",
                   "checks: ATS arbitrary loads, per-domain HTTP exceptions, "
                   "custom URL schemes, background modes"])

    ats = data.get("NSAppTransportSecurity") or {}
    log(f"[info_plist] Checking App Transport Security — ATS config present: {bool(ats)}")
    if ats.get("NSAllowsArbitraryLoads"):
        log("[info_plist] ATS: NSAllowsArbitraryLoads=true — finding emitted")
        finding(title="Network Security: App Transport Security Arbitrary Loads Allowed",
                 severity="HIGH",
                 description=("NSAllowsArbitraryLoads=true disables ATS globally; "
                               "non-HTTPS connections are permitted."),
                 data={"catalogue_id": "QUILL-IOS-001",
                       "affected": bundle_id,
                       "remediation": "Remove NSAllowsArbitraryLoads or restrict to specific domains."},
                 output_file=str(out_file))
    exc_domains = ats.get("NSExceptionDomains") or {}
    if exc_domains:
        log(f"[info_plist] ATS: {len(exc_domains)} exception domain(s) configured")
    for dom, cfg in exc_domains.items():
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
            log(f"[info_plist] ATS: HTTP exception for domain {dom} — finding emitted")
            finding(title=f"Network Security: ATS Exception Allows HTTP for {dom}",
                     severity="MEDIUM",
                     description=("Per-domain exception allows cleartext HTTP."),
                     data={"catalogue_id": "QUILL-IOS-002",
                           "affected": f"{bundle_id} / {dom}"},
                     output_file=str(out_file))

    schemes = data.get("CFBundleURLTypes") or []
    log(f"[info_plist] Checking URL schemes — {len(schemes)} bundle URL type(s)")
    for entry in schemes:
        for sch in entry.get("CFBundleURLSchemes") or []:
            log(f"URL scheme: {sch}://")
            if sch.lower() in ("http", "https", "file", "tel", "sms", "mailto"):
                continue
            finding(title=f"Attack Surface: Custom URL Scheme Registered: {sch}://",
                     severity="INFO",
                     description=("Custom URL schemes can be invoked by any app; "
                                   "ensure all parameters are validated and authentication "
                                   "is enforced before sensitive actions."),
                     data={"catalogue_id": "QUILL-IOS-010",
                           "affected": f"{bundle_id} / {sch}"},
                     output_file=str(out_file))

    bg_modes = data.get("UIBackgroundModes") or []
    if bg_modes:
        log(f"[info_plist] Background modes: {', '.join(bg_modes)}")
    if "background-fetch" in bg_modes:
        log("[info_plist] Background fetch enabled")
    log(f"[info_plist] Info.plist analysis complete — bundle {bundle_id}")
    status("info_plist", "Info.plist analysis", "complete")
    return data


def analyse_entitlements(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[entitlements] Starting entitlements extraction for {app_dir.name}...")
    status("entitlements", "Entitlements extraction", "running")
    codesign = shutil.which("codesign")
    if not codesign:
        log("[entitlements] codesign not available — skipping entitlements (macOS-only tool)")
        status("entitlements", "Entitlements extraction", "skipped")
        return
    log(f"[entitlements] Using codesign: {codesign}")
    out_file = output_dir / "entitlements.xml"
    try:
        if _ur is not None:
            cp = _ur.run_tool([codesign, "-d", "--entitlements", ":-", str(app_dir)],
                                output_file=str(out_file), timeout=60,
                                tool_name="codesign",
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(
                [codesign, "-d", "--entitlements", ":-", str(app_dir)],
                capture_output=True, text=True, timeout=60)
        ent = cp.stdout or ""
        out_file.write_text(ent, encoding="utf-8")
        log(f"[entitlements] Extracted {len(ent)} bytes of entitlement data")
        log("[entitlements] Checking get-task-allow (debuggable)...")
        if "get-task-allow" in ent and "<true/>" in ent.split("get-task-allow")[-1][:60]:
            log("[entitlements] get-task-allow=true detected — finding emitted")
            finding(title="Build Configuration: get-task-allow Enabled (Debuggable Binary)",
                     severity="HIGH",
                     description=("get-task-allow=true permits attaching a debugger; "
                                   "should be FALSE in production builds."),
                     data={"catalogue_id": "QUILL-IOS-020",
                           "remediation": "Set get-task-allow=false in entitlements before App Store submission."},
                     output_file=str(out_file))
        log("[entitlements] Checking application-identifier for wildcards...")
        if "application-identifier" in ent and "wildcard" in ent.lower():
            log("[entitlements] Wildcard application-identifier detected — finding emitted")
            finding(title="Build Configuration: Wildcard Application-Identifier in Entitlements",
                     severity="MEDIUM",
                     description=("Wildcard provisioning profile in use; key-chain "
                                   "sharing scope is over-broad."),
                     data={"catalogue_id": "QUILL-IOS-021"},
                     output_file=str(out_file))
    except Exception as exc:
        err(f"codesign error: {exc}")
    log(f"[entitlements] Entitlements extraction complete")
    status("entitlements", "Entitlements extraction", "complete")


_HARDCODED_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"), "Slack token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe live key"),
    (re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"), "Embedded private key"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub personal access token"),
    (re.compile(r"glpat-[0-9a-zA-Z\-_]{20,}"), "GitLab personal access token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}"), "JWT token"),
    (re.compile(r"(?i)(?:password|passwd|secret|api_key|apikey)\s*[=:]\s*[\"'][^\"']{6,}[\"']"), "Hard-coded credential"),
]


def analyse_strings(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[strings] Starting hard-coded secret scan on {app_dir.name}...")
    status("strings", "Hard-coded secret scan", "running")
    strings_bin = shutil.which("strings")
    log(f"[strings] strings binary: {strings_bin or 'not found'}")
    log(f"[strings] Scanning {len(_HARDCODED_PATTERNS)} secret patterns (AWS, Google, Slack, Stripe, keys, JWT, creds...)")
    out_file = output_dir / "string_findings.txt"
    out_file.write_text("", encoding="utf-8")

    app_name = app_dir.name.replace(".app", "")
    binary = app_dir / app_name
    if not binary.exists():
        log(f"[strings] Main binary not found at {binary} — scanning entire bundle")
    else:
        log(f"[strings] Main binary located: {binary}")

    hits: list = []
    def _scan(text: str, source: str) -> None:
        for rx, label in _HARDCODED_PATTERNS:
            for m in rx.finditer(text):
                hits.append((label, m.group(0)[:80], source))

    strings_raw = output_dir / "strings_raw.txt"
    if binary.exists() and strings_bin:
        log(f"[strings] Running strings on main binary...")
        try:
            if _ur is not None:
                cp = _ur.run_tool([strings_bin, str(binary)],
                                    output_file=str(strings_raw), timeout=120,
                                    tool_name="strings",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run([strings_bin, str(binary)],
                                      capture_output=True, text=True, timeout=120)
            strings_raw.write_text(cp.stdout or "", encoding="utf-8")
            _scan(cp.stdout or "", str(binary))
            log(f"[strings] Binary strings extracted — {len((cp.stdout or '').splitlines())} lines")
        except Exception:
            pass

    _check_pause()
    log("[strings] Scanning resource files (plist, json, strings, txt)...")
    _resource_count = 0
    for ext in ("plist", "json", "strings", "txt"):
        for p in app_dir.rglob(f"*.{ext}"):
            _resource_count += 1
            try:
                _scan(p.read_text(encoding="utf-8", errors="ignore")[:200000], str(p))
            except Exception:
                continue
    log(f"[strings] Scanned {_resource_count} resource files")

    _analysis_log(out_file, "Hard-coded secret scan",
                  [f"strings_binary: {strings_bin}",
                   f"main_binary: {binary}",
                   "scanned_exts: plist, json, strings, txt",
                   f"pattern_hits: {len(hits)}"])
    if hits:
        log(f"[strings] {len(hits)} potential secret(s) found — writing findings (capped at 30)")
        out_file.write_text(
            "\n".join(f"[{label}] {match} (in {source})" for label, match, source in hits),
            encoding="utf-8")
        for label, match, source in hits[:30]:
            clean_src = _clean_affected(source)
            finding(title=f"Information Disclosure: Potential hard-coded secret: {label}",
                     severity="HIGH",
                     description=(f"Pattern matching {label} was found in {clean_src}. "
                                   "Verify whether this is a real secret or a test fixture."),
                     data={"catalogue_id": "QUILL-IOS-030",
                           "affected": clean_src,
                           "evidence": match[:80]},
                     output_file=str(out_file))
    else:
        log("[strings] No hard-coded secrets detected in IPA bundle")
    log("[strings] Hard-coded secret scan complete")
    status("strings", "Hard-coded secret scan", "complete")


# ── APK extraction ────────────────────────────────────────────────────────────

def extract_apk(apk_path: Path, dest: Path) -> Optional[Path]:
    _check_pause()
    log(f"[extract] Extracting APK archive: {apk_path}")
    status("extract", "APK extraction", "running")
    if not apk_path.exists():
        err(f"APK not found: {apk_path}")
        status("extract", "APK extraction", "error")
        return None
    apk_size = apk_path.stat().st_size
    log(f"[extract] APK size: {apk_size / 1048576:.1f} MB")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            members = z.namelist()
            log(f"[extract] Archive contains {len(members)} entries — extracting to {dest}")
            z.extractall(dest)
    except zipfile.BadZipFile as exc:
        err(f"Invalid APK archive: {exc}")
        status("extract", "APK extraction", "error")
        return None

    if not (dest / "AndroidManifest.xml").exists() and not (dest / "classes.dex").exists():
        log("[extract] Standard manifest/dex not found — binary XML suspected")
        apktool = shutil.which("apktool")
        if apktool:
            log(f"[extract] Binary XML detected — running apktool decode ({apktool})")
            _save_checkpoint()
            try:
                decoded = dest / "decoded"
                if _ur is not None:
                    _ur.run_tool([apktool, "d", "-f", "-o", str(decoded), str(apk_path)],
                                  output_file=str(decoded / "apktool.yml"),
                                  timeout=300, tool_name="apktool",
                                  errors_log=(str(_RUN_DIR / "errors.log")
                                              if _RUN_DIR is not None else None))
                else:
                    subprocess.run([apktool, "d", "-f", "-o", str(decoded), str(apk_path)],
                                    capture_output=True, text=True, timeout=300)
                _check_pause()
                if (decoded / "AndroidManifest.xml").exists():
                    log(f"[extract] apktool decode successful — decoded manifest at {decoded}")
                    status("extract", "APK extraction", "complete")
                    return decoded
            except Exception as exc:
                err(f"apktool error: {exc}")
        else:
            log("[extract] apktool not available — raw ZIP extraction only (binary XML not decoded)")
    else:
        log("[extract] Standard APK layout confirmed (manifest and/or dex present)")

    log(f"[extract] APK extraction complete — root: {dest}")
    status("extract", "APK extraction", "complete")
    return dest


_ANDROID_DANGEROUS_PERMS = {
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS", "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.BODY_SENSORS", "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH", "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_CONNECT", "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_ADVERTISE",
}

_NS = {"android": "http://schemas.android.com/apk/res/android"}


def _attr(el, name: str) -> str:
    return el.get(f"{{{_NS['android']}}}{name}", el.get(name, ""))


def analyse_manifest(app_dir: Path, output_dir: Path) -> dict:
    _check_pause()
    _save_checkpoint()
    log(f"[manifest] Starting AndroidManifest.xml analysis for {app_dir.name}...")
    status("manifest", "AndroidManifest.xml analysis", "running")
    manifest_path = app_dir / "AndroidManifest.xml"
    out_file = output_dir / "manifest_analysis.json"

    if not manifest_path.exists():
        err("AndroidManifest.xml not found")
        status("manifest", "AndroidManifest.xml analysis", "error")
        return {}

    try:
        raw = manifest_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        err(f"AndroidManifest.xml read error: {exc}")
        status("manifest", "AndroidManifest.xml analysis", "error")
        return {}
    log(f"[manifest] Manifest loaded — {len(raw)} bytes")

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        err(f"AndroidManifest.xml parse error: {exc}")
        status("manifest", "AndroidManifest.xml analysis", "error")
        return {}

    package = root.get("package", "")
    log(f"[manifest] Package: {package}")

    app_el = root.find("application")
    result = {"package": package, "permissions": [], "components": [], "flags": {}}

    if app_el is not None:
        log("[manifest] Checking application security flags...")
        debuggable = _attr(app_el, "debuggable").lower() == "true"
        allow_backup = _attr(app_el, "allowBackup").lower() != "false"
        use_cleartext = _attr(app_el, "usesCleartextTraffic").lower() == "true"
        network_config = _attr(app_el, "networkSecurityConfig")
        log(f"[manifest] Flags — debuggable={debuggable}, allowBackup={allow_backup}, "
            f"usesCleartextTraffic={use_cleartext}, networkSecurityConfig={bool(network_config)}")

        result["flags"] = {
            "debuggable": debuggable,
            "allowBackup": allow_backup,
            "usesCleartextTraffic": use_cleartext,
            "networkSecurityConfig": network_config,
        }

        if debuggable:
            log("[manifest] android:debuggable=true — finding emitted")
            finding(title="Application is debuggable",
                     severity="HIGH",
                     description="android:debuggable=true allows attaching a debugger to the running app, "
                                 "enabling memory inspection, method interception, and data extraction.",
                     data={"catalogue_id": "QUILL-APK-001", "affected": package,
                           "remediation": "Set android:debuggable=false in release builds."},
                     output_file=str(out_file))

        if allow_backup:
            finding(title="Application allows backup",
                     severity="MEDIUM",
                     description="android:allowBackup is true (or not explicitly set to false), "
                                 "allowing adb backup to extract application data including databases and shared preferences.",
                     data={"catalogue_id": "QUILL-APK-002", "affected": package,
                           "remediation": "Set android:allowBackup=false or implement a BackupAgent with encryption."},
                     output_file=str(out_file))

        if use_cleartext:
            log("[manifest] usesCleartextTraffic=true — finding emitted")
            finding(title="Cleartext traffic allowed",
                     severity="HIGH",
                     description="android:usesCleartextTraffic=true allows unencrypted HTTP connections globally.",
                     data={"catalogue_id": "QUILL-APK-003", "affected": package,
                           "remediation": "Set usesCleartextTraffic=false and use a network security config for exceptions."},
                     output_file=str(out_file))

        log("[manifest] Enumerating exported components...")
        _exported_count = 0
        for comp_type in ("activity", "service", "receiver", "provider"):
            for comp in app_el.findall(comp_type):
                name = _attr(comp, "name")
                exported = _attr(comp, "exported").lower()
                has_intent_filter = comp.find("intent-filter") is not None
                is_exported = exported == "true" or (exported == "" and has_intent_filter)
                perm = _attr(comp, "permission")
                result["components"].append({
                    "type": comp_type, "name": name,
                    "exported": is_exported, "permission": perm,
                    "has_intent_filter": has_intent_filter,
                })
                if is_exported:
                    _exported_count += 1
                if is_exported and not perm:
                    if name and not name.endswith(".MainActivity"):
                        finding(title=f"Exported {comp_type} without permission: {name}",
                                 severity="MEDIUM",
                                 description=f"The {comp_type} {name} is exported and accessible by any app "
                                             "without requiring a permission. An attacker could invoke it directly.",
                                 data={"catalogue_id": "QUILL-APK-010", "affected": f"{package}/{name}",
                                       "remediation": f"Set android:exported=false or add a permission attribute to {name}."},
                                 output_file=str(out_file))

    log(f"[manifest] Components scanned — {len(result['components'])} total, {_exported_count} exported")

    sdk_el = root.find("uses-sdk")
    if sdk_el is not None:
        min_sdk = _attr(sdk_el, "minSdkVersion")
        target_sdk = _attr(sdk_el, "targetSdkVersion")
        log(f"[manifest] SDK versions — minSdk={min_sdk}, targetSdk={target_sdk}")
        result["flags"]["minSdkVersion"] = min_sdk
        result["flags"]["targetSdkVersion"] = target_sdk
        if min_sdk and int(min_sdk) < 24:
            finding(title=f"Low minimum SDK version: API {min_sdk}",
                     severity="LOW",
                     description=f"minSdkVersion={min_sdk} (Android < 7.0). Older Android versions lack security "
                                 "features like network security config, file-based encryption, and scoped storage.",
                     data={"catalogue_id": "QUILL-APK-020", "affected": package},
                     output_file=str(out_file))

    perms = []
    for perm_el in root.findall("uses-permission"):
        perm_name = _attr(perm_el, "name")
        if perm_name:
            perms.append(perm_name)
    result["permissions"] = perms
    log(f"[manifest] {len(perms)} permission(s) declared")

    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "AndroidManifest.xml analysis",
                  [f"package: {package}",
                   f"permissions: {len(perms)}",
                   f"components: {len(result['components'])}",
                   f"debuggable: {result['flags'].get('debuggable')}",
                   f"allowBackup: {result['flags'].get('allowBackup')}"])

    log(f"[manifest] AndroidManifest.xml analysis complete — {package}")
    status("manifest", "AndroidManifest.xml analysis", "complete")
    return result


def analyse_permissions(app_dir: Path, output_dir: Path, manifest_data: dict) -> None:
    _check_pause()
    log(f"[permissions] Starting permission analysis...")
    status("permissions", "Permission analysis", "running")
    perms = manifest_data.get("permissions", [])
    package = manifest_data.get("package", "")
    out_file = output_dir / "permission_analysis.json"

    dangerous = [p for p in perms if p in _ANDROID_DANGEROUS_PERMS]
    normal = [p for p in perms if p not in _ANDROID_DANGEROUS_PERMS]
    log(f"[permissions] {len(perms)} total — {len(dangerous)} dangerous, {len(normal)} normal")

    result = {
        "total": len(perms),
        "dangerous_count": len(dangerous),
        "dangerous": dangerous,
        "normal": normal,
    }
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Permission analysis",
                  [f"package: {package}",
                   f"total_permissions: {len(perms)}",
                   f"dangerous_permissions: {len(dangerous)}"])

    if len(dangerous) > 10:
        log(f"[permissions] Excessive dangerous permissions ({len(dangerous)} > 10) — finding emitted")
        finding(title=f"Excessive dangerous permissions ({len(dangerous)})",
                 severity="MEDIUM",
                 description=f"The application requests {len(dangerous)} dangerous permissions. "
                             "Excessive permission requests expand the attack surface and increase "
                             "the risk of data leakage if the app is compromised.",
                 data={"catalogue_id": "QUILL-APK-030", "affected": package,
                       "remediation": "Review and remove unnecessary dangerous permissions."},
                 output_file=str(out_file))

    log(f"[permissions] Emitting individual findings for {len(dangerous)} dangerous permission(s)")
    for perm in dangerous:
        short = perm.rsplit(".", 1)[-1]
        finding(title=f"Dangerous permission: {short}",
                 severity="INFO",
                 description=f"The app requests {perm}, classified as a dangerous (runtime) permission by Android.",
                 data={"catalogue_id": "QUILL-APK-031", "affected": f"{package} / {short}"},
                 output_file=str(out_file))

    log("[permissions] Permission analysis complete")
    status("permissions", "Permission analysis", "complete")


def analyse_strings_apk(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[strings_apk] Starting APK hard-coded secret scan on {app_dir.name}...")
    status("strings_apk", "APK hard-coded secret scan", "running")
    strings_bin = shutil.which("strings")
    log(f"[strings_apk] strings binary: {strings_bin or 'not found'}")
    log(f"[strings_apk] Scanning {len(_HARDCODED_PATTERNS)} secret patterns (AWS, Google, Slack, Stripe, keys, JWT, creds...)")
    out_file = output_dir / "string_findings.txt"
    out_file.write_text("", encoding="utf-8")

    hits: list = []
    def _scan(text: str, source: str) -> None:
        for rx, label in _HARDCODED_PATTERNS:
            for m in rx.finditer(text):
                hits.append((label, m.group(0)[:80], source))

    # Scan DEX files
    _dex_files = list(app_dir.rglob("*.dex"))
    log(f"[strings_apk] Found {len(_dex_files)} DEX file(s) to scan")
    for dex in _dex_files:
        _check_pause()
        if strings_bin:
            try:
                strings_raw = output_dir / f"strings_{dex.name}.txt"
                if _ur is not None:
                    cp = _ur.run_tool([strings_bin, str(dex)],
                                        output_file=str(strings_raw), timeout=120,
                                        tool_name="strings",
                                        errors_log=(str(_RUN_DIR / "errors.log")
                                                    if _RUN_DIR is not None else None))
                else:
                    cp = subprocess.run([strings_bin, str(dex)],
                                          capture_output=True, text=True, timeout=120)
                strings_raw.write_text(cp.stdout or "", encoding="utf-8")
                _scan(cp.stdout or "", str(dex))
            except Exception:
                pass

    _check_pause()
    # Scan smali files (if apktool decoded)
    _smali_files = list(app_dir.rglob("*.smali"))
    if _smali_files:
        log(f"[strings_apk] Scanning {len(_smali_files)} smali file(s) (apktool decoded)")
    for smali in _smali_files:
        try:
            _scan(smali.read_text(encoding="utf-8", errors="ignore")[:200000], str(smali))
        except Exception:
            continue

    # Scan resource/config files
    log("[strings_apk] Scanning resource/config files (xml, json, properties, txt, cfg, yml, yaml)...")
    _res_count = 0
    for ext in ("xml", "json", "properties", "txt", "cfg", "yml", "yaml"):
        for p in app_dir.rglob(f"*.{ext}"):
            _res_count += 1
            try:
                _scan(p.read_text(encoding="utf-8", errors="ignore")[:200000], str(p))
            except Exception:
                continue
    log(f"[strings_apk] Scanned {_res_count} resource/config files")

    _analysis_log(out_file, "APK hard-coded secret scan",
                  [f"strings_binary: {strings_bin}",
                   "scanned: dex, smali, xml, json, properties, txt, cfg, yml, yaml",
                   f"pattern_hits: {len(hits)}"])

    if hits:
        log(f"[strings_apk] {len(hits)} potential secret(s) found — writing findings (capped at 30)")
        out_file.write_text(
            "\n".join(f"[{label}] {match} (in {source})" for label, match, source in hits),
            encoding="utf-8")
        for label, match, source in hits[:30]:
            clean_src = _clean_affected(source)
            finding(title=f"Information Disclosure: Potential hard-coded secret: {label}",
                     severity="HIGH",
                     description=(f"Pattern matching {label} was found in {clean_src}. "
                                   "Verify whether this is a real secret or a test fixture."),
                     data={"catalogue_id": "QUILL-APK-040",
                           "affected": clean_src,
                           "evidence": match[:80]},
                     output_file=str(out_file))
    else:
        log("[strings_apk] No hard-coded secrets detected in APK bundle")

    log("[strings_apk] APK hard-coded secret scan complete")
    status("strings_apk", "APK hard-coded secret scan", "complete")


# ── iOS binary analysis ──────────────────────────────────────────────────────

def _find_ios_main_binary(app_dir: Path) -> Optional[Path]:
    app_name = app_dir.name.replace(".app", "")
    binary = app_dir / app_name
    if binary.exists() and binary.is_file():
        return binary
    for p in app_dir.iterdir():
        if p.is_file() and not p.suffix and os.access(str(p), os.X_OK):
            return p
    return None


def _run_tool_cmd(cmd: list, *, output_file: str = "", timeout: int = 60,
                  tool_name: str = "") -> Optional[subprocess.CompletedProcess]:
    try:
        if _ur is not None:
            return _ur.run_tool(cmd, output_file=output_file, timeout=timeout,
                                tool_name=tool_name,
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        err(f"{tool_name or cmd[0]} error: {exc}")
        return None


def _check_binary_mitigations(binary: Path, output_dir: Path,
                               label_prefix: str = "") -> dict:
    otool = shutil.which("otool")
    nm_bin = shutil.which("nm")
    codesign = shutil.which("codesign")
    results = {}

    bin_name = binary.name
    pfx = f"[{label_prefix}] " if label_prefix else ""

    # ── otool -hv: PIE and NX flags ──
    if otool:
        out_file = output_dir / f"{bin_name}_otool_header.txt"
        cp = _run_tool_cmd([otool, "-hv", str(binary)],
                           output_file=str(out_file), timeout=60,
                           tool_name="otool")
        if cp is not None:
            header = cp.stdout or ""
            out_file.write_text(header, encoding="utf-8")
            flags_line = ""
            for line in header.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("Mach") and not stripped.startswith("magic"):
                    if "PIE" in stripped or "EXECUTE" in stripped or "MH_" in stripped:
                        flags_line = stripped
                        break
            if not flags_line:
                lines = header.strip().splitlines()
                if len(lines) >= 4:
                    flags_line = lines[-1].strip()

            results["pie"] = "PIE" in header
            results["nx"] = "MH_NO_HEAP_EXECUTION" in header or results["pie"]
            log(f"{pfx}otool -hv flags: PIE={results['pie']}, NX={results['nx']}")

        # ── otool -I -v: stack canary and ARC symbols ──
        out_file_syms = output_dir / f"{bin_name}_otool_symbols.txt"
        cp2 = _run_tool_cmd([otool, "-I", "-v", str(binary)],
                            output_file=str(out_file_syms), timeout=120,
                            tool_name="otool")
        if cp2 is not None:
            syms = cp2.stdout or ""
            out_file_syms.write_text(syms, encoding="utf-8")
            results["stack_canary"] = ("___stack_chk_fail" in syms
                                       and "___stack_chk_guard" in syms)
            results["arc"] = "_objc_release" in syms
            log(f"{pfx}otool -I -v: stack_canary={results.get('stack_canary')}, "
                f"ARC={results.get('arc')}")

        # ── otool -l: RPATH and encryption ──
        out_file_load = output_dir / f"{bin_name}_otool_load.txt"
        cp3 = _run_tool_cmd([otool, "-l", str(binary)],
                            output_file=str(out_file_load), timeout=60,
                            tool_name="otool")
        if cp3 is not None:
            load_cmds = cp3.stdout or ""
            out_file_load.write_text(load_cmds, encoding="utf-8")
            results["rpath"] = "LC_RPATH" in load_cmds

            encrypted = False
            in_enc_section = False
            for line in load_cmds.splitlines():
                stripped = line.strip()
                if "LC_ENCRYPTION_INFO" in stripped:
                    in_enc_section = True
                if in_enc_section and stripped.startswith("cryptid"):
                    try:
                        cid = int(stripped.split()[-1])
                        encrypted = cid != 0
                    except (ValueError, IndexError):
                        pass
                    in_enc_section = False
            results["encrypted"] = encrypted
            log(f"{pfx}otool -l: RPATH={results.get('rpath')}, encrypted={encrypted}")

    # ── codesign -dv: code signature ──
    if codesign:
        out_file_cs = output_dir / f"{bin_name}_codesign.txt"
        cp4 = _run_tool_cmd([codesign, "-dv", str(binary)],
                            output_file=str(out_file_cs), timeout=30,
                            tool_name="codesign")
        if cp4 is not None:
            cs_out = (cp4.stdout or "") + (cp4.stderr or "")
            out_file_cs.write_text(cs_out, encoding="utf-8")
            results["signed"] = "Signature=" in cs_out or "valid on disk" in cs_out.lower()
            log(f"{pfx}codesign: signed={results.get('signed')}")

    # ── nm: debug symbols stripped ──
    if nm_bin:
        out_file_nm = output_dir / f"{bin_name}_nm.txt"
        cp5 = _run_tool_cmd([nm_bin, str(binary)],
                            output_file=str(out_file_nm), timeout=60,
                            tool_name="nm")
        if cp5 is not None:
            nm_out = cp5.stdout or ""
            nm_stderr = cp5.stderr or ""
            out_file_nm.write_text(nm_out, encoding="utf-8")
            sym_count = len(nm_out.strip().splitlines())
            results["symbols_stripped"] = sym_count < 10 or "no symbols" in nm_stderr.lower()
            log(f"{pfx}nm: {sym_count} symbol(s), stripped={results.get('symbols_stripped')}")

    return results


def analyse_ios_binary(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[ios_binary] Starting iOS binary exploit mitigation analysis for {app_dir.name}...")
    status("ios_binary", "iOS binary mitigations", "running")

    otool = shutil.which("otool")
    nm_bin = shutil.which("nm")
    if not otool:
        log("[ios_binary] otool not available — skipping binary mitigations (macOS-only)")
        status("ios_binary", "iOS binary mitigations", "skipped")
        return

    binary = _find_ios_main_binary(app_dir)
    if not binary:
        err("[ios_binary] Main binary not found in .app bundle")
        status("ios_binary", "iOS binary mitigations", "error")
        return

    log(f"[ios_binary] Analysing main binary: {binary.name} ({binary.stat().st_size / 1048576:.1f} MB)")
    out_file = output_dir / "ios_binary_mitigations.json"

    results = _check_binary_mitigations(binary, output_dir, label_prefix="ios_binary")

    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _analysis_log(out_file, "iOS binary exploit mitigations",
                  [f"binary: {binary}",
                   f"otool: {otool}",
                   f"nm: {nm_bin}",
                   f"checks: PIE, NX, stack_canary, ARC, RPATH, signed, encrypted, symbols"])

    if "nx" in results and not results["nx"]:
        finding(title="Binary Security: NX (No-Execute) Bit Not Confirmed",
                severity="MEDIUM",
                description=("The binary does not appear to have the NX/MH_NO_HEAP_EXECUTION flag set. "
                             "Modern iOS enforces NX when PIE is enabled; missing PIE implies NX may "
                             "not be enforced, increasing exploitability of memory corruption bugs."),
                data={"catalogue_id": "QUILL-IOS-040",
                      "affected": str(binary),
                      "remediation": "Enable PIE (Position Independent Executable) which implicitly enables NX on iOS."},
                output_file=str(out_file))

    if "pie" in results and not results["pie"]:
        finding(title="Binary Security: PIE (Position Independent Executable) Not Enabled",
                severity="HIGH",
                description=("The binary is not compiled as a Position Independent Executable. "
                             "Without PIE, ASLR cannot randomise the base address, making "
                             "return-oriented programming (ROP) attacks significantly easier."),
                data={"catalogue_id": "QUILL-IOS-041",
                      "affected": str(binary),
                      "remediation": "Recompile with -fPIE / -pie flags. Xcode enables this by default for iOS."},
                output_file=str(out_file))

    if "stack_canary" in results and not results["stack_canary"]:
        finding(title="Binary Security: Stack Canary (Stack Protector) Missing",
                severity="HIGH",
                description=("The binary does not contain ___stack_chk_fail / ___stack_chk_guard symbols, "
                             "indicating stack canaries are not enabled. Stack-based buffer overflows "
                             "become trivially exploitable without stack smashing protection."),
                data={"catalogue_id": "QUILL-IOS-042",
                      "affected": str(binary),
                      "remediation": "Compile with -fstack-protector-all. Xcode enables this by default."},
                output_file=str(out_file))

    if "arc" in results and not results["arc"]:
        finding(title="Binary Security: ARC (Automatic Reference Counting) Not Enabled",
                severity="HIGH",
                description=("The binary does not contain _objc_release symbol, suggesting Automatic "
                             "Reference Counting is not in use. Manual memory management increases "
                             "the risk of use-after-free and double-free vulnerabilities."),
                data={"catalogue_id": "QUILL-IOS-043",
                      "affected": str(binary),
                      "remediation": "Enable ARC in Xcode build settings (CLANG_ENABLE_OBJC_ARC=YES)."},
                output_file=str(out_file))

    if results.get("rpath"):
        finding(title="Binary Security: RPATH Load Command Present in Binary",
                severity="INFO",
                description=("The binary contains LC_RPATH load commands, which specify runtime search "
                             "paths for dynamic libraries. On jailbroken devices this could be abused "
                             "to load malicious dylibs via dylib hijacking."),
                data={"catalogue_id": "QUILL-IOS-044",
                      "affected": str(binary),
                      "remediation": "Review RPATH entries; remove unnecessary runtime library search paths."},
                output_file=str(out_file))

    if "signed" in results and not results["signed"]:
        finding(title="Binary Security: Code Signature Missing or Invalid",
                severity="HIGH",
                description=("The binary does not appear to be code-signed. iOS requires valid code "
                             "signatures for execution; an unsigned binary may indicate a development "
                             "build or tampered artifact."),
                data={"catalogue_id": "QUILL-IOS-045",
                      "affected": str(binary),
                      "remediation": "Sign the binary with a valid Apple distribution certificate before release."},
                output_file=str(out_file))

    if "encrypted" in results and not results["encrypted"]:
        finding(title="Binary Security: Binary Not Encrypted (FairPlay DRM Absent)",
                severity="MEDIUM",
                description=("The binary's LC_ENCRYPTION_INFO cryptid is 0, meaning FairPlay DRM "
                             "encryption is not applied. The binary can be directly disassembled "
                             "without needing to dump it from a running process."),
                data={"catalogue_id": "QUILL-IOS-046",
                      "affected": str(binary),
                      "remediation": "Submit through App Store Connect which applies FairPlay encryption automatically."},
                output_file=str(out_file))

    if "symbols_stripped" in results and not results["symbols_stripped"]:
        finding(title="Information Disclosure: Debug Symbols Not Stripped from Binary",
                severity="LOW",
                description=("The binary contains debug symbols (nm reports significant symbol output). "
                             "Debug symbols reveal internal class names, method names, and variable "
                             "names, making reverse engineering substantially easier."),
                data={"catalogue_id": "QUILL-IOS-047",
                      "affected": str(binary),
                      "remediation": "Strip symbols in release builds (STRIP_INSTALLED_PRODUCT=YES in Xcode)."},
                output_file=str(out_file))

    log(f"[ios_binary] iOS binary mitigation analysis complete — {len(results)} check(s) evaluated")
    status("ios_binary", "iOS binary mitigations", "complete")


# ── Insecure C API symbols ──

_INSECURE_C_APIS = {
    "_fopen", "_memcpy", "_memmove", "_strcat", "_strcpy", "_strncat",
    "_strncpy", "_sprintf", "_vsprintf", "_gets", "_scanf", "_sscanf",
    "_fscanf", "_printf", "_fprintf",
}


def analyse_ios_binary_code(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[ios_code] Starting iOS insecure API detection for {app_dir.name}...")
    status("ios_code", "iOS insecure API detection", "running")

    nm_bin = shutil.which("nm")
    if not nm_bin:
        log("[ios_code] nm not available — skipping insecure API detection (macOS-only)")
        status("ios_code", "iOS insecure API detection", "skipped")
        return

    binary = _find_ios_main_binary(app_dir)
    if not binary:
        err("[ios_code] Main binary not found in .app bundle")
        status("ios_code", "iOS insecure API detection", "error")
        return

    log(f"[ios_code] Running nm -u on {binary.name} to extract undefined (imported) symbols...")
    out_file = output_dir / "ios_insecure_apis.json"
    undef_file = output_dir / f"{binary.name}_nm_undefined.txt"

    cp = _run_tool_cmd([nm_bin, "-u", str(binary)],
                       output_file=str(undef_file), timeout=120,
                       tool_name="nm")
    if cp is None:
        status("ios_code", "iOS insecure API detection", "error")
        return

    undef_syms = cp.stdout or ""
    undef_file.write_text(undef_syms, encoding="utf-8")
    sym_set = set()
    for line in undef_syms.splitlines():
        parts = line.strip().split()
        if parts:
            sym_set.add(parts[-1])

    log(f"[ios_code] {len(sym_set)} undefined symbol(s) extracted")

    insecure_found = [s for s in sorted(_INSECURE_C_APIS) if s in sym_set]
    has_nslog = "_NSLog" in sym_set
    has_malloc = "_malloc" in sym_set
    has_calloc = "_calloc" in sym_set

    result = {
        "insecure_c_apis": insecure_found,
        "nslog_present": has_nslog,
        "malloc_without_calloc": has_malloc and not has_calloc,
        "total_undefined": len(sym_set),
    }
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "iOS insecure API detection",
                  [f"binary: {binary}",
                   f"nm: {nm_bin}",
                   f"undefined_symbols: {len(sym_set)}",
                   f"insecure_c_apis_found: {len(insecure_found)}",
                   f"nslog: {has_nslog}",
                   f"malloc_without_calloc: {has_malloc and not has_calloc}"])

    if insecure_found:
        log(f"[ios_code] {len(insecure_found)} insecure C API(s) detected: {', '.join(insecure_found)}")
        finding(title=f"Binary Security: Insecure C API Usage Detected ({len(insecure_found)} function(s))",
                severity="MEDIUM",
                description=(f"The binary imports potentially dangerous C functions: "
                             f"{', '.join(insecure_found)}. These functions are prone to buffer "
                             f"overflows and format string vulnerabilities when used with "
                             f"untrusted input."),
                data={"catalogue_id": "QUILL-IOS-050",
                      "affected": str(binary),
                      "remediation": "Replace with safer alternatives (strlcpy, snprintf, fgets, etc.) or use Swift."},
                output_file=str(out_file))

    if has_nslog:
        log("[ios_code] NSLog usage detected — potential sensitive info in system log")
        finding(title="Information Disclosure: NSLog Usage Detected in Binary",
                severity="MEDIUM",
                description=("The binary imports NSLog, which writes to the system log accessible "
                             "by any app on jailbroken devices and via Xcode console. Sensitive "
                             "data (tokens, PII, internal URLs) logged via NSLog is trivially "
                             "recoverable."),
                data={"catalogue_id": "QUILL-IOS-051",
                      "affected": str(binary),
                      "remediation": "Replace NSLog with os_log with appropriate privacy levels, or use a "
                                     "logging framework that strips logs in release builds."},
                output_file=str(out_file))

    if has_malloc and not has_calloc:
        log("[ios_code] malloc used without calloc — allocated memory may contain stale data")
        finding(title="Binary Security: malloc Used Without calloc (Uninitialized Memory Risk)",
                severity="INFO",
                description=("The binary imports malloc but not calloc. Memory allocated with "
                             "malloc is not zero-initialized and may contain sensitive data from "
                             "previous allocations if not explicitly cleared."),
                data={"catalogue_id": "QUILL-IOS-052",
                      "affected": str(binary),
                      "remediation": "Prefer calloc over malloc, or explicitly zero memory with memset after allocation."},
                output_file=str(out_file))

    log(f"[ios_code] iOS insecure API detection complete")
    status("ios_code", "iOS insecure API detection", "complete")


def analyse_ios_frameworks(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[ios_frameworks] Starting framework/dylib binary analysis for {app_dir.name}...")
    status("ios_frameworks", "Framework binary analysis", "running")

    otool = shutil.which("otool")
    if not otool:
        log("[ios_frameworks] otool not available — skipping framework analysis (macOS-only)")
        status("ios_frameworks", "Framework binary analysis", "skipped")
        return

    fw_dir = output_dir / "framework_analysis"
    fw_dir.mkdir(parents=True, exist_ok=True)

    frameworks = list(app_dir.rglob("*.framework"))
    dylibs = list(app_dir.rglob("*.dylib"))
    log(f"[ios_frameworks] Found {len(frameworks)} framework(s) and {len(dylibs)} dylib(s) in bundle")

    binaries_to_check: list = []
    for fw in frameworks:
        fw_name = fw.stem
        fw_binary = fw / fw_name
        if fw_binary.exists() and fw_binary.is_file():
            binaries_to_check.append(("framework", fw_name, fw_binary))
        else:
            for p in fw.iterdir():
                if p.is_file() and not p.suffix and os.access(str(p), os.X_OK):
                    binaries_to_check.append(("framework", p.name, p))
                    break

    for dl in dylibs:
        binaries_to_check.append(("dylib", dl.name, dl))

    if not binaries_to_check:
        log("[ios_frameworks] No framework/dylib binaries found to analyse")
        status("ios_frameworks", "Framework binary analysis", "complete")
        return

    log(f"[ios_frameworks] Analysing {len(binaries_to_check)} binary/binaries for stack canary and ARC...")
    out_file = output_dir / "framework_binary_analysis.json"
    all_results = []
    weak_count = 0

    for btype, bname, bpath in binaries_to_check:
        _check_pause()
        log(f"[ios_frameworks] Checking {btype} {bname}...")
        res = _check_binary_mitigations(bpath, fw_dir, label_prefix=f"fw_{bname}")
        entry = {"type": btype, "name": bname, "path": str(bpath)}
        entry.update(res)
        all_results.append(entry)

        weaknesses = []
        if "stack_canary" in res and not res["stack_canary"]:
            weaknesses.append("missing stack canary")
        if "arc" in res and not res["arc"]:
            weaknesses.append("ARC not enabled")

        if weaknesses:
            weak_count += 1
            finding(title=f"Framework Binary Weakness: {', '.join(weaknesses)}",
                    severity="MEDIUM",
                    description=(f"The {btype} binary {bname} has the following security weakness(es): "
                                 f"{', '.join(weaknesses)}. Embedded frameworks are part of the app's "
                                 f"attack surface and should meet the same binary hardening standards "
                                 f"as the main executable."),
                    data={"catalogue_id": "QUILL-IOS-055",
                          "affected": f"{bname} ({btype})",
                          "remediation": "Rebuild the framework with stack protection (-fstack-protector-all) and ARC enabled."},
                    output_file=str(out_file))

    out_file.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Framework/dylib binary analysis",
                  [f"app_dir: {app_dir}",
                   f"frameworks: {len(frameworks)}",
                   f"dylibs: {len(dylibs)}",
                   f"binaries_checked: {len(binaries_to_check)}",
                   f"weak_binaries: {weak_count}"])

    log(f"[ios_frameworks] Framework binary analysis complete — {len(binaries_to_check)} checked, "
        f"{weak_count} with weakness(es)")
    status("ios_frameworks", "Framework binary analysis", "complete")


# ── iOS permission enumeration ──

_IOS_DANGEROUS_PERMISSIONS = {
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSContactsUsageDescription",
    "NSCalendarsUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSHealthShareUsageDescription",
    "NSMotionUsageDescription",
    "NSFaceIDUsageDescription",
}


def analyse_ios_permissions(app_dir: Path, output_dir: Path, plist_data: dict) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[ios_perms] Starting iOS permission enumeration for {app_dir.name}...")
    status("ios_perms", "iOS permission enumeration", "running")

    out_file = output_dir / "ios_permissions.json"
    permissions_found: list = []

    for key, value in plist_data.items():
        if (key.startswith("NS") and key.endswith("UsageDescription")) or \
           key.startswith("Privacy -"):
            reason = str(value) if value else "(no reason provided)"
            permissions_found.append({"key": key, "reason": reason})
            log(f"[ios_perms] Permission: {key} — {reason[:80]}")

    dangerous_found = [p for p in permissions_found
                       if p["key"] in _IOS_DANGEROUS_PERMISSIONS]

    result = {
        "total_permissions": len(permissions_found),
        "dangerous_count": len(dangerous_found),
        "permissions": permissions_found,
    }
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "iOS permission enumeration",
                  [f"app_dir: {app_dir}",
                   f"total_permissions: {len(permissions_found)}",
                   f"dangerous_permissions: {len(dangerous_found)}"])

    log(f"[ios_perms] {len(permissions_found)} permission(s) found, "
        f"{len(dangerous_found)} classified as dangerous")

    for p in permissions_found:
        finding(title=f"iOS Permission: {p['key']}",
                severity="INFO",
                description=(f"The app requests {p['key']} with reason: \"{p['reason']}\". "
                             f"Verify that this permission is necessary for the app's core functionality."),
                data={"catalogue_id": "QUILL-IOS-070",
                      "affected": p["key"]},
                output_file=str(out_file))

    if len(dangerous_found) > 6:
        log(f"[ios_perms] Excessive dangerous iOS permissions ({len(dangerous_found)} > 6) — finding emitted")
        perm_list = ", ".join(p["key"] for p in dangerous_found)
        finding(title=f"iOS Permission: Excessive Permissions ({len(dangerous_found)} Dangerous)",
                severity="MEDIUM",
                description=(f"The application requests {len(dangerous_found)} dangerous iOS "
                             f"permissions: {perm_list}. Excessive permission requests expand "
                             f"the attack surface and increase data exposure risk if the app "
                             f"or its dependencies are compromised."),
                data={"catalogue_id": "QUILL-IOS-071",
                      "affected": perm_list,
                      "remediation": "Review and remove unnecessary permission usage descriptions from Info.plist."},
                output_file=str(out_file))

    log("[ios_perms] iOS permission enumeration complete")
    status("ios_perms", "iOS permission enumeration", "complete")


# ── Android network security config deep parse ──

def analyse_network_security_config(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[nsc] Starting Android network security config deep parse for {app_dir.name}...")
    status("nsc", "Network security config analysis", "running")

    nsc_path = None
    for candidate in [
        app_dir / "res" / "xml" / "network_security_config.xml",
        app_dir / "res" / "xml" / "network_security_configuration.xml",
    ]:
        if candidate.exists():
            nsc_path = candidate
            break

    if nsc_path is None:
        nsc_files = list(app_dir.rglob("network_security_config.xml"))
        if nsc_files:
            nsc_path = nsc_files[0]

    if nsc_path is None:
        log("[nsc] No network_security_config.xml found in APK — skipping")
        status("nsc", "Network security config analysis", "skipped")
        return

    log(f"[nsc] Found network security config: {nsc_path}")
    out_file = output_dir / "network_security_config_analysis.json"

    try:
        raw = nsc_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        err(f"[nsc] Failed to read network security config: {exc}")
        status("nsc", "Network security config analysis", "error")
        return

    try:
        tree = ET.parse(nsc_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        err(f"[nsc] XML parse error in network security config: {exc}")
        status("nsc", "Network security config analysis", "error")
        return

    result = {"source": str(nsc_path), "findings": []}

    base_configs = root.findall(".//base-config")
    for bc in base_configs:
        cleartext = bc.get("cleartextTrafficPermitted", "").lower()
        if cleartext == "true":
            log("[nsc] base-config allows cleartext traffic globally — finding emitted")
            result["findings"].append("base_cleartext")
            finding(title="Mobile Security: Network security config allows cleartext (base-config)",
                    severity="HIGH",
                    description=("The network_security_config.xml base-config sets "
                                 "cleartextTrafficPermitted=true, allowing unencrypted HTTP "
                                 "connections globally. On-path attackers can intercept or "
                                 "modify all plaintext traffic."),
                    data={"catalogue_id": "QUILL-APK-090",
                          "affected": str(nsc_path),
                          "remediation": "Set cleartextTrafficPermitted=false in base-config."},
                    output_file=str(out_file))

    domain_configs = root.findall(".//domain-config")
    for dc in domain_configs:
        trust_anchors = dc.findall(".//trust-anchors/certificates")
        for cert in trust_anchors:
            src = cert.get("src", "").lower()
            if src == "user":
                domains = [d.text or d.get("domain", "") for d in dc.findall(".//domain")]
                domain_list = ", ".join(d for d in domains if d)
                log(f"[nsc] domain-config trusts user certificates for: {domain_list}")
                result["findings"].append(f"user_cert_trust:{domain_list}")
                finding(title=f"Mobile Security: Domain config trusts user installed certificates",
                        severity="HIGH",
                        description=(f"The network security config trusts user-installed CA certificates "
                                     f"for domain(s): {domain_list or '(unspecified)'}. An attacker who "
                                     f"installs a rogue CA on the device can intercept HTTPS traffic "
                                     f"to these domains."),
                        data={"catalogue_id": "QUILL-APK-091",
                              "affected": domain_list or str(nsc_path),
                              "remediation": "Remove user certificates from trust-anchors; pin to specific CAs."},
                        output_file=str(out_file))

        dc_cleartext = dc.get("cleartextTrafficPermitted", "").lower()
        if dc_cleartext == "true":
            domains = [d.text or d.get("domain", "") for d in dc.findall(".//domain")]
            domain_list = ", ".join(d for d in domains if d)
            includes_subdomains = any(
                d.get("includeSubdomains", "").lower() == "true"
                for d in dc.findall(".//domain"))
            scope_note = " (including subdomains)" if includes_subdomains else ""
            log(f"[nsc] domain-config allows cleartext for: {domain_list}{scope_note}")
            result["findings"].append(f"domain_cleartext:{domain_list}")
            finding(title=f"Mobile Security: Domain permits cleartext traffic: {domain_list}",
                    severity="MEDIUM",
                    description=(f"The network security config allows cleartext HTTP for "
                                 f"domain(s): {domain_list}{scope_note}. Traffic to these "
                                 f"domains is subject to interception."),
                    data={"catalogue_id": "QUILL-APK-092",
                          "affected": domain_list or str(nsc_path),
                          "remediation": "Migrate listed domains to HTTPS and remove cleartextTrafficPermitted."},
                    output_file=str(out_file))

    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Network security config deep parse",
                  [f"source: {nsc_path}",
                   f"findings_count: {len(result['findings'])}"])

    log(f"[nsc] Network security config analysis complete — {len(result['findings'])} issue(s)")
    status("nsc", "Network security config analysis", "complete")


# ── Android SAST code analysis ───────────────────────────────────────────────

_SAST_PATTERNS = [
    (re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)"),
     "WebView JavaScript enabled", "MEDIUM", "QUILL-APK-100",
     "WebView has JavaScript enabled via setJavaScriptEnabled(true). "
     "JavaScript execution in a WebView expands the attack surface to "
     "XSS, script injection, and bridge exploitation.",
     "Disable JavaScript unless explicitly required; use addJavascriptInterface "
     "only with @JavascriptInterface annotation on API 17+."),
    (re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)"),
     "WebView file access enabled", "MEDIUM", "QUILL-APK-101",
     "WebView allows file:// URI access via setAllowFileAccess(true). "
     "An attacker who controls WebView content can read local files.",
     "Set setAllowFileAccess(false) and load content via HTTPS or assets."),
    (re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"),
     "WebView universal file URL access", "HIGH", "QUILL-APK-102",
     "WebView allows universal access from file URLs. This permits "
     "JavaScript in a file:// context to access content from any origin, "
     "enabling local file exfiltration.",
     "Set setAllowUniversalAccessFromFileURLs(false)."),
    (re.compile(r"addJavascriptInterface\s*\("),
     "JavaScript interface exposed to WebView", "MEDIUM", "QUILL-APK-103",
     "A Java object is exposed to WebView JavaScript via addJavascriptInterface. "
     "On API < 17 all public methods are accessible; on API 17+ only "
     "@JavascriptInterface-annotated methods are exposed.",
     "Ensure minSdkVersion >= 17 and annotate only safe methods with "
     "@JavascriptInterface. Validate all input from JavaScript."),
    (re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"),
     "WebView remote debugging enabled", "HIGH", "QUILL-APK-104",
     "WebView remote debugging is enabled in the application. An attacker "
     "with USB or network access can inspect and manipulate WebView content "
     "via Chrome DevTools.",
     "Disable setWebContentsDebuggingEnabled in release builds."),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
     "Runtime.exec() command execution", "HIGH", "QUILL-APK-105",
     "The application uses Runtime.exec() to execute system commands. "
     "If any argument is derived from user input, this enables arbitrary "
     "command injection.",
     "Avoid Runtime.exec() with user-controlled input. Use ProcessBuilder "
     "with explicit argument lists if shell execution is required."),
    (re.compile(r"new\s+ProcessBuilder\s*\("),
     "ProcessBuilder command execution", "MEDIUM", "QUILL-APK-106",
     "The application uses ProcessBuilder to execute system commands. "
     "Verify that command arguments are not derived from untrusted input.",
     "Validate and sanitize all ProcessBuilder arguments. Prefer Android "
     "APIs over shell commands."),
    (re.compile(r"Cipher\.getInstance\s*\(\s*[\"'](?:[^\"']*(?:ECB|DES/))"),
     "Weak cryptographic algorithm (ECB/DES)", "HIGH", "QUILL-APK-107",
     "The application uses a weak cryptographic algorithm (ECB mode or DES). "
     "ECB mode leaks plaintext patterns; DES has a 56-bit key trivially "
     "brute-forced on modern hardware.",
     "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with a random IV. "
     "Replace DES with AES-256."),
    (re.compile(r"SecureRandom\s*\(\s*\).*?\.setSeed\s*\(|\.setSeed\s*\(.*SecureRandom"),
     "SecureRandom seeded with predictable value", "MEDIUM", "QUILL-APK-108",
     "SecureRandom.setSeed() is called, which on some Android versions "
     "replaces the OS entropy source with a potentially predictable seed, "
     "weakening all subsequent random output.",
     "Do not call setSeed() on SecureRandom. The default OS-seeded PRNG "
     "is cryptographically strong."),
    (re.compile(r"(?:rawQuery|execSQL)\s*\("),
     "Direct SQL query execution", "MEDIUM", "QUILL-APK-109",
     "The application uses rawQuery() or execSQL() which may concatenate "
     "user input into SQL strings, enabling SQL injection against the "
     "local SQLite database.",
     "Use parameterized queries (selectionArgs) or Room DAO instead of "
     "string concatenation in SQL statements."),
    (re.compile(r"MODE_WORLD_(?:READABLE|WRITABLE)"),
     "World-readable/writable file mode", "HIGH", "QUILL-APK-110",
     "The application creates files with MODE_WORLD_READABLE or "
     "MODE_WORLD_WRITABLE. Any app on the device can read or modify "
     "these files, exposing sensitive data.",
     "Use MODE_PRIVATE for SharedPreferences and internal files. Share "
     "data via ContentProvider with proper permissions."),
    (re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier"),
     "Hostname verification bypass", "HIGH", "QUILL-APK-111",
     "The application disables hostname verification, allowing any "
     "certificate to be accepted regardless of the hostname. This "
     "enables trivial MITM attacks.",
     "Remove ALLOW_ALL_HOSTNAME_VERIFIER. Use the default "
     "StrictHostnameVerifier."),
    (re.compile(r"setPrimaryClip\s*\("),
     "Clipboard write detected", "INFO", "QUILL-APK-112",
     "The application writes to the system clipboard via setPrimaryClip(). "
     "On Android < 10 any app can read clipboard content, potentially "
     "exposing copied sensitive data (tokens, passwords).",
     "Avoid placing sensitive data on the clipboard. If required, clear "
     "the clipboard after a short timeout."),
]

_LOG_CALL_RX = re.compile(r"\bLog\.[dviwe]\s*\(")


def analyse_android_code(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[sast] Starting Android SAST code analysis for {app_dir.name}...")
    status("sast", "Android code analysis", "running")

    out_file = output_dir / "sast_analysis.json"

    code_files: list = []
    for ext in ("smali", "java", "kt", "xml"):
        code_files.extend(app_dir.rglob(f"*.{ext}"))
    log(f"[sast] Found {len(code_files)} code file(s) to scan (smali/java/kt/xml)")

    dex_text = ""
    if not any(f.suffix == ".smali" for f in code_files):
        strings_bin = shutil.which("strings")
        if strings_bin:
            for dex in app_dir.rglob("*.dex"):
                cp = _run_tool_cmd([strings_bin, str(dex)],
                                   output_file=str(output_dir / f"sast_strings_{dex.name}.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    dex_text += (cp.stdout or "")
            if dex_text:
                log(f"[sast] No smali files — scanning DEX strings ({len(dex_text)} chars)")

    pattern_hits: dict = {}
    for pat, title, sev, cat_id, desc, remed in _SAST_PATTERNS:
        pattern_hits[cat_id] = {"title": title, "severity": sev, "cat_id": cat_id,
                                "desc": desc, "remed": remed, "files": []}

    log_call_count = 0
    log_files: list = []
    file_idx = 0
    for cf in code_files:
        file_idx += 1
        if file_idx % 50 == 0:
            _check_pause()
        try:
            text = cf.read_text(encoding="utf-8", errors="ignore")[:300000]
        except Exception:
            continue
        for pat, title, sev, cat_id, desc, remed in _SAST_PATTERNS:
            if pat.search(text):
                if len(pattern_hits[cat_id]["files"]) < 5:
                    pattern_hits[cat_id]["files"].append(str(cf))
        lc = len(_LOG_CALL_RX.findall(text))
        if lc > 0:
            log_call_count += lc
            if len(log_files) < 5:
                log_files.append(str(cf))

    if dex_text:
        for pat, title, sev, cat_id, desc, remed in _SAST_PATTERNS:
            if pat.search(dex_text) and not pattern_hits[cat_id]["files"]:
                pattern_hits[cat_id]["files"].append("(DEX strings)")
        lc = len(_LOG_CALL_RX.findall(dex_text))
        log_call_count += lc

    result = {"patterns": {}, "log_call_count": log_call_count}
    finding_count = 0
    for cat_id, info in pattern_hits.items():
        if info["files"]:
            result["patterns"][cat_id] = {"title": info["title"], "files": info["files"]}
            file_list = ", ".join(Path(f).name for f in info["files"][:5])
            finding(title=f"Android SAST: {info['title']}",
                    severity=info["severity"],
                    description=f"{info['desc']} Found in: {file_list}.",
                    data={"catalogue_id": cat_id,
                          "affected": file_list,
                          "remediation": info["remed"]},
                    output_file=str(out_file))
            finding_count += 1

    if log_call_count > 50:
        result["excessive_logging"] = True
        file_list = ", ".join(Path(f).name for f in log_files[:5])
        finding(title=f"Android SAST: Excessive logging ({log_call_count} Log calls)",
                severity="LOW",
                description=(f"The application contains {log_call_count} Log.d/v/i/w/e calls. "
                             f"Verbose logging in production can leak sensitive data to logcat, "
                             f"which is readable by other apps on rooted devices."),
                data={"catalogue_id": "QUILL-APK-113",
                      "affected": file_list,
                      "remediation": "Remove or guard debug logging with BuildConfig.DEBUG checks. "
                                     "Use ProGuard/R8 to strip Log calls in release builds."},
                output_file=str(out_file))
        finding_count += 1

    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Android SAST code analysis",
                  [f"app_dir: {app_dir}",
                   f"code_files_scanned: {len(code_files)}",
                   f"dex_fallback: {bool(dex_text)}",
                   f"patterns_matched: {finding_count}",
                   f"log_call_count: {log_call_count}"])

    log(f"[sast] Android SAST code analysis complete — {finding_count} pattern(s) matched, "
        f"{log_call_count} log call(s)")
    status("sast", "Android code analysis", "complete")


# ── Tracker SDK detection ────────────────────────────────────────────────────

_KNOWN_TRACKERS = {
    "com.google.android.gms.analytics": "Google Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.facebook.appevents": "Facebook Analytics",
    "com.facebook.ads": "Facebook Ads",
    "com.adjust.sdk": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "io.branch": "Branch.io",
    "com.mixpanel.android": "Mixpanel",
    "com.amplitude": "Amplitude",
    "com.crashlytics": "Crashlytics",
    "com.newrelic": "New Relic",
    "com.segment.analytics": "Segment",
    "com.braze": "Braze",
    "com.urbanairship": "Urban Airship",
    "com.flurry": "Flurry",
    "ly.count.android": "Countly",
    "com.clevertap": "CleverTap",
    "com.onesignal": "OneSignal",
    "com.batch.android": "Batch",
    "com.leanplum": "Leanplum",
    "com.appdynamics": "AppDynamics",
    "com.instabug": "Instabug",
    "com.bugsnag": "Bugsnag",
    "io.sentry.android": "Sentry",
}


def detect_trackers(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[trackers] Starting tracker SDK detection for {app_dir.name}...")
    status("trackers", "Tracker SDK detection", "running")

    out_file = output_dir / "tracker_analysis.json"
    found_trackers: list = []

    smali_dirs = set()
    for smali in app_dir.rglob("*.smali"):
        try:
            rel = smali.relative_to(app_dir)
            parts = list(rel.parts)
            if parts and parts[0].startswith("smali"):
                parts = parts[1:]
            pkg = ".".join(parts[:-1]) if len(parts) > 1 else ""
            if pkg:
                smali_dirs.add(pkg)
        except Exception:
            continue

    if smali_dirs:
        log(f"[trackers] Scanning {len(smali_dirs)} smali package path(s)")
        for tracker_pkg, tracker_name in _KNOWN_TRACKERS.items():
            for pkg in smali_dirs:
                if pkg.startswith(tracker_pkg):
                    found_trackers.append({"package": tracker_pkg, "name": tracker_name,
                                           "method": "smali_path", "evidence": pkg})
                    break
    else:
        log("[trackers] No smali dirs — scanning DEX strings for tracker package names")
        strings_bin = shutil.which("strings")
        dex_text = ""
        if strings_bin:
            for dex in app_dir.rglob("*.dex"):
                cp = _run_tool_cmd([strings_bin, str(dex)],
                                   output_file=str(output_dir / f"tracker_strings_{dex.name}.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    dex_text += (cp.stdout or "")
        for cf in app_dir.rglob("*.xml"):
            try:
                dex_text += cf.read_text(encoding="utf-8", errors="ignore")[:100000]
            except Exception:
                continue

        for tracker_pkg, tracker_name in _KNOWN_TRACKERS.items():
            pkg_slash = tracker_pkg.replace(".", "/")
            if tracker_pkg in dex_text or pkg_slash in dex_text:
                found_trackers.append({"package": tracker_pkg, "name": tracker_name,
                                       "method": "dex_strings"})

    seen = set()
    deduped = []
    for t in found_trackers:
        if t["package"] not in seen:
            seen.add(t["package"])
            deduped.append(t)
    found_trackers = deduped

    result = {"trackers_found": len(found_trackers), "trackers": found_trackers}
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Tracker SDK detection",
                  [f"app_dir: {app_dir}",
                   f"smali_packages: {len(smali_dirs)}",
                   f"trackers_found: {len(found_trackers)}"])

    for t in found_trackers:
        log(f"[trackers] Tracker detected: {t['name']} ({t['package']})")
        finding(title=f"Tracker SDK detected: {t['name']}",
                severity="INFO",
                description=(f"The application embeds the {t['name']} tracking SDK "
                             f"(package: {t['package']}). Tracking SDKs collect user "
                             f"behaviour data and may transmit it to third-party servers."),
                data={"catalogue_id": "QUILL-APK-120",
                      "affected": t["package"]},
                output_file=str(out_file))

    if len(found_trackers) > 5:
        names = ", ".join(t["name"] for t in found_trackers)
        finding(title=f"Excessive tracking SDKs ({len(found_trackers)} detected)",
                severity="LOW",
                description=(f"The application embeds {len(found_trackers)} tracking SDKs: "
                             f"{names}. Each SDK increases the attack surface, adds data "
                             f"collection endpoints, and expands the privacy impact."),
                data={"catalogue_id": "QUILL-APK-121",
                      "affected": names,
                      "remediation": "Review tracker necessity. Remove unused SDKs and "
                                     "consolidate analytics to reduce third-party exposure."},
                output_file=str(out_file))

    log(f"[trackers] Tracker SDK detection complete — {len(found_trackers)} tracker(s) found")
    status("trackers", "Tracker SDK detection", "complete")


# ── APKiD / packer detection ─────────────────────────────────────────────────

def analyse_apkid(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[apkid] Starting APKiD / packer detection for {app_dir.name}...")
    status("apkid", "APKiD / packer detection", "running")

    out_file = output_dir / "apkid_analysis.json"
    result: dict = {"anti_debug": [], "anti_vm": [], "packers": [], "method": "signature"}

    apkid_bin = shutil.which("apkid")
    if apkid_bin:
        log(f"[apkid] apkid binary found: {apkid_bin} — running JSON analysis")
        result["method"] = "apkid"
        apkid_out = output_dir / "apkid_raw.json"
        cp = _run_tool_cmd([apkid_bin, "-j", str(app_dir)],
                           output_file=str(apkid_out), timeout=120, tool_name="apkid")
        if cp is not None:
            raw = cp.stdout or ""
            apkid_out.write_text(raw, encoding="utf-8")
            try:
                apkid_data = json.loads(raw)
                for file_entry in apkid_data if isinstance(apkid_data, list) else [apkid_data]:
                    matches = file_entry.get("matches") or file_entry.get("results") or {}
                    for category, items in (matches.items() if isinstance(matches, dict) else []):
                        cat_l = category.lower()
                        if "anti_debug" in cat_l or "anti_disassembly" in cat_l:
                            result["anti_debug"].extend(items if isinstance(items, list) else [items])
                        elif "anti_vm" in cat_l or "anti_emulator" in cat_l:
                            result["anti_vm"].extend(items if isinstance(items, list) else [items])
                        elif "packer" in cat_l or "obfuscator" in cat_l or "protector" in cat_l:
                            result["packers"].extend(items if isinstance(items, list) else [items])
            except (json.JSONDecodeError, KeyError):
                log("[apkid] Failed to parse apkid JSON output — falling back to signatures")
                result["method"] = "signature"

    if result["method"] == "signature":
        log("[apkid] Using signature-based fallback analysis")
        all_text = ""
        file_idx = 0
        for sf in app_dir.rglob("*.smali"):
            file_idx += 1
            if file_idx % 100 == 0:
                _check_pause()
            try:
                all_text += sf.read_text(encoding="utf-8", errors="ignore")[:200000]
            except Exception:
                continue

        if not all_text:
            strings_bin = shutil.which("strings")
            if strings_bin:
                for dex in app_dir.rglob("*.dex"):
                    cp = _run_tool_cmd([strings_bin, str(dex)],
                                       output_file=str(output_dir / f"apkid_strings_{dex.name}.txt"),
                                       timeout=120, tool_name="strings")
                    if cp is not None:
                        all_text += (cp.stdout or "")

        _anti_debug_sigs = ["isDebuggerConnected", "Debug.isDebuggerConnected",
                            "ptrace", "TracerPid", "android.os.Debug"]
        _anti_vm_sigs = ["Build.FINGERPRINT", "Build.MODEL", "Build.MANUFACTURER",
                         "ro.hardware", "goldfish", "generic", "google_sdk",
                         "Emulator", "Andy", "nox", "BlueStacks"]
        _packer_sigs = {
            "com.guardsquare.dexguard": "DexGuard",
            "com.secneo": "Secneo/Bangcle",
            "com.bangcle": "Bangcle",
            "com.tencent.StubShell": "Tencent Legu",
            "com.qihoo.util": "Qihoo 360",
            "com.secshell": "SecShell",
            "com.alibaba.wireless.security": "Alibaba",
            "com.baidu.protect": "Baidu",
        }

        for sig in _anti_debug_sigs:
            if sig in all_text:
                result["anti_debug"].append(sig)
        for sig in _anti_vm_sigs:
            if sig in all_text:
                result["anti_vm"].append(sig)
        for pkg, name in _packer_sigs.items():
            pkg_slash = pkg.replace(".", "/")
            if pkg in all_text or pkg_slash in all_text:
                result["packers"].append(name)

        mapping_files = list(app_dir.rglob("mapping.txt")) + list(app_dir.rglob("proguard*"))
        if mapping_files:
            result["packers"].append("ProGuard/R8 (mapping file present)")

        for dex in app_dir.rglob("*.dex"):
            try:
                with open(dex, "rb") as f:
                    magic = f.read(8)
                if magic[:4] != b"dex\n":
                    result["packers"].append(f"Non-standard DEX header in {dex.name}")
            except Exception:
                continue

    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "APKiD / packer detection",
                  [f"app_dir: {app_dir}",
                   f"method: {result['method']}",
                   f"anti_debug: {len(result['anti_debug'])}",
                   f"anti_vm: {len(result['anti_vm'])}",
                   f"packers: {len(result['packers'])}"])

    if result["anti_debug"]:
        sigs = ", ".join(str(s) for s in result["anti_debug"][:10])
        log(f"[apkid] Anti-debug mechanisms detected: {sigs}")
        finding(title=f"Anti-debug mechanism detected ({len(result['anti_debug'])} indicator(s))",
                severity="INFO",
                description=(f"The application contains anti-debugging indicators: {sigs}. "
                             f"This is a positive security control that makes dynamic analysis "
                             f"and tampering more difficult."),
                data={"catalogue_id": "QUILL-APK-125", "affected": sigs},
                output_file=str(out_file))

    if result["anti_vm"]:
        sigs = ", ".join(str(s) for s in result["anti_vm"][:10])
        log(f"[apkid] Anti-emulator detection found: {sigs}")
        finding(title=f"Anti-emulator detection found ({len(result['anti_vm'])} indicator(s))",
                severity="INFO",
                description=(f"The application checks for emulator/VM environment: {sigs}. "
                             f"This is a positive security control that hinders automated "
                             f"analysis in emulated environments."),
                data={"catalogue_id": "QUILL-APK-126", "affected": sigs},
                output_file=str(out_file))

    if result["packers"]:
        names = ", ".join(str(s) for s in result["packers"][:10])
        log(f"[apkid] Packer/obfuscator detected: {names}")
        finding(title=f"Packer/obfuscator detected: {names}",
                severity="INFO",
                description=(f"The application uses code protection: {names}. "
                             f"Obfuscation and packing make reverse engineering more "
                             f"difficult, which is a positive security measure."),
                data={"catalogue_id": "QUILL-APK-127", "affected": names},
                output_file=str(out_file))

    if not result["anti_debug"] and not result["anti_vm"] and not result["packers"]:
        log("[apkid] No obfuscation, anti-debug, or anti-VM mechanisms detected")
        finding(title="No code protection/obfuscation detected",
                severity="LOW",
                description=("The application does not appear to use code obfuscation, "
                             "packing, anti-debugging, or anti-emulator protections. "
                             "The APK can be trivially decompiled and analysed."),
                data={"catalogue_id": "QUILL-APK-128",
                      "remediation": "Apply ProGuard/R8 at minimum. Consider DexGuard or "
                                     "similar commercial protectors for high-value apps."},
                output_file=str(out_file))

    log(f"[apkid] APKiD / packer detection complete — method={result['method']}")
    status("apkid", "APKiD / packer detection", "complete")


# ── Firebase detection ────────────────────────────────────────────────────────

_FIREBASE_DB_RX = re.compile(r"https?://[a-zA-Z0-9._-]+\.firebaseio\.com[^\s\"'<>]*")
_FIREBASE_STORAGE_RX = re.compile(r"https?://firebasestorage\.googleapis\.com[^\s\"'<>]*")
_FIREBASE_REMOTE_CONFIG_RX = re.compile(
    r"FirebaseRemoteConfig|com\.google\.firebase\.remoteconfig|"
    r"com/google/firebase/remoteconfig")


def detect_firebase(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[firebase] Starting Firebase detection for {app_dir.name}...")
    status("firebase", "Firebase detection", "running")

    out_file = output_dir / "firebase_analysis.json"
    result: dict = {"db_urls": [], "storage_urls": [], "google_services": None,
                    "remote_config": False}

    text_exts = {"xml", "json", "smali", "java", "kt", "properties", "txt", "cfg", "yml", "yaml"}
    all_text = ""
    file_idx = 0
    for ext in text_exts:
        for f in app_dir.rglob(f"*.{ext}"):
            file_idx += 1
            if file_idx % 50 == 0:
                _check_pause()
            try:
                all_text += f.read_text(encoding="utf-8", errors="ignore")[:200000]
            except Exception:
                continue

    strings_bin = shutil.which("strings")
    if strings_bin:
        for dex in app_dir.rglob("*.dex"):
            cp = _run_tool_cmd([strings_bin, str(dex)],
                               output_file=str(output_dir / f"firebase_strings_{dex.name}.txt"),
                               timeout=120, tool_name="strings")
            if cp is not None:
                all_text += (cp.stdout or "")

    db_urls = list(set(_FIREBASE_DB_RX.findall(all_text)))
    storage_urls = list(set(_FIREBASE_STORAGE_RX.findall(all_text)))
    has_remote_config = bool(_FIREBASE_REMOTE_CONFIG_RX.search(all_text))
    result["db_urls"] = db_urls[:20]
    result["storage_urls"] = storage_urls[:20]
    result["remote_config"] = has_remote_config

    gs_files = list(app_dir.rglob("google-services.json"))
    if gs_files:
        gs_path = gs_files[0]
        log(f"[firebase] google-services.json found: {gs_path}")
        try:
            gs_data = json.loads(gs_path.read_text(encoding="utf-8"))
            project_id = (gs_data.get("project_info") or {}).get("project_id", "")
            result["google_services"] = {"path": str(gs_path), "project_id": project_id}
        except Exception:
            result["google_services"] = {"path": str(gs_path), "project_id": ""}

    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Firebase detection",
                  [f"app_dir: {app_dir}",
                   f"db_urls: {len(db_urls)}",
                   f"storage_urls: {len(storage_urls)}",
                   f"google_services: {result['google_services'] is not None}",
                   f"remote_config: {has_remote_config}"])

    for url in db_urls[:10]:
        log(f"[firebase] Firebase Realtime Database URL: {url}")
        finding(title=f"Firebase Realtime Database URL detected",
                severity="MEDIUM",
                description=(f"The application references a Firebase Realtime Database: {url}. "
                             f"If database rules allow unauthenticated reads, anyone can "
                             f"access the data by appending .json to the URL."),
                data={"catalogue_id": "QUILL-APK-130", "affected": url,
                      "remediation": "Review Firebase Realtime Database security rules. "
                                     "Ensure authentication is required for all read/write operations."},
                output_file=str(out_file))

    for url in storage_urls[:10]:
        log(f"[firebase] Firebase Storage URL: {url}")
        finding(title=f"Firebase Storage URL detected",
                severity="MEDIUM",
                description=(f"The application references Firebase Storage: {url}. "
                             f"If storage rules are misconfigured, files may be publicly "
                             f"downloadable or uploadable."),
                data={"catalogue_id": "QUILL-APK-131", "affected": url,
                      "remediation": "Review Firebase Storage security rules. "
                                     "Require authentication for all read/write operations."},
                output_file=str(out_file))

    if result["google_services"]:
        pid = result["google_services"].get("project_id", "(unknown)")
        finding(title=f"Google Services configuration file present (project: {pid})",
                severity="INFO",
                description=(f"google-services.json found with project ID: {pid}. "
                             f"This file contains Firebase project configuration including "
                             f"API keys and project identifiers. While not secret per se, "
                             f"it identifies the backend infrastructure."),
                data={"catalogue_id": "QUILL-APK-132",
                      "affected": pid},
                output_file=str(out_file))

    if has_remote_config:
        log("[firebase] Firebase Remote Config usage detected")
        finding(title="Firebase Remote Config in use",
                severity="INFO",
                description=("The application uses Firebase Remote Config, which fetches "
                             "configuration values from Google's servers at runtime. "
                             "Ensure the config does not control security-sensitive "
                             "parameters (feature flags for auth, URLs, keys)."),
                data={"catalogue_id": "QUILL-APK-133"},
                output_file=str(out_file))

    log(f"[firebase] Firebase detection complete — {len(db_urls)} DB URL(s), "
        f"{len(storage_urls)} storage URL(s)")
    status("firebase", "Firebase detection", "complete")


# ── Certificate / signing analysis ───────────────────────────────────────────

def analyse_signing(apk_path: Path, app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[signing] Starting APK signing analysis for {apk_path.name}...")
    status("signing", "APK signing analysis", "running")

    out_file = output_dir / "signing_analysis.json"
    result: dict = {"v1": False, "v2": False, "v3": False, "certs": [],
                    "tool_used": None, "raw_output": ""}

    apksigner = shutil.which("apksigner")
    if apksigner:
        log(f"[signing] Using apksigner: {apksigner}")
        result["tool_used"] = "apksigner"
        raw_file = output_dir / "apksigner_output.txt"
        cp = _run_tool_cmd([apksigner, "verify", "--print-certs", "-v", str(apk_path)],
                           output_file=str(raw_file), timeout=60, tool_name="apksigner")
        if cp is not None:
            raw = (cp.stdout or "") + (cp.stderr or "")
            raw_file.write_text(raw, encoding="utf-8")
            result["raw_output"] = raw[:5000]

            result["v1"] = "Verified using v1 scheme (JAR signing): true" in raw
            result["v2"] = "Verified using v2 scheme (APK Signature Scheme v2): true" in raw
            result["v3"] = "Verified using v3 scheme (APK Signature Scheme v3): true" in raw

            for line in raw.splitlines():
                line_s = line.strip()
                if line_s.startswith("Signer #") and "certificate" in line_s.lower():
                    continue
                if "DN:" in line_s or "CN=" in line_s:
                    result["certs"].append(line_s)
                if "digest algorithm:" in line_s.lower() or "signature algorithm:" in line_s.lower():
                    result["certs"].append(line_s)
    else:
        jarsigner = shutil.which("jarsigner")
        if jarsigner:
            log(f"[signing] apksigner not found — using jarsigner: {jarsigner}")
            result["tool_used"] = "jarsigner"
            raw_file = output_dir / "jarsigner_output.txt"
            cp = _run_tool_cmd([jarsigner, "-verify", "-verbose", "-certs", str(apk_path)],
                               output_file=str(raw_file), timeout=60, tool_name="jarsigner")
            if cp is not None:
                raw = (cp.stdout or "") + (cp.stderr or "")
                raw_file.write_text(raw, encoding="utf-8")
                result["raw_output"] = raw[:5000]
                result["v1"] = "jar verified" in raw.lower()
                for line in raw.splitlines():
                    if "CN=" in line or "Owner:" in line or "Issuer:" in line:
                        result["certs"].append(line.strip())
        else:
            log("[signing] Neither apksigner nor jarsigner available — skipping signing analysis")
            status("signing", "APK signing analysis", "skipped")
            return

    out_file.write_text(json.dumps({k: v for k, v in result.items() if k != "raw_output"},
                                    indent=2), encoding="utf-8")
    _analysis_log(out_file, "APK signing analysis",
                  [f"apk: {apk_path}",
                   f"tool: {result['tool_used']}",
                   f"v1: {result['v1']}, v2: {result['v2']}, v3: {result['v3']}",
                   f"certs: {len(result['certs'])}"])

    raw = result["raw_output"]

    if result["v1"] and not result["v2"] and not result["v3"]:
        log("[signing] Only v1 (JAR) signing — vulnerable to Janus CVE-2017-13156")
        finding(title="APK uses only v1 (JAR) signing — Janus vulnerability (CVE-2017-13156)",
                severity="HIGH",
                description=("The APK is signed only with the v1 (JAR) signature scheme. "
                             "V1-only signed APKs are vulnerable to the Janus attack "
                             "(CVE-2017-13156), which allows prepending a DEX file to the "
                             "APK without invalidating the signature."),
                data={"catalogue_id": "QUILL-APK-140",
                      "affected": str(apk_path),
                      "cves": "CVE-2017-13156",
                      "remediation": "Sign with v2 (or v3) APK Signature Scheme in addition to v1."},
                output_file=str(out_file))

    weak_algos = []
    for algo in ("SHA1withRSA", "MD5withRSA", "SHA1withDSA", "MD5withDSA"):
        if algo in raw:
            weak_algos.append(algo)
    if weak_algos:
        algo_str = ", ".join(weak_algos)
        log(f"[signing] Weak signature algorithm detected: {algo_str}")
        finding(title=f"Weak signing algorithm: {algo_str}",
                severity="MEDIUM",
                description=(f"The APK certificate uses weak signature algorithm(s): "
                             f"{algo_str}. SHA-1 and MD5 are vulnerable to collision attacks."),
                data={"catalogue_id": "QUILL-APK-141",
                      "affected": algo_str,
                      "remediation": "Re-sign with SHA-256 (SHA256withRSA or SHA256withECDSA)."},
                output_file=str(out_file))

    if "Android Debug" in raw or "CN=Android Debug" in raw:
        log("[signing] Debug certificate detected")
        finding(title="APK signed with debug certificate",
                severity="HIGH",
                description=("The APK is signed with the Android debug keystore certificate "
                             "(CN=Android Debug). Debug-signed apps cannot be published to "
                             "the Play Store and their private key is publicly known."),
                data={"catalogue_id": "QUILL-APK-143",
                      "affected": str(apk_path),
                      "remediation": "Sign with a production release keystore before distribution."},
                output_file=str(out_file))

    cert_summary = "; ".join(result["certs"][:5]) if result["certs"] else "(no cert details extracted)"
    schemes = []
    if result["v1"]:
        schemes.append("v1")
    if result["v2"]:
        schemes.append("v2")
    if result["v3"]:
        schemes.append("v3")
    scheme_str = "+".join(schemes) if schemes else "unknown"
    finding(title=f"APK signing details: {scheme_str}",
            severity="INFO",
            description=(f"APK signing scheme(s): {scheme_str}. "
                         f"Certificate details: {cert_summary}"),
            data={"catalogue_id": "QUILL-APK-140",
                  "affected": str(apk_path)},
            output_file=str(out_file))

    log(f"[signing] APK signing analysis complete — schemes: {scheme_str}")
    status("signing", "APK signing analysis", "complete")


# ── Browsable activities / deep link analysis ────────────────────────────────

def analyse_browsable_activities(app_dir: Path, output_dir: Path,
                                 manifest_data: dict) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[deeplinks] Starting browsable activity / deep link analysis for {app_dir.name}...")
    status("deeplinks", "Deep link analysis", "running")

    out_file = output_dir / "deep_link_analysis.json"
    deep_links: list = []

    manifest_path = app_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        log("[deeplinks] AndroidManifest.xml not found — skipping")
        status("deeplinks", "Deep link analysis", "skipped")
        return

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        err(f"[deeplinks] Manifest parse error: {exc}")
        status("deeplinks", "Deep link analysis", "error")
        return

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    package = manifest_data.get("package", root.get("package", ""))
    app_el = root.find("application")
    if app_el is None:
        log("[deeplinks] No <application> element — skipping")
        status("deeplinks", "Deep link analysis", "complete")
        return

    comp_map = {}
    for c in manifest_data.get("components", []):
        comp_map[c.get("name", "")] = c

    for activity in app_el.findall("activity"):
        act_name = activity.get(f"{{{ns['android']}}}name",
                                activity.get("name", ""))
        for intent_filter in activity.findall("intent-filter"):
            categories = [c.get(f"{{{ns['android']}}}name",
                                c.get("name", ""))
                          for c in intent_filter.findall("category")]
            if "android.intent.category.BROWSABLE" not in categories:
                continue

            data_elements = intent_filter.findall("data")
            schemes_hosts: list = []
            for d in data_elements:
                scheme = d.get(f"{{{ns['android']}}}scheme",
                               d.get("scheme", ""))
                host = d.get(f"{{{ns['android']}}}host",
                             d.get("host", ""))
                path = d.get(f"{{{ns['android']}}}path",
                             d.get("path", ""))
                path_prefix = d.get(f"{{{ns['android']}}}pathPrefix",
                                    d.get("pathPrefix", ""))
                path_pattern = d.get(f"{{{ns['android']}}}pathPattern",
                                     d.get("pathPattern", ""))
                entry = {"scheme": scheme, "host": host}
                if path:
                    entry["path"] = path
                if path_prefix:
                    entry["pathPrefix"] = path_prefix
                if path_pattern:
                    entry["pathPattern"] = path_pattern
                schemes_hosts.append(entry)

            comp_info = comp_map.get(act_name, {})
            is_exported = comp_info.get("exported", True)
            has_permission = bool(comp_info.get("permission", ""))

            link_entry = {
                "activity": act_name,
                "exported": is_exported,
                "permission": comp_info.get("permission", ""),
                "data": schemes_hosts,
            }
            deep_links.append(link_entry)

            uri_parts = []
            for sh in schemes_hosts:
                uri = f"{sh['scheme']}://{sh['host']}" if sh.get("scheme") and sh.get("host") else ""
                if uri and sh.get("pathPrefix"):
                    uri += sh["pathPrefix"]
                elif uri and sh.get("path"):
                    uri += sh["path"]
                if uri:
                    uri_parts.append(uri)
            uri_str = ", ".join(uri_parts) if uri_parts else "(no scheme+host)"

            log(f"[deeplinks] Browsable activity: {act_name} → {uri_str}")
            finding(title=f"Browsable activity: {act_name}",
                    severity="INFO",
                    description=(f"Activity {act_name} is registered with BROWSABLE category "
                                 f"and handles deep links: {uri_str}. Any app or web page can "
                                 f"invoke this activity via an intent URL."),
                    data={"catalogue_id": "QUILL-APK-150",
                          "affected": f"{package}/{act_name}"},
                    output_file=str(out_file))

            if is_exported and not has_permission:
                finding(title=f"Unprotected browsable activity: {act_name}",
                        severity="MEDIUM",
                        description=(f"Activity {act_name} is exported, browsable, and has no "
                                     f"permission guard. Deep links ({uri_str}) can be crafted "
                                     f"to invoke it with arbitrary parameters. Verify all "
                                     f"intent extras and URI parameters are validated."),
                        data={"catalogue_id": "QUILL-APK-151",
                              "affected": f"{package}/{act_name}",
                              "remediation": "Add input validation for all intent extras and URI parameters. "
                                             "Consider adding a custom permission or signature-level protection."},
                        output_file=str(out_file))

    result = {"total_deep_links": len(deep_links), "deep_links": deep_links}
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Deep link analysis",
                  [f"app_dir: {app_dir}",
                   f"package: {package}",
                   f"browsable_activities: {len(deep_links)}"])

    log(f"[deeplinks] Deep link analysis complete — {len(deep_links)} browsable activity/activities")
    status("deeplinks", "Deep link analysis", "complete")


# ── Behaviour pattern analysis ───────────────────────────────────────────────

_BEHAVIOUR_CHECKS = [
    {
        "id": "QUILL-APK-160", "label": "SMS sending",
        "apis": [re.compile(r"SmsManager"), re.compile(r"sendTextMessage|sendMultipartTextMessage")],
        "permissions": {"android.permission.SEND_SMS"},
        "desc_with": "The application has SMS sending capability (SmsManager) with SEND_SMS permission.",
        "desc_without": "The application uses SmsManager APIs but does NOT declare SEND_SMS permission. "
                        "It may rely on reflection, target an older SDK, or invoke via intent.",
    },
    {
        "id": "QUILL-APK-161", "label": "Phone call initiation",
        "apis": [re.compile(r"ACTION_CALL|telecomManager|TelecomManager")],
        "permissions": {"android.permission.CALL_PHONE"},
        "desc_with": "The application can initiate phone calls (ACTION_CALL / TelecomManager) with CALL_PHONE permission.",
        "desc_without": "The application references call-initiation APIs without CALL_PHONE permission.",
    },
    {
        "id": "QUILL-APK-162", "label": "Contact access",
        "apis": [re.compile(r"ContactsContract|content://contacts|content://com\.android\.contacts")],
        "permissions": {"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"},
        "desc_with": "The application accesses the device contacts database with appropriate permission.",
        "desc_without": "The application references contact APIs without declaring READ_CONTACTS or WRITE_CONTACTS.",
    },
    {
        "id": "QUILL-APK-163", "label": "Location tracking",
        "apis": [re.compile(r"requestLocationUpdates|getLastKnownLocation|FusedLocationProviderClient|LocationManager")],
        "permissions": {"android.permission.ACCESS_FINE_LOCATION",
                        "android.permission.ACCESS_COARSE_LOCATION",
                        "android.permission.ACCESS_BACKGROUND_LOCATION"},
        "desc_with": "The application tracks device location via GPS/network providers with location permission.",
        "desc_without": "The application references location APIs without declaring location permissions.",
    },
    {
        "id": "QUILL-APK-164", "label": "Camera capture",
        "apis": [re.compile(r"ACTION_IMAGE_CAPTURE|camera\.open|Camera\.open|CameraManager|camera2")],
        "permissions": {"android.permission.CAMERA"},
        "desc_with": "The application captures images/video via camera APIs with CAMERA permission.",
        "desc_without": "The application references camera APIs without declaring CAMERA permission.",
    },
    {
        "id": "QUILL-APK-165", "label": "Audio recording",
        "apis": [re.compile(r"MediaRecorder|AudioRecord|RECORD_AUDIO")],
        "permissions": {"android.permission.RECORD_AUDIO"},
        "desc_with": "The application can record audio via MediaRecorder/AudioRecord with RECORD_AUDIO permission.",
        "desc_without": "The application references audio recording APIs without RECORD_AUDIO permission.",
    },
]


def analyse_behaviour_patterns(app_dir: Path, output_dir: Path,
                               manifest_data: dict) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[behaviour] Starting behaviour pattern analysis for {app_dir.name}...")
    status("behaviour", "Behaviour analysis", "running")

    out_file = output_dir / "behaviour_analysis.json"
    declared_perms = set(manifest_data.get("permissions", []))
    package = manifest_data.get("package", "")
    log(f"[behaviour] {len(declared_perms)} declared permission(s) for cross-reference")

    all_text = ""
    file_idx = 0
    for ext in ("smali", "java", "kt"):
        for f in app_dir.rglob(f"*.{ext}"):
            file_idx += 1
            if file_idx % 50 == 0:
                _check_pause()
            try:
                all_text += f.read_text(encoding="utf-8", errors="ignore")[:200000]
            except Exception:
                continue

    if not all_text:
        strings_bin = shutil.which("strings")
        if strings_bin:
            for dex in app_dir.rglob("*.dex"):
                cp = _run_tool_cmd([strings_bin, str(dex)],
                                   output_file=str(output_dir / f"behaviour_strings_{dex.name}.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    all_text += (cp.stdout or "")

    results: list = []
    for check in _BEHAVIOUR_CHECKS:
        api_found = False
        for rx in check["apis"]:
            if rx.search(all_text):
                api_found = True
                break
        if not api_found:
            continue

        has_perm = bool(check["permissions"] & declared_perms)
        entry = {
            "id": check["id"],
            "label": check["label"],
            "api_found": True,
            "permission_declared": has_perm,
            "matching_permissions": sorted(check["permissions"] & declared_perms),
        }
        results.append(entry)

        if has_perm:
            log(f"[behaviour] {check['label']}: API present + permission declared")
            finding(title=f"Behaviour: {check['label']} capability detected",
                    severity="INFO",
                    description=check["desc_with"],
                    data={"catalogue_id": check["id"], "affected": package},
                    output_file=str(out_file))
        else:
            log(f"[behaviour] {check['label']}: API present WITHOUT permission — suspicious")
            finding(title=f"Behaviour: {check['label']} API without permission",
                    severity="MEDIUM",
                    description=check["desc_without"],
                    data={"catalogue_id": check["id"], "affected": package,
                          "remediation": "Investigate how the API is used. The app may "
                                         "use reflection, invoke via implicit intent, or "
                                         "target an older SDK that grants the permission "
                                         "implicitly."},
                    output_file=str(out_file))

    result_doc = {"behaviours_detected": len(results), "behaviours": results}
    out_file.write_text(json.dumps(result_doc, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Behaviour pattern analysis",
                  [f"app_dir: {app_dir}",
                   f"package: {package}",
                   f"declared_permissions: {len(declared_perms)}",
                   f"behaviours_detected: {len(results)}"])

    log(f"[behaviour] Behaviour analysis complete — {len(results)} pattern(s) detected")
    status("behaviour", "Behaviour analysis", "complete")


# ── File hash computation ──

def compute_file_hashes(file_path: Path, output_dir: Path) -> None:
    _check_pause()
    log(f"[hashes] Computing file hashes for {file_path.name}...")
    status("hashes", "File hash computation", "running")

    out_file = output_dir / "file_hashes.json"
    if not file_path.exists():
        err(f"[hashes] File not found: {file_path}")
        status("hashes", "File hash computation", "error")
        return

    file_size = file_path.stat().st_size
    log(f"[hashes] File size: {file_size / 1048576:.1f} MB — computing MD5, SHA1, SHA256...")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except Exception as exc:
        err(f"[hashes] Hash computation failed: {exc}")
        status("hashes", "File hash computation", "error")
        return

    result = {
        "file": str(file_path),
        "file_name": file_path.name,
        "file_size": file_size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "File hash computation",
                  [f"file: {file_path}",
                   f"size: {file_size}",
                   f"md5: {result['md5']}",
                   f"sha1: {result['sha1']}",
                   f"sha256: {result['sha256']}"])

    log(f"[hashes] MD5:    {result['md5']}")
    log(f"[hashes] SHA1:   {result['sha1']}")
    log(f"[hashes] SHA256: {result['sha256']}")
    log("[hashes] File hash computation complete")
    status("hashes", "File hash computation", "complete")


# ── Dynamic analysis (Frida) ─────────────────────────────────────────────────

_FRIDA_SSL_PINNING_SCRIPT = """
Java.perform(function() {
    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'quill.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var tm = [TrustManager.$new()];
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, tm, null);
    SSLContext.setDefault(ctx);
    send({type: 'ssl_bypass', status: 'injected'});
});
"""

_FRIDA_ROOT_DETECT_SCRIPT = """
Java.perform(function() {
    var f = Java.use('java.io.File');
    var origExists = f.exists;
    f.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var sus = ['/system/app/Superuser.apk', '/system/xbin/su', '/sbin/su',
                   '/data/local/xbin/su', '/data/local/bin/su', '/su/bin/su',
                   '/system/bin/.ext/su', '/system/bin/failsafe/su'];
        for (var i = 0; i < sus.length; i++) {
            if (path === sus[i]) {
                send({type: 'root_detect', path: path, bypassed: true});
                return false;
            }
        }
        return origExists.call(this);
    };
    send({type: 'root_detect', status: 'hooks_installed'});
});
"""

_FRIDA_DATA_STORAGE_SCRIPT = """
Java.perform(function() {
    // SharedPreferences monitoring
    var sp = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    sp.putString.implementation = function(key, value) {
        send({type: 'shared_pref', key: key, value_preview: (value || '').substring(0, 100)});
        return this.putString(key, value);
    };

    // SQLite monitoring
    try {
        var db = Java.use('android.database.sqlite.SQLiteDatabase');
        db.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
            send({type: 'sqlite_query', sql: sql});
            return this.rawQuery(sql, args);
        };
    } catch(e) {}

    send({type: 'data_storage', status: 'hooks_installed'});
});
"""

_FRIDA_CRYPTO_SCRIPT = """
Java.perform(function() {
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.getInstance.overload('java.lang.String').implementation = function(transform) {
        send({type: 'crypto', transform: transform});
        return this.getInstance(transform);
    };

    try {
        var md = Java.use('java.security.MessageDigest');
        md.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type: 'crypto_hash', algorithm: algo});
            return this.getInstance(algo);
        };
    } catch(e) {}

    send({type: 'crypto', status: 'hooks_installed'});
});
"""

_FRIDA_WEBVIEW_SCRIPT = """
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    try {
        WebView.setWebContentsDebuggingEnabled.implementation = function(enabled) {
            send({type: 'webview_debug', enabled: enabled});
            return this.setWebContentsDebuggingEnabled(enabled);
        };
    } catch(e) {}

    try {
        var ws = Java.use('android.webkit.WebSettings');
        ws.setJavaScriptEnabled.implementation = function(enabled) {
            send({type: 'webview_js', enabled: enabled});
            return this.setJavaScriptEnabled(enabled);
        };
    } catch(e) {}

    send({type: 'webview', status: 'hooks_installed'});
});
"""

_FRIDA_IOS_JAILBREAK_SCRIPT = """
if (ObjC.available) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    Interceptor.attach(fm['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) {
            var path = ObjC.Object(args[2]).toString();
            var sus = ['/Applications/Cydia.app', '/Library/MobileSubstrate',
                       '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt',
                       '/bin/bash', '/usr/bin/ssh'];
            for (var i = 0; i < sus.length; i++) {
                if (path === sus[i]) {
                    send({type: 'jailbreak_detect', path: path, bypassed: true});
                    args[2] = ObjC.classes.NSString.stringWithString_('/nonexistent');
                }
            }
        }
    });
    send({type: 'jailbreak_detect', status: 'hooks_installed'});
}
"""

_FRIDA_IOS_SSL_SCRIPT = """
if (ObjC.available) {
    try {
        var SSLSetSessionOption = Module.findExportByName(null, 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(ctx, opt, val) {
                if (opt === 4) { send({type: 'ssl_bypass', status: 'SSLSetSessionOption bypassed'}); return 0; }
                return new NativeFunction(SSLSetSessionOption, 'int', ['pointer', 'int', 'bool'])(ctx, opt, val);
            }, 'int', ['pointer', 'int', 'bool']));
        }
    } catch(e) {}

    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['+ sessionWithConfiguration:delegate:delegateQueue:'].implementation, {
            onEnter: function(args) { send({type: 'ssl_bypass', status: 'NSURLSession intercepted'}); }
        });
    } catch(e) {}

    send({type: 'ssl_bypass', status: 'iOS hooks installed'});
}
"""

_FRIDA_IOS_KEYCHAIN_SCRIPT = """
if (ObjC.available) {
    var SecItemAdd = Module.findExportByName(null, 'SecItemAdd');
    if (SecItemAdd) {
        Interceptor.attach(SecItemAdd, {
            onEnter: function(args) {
                send({type: 'keychain_add', status: 'item added'});
            }
        });
    }
    var SecItemCopyMatching = Module.findExportByName(null, 'SecItemCopyMatching');
    if (SecItemCopyMatching) {
        Interceptor.attach(SecItemCopyMatching, {
            onEnter: function(args) {
                send({type: 'keychain_read', status: 'item queried'});
            }
        });
    }
    send({type: 'keychain', status: 'hooks_installed'});
}
"""


def dynamic_analysis(target: str, platform: str, device: str, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[dynamic] Starting Frida dynamic analysis — target={target}, platform={platform}, device={device or 'local'}")
    status("dynamic", "Dynamic analysis", "running")

    frida_bin = shutil.which("frida")
    if not frida_bin:
        err("frida not available — install frida-tools for dynamic analysis")
        status("dynamic", "Dynamic analysis", "skipped")
        return
    log(f"[dynamic] Frida binary: {frida_bin}")

    scripts_dir = output_dir / "frida_scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    results_dir = output_dir / "dynamic_results"
    results_dir.mkdir(parents=True, exist_ok=True)

    if platform == "android":
        checks = [
            ("ssl_pinning", "SSL pinning bypass", _FRIDA_SSL_PINNING_SCRIPT, "QUILL-DYN-001"),
            ("root_detect", "Root detection bypass", _FRIDA_ROOT_DETECT_SCRIPT, "QUILL-DYN-002"),
            ("data_storage", "Data storage monitoring", _FRIDA_DATA_STORAGE_SCRIPT, "QUILL-DYN-003"),
            ("crypto", "Cryptographic API monitoring", _FRIDA_CRYPTO_SCRIPT, "QUILL-DYN-004"),
            ("webview", "WebView security", _FRIDA_WEBVIEW_SCRIPT, "QUILL-DYN-005"),
        ]
    else:
        checks = [
            ("ssl_pinning", "SSL pinning bypass", _FRIDA_IOS_SSL_SCRIPT, "QUILL-DYN-010"),
            ("jailbreak_detect", "Jailbreak detection bypass", _FRIDA_IOS_JAILBREAK_SCRIPT, "QUILL-DYN-011"),
            ("keychain", "Keychain monitoring", _FRIDA_IOS_KEYCHAIN_SCRIPT, "QUILL-DYN-012"),
        ]

    log(f"[dynamic] Running {len(checks)} Frida check(s) on {platform} target")
    for check_id, label, script_code, catalogue_id in checks:
        _check_pause()
        log(f"[dynamic] Injecting Frida script: {label} ({check_id})...")
        status("dynamic", f"Dynamic: {label}", "running")
        script_file = scripts_dir / f"{check_id}.js"
        result_file = results_dir / f"{check_id}.json"
        script_file.write_text(script_code, encoding="utf-8")

        cmd = [frida_bin]
        if device:
            cmd.extend(["-D", device])
        cmd.extend(["-n", target, "-l", str(script_file), "--no-pause", "-q"])

        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(result_file), timeout=30,
                                    tool_name="frida",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = cp.stdout or ""
            result_file.write_text(output, encoding="utf-8")

            if "bypassed" in output.lower() or "injected" in output.lower():
                sev = "HIGH" if "ssl" in check_id or "root" in check_id or "jailbreak" in check_id else "MEDIUM"
                log(f"[dynamic] {label} — VULNERABLE (bypass/injection successful, severity={sev})")
                finding(title=f"Dynamic: {label} — vulnerable",
                         severity=sev,
                         description=f"Frida {label} check succeeded, indicating the app is vulnerable to {label.lower()}.",
                         data={"catalogue_id": catalogue_id, "affected": target, "command": " ".join(cmd)},
                         output_file=str(result_file))
            elif output.strip():
                log(f"[dynamic] {label} — output captured ({len(output)} bytes), no bypass detected")
            else:
                log(f"[dynamic] {label} — no output (app may not exercise this path)")
        except subprocess.TimeoutExpired:
            log(f"[dynamic] {label}: timeout (30s) — app may have anti-frida protection")
            finding(title=f"Dynamic: {label} — possible anti-instrumentation",
                     severity="INFO",
                     description=f"Frida script for {label} timed out, which may indicate anti-instrumentation defenses.",
                     data={"catalogue_id": catalogue_id, "affected": target},
                     output_file=str(script_file))
        except Exception as exc:
            err(f"Dynamic {check_id} error: {exc}")
        log(f"[dynamic] {label} check done")
        status("dynamic", f"Dynamic: {label}", "complete")

    log(f"[dynamic] Dynamic analysis complete — {len(checks)} check(s) executed")
    status("dynamic", "Dynamic analysis", "complete")


# ── Shared utilities ──────────────────────────────────────────────────────────

def _risk_counts(findings: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = str(f.get("risk", "")).upper()
        if r in rc:
            rc[r] += 1
    return rc


def _write_findings_csv(path: Path, findings: list) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            for fd in findings:
                w.writerow({k: fd.get(k, "") for k in _CSV_FIELDS})
    except Exception as exc:
        err(f"findings.csv write failed: {exc}")


def _detect_platform(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext == ".ipa":
        return "ios"
    elif ext == ".apk":
        return "android"
    return ""


def main() -> int:
    global _pause

    p = argparse.ArgumentParser(prog="quill",
                                  description="Quill — Mobile application security analysis tool")
    p.add_argument("--app", help="Path to .ipa or .apk file")
    p.add_argument("--ipa", help="Path to .ipa archive (legacy, same as --app)")
    p.add_argument("--platform", choices=["ios", "android", "auto"], default="auto",
                     help="Target platform (default: auto-detect from file extension)")
    p.add_argument("--dynamic", action="store_true", help="Enable Frida-based dynamic analysis")
    p.add_argument("--device", default="", help="Frida device ID (for --dynamic)")
    p.add_argument("--target-process", default="", help="Target process name for dynamic analysis")
    p.add_argument("--client-short", default="default")
    p.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    p.add_argument("--engagement-name", default="quill run", help="Engagement name for meta.json")
    p.add_argument("--project", help="Override project output directory")
    p.add_argument("--version", action="store_true")
    args = p.parse_args()

    if args.version:
        print(VERSION)
        return 0

    app_path = args.app or args.ipa
    if not app_path:
        p.error("--app (or --ipa) is required")

    platform = args.platform
    if platform == "auto":
        platform = _detect_platform(app_path)
        if not platform:
            p.error(f"Cannot detect platform from extension: {app_path} — use --platform ios|android")
        log(f"[init] Auto-detected platform: {platform} (from file extension)")
    else:
        log(f"[init] Platform specified: {platform}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        project_dir = Path(args.project)
    elif _us is not None:
        project_dir = _us.universal_run_dir(args.client_short, "quill",
                                              year=datetime.now().strftime("%Y"),
                                              ts=ts)
    else:
        project_dir = Path.cwd() / f"quill_{args.client_short}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)
    log(f"[init] Output directory: {project_dir}")

    global _RUN_DIR, _RUNLOG
    _RUN_DIR = project_dir
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
            log("[init] Event logger initialised (scan.log + errors.log)")
        except Exception:
            _RUNLOG = None

    if _PP is not None:
        _pause = _PP(project_dir, "quill")
        _pause.start_watcher(
            checkpoint_callback=_save_checkpoint,
            grace_period=30,
        )
        log("[init] Pause manager active (grace=30s)")

    if _us is not None:
        _us.write_meta(project_dir, _us.make_meta(
            tool="quill", version=VERSION,
            client_short=args.client_short,
            client_name=(args.client_name or args.client_short),
            engagement_name=args.engagement_name,
            target=app_path))
        log("[init] meta.json written (universal schema)")
        try:
            import pr0t31n_dep_snapshot as _ds
            _ds.write_snapshot(
                project_dir, "quill", VERSION,
                binaries=["strings", "apktool", "frida", "codesign", "otool", "nm",
                          "apkid", "apksigner", "jarsigner"],
                pip_packages=[],
            )
        except Exception:
            pass

    global _APP_TARGET, _EXTRACT_BASE
    _APP_TARGET = Path(app_path).name
    log(f"[init] Quill v{VERSION} starting — {platform.upper()}: {app_path}")
    log(f"[init] Client: {args.client_short}, Engagement: {args.engagement_name}")
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    extract_dir = project_dir / "extract"
    _EXTRACT_BASE = extract_dir

    _check_pause()
    if platform == "ios":
        app_dir = extract_ipa(Path(app_path), extract_dir)
        if not app_dir:
            return 1
        _check_pause()
        plist_data = analyse_info_plist(app_dir, project_dir)
        _check_pause()
        analyse_entitlements(app_dir, project_dir)
        _check_pause()
        analyse_strings(app_dir, project_dir)
        _check_pause()
        analyse_ios_binary(app_dir, project_dir)
        _check_pause()
        analyse_ios_binary_code(app_dir, project_dir)
        _check_pause()
        analyse_ios_frameworks(app_dir, project_dir)
        _check_pause()
        analyse_ios_permissions(app_dir, project_dir, plist_data)
        _check_pause()
        compute_file_hashes(Path(app_path), project_dir)
    elif platform == "android":
        app_dir = extract_apk(Path(app_path), extract_dir)
        if not app_dir:
            return 1
        _check_pause()
        manifest_data = analyse_manifest(app_dir, project_dir)
        _check_pause()
        analyse_permissions(app_dir, project_dir, manifest_data)
        _check_pause()
        analyse_strings_apk(app_dir, project_dir)
        _check_pause()
        analyse_network_security_config(app_dir, project_dir)
        _check_pause()
        analyse_android_code(app_dir, project_dir)
        _check_pause()
        detect_trackers(app_dir, project_dir)
        _check_pause()
        analyse_apkid(app_dir, project_dir)
        _check_pause()
        detect_firebase(app_dir, project_dir)
        _check_pause()
        analyse_signing(Path(app_path), app_dir, project_dir)
        _check_pause()
        analyse_browsable_activities(app_dir, project_dir, manifest_data)
        _check_pause()
        analyse_behaviour_patterns(app_dir, project_dir, manifest_data)
        _check_pause()
        compute_file_hashes(Path(app_path), project_dir)

    _check_pause()
    if args.dynamic:
        log("[main] Dynamic analysis requested — resolving target process...")
        target_process = args.target_process
        if not target_process:
            if platform == "android":
                app_dir_for_pkg = extract_dir
                manifest = app_dir_for_pkg / "AndroidManifest.xml"
                if not manifest.exists() and app_dir:
                    manifest = app_dir / "AndroidManifest.xml"
                if manifest.exists():
                    try:
                        tree = ET.parse(manifest)
                        target_process = tree.getroot().get("package", "")
                    except Exception:
                        pass
            if not target_process:
                target_process = Path(app_path).stem
            log(f"[main] Dynamic target process resolved: {target_process}")
        dynamic_analysis(target_process, platform, args.device, project_dir)

    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log(f"[finalize] Analysis phases complete — writing output files...")

    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="quill") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        _write_findings_csv(project_dir / "findings.csv", out)
        log(f"[finalize] findings.json + findings.csv written ({len(out)} findings, universal schema)")
        try:
            summary = _us.make_summary(
                tool="quill", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=app_path,
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
            log(f"[finalize] summary.json written — {_risk_counts(out)}")
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        _write_findings_csv(project_dir / "findings.csv", _findings)
        log(f"[finalize] findings.json + findings.csv written ({len(_findings)} findings, legacy format)")

    log("[finalize] Generating cross-tool action items...")
    _generate_cross_tool_action_items(project_dir)
    if _pause is not None:
        _pause.write_stop_reason("completed", "all_phases_done")
    rc = _risk_counts(_findings)
    log(f"[shutdown] Quill v{VERSION} complete — {len(_findings)} finding(s) "
        f"(C={rc['CRITICAL']} H={rc['HIGH']} M={rc['MEDIUM']} L={rc['LOW']} I={rc['INFO']}) — output: {project_dir}")
    return 0


def _generate_cross_tool_action_items(project_dir: Path) -> None:
    """Emit cross-tool action items based on Quill analysis findings."""
    _CLOUD_PATTERNS = ("aws", "azure", "google", "stripe")
    _API_PATTERNS = ("api key", "api_key", "apikey", "bearer", "jwt", "token")

    fj = project_dir / "findings.json"
    if not fj.exists():
        log("[cross-tool] No findings.json found — skipping action item generation")
        return
    try:
        findings = json.loads(fj.read_text(encoding="utf-8"))
    except Exception:
        log("[cross-tool] Failed to parse findings.json — skipping action items")
        return
    log(f"[cross-tool] Analysing {len(findings)} finding(s) for cross-tool opportunities...")

    items: list = []
    seen: set = set()

    def _add(item_type, tool, target, title, desc, priority="MEDIUM",
             source_finding="", metadata=None):
        key = (tool.lower(), target.lower(), title.strip().lower())
        if key in seen:
            return
        seen.add(key)
        items.append({
            "id": str(uuid.uuid4()),
            "type": item_type,
            "recommended_tool": tool,
            "target": target,
            "ip": "", "port": 0, "hostname": "",
            "title": title,
            "description": desc,
            "source_finding": source_finding,
            "priority": priority,
            "scope": "ext",
            "status": "pending",
            "datetime": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        })

    _api_urls: set = set()
    _webview_urls: set = set()

    # Scan string_findings.txt for URLs and API endpoints
    sf_path = project_dir / "string_findings.txt"
    if sf_path.exists():
        try:
            sf_text = sf_path.read_text(encoding="utf-8", errors="ignore")
            for url_m in re.finditer(r'https?://[^\s"\'<>\]]{10,}', sf_text):
                url = url_m.group(0).rstrip(".,;)")
                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                except Exception:
                    continue
                if not host or host in ("localhost", "127.0.0.1"):
                    continue
                if any(kw in url.lower() for kw in
                       ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
                    _api_urls.add(url)
                else:
                    _webview_urls.add(url)
        except Exception:
            pass

    if _api_urls:
        log(f"[cross-tool] Found {len(_api_urls)} API URL(s) in string findings")
    if _webview_urls:
        log(f"[cross-tool] Found {len(_webview_urls)} web URL(s) in string findings")

    # API URLs → Siphon
    _api_hosts: set = set()
    for url in list(_api_urls)[:20]:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if host in _api_hosts:
            continue
        _api_hosts.add(host)
        _add("api", "Siphon", url, f"API endpoint from mobile app: {host}",
             f"Quill extracted API endpoint {url} from the mobile application. "
             f"Siphon can test this API for authentication, authorization, "
             f"injection, and data exposure vulnerabilities.",
             priority="HIGH", source_finding="Mobile app API endpoint")

    # WebView URLs → Fracture
    _web_hosts: set = set()
    for url in list(_webview_urls)[:20]:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if host in _web_hosts or host in _api_hosts:
            continue
        _web_hosts.add(host)
        _add("web_app", "Fracture", url, f"Web target from mobile app: {host}",
             f"Quill extracted URL {url} from the mobile application. "
             f"Fracture can test this web target for vulnerabilities.",
             priority="MEDIUM", source_finding="Mobile app embedded URL")

    # Findings-based action items
    for f in findings:
        title_l = (f.get("title") or "").lower()
        data = f.get("data") or {}

        # Cloud credentials → Forge
        if any(kw in title_l for kw in _CLOUD_PATTERNS):
            _add("cloud_audit", "Forge",
                 data.get("affected", "mobile app"),
                 f"Cloud credential from mobile app",
                 f"Quill found {f.get('title', 'a cloud credential')} in the mobile "
                 f"application. Forge can audit the associated cloud environment "
                 f"for misconfigurations and exposed resources.",
                 priority="CRITICAL",
                 source_finding=f.get("title", ""))

        # API keys → Siphon
        if any(kw in title_l for kw in _API_PATTERNS):
            _add("api", "Siphon",
                 data.get("affected", "mobile app"),
                 f"API credential from mobile app",
                 f"Quill found {f.get('title', 'an API credential')} in the mobile "
                 f"application. Siphon can use discovered credentials to test "
                 f"API endpoints for authorization flaws.",
                 priority="HIGH",
                 source_finding=f.get("title", ""))

        # Private keys / certs → Isotope
        if "private key" in title_l or "certificate" in title_l:
            _add("file_analysis", "Isotope",
                 data.get("affected", "mobile app"),
                 f"Certificate/key from mobile app",
                 f"Quill found {f.get('title', 'embedded key material')} in the mobile "
                 f"application. Isotope can perform deeper certificate chain "
                 f"analysis and extract additional metadata.",
                 priority="HIGH",
                 source_finding=f.get("title", ""))

    if not items:
        log("[cross-tool] No cross-tool action items generated")
        return
    ai_path = project_dir / "action_items.json"
    try:
        existing = json.loads(ai_path.read_text(encoding="utf-8")) if ai_path.exists() else []
    except Exception:
        existing = []
    existing.extend(items)
    ai_path.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")
    log(f"[cross-tool] {len(items)} action item(s) generated")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
