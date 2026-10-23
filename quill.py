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


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:[{datetime.now().isoformat()}] {msg}", flush=True)
    else:
        print(f"[{_ts()}] {msg}", flush=True)


def log(msg: str) -> None:
    _tok("__CRUCIBLE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__CRUCIBLE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__CRUCIBLE_STATUS__",
         json.dumps({"phase": phase, "label": label, "state": state, "step": step,
                     "ts": datetime.now().isoformat()}))


def finding(*, title: str, severity: str, description: str,
             data: dict | None = None, output_file: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    if _us is not None:
        rec = _us.make_finding(
            tool="quill", title=title, risk=severity.upper(),
            description=description, ip="0.0.0.0", port=0,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=(data or {}).get("affected", ""),
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
        finding(title="Mobile Security: App Transport Security: arbitrary loads allowed",
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
            finding(title=f"Mobile Security: ATS exception allows HTTP for {dom}",
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
            finding(title=f"Mobile Security: Custom URL scheme registered: {sch}://",
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
            finding(title="Mobile Security: get-task-allow enabled (debuggable binary)",
                     severity="HIGH",
                     description=("get-task-allow=true permits attaching a debugger; "
                                   "should be FALSE in production builds."),
                     data={"catalogue_id": "QUILL-IOS-020",
                           "remediation": "Set get-task-allow=false in entitlements before App Store submission."},
                     output_file=str(out_file))
        log("[entitlements] Checking application-identifier for wildcards...")
        if "application-identifier" in ent and "wildcard" in ent.lower():
            log("[entitlements] Wildcard application-identifier detected — finding emitted")
            finding(title="Mobile Security: Wildcard application-identifier in entitlements",
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
            finding(title=f"Information Disclosure: Potential hard-coded secret: {label}",
                     severity="HIGH",
                     description=(f"Pattern matching {label} was found in {source}. "
                                   "Verify whether this is a real secret or a test fixture."),
                     data={"catalogue_id": "QUILL-IOS-030",
                           "affected": source,
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
            finding(title=f"Information Disclosure: Potential hard-coded secret: {label}",
                     severity="HIGH",
                     description=(f"Pattern matching {label} was found in {source}. "
                                   "Verify whether this is a real secret or a test fixture."),
                     data={"catalogue_id": "QUILL-APK-040",
                           "affected": source,
                           "evidence": match[:80]},
                     output_file=str(out_file))
    else:
        log("[strings_apk] No hard-coded secrets detected in APK bundle")

    log("[strings_apk] APK hard-coded secret scan complete")
    status("strings_apk", "APK hard-coded secret scan", "complete")


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
                binaries=["strings", "apktool", "frida", "codesign"],
                pip_packages=[],
            )
        except Exception:
            pass

    log(f"[init] Quill v{VERSION} starting — {platform.upper()}: {app_path}")
    log(f"[init] Client: {args.client_short}, Engagement: {args.engagement_name}")
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    extract_dir = project_dir / "extract"

    _check_pause()
    if platform == "ios":
        app_dir = extract_ipa(Path(app_path), extract_dir)
        if not app_dir:
            return 1
        _check_pause()
        analyse_info_plist(app_dir, project_dir)
        _check_pause()
        analyse_entitlements(app_dir, project_dir)
        _check_pause()
        analyse_strings(app_dir, project_dir)
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
