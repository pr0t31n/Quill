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
import logging
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

import atexit as _atexit_mod, signal as _sig
_sig.signal(_sig.SIGTERM, lambda s, f: sys.exit(128 + s))

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

try:
    from androguard.core.axml import AXMLPrinter as _AXMLPrinter
    logging.getLogger("androguard").setLevel(logging.WARNING)
except ImportError:
    _AXMLPrinter = None

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
             data: dict | None = None, output_file: str = "",
             output: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    affected = _clean_affected((data or {}).get("affected", ""))
    src_excerpt = output[:4096] if output else ""
    if _us is not None:
        rec = _us.make_finding(
            tool="quill", title=title, risk=severity.upper(),
            description=description, ip="", port=0,
            hostname=_APP_TARGET,
            command=(data or {}).get("command", ""),
            output=src_excerpt,
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
            "output": src_excerpt,
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
        ats_excerpt = json.dumps(ats, default=str, indent=2)[:512]
        finding(title="Network Security: App Transport Security Arbitrary Loads Allowed",
                 severity="HIGH",
                 description=("NSAllowsArbitraryLoads=true disables ATS globally; "
                               "non-HTTPS connections are permitted."),
                 data={"catalogue_id": "QUILL-IOS-001",
                       "affected": bundle_id,
                       "remediation": "Remove NSAllowsArbitraryLoads or restrict to specific domains."},
                 output=f"Info.plist NSAppTransportSecurity:\n{ats_excerpt}",
                 output_file=str(out_file))
    exc_domains = ats.get("NSExceptionDomains") or {}
    if exc_domains:
        log(f"[info_plist] ATS: {len(exc_domains)} exception domain(s) configured")
    for dom, cfg in exc_domains.items():
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
            log(f"[info_plist] ATS: HTTP exception for domain {dom} — finding emitted")
            dom_cfg_str = json.dumps({dom: cfg}, default=str, indent=2)[:400]
            finding(title=f"Network Security: ATS Exception Allows HTTP for {dom}",
                     severity="MEDIUM",
                     description=("Per-domain exception allows cleartext HTTP."),
                     data={"catalogue_id": "QUILL-IOS-002",
                           "affected": f"{bundle_id} / {dom}"},
                     output=f"Info.plist NSExceptionDomains:\n{dom_cfg_str}",
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
                     output=f"Info.plist CFBundleURLSchemes: \"{sch}\"",
                     output_file=str(out_file))

    pinned_domains = ats.get("NSPinnedDomains") or {}
    if pinned_domains:
        pin_list = ", ".join(sorted(pinned_domains.keys())[:10])
        log(f"[info_plist] ATS: Certificate pinning configured for {len(pinned_domains)} domain(s): {pin_list}")
    else:
        log("[info_plist] ATS: No NSPinnedDomains — no ATS-level certificate pinning configured")
        finding(title="Certificate pinning not configured in App Transport Security",
                severity="MEDIUM",
                description=("The Info.plist NSAppTransportSecurity dictionary does not contain "
                             "NSPinnedDomains. Without certificate pinning, the application "
                             "relies solely on the device trust store for TLS validation, "
                             "allowing man-in-the-middle attacks by anyone who can install a "
                             "trusted CA certificate on the device (iOS 14+ supports native "
                             "ATS pinning via NSPinnedDomains)."),
                data={"catalogue_id": "QUILL-IOS-030",
                      "affected": bundle_id,
                      "remediation": "Add NSPinnedDomains to NSAppTransportSecurity in Info.plist "
                                     "with SPKI digests for critical API domains, or implement "
                                     "pinning in code using URLSessionDelegate or TrustKit."},
                output=f"Info.plist NSAppTransportSecurity:\n"
                       f"  NSPinnedDomains: NOT PRESENT\n"
                       f"  ATS config keys: {', '.join(ats.keys()) if ats else '(empty/absent)'}",
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
            gta_idx = ent.find("get-task-allow")
            gta_ctx = ent[max(0, gta_idx - 40):gta_idx + 80].strip()
            finding(title="Build Configuration: get-task-allow Enabled (Debuggable Binary)",
                     severity="HIGH",
                     description=("get-task-allow=true permits attaching a debugger; "
                                   "should be FALSE in production builds."),
                     data={"catalogue_id": "QUILL-IOS-020",
                           "remediation": "Set get-task-allow=false in entitlements before App Store submission."},
                     output=f"Entitlements excerpt:\n{gta_ctx}",
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
                     output=f"Source: {clean_src}\nMatch: {match[:200]}",
                     output_file=str(out_file))
    else:
        log("[strings] No hard-coded secrets detected in IPA bundle")
    log("[strings] Hard-coded secret scan complete")
    status("strings", "Hard-coded secret scan", "complete")


# ── APK extraction ────────────────────────────────────────────────────────────


def _decode_binary_xml_inplace(extract_dir: Path) -> bool:
    if _AXMLPrinter is None:
        log("[extract] androguard not installed — cannot decode binary XML in-place")
        return False
    ag_log = logging.getLogger("androguard")
    ag_log.setLevel(logging.WARNING)
    ag_file_handler = None
    if _RUN_DIR is not None:
        try:
            ag_log_path = _RUN_DIR / "androguard_debug.log"
            ag_file_handler = logging.FileHandler(str(ag_log_path), mode="w")
            ag_file_handler.setLevel(logging.DEBUG)
            ag_file_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
            ag_log.addHandler(ag_file_handler)
            ag_log.setLevel(logging.DEBUG)
        except Exception:
            ag_file_handler = None
    targets = []
    manifest = extract_dir / "AndroidManifest.xml"
    if manifest.exists():
        targets.append(manifest)
    res_xml = extract_dir / "res" / "xml"
    if res_xml.is_dir():
        targets.extend(f for f in res_xml.iterdir() if f.suffix == ".xml")
    decoded = 0
    for xml_path in targets:
        try:
            ET.parse(xml_path)
            continue
        except ET.ParseError:
            pass
        try:
            raw = xml_path.read_bytes()
            ap = _AXMLPrinter(raw)
            text = ap.get_xml()
            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="replace")
            xml_path.write_text(text, encoding="utf-8")
            decoded += 1
            log(f"[extract] Decoded binary XML: {xml_path.name}")
        except Exception as exc:
            err(f"[extract] Failed to decode {xml_path.name}: {exc}")
    if ag_file_handler is not None:
        ag_log.removeHandler(ag_file_handler)
        ag_file_handler.close()
        ag_log.setLevel(logging.WARNING)
    if decoded:
        log(f"[extract] Decoded {decoded} binary XML file(s) via androguard")
        return True
    return False


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

    _needs_decode = False
    _manifest = dest / "AndroidManifest.xml"
    if _manifest.exists():
        try:
            ET.parse(_manifest)
        except ET.ParseError:
            _needs_decode = True
            log("[extract] Binary XML manifest detected — decoding needed")
    elif not (dest / "classes.dex").exists():
        _needs_decode = True
        log("[extract] Standard manifest/dex not found — unusual archive")

    if _needs_decode:
        if _decode_binary_xml_inplace(dest):
            log("[extract] In-place binary XML decode successful")
        else:
            apktool = shutil.which("apktool")
            if apktool:
                log(f"[extract] Falling back to apktool decode ({apktool})")
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
                err("[extract] Neither androguard nor apktool available — binary XML cannot be decoded")
    else:
        log("[extract] Standard APK layout confirmed (text XML manifest)")

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
                     output=f"AndroidManifest.xml: <application android:debuggable=\"true\" ...>",
                     output_file=str(out_file))

        if allow_backup:
            backup_explicit = _attr(app_el, "allowBackup")
            backup_src = f'android:allowBackup="{backup_explicit}"' if backup_explicit else "android:allowBackup not set (defaults to true)"
            finding(title="Application allows backup",
                     severity="MEDIUM",
                     description="android:allowBackup is true (or not explicitly set to false), "
                                 "allowing adb backup to extract application data including databases and shared preferences.",
                     data={"catalogue_id": "QUILL-APK-002", "affected": package,
                           "remediation": "Set android:allowBackup=false or implement a BackupAgent with encryption."},
                     output=f"AndroidManifest.xml: <application {backup_src} ...>",
                     output_file=str(out_file))

        if use_cleartext:
            log("[manifest] usesCleartextTraffic=true — finding emitted")
            finding(title="Cleartext traffic allowed",
                     severity="HIGH",
                     description="android:usesCleartextTraffic=true allows unencrypted HTTP connections globally.",
                     data={"catalogue_id": "QUILL-APK-003", "affected": package,
                           "remediation": "Set usesCleartextTraffic=false and use a network security config for exceptions."},
                     output=f"AndroidManifest.xml: <application android:usesCleartextTraffic=\"true\" ...>",
                     output_file=str(out_file))

        defined_perms = set()
        for pdef in root.findall("permission"):
            pn = _attr(pdef, "name")
            if pn:
                defined_perms.add(pn)
        for pdef in root.findall("permission-group"):
            pn = _attr(pdef, "name")
            if pn:
                defined_perms.add(pn)

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
                xml_snippet = ET.tostring(comp, encoding="unicode")[:500] if comp is not None else ""
                if is_exported and not perm:
                    if name and not name.endswith(".MainActivity"):
                        finding(title=f"Exported {comp_type} without permission: {name}",
                                 severity="MEDIUM",
                                 description=f"The {comp_type} {name} is exported and accessible by any app "
                                             "without requiring a permission. An attacker could invoke it directly.",
                                 data={"catalogue_id": "QUILL-APK-010", "affected": f"{package}/{name}",
                                       "remediation": f"Set android:exported=false or add a permission attribute to {name}."},
                                 output=f"AndroidManifest.xml excerpt:\n{xml_snippet}",
                                 output_file=str(out_file))
                if is_exported and perm and perm not in defined_perms and not perm.startswith("android.permission."):
                    finding(title=f"Exported {comp_type} protected by undefined permission: {name}",
                             severity="HIGH",
                             description=(f"The {comp_type} {name} is exported and protected by permission "
                                          f"'{perm}', which is not defined in the app's manifest. Any app "
                                          f"can declare this permission and access the component."),
                             data={"catalogue_id": "QUILL-APK-011", "affected": f"{package}/{name}",
                                   "remediation": f"Define the permission '{perm}' with <permission> in the manifest, "
                                                  "or use a system-defined permission."},
                             output=f"AndroidManifest.xml excerpt:\n{xml_snippet}\n\n"
                                    f"Defined permissions in manifest: {sorted(defined_perms) if defined_perms else '(none)'}",
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
                     output=f"AndroidManifest.xml: <uses-sdk android:minSdkVersion=\"{min_sdk}\" android:targetSdkVersion=\"{target_sdk}\" />",
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
        perm_list_str = "\n".join(f"  {p}" for p in dangerous)
        finding(title=f"Excessive dangerous permissions ({len(dangerous)})",
                 severity="MEDIUM",
                 description=f"The application requests {len(dangerous)} dangerous permissions. "
                             "Excessive permission requests expand the attack surface and increase "
                             "the risk of data leakage if the app is compromised.",
                 data={"catalogue_id": "QUILL-APK-030", "affected": package,
                       "remediation": "Review and remove unnecessary dangerous permissions."},
                 output=f"AndroidManifest.xml dangerous permissions:\n{perm_list_str}",
                 output_file=str(out_file))

    log(f"[permissions] Emitting individual findings for {len(dangerous)} dangerous permission(s)")
    for perm in dangerous:
        short = perm.rsplit(".", 1)[-1]
        finding(title=f"Dangerous permission: {short}",
                 severity="INFO",
                 description=f"The app requests {perm}, classified as a dangerous (runtime) permission by Android.",
                 data={"catalogue_id": "QUILL-APK-031", "affected": f"{package} / {short}"},
                 output=f"AndroidManifest.xml: <uses-permission android:name=\"{perm}\" />",
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
                     output=f"Source: {clean_src}\nMatch: {match[:200]}",
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
            results["signed"] = ("Signature size=" in cs_out or
                                  "Signature=" in cs_out or
                                  "valid on disk" in cs_out.lower())
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
            nm_lines = nm_out.strip().splitlines()
            local_syms = 0
            for _nmline in nm_lines:
                _parts = _nmline.strip().split()
                if len(_parts) >= 2:
                    _tc = _parts[0] if len(_parts[0]) == 1 else (_parts[1] if len(_parts) >= 2 and len(_parts[1]) == 1 else "")
                    if _tc and _tc != "U" and _tc != "u":
                        local_syms += 1
            results["symbols_stripped"] = local_syms < 10 or "no symbols" in nm_stderr.lower()
            log(f"{pfx}nm: {len(nm_lines)} total, {local_syms} local symbol(s), stripped={results.get('symbols_stripped')}")

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

    bin_name = binary.name
    if "nx" in results and not results["nx"]:
        finding(title="Binary Security: NX (No-Execute) Bit Not Confirmed",
                severity="MEDIUM",
                description=("The binary does not appear to have the NX/MH_NO_HEAP_EXECUTION flag set. "
                             "Modern iOS enforces NX when PIE is enabled; missing PIE implies NX may "
                             "not be enforced, increasing exploitability of memory corruption bugs."),
                data={"catalogue_id": "QUILL-IOS-040",
                      "affected": str(binary),
                      "remediation": "Enable PIE (Position Independent Executable) which implicitly enables NX on iOS."},
                output=f"otool -hv {bin_name}: MH_NO_HEAP_EXECUTION flag absent",
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
                output=f"otool -hv {bin_name}: MH_PIE flag absent in Mach-O header",
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
                output=f"nm -u {bin_name}: ___stack_chk_fail and ___stack_chk_guard symbols absent",
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
                output=f"nm -u {bin_name}: _objc_release symbol absent",
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
                output=f"otool -l {bin_name}: LC_RPATH load command present",
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
                output=f"codesign -dv {bin_name}: no valid signature found",
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
                output=f"otool -l {bin_name}: LC_ENCRYPTION_INFO cryptid=0 (not encrypted)",
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
                output=f"nm {bin_name}: debug symbols present (not stripped)",
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
                output=f"nm -u {binary.name}: imported unsafe symbols:\n" + "\n".join(f"  {s}" for s in insecure_found),
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
                output=f"nm -u {binary.name}: _NSLog symbol imported (undefined external)",
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
                output=f"nm -u {binary.name}: _malloc imported, _calloc absent",
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
            weak_detail = []
            if "missing stack canary" in weaknesses:
                weak_detail.append(f"nm -u {bname}: ___stack_chk_fail absent")
            if "ARC not enabled" in weaknesses:
                weak_detail.append(f"nm -u {bname}: _objc_release absent")
            finding(title=f"Framework Binary Weakness: {', '.join(weaknesses)}",
                    severity="MEDIUM",
                    description=(f"The {btype} binary {bname} has the following security weakness(es): "
                                 f"{', '.join(weaknesses)}. Embedded frameworks are part of the app's "
                                 f"attack surface and should meet the same binary hardening standards "
                                 f"as the main executable."),
                    data={"catalogue_id": "QUILL-IOS-055",
                          "affected": f"{bname} ({btype})",
                          "remediation": "Rebuild the framework with stack protection (-fstack-protector-all) and ARC enabled."},
                    output="\n".join(weak_detail),
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
                output=f"Info.plist: {p['key']} = \"{p['reason'][:200]}\"",
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
                output="Info.plist dangerous permissions:\n" + "\n".join(f"  {p['key']}: {p['reason'][:80]}" for p in dangerous_found),
                output_file=str(out_file))

    log("[ios_perms] iOS permission enumeration complete")
    status("ios_perms", "iOS permission enumeration", "complete")


# ── iOS runtime protections (jailbreak detection + code-level pinning) ───────

_IOS_JB_DETECT_PATTERNS = [
    re.compile(rb"(?:IOSSecuritySuite|isJailbroken|amIJailbroken)"),
    re.compile(rb"(?:/Applications/Cydia\.app|/Library/MobileSubstrate|/usr/sbin/sshd)"),
    re.compile(rb"(?:/bin/bash|/usr/bin/ssh|/etc/apt|/private/var/lib/apt)"),
    re.compile(rb"DTTJailbreakDetection|JailBreakDetection|JailbreakChecker"),
    re.compile(rb"canOpenURL.*?cydia://"),
]

_IOS_PINNING_PATTERNS = [
    re.compile(rb"TrustKit|trustkit"),
    re.compile(rb"AFSecurityPolicy|evaluateServerTrust"),
    re.compile(rb"SecTrustSetAnchorCertificates"),
    re.compile(rb"CertificatePinner|SSLPinning"),
    re.compile(rb"URLSessionPinningDelegate|didReceiveChallenge.*?serverTrust"),
    re.compile(rb"Alamofire.*?ServerTrustManager"),
]


def analyse_ios_runtime_protections(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log("[ios_rprot] Checking iOS runtime protections (jailbreak detection, code-level pinning)...")
    status("ios_rprot", "iOS runtime protection analysis", "running")

    binary_data = b""
    app_binary = None
    for f in app_dir.iterdir():
        if f.is_file() and not f.suffix and f.stat().st_size > 10000:
            app_binary = f
            break
    if app_binary is None:
        for f in app_dir.rglob("*"):
            if f.is_file() and f.suffix == "" and f.stat().st_size > 50000:
                app_binary = f
                break

    if app_binary:
        try:
            binary_data = app_binary.read_bytes()[:20_000_000]
        except Exception:
            pass

    for fw_dir in app_dir.rglob("*.framework"):
        for f in fw_dir.iterdir():
            if f.is_file() and not f.suffix and f.stat().st_size > 5000:
                try:
                    binary_data += f.read_bytes()[:5_000_000]
                except Exception:
                    pass
        if len(binary_data) > 30_000_000:
            break

    strings_text = b""
    strings_bin = shutil.which("strings")
    if strings_bin and app_binary:
        cp = _run_tool_cmd([strings_bin, "-n", "8", str(app_binary)],
                           output_file=str(output_dir / "ios_rprot_strings.txt"),
                           timeout=120, tool_name="strings")
        if cp is not None and cp.stdout:
            strings_text = cp.stdout.encode("utf-8", errors="ignore")

    search_data = binary_data + strings_text

    jb_found: list = []
    for pat in _IOS_JB_DETECT_PATTERNS:
        m = pat.search(search_data)
        if m:
            jb_found.append(m.group().decode("utf-8", errors="replace")[:80])

    if not jb_found:
        log("[ios_rprot] No jailbreak detection mechanisms found — finding emitted")
        finding(title="No jailbreak detection implemented",
                severity="MEDIUM",
                description=("The iOS application does not implement jailbreak detection. "
                             "No evidence of IOSSecuritySuite, Cydia path checks, "
                             "DTTJailbreakDetection, or other jailbreak detection patterns "
                             "was found in the application binary. Applications without "
                             "jailbreak detection can be more easily analysed and attacked "
                             "on jailbroken devices."),
                data={"catalogue_id": "QUILL-IOS-031",
                      "affected": "Application binary",
                      "remediation": "Implement jailbreak detection using IOSSecuritySuite "
                                     "or equivalent. The application can warn users, restrict "
                                     "functionality, or refuse to run on compromised devices."},
                output="Jailbreak detection indicators searched:\n"
                       "  IOSSecuritySuite, isJailbroken, Cydia.app, MobileSubstrate,\n"
                       "  DTTJailbreakDetection, /bin/bash, /usr/bin/ssh, canOpenURL cydia://\n"
                       "Result: NONE FOUND")
    else:
        jb_str = ", ".join(jb_found[:5])
        log(f"[ios_rprot] Jailbreak detection found: {jb_str}")

    pin_found: list = []
    for pat in _IOS_PINNING_PATTERNS:
        m = pat.search(search_data)
        if m:
            pin_found.append(m.group().decode("utf-8", errors="replace")[:80])

    if not pin_found:
        log("[ios_rprot] No code-level certificate pinning found — finding emitted")
        finding(title="No code-level certificate pinning detected in binary",
                severity="MEDIUM",
                description=("The iOS application binary does not contain evidence of "
                             "code-level certificate pinning. No references to TrustKit, "
                             "AFSecurityPolicy, SecTrustSetAnchorCertificates, "
                             "URLSessionPinningDelegate, or Alamofire ServerTrustManager "
                             "were found. Combined with no NSPinnedDomains in Info.plist, "
                             "the application relies entirely on the device trust store."),
                data={"catalogue_id": "QUILL-IOS-032",
                      "affected": "Application binary",
                      "remediation": "Implement certificate pinning using TrustKit, "
                                     "URLSession delegate challenges with SecTrust, "
                                     "or NSPinnedDomains in Info.plist (iOS 14+)."},
                output="Certificate pinning indicators searched in binary:\n"
                       "  TrustKit, AFSecurityPolicy, SecTrustSetAnchorCertificates,\n"
                       "  CertificatePinner, URLSessionPinningDelegate, Alamofire ServerTrustManager\n"
                       "Result: NONE FOUND")
    else:
        pin_str = ", ".join(pin_found[:5])
        log(f"[ios_rprot] Code-level pinning found: {pin_str}")

    log("[ios_rprot] iOS runtime protection analysis complete")
    status("ios_rprot", "iOS runtime protection analysis", "complete")


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
        log("[nsc] No network_security_config.xml found — no NSC-level certificate pinning")
        finding(title="Certificate pinning not configured in network security config",
                severity="MEDIUM",
                description=("No network_security_config.xml was found in the APK. Without a "
                             "network security configuration, the application has no certificate "
                             "pinning via the Android NSC mechanism, relying solely on the device "
                             "trust store for TLS validation."),
                data={"catalogue_id": "QUILL-APK-146",
                      "affected": "network_security_config.xml (absent)",
                      "remediation": "Add a network_security_config.xml with <pin-set> elements "
                                     "for critical domains. Reference it in AndroidManifest.xml via "
                                     "android:networkSecurityConfig."},
                output="network_security_config.xml: NOT FOUND in APK\n"
                       "Certificate pinning via Android Network Security Configuration is not configured.")
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
            bc_xml = ET.tostring(bc, encoding="unicode")[:500]
            finding(title="Mobile Security: Network security config allows cleartext (base-config)",
                    severity="HIGH",
                    description=("The network_security_config.xml base-config sets "
                                 "cleartextTrafficPermitted=true, allowing unencrypted HTTP "
                                 "connections globally. On-path attackers can intercept or "
                                 "modify all plaintext traffic."),
                    data={"catalogue_id": "QUILL-APK-090",
                          "affected": str(nsc_path),
                          "remediation": "Set cleartextTrafficPermitted=false in base-config."},
                    output=f"network_security_config.xml:\n{bc_xml}",
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
                dc_xml = ET.tostring(dc, encoding="unicode")[:500]
                finding(title=f"Mobile Security: Domain config trusts user installed certificates",
                        severity="HIGH",
                        description=(f"The network security config trusts user-installed CA certificates "
                                     f"for domain(s): {domain_list or '(unspecified)'}. An attacker who "
                                     f"installs a rogue CA on the device can intercept HTTPS traffic "
                                     f"to these domains."),
                        data={"catalogue_id": "QUILL-APK-091",
                              "affected": domain_list or str(nsc_path),
                              "remediation": "Remove user certificates from trust-anchors; pin to specific CAs."},
                        output=f"network_security_config.xml:\n{dc_xml}",
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
            dc_ct_xml = ET.tostring(dc, encoding="unicode")[:500]
            finding(title=f"Mobile Security: Domain permits cleartext traffic: {domain_list}",
                    severity="MEDIUM",
                    description=(f"The network security config allows cleartext HTTP for "
                                 f"domain(s): {domain_list}{scope_note}. Traffic to these "
                                 f"domains is subject to interception."),
                    data={"catalogue_id": "QUILL-APK-092",
                          "affected": domain_list or str(nsc_path),
                          "remediation": "Migrate listed domains to HTTPS and remove cleartextTrafficPermitted."},
                    output=f"network_security_config.xml:\n{dc_ct_xml}",
                    output_file=str(out_file))

    pin_sets = tree.findall(".//pin-set") if tree is not None else []
    if not pin_sets:
        log("[nsc] No <pin-set> elements found — certificate pinning not configured via NSC")
        result["findings"].append("no_pin_set")
        finding(title="Certificate pinning not configured in network security config",
                severity="MEDIUM",
                description=("The network_security_config.xml does not contain any <pin-set> "
                             "elements. Without certificate pinning, the application relies solely "
                             "on the device trust store for TLS validation, allowing man-in-the-middle "
                             "attacks by anyone who can install a trusted CA certificate on the device."),
                data={"catalogue_id": "QUILL-APK-146",
                      "affected": str(nsc_path),
                      "remediation": "Add <pin-set> with backup pins for critical domains. "
                                     "Use the SubjectPublicKeyInfo digest of the leaf or intermediate CA."},
                output=f"network_security_config.xml present but contains no <pin-set> elements.\n"
                       f"Parsed from: {nsc_path}",
                output_file=str(out_file))
    else:
        pin_domains = []
        for ps in pin_sets:
            parent = ps.find("..")
            if parent is not None:
                for d in parent.findall(".//domain"):
                    pin_domains.append(d.text or "(unnamed)")
        log(f"[nsc] Certificate pinning configured for {len(pin_domains)} domain(s)")

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

_DEX_SAST_PATTERNS = [
    (re.compile(r"(?:AES|DES|Blowfish|RC[24])/CBC/PKCS[57]Padding"),
     "Cipher with CBC/PKCS padding (padding oracle risk)", "HIGH", "QUILL-APK-114",
     "The application uses CBC mode with PKCS5/PKCS7 padding. This combination "
     "is vulnerable to padding oracle attacks that can decrypt ciphertext "
     "without the key.",
     "Use AES/GCM/NoPadding which provides authenticated encryption."),
    (re.compile(r"(?:^|\W)(?:SHA-?1)(?:\W|$)", re.IGNORECASE),
     "Weak SHA-1 hash algorithm", "MEDIUM", "QUILL-APK-117",
     "The application uses SHA-1 which is deprecated and vulnerable to "
     "collision attacks (SHAttered, 2017).",
     "Migrate to SHA-256 or SHA-3 for all cryptographic hashing."),
    (re.compile(r"(?:^|\W)MD5(?:\W|$)"),
     "Weak MD5 hash algorithm", "MEDIUM", "QUILL-APK-118",
     "The application uses MD5 which is cryptographically broken.",
     "Replace MD5 with SHA-256 or SHA-3."),
    (re.compile(r"java\.util\.Random"),
     "Insecure random number generator (java.util.Random)", "MEDIUM", "QUILL-APK-119",
     "The application uses java.util.Random which is not cryptographically "
     "secure. Its output is predictable given enough observations.",
     "Use java.security.SecureRandom for security-sensitive randomness."),
    (re.compile(r"getExternal(?:StorageDirectory|FilesDir|CacheDir)"),
     "External storage access", "LOW", "QUILL-APK-134",
     "The application accesses external storage which is world-readable "
     "on Android < 10. Sensitive files stored here are accessible by any app.",
     "Use internal storage (getFilesDir()) for sensitive data."),
    (re.compile(r"createTempFile"),
     "Temporary file creation", "LOW", "QUILL-APK-135",
     "The application creates temporary files which may be created in a "
     "shared directory, accessible by other apps.",
     "Create temp files in the app's internal cache directory."),
    (re.compile(r"DES(?:ede)?/"),
     "Weak DES/3DES cipher usage", "MEDIUM", "QUILL-APK-115",
     "The application references DES or 3DES. DES uses a 56-bit key "
     "and is trivially brute-forced on modern hardware.",
     "Replace DES/3DES with AES-256."),
    (re.compile(r"/ECB/"),
     "ECB cipher mode (pattern leakage)", "HIGH", "QUILL-APK-116",
     "The application uses ECB cipher mode. ECB leaks plaintext patterns "
     "since identical plaintext blocks produce identical ciphertext blocks.",
     "Use CBC with random IV, or preferably GCM mode."),
    (re.compile(r"(?:rawQuery|execSQL|compileStatement)\s*\("),
     "Raw SQL query execution", "MEDIUM", "QUILL-APK-136",
     "The application executes raw SQL queries which may be vulnerable "
     "to SQL injection if user input is concatenated into the query string.",
     "Use parameterised queries (query() with selectionArgs, or Room DAO)."),
    (re.compile(r"(?:OkHttpClientProvider\.setOkHttpClientFactory|\.cache\s*\(\s*new\s+Cache|CacheControl\.FORCE_CACHE)"),
     "HTTP response caching configured", "LOW", "QUILL-APK-147",
     "The application configures HTTP response caching (OkHttp Cache or "
     "CacheControl). Cached responses may contain sensitive data (PII, ePHI, "
     "tokens) that persists on the device filesystem.",
     "Disable caching for responses containing sensitive data via Cache-Control: "
     "no-store, or encrypt the cache directory."),
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
            m = pat.search(text)
            if m:
                if len(pattern_hits[cat_id]["files"]) < 5:
                    pattern_hits[cat_id]["files"].append(str(cf))
                    ctx_start = max(0, m.start() - 40)
                    ctx_end = min(len(text), m.end() + 40)
                    snippet = text[ctx_start:ctx_end].replace("\n", " ").strip()
                    pattern_hits[cat_id].setdefault("evidence_lines", []).append(
                        f"{cf.name}: ...{snippet}...")
        lc = len(_LOG_CALL_RX.findall(text))
        if lc > 0:
            log_call_count += lc
            if len(log_files) < 5:
                log_files.append(str(cf))

    dex_lines = dex_text.splitlines() if dex_text else []
    if dex_text:
        for pat, title, sev, cat_id, desc, remed in _SAST_PATTERNS:
            if pat.search(dex_text) and not pattern_hits[cat_id]["files"]:
                pattern_hits[cat_id]["files"].append("(DEX strings)")
        lc = len(_LOG_CALL_RX.findall(dex_text))
        log_call_count += lc
        for pat, title, sev, cat_id, desc, remed in _DEX_SAST_PATTERNS:
            if cat_id not in pattern_hits:
                pattern_hits[cat_id] = {"title": title, "severity": sev, "cat_id": cat_id,
                                        "desc": desc, "remed": remed, "files": [],
                                        "evidence_lines": []}
            if pat.search(dex_text) and not pattern_hits[cat_id]["files"]:
                pattern_hits[cat_id]["files"].append("(DEX strings)")
                ev = []
                for ln in dex_lines:
                    if pat.search(ln) and len(ev) < 5:
                        ev.append(ln.strip()[:200])
                pattern_hits[cat_id].setdefault("evidence_lines", []).extend(ev)
                log(f"[sast] DEX-level match: {title} ({cat_id})")

    result = {"patterns": {}, "log_call_count": log_call_count}
    finding_count = 0
    for cat_id, info in pattern_hits.items():
        if info["files"]:
            result["patterns"][cat_id] = {"title": info["title"], "files": info["files"]}
            file_list = ", ".join(Path(f).name for f in info["files"][:5])
            ev = info.get("evidence_lines", [])
            src_output = ""
            if ev:
                src_output = "Source excerpts from app:\n" + "\n".join(f"  {l}" for l in ev)
            finding(title=f"Android SAST: {info['title']}",
                    severity=info["severity"],
                    description=f"{info['desc']} Found in: {file_list}.",
                    data={"catalogue_id": cat_id,
                          "affected": file_list,
                          "remediation": info["remed"]},
                    output=src_output,
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
                output=f"{log_call_count} Log.x() calls across: {file_list}",
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


# ── Runtime protection detection (root/jailbreak, tamper, debugger) ──────────

_ROOT_DETECT_INDICATORS = [
    ("com/scottyab/rootbeer", "RootBeer"),
    ("com/google/android/gms/safetynet", "SafetyNet Attestation"),
    ("com/google/android/play/core/integrity", "Play Integrity API"),
    ("com/scottyab/safetynet", "SafetyNet Helper"),
    ("org/lsposed/lsposed", "LSPosed detection"),
    ("com/noshufou/android/su", "SuperUser detection"),
    ("eu/chainfire/libsuperuser", "libSuperUser"),
    ("com/topjohnwu/superuser", "Magisk/libsu"),
]

_ROOT_DETECT_CODE_PATTERNS = [
    re.compile(r"RootBeer|isRooted|isRootedWithBusyBox"),
    re.compile(r"SafetyNetClient|SafetyNetApi|safetynet\.SafeBrowsing"),
    re.compile(r"IntegrityManager|requestIntegrityToken"),
    re.compile(r"/system/app/Superuser\.apk|/system/xbin/su\b|/sbin/su\b"),
    re.compile(r"com\.noshufou\.android\.su|eu\.chainfire\.\w*su|com\.topjohnwu"),
    re.compile(r"test-keys|ro\.debuggable"),
]


def analyse_runtime_protections(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log("[rprot] Checking for runtime protection mechanisms (root detection, tamper, debug)...")
    status("rprot", "Runtime protection analysis", "running")

    found_indicators: list = []

    smali_root = app_dir / "smali"
    smali_dirs = list(app_dir.glob("smali*")) if smali_root.exists() else []

    for pkg_path, lib_name in _ROOT_DETECT_INDICATORS:
        for sd in smali_dirs:
            if (sd / pkg_path).exists():
                found_indicators.append(lib_name)
                break

    all_text = ""
    for ext in ("smali", "java", "kt"):
        for f in app_dir.rglob(f"*.{ext}"):
            try:
                all_text += f.read_text(encoding="utf-8", errors="ignore")[:200000]
            except Exception:
                continue
            if len(all_text) > 5_000_000:
                break

    if not all_text:
        strings_bin = shutil.which("strings")
        if strings_bin:
            for dex in app_dir.rglob("*.dex"):
                cp = _run_tool_cmd([strings_bin, str(dex)],
                                   output_file=str(output_dir / f"rprot_strings_{dex.name}.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    all_text += (cp.stdout or "")

    for pat in _ROOT_DETECT_CODE_PATTERNS:
        m = pat.search(all_text)
        if m:
            match_text = m.group()[:80]
            if match_text not in [i for i in found_indicators]:
                found_indicators.append(f"code pattern: {match_text}")

    if not found_indicators:
        log("[rprot] No root/jailbreak detection mechanisms found — finding emitted")
        finding(title="No root/jailbreak detection implemented",
                severity="MEDIUM",
                description=("The application does not implement root or jailbreak detection. "
                             "No evidence of RootBeer, SafetyNet Attestation, Play Integrity API, "
                             "su-binary checks, or other root detection libraries was found in "
                             "the application code. Applications without root detection can be "
                             "more easily analysed and attacked on rooted/jailbroken devices."),
                data={"catalogue_id": "QUILL-APK-148",
                      "affected": "Application binary",
                      "remediation": "Implement root/jailbreak detection using a library such as "
                                     "RootBeer or Google Play Integrity API. The application can "
                                     "warn users, restrict functionality, or refuse to run on "
                                     "compromised devices depending on risk tolerance."},
                output="Root detection indicators searched:\n"
                       "  Smali packages: " + ", ".join(p for p, _ in _ROOT_DETECT_INDICATORS) + "\n"
                       "  Code patterns: RootBeer, SafetyNet, Play Integrity, su binary paths, "
                       "test-keys, ro.debuggable\n"
                       "Result: NONE FOUND")
    else:
        indicators_str = ", ".join(found_indicators)
        log(f"[rprot] Root detection mechanisms found: {indicators_str}")

    log("[rprot] Runtime protection analysis complete")
    status("rprot", "Runtime protection analysis", "complete")


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
                output=f"Detection: smali package '{t['package']}' found in APK ({t.get('method', 'smali_dir')})",
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


# ── iOS tracker SDK detection ────────────────────────────────────────────────

_KNOWN_IOS_TRACKERS = {
    "GoogleAnalytics": "Google Analytics",
    "FirebaseAnalytics": "Firebase Analytics",
    "FBSDKCoreKit": "Facebook SDK",
    "FBSDKLoginKit": "Facebook Login",
    "GoogleMobileAds": "Google AdMob",
    "GADMobileAds": "Google AdMob",
    "Adjust": "Adjust",
    "Mixpanel": "Mixpanel",
    "MixpanelAPI": "Mixpanel",
    "Amplitude": "Amplitude",
    "Branch": "Branch.io",
    "Segment": "Segment",
    "Braze": "Braze",
    "Crashlytics": "Crashlytics",
    "NewRelicAgent": "New Relic",
    "Bugsnag": "Bugsnag",
    "Instabug": "Instabug",
    "Countly": "Countly",
    "CleverTap": "CleverTap",
    "OneSignal": "OneSignal",
    "AppsFlyerLib": "AppsFlyer",
    "Flurry": "Flurry",
    "Sentry": "Sentry",
    "ComScore": "comScore",
    "MoEngage": "MoEngage",
    "Airship": "Urban Airship",
    "Leanplum": "Leanplum",
    "AppDynamics": "AppDynamics",
    "Batch": "Batch",
}


def detect_trackers_ios(app_dir: Path, output_dir: Path) -> None:
    _check_pause()
    _save_checkpoint()
    log(f"[trackers_ios] Starting iOS tracker SDK detection for {app_dir.name}...")
    status("trackers_ios", "iOS tracker SDK detection", "running")

    out_file = output_dir / "tracker_analysis.json"
    found: list = []
    seen_names: set = set()

    frameworks_dir = app_dir / "Frameworks"
    if frameworks_dir.exists():
        for fw in frameworks_dir.iterdir():
            if fw.is_dir() or fw.suffix == ".framework":
                fw_stem = fw.stem
                for key, name in _KNOWN_IOS_TRACKERS.items():
                    if key.lower() in fw_stem.lower() and name not in seen_names:
                        seen_names.add(name)
                        found.append({"package": fw_stem, "name": name,
                                      "method": "framework_dir", "evidence": fw.name})
                        break
            if fw.suffix == ".dylib":
                for key, name in _KNOWN_IOS_TRACKERS.items():
                    if key.lower() in fw.stem.lower() and name not in seen_names:
                        seen_names.add(name)
                        found.append({"package": fw.stem, "name": name,
                                      "method": "dylib", "evidence": fw.name})
                        break

    strings_bin = shutil.which("strings")
    if strings_bin:
        main_bin = _find_ios_main_binary(app_dir)
        if main_bin:
            cp = _run_tool_cmd([strings_bin, str(main_bin)],
                               output_file=str(output_dir / "tracker_ios_strings.txt"),
                               timeout=120, tool_name="strings")
            if cp is not None:
                bin_text = cp.stdout or ""
                for key, name in _KNOWN_IOS_TRACKERS.items():
                    if name not in seen_names and key in bin_text:
                        seen_names.add(name)
                        found.append({"package": key, "name": name,
                                      "method": "binary_strings"})

    result = {"trackers_found": len(found), "trackers": found}
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "iOS tracker SDK detection",
                  [f"app_dir: {app_dir}",
                   f"trackers_found: {len(found)}"])

    for t in found:
        log(f"[trackers_ios] Tracker detected: {t['name']} ({t.get('package', '')})")
        det_method = t.get("method", "unknown")
        finding(title=f"Tracker SDK detected: {t['name']}",
                severity="INFO",
                description=(f"The iOS application embeds the {t['name']} tracking SDK "
                             f"({t.get('package', '')}). Tracking SDKs collect user "
                             f"behaviour data and may transmit it to third-party servers."),
                data={"catalogue_id": "QUILL-IOS-060",
                      "affected": t.get("package", t["name"])},
                output=f"Detection: '{t.get('package', t['name'])}' found via {det_method}",
                output_file=str(out_file))

    if len(found) > 5:
        names = ", ".join(t["name"] for t in found)
        finding(title=f"Excessive tracking SDKs ({len(found)} detected)",
                severity="LOW",
                description=(f"The iOS application embeds {len(found)} tracking SDKs: {names}. "
                             f"Each SDK increases attack surface and privacy impact."),
                data={"catalogue_id": "QUILL-IOS-061", "affected": names,
                      "remediation": "Review tracker necessity. Remove unused SDKs."},
                output_file=str(out_file))

    log(f"[trackers_ios] iOS tracker detection complete — {len(found)} tracker(s)")
    status("trackers_ios", "iOS tracker SDK detection", "complete")


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
                output=f"Detected indicators: {sigs}",
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
                output=f"Detected indicators: {sigs}",
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
                output=f"Detected packers/obfuscators: {names}",
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
                output=f"Analysis method: {result['method']}\nNo anti-debug, anti-VM, or packer indicators found",
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
        for arsc in app_dir.rglob("resources.arsc"):
            cp = _run_tool_cmd([strings_bin, str(arsc)],
                               output_file=str(output_dir / "firebase_strings_resources_arsc.txt"),
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
        ctx_lines = [ln.strip() for ln in all_text.splitlines()
                     if url in ln][:3]
        ctx = "\n".join(ctx_lines) if ctx_lines else url
        finding(title=f"Firebase Realtime Database URL detected",
                severity="MEDIUM",
                description=(f"The application references a Firebase Realtime Database: {url}. "
                             f"If database rules allow unauthenticated reads, anyone can "
                             f"access the data by appending .json to the URL."),
                data={"catalogue_id": "QUILL-APK-130", "affected": url,
                      "remediation": "Review Firebase Realtime Database security rules. "
                                     "Ensure authentication is required for all read/write operations."},
                output=f"Source reference:\n{ctx}",
                output_file=str(out_file))

    for url in storage_urls[:10]:
        log(f"[firebase] Firebase Storage URL: {url}")
        ctx_lines = [ln.strip() for ln in all_text.splitlines()
                     if url in ln][:3]
        ctx = "\n".join(ctx_lines) if ctx_lines else url
        finding(title=f"Firebase Storage URL detected",
                severity="MEDIUM",
                description=(f"The application references Firebase Storage: {url}. "
                             f"If storage rules are misconfigured, files may be publicly "
                             f"downloadable or uploadable."),
                data={"catalogue_id": "QUILL-APK-131", "affected": url,
                      "remediation": "Review Firebase Storage security rules. "
                                     "Require authentication for all read/write operations."},
                output=f"Source reference:\n{ctx}",
                output_file=str(out_file))

    if result["google_services"]:
        pid = result["google_services"].get("project_id", "(unknown)")
        gs_excerpt = json.dumps(result["google_services"], indent=2)[:1024]
        finding(title=f"Google Services configuration file present (project: {pid})",
                severity="INFO",
                description=(f"google-services.json found with project ID: {pid}. "
                             f"This file contains Firebase project configuration including "
                             f"API keys and project identifiers. While not secret per se, "
                             f"it identifies the backend infrastructure."),
                data={"catalogue_id": "QUILL-APK-132",
                      "affected": pid},
                output=f"google-services.json excerpt:\n{gs_excerpt}",
                output_file=str(out_file))

    if has_remote_config:
        log("[firebase] Firebase Remote Config usage detected")
        rc_lines = [ln.strip() for ln in all_text.splitlines()
                    if "remoteconfig" in ln.lower() or "remote_config" in ln.lower()][:5]
        rc_ctx = "\n".join(rc_lines) if rc_lines else "Firebase Remote Config references detected in application"
        finding(title="Firebase Remote Config in use",
                severity="INFO",
                description=("The application uses Firebase Remote Config, which fetches "
                             "configuration values from Google's servers at runtime. "
                             "Ensure the config does not control security-sensitive "
                             "parameters (feature flags for auth, URLs, keys)."),
                data={"catalogue_id": "QUILL-APK-133"},
                output=f"Source references:\n{rc_ctx}",
                output_file=str(out_file))

    log(f"[firebase] Firebase detection complete — {len(db_urls)} DB URL(s), "
        f"{len(storage_urls)} storage URL(s)")
    status("firebase", "Firebase detection", "complete")


# ── Certificate / signing analysis ───────────────────────────────────────────


def _detect_apk_signing_python(apk_path: Path) -> dict:
    """Detect APK signing schemes via pure Python (no Java required)."""
    result = {"v1": False, "v2": False, "v3": False, "certs": [],
              "evidence": []}
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            sf_files = [n for n in names if n.startswith("META-INF/") and n.endswith(".SF")]
            sig_files = [n for n in names if n.startswith("META-INF/") and
                         any(n.endswith(e) for e in (".RSA", ".DSA", ".EC"))]
            result["v1"] = bool(sf_files and sig_files)
            if sf_files or sig_files:
                result["evidence"].append(
                    f"v1 JAR signing: SF={sf_files}, SIG={sig_files}")
    except Exception:
        pass
    try:
        with open(apk_path, "rb") as f:
            f.seek(0, 2)
            sz = f.tell()
            chunk = min(sz, 2 * 1024 * 1024)
            f.seek(sz - chunk)
            data = f.read(chunk)
        magic = b"APK Sig Block 42"
        mi = data.rfind(magic)
        if mi > 8:
            block_sz = int.from_bytes(data[mi - 8:mi], "little")
            content_sz = block_sz - 24
            start = mi - 8 - content_sz
            if 0 <= start < mi - 8 and content_sz > 0 and content_sz < 10_000_000:
                block = data[start:mi - 8]
                result["evidence"].append(
                    f"APK Signing Block found: magic at offset {mi}, "
                    f"block_size={block_sz}, content_size={content_sz}")
                p = 0
                while p + 12 <= len(block):
                    ps = int.from_bytes(block[p:p + 8], "little")
                    if ps < 4 or p + 8 + ps > len(block):
                        break
                    pid = int.from_bytes(block[p + 8:p + 12], "little")
                    result["evidence"].append(
                        f"  Pair: id=0x{pid:08x}, size={ps}")
                    if pid == 0x7109871a:
                        result["v2"] = True
                        result["evidence"].append(
                            "    → APK Signature Scheme v2 detected")
                    elif pid == 0xf05368c0:
                        result["v3"] = True
                        result["evidence"].append(
                            "    → APK Signature Scheme v3 detected")
                    elif pid == 0x1b93ad61:
                        result["v3"] = True
                        result["evidence"].append(
                            "    → APK Signature Scheme v3.1 detected")
                    p += 8 + ps
    except Exception:
        pass
    return result


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
                if "unable to locate" in raw.lower() or "error:" in raw.lower():
                    log("[signing] jarsigner failed (Java not available) — using Python fallback")
                    py_result = _detect_apk_signing_python(apk_path)
                    result["tool_used"] = "python-zip"
                    result["v1"] = py_result["v1"]
                    result["v2"] = py_result["v2"]
                    result["v3"] = py_result["v3"]
                    result["certs"] = py_result["certs"]
                    result["evidence"] = py_result.get("evidence", [])
                else:
                    result["v1"] = "jar verified" in raw.lower()
                    for line in raw.splitlines():
                        if "CN=" in line or "Owner:" in line or "Issuer:" in line:
                            result["certs"].append(line.strip())
        else:
            log("[signing] Neither apksigner nor jarsigner available — using Python fallback")
            py_result = _detect_apk_signing_python(apk_path)
            result["tool_used"] = "python-zip"
            result["v1"] = py_result["v1"]
            result["v2"] = py_result["v2"]
            result["v3"] = py_result["v3"]
            result["certs"] = py_result["certs"]
            result["evidence"] = py_result.get("evidence", [])

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
    elif result["v1"] and (result["v2"] or result["v3"]):
        schemes = "v1"
        if result["v2"]: schemes += "+v2"
        if result["v3"]: schemes += "+v3"
        log(f"[signing] {schemes} signing — v1 still present, Janus risk on Android 5.0-7.0")
        finding(title=f"APK includes v1 (JAR) signature scheme ({schemes})",
                severity="MEDIUM",
                description=(f"The APK is signed with {schemes}. While v2/v3 signatures "
                             "protect against modification on modern devices, the presence "
                             "of v1 (JAR) signing makes the APK vulnerable to the Janus "
                             "attack (CVE-2017-13156) on devices running Android 5.0-7.0 "
                             "that only verify v1 signatures."),
                data={"catalogue_id": "QUILL-APK-145",
                      "affected": str(apk_path),
                      "cves": "CVE-2017-13156",
                      "remediation": "Remove v1 signing and use v2/v3 only, or raise minSdkVersion "
                                     "to API 24+ where v2 verification is enforced."},
                output=f"Signing schemes detected: {schemes}\nv1 (JAR): {result['v1']}\n"
                       f"v2 (APK Signature Scheme): {result['v2']}\nv3 (rotation): {result['v3']}",
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
    ev_lines = result.get("evidence", [])
    if result.get("raw_output"):
        ev_lines = [f"Tool: {result['tool_used']}",
                    "--- raw output (first 2000 chars) ---",
                    result["raw_output"][:2000]]
    evidence_str = "\n".join(str(l) for l in ev_lines) if ev_lines else ""
    finding(title=f"APK signing details: {scheme_str}",
            severity="INFO",
            description=(f"APK signing scheme(s): {scheme_str}. "
                         f"Certificate details: {cert_summary}"),
            data={"catalogue_id": "QUILL-APK-140",
                  "affected": str(apk_path)},
            output=evidence_str,
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
            dl_schemes = ", ".join(f"{sh.get('scheme','')}://{sh.get('host','')}" for sh in schemes_hosts if sh.get('scheme'))
            finding(title=f"Browsable activity: {act_name}",
                    severity="INFO",
                    description=(f"Activity {act_name} is registered with BROWSABLE category "
                                 f"and handles deep links: {uri_str}. Any app or web page can "
                                 f"invoke this activity via an intent URL."),
                    data={"catalogue_id": "QUILL-APK-150",
                          "affected": f"{package}/{act_name}"},
                    output=f"AndroidManifest.xml intent-filter:\n  Activity: {act_name}\n  URIs: {dl_schemes or uri_str}",
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
                        output=f"AndroidManifest.xml:\n  <activity android:name=\"{act_name}\" android:exported=\"true\">\n  No android:permission attribute\n  URIs: {uri_str}",
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
            perm_list = ", ".join(sorted(check["permissions"] & declared_perms))
            log(f"[behaviour] {check['label']}: API present + permission declared")
            finding(title=f"Behaviour: {check['label']} capability detected",
                    severity="INFO",
                    description=check["desc_with"],
                    data={"catalogue_id": check["id"], "affected": package},
                    output=f"API class/method references found in DEX\nDeclared permissions: {perm_list}",
                    output_file=str(out_file))
        else:
            expected_perms = ", ".join(sorted(check["permissions"]))
            log(f"[behaviour] {check['label']}: API present WITHOUT permission — suspicious")
            finding(title=f"Behaviour: {check['label']} API without permission",
                    severity="MEDIUM",
                    description=check["desc_without"],
                    data={"catalogue_id": check["id"], "affected": package,
                          "remediation": "Investigate how the API is used. The app may "
                                         "use reflection, invoke via implicit intent, or "
                                         "target an older SDK that grants the permission "
                                         "implicitly."},
                    output=f"API class/method references found in DEX\nExpected permissions NOT declared: {expected_perms}",
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


_MITM_AUTH_CAPTURE_ADDON = r'''
"""mitmdump addon — real-time auth/API/web target capture + TLS auto-passthrough.

Prints structured tokens to stdout that _drain_mitm() picks up:
  __QUILL_AUTH__:<json>         — captured auth token / session cookie
  __QUILL_API__:<json>          — API endpoint detected
  __QUILL_WEB__:<json>          — web app target detected
  __QUILL_PASSTHROUGH__:<json>  — host added to TLS passthrough (cert pinning)
"""
import json, os, re, sys
from mitmproxy import http

# ── TLS auto-passthrough for cert-pinned hosts ──
_tls_fail_counts = {}
_passthrough_hosts = set()
_PASSTHROUGH_THRESHOLD = 2

_preseed = os.environ.get("QUILL_MITM_PASSTHROUGH_HOSTS", "")
if _preseed:
    for _h in _preseed.split(","):
        _h = _h.strip()
        if _h:
            _passthrough_hosts.add(_h)

_seen_hosts = set()
_seen_auth = set()
_seen_api = set()
_seen_web = set()

_API_CT = ("application/json", "application/graphql", "application/xml",
           "text/xml", "application/grpc", "application/protobuf")
_API_PATHS = ("/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/graphql",
              "/rest/", "/query", "/mutation", "/.well-known/openid",
              "/oauth", "/token", "/swagger", "/openapi")
_AUTH_HEADERS = ("authorization", "x-auth-token", "x-api-key",
                 "x-access-token", "x-csrf-token", "x-session-id")
_AUTH_COOKIES = ("session", "sid", "token", "jwt", "auth", "access_token",
                 "refresh_token", "sessionid", "connect.sid", "csrf",
                 "__session", "ssid")

def _emit(tag, payload):
    print(f"{tag}:{json.dumps(payload)}", flush=True)

def tls_clienthello(data):
    sni = data.client_hello.sni or ""
    if not sni:
        return
    if sni in _passthrough_hosts:
        data.ignore_connection = True
        return
    for pat in list(_passthrough_hosts):
        if pat != sni:
            try:
                if re.fullmatch(pat, sni):
                    data.ignore_connection = True
                    return
            except re.error:
                pass

def tls_failed_client(data):
    sni = getattr(data.conn, "sni", "") or ""
    if not sni or sni in _passthrough_hosts:
        return
    _tls_fail_counts[sni] = _tls_fail_counts.get(sni, 0) + 1
    if _tls_fail_counts[sni] >= _PASSTHROUGH_THRESHOLD:
        _passthrough_hosts.add(sni)
        _emit("__QUILL_PASSTHROUGH__", {
            "host": sni, "reason": "cert_pinning",
            "failures": _tls_fail_counts[sni]})

def tls_established_client(data):
    sni = getattr(data.conn, "sni", "") or ""
    if sni in _tls_fail_counts:
        del _tls_fail_counts[sni]

def _is_api(flow):
    ct = (flow.response.headers.get("content-type", "") or "").lower()
    path = flow.request.path.lower()
    if any(api_ct in ct for api_ct in _API_CT):
        return True
    if any(p in path for p in _API_PATHS):
        return True
    return False

def response(flow: http.HTTPFlow):
    if not flow.response:
        return
    host = flow.request.pretty_host
    scheme = flow.request.scheme
    port = flow.request.port
    base = f"{scheme}://{host}" + (f":{port}" if port not in (80, 443) else "")
    url = flow.request.url

    # Auth capture — headers
    for hdr in _AUTH_HEADERS:
        val = flow.request.headers.get(hdr, "")
        if val:
            key = (host, hdr, val[:32])
            if key not in _seen_auth:
                _seen_auth.add(key)
                _emit("__QUILL_AUTH__", {
                    "host": host, "header": hdr, "value": val[:2048],
                    "url": url[:512], "method": flow.request.method})

    # Auth capture — cookies
    cookie_hdr = flow.request.headers.get("cookie", "")
    if cookie_hdr:
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            cname, _, cval = part.partition("=")
            cname = cname.strip().lower()
            if any(ac in cname for ac in _AUTH_COOKIES):
                key = (host, cname, cval[:32])
                if key not in _seen_auth:
                    _seen_auth.add(key)
                    _emit("__QUILL_AUTH__", {
                        "host": host, "cookie": cname,
                        "value": cval[:2048], "url": url[:512],
                        "method": flow.request.method})

    # Auth capture — response Set-Cookie
    for sc in flow.response.headers.get_all("set-cookie"):
        if "=" not in sc:
            continue
        cname, _, cval = sc.partition("=")
        cname = cname.strip().lower()
        cval = cval.split(";")[0].strip()
        if any(ac in cname for ac in _AUTH_COOKIES):
            key = (host, "set-" + cname, cval[:32])
            if key not in _seen_auth:
                _seen_auth.add(key)
                _emit("__QUILL_AUTH__", {
                    "host": host, "set_cookie": cname,
                    "value": cval[:2048], "url": url[:512]})

    # Auth capture — JSON body tokens
    ct = (flow.response.headers.get("content-type", "") or "").lower()
    _resp_bytes = _safe_flow_content(flow.response)
    if "json" in ct and _resp_bytes:
        try:
            body = json.loads(_resp_bytes[:65536])
            if isinstance(body, dict):
                for tk in ("access_token", "token", "id_token",
                           "refresh_token", "jwt", "session_token",
                           "auth_token", "accessToken", "idToken"):
                    if tk in body and isinstance(body[tk], str) and len(body[tk]) > 8:
                        key = (host, tk, body[tk][:32])
                        if key not in _seen_auth:
                            _seen_auth.add(key)
                            _emit("__QUILL_AUTH__", {
                                "host": host, "json_field": tk,
                                "value": body[tk][:2048],
                                "url": url[:512]})
        except Exception:
            pass

    # API vs Web classification
    if _is_api(flow):
        if host not in _seen_api:
            _seen_api.add(host)
            path = flow.request.path
            api_base = base
            for prefix in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/"):
                idx = path.lower().find(prefix)
                if idx >= 0:
                    api_base = base + path[:idx + len(prefix)]
                    break
            _emit("__QUILL_API__", {
                "host": host, "base_url": api_base,
                "sample_url": url[:512],
                "method": flow.request.method,
                "content_type": ct[:128]})
    else:
        if host not in _seen_web and flow.response.status_code and flow.response.status_code < 400:
            html_ct = "text/html" in ct
            if html_ct:
                _seen_web.add(host)
                _emit("__QUILL_WEB__", {
                    "host": host, "base_url": base,
                    "sample_url": url[:512],
                    "status": flow.response.status_code})
'''


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
                         output=f"Frida output:\n{output[:1024]}",
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


# ── MITM traffic analysis ────────────────────────────────────────────────────

_SENSITIVE_URL_PATTERNS = {
    "password": re.compile(r'(?:password|passwd|pwd|pass)=[^&]+', re.IGNORECASE),
    "token": re.compile(r'(?:token|access_token|auth_token|session_id|sessionid|sid)=[^&]+', re.IGNORECASE),
    "api_key": re.compile(r'(?:api_?key|apikey|app_?key|secret)=[^&]+', re.IGNORECASE),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "email_param": re.compile(r'(?:email|user|username)=[^&]*@[^&]+', re.IGNORECASE),
    "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
}

_API_KEY_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "firebase_key": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    "github_token": re.compile(r'gh[ps]_[A-Za-z0-9_]{36,255}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    "stripe_key": re.compile(r'[sr]k_(live|test)_[0-9a-zA-Z]{24,}'),
    "twilio_key": re.compile(r'SK[0-9a-fA-F]{32}'),
    "generic_bearer": re.compile(r'Bearer\s+[A-Za-z0-9\-_.~+/]+=*', re.IGNORECASE),
}

_TRACKER_DOMAINS = {
    "google-analytics.com": "Google Analytics",
    "analytics.google.com": "Google Analytics",
    "firebaselogging.googleapis.com": "Firebase Analytics",
    "firebaseinstallations.googleapis.com": "Firebase",
    "app-measurement.com": "Google App Measurement",
    "graph.facebook.com": "Facebook SDK",
    "www.facebook.com": "Facebook SDK",
    "app.adjust.com": "Adjust",
    "app.appsflyer.com": "AppsFlyer",
    "api2.branch.io": "Branch.io",
    "api.crashlytics.com": "Crashlytics",
    "settings.crashlytics.com": "Crashlytics",
    "api.amplitude.com": "Amplitude",
    "api.mixpanel.com": "Mixpanel",
    "api.segment.io": "Segment",
    "dc.services.visualstudio.com": "App Center",
    "mobile.launchdarkly.com": "LaunchDarkly",
    "sentry.io": "Sentry",
}

_SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS Header",
    "content-security-policy": "Missing Content-Security-Policy",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "x-frame-options": "Missing X-Frame-Options",
}

_AUTH_URL_PATTERNS = re.compile(
    r'(?:login|signin|sign-in|authenticate|auth|oauth|token|session)', re.IGNORECASE)

_PII_BODY_PATTERNS = {
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}\b'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "phone": re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "password_field": re.compile(r'"(?:password|passwd|pwd|pass|secret)"\s*:\s*"[^"]*"', re.IGNORECASE),
}


def _safe_flow_content(msg) -> bytes:
    try:
        return msg.content or b""
    except (ValueError, LookupError):
        return msg.raw_content or b""


def _safe_evidence_path(method: str, url_path: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._/-]', '_', url_path)[:80]
    safe = safe.strip("/").replace("/", "__")
    return f"{method}__{safe}" if safe else method


def _write_mitm_evidence(flow, evidence_dir: Path, seq: int):
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        from urllib.parse import urlparse
        path_part = urlparse(flow.request.url).path or "/"
    except Exception:
        path_part = "/"
    safe_dir = evidence_dir / _safe_evidence_path(flow.request.method, path_part)
    safe_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"req_{seq:04d}_{ts_str}"
    req_lines = [f"{flow.request.method} {flow.request.url} {flow.request.http_version}"]
    for k, v in flow.request.headers.items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    req_bytes = _safe_flow_content(flow.request)
    body = req_bytes.decode("utf-8", errors="replace")[:50000]
    if body:
        req_lines.append(body)
    req_file = safe_dir / f"{prefix}_request.txt"
    req_file.write_text("\n".join(req_lines), encoding="utf-8")
    resp_lines = [f"{flow.response.http_version} {flow.response.status_code} "
                  f"{flow.response.reason}"]
    for k, v in flow.response.headers.items():
        resp_lines.append(f"{k}: {v}")
    resp_lines.append("")
    resp_bytes = _safe_flow_content(flow.response)
    rbody = resp_bytes.decode("utf-8", errors="replace")[:50000]
    if rbody:
        resp_lines.append(rbody)
    resp_file = safe_dir / f"{prefix}_response.txt"
    resp_file.write_text("\n".join(resp_lines), encoding="utf-8")
    dur = 0
    if hasattr(flow, 'timestamp_end') and hasattr(flow, 'timestamp_start'):
        dur = (flow.timestamp_end or 0) - (flow.timestamp_start or 0)
    log_file = safe_dir / f"{prefix}.log"
    log_file.write_text("\n".join([
        f"# Tool: mitmdump (MITM proxy)",
        f"# Request: {flow.request.method} {flow.request.url}",
        f"# Status: {flow.response.status_code}",
        f"# Duration: {dur:.3f}s",
        f"# Request size: {len(req_bytes)} bytes",
        f"# Response size: {len(resp_bytes)} bytes",
    ]), encoding="utf-8")
    return _rel(str(req_file)), _rel(str(resp_file)), _rel(str(log_file))


_MITM_MEM_THRESHOLD_MB = 512

def _get_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except FileNotFoundError:
        pass
    try:
        import resource
        r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return int(r.stdout.strip()) / 1024.0
    except Exception:
        pass
    return 0.0

_PERSISTENT_CA_DIR = Path("/opt/pr0t31n/Quill/.mitmproxy")


def _ensure_mitmproxy_ca(mitmdump_bin: str) -> Path:
    """Ensure persistent mitmproxy CA exists; auto-generate on first run.

    Stores the CA under /opt/pr0t31n/Quill/.mitmproxy/ so it survives across
    runs and the device only needs to install it once.
    """
    ca_dir = _PERSISTENT_CA_DIR
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_pem = ca_dir / "mitmproxy-ca.pem"
    ca_cert = ca_dir / "mitmproxy-ca-cert.pem"
    if ca_pem.exists() and ca_cert.exists():
        log(f"[mitm] Using persistent CA from {ca_dir}")
        return ca_cert
    log("[mitm] Persistent mitmproxy CA not found — generating...")
    try:
        proc = subprocess.Popen(
            [mitmdump_bin, "-p", "0", "--set", "flow_detail=0",
             "--set", f"confdir={ca_dir}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time as _t
        _t.sleep(3)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as exc:
        log(f"[mitm] CA generation failed: {exc}")
        return None
    if ca_pem.exists() and ca_cert.exists():
        log(f"[mitm] Persistent CA generated: {ca_dir}")
        return ca_cert
    log("[mitm] CA generation did not produce expected files")
    return None


def _setup_burp_ca_confdir(burp_ca_path: str, mitm_dir: Path) -> Optional[Path]:
    """Create a mitmproxy confdir that uses an upstream proxy's CA for signing.

    The proxy's exported CA (cert+key PEM) is copied as mitmproxy-ca.pem so
    mitmdump presents certs the device already trusts (via the proxy CA).
    Returns the confdir path, or None if the CA file is invalid.
    """
    src = Path(burp_ca_path)
    if not src.exists():
        err(f"[mitm] Proxy CA file not found: {burp_ca_path}")
        return None
    pem = src.read_text(encoding="utf-8", errors="replace")
    if "PRIVATE KEY" not in pem or "CERTIFICATE" not in pem:
        err("[mitm] Proxy CA file must contain both certificate and private key in PEM format")
        return None
    confdir = mitm_dir / ".mitmproxy_burp"
    confdir.mkdir(parents=True, exist_ok=True)
    (confdir / "mitmproxy-ca.pem").write_text(pem, encoding="utf-8")
    log(f"[mitm] Using upstream proxy CA for signing — device only needs one CA trusted")
    return confdir


def mitm_capture(target_process: str, platform: str, device: str,
                 output_dir: Path, *, port: int = 8080,
                 transparent: bool = False,
                 upstream_proxy: str = "",
                 burp_ca: str = "",
                 ignore_hosts: str = "", **_kw) -> Optional[Path]:
    _check_pause()
    _save_checkpoint()
    log(f"[mitm] Starting MITM traffic capture — port={port}, "
        f"transparent={transparent}")
    status("mitm_capture", "MITM traffic capture", "running")
    mitmdump_bin = shutil.which("mitmdump")
    if not mitmdump_bin:
        err("mitmdump not available — install mitmproxy for MITM analysis")
        status("mitm_capture", "MITM traffic capture", "skipped")
        return None
    frida_bin = shutil.which("frida")
    if not frida_bin:
        log("[mitm] Frida not available — MITM capture will run without SSL bypass "
            "(use Burp or manual bypass upstream)")

    mitm_dir = output_dir / "mitm"
    mitm_dir.mkdir(parents=True, exist_ok=True)
    (mitm_dir / "evidence").mkdir(parents=True, exist_ok=True)
    flows_file = mitm_dir / "traffic_capture.mitm"

    # Set up signing CA — use upstream proxy's CA if provided, otherwise mitmproxy's own
    _custom_confdir = None
    if burp_ca:
        _custom_confdir = _setup_burp_ca_confdir(burp_ca, mitm_dir)
    _mitm_ca = _ensure_mitmproxy_ca(mitmdump_bin)
    _ca_dst = mitm_dir / "mitmproxy-ca-cert.pem"
    if _custom_confdir:
        _proxy_cert = Path(burp_ca)
        if _proxy_cert.exists():
            pem = _proxy_cert.read_text(encoding="utf-8", errors="replace")
            import re as _re_mod
            cert_match = _re_mod.search(
                r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
                pem, _re_mod.DOTALL)
            if cert_match:
                _ca_dst.write_text(cert_match.group(1) + "\n", encoding="utf-8")
                log(f"[mitm] Proxy CA cert (public) copied to {_ca_dst}")
    elif _mitm_ca:
        shutil.copy2(str(_mitm_ca), str(_ca_dst))
        log(f"[mitm] mitmproxy CA cert copied to {_ca_dst}")

    ssl_script_file = None
    if frida_bin:
        ssl_script = _FRIDA_SSL_PINNING_SCRIPT if platform == "android" else _FRIDA_IOS_SSL_SCRIPT
        ssl_script_file = mitm_dir / "ssl_bypass.js"
        ssl_script_file.write_text(ssl_script, encoding="utf-8")

    log(f"[mitm] Proxy listening on port {port} — "
        "ensure device proxy points to this host")
    status("mitm_capture", f"Proxy on :{port} — configure device", "running")

    if upstream_proxy:
        mode = f"upstream:{upstream_proxy}"
        log(f"[mitm] Upstream proxy mode — forwarding through {upstream_proxy}")
        log(f"[mitm] Chain: Device → mitmdump (:{port}) → upstream proxy ({upstream_proxy}) → Internet")
    elif transparent:
        mode = "transparent"
    else:
        mode = "regular"
    mitm_cmd = [mitmdump_bin, "-w", f"+{flows_file}", "--mode", mode,
                "-p", str(port), "--ssl-insecure",
                "--set", "flow_detail=1",
                "--set", "stream_large_bodies=5m"]
    _confdir = _custom_confdir or _PERSISTENT_CA_DIR
    mitm_cmd.extend(["--set", f"confdir={_confdir}"])
    if ignore_hosts:
        mitm_cmd.extend(["--ignore-hosts", ignore_hosts])
        log(f"[mitm] Pre-seeded ignore hosts: {ignore_hosts}")
    addon_file = mitm_dir / "_auth_capture.py"
    addon_file.write_text(_MITM_AUTH_CAPTURE_ADDON, encoding="utf-8")
    mitm_cmd.extend(["-s", str(addon_file)])
    log("[mitm] Auth/API/TLS-passthrough addon loaded")
    log(f"[mitm] Launching mitmdump: {' '.join(mitm_cmd)}")
    mitm_started = datetime.now(timezone.utc)
    _mitm_env = dict(os.environ)
    if ignore_hosts:
        _mitm_env["QUILL_MITM_PASSTHROUGH_HOSTS"] = ignore_hosts.replace("|", ",")
    mitm_proc = subprocess.Popen(mitm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=_mitm_env)

    import threading as _thr_mod
    _mitm_lines = []
    _captured_auth: list = []
    _captured_api: list = []
    _captured_web: list = []
    _emitted_actions: set = set()
    _pending_api_targets: list = []
    _pending_web_targets: list = []

    _mitm_scope = os.environ.get("CRUCIBLE_SCOPE", "")

    def _emit_action_item(category: str, tool: str, target: str, title: str,
                          desc: str, priority: str = "HIGH", metadata: dict = None):
        key = (tool.lower(), target.lower())
        if key in _emitted_actions:
            return
        _emitted_actions.add(key)
        item = {
            "category": category,
            "recommended_tool": tool,
            "target": target,
            "title": title,
            "description": desc,
            "priority": priority,
            "approval_tier": "auto",
            "source_tool": "quill",
            "scope": _mitm_scope,
            "metadata": dict(metadata or {}, immediate_queue=(tool.lower() != "siphon")),
        }
        _tok("__CRUCIBLE_ACTION_ITEM__", json.dumps(item))
        log(f"[mitm] Action item emitted: {tool} → {target}")

    def _build_auth_meta(host, prefer_cookie=False):
        meta = {}
        for a in _captured_auth:
            if a.get("host") != host:
                continue
            if prefer_cookie:
                if a.get("cookie"):
                    meta.setdefault("auth_cookies", {})[a["cookie"]] = a.get("value", "")
                elif a.get("header"):
                    meta["auth_header"] = a["header"]
                    meta["auth_value"] = a.get("value", "")
            else:
                if a.get("header"):
                    meta["auth_header"] = a["header"]
                    meta["auth_value"] = a.get("value", "")
                elif a.get("cookie"):
                    meta.setdefault("auth_cookies", {})[a["cookie"]] = a.get("value", "")
                elif a.get("json_field"):
                    meta["auth_token_field"] = a["json_field"]
                    meta["auth_token_value"] = a.get("value", "")
            break
        return meta

    def _has_auth_for(host):
        return any(a.get("host") == host for a in _captured_auth)

    def _flush_pending_for_host(host):
        remaining_api = []
        for p in _pending_api_targets:
            if p["host"] == host:
                auth_meta = _build_auth_meta(host)
                _emit_action_item(
                    "api_discovered", "siphon", p["base"],
                    f"API endpoint from MITM capture: {host}",
                    f"Quill MITM captured live API traffic to {host}. "
                    f"Siphon can test this API for OWASP API Top 10 vulnerabilities.",
                    priority="HIGH", metadata=auth_meta)
            else:
                remaining_api.append(p)
        _pending_api_targets[:] = remaining_api

        remaining_web = []
        for p in _pending_web_targets:
            if p["host"] == host:
                auth_meta = _build_auth_meta(host, prefer_cookie=True)
                _emit_action_item(
                    "webapp_discovered", "fracture", p["base"],
                    f"Web target from MITM capture: {host}",
                    f"Quill MITM captured live web traffic to {host}. "
                    f"Fracture can test this web app for OWASP Top 10 vulnerabilities.",
                    priority="HIGH", metadata=auth_meta)
            else:
                remaining_web.append(p)
        _pending_web_targets[:] = remaining_web

    def _emit_noauth_action_item(category, tool, target, title, desc):
        """Emit an action item that requires manual approval (no auth captured)."""
        key = (tool.lower(), target.lower())
        if key in _emitted_actions:
            return
        _emitted_actions.add(key)
        item = {
            "category": category,
            "recommended_tool": tool,
            "target": target,
            "title": title,
            "description": desc,
            "priority": "MEDIUM",
            "approval_tier": "manual",
            "source_tool": "quill",
            "scope": _mitm_scope,
            "metadata": {"no_auth_captured": True},
        }
        _tok("__CRUCIBLE_ACTION_ITEM__", json.dumps(item))
        log(f"[mitm] Action item emitted (NO AUTH — manual approval): {tool} → {target}")

    def _flush_all_pending():
        authed_api = authed_web = noauth_api = noauth_web = 0
        for p in list(_pending_api_targets):
            if _has_auth_for(p["host"]):
                auth_meta = _build_auth_meta(p["host"])
                _emit_action_item(
                    "api_discovered", "siphon", p["base"],
                    f"API endpoint from MITM capture: {p['host']}",
                    f"Quill MITM captured live API traffic to {p['host']}. "
                    f"Siphon can test this API for OWASP API Top 10 vulnerabilities.",
                    priority="HIGH", metadata=auth_meta)
                authed_api += 1
            else:
                _emit_noauth_action_item(
                    "api_discovered", "siphon", p["base"],
                    f"API endpoint from MITM capture (no auth): {p['host']}",
                    f"Quill MITM captured live API traffic to {p['host']} but no "
                    f"authentication was captured. Manual auth configuration required.")
                noauth_api += 1
        _pending_api_targets.clear()
        for p in list(_pending_web_targets):
            if _has_auth_for(p["host"]):
                auth_meta = _build_auth_meta(p["host"], prefer_cookie=True)
                _emit_action_item(
                    "webapp_discovered", "fracture", p["base"],
                    f"Web target from MITM capture: {p['host']}",
                    f"Quill MITM captured live web traffic to {p['host']}. "
                    f"Fracture can test this web app for OWASP Top 10 vulnerabilities.",
                    priority="HIGH", metadata=auth_meta)
                authed_web += 1
            else:
                _emit_noauth_action_item(
                    "webapp_discovered", "fracture", p["base"],
                    f"Web target from MITM capture (no auth): {p['host']}",
                    f"Quill MITM captured live web traffic to {p['host']} but no "
                    f"authentication was captured. Manual auth configuration required.")
                noauth_web += 1
        _pending_web_targets.clear()
        if noauth_api or noauth_web:
            log(f"[mitm] {noauth_api} API + {noauth_web} web targets emitted "
                f"WITHOUT auth (manual approval required)")

    def _drain_mitm(stream, label):
        try:
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                _mitm_lines.append(line)
                if line.startswith("__QUILL_AUTH__:"):
                    try:
                        payload = json.loads(line[len("__QUILL_AUTH__:"):])
                        _captured_auth.append(payload)
                        host = payload.get("host", "")
                        auth_type = payload.get("header") or payload.get("cookie") or payload.get("json_field") or payload.get("set_cookie") or "unknown"
                        log(f"[mitm] Auth captured: {auth_type} from {host}")
                        _flush_pending_for_host(host)
                    except Exception:
                        pass
                elif line.startswith("__QUILL_API__:"):
                    try:
                        payload = json.loads(line[len("__QUILL_API__:"):])
                        _captured_api.append(payload)
                        host = payload.get("host", "")
                        base = payload.get("base_url", "")
                        log(f"[mitm] API target detected: {host}")
                        if _has_auth_for(host):
                            auth_meta = _build_auth_meta(host)
                            _emit_action_item(
                                "api_discovered", "siphon", base,
                                f"API endpoint from MITM capture: {host}",
                                f"Quill MITM captured live API traffic to {host}. "
                                f"Siphon can test this API for OWASP API Top 10 vulnerabilities.",
                                priority="HIGH", metadata=auth_meta)
                        else:
                            _pending_api_targets.append({"host": host, "base": base})
                            log(f"[mitm] API target {host} buffered — waiting for auth")
                    except Exception:
                        pass
                elif line.startswith("__QUILL_WEB__:"):
                    try:
                        payload = json.loads(line[len("__QUILL_WEB__:"):])
                        _captured_web.append(payload)
                        host = payload.get("host", "")
                        base = payload.get("base_url", "")
                        log(f"[mitm] Web target detected: {host}")
                        if _has_auth_for(host):
                            auth_meta = _build_auth_meta(host, prefer_cookie=True)
                            _emit_action_item(
                                "webapp_discovered", "fracture", base,
                                f"Web target from MITM capture: {host}",
                                f"Quill MITM captured live web traffic to {host}. "
                                f"Fracture can test this web app for OWASP Top 10 vulnerabilities.",
                                priority="HIGH", metadata=auth_meta)
                        else:
                            _pending_web_targets.append({"host": host, "base": base})
                            log(f"[mitm] Web target {host} buffered — waiting for auth")
                    except Exception:
                        pass
                elif line.startswith("__QUILL_PASSTHROUGH__:"):
                    try:
                        payload = json.loads(line[len("__QUILL_PASSTHROUGH__:"):])
                        host = payload.get("host", "")
                        failures = payload.get("failures", 0)
                        log(f"[mitm] Auto-passthrough: {host} — cert pinning detected "
                            f"after {failures} TLS failures (future connections bypass MITM)")
                    except Exception:
                        pass
                else:
                    log(f"[mitm] [{label}] {line}")
        except Exception:
            pass
    _t_out = _thr_mod.Thread(target=_drain_mitm, args=(mitm_proc.stdout, "out"), daemon=True)
    _t_err = _thr_mod.Thread(target=_drain_mitm, args=(mitm_proc.stderr, "err"), daemon=True)
    _t_out.start()
    _t_err.start()

    frida_proc = None
    if frida_bin and ssl_script_file:
        frida_cmd = [frida_bin]
        if device:
            frida_cmd.extend(["-D", device])
        frida_cmd.extend(["-n", target_process, "-l", str(ssl_script_file),
                          "--no-pause", "-q"])
        log(f"[mitm] Launching Frida SSL bypass: {' '.join(frida_cmd)}")
        try:
            frida_proc = subprocess.Popen(frida_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as exc:
            log(f"[mitm] Frida launch failed (capture continues without SSL bypass): {exc}")
    else:
        log("[mitm] Frida SSL bypass skipped — using external bypass (upstream proxy / manual)")

    import time as _time_mod
    mitm_sentinel = output_dir / "_mitm_stop"
    if mitm_sentinel.exists():
        mitm_sentinel.unlink()
    if _MANAGED:
        import json as _json_mod
        print("__CRUCIBLE_STATUS__:" + _json_mod.dumps({
            "phase": "mitm_capture", "label": "MITM capture active",
            "state": "running", "mitm_active": True}), flush=True)
    log("[mitm] Capturing traffic — exercise the app now "
        f"(stop via Crucible or touch {mitm_sentinel.name})")
    status("mitm_capture", "Capturing traffic — stop when ready", "running")
    elapsed = 0
    stop_reason = None
    while True:
        _check_pause()
        if mitm_sentinel.exists():
            stop_reason = "user"
            log("[mitm] Stop signal received — ending capture")
            try:
                mitm_sentinel.unlink()
            except OSError:
                pass
            break
        if mitm_proc.poll() is not None:
            stop_reason = "process_exited"
            log(f"[mitm] mitmproxy exited (code {mitm_proc.returncode})")
            break
        if elapsed > 0 and elapsed % 30 == 0:
            rss = _get_rss_mb(mitm_proc.pid)
            if rss >= _MITM_MEM_THRESHOLD_MB:
                stop_reason = "memory"
                log(f"[mitm] Memory threshold reached ({rss:.0f}MB >= "
                    f"{_MITM_MEM_THRESHOLD_MB}MB) — pausing capture")
                status("mitm_capture",
                       f"Paused — memory threshold ({rss:.0f}MB)", "paused")
                if _MANAGED:
                    print("__CRUCIBLE_STATUS__:" + _json_mod.dumps({
                        "phase": "mitm_capture",
                        "label": f"MITM paused — memory ({rss:.0f}MB)",
                        "state": "paused", "mitm_active": False,
                        "mitm_paused": True}), flush=True)
                break
            log(f"[mitm] Capture in progress — {elapsed}s elapsed, "
                f"mitmproxy RSS {rss:.0f}MB")
            status("mitm_capture", f"Capturing ({elapsed}s)", "running")
        _time_mod.sleep(5)
        elapsed += 5

    if stop_reason == "memory":
        log(f"[mitm] Capture paused after {elapsed}s due to memory — "
            "resume via Crucible or restart Quill with --resume")
    elif stop_reason == "user":
        log(f"[mitm] User stopped capture after {elapsed}s")
    elif stop_reason == "process_exited":
        log(f"[mitm] Capture ended after {elapsed}s — mitmproxy exited")
    else:
        log(f"[mitm] Capture ended after {elapsed}s")
    log("[mitm] Stopping proxy and Frida...")
    import signal as _sig_mod
    try:
        mitm_proc.send_signal(_sig_mod.SIGINT)
        mitm_proc.wait(timeout=10)
    except Exception:
        mitm_proc.kill()
        mitm_proc.wait()
    mitm_ended = datetime.now(timezone.utc)
    _t_out.join(timeout=5)
    _t_err.join(timeout=5)
    if _pending_api_targets or _pending_web_targets:
        n_authed = sum(1 for p in _pending_api_targets if _has_auth_for(p["host"])) + \
                   sum(1 for p in _pending_web_targets if _has_auth_for(p["host"]))
        n_noauth = (len(_pending_api_targets) + len(_pending_web_targets)) - n_authed
        log(f"[mitm] Flushing {len(_pending_api_targets)} API + "
            f"{len(_pending_web_targets)} web buffered targets (MITM ended) — "
            f"{n_authed} with auth (auto), {n_noauth} without auth (manual)")
        _flush_all_pending()
    mitm_stdout = "\n".join(_mitm_lines)[:8_000_000]
    mitm_stderr = ""
    if frida_proc is not None:
        try:
            frida_proc.kill()
            frida_proc.wait(timeout=5)
        except Exception:
            pass
    if _ur is not None:
        try:
            _ur.write_tool_log(
                cmd=mitm_cmd, started=mitm_started.isoformat(),
                ended=mitm_ended.isoformat(), exit_code=mitm_proc.returncode,
                stdout=mitm_stdout, stderr=mitm_stderr,
                tool_name="mitmdump", tool_path=mitmdump_bin,
                output_file=str(flows_file),
                errors_log=(str(_RUN_DIR / "errors.log") if _RUN_DIR else None))
        except Exception:
            pass
    if not flows_file.exists() or flows_file.stat().st_size == 0:
        err("No traffic captured — ensure the app was exercised and proxy was configured")
        status("mitm_capture", "MITM traffic capture", "error")
        return None
    log(f"[mitm] Capture complete — {flows_file.stat().st_size / 1024:.1f} KB")
    status("mitm_capture", "MITM traffic capture", "complete")
    return flows_file


def mitm_analyse(output_dir: Path, flows_file: Path) -> None:
    _check_pause()
    log("[mitm-analyse] Starting traffic analysis...")
    status("mitm_analyse", "MITM traffic analysis", "running")
    try:
        from mitmproxy.io import FlowReader
        from mitmproxy import http as mhttp
    except ImportError:
        err("mitmproxy Python package not available — cannot analyse flows")
        status("mitm_analyse", "MITM traffic analysis", "skipped")
        return
    mitm_dir = output_dir / "mitm"
    evidence_dir = mitm_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    flows = []
    try:
        with open(flows_file, "rb") as f:
            reader = FlowReader(f)
            for flow in reader.stream():
                if isinstance(flow, mhttp.HTTPFlow) and flow.response:
                    flows.append(flow)
    except Exception as exc:
        err(f"Failed to read flow file: {exc}")
        status("mitm_analyse", "MITM traffic analysis", "error")
        return
    if not flows:
        log("[mitm-analyse] No HTTP flows found in capture")
        status("mitm_analyse", "MITM traffic analysis", "complete")
        return
    log(f"[mitm-analyse] Loaded {len(flows)} HTTP flow(s)")
    _mitm_check_cleartext(flows, evidence_dir)
    _mitm_check_sensitive_urls(flows, evidence_dir)
    _mitm_check_sensitive_bodies(flows, evidence_dir)
    _mitm_check_security_headers(flows, evidence_dir)
    _mitm_check_api_keys(flows, evidence_dir)
    _mitm_check_cookies(flows, evidence_dir)
    _mitm_check_certs(flows, evidence_dir)
    _mitm_check_trackers(flows, evidence_dir)
    _mitm_check_auth(flows, evidence_dir)
    _mitm_check_tls_versions(flows, evidence_dir)
    _mitm_write_har(flows, mitm_dir / "traffic_capture.har")
    _mitm_write_api_inventory(flows, output_dir / "api_inventory.json")
    _mitm_write_traffic_analysis(flows, output_dir / "traffic_analysis.json")
    log("[mitm-analyse] Traffic analysis complete")
    status("mitm_analyse", "MITM traffic analysis", "complete")


def _mitm_check_cleartext(flows, evidence_dir):
    seq, seen = 0, set()
    for flow in flows:
        if flow.request.scheme == "http":
            host = flow.request.host
            if host in seen:
                continue
            seen.add(host)
            seq += 1
            ev = _write_mitm_evidence(flow, evidence_dir, seq)
            finding(title=f"Cleartext HTTP Traffic to {host}", severity="HIGH",
                    description=f"The application sent HTTP (unencrypted) traffic to {host}. "
                                f"All data in transit is visible to anyone on the network path.",
                    data={"catalogue_id": "QUILL-MITM-001",
                          "affected": f"{host}:{flow.request.port}",
                          "command": f"mitmdump — {flow.request.method} {flow.request.url}",
                          "remediation": "Enforce HTTPS for all communications. Implement HSTS."
                    }, output=f"{flow.request.method} {flow.request.url[:300]}\nScheme: HTTP (unencrypted)",
                    output_file=ev[0] if ev else "")


def _mitm_check_sensitive_urls(flows, evidence_dir):
    seq = 1000
    for flow in flows:
        url = flow.request.url
        for pat_name, pat in _SENSITIVE_URL_PATTERNS.items():
            if pat.search(url):
                seq += 1
                ev = _write_mitm_evidence(flow, evidence_dir, seq)
                finding(title=f"Sensitive Data in URL ({pat_name})", severity="HIGH",
                        description=f"The request URL contains {pat_name} data: "
                                    f"{flow.request.method} {flow.request.pretty_host}"
                                    f"{flow.request.path}. URLs are logged, cached, and "
                                    f"recorded in browser history.",
                        data={"catalogue_id": "QUILL-MITM-002",
                              "affected": flow.request.pretty_host,
                              "command": f"{flow.request.method} {url[:200]}",
                              "remediation": "Move sensitive data from URL parameters "
                                             "to request headers or POST body."
                        }, output=f"{flow.request.method} {url[:400]}",
                        output_file=ev[0] if ev else "")
                break


def _mitm_check_sensitive_bodies(flows, evidence_dir):
    seq = 2000
    for flow in flows:
        pairs = [("request", _safe_flow_content(flow.request)),
                 ("response", _safe_flow_content(flow.response))]
        for src_name, content in pairs:
            if not content:
                continue
            text = content.decode("utf-8", errors="replace")[:100000]
            for pat_name, pat in _PII_BODY_PATTERNS.items():
                if pat.search(text):
                    seq += 1
                    ev = _write_mitm_evidence(flow, evidence_dir, seq)
                    m = pat.search(text)
                    matched_ctx = text[max(0, m.start()-30):m.end()+30] if m else ""
                    finding(title=f"Sensitive Data in {src_name.title()} Body ({pat_name})",
                            severity="MEDIUM",
                            description=f"The {src_name} body to "
                                        f"{flow.request.pretty_host} contains {pat_name} data.",
                            data={"catalogue_id": "QUILL-MITM-003",
                                  "affected": flow.request.pretty_host,
                                  "command": f"{flow.request.method} {flow.request.url[:200]}",
                                  "remediation": "Minimize sensitive data. Use tokenization for PII."
                            }, output=f"{flow.request.method} {flow.request.url[:200]}\n{src_name} excerpt: ...{matched_ctx[:200]}...",
                            output_file=ev[0] if ev else "")
                    break


def _mitm_check_security_headers(flows, evidence_dir):
    seq, seen = 3000, set()
    for flow in flows:
        if flow.request.scheme != "https":
            continue
        host = flow.request.pretty_host
        resp_headers = {k.lower(): v for k, v in flow.response.headers.items()}
        for hdr, label in _SECURITY_HEADERS.items():
            key = (host, hdr)
            if key in seen or hdr in resp_headers:
                continue
            seen.add(key)
            seq += 1
            ev = _write_mitm_evidence(flow, evidence_dir, seq)
            resp_hdrs_str = "\n".join(f"  {k}: {v}" for k, v in list(flow.response.headers.items())[:15])
            finding(title=f"{label}: {host}", severity="MEDIUM",
                    description=f"Response from {host} is missing the {hdr} header.",
                    data={"catalogue_id": "QUILL-MITM-004",
                          "affected": host,
                          "command": f"{flow.request.method} {flow.request.url[:200]}",
                          "remediation": f"Configure the server to include {hdr} in responses."
                    }, output=f"Response headers from {host}:\n{resp_hdrs_str}\n\nMissing: {hdr}",
                    output_file=ev[0] if ev else "")


def _mitm_check_api_keys(flows, evidence_dir):
    seq, seen_keys = 4000, set()
    for flow in flows:
        for src_name, text in [
            ("request headers", "\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())),
            ("request body", _safe_flow_content(flow.request).decode("utf-8", errors="replace")[:100000]),
            ("request URL", flow.request.url),
            ("response body", _safe_flow_content(flow.response).decode("utf-8", errors="replace")[:100000]),
        ]:
            if not text:
                continue
            for key_type, pat in _API_KEY_PATTERNS.items():
                if key_type == "generic_bearer" and src_name != "request headers":
                    continue
                if pat.search(text):
                    dedup = (flow.request.pretty_host, key_type)
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)
                    seq += 1
                    ev = _write_mitm_evidence(flow, evidence_dir, seq)
                    finding(title=f"API Key/Token in Traffic ({key_type}): "
                                  f"{flow.request.pretty_host}",
                            severity="HIGH",
                            description=f"A {key_type} pattern was found in {src_name} "
                                        f"to {flow.request.pretty_host}.",
                            data={"catalogue_id": "QUILL-MITM-005",
                                  "affected": flow.request.pretty_host,
                                  "command": f"{flow.request.method} {flow.request.url[:200]}",
                                  "remediation": "Rotate the exposed key. Use short-lived tokens."
                            }, output_file=ev[0] if ev else "")


def _mitm_check_cookies(flows, evidence_dir):
    seq, seen = 5000, set()
    for flow in flows:
        for hdr_val in flow.response.headers.get_all("set-cookie"):
            parts = hdr_val.split(";")
            if not parts:
                continue
            cookie_name = parts[0].split("=")[0].strip()
            flags_lower = hdr_val.lower()
            host = flow.request.pretty_host
            issues = []
            if "secure" not in flags_lower:
                issues.append("Secure")
            if "httponly" not in flags_lower:
                issues.append("HttpOnly")
            if "samesite" not in flags_lower:
                issues.append("SameSite")
            if not issues:
                continue
            key = (host, cookie_name)
            if key in seen:
                continue
            seen.add(key)
            seq += 1
            ev = _write_mitm_evidence(flow, evidence_dir, seq)
            finding(title=f"Insecure Cookie: {cookie_name} on {host}", severity="MEDIUM",
                    description=f"Cookie '{cookie_name}' from {host} is missing: "
                                f"{', '.join(issues)}.",
                    data={"catalogue_id": "QUILL-MITM-006",
                          "affected": host,
                          "command": f"Set-Cookie: {hdr_val[:200]}",
                          "remediation": f"Add {', '.join(issues)} flag(s) to the cookie."
                    }, output_file=ev[0] if ev else "")


def _mitm_check_certs(flows, evidence_dir):
    seq, seen = 6000, set()
    for flow in flows:
        if not hasattr(flow, 'server_conn') or flow.server_conn is None:
            continue
        sc = flow.server_conn
        host = flow.request.pretty_host
        if host in seen:
            continue
        if hasattr(sc, 'error') and sc.error:
            seen.add(host)
            seq += 1
            ev = _write_mitm_evidence(flow, evidence_dir, seq)
            finding(title=f"TLS Certificate Issue: {host}", severity="HIGH",
                    description=f"mitmproxy recorded a TLS error for {host}: {sc.error}.",
                    data={"catalogue_id": "QUILL-MITM-007",
                          "affected": host,
                          "remediation": "Use valid certificates from a trusted CA. "
                                         "Implement certificate pinning."
                    }, output_file=ev[0] if ev else "")


def _mitm_check_trackers(flows, evidence_dir):
    seq, seen = 7000, set()
    for flow in flows:
        host = flow.request.host
        for domain, tracker_name in _TRACKER_DOMAINS.items():
            if host == domain or host.endswith("." + domain):
                if tracker_name in seen:
                    continue
                seen.add(tracker_name)
                body = _safe_flow_content(flow.request).decode("utf-8", errors="replace")[:50000]
                data_types = []
                if re.search(r'(?:device_?id|idfa|gaid|advertisingId)', body, re.IGNORECASE):
                    data_types.append("device identifiers")
                if re.search(r'(?:latitude|longitude|lat|lng|geo)', body, re.IGNORECASE):
                    data_types.append("location data")
                if re.search(r'(?:email|user_?name|user_?id)', body, re.IGNORECASE):
                    data_types.append("user identifiers")
                seq += 1
                ev = _write_mitm_evidence(flow, evidence_dir, seq)
                data_desc = f" Data includes: {', '.join(data_types)}." if data_types else ""
                finding(title=f"Third-Party Data Leakage: {tracker_name}", severity="MEDIUM",
                        description=f"The app sends data to {tracker_name} ({host}).{data_desc}",
                        data={"catalogue_id": "QUILL-MITM-008",
                              "affected": host,
                              "command": f"{flow.request.method} {flow.request.url[:200]}",
                              "remediation": "Review data sent to third-party analytics. "
                                             "Minimize PII. Disclose in privacy policy."
                        }, output_file=ev[0] if ev else "")
                break


def _mitm_check_auth(flows, evidence_dir):
    seq, seen = 9000, set()
    for flow in flows:
        if not _AUTH_URL_PATTERNS.search(flow.request.url.lower()):
            continue
        host = flow.request.pretty_host
        if flow.request.scheme == "http":
            key = ("http_auth", host)
            if key not in seen:
                seen.add(key)
                seq += 1
                ev = _write_mitm_evidence(flow, evidence_dir, seq)
                finding(title=f"Unencrypted Authentication: {host}", severity="CRITICAL",
                        description=f"Authentication request to {host} sent over plaintext HTTP. "
                                    f"Credentials are fully exposed to network observers.",
                        data={"catalogue_id": "QUILL-MITM-010",
                              "affected": host,
                              "command": f"{flow.request.method} {flow.request.url[:200]}",
                              "remediation": "All auth endpoints MUST use HTTPS. Implement HSTS."
                        }, output_file=ev[0] if ev else "")
        if _SENSITIVE_URL_PATTERNS["password"].search(flow.request.url):
            key = ("url_creds", host)
            if key not in seen:
                seen.add(key)
                seq += 1
                ev = _write_mitm_evidence(flow, evidence_dir, seq)
                finding(title=f"Credentials in URL on Auth Endpoint: {host}",
                        severity="CRITICAL",
                        description=f"Password data in URL of auth request to {host}. "
                                    f"URLs are logged, cached, and in browser history.",
                        data={"catalogue_id": "QUILL-MITM-010",
                              "affected": host,
                              "command": f"{flow.request.method} {flow.request.url[:200]}",
                              "remediation": "Send credentials in request body, not URL. Use HTTPS."
                        }, output_file=ev[0] if ev else "")


def _mitm_check_tls_versions(flows, evidence_dir):
    seq, seen = 10000, set()
    deprecated = {"TLSv1", "TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1",
                  "SSLv2", "SSLv3", "SSL 2.0", "SSL 3.0"}
    for flow in flows:
        if not hasattr(flow, 'server_conn') or flow.server_conn is None:
            continue
        host = flow.request.pretty_host
        if host in seen:
            continue
        tls_ver = getattr(flow.server_conn, 'tls_version', None) or ""
        if tls_ver and tls_ver in deprecated:
            seen.add(host)
            seq += 1
            ev = _write_mitm_evidence(flow, evidence_dir, seq)
            finding(title=f"Deprecated TLS Version ({tls_ver}): {host}", severity="MEDIUM",
                    description=f"Connection to {host} used {tls_ver}, which has known "
                                f"vulnerabilities. TLS 1.2 is the minimum acceptable version.",
                    data={"catalogue_id": "QUILL-MITM-011",
                          "affected": host,
                          "remediation": "Configure server to support TLS 1.2+ only."
                    }, output_file=ev[0] if ev else "")


def _mitm_write_har(flows, har_path: Path) -> None:
    entries = []
    for flow in flows:
        started = ""
        if hasattr(flow, 'timestamp_start') and flow.timestamp_start:
            started = datetime.fromtimestamp(flow.timestamp_start, tz=timezone.utc).isoformat()
        dur = 0
        if hasattr(flow, 'timestamp_end') and hasattr(flow, 'timestamp_start'):
            dur = ((flow.timestamp_end or 0) - (flow.timestamp_start or 0)) * 1000
        entry = {
            "startedDateTime": started, "time": round(dur, 2),
            "request": {
                "method": flow.request.method, "url": flow.request.url,
                "httpVersion": flow.request.http_version,
                "headers": [{"name": k, "value": v} for k, v in flow.request.headers.items()],
                "headersSize": -1, "bodySize": len(_safe_flow_content(flow.request)),
            },
            "response": {
                "status": flow.response.status_code,
                "statusText": flow.response.reason or "",
                "httpVersion": flow.response.http_version,
                "headers": [{"name": k, "value": v} for k, v in flow.response.headers.items()],
                "headersSize": -1, "bodySize": len(_safe_flow_content(flow.response)),
            },
            "timings": {"send": -1, "wait": round(dur, 2), "receive": -1},
        }
        _har_req_bytes = _safe_flow_content(flow.request)
        if _har_req_bytes:
            entry["request"]["postData"] = {
                "mimeType": flow.request.headers.get("content-type", ""),
                "text": _har_req_bytes.decode("utf-8", errors="replace")[:50000],
            }
        entries.append(entry)
    har = {"log": {"version": "1.2",
                   "creator": {"name": "Quill MITM", "version": VERSION},
                   "entries": entries}}
    try:
        har_path.write_text(json.dumps(har, indent=2, default=str), encoding="utf-8")
        log(f"[mitm-intel] HAR file written ({len(entries)} entries)")
    except Exception as exc:
        err(f"HAR write failed: {exc}")


def _mitm_write_api_inventory(flows, inv_path: Path) -> None:
    endpoints = {}
    for flow in flows:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(flow.request.url)
        except Exception:
            continue
        key = (flow.request.method, parsed.hostname, parsed.path)
        if key not in endpoints:
            endpoints[key] = {
                "method": flow.request.method, "host": parsed.hostname or "",
                "path": parsed.path or "/", "scheme": parsed.scheme,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "content_types": set(), "status_codes": set(),
                "has_auth": False, "auth_type": "", "request_count": 0,
                "query_params": set(),
            }
        ep = endpoints[key]
        ep["request_count"] += 1
        ct = flow.response.headers.get("content-type", "").split(";")[0].strip()
        if ct:
            ep["content_types"].add(ct)
        ep["status_codes"].add(flow.response.status_code)
        auth = flow.request.headers.get("authorization", "")
        if auth:
            ep["has_auth"] = True
            ep["auth_type"] = auth.split(" ")[0] if " " in auth else "custom"
        if parsed.query:
            for p in parsed.query.split("&"):
                pn = p.split("=")[0]
                if pn:
                    ep["query_params"].add(pn)
    inventory = []
    for ep in endpoints.values():
        ep["content_types"] = sorted(ep["content_types"])
        ep["status_codes"] = sorted(ep["status_codes"])
        ep["query_params"] = sorted(ep["query_params"])
        inventory.append(ep)
    inventory.sort(key=lambda e: (e["host"], e["path"], e["method"]))
    try:
        inv_path.write_text(json.dumps({"endpoints": inventory, "total": len(inventory)},
                                        indent=2, default=str), encoding="utf-8")
        log(f"[mitm-intel] API inventory written ({len(inventory)} endpoints)")
    except Exception as exc:
        err(f"API inventory write failed: {exc}")


def _mitm_write_traffic_analysis(flows, analysis_path: Path) -> None:
    hosts, methods, status_codes, content_types = {}, {}, {}, {}
    total_req, total_resp = 0, 0
    for flow in flows:
        host = flow.request.pretty_host
        if host not in hosts:
            hosts[host] = {"request_count": 0, "schemes": set()}
        hosts[host]["request_count"] += 1
        hosts[host]["schemes"].add(flow.request.scheme)
        total_req += len(_safe_flow_content(flow.request))
        total_resp += len(_safe_flow_content(flow.response))
        methods[flow.request.method] = methods.get(flow.request.method, 0) + 1
        sc = flow.response.status_code
        status_codes[sc] = status_codes.get(sc, 0) + 1
        ct = flow.response.headers.get("content-type", "").split(";")[0].strip()
        if ct:
            content_types[ct] = content_types.get(ct, 0) + 1
    host_list = sorted(hosts.items(), key=lambda h: h[1]["request_count"], reverse=True)
    analysis = {
        "total_flows": len(flows), "total_request_bytes": total_req,
        "total_response_bytes": total_resp, "unique_hosts": len(hosts),
        "methods": methods,
        "status_codes": {str(k): v for k, v in sorted(status_codes.items())},
        "content_types": content_types,
        "hosts": [{"host": h, "request_count": d["request_count"],
                   "schemes": sorted(d["schemes"]),
                   "is_tracker": any(h == td or h.endswith("." + td)
                                     for td in _TRACKER_DOMAINS)}
                  for h, d in host_list],
    }
    try:
        analysis_path.write_text(json.dumps(analysis, indent=2, default=str), encoding="utf-8")
        log(f"[mitm-intel] Traffic analysis written ({len(flows)} flows, {len(hosts)} hosts)")
    except Exception as exc:
        err(f"Traffic analysis write failed: {exc}")


# ── Intelligence extraction — domains, URLs, emails ──────────────────────────

_URL_RX = re.compile(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%\-]+', re.ASCII)
_EMAIL_RX = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

_JUNK_DOMAINS = frozenset({
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "xmlpull.org",
    "xml.org", "purl.org", "apache.org", "example.com", "example.org",
    "example.net", "localhost", "schema.org", "json-schema.org",
    "0.0.0.0", "127.0.0.1", "::1",
})

_JUNK_EMAIL_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "test.com",
    "localhost", "noreply.com",
})


def _gather_all_text(app_dir: Path, output_dir: Path, platform: str) -> str:
    text_exts = {"xml", "json", "plist", "strings", "txt", "cfg", "yml", "yaml",
                 "properties", "smali", "java", "kt", "swift", "m", "h"}
    parts = []
    for ext in text_exts:
        for f in app_dir.rglob(f"*.{ext}"):
            try:
                parts.append(f.read_text(encoding="utf-8", errors="ignore")[:200000])
            except Exception:
                continue

    strings_bin = shutil.which("strings")
    if strings_bin:
        if platform == "android":
            for dex in app_dir.rglob("*.dex"):
                cp = _run_tool_cmd([strings_bin, str(dex)],
                                   output_file=str(output_dir / f"intel_strings_{dex.name}.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    parts.append(cp.stdout or "")
            for arsc in app_dir.rglob("resources.arsc"):
                cp = _run_tool_cmd([strings_bin, str(arsc)],
                                   output_file=str(output_dir / "intel_strings_resources_arsc.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    parts.append(cp.stdout or "")
            for so in sorted(app_dir.rglob("*.so")):
                if so.stat().st_size > 50_000_000:
                    continue
                cp = _run_tool_cmd([strings_bin, "-n", "8", str(so)],
                                   output_file=str(output_dir / f"intel_strings_{so.name}.txt"),
                                   timeout=180, tool_name="strings")
                if cp is not None:
                    parts.append(cp.stdout or "")
        else:
            main_bin = _find_ios_main_binary(app_dir)
            if main_bin:
                cp = _run_tool_cmd([strings_bin, str(main_bin)],
                                   output_file=str(output_dir / "intel_strings_binary.txt"),
                                   timeout=120, tool_name="strings")
                if cp is not None:
                    parts.append(cp.stdout or "")
            for fw_dir in (app_dir / "Frameworks").iterdir() if (app_dir / "Frameworks").is_dir() else []:
                fw_bin = fw_dir / fw_dir.stem if fw_dir.is_dir() else None
                if fw_bin and fw_bin.exists() and fw_bin.stat().st_size < 50_000_000:
                    cp = _run_tool_cmd([strings_bin, "-n", "8", str(fw_bin)],
                                       output_file=str(output_dir / f"intel_strings_{fw_dir.stem}.txt"),
                                       timeout=120, tool_name="strings")
                    if cp is not None:
                        parts.append(cp.stdout or "")
    return "\n".join(parts)


def extract_domains_and_urls(app_dir: Path, output_dir: Path, platform: str) -> dict:
    _check_pause()
    _save_checkpoint()
    log(f"[intel_urls] Extracting domains and URLs for {app_dir.name}...")
    status("intel_urls", "URL & domain extraction", "running")

    all_text = _gather_all_text(app_dir, output_dir, platform)
    raw_urls = _URL_RX.findall(all_text)

    urls_dedup: dict = {}
    domains: dict = {}
    for u in raw_urls:
        u_clean = u.rstrip(".,;:'\")>")
        if u_clean not in urls_dedup:
            urls_dedup[u_clean] = True
        try:
            host = u_clean.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        except IndexError:
            continue
        if host and host not in _JUNK_DOMAINS and not host.replace(".", "").isdigit():
            domains.setdefault(host, 0)
            domains[host] += 1

    sorted_domains = sorted(domains.items(), key=lambda x: -x[1])
    sorted_urls = sorted(urls_dedup.keys())

    result = {
        "unique_urls": len(sorted_urls),
        "unique_domains": len(sorted_domains),
        "domains": [{"domain": d, "count": c} for d, c in sorted_domains],
        "urls": sorted_urls[:2000],
    }

    out_file = output_dir / "url_domain_analysis.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "URL & domain extraction",
                  [f"unique_urls: {len(sorted_urls)}",
                   f"unique_domains: {len(sorted_domains)}"])

    log(f"[intel_urls] Extraction complete — {len(sorted_urls)} URLs, {len(sorted_domains)} domains")
    status("intel_urls", "URL & domain extraction", "complete")
    return result


def extract_emails(app_dir: Path, output_dir: Path, platform: str) -> dict:
    _check_pause()
    _save_checkpoint()
    log(f"[intel_emails] Extracting emails for {app_dir.name}...")
    status("intel_emails", "Email extraction", "running")

    all_text = _gather_all_text(app_dir, output_dir, platform)
    raw_emails = _EMAIL_RX.findall(all_text)

    emails_dedup: dict = {}
    for e in raw_emails:
        e_lower = e.lower()
        if "%" in e or "$" in e:
            continue
        local = e_lower.rsplit("@", 1)[0]
        if local.startswith(".") or local.endswith(".") or ".." in local:
            continue
        if len(local) < 2 or len(local) > 64:
            continue
        domain = e_lower.rsplit("@", 1)[-1]
        if domain not in _JUNK_EMAIL_DOMAINS and not e_lower.endswith(".png") and \
           not e_lower.endswith(".jpg") and not e_lower.endswith(".xml") and \
           not e_lower.endswith(".so") and not e_lower.endswith(".dylib") and \
           not e_lower.endswith(".class"):
            emails_dedup.setdefault(e_lower, e)

    sorted_emails = sorted(emails_dedup.values())
    result = {
        "unique_emails": len(sorted_emails),
        "emails": sorted_emails[:500],
    }

    out_file = output_dir / "email_analysis.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _analysis_log(out_file, "Email extraction",
                  [f"unique_emails: {len(sorted_emails)}"])

    log(f"[intel_emails] Extraction complete — {len(sorted_emails)} emails")
    status("intel_emails", "Email extraction", "complete")
    return result


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
    p.add_argument("--mode", choices=["static", "dynamic", "full"], default="full",
                     help="Analysis mode: static (no device needed), dynamic (Frida + MITM only), "
                          "full (static + dynamic, default)")
    p.add_argument("--dynamic", action="store_true", help="Enable Frida-based dynamic analysis (legacy, same as --mode full)")
    p.add_argument("--device", default="", help="Frida device ID (for dynamic/full mode)")
    p.add_argument("--target-process", default="", help="Target process name for dynamic analysis")
    p.add_argument("--client-short", default="default")
    p.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    p.add_argument("--engagement-name", default="quill run", help="Engagement name for meta.json")
    p.add_argument("--mitm", action="store_true",
                     help="Enable MITM traffic capture and analysis (works with any mode; "
                          "does NOT require Frida — use --mitm-upstream-proxy to chain "
                          "through an external proxy for manual pinning bypass flows)")
    p.add_argument("--mitm-duration", type=int, default=0,
                     help="Deprecated — capture runs until stopped. "
                          "Kept for backward compatibility; value is ignored")
    p.add_argument("--mitm-port", type=int, default=8080,
                     help="mitmproxy listen port (default: 8080)")
    p.add_argument("--mitm-transparent", action="store_true",
                     help="Use transparent proxy mode (requires iptables/pf)")
    p.add_argument("--mitm-upstream-proxy", default="",
                     help="Upstream proxy URL (e.g. http://127.0.0.1:8080) — "
                          "chain: Device → Quill MITM → Proxy → Internet")
    p.add_argument("--mitm-burp-ca", default="",
                     help="Path to upstream proxy's CA (cert+key PEM) — "
                          "Quill signs with this CA so the device only "
                          "needs one CA trusted, not two")
    p.add_argument("--mitm-ignore-hosts", default="",
                     help="Regex of hosts to pass through without intercepting "
                          "(e.g. '.*\\.sentry\\.io|.*\\.mixpanel\\.com'). "
                          "Use for SDK domains that pin certificates")
    p.add_argument("--project", help="Override project output directory")
    p.add_argument("--version", action="store_true")
    args = p.parse_args()

    if args.version:
        print(VERSION)
        return 0

    app_path = args.app or args.ipa
    _dynamic_only = args.mode == "dynamic" or (args.dynamic and args.mode != "full")
    _mitm_only = args.mitm and not _dynamic_only and args.mode != "full"
    if not app_path and not _dynamic_only and not _mitm_only:
        p.error("--app (or --ipa) is required unless --mode dynamic or --mitm")
    if not app_path and _dynamic_only and not args.target_process and not args.mitm:
        p.error("--target-process is required when running dynamic-only without --app "
                "(not needed for MITM-only — pass --mitm)")

    platform = args.platform
    if platform == "auto":
        if app_path:
            platform = _detect_platform(app_path)
            if not platform:
                p.error(f"Cannot detect platform from extension: {app_path} — use --platform ios|android")
            log(f"[init] Auto-detected platform: {platform} (from file extension)")
        else:
            p.error("--platform ios|android is required when no app binary is provided")
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
            target=app_path or args.target_process or "dynamic"))
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

    mode = args.mode
    if args.dynamic and mode == "full":
        pass
    elif args.dynamic and mode == "static":
        mode = "full"
    run_static = mode in ("static", "full")
    run_dynamic = mode in ("dynamic", "full")
    run_mitm = args.mitm

    global _APP_TARGET, _EXTRACT_BASE
    _APP_TARGET = Path(app_path).name if app_path else (args.target_process or "dynamic")
    _mode_label = "MITM-only" if (run_mitm and not run_dynamic and not app_path) else "dynamic/MITM only" if not app_path else app_path
    log(f"[init] Quill v{VERSION} starting — {platform.upper()}: {_mode_label}")
    log(f"[init] Mode: {mode} (static={run_static}, dynamic={run_dynamic}, mitm={run_mitm})")
    log(f"[init] Client: {args.client_short}, Engagement: {args.engagement_name}")
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    extract_dir = project_dir / "extract"
    _EXTRACT_BASE = extract_dir

    _check_pause()
    app_dir = None
    manifest_data = {}
    plist_data = {}
    if not app_path:
        log("[main] No app binary — skipping extraction and static analysis (dynamic/MITM only)")
    elif platform == "ios":
        app_dir = extract_ipa(Path(app_path), extract_dir)
        if not app_dir:
            return 1
        if run_static:
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
            analyse_ios_runtime_protections(app_dir, project_dir)
            _check_pause()
            detect_trackers_ios(app_dir, project_dir)
            _check_pause()
            url_domain_intel = extract_domains_and_urls(app_dir, project_dir, "ios")
            _check_pause()
            email_intel = extract_emails(app_dir, project_dir, "ios")
            _check_pause()
            compute_file_hashes(Path(app_path), project_dir)
        elif not run_static:
            log("[main] Static analysis skipped (mode=dynamic)")
    elif platform == "android":
        app_dir = extract_apk(Path(app_path), extract_dir)
        if not app_dir:
            return 1
        if run_static:
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
            analyse_runtime_protections(app_dir, project_dir)
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
            url_domain_intel = extract_domains_and_urls(app_dir, project_dir, "android")
            _check_pause()
            email_intel = extract_emails(app_dir, project_dir, "android")
            _check_pause()
            compute_file_hashes(Path(app_path), project_dir)
        elif not run_static:
            log("[main] Static analysis skipped (mode=dynamic)")

    _check_pause()
    if run_dynamic:
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
            if not target_process and app_path:
                target_process = Path(app_path).stem
            if not target_process:
                if run_mitm:
                    log("[main] No target process — skipping Frida dynamic analysis (MITM-only)")
                else:
                    err("[main] Cannot resolve dynamic target — no --target-process and no app binary")
                    return 1
        if target_process:
            log(f"[main] Dynamic target process resolved: {target_process}")
            dynamic_analysis(target_process, platform, args.device, project_dir)

    _check_pause()
    if run_mitm:
        log("[main] MITM traffic analysis requested — resolving target process...")
        mitm_target = args.target_process
        if not mitm_target:
            if platform == "android":
                manifest = extract_dir / "AndroidManifest.xml"
                if not manifest.exists() and app_dir:
                    manifest = app_dir / "AndroidManifest.xml"
                if manifest.exists():
                    try:
                        tree = ET.parse(manifest)
                        mitm_target = tree.getroot().get("package", "")
                    except Exception:
                        pass
            if not mitm_target and app_path:
                mitm_target = Path(app_path).stem
            if not mitm_target:
                mitm_target = "unknown"
                log("[main] MITM target process unknown — capturing all traffic on proxy port")
            log(f"[main] MITM target process: {mitm_target}")
        flows_file = mitm_capture(
            mitm_target, platform, args.device, project_dir,
            port=args.mitm_port,
            transparent=args.mitm_transparent,
            upstream_proxy=args.mitm_upstream_proxy,
            burp_ca=args.mitm_burp_ca,
            ignore_hosts=args.mitm_ignore_hosts)
        if flows_file:
            mitm_analyse(project_dir, flows_file)

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
                target=app_path or args.target_process or "dynamic",
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

    log("[finalize] Generating intelligence data files...")
    _write_intel_files(project_dir, platform, _APP_TARGET)

    log("[finalize] Generating cross-tool action items...")
    _generate_cross_tool_action_items(project_dir)
    if _pause is not None:
        _pause.write_stop_reason("completed", "all_phases_done")
    rc = _risk_counts(_findings)
    log(f"[shutdown] Quill v{VERSION} complete — {len(_findings)} finding(s) "
        f"(C={rc['CRITICAL']} H={rc['HIGH']} M={rc['MEDIUM']} L={rc['LOW']} I={rc['INFO']}) — output: {project_dir}")
    return 0


def _write_intel_files(project_dir: Path, platform: str, app_name: str) -> None:
    """Write consolidated intelligence files for Crucible's mobile intel tabs."""

    def _load(name):
        p = project_dir / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    app_entry = {"name": app_name, "platform": platform}

    # ── components.json ──
    components_data = {"apps": []}
    if platform == "android":
        manifest = _load("manifest_analysis.json")
        if manifest:
            app_entry_c = dict(app_entry)
            app_entry_c["package"] = manifest.get("package", "")
            app_entry_c["components"] = manifest.get("components", [])
            app_entry_c["flags"] = manifest.get("flags", {})
            components_data["apps"].append(app_entry_c)
    elif platform == "ios":
        plist = _load("info_plist.json")
        if plist:
            app_entry_c = dict(app_entry)
            app_entry_c["bundle_id"] = plist.get("CFBundleIdentifier", "")
            ents = []
            ent_file = project_dir / "entitlements.xml"
            if ent_file.exists():
                try:
                    raw = ent_file.read_text(encoding="utf-8", errors="replace")
                    for line in raw.splitlines():
                        line = line.strip()
                        if line.startswith("<key>") and line.endswith("</key>"):
                            ents.append(line[5:-6])
                except Exception:
                    pass
            app_entry_c["entitlements"] = ents
            app_entry_c["flags"] = {
                "ats_enabled": bool(plist.get("NSAppTransportSecurity")),
                "allows_arbitrary_loads": bool(
                    (plist.get("NSAppTransportSecurity") or {}).get(
                        "NSAllowsArbitraryLoads")),
            }
            components_data["apps"].append(app_entry_c)
    try:
        (project_dir / "components.json").write_text(
            json.dumps(components_data, indent=2), encoding="utf-8")
    except Exception:
        pass

    # ── permissions.json ──
    perms_data = {"apps": []}
    if platform == "android":
        perm_analysis = _load("permission_analysis.json")
        if perm_analysis:
            app_entry_p = dict(app_entry)
            dangerous = set(perm_analysis.get("dangerous", []))
            all_perms = perm_analysis.get("dangerous", []) + perm_analysis.get("normal", [])
            app_entry_p["permissions"] = [
                {"name": p, "dangerous": p in dangerous}
                for p in all_perms
            ]
            app_entry_p["dangerous_count"] = perm_analysis.get("dangerous_count", 0)
            app_entry_p["total"] = perm_analysis.get("total", len(all_perms))
            perms_data["apps"].append(app_entry_p)
    elif platform == "ios":
        ios_perms = _load("ios_permissions.json")
        if ios_perms:
            app_entry_p = dict(app_entry)
            app_entry_p["permissions"] = ios_perms.get("permissions", [])
            app_entry_p["dangerous_count"] = ios_perms.get("dangerous_count", 0)
            app_entry_p["total"] = ios_perms.get("total_permissions", 0)
            perms_data["apps"].append(app_entry_p)
    try:
        (project_dir / "permissions.json").write_text(
            json.dumps(perms_data, indent=2), encoding="utf-8")
    except Exception:
        pass

    # ── hardening.json ──
    hardening_data = {"apps": []}
    if platform == "ios":
        mitigations = _load("ios_binary_mitigations.json")
        if mitigations:
            app_entry_h = dict(app_entry)
            checks = []
            for key, val in mitigations.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, bool):
                    checks.append({"name": key, "status": "pass" if val else "fail",
                                   "details": ""})
                elif isinstance(val, dict):
                    checks.append({"name": key,
                                   "status": val.get("status", "unknown"),
                                   "details": val.get("details", "")})
            app_entry_h["checks"] = checks
            hardening_data["apps"].append(app_entry_h)
        fw = _load("framework_binary_analysis.json")
        if fw and isinstance(fw, dict):
            weak = fw.get("weak_binaries", [])
            if weak:
                for w in (weak if isinstance(weak, list) else []):
                    name = w.get("name", "") if isinstance(w, dict) else str(w)
                    app_entry_fw = {"name": f"{app_name} (framework: {name})",
                                    "platform": platform,
                                    "checks": w.get("checks", []) if isinstance(w, dict) else []}
                    hardening_data["apps"].append(app_entry_fw)
    elif platform == "android":
        signing = _load("signing_analysis.json")
        apkid = _load("apkid_analysis.json")
        checks = []
        manifest = _load("manifest_analysis.json")
        if manifest:
            flags = manifest.get("flags", {})
            checks.append({"name": "debuggable",
                           "status": "fail" if flags.get("debuggable") else "pass",
                           "details": "android:debuggable flag"})
            checks.append({"name": "allowBackup",
                           "status": "fail" if flags.get("allowBackup") else "pass",
                           "details": "android:allowBackup flag"})
            checks.append({"name": "cleartext_traffic",
                           "status": "fail" if flags.get("usesCleartextTraffic") else "pass",
                           "details": "usesCleartextTraffic flag"})
            checks.append({"name": "network_security_config",
                           "status": "pass" if flags.get("networkSecurityConfig") else "warn",
                           "details": "Custom network security configuration"})
        if signing and isinstance(signing, dict):
            scheme = signing.get("scheme", "")
            checks.append({"name": "signing_scheme",
                           "status": "pass" if "v2" in str(scheme).lower() or "v3" in str(scheme).lower() else "warn",
                           "details": f"APK signing scheme: {scheme}"})
        if apkid and isinstance(apkid, dict):
            detections = apkid.get("detections", {}) if isinstance(apkid, dict) else {}
            obf = any("obfuscat" in str(v).lower() for v in
                       (detections.values() if isinstance(detections, dict) else []))
            checks.append({"name": "obfuscation",
                           "status": "pass" if obf else "warn",
                           "details": "Code obfuscation detected" if obf else "No obfuscation detected"})
        if checks:
            app_entry_h = dict(app_entry)
            app_entry_h["checks"] = checks
            hardening_data["apps"].append(app_entry_h)
    try:
        (project_dir / "hardening.json").write_text(
            json.dumps(hardening_data, indent=2), encoding="utf-8")
    except Exception:
        pass

    # ── data.json ──
    data_flow = {"apps": []}
    app_entry_d = dict(app_entry)
    if platform == "android":
        nsc = _load("network_security_config_analysis.json")
        app_entry_d["network_config"] = nsc or {}
        dl = _load("deep_link_analysis.json")
        app_entry_d["deep_links"] = (dl.get("activities", []) if isinstance(dl, dict) else dl) or []
        fb = _load("firebase_analysis.json")
        app_entry_d["firebase"] = fb or {}
        trackers = _load("tracker_analysis.json")
        app_entry_d["trackers"] = (trackers.get("trackers", []) if isinstance(trackers, dict) else []) or []
    elif platform == "ios":
        plist = _load("info_plist.json") or {}
        ats = plist.get("NSAppTransportSecurity", {}) or {}
        app_entry_d["network_config"] = {
            "ats_enabled": bool(ats),
            "allows_arbitrary_loads": ats.get("NSAllowsArbitraryLoads", False),
            "exception_domains": list((ats.get("NSExceptionDomains") or {}).keys()),
        }
        app_entry_d["deep_links"] = []
        schemes = plist.get("CFBundleURLTypes", [])
        if isinstance(schemes, list):
            for s in schemes:
                if isinstance(s, dict):
                    for sch in (s.get("CFBundleURLSchemes") or []):
                        app_entry_d["deep_links"].append({"scheme": sch})
        app_entry_d["firebase"] = {}
        ios_trackers = _load("tracker_analysis.json")
        app_entry_d["trackers"] = (ios_trackers.get("trackers", []) if isinstance(ios_trackers, dict) else []) or []
    data_flow["apps"].append(app_entry_d)
    try:
        (project_dir / "data.json").write_text(
            json.dumps(data_flow, indent=2), encoding="utf-8")
    except Exception:
        pass

    # ── domains.json ──
    url_domain = _load("url_domain_analysis.json")
    if url_domain:
        domains_data = {"apps": []}
        app_entry_dom = dict(app_entry)
        app_entry_dom["unique_domains"] = url_domain.get("unique_domains", 0)
        app_entry_dom["unique_urls"] = url_domain.get("unique_urls", 0)
        app_entry_dom["domains"] = url_domain.get("domains", [])
        app_entry_dom["urls"] = url_domain.get("urls", [])[:500]
        domains_data["apps"].append(app_entry_dom)
        try:
            (project_dir / "domains.json").write_text(
                json.dumps(domains_data, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── emails.json ──
    email_data = _load("email_analysis.json")
    if email_data:
        emails_out = {"apps": []}
        app_entry_em = dict(app_entry)
        app_entry_em["unique_emails"] = email_data.get("unique_emails", 0)
        app_entry_em["emails"] = email_data.get("emails", [])
        emails_out["apps"].append(app_entry_em)
        try:
            (project_dir / "emails.json").write_text(
                json.dumps(emails_out, indent=2), encoding="utf-8")
        except Exception:
            pass

    log(f"[finalize] Intelligence files written (components/permissions/hardening/data/domains/emails)")


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
        _q_scope = os.environ.get("CRUCIBLE_SCOPE", "")
        item = {
            "id": str(uuid.uuid4()),
            "type": item_type,
            "recommended_tool": tool,
            "target": target,
            "ip": "", "port": 0, "hostname": "",
            "title": title,
            "description": desc,
            "source_finding": source_finding,
            "priority": priority,
            "scope": _q_scope,
            "status": "pending",
            "datetime": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        items.append(item)
        if _MANAGED:
            cat_map = {"api": "api_discovered", "web_app": "webapp_discovered",
                       "cloud_audit": "other", "file_analysis": "other"}
            _tok("__CRUCIBLE_ACTION_ITEM__", json.dumps({
                "category": cat_map.get(item_type, "other"),
                "recommended_tool": tool.lower(),
                "target": target,
                "title": title,
                "description": desc,
                "priority": priority,
                "approval_tier": "auto",
                "source_tool": "quill",
                "scope": _q_scope,
                "metadata": metadata or {},
            }))

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
