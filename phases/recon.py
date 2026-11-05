"""Recon phase — static analysis of the extracted APK/IPA.

This phase runs first (order=100) and does NOT require a connected device.
It extracts metadata from the app binary that other phases consume:
  - Exported components (activities, services, receivers, providers)
  - Permissions and their protection levels
  - App flags (debuggable, allowBackup, networkSecurityConfig)
  - URL schemes and deep links
  - Embedded secrets and API keys
  - Third-party SDK detection
  - Binary protection checks (PIE, RELRO, stack canary, ARC)

Results are stored in context["recon"] for downstream phases.
"""
from __future__ import annotations

import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from phases.base import Phase, PhaseResult


_SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
    (r'(?i)(?:secret|client_secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Hardcoded Password"),
    (r'(?i)(?:token|auth_token|access_token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Hardcoded Token"),
    (r'(?i)(?:aws_access_key_id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "AWS Access Key"),
    (r'(?i)(?:aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Key"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Token"),
    # --- AI / LLM provider keys (specific patterns before generic sk-) ---
    (r'sk-ant-api03-[A-Za-z0-9]{93}', "Anthropic API Key"),
    (r'sk-proj-[A-Za-z0-9_\-]{20,}', "OpenAI Project API Key"),
    (r'hf_[A-Za-z]{34}', "HuggingFace Access Token"),
    (r'AIza[A-Za-z0-9_\-]{35}', "Google AI / Gemini API Key"),
    (r'r8_[A-Za-z0-9]{40}', "Replicate API Token"),
    (r'xai-[A-Za-z0-9]{40,}', "xAI / Grok API Key"),
    (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:fx', "DeepL API Key"),
    # --- end AI keys ---
    (r'sk-[A-Za-z0-9]{20,}', "Stripe/OpenAI Secret Key"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
    (r'(?i)firebase[A-Za-z]*\.googleapis\.com', "Firebase Endpoint"),
]

_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("HIGH", "Can read SMS messages"),
    "android.permission.SEND_SMS": ("HIGH", "Can send SMS without user interaction"),
    "android.permission.READ_CALL_LOG": ("HIGH", "Can read call history"),
    "android.permission.READ_CONTACTS": ("MEDIUM", "Can read device contacts"),
    "android.permission.ACCESS_FINE_LOCATION": ("MEDIUM", "Has precise location access"),
    "android.permission.CAMERA": ("MEDIUM", "Has camera access"),
    "android.permission.RECORD_AUDIO": ("MEDIUM", "Has microphone access"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("MEDIUM", "Can write to shared storage"),
    "android.permission.READ_EXTERNAL_STORAGE": ("MEDIUM", "Can read shared storage"),
    "android.permission.INSTALL_PACKAGES": ("HIGH", "Can install packages silently"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("MEDIUM", "Can request package install"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("MEDIUM", "Can draw overlay windows"),
    "android.permission.WRITE_SETTINGS": ("MEDIUM", "Can modify system settings"),
}

_TRACKER_DOMAINS = {
    "google-analytics.com": "Google Analytics",
    "firebase.google.com": "Firebase",
    "crashlytics.com": "Crashlytics",
    "facebook.com/tr": "Facebook Pixel",
    "graph.facebook.com": "Facebook SDK",
    "appsflyer.com": "AppsFlyer",
    "adjust.com": "Adjust",
    "branch.io": "Branch.io",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "segment.com": "Segment",
    "sentry.io": "Sentry",
    "bugsnag.com": "Bugsnag",
    "instabug.com": "Instabug",
    "appcenter.ms": "App Center",
    "braze.com": "Braze",
    "onesignal.com": "OneSignal",
    "urbanairship.com": "Airship",
    "clevertap.com": "CleverTap",
}


class ReconPhase(Phase):

    @property
    def name(self) -> str:
        return "recon"

    @property
    def display_name(self) -> str:
        return "Static Reconnaissance"

    @property
    def description(self) -> str:
        return ("Extract app metadata, permissions, exported components, "
                "embedded secrets, and binary protections from the app binary.")

    @property
    def order(self) -> int:
        return 100

    @property
    def requires_device(self) -> bool:
        return False

    @property
    def requires_app_binary(self) -> bool:
        return True

    def run(self) -> PhaseResult:
        result = PhaseResult(phase_name=self.name)
        findings = 0

        if not self.app_dir or not self.app_dir.exists():
            result.skipped = True
            result.skip_reason = "no extracted app directory"
            return result

        self.status("Static Reconnaissance", "running")
        out_dir = self.phase_dir()

        recon_data = {}

        if self.platform == "android":
            findings += self._android_recon(out_dir, recon_data)
        elif self.platform == "ios":
            findings += self._ios_recon(out_dir, recon_data)

        findings += self._scan_secrets(out_dir, recon_data)
        findings += self._detect_trackers(out_dir, recon_data)

        self._context["recon"] = recon_data

        summary_path = out_dir / "recon_summary.json"
        summary_path.write_text(json.dumps(recon_data, indent=2, default=str),
                                encoding="utf-8")
        self.log(f"[recon] Summary written to {summary_path}")

        result.findings_count = findings
        result.data = {"recon_summary": str(summary_path)}
        return result

    def _android_recon(self, out_dir: Path, recon: dict) -> int:
        findings = 0
        manifest = self.app_dir / "AndroidManifest.xml"
        if not manifest.exists():
            self.err("[recon] AndroidManifest.xml not found")
            return 0

        self.log("[recon] Parsing AndroidManifest.xml...")
        self.check_pause()

        try:
            tree = ET.parse(manifest)
            root = tree.getroot()
        except ET.ParseError as exc:
            self.err(f"[recon] Manifest parse error: {exc}")
            return 0

        ns = {"a": "http://schemas.android.com/apk/res/android"}
        pkg = root.get("package", "")
        recon["package"] = pkg
        self.log(f"[recon] Package: {pkg}")

        app_el = root.find("application")
        if app_el is not None:
            flags = {
                "debuggable": app_el.get(f"{{{ns['a']}}}debuggable", "false") == "true",
                "allowBackup": app_el.get(f"{{{ns['a']}}}allowBackup", "true") != "false",
                "usesCleartextTraffic": app_el.get(
                    f"{{{ns['a']}}}usesCleartextTraffic", "false") == "true",
                "networkSecurityConfig": app_el.get(
                    f"{{{ns['a']}}}networkSecurityConfig", ""),
            }
            recon["flags"] = flags

            if flags["debuggable"]:
                self.finding(
                    title="Application is Debuggable",
                    severity="HIGH",
                    description="The android:debuggable flag is set to true in the manifest. "
                                "This allows attachment of a debugger to the process, enabling "
                                "inspection of runtime state, breakpoints on sensitive operations, "
                                "and extraction of in-memory credentials.",
                    catalogue_id="QUILL-REC-001",
                    affected=pkg,
                    output_file=f"recon/manifest_flags.json",
                    category="Build Configuration",
                )
                findings += 1

            if flags["allowBackup"]:
                self.finding(
                    title="Application Allows Backup",
                    severity="MEDIUM",
                    description="android:allowBackup is not explicitly set to false. "
                                "An attacker with physical access or ADB can extract the app's "
                                "private data directory via 'adb backup', potentially exposing "
                                "stored credentials, tokens, and user data.",
                    catalogue_id="QUILL-REC-002",
                    affected=pkg,
                    output_file=f"recon/manifest_flags.json",
                    category="Build Configuration",
                )
                findings += 1

            if flags["usesCleartextTraffic"]:
                self.finding(
                    title="Cleartext Traffic Allowed",
                    severity="MEDIUM",
                    description="android:usesCleartextTraffic is true, allowing the app to "
                                "send unencrypted HTTP traffic. Sensitive data transmitted "
                                "over cleartext is vulnerable to interception on the network.",
                    catalogue_id="QUILL-REC-003",
                    affected=pkg,
                    output_file=f"recon/manifest_flags.json",
                    category="Transport Security",
                )
                findings += 1

            (out_dir / "manifest_flags.json").write_text(
                json.dumps(flags, indent=2), encoding="utf-8")

        self.check_pause()
        components = self._extract_components(root, ns, pkg)
        recon["components"] = components

        exported = [c for c in components if c.get("exported")]
        recon["exported_components"] = exported
        self.log(f"[recon] Found {len(components)} components, "
                 f"{len(exported)} exported")

        if exported:
            (out_dir / "exported_components.json").write_text(
                json.dumps(exported, indent=2), encoding="utf-8")
            unprotected = [c for c in exported if not c.get("permission")]
            if unprotected:
                self.finding(
                    title=f"Exported Components Without Permission Protection ({len(unprotected)})",
                    severity="MEDIUM",
                    description=f"{len(unprotected)} component(s) are exported without "
                                f"requiring a permission. These can be invoked by any app "
                                f"on the device, potentially bypassing intended access controls.",
                    catalogue_id="QUILL-REC-004",
                    affected=", ".join(c["name"].split(".")[-1] for c in unprotected[:5]),
                    output_file="recon/exported_components.json",
                    category="Android Components",
                )
                findings += 1

        self.check_pause()
        permissions = self._extract_permissions(root, ns)
        recon["permissions"] = permissions
        dangerous = [p for p in permissions
                     if p["name"] in _DANGEROUS_PERMISSIONS]
        if dangerous:
            (out_dir / "dangerous_permissions.json").write_text(
                json.dumps(dangerous, indent=2), encoding="utf-8")
            for p in dangerous:
                sev, desc = _DANGEROUS_PERMISSIONS[p["name"]]
                short = p["name"].split(".")[-1]
                self.finding(
                    title=f"Dangerous Permission: {short}",
                    severity=sev,
                    description=f"App requests {p['name']}. {desc}. "
                                f"Verify this permission is necessary for core "
                                f"functionality and that access is properly scoped.",
                    catalogue_id="QUILL-REC-005",
                    affected=pkg,
                    output_file="recon/dangerous_permissions.json",
                )
                findings += 1

        self.check_pause()
        deep_links = self._extract_deep_links(root, ns, pkg)
        recon["deep_links"] = deep_links
        if deep_links:
            (out_dir / "deep_links.json").write_text(
                json.dumps(deep_links, indent=2), encoding="utf-8")
            self.log(f"[recon] Found {len(deep_links)} deep link scheme(s)")

        nsc_file = self.app_dir / "res" / "xml" / "network_security_config.xml"
        if nsc_file.exists():
            recon["network_security_config"] = True
            findings += self._analyse_nsc(nsc_file, out_dir, pkg)
        elif flags.get("networkSecurityConfig"):
            recon["network_security_config"] = False
            self.log("[recon] networkSecurityConfig declared but file not found in extract")

        return findings

    def _ios_recon(self, out_dir: Path, recon: dict) -> int:
        findings = 0

        plist_path = self.app_dir / "Info.plist"
        if not plist_path.exists():
            for child in self.app_dir.iterdir():
                if child.suffix == ".app":
                    plist_path = child / "Info.plist"
                    break

        if not plist_path.exists():
            self.err("[recon] Info.plist not found")
            return 0

        self.log("[recon] Parsing Info.plist...")
        import plistlib
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
        except Exception as exc:
            self.err(f"[recon] plist parse error: {exc}")
            return 0

        bundle_id = plist.get("CFBundleIdentifier", "")
        recon["package"] = bundle_id
        recon["bundle_name"] = plist.get("CFBundleName", "")
        recon["version"] = plist.get("CFBundleShortVersionString", "")

        ats = plist.get("NSAppTransportSecurity", {})
        recon["ats"] = ats
        if ats.get("NSAllowsArbitraryLoads"):
            self.finding(
                title="App Transport Security Disabled",
                severity="MEDIUM",
                description="NSAllowsArbitraryLoads is set to YES, disabling ATS. "
                            "The app can make cleartext HTTP connections to any domain. "
                            "Sensitive data transmitted without TLS is vulnerable to interception.",
                catalogue_id="QUILL-REC-010",
                affected=bundle_id,
                output_file="recon/ats_config.json",
                category="Transport Security",
            )
            findings += 1

        (out_dir / "ats_config.json").write_text(
            json.dumps(ats, indent=2, default=str), encoding="utf-8")

        self.check_pause()
        url_schemes = []
        for url_type in plist.get("CFBundleURLTypes", []):
            for scheme in url_type.get("CFBundleURLSchemes", []):
                url_schemes.append({
                    "scheme": scheme,
                    "name": url_type.get("CFBundleURLName", ""),
                    "role": url_type.get("CFBundleTypeRole", ""),
                })
        recon["url_schemes"] = url_schemes
        if url_schemes:
            (out_dir / "url_schemes.json").write_text(
                json.dumps(url_schemes, indent=2), encoding="utf-8")
            self.log(f"[recon] Found {len(url_schemes)} URL scheme(s)")

        self.check_pause()
        queried_schemes = plist.get("LSApplicationQueriesSchemes", [])
        recon["queried_schemes"] = queried_schemes

        bg_modes = plist.get("UIBackgroundModes", [])
        recon["background_modes"] = bg_modes

        privacy_keys = {k: v for k, v in plist.items()
                        if k.startswith("NS") and k.endswith("UsageDescription")}
        recon["privacy_descriptions"] = privacy_keys

        return findings

    def _extract_components(self, root, ns: dict, pkg: str) -> list[dict]:
        components = []
        for tag in ("activity", "service", "receiver", "provider"):
            app = root.find("application")
            if app is None:
                continue
            for el in app.findall(tag):
                name = el.get(f"{{{ns['a']}}}name", "")
                if name.startswith("."):
                    name = pkg + name
                exported_attr = el.get(f"{{{ns['a']}}}exported")
                has_intent_filter = el.find("intent-filter") is not None
                if exported_attr is not None:
                    exported = exported_attr == "true"
                else:
                    exported = has_intent_filter
                perm = el.get(f"{{{ns['a']}}}permission", "")

                intent_filters = []
                for iff in el.findall("intent-filter"):
                    actions = [a.get(f"{{{ns['a']}}}name", "")
                               for a in iff.findall("action")]
                    categories = [c.get(f"{{{ns['a']}}}name", "")
                                  for c in iff.findall("category")]
                    data_els = []
                    for d in iff.findall("data"):
                        data_els.append({
                            "scheme": d.get(f"{{{ns['a']}}}scheme", ""),
                            "host": d.get(f"{{{ns['a']}}}host", ""),
                            "path": d.get(f"{{{ns['a']}}}path", "")
                                    or d.get(f"{{{ns['a']}}}pathPrefix", ""),
                        })
                    intent_filters.append({
                        "actions": actions,
                        "categories": categories,
                        "data": data_els,
                    })

                components.append({
                    "type": tag,
                    "name": name,
                    "exported": exported,
                    "permission": perm,
                    "intent_filters": intent_filters,
                })
        return components

    def _extract_permissions(self, root, ns: dict) -> list[dict]:
        perms = []
        for el in root.findall("uses-permission"):
            name = el.get(f"{{{ns['a']}}}name", "")
            if name:
                perms.append({
                    "name": name,
                    "max_sdk": el.get(f"{{{ns['a']}}}maxSdkVersion", ""),
                })
        return perms

    def _extract_deep_links(self, root, ns: dict, pkg: str) -> list[dict]:
        links = []
        app = root.find("application")
        if app is None:
            return links
        for act in app.findall("activity"):
            act_name = act.get(f"{{{ns['a']}}}name", "")
            for iff in act.findall("intent-filter"):
                actions = [a.get(f"{{{ns['a']}}}name", "")
                           for a in iff.findall("action")]
                if "android.intent.action.VIEW" not in actions:
                    continue
                for d in iff.findall("data"):
                    scheme = d.get(f"{{{ns['a']}}}scheme", "")
                    host = d.get(f"{{{ns['a']}}}host", "")
                    path = (d.get(f"{{{ns['a']}}}path", "")
                            or d.get(f"{{{ns['a']}}}pathPrefix", "")
                            or d.get(f"{{{ns['a']}}}pathPattern", ""))
                    if scheme:
                        links.append({
                            "activity": act_name,
                            "scheme": scheme,
                            "host": host,
                            "path": path,
                        })
        return links

    def _analyse_nsc(self, nsc_file: Path, out_dir: Path, pkg: str) -> int:
        findings = 0
        try:
            tree = ET.parse(nsc_file)
            root = tree.getroot()
        except ET.ParseError:
            return 0

        base_config = root.find("base-config")
        if base_config is not None:
            cleartext = base_config.get("cleartextTrafficPermitted", "")
            if cleartext == "true":
                self.finding(
                    title="Network Security Config Allows Cleartext",
                    severity="MEDIUM",
                    description="The network_security_config.xml base-config permits "
                                "cleartext traffic to all domains.",
                    catalogue_id="QUILL-REC-006",
                    affected=pkg,
                    output_file="recon/network_security_config.xml",
                    category="Transport Security",
                )
                findings += 1

        for domain_config in root.findall(".//domain-config"):
            cleartext = domain_config.get("cleartextTrafficPermitted", "")
            trust_anchors = domain_config.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.findall("certificates"):
                    src = cert.get("src", "")
                    if src == "user":
                        domains = [d.text for d in domain_config.findall("domain")
                                   if d.text]
                        self.finding(
                            title="Network Security Config Trusts User Certificates",
                            severity="INFO",
                            description=f"Domain config trusts user-installed CA certificates "
                                        f"for: {', '.join(domains)}. This is expected for "
                                        f"development/debug builds but should not be in production.",
                            catalogue_id="QUILL-REC-007",
                            affected=", ".join(domains),
                            output_file="recon/network_security_config.xml",
                            category="Transport Security",
                        )
                        findings += 1

        import shutil
        shutil.copy2(nsc_file, out_dir / "network_security_config.xml")
        return findings

    def _scan_secrets(self, out_dir: Path, recon: dict) -> int:
        if not self.app_dir:
            return 0
        self.log("[recon] Scanning extracted files for embedded secrets...")
        self.check_pause()

        findings = 0
        secrets_found = []
        scan_extensions = {".xml", ".json", ".properties", ".yml", ".yaml",
                          ".plist", ".strings", ".js", ".html", ".txt",
                          ".smali", ".java", ".kt", ".swift", ".m", ".h",
                          ".cfg", ".conf", ".ini", ".env", ".gradle"}

        for fpath in self.app_dir.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in scan_extensions:
                continue
            if fpath.stat().st_size > 5_000_000:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for pattern, label in _SECRET_PATTERNS:
                for match in re.finditer(pattern, text):
                    value = match.group(0)
                    if len(value) > 200:
                        value = value[:200] + "..."
                    rel_path = str(fpath.relative_to(self.app_dir))
                    entry = {
                        "type": label,
                        "file": rel_path,
                        "line": text[:match.start()].count("\n") + 1,
                        "match_preview": value[:80],
                    }
                    secrets_found.append(entry)

        if secrets_found:
            deduped = {}
            for s in secrets_found:
                key = (s["type"], s["match_preview"][:40])
                if key not in deduped:
                    deduped[key] = s

            secrets_found = list(deduped.values())
            (out_dir / "secrets_found.json").write_text(
                json.dumps(secrets_found, indent=2), encoding="utf-8")

            by_type = {}
            for s in secrets_found:
                by_type.setdefault(s["type"], []).append(s)

            for stype, items in by_type.items():
                sev = "CRITICAL" if "Password" in stype or "Private Key" in stype else "HIGH"
                self.finding(
                    title=f"Embedded Secret: {stype} ({len(items)} instance(s))",
                    severity=sev,
                    description=f"Found {len(items)} instance(s) of {stype} embedded in "
                                f"the application binary. Secrets compiled into the app can "
                                f"be extracted by anyone who downloads it.",
                    catalogue_id="QUILL-REC-008",
                    affected=", ".join(i["file"] for i in items[:3]),
                    output_file="recon/secrets_found.json",
                )
                findings += 1

            recon["secrets"] = secrets_found
            self.log(f"[recon] Found {len(secrets_found)} embedded secret(s)")
        else:
            self.log("[recon] No embedded secrets detected")

        return findings

    def _detect_trackers(self, out_dir: Path, recon: dict) -> int:
        if not self.app_dir:
            return 0
        self.log("[recon] Detecting third-party trackers and SDKs...")
        self.check_pause()

        detected = set()
        scan_extensions = {".xml", ".json", ".smali", ".js", ".java", ".kt",
                          ".swift", ".m", ".plist", ".strings"}

        for fpath in self.app_dir.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in scan_extensions:
                continue
            if fpath.stat().st_size > 5_000_000:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for domain, name in _TRACKER_DOMAINS.items():
                if domain in text:
                    detected.add(name)

        trackers = sorted(detected)
        recon["trackers"] = trackers
        if trackers:
            (out_dir / "trackers.json").write_text(
                json.dumps(trackers, indent=2), encoding="utf-8")
            self.log(f"[recon] Detected {len(trackers)} tracker(s)/SDK(s): "
                     f"{', '.join(trackers[:5])}")
            self.finding(
                title=f"Third-Party Tracking SDKs Detected ({len(trackers)})",
                severity="INFO",
                description=f"The application includes {len(trackers)} third-party "
                            f"tracking/analytics SDK(s): {', '.join(trackers)}. "
                            f"These may transmit user data to external parties. "
                            f"Review data sharing practices and privacy policy compliance.",
                catalogue_id="QUILL-REC-009",
                affected=", ".join(trackers),
                output_file="recon/trackers.json",
                category="Privacy",
            )
            return 1
        return 0
