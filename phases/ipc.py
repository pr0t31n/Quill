"""IPC Testing phase — test inter-process communication attack surface."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional

from phases.base import GateType, Phase, PhaseResult, UserGate


_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1",
    "'; DROP TABLE --",
    "1' UNION SELECT 1,2,3--",
    "\" OR \"\"=\"",
]

_DEEPLINK_FUZZ_PAYLOADS = [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "../../../etc/passwd",
    "%00",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${7*7}",
    "https://evil.com",
]


class IPCPhase(Phase):

    @property
    def name(self) -> str:
        return "ipc"

    @property
    def display_name(self) -> str:
        return "IPC Testing"

    @property
    def description(self) -> str:
        return ("Test inter-process communication attack surface: exported "
                "components, content providers, intent injection, deep links, "
                "URL schemes, and pasteboard data leaks.")

    @property
    def order(self) -> int:
        return 400

    @property
    def requires_device(self) -> bool:
        return True

    @property
    def requires_root(self) -> bool:
        return True

    def pre_gates(self) -> list[UserGate]:
        return [UserGate(
            instruction=(
                "Ensure the app is installed and running on the device. "
                "Navigate past any onboarding screens so the main UI is visible."
            ),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=lambda: self._device and self._device.is_app_running(self.package),
            auto_detect_interval=5.0,
            auto_detect_timeout=300.0,
            prompt_id="ipc_app_running",
        )]

    def run(self) -> PhaseResult:
        result = PhaseResult(phase_name=self.name)
        findings = 0
        out_dir = self.phase_dir()

        self.status("IPC Testing", "running")

        if self.platform == "android":
            findings += self._test_android_ipc(out_dir)
        elif self.platform == "ios":
            findings += self._test_ios_ipc(out_dir)

        result.findings_count = findings
        return result

    # ── Android IPC ──────────────────────────────────────────────────────

    def _test_android_ipc(self, out_dir: Path) -> int:
        findings = 0

        self.status("IPC Testing", "running", "exported components")
        findings += self._test_exported_components(out_dir)
        self.check_pause()

        self.status("IPC Testing", "running", "content providers")
        findings += self._test_content_providers(out_dir)
        self.check_pause()

        self.status("IPC Testing", "running", "broadcast receivers")
        findings += self._test_broadcast_receivers(out_dir)
        self.check_pause()

        self.status("IPC Testing", "running", "deep links")
        findings += self._test_deep_links(out_dir)
        self.check_pause()

        return findings

    def _test_exported_components(self, out_dir: Path) -> int:
        findings = 0
        recon = self._context.get("recon", {})
        exported = recon.get("exported_components", [])
        if not exported:
            self.log("[ipc] No exported components from recon — querying dumpsys")
            rc, dumpsys_out, _ = self._device.shell(
                f"dumpsys package {self.package}", root=False, timeout=15)
            if rc == 0:
                (out_dir / "dumpsys_package.txt").write_text(
                    dumpsys_out, encoding="utf-8")
            return 0

        unprotected_activities = []
        unprotected_services = []

        for comp in exported:
            ctype = comp.get("type", "")
            cname = comp.get("name", "")
            perm = comp.get("permission", "")

            if perm:
                continue

            if ctype == "activity":
                unprotected_activities.append(cname)
                self.log(f"[ipc] Testing exported activity: {cname}")
                rc, out, err = self._device.shell(
                    f"am start -n {self.package}/{cname}",
                    root=False, timeout=10)
                ev_file = out_dir / f"activity_{cname.split('.')[-1]}.txt"
                ev_file.write_text(
                    f"Command: am start -n {self.package}/{cname}\n"
                    f"Exit: {rc}\nStdout:\n{out}\nStderr:\n{err}",
                    encoding="utf-8")

            elif ctype == "service":
                unprotected_services.append(cname)
                self.log(f"[ipc] Testing exported service: {cname}")
                rc, out, err = self._device.shell(
                    f"am startservice -n {self.package}/{cname}",
                    root=False, timeout=10)
                ev_file = out_dir / f"service_{cname.split('.')[-1]}.txt"
                ev_file.write_text(
                    f"Command: am startservice -n {self.package}/{cname}\n"
                    f"Exit: {rc}\nStdout:\n{out}\nStderr:\n{err}",
                    encoding="utf-8")

        if unprotected_activities:
            ev_file = out_dir / "unprotected_activities.json"
            ev_file.write_text(json.dumps(unprotected_activities, indent=2),
                               encoding="utf-8")
            self.finding(
                title=f"Exported Activities Without Permission ({len(unprotected_activities)})",
                severity="MEDIUM",
                description=(
                    f"{len(unprotected_activities)} activity component(s) are exported "
                    f"without requiring a permission. Any app can launch them, potentially "
                    f"bypassing authentication or accessing restricted functionality."
                ),
                catalogue_id="QUILL-IPC-001",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=", ".join(a.split(".")[-1] for a in unprotected_activities[:5]),
            )
            findings += 1

        if unprotected_services:
            ev_file = out_dir / "unprotected_services.json"
            ev_file.write_text(json.dumps(unprotected_services, indent=2),
                               encoding="utf-8")
            self.finding(
                title=f"Exported Services Without Permission ({len(unprotected_services)})",
                severity="MEDIUM",
                description=(
                    f"{len(unprotected_services)} service component(s) are exported "
                    f"without requiring a permission. Any app can bind to or start "
                    f"them, potentially triggering privileged operations."
                ),
                catalogue_id="QUILL-IPC-002",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=", ".join(s.split(".")[-1] for s in unprotected_services[:5]),
            )
            findings += 1

        return findings

    def _test_content_providers(self, out_dir: Path) -> int:
        findings = 0
        recon = self._context.get("recon", {})
        components = recon.get("components", [])
        providers = [c for c in components
                     if c.get("type") == "provider" and c.get("exported")]

        if not providers:
            self.log("[ipc] No exported content providers found")
            return 0

        for prov in providers:
            pname = prov.get("name", "")
            perm = prov.get("permission", "")
            short = pname.split(".")[-1]
            self.log(f"[ipc] Testing content provider: {short}")

            authority = short.lower()
            uri = f"content://{self.package}.{authority}/"

            rc, out, err = self._device.shell(
                f"content query --uri {uri}", root=False, timeout=10)
            ev_file = out_dir / f"provider_{short}.txt"
            ev_text = f"Provider: {pname}\nPermission: {perm or 'NONE'}\n"
            ev_text += f"URI: {uri}\n\nQuery result:\n{out}\n"

            accessible = rc == 0 and "Error" not in out and out.strip()

            if accessible and not perm:
                self.finding(
                    title=f"Unprotected Content Provider: {short}",
                    severity="HIGH",
                    description=(
                        f"Content provider {pname} is exported without permission "
                        f"protection and responds to queries. Any app can read its "
                        f"data, which may include user records, credentials, or "
                        f"internal application state."
                    ),
                    catalogue_id="QUILL-IPC-003",
                    output_file=str(ev_file.relative_to(self._output_dir)),
                    affected=pname,
                )
                findings += 1

            if accessible:
                sqli_results = self._test_provider_sqli(uri, short, out_dir)
                findings += sqli_results

            ev_file.write_text(ev_text, encoding="utf-8")

        return findings

    def _test_provider_sqli(self, base_uri: str, short_name: str,
                            out_dir: Path) -> int:
        findings = 0
        sqli_hits = []

        for payload in _SQLI_PAYLOADS:
            rc, out, err = self._device.shell(
                f"content query --uri {base_uri} --where \"{payload}\"",
                root=False, timeout=10)
            if rc == 0 and out.strip() and "Error" not in out:
                sqli_hits.append({
                    "payload": payload,
                    "response_preview": out[:500],
                })

        if sqli_hits:
            ev_file = out_dir / f"sqli_{short_name}.json"
            ev_file.write_text(json.dumps(sqli_hits, indent=2), encoding="utf-8")
            self.finding(
                title=f"SQL Injection in Content Provider: {short_name}",
                severity="CRITICAL",
                description=(
                    f"Content provider at {base_uri} is vulnerable to SQL "
                    f"injection. {len(sqli_hits)} payload(s) returned data "
                    f"instead of an error. An attacker can extract or modify "
                    f"all data stored by the provider."
                ),
                catalogue_id="QUILL-IPC-004",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=base_uri,
            )
            findings += 1

        return findings

    def _test_broadcast_receivers(self, out_dir: Path) -> int:
        findings = 0
        recon = self._context.get("recon", {})
        components = recon.get("components", [])
        receivers = [c for c in components
                     if c.get("type") == "receiver" and c.get("exported")
                     and not c.get("permission")]

        if not receivers:
            self.log("[ipc] No unprotected exported broadcast receivers")
            return 0

        injectable = []
        for recv in receivers:
            rname = recv.get("name", "")
            short = rname.split(".")[-1]
            self.log(f"[ipc] Testing broadcast receiver: {short}")

            for iff in recv.get("intent_filters", []):
                for action in iff.get("actions", []):
                    rc, out, err = self._device.shell(
                        f"am broadcast -a {action} -n {self.package}/{rname}",
                        root=False, timeout=10)
                    ev_file = out_dir / f"broadcast_{short}.txt"
                    ev_file.write_text(
                        f"Receiver: {rname}\nAction: {action}\n"
                        f"Exit: {rc}\nStdout:\n{out}\nStderr:\n{err}",
                        encoding="utf-8")
                    if rc == 0 and "Error" not in out:
                        injectable.append({"receiver": rname, "action": action})

        if injectable:
            ev_file = out_dir / "injectable_receivers.json"
            ev_file.write_text(json.dumps(injectable, indent=2), encoding="utf-8")
            self.finding(
                title=f"Injectable Broadcast Receivers ({len(injectable)})",
                severity="MEDIUM",
                description=(
                    f"{len(injectable)} broadcast receiver action(s) accepted "
                    f"intents from an unprivileged caller. Malicious apps can "
                    f"trigger these receivers to manipulate app behavior, "
                    f"bypass controls, or exfiltrate data via crafted extras."
                ),
                catalogue_id="QUILL-IPC-005",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=", ".join(i["receiver"].split(".")[-1]
                                   for i in injectable[:5]),
            )
            findings += 1

        return findings

    def _test_deep_links(self, out_dir: Path) -> int:
        findings = 0
        recon = self._context.get("recon", {})
        deep_links = recon.get("deep_links", [])

        if not deep_links:
            self.log("[ipc] No deep links found in manifest")
            return 0

        self.log(f"[ipc] Testing {len(deep_links)} deep link scheme(s)...")
        hijackable = []
        fuzz_hits = []

        for dl in deep_links:
            scheme = dl.get("scheme", "")
            host = dl.get("host", "")
            path = dl.get("path", "")
            activity = dl.get("activity", "")

            if not scheme:
                continue

            base_url = f"{scheme}://{host}{path}" if host else f"{scheme}://"

            rc, out, err = self._device.shell(
                f"am start -a android.intent.action.VIEW -d \"{base_url}\"",
                root=False, timeout=10)

            if scheme not in ("http", "https"):
                hijackable.append({
                    "scheme": scheme, "host": host, "path": path,
                    "activity": activity,
                })

            for payload in _DEEPLINK_FUZZ_PAYLOADS:
                fuzz_url = f"{base_url}{payload}"
                rc, out, err = self._device.shell(
                    f"am start -a android.intent.action.VIEW -d \"{fuzz_url}\"",
                    root=False, timeout=5)
                if rc == 0 and "Error" not in out:
                    fuzz_hits.append({
                        "url": fuzz_url,
                        "payload": payload,
                        "response": out[:300],
                    })

        if hijackable:
            ev_file = out_dir / "deep_link_schemes.json"
            ev_file.write_text(json.dumps(hijackable, indent=2), encoding="utf-8")
            self.finding(
                title=f"Custom URL Scheme Deep Links ({len(hijackable)})",
                severity="MEDIUM",
                description=(
                    f"{len(hijackable)} custom URL scheme(s) registered by the app "
                    f"({', '.join(h['scheme'] for h in hijackable[:5])}). Custom "
                    f"schemes can be hijacked by a malicious app registering the "
                    f"same scheme, intercepting sensitive data passed via deep links."
                ),
                catalogue_id="QUILL-IPC-006",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=", ".join(h["scheme"] for h in hijackable[:5]),
            )
            findings += 1

        if fuzz_hits:
            ev_file = out_dir / "deep_link_fuzz.json"
            ev_file.write_text(json.dumps(fuzz_hits, indent=2), encoding="utf-8")
            self.finding(
                title=f"Deep Link Input Validation Issues ({len(fuzz_hits)})",
                severity="HIGH",
                description=(
                    f"{len(fuzz_hits)} deep link fuzz payload(s) were accepted "
                    f"without error. The app may be vulnerable to injection "
                    f"attacks (XSS, path traversal, SSRF) via crafted deep links."
                ),
                catalogue_id="QUILL-IPC-007",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected="deep link handlers",
            )
            findings += 1

        return findings

    # ── iOS IPC ──────────────────────────────────────────────────────────

    def _test_ios_ipc(self, out_dir: Path) -> int:
        findings = 0

        self.status("IPC Testing", "running", "URL schemes")
        findings += self._test_ios_url_schemes(out_dir)
        self.check_pause()

        self.status("IPC Testing", "running", "pasteboard")
        findings += self._test_ios_pasteboard(out_dir)
        self.check_pause()

        self.status("IPC Testing", "running", "app extensions")
        findings += self._test_ios_extensions(out_dir)
        self.check_pause()

        return findings

    def _test_ios_url_schemes(self, out_dir: Path) -> int:
        findings = 0
        recon = self._context.get("recon", {})
        url_schemes = recon.get("url_schemes", [])

        if not url_schemes:
            self.log("[ipc] No URL schemes found in Info.plist")
            return 0

        self.log(f"[ipc] Testing {len(url_schemes)} URL scheme(s)...")
        tested = []

        for entry in url_schemes:
            scheme = entry.get("scheme", "")
            if not scheme:
                continue

            test_url = f"{scheme}://"
            rc, out, err = self._device.shell(
                f"uiopen {test_url}", root=False, timeout=10)
            tested.append({
                "scheme": scheme,
                "name": entry.get("name", ""),
                "test_url": test_url,
                "exit_code": rc,
                "output": out[:300],
            })

            for payload in _DEEPLINK_FUZZ_PAYLOADS:
                fuzz_url = f"{scheme}://{payload}"
                self._device.shell(
                    f"uiopen \"{fuzz_url}\"", root=False, timeout=5)

        if tested:
            ev_file = out_dir / "ios_url_schemes.json"
            ev_file.write_text(json.dumps(tested, indent=2), encoding="utf-8")
            self.finding(
                title=f"Custom URL Schemes ({len(tested)})",
                severity="MEDIUM",
                description=(
                    f"The app registers {len(tested)} custom URL scheme(s): "
                    f"{', '.join(t['scheme'] for t in tested[:5])}. On iOS, "
                    f"URL schemes are first-come-first-served and can be "
                    f"hijacked by a malicious app. Consider using Universal "
                    f"Links (Associated Domains) instead."
                ),
                catalogue_id="QUILL-IPC-008",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=", ".join(t["scheme"] for t in tested[:5]),
            )
            findings += 1

        return findings

    def _test_ios_pasteboard(self, out_dir: Path) -> int:
        findings = 0

        self.log("[ipc] Checking pasteboard for sensitive data...")
        clipboard = self._device.get_clipboard()

        if not clipboard:
            self.log("[ipc] Pasteboard is empty")
            return 0

        from phases.storage import _SENSITIVE_PATTERNS, _SENSITIVE_VALUES

        sensitive_in_pb = []
        for pat, label in _SENSITIVE_PATTERNS:
            if pat.search(clipboard):
                sensitive_in_pb.append(label)
        for vpat in _SENSITIVE_VALUES:
            if vpat.search(clipboard):
                sensitive_in_pb.append("token/key")
                break

        if sensitive_in_pb:
            ev_file = out_dir / "pasteboard_leak.txt"
            ev_file.write_text(
                f"Pasteboard content (after app use):\n"
                f"Length: {len(clipboard)} chars\n"
                f"Sensitive types detected: {', '.join(set(sensitive_in_pb))}\n"
                f"Preview: {clipboard[:200]}",
                encoding="utf-8")
            self.finding(
                title="Sensitive Data in Pasteboard",
                severity="HIGH",
                description=(
                    f"The device pasteboard contains sensitive data "
                    f"({', '.join(set(sensitive_in_pb))}) after app usage. "
                    f"Other apps can read the pasteboard, allowing cross-app "
                    f"data theft. The app should clear the pasteboard after "
                    f"copying sensitive data or use UIPasteboard with "
                    f"localOnly and expirationDate."
                ),
                catalogue_id="QUILL-IPC-009",
                output_file=str(ev_file.relative_to(self._output_dir)),
                affected=self.package,
            )
            findings += 1

        return findings

    def _test_ios_extensions(self, out_dir: Path) -> int:
        findings = 0
        if not self.app_dir:
            return 0

        plugins_dir = None
        for child in self.app_dir.rglob("PlugIns"):
            if child.is_dir():
                plugins_dir = child
                break
        if not plugins_dir:
            self.log("[ipc] No app extensions (PlugIns) found")
            return 0

        extensions = []
        for ext_dir in plugins_dir.iterdir():
            if ext_dir.suffix == ".appex" and ext_dir.is_dir():
                import plistlib
                ext_plist = ext_dir / "Info.plist"
                if ext_plist.exists():
                    try:
                        with open(ext_plist, "rb") as f:
                            plist = plistlib.load(f)
                        ext_info = plist.get("NSExtension", {})
                        extensions.append({
                            "name": ext_dir.stem,
                            "point": ext_info.get("NSExtensionPointIdentifier", ""),
                            "principal_class": ext_info.get("NSExtensionPrincipalClass", ""),
                        })
                    except Exception:
                        extensions.append({"name": ext_dir.stem, "point": "", "principal_class": ""})

        if extensions:
            ev_file = out_dir / "ios_extensions.json"
            ev_file.write_text(json.dumps(extensions, indent=2), encoding="utf-8")
            self.log(f"[ipc] Found {len(extensions)} app extension(s)")

        return findings
