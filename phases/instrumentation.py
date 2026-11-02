"""Instrumentation phase — manage Frida hooks for runtime analysis."""
from __future__ import annotations

import json
import subprocess
import shutil
import time
from pathlib import Path
from typing import Optional

from phases.base import Phase, PhaseResult, UserGate, GateType


_HOOK_SCRIPTS = {
    "ssl_bypass": {
        "file": "ssl_bypass.js",
        "display": "SSL Pinning Bypass",
        "description": "Bypass certificate pinning for MITM interception",
        "required": True,
        "platforms": {"android", "ios"},
    },
    "root_detect_bypass": {
        "file": "root_detect_bypass.js",
        "display": "Root/Jailbreak Detection Bypass",
        "description": "Bypass root and jailbreak detection checks",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "crypto_hooks": {
        "file": "crypto_hooks.js",
        "display": "Cryptographic Operations Monitor",
        "description": "Intercept and log encryption/decryption/hashing operations",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "auth_hooks": {
        "file": "auth_hooks.js",
        "display": "Authentication Flow Monitor",
        "description": "Intercept biometric, keychain, and credential operations",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "clipboard_monitor": {
        "file": "clipboard_monitor.js",
        "display": "Clipboard Monitor",
        "description": "Monitor clipboard read/write operations for data leakage",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "screenshot_check": {
        "file": "screenshot_check.js",
        "display": "Screenshot Protection Check",
        "description": "Detect whether the app prevents screenshots of sensitive screens",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "keychain_hooks": {
        "file": "keychain_hooks.js",
        "display": "Keychain/Keystore Monitor",
        "description": "Monitor secure storage read/write operations",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "webview_hooks": {
        "file": "webview_hooks.js",
        "display": "WebView Monitor",
        "description": "Intercept WebView URL loads, JavaScript bridges, and eval calls",
        "required": False,
        "platforms": {"android", "ios"},
    },
    "biometric_hooks": {
        "file": "biometric_hooks.js",
        "display": "Biometric Authentication Monitor",
        "description": "Monitor biometric auth prompts and bypass attempts",
        "required": False,
        "platforms": {"android", "ios"},
    },
}


class InstrumentationPhase(Phase):

    @property
    def name(self) -> str:
        return "instrumentation"

    @property
    def display_name(self) -> str:
        return "Frida Instrumentation"

    @property
    def description(self) -> str:
        return "Attach Frida hooks for runtime analysis of the target application"

    @property
    def order(self) -> int:
        return 800

    @property
    def requires_device(self) -> bool:
        return True

    @property
    def requires_root(self) -> bool:
        return True

    @property
    def requires_frida(self) -> bool:
        return True

    def pre_gates(self) -> list[UserGate]:
        return [UserGate(
            instruction=(
                "Launch the app on the device and navigate to the login "
                "screen. Press Done when the app is open and ready."),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=self._app_is_running,
            auto_detect_interval=3.0,
            auto_detect_timeout=120.0,
            prompt_id="instrumentation_app_ready",
        )]

    def _app_is_running(self) -> bool:
        if not self._device or not self.package:
            return False
        return self._device.is_app_running(self.package)

    def run(self) -> PhaseResult:
        self.status("Instrumentation", "running", "preparing Frida hooks")
        out = self.phase_dir()
        findings_count = 0

        pkg = self.package
        if not pkg:
            self.log("[instrumentation] No target package — skipping")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="no target package")

        self.status("Instrumentation", "running", "ensuring Frida server")
        if not self._device.ensure_frida_server():
            self.err("[instrumentation] Failed to start Frida server on device")
            return PhaseResult(phase_name=self.name, success=False,
                               error="Frida server not available")

        scripts_dir = self._locate_scripts_dir()
        if not scripts_dir:
            self.err("[instrumentation] Cannot locate frida_scripts/ directory")
            return PhaseResult(phase_name=self.name, success=False,
                               error="frida_scripts directory not found")

        platform = self.platform
        enabled_hooks = self._context.get("enabled_hooks", None)

        hooks_to_load: list[dict] = []
        for hook_id, meta in _HOOK_SCRIPTS.items():
            if platform and platform not in meta["platforms"]:
                continue
            if enabled_hooks is not None and hook_id not in enabled_hooks:
                if not meta["required"]:
                    continue
            script_path = scripts_dir / meta["file"]
            if not script_path.exists():
                self.log(f"[instrumentation] Script not found: {meta['file']} — skipping")
                continue
            hooks_to_load.append({
                "id": hook_id,
                "path": str(script_path),
                "display": meta["display"],
                "description": meta["description"],
            })

        self.log(f"[instrumentation] Loading {len(hooks_to_load)} Frida hook(s) for {pkg}")

        combined_script = self._build_combined_script(hooks_to_load, out)
        if not combined_script:
            self.log("[instrumentation] No scripts to load")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="no Frida scripts available")

        self.status("Instrumentation", "running", "attaching to target process")
        session_data = self._attach_and_load(pkg, combined_script, out)

        if session_data.get("ssl_bypass_active"):
            self._context["ssl_pinning_bypassed"] = True
            self.log("[instrumentation] SSL pinning bypass active")

        if session_data.get("root_bypass_active"):
            self._context["root_detection_bypassed"] = True
            self.log("[instrumentation] Root detection bypass active")

        if session_data.get("root_detection_found") and not session_data.get("root_bypass_active"):
            self.finding(
                title="Root/Jailbreak Detection Present",
                severity="INFO",
                catalogue_id="QUILL-INST-001",
                description=(
                    "The application implements root/jailbreak detection. "
                    "This was detected by Frida hooking known detection "
                    "methods. The detection was bypassed for testing."),
                output=session_data.get("root_detect_details", ""),
                affected=pkg,
                remediation="N/A — informational finding about detection presence.",
            )
            findings_count += 1

        if session_data.get("ssl_pinning_found"):
            self.finding(
                title="SSL Certificate Pinning Implemented",
                severity="INFO",
                catalogue_id="QUILL-INST-002",
                description=(
                    "The application implements SSL certificate pinning. "
                    "Pinning was bypassed via Frida for MITM analysis."),
                output=session_data.get("ssl_pin_details", ""),
                affected=pkg,
                remediation="N/A — informational finding. Pinning is a defense.",
            )
            findings_count += 1

        if session_data.get("no_screenshot_protection"):
            self.finding(
                title="Missing Screenshot Protection on Sensitive Screens",
                severity="MEDIUM",
                catalogue_id="QUILL-INST-003",
                description=(
                    "The application does not implement FLAG_SECURE (Android) "
                    "or screenshot prevention (iOS) on sensitive screens. "
                    "Sensitive data may appear in the recent-apps thumbnail "
                    "and can be captured via screenshots."),
                output=session_data.get("screenshot_details", ""),
                affected=pkg,
                remediation=(
                    "Set FLAG_SECURE on Activities displaying sensitive data "
                    "(Android). On iOS, overlay a blur or placeholder in "
                    "applicationWillResignActive. Prevent screenshots on "
                    "login, payment, and profile screens."),
            )
            findings_count += 1

        hook_log = session_data.get("hook_log", [])
        if hook_log:
            log_file = out / "frida_hook_log.json"
            log_file.write_text(json.dumps(hook_log, indent=2, default=str),
                                encoding="utf-8")

        self._context["frida_session"] = {
            "pid": session_data.get("pid", 0),
            "hooks_loaded": [h["id"] for h in hooks_to_load],
            "hook_count": len(hooks_to_load),
        }

        self.log(f"[instrumentation] Hooks loaded — {findings_count} finding(s)")
        return PhaseResult(phase_name=self.name, findings_count=findings_count,
                           data={"hooks_loaded": len(hooks_to_load)})

    def _locate_scripts_dir(self) -> Optional[Path]:
        candidates = [
            Path("/opt/pr0t31n/Quill/frida_scripts"),
            Path(__file__).resolve().parent.parent / "frida_scripts",
        ]
        quill_dir = self._context.get("quill_dir")
        if quill_dir:
            candidates.insert(0, Path(quill_dir) / "frida_scripts")
        for c in candidates:
            if c.is_dir():
                return c
        return None

    def _build_combined_script(self, hooks: list[dict], out: Path) -> Optional[Path]:
        if not hooks:
            return None
        parts: list[str] = [
            "// Quill combined Frida instrumentation script",
            "// Auto-generated — do not edit",
            f"// Hooks: {', '.join(h['id'] for h in hooks)}",
            "",
            "var _quill_log = [];",
            "function quill_emit(hook_id, event_type, data) {",
            "    var entry = {hook: hook_id, type: event_type, data: data, ts: Date.now()};",
            "    _quill_log.push(entry);",
            "    send({type: 'quill_hook', payload: entry});",
            "}",
            "",
        ]
        for h in hooks:
            try:
                script_text = Path(h["path"]).read_text(encoding="utf-8")
                parts.append(f"// ── {h['id']} ──────────────────────────────")
                parts.append(f"(function() {{ // {h['display']}")
                parts.append(script_text)
                parts.append(f"}})(); // end {h['id']}")
                parts.append("")
            except OSError as e:
                self.log(f"[instrumentation] Cannot read {h['path']}: {e}")

        combined = out / "combined_hooks.js"
        combined.write_text("\n".join(parts), encoding="utf-8")
        return combined

    def _attach_and_load(self, package: str, script_path: Path,
                         out: Path) -> dict:
        result = {
            "pid": 0,
            "ssl_bypass_active": False,
            "root_bypass_active": False,
            "ssl_pinning_found": False,
            "root_detection_found": False,
            "no_screenshot_protection": False,
            "hook_log": [],
        }

        frida_bin = shutil.which("frida")
        if not frida_bin:
            self.err("[instrumentation] frida CLI not found on host")
            return result

        cmd = [frida_bin, "-U", "-l", str(script_path), "-f", package,
               "-o", str(out / "frida_output.log")]

        self.log(f"[instrumentation] Spawning: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)

            self._context["_frida_proc"] = proc

            deadline = time.time() + 15
            lines_collected = []
            while time.time() < deadline and proc.poll() is None:
                import select
                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    lines_collected.append(line.strip())
                    ll = line.lower()
                    if "ssl" in ll and ("bypass" in ll or "unpin" in ll):
                        result["ssl_bypass_active"] = True
                        result["ssl_pinning_found"] = True
                    if "root" in ll and "bypass" in ll:
                        result["root_bypass_active"] = True
                        result["root_detection_found"] = True
                    if "screenshot" in ll and "no protection" in ll:
                        result["no_screenshot_protection"] = True

            if proc.poll() is not None and proc.returncode != 0:
                stderr = proc.stderr.read()
                self.err(f"[instrumentation] Frida exited with code {proc.returncode}: {stderr[:500]}")
            else:
                result["pid"] = proc.pid

        except Exception as e:
            self.err(f"[instrumentation] Failed to attach Frida: {e}")

        return result

    def teardown(self) -> None:
        proc = self._context.pop("_frida_proc", None)
        if proc and proc.poll() is None:
            self.log("[instrumentation] Terminating Frida session")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
