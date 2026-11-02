"""Resilience Testing phase — test app tamper resistance and runtime protections."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout
from pathlib import Path
from typing import Optional

from phases.base import GateType, Phase, PhaseResult, UserGate

FRIDA_OP_TIMEOUT = 30


class ResiliencePhase(Phase):

    @property
    def name(self) -> str:
        return "resilience"

    @property
    def display_name(self) -> str:
        return "Resilience Testing"

    @property
    def description(self) -> str:
        return ("Test app tamper resistance: root/jailbreak detection, SSL "
                "pinning, debugger protection, emulator detection, screenshot "
                "prevention, and clipboard security.")

    @property
    def order(self) -> int:
        return 700

    @property
    def requires_device(self) -> bool:
        return True

    @property
    def requires_frida(self) -> bool:
        return True

    def _frida_with_timeout(self, fn, label: str, timeout: int = FRIDA_OP_TIMEOUT):
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(fn)
        pool.shutdown(wait=False)
        try:
            return future.result(timeout=timeout)
        except _FuturesTimeout:
            if future.done():
                try:
                    exc = future.exception(timeout=0)
                except Exception as inner:
                    exc = inner
                self.err(f"[resilience] Frida operation failed ({label}): {exc}")
            else:
                self.err(f"[resilience] Frida operation timed out after {timeout}s: {label}")
            return None
        except Exception as exc:
            self.err(f"[resilience] Frida operation failed ({label}): {exc}")
            return None

    def pre_gates(self) -> list[UserGate]:
        return [UserGate(
            instruction=(
                "Launch the app on the device and navigate to the login "
                "or main screen. The app must be running and visible."
            ),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=lambda: self._device and self._device.is_app_running(self.package),
            auto_detect_interval=5.0,
            auto_detect_timeout=300.0,
            prompt_id="resilience_app_running",
        )]

    def run(self) -> PhaseResult:
        result = PhaseResult(phase_name=self.name)
        findings = 0
        out_dir = self.phase_dir()

        self.status("Resilience Testing", "running")

        self.status("Resilience Testing", "running", "root/jailbreak detection")
        findings += self._test_root_detection(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "SSL pinning")
        findings += self._test_ssl_pinning(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "debugger detection")
        findings += self._test_debugger_detection(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "emulator detection")
        findings += self._test_emulator_detection(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "screenshot prevention")
        findings += self._test_screenshot_prevention(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "clipboard security")
        findings += self._test_clipboard_security(out_dir)
        self.check_pause()

        self.status("Resilience Testing", "running", "code integrity")
        findings += self._test_code_integrity(out_dir)
        self.check_pause()

        result.findings_count = findings
        return result

    # ── root / jailbreak detection ───────────────────────────────────────

    def _test_root_detection(self, out_dir: Path) -> int:
        findings = 0

        if not self._device.is_rooted():
            self.log("[resilience] Device is not rooted — skipping root detection test")
            return 0

        self.log("[resilience] Device IS rooted — testing whether app detects it...")

        app_running_before = self._device.is_app_running(self.package)
        if not app_running_before:
            self._device.launch_app(self.package)
            time.sleep(3)

        app_still_running = self._device.is_app_running(self.package)
        app_crashed = not app_still_running and app_running_before

        ev_data = {
            "device_rooted": True,
            "root_method": self._device.get_root_method(),
            "app_running_after_launch": app_still_running,
            "app_crashed_on_root": app_crashed,
        }

        if app_still_running:
            self.finding(
                title="Missing Root/Jailbreak Detection",
                severity="MEDIUM",
                description=(
                    "The app runs without issue on a rooted/jailbroken device "
                    f"({self._device.get_root_method()}). It does not appear to "
                    "detect or respond to the compromised device state. A rooted "
                    "device enables an attacker to bypass OS sandboxing, read "
                    "app data, hook runtime methods, and intercept traffic."
                ),
                catalogue_id="QUILL-RES-001",
                output_file=str((out_dir / "root_detection.json").relative_to(self._output_dir)),
                affected=self.package,
            )
            findings += 1

            findings += self._test_root_bypass(out_dir, ev_data)
        else:
            self.log("[resilience] App appears to detect root (crashed or refused to run)")
            ev_data["detection_effective"] = True
            findings += self._test_root_bypass(out_dir, ev_data)

        (out_dir / "root_detection.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        return findings

    def _test_root_bypass(self, out_dir: Path, ev_data: dict) -> int:
        findings = 0
        frida_scripts = self._context.get("frida_scripts", {})
        root_bypass_script = frida_scripts.get("root_detect_bypass")

        if not root_bypass_script:
            self.log("[resilience] No root_detect_bypass Frida script available")
            return 0

        self.log("[resilience] Attempting root detection bypass via Frida...")

        self._device.kill_app(self.package)
        time.sleep(1)

        try:
            import frida

            def _do_root_bypass():
                device = frida.get_usb_device(timeout=5)
                pid = device.spawn([self.package])
                session = device.attach(pid)
                script = session.create_script(root_bypass_script)

                bypass_log = []

                def on_message(message, data):
                    if message.get("type") == "send":
                        bypass_log.append(message.get("payload", ""))

                script.on("message", on_message)
                script.load()
                device.resume(pid)
                time.sleep(5)
                session.detach()
                return bypass_log

            bypass_log = self._frida_with_timeout(_do_root_bypass, "root detection bypass")

            if bypass_log is None:
                ev_data["frida_bypass_error"] = "timeout"
                return findings

            app_running = self._device.is_app_running(self.package)

            ev_data["frida_bypass_attempted"] = True
            ev_data["frida_bypass_log"] = bypass_log
            ev_data["app_running_after_bypass"] = app_running

            if app_running and ev_data.get("detection_effective", False):
                (out_dir / "root_bypass_log.json").write_text(
                    json.dumps(bypass_log, indent=2), encoding="utf-8")
                self.finding(
                    title="Root/Jailbreak Detection Bypassable",
                    severity="HIGH",
                    description=(
                        "The app's root/jailbreak detection was bypassed using "
                        "Frida runtime hooks. The detection logic relies on "
                        "methods that can be intercepted (file existence checks, "
                        "system property reads). Implement multi-layered "
                        "detection with native code integrity checks."
                    ),
                    catalogue_id="QUILL-RES-002",
                    output_file=str((out_dir / "root_bypass_log.json").relative_to(self._output_dir)),
                    affected=self.package,
                )
                findings += 1
        except ImportError:
            self.err("[resilience] frida Python module not available")
        except Exception as exc:
            self.err(f"[resilience] Frida root bypass test failed: {exc}")
            ev_data["frida_bypass_error"] = str(exc)
        finally:
            try:
                self._device.kill_app(self.package)
            except Exception:
                pass
            try:
                self._device.launch_app(self.package)
                time.sleep(3)
            except Exception:
                pass

        return findings

    # ── SSL pinning ──────────────────────────────────────────────────────

    def _test_ssl_pinning(self, out_dir: Path) -> int:
        findings = 0
        frida_scripts = self._context.get("frida_scripts", {})
        ssl_bypass_script = frida_scripts.get("ssl_bypass")

        self.log("[resilience] Testing SSL certificate pinning...")

        try:
            import frida

            if not self._device.is_app_running(self.package):
                self._device.launch_app(self.package)
                time.sleep(3)

            def _do_ssl_pinning():
                device = frida.get_usb_device(timeout=5)
                pid = device.get_process(self.package).pid
                session = device.attach(pid)

                hook_log = []
                pin_detected = False

                if ssl_bypass_script:
                    script = session.create_script(ssl_bypass_script)

                    def on_message(message, data):
                        nonlocal pin_detected
                        if message.get("type") == "send":
                            payload = message.get("payload", "")
                            hook_log.append(payload)
                            if "pinning" in str(payload).lower() or "certificate" in str(payload).lower():
                                pin_detected = True

                    script.on("message", on_message)
                    script.load()
                    time.sleep(8)

                session.detach()
                return hook_log, pin_detected

            result = self._frida_with_timeout(_do_ssl_pinning, "SSL pinning test")

            if result is None:
                return findings

            hook_log, pin_detected = result

            if ssl_bypass_script:
                (out_dir / "ssl_pinning_hooks.json").write_text(
                    json.dumps(hook_log, indent=2), encoding="utf-8")

                if pin_detected:
                    self.finding(
                        title="SSL Certificate Pinning Bypassable",
                        severity="HIGH",
                        description=(
                            "The app implements SSL certificate pinning but it "
                            "was bypassed using Frida runtime hooks. Pinning "
                            "validation occurs in hookable Java/ObjC methods. "
                            "Consider implementing pinning in native code with "
                            "integrity checks on the validation logic."
                        ),
                        catalogue_id="QUILL-RES-004",
                        output_file=str((out_dir / "ssl_pinning_hooks.json").relative_to(self._output_dir)),
                        affected=self.package,
                    )
                    findings += 1
                elif not hook_log:
                    self.finding(
                        title="No SSL Certificate Pinning Detected",
                        severity="MEDIUM",
                        description=(
                            "The app does not appear to implement SSL certificate "
                            "pinning. Without pinning, a MITM attacker with a "
                            "trusted CA certificate can intercept all HTTPS "
                            "traffic between the app and its backend."
                        ),
                        catalogue_id="QUILL-RES-003",
                        output_file=str((out_dir / "ssl_pinning_hooks.json").relative_to(self._output_dir)),
                        affected=self.package,
                    )
                    findings += 1
        except ImportError:
            self.err("[resilience] frida Python module not available")
        except Exception as exc:
            self.err(f"[resilience] SSL pinning test failed: {exc}")

        return findings

    # ── debugger detection ───────────────────────────────────────────────

    def _test_debugger_detection(self, out_dir: Path) -> int:
        findings = 0
        self.log("[resilience] Testing debugger/anti-debug protections...")

        ev_data = {}

        if self.platform == "android":
            if not self._device.is_app_running(self.package):
                self._device.launch_app(self.package)
                time.sleep(2)

            rc, out, _ = self._device.shell(
                f"cat /proc/$(pidof {self.package})/status 2>/dev/null",
                root=True, timeout=10)
            for line in out.splitlines():
                if line.startswith("TracerPid:"):
                    ev_data["tracerpid"] = line.split(":")[1].strip()
                    break

        try:
            import frida

            if not self._device.is_app_running(self.package):
                self._device.launch_app(self.package)
                time.sleep(3)

            if self.platform == "android":
                debug_script = """
                Java.perform(function() {
                    var Debug = Java.use('android.os.Debug');
                    send({debug_connected: Debug.isDebuggerConnected()});
                });
                """
            else:
                debug_script = """
                var ptrace = Module.findExportByName(null, 'ptrace');
                send({ptrace_found: ptrace !== null});
                var sysctl = Module.findExportByName(null, 'sysctl');
                send({sysctl_found: sysctl !== null});
                """

            def _do_debugger_test():
                device = frida.get_usb_device(timeout=5)
                pid = device.get_process(self.package).pid
                session = device.attach(pid)
                script = session.create_script(debug_script)
                debug_results = []

                def on_msg(msg, data):
                    if msg.get("type") == "send":
                        debug_results.append(msg.get("payload", {}))

                script.on("message", on_msg)
                script.load()
                time.sleep(2)
                session.detach()
                return debug_results

            result = self._frida_with_timeout(_do_debugger_test, "debugger detection")

            if result is not None:
                ev_data["frida_attach_succeeded"] = True
                ev_data["debug_results"] = result
            else:
                ev_data["frida_attach_succeeded"] = False
                ev_data["frida_attach_error"] = "timeout"
        except ImportError:
            ev_data["frida_available"] = False
        except Exception as exc:
            ev_data["frida_attach_error"] = str(exc)
            ev_data["frida_attach_succeeded"] = False

        (out_dir / "debugger_detection.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        if ev_data.get("frida_attach_succeeded"):
            self.finding(
                title="No Anti-Debug / Frida Detection",
                severity="MEDIUM",
                description=(
                    "Frida was able to attach to the running app process "
                    "without triggering any anti-debug or anti-instrumentation "
                    "response. An attacker can use Frida to hook methods, "
                    "bypass security checks, and extract runtime secrets."
                ),
                catalogue_id="QUILL-RES-005",
                output_file=str((out_dir / "debugger_detection.json").relative_to(self._output_dir)),
                affected=self.package,
            )
            findings += 1

        return findings

    # ── emulator detection ───────────────────────────────────────────────

    def _test_emulator_detection(self, out_dir: Path) -> int:
        if self.platform != "android":
            return 0

        findings = 0
        self.log("[resilience] Testing emulator detection...")

        ev_data = {}
        rc, out, _ = self._device.shell("getprop ro.hardware", timeout=5)
        hardware = out.strip()
        rc2, out2, _ = self._device.shell("getprop ro.product.model", timeout=5)
        model = out2.strip()
        rc3, out3, _ = self._device.shell("getprop ro.kernel.qemu", timeout=5)
        qemu = out3.strip()

        is_emulator = (
            hardware in ("goldfish", "ranchu", "vbox86")
            or qemu == "1"
            or "sdk" in model.lower()
            or "emulator" in model.lower()
        )

        ev_data["hardware"] = hardware
        ev_data["model"] = model
        ev_data["qemu_prop"] = qemu
        ev_data["appears_emulator"] = is_emulator

        if is_emulator:
            app_running = self._device.is_app_running(self.package)
            if not app_running:
                self._device.launch_app(self.package)
                time.sleep(3)
                app_running = self._device.is_app_running(self.package)

            ev_data["app_runs_on_emulator"] = app_running

            if app_running:
                self.finding(
                    title="No Emulator Detection",
                    severity="LOW",
                    description=(
                        f"The app runs on an emulator (hardware={hardware}, "
                        f"model={model}) without restriction. Emulators make "
                        f"dynamic analysis, traffic interception, and reverse "
                        f"engineering easier. Consider detecting emulator "
                        f"environments for sensitive operations."
                    ),
                    catalogue_id="QUILL-RES-006",
                    output_file=str((out_dir / "emulator_detection.json").relative_to(self._output_dir)),
                    affected=self.package,
                )
                findings += 1

        (out_dir / "emulator_detection.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        return findings

    # ── screenshot prevention ────────────────────────────────────────────

    def _test_screenshot_prevention(self, out_dir: Path) -> int:
        findings = 0
        self.log("[resilience] Testing screenshot prevention (FLAG_SECURE)...")

        if not self._device.is_app_running(self.package):
            self._device.launch_app(self.package)
            time.sleep(3)

        ev_data = {}

        if self.platform == "android":
            rc, out, _ = self._device.shell(
                "screencap -p /data/local/tmp/quill_screenshot_test.png",
                root=False, timeout=10)

            screenshot_taken = rc == 0
            if screenshot_taken:
                self._device.shell(
                    "rm -f /data/local/tmp/quill_screenshot_test.png",
                    root=False, timeout=5)

            rc2, out2, _ = self._device.shell(
                f"dumpsys window windows | grep -A5 'mCurrentFocus.*{self.package}'",
                root=False, timeout=10)
            flag_secure = "FLAG_SECURE" in out2

            ev_data["screenshot_succeeded"] = screenshot_taken
            ev_data["flag_secure_detected"] = flag_secure

            if screenshot_taken and not flag_secure:
                self.finding(
                    title="Screenshot Not Prevented",
                    severity="LOW",
                    description=(
                        "The app does not set FLAG_SECURE on sensitive screens. "
                        "Screenshots and screen recordings can capture sensitive "
                        "data displayed by the app. Malware with accessibility "
                        "permissions can take screenshots silently."
                    ),
                    catalogue_id="QUILL-RES-007",
                    output_file=str((out_dir / "screenshot_prevention.json").relative_to(self._output_dir)),
                    affected=self.package,
                )
                findings += 1

        elif self.platform == "ios":
            ev_data["platform"] = "ios"
            try:
                import frida

                ios_script = """
                ObjC.perform(function() {
                    var app = ObjC.classes.UIApplication.sharedApplication();
                    var windows = app.windows();
                    var secureFound = false;
                    for (var i = 0; i < windows.count(); i++) {
                        var win = windows.objectAtIndex_(i);
                        if (win.respondsToSelector_(ObjC.selector('isSecure'))) {
                            if (win.isSecure()) secureFound = true;
                        }
                    }
                    send({secure_window: secureFound});
                });
                """

                def _do_screenshot_ios():
                    device = frida.get_usb_device(timeout=5)
                    pid = device.get_process(self.package).pid
                    session = device.attach(pid)
                    script = session.create_script(ios_script)
                    results = []

                    def on_msg(msg, data):
                        if msg.get("type") == "send":
                            results.append(msg.get("payload", {}))

                    script.on("message", on_msg)
                    script.load()
                    time.sleep(2)
                    session.detach()
                    return results

                result = self._frida_with_timeout(_do_screenshot_ios, "iOS screenshot prevention")
                if result is not None:
                    ev_data["frida_results"] = result
                else:
                    ev_data["frida_error"] = "timeout"
            except Exception as exc:
                ev_data["frida_error"] = str(exc)

        (out_dir / "screenshot_prevention.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        return findings

    # ── clipboard security ───────────────────────────────────────────────

    def _test_clipboard_security(self, out_dir: Path) -> int:
        findings = 0
        self.log("[resilience] Testing clipboard data leakage...")

        pre_clipboard = self._device.get_clipboard()

        if not self._device.is_app_running(self.package):
            self._device.launch_app(self.package)
            time.sleep(3)

        time.sleep(5)
        post_clipboard = self._device.get_clipboard()

        ev_data = {
            "pre_app_clipboard": pre_clipboard[:200] if pre_clipboard else "",
            "post_app_clipboard": post_clipboard[:200] if post_clipboard else "",
            "clipboard_changed": pre_clipboard != post_clipboard,
        }

        if post_clipboard and post_clipboard != pre_clipboard:
            from phases.storage import _SENSITIVE_PATTERNS
            for pat, label in _SENSITIVE_PATTERNS:
                if pat.search(post_clipboard):
                    ev_data["sensitive_type"] = label
                    self.finding(
                        title="App Leaks Sensitive Data to Clipboard",
                        severity="MEDIUM",
                        description=(
                            f"After app usage, the clipboard contains {label} "
                            f"data that was not present before. Clipboard data "
                            f"is accessible to all apps on the device."
                        ),
                        catalogue_id="QUILL-RES-008",
                        output_file=str((out_dir / "clipboard_security.json").relative_to(self._output_dir)),
                        affected=self.package,
                    )
                    findings += 1
                    break

        (out_dir / "clipboard_security.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        return findings

    # ── code integrity ───────────────────────────────────────────────────

    def _test_code_integrity(self, out_dir: Path) -> int:
        findings = 0
        self.log("[resilience] Testing code integrity / anti-tampering...")

        ev_data = {}

        if self.platform == "android":
            recon = self._context.get("recon", {})
            flags = recon.get("flags", {})
            ev_data["debuggable"] = flags.get("debuggable", False)

            try:
                import frida

                if not self._device.is_app_running(self.package):
                    self._device.launch_app(self.package)
                    time.sleep(3)

                tamper_script = """
                Java.perform(function() {
                    var found = [];
                    Java.enumerateLoadedClassesSync().forEach(function(c) {
                        var cl = c.toLowerCase();
                        if (cl.indexOf('integrity') !== -1
                            || cl.indexOf('tamper') !== -1
                            || cl.indexOf('safetynet') !== -1
                            || cl.indexOf('playintegrity') !== -1) {
                            found.push(c);
                        }
                    });
                    send({integrity_classes: found});
                });
                """

                def _do_integrity_check():
                    device = frida.get_usb_device(timeout=5)
                    pid = device.get_process(self.package).pid
                    session = device.attach(pid)
                    script = session.create_script(tamper_script)
                    integrity_results = []

                    def on_msg(msg, data):
                        if msg.get("type") == "send":
                            integrity_results.append(msg.get("payload", {}))

                    script.on("message", on_msg)
                    script.load()
                    time.sleep(3)
                    session.detach()
                    return integrity_results

                integrity_results = self._frida_with_timeout(_do_integrity_check, "code integrity check")

                if integrity_results is not None:
                    ev_data["integrity_results"] = integrity_results
                    has_integrity = any(
                        r.get("integrity_classes")
                        for r in integrity_results
                        if isinstance(r, dict)
                    )
                    if not has_integrity:
                        self.finding(
                            title="No Code Integrity / Anti-Tampering",
                            severity="LOW",
                            description=(
                                "No runtime integrity verification was detected. "
                                "The app does not appear to use SafetyNet, Play "
                                "Integrity API, or custom tamper-detection. A "
                                "repackaged or modified APK will run without "
                                "restriction."
                            ),
                            catalogue_id="QUILL-RES-009",
                            output_file=str((out_dir / "code_integrity.json").relative_to(self._output_dir)),
                            affected=self.package,
                        )
                        findings += 1

            except ImportError:
                self.err("[resilience] frida Python module not available")
            except Exception as exc:
                self.err(f"[resilience] Code integrity test failed: {exc}")
                ev_data["frida_error"] = str(exc)

        (out_dir / "code_integrity.json").write_text(
            json.dumps(ev_data, indent=2), encoding="utf-8")

        return findings
