"""Memory Analysis phase — inspect process memory for secrets and sensitive data."""
from __future__ import annotations

import json
import re
from pathlib import Path

from phases.base import Phase, PhaseResult, UserGate, GateType


_JWT_RE = re.compile(rb'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}')
_BEARER_RE = re.compile(rb'(?i)bearer\s+[A-Za-z0-9_\-/.+=]{20,}')
_APIKEY_RE = re.compile(
    rb'(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?key)'
    rb'["\s:=]+["\']?([A-Za-z0-9_\-/.+=]{20,})')
_PASSWORD_RE = re.compile(rb'(?i)(?:password|passwd|pwd)["\s:=]+["\']?(\S{4,64})')
_PRIVKEY_RE = re.compile(rb'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')
_CC_RE = re.compile(rb'(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))'
                    rb'[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)')
_SSN_RE = re.compile(rb'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)')
_PINCODE_RE = re.compile(rb'(?i)(?:pin|passcode|mpin)["\s:=]+["\']?(\d{4,8})')

_CATEGORIES = [
    ("jwt_in_memory",    "JWT Token Found in Process Memory",      "HIGH",     "QUILL-MEM-001", [_JWT_RE]),
    ("bearer_in_memory", "Bearer Token Found in Process Memory",   "HIGH",     "QUILL-MEM-002", [_BEARER_RE]),
    ("apikey_in_memory", "API Key Found in Process Memory",        "HIGH",     "QUILL-MEM-003", [_APIKEY_RE]),
    ("password_in_mem",  "Password Found in Process Memory",       "CRITICAL", "QUILL-MEM-004", [_PASSWORD_RE]),
    ("privkey_in_mem",   "Private Key Found in Process Memory",    "CRITICAL", "QUILL-MEM-005", [_PRIVKEY_RE]),
    ("cc_in_memory",     "Credit Card Number in Process Memory",   "HIGH",     "QUILL-MEM-006", [_CC_RE]),
    ("ssn_in_memory",    "SSN Found in Process Memory",            "HIGH",     "QUILL-MEM-007", [_SSN_RE]),
    ("pin_in_memory",    "PIN/Passcode Found in Process Memory",   "MEDIUM",   "QUILL-MEM-008", [_PINCODE_RE]),
]


class MemoryPhase(Phase):

    @property
    def name(self) -> str:
        return "memory"

    @property
    def display_name(self) -> str:
        return "Memory Analysis"

    @property
    def description(self) -> str:
        return "Dump and scan process memory for secrets, credentials, and sensitive data"

    @property
    def order(self) -> int:
        return 600

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
                "Memory analysis requires the app to be running with active "
                "session data. Please log in to the app and navigate through "
                "key features (authentication, profile, payments) before "
                "continuing. Press Done when ready."),
            gate_type=GateType.AUTO_DETECT,
            auto_detect_fn=self._app_is_running,
            auto_detect_interval=3.0,
            auto_detect_timeout=120.0,
            prompt_id="memory_app_active",
        )]

    def post_gates(self) -> list[UserGate]:
        return [UserGate(
            instruction=(
                "Now log OUT of the app (or navigate away from the "
                "sensitive screen). Press Done when the logout or "
                "navigation is complete."),
            gate_type=GateType.MANUAL,
            auto_detect_timeout=300.0,
            prompt_id="memory_post_logout",
        )]

    def _app_is_running(self) -> bool:
        if not self._device or not self.package:
            return False
        return self._device.is_app_running(self.package)

    def run(self) -> PhaseResult:
        self.status("Memory Analysis", "running", "locating target process")
        out = self.phase_dir()
        findings_count = 0

        pkg = self.package
        if not pkg:
            self.log("[memory] No target package — skipping")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="no target package")

        pid = self._find_pid(pkg)
        if not pid:
            self.log(f"[memory] Process {pkg} not running — skipping memory dump")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="target process not running")

        self.log(f"[memory] Target PID: {pid}")

        self.status("Memory Analysis", "running", "reading memory maps")
        maps_text = self._device.read_proc_maps(pid)
        if maps_text:
            maps_file = out / "proc_maps.txt"
            maps_file.write_text(maps_text, encoding="utf-8")
            self.log(f"[memory] Saved memory map ({len(maps_text.splitlines())} regions)")

            heap_regions = [ln for ln in maps_text.splitlines() if "[heap]" in ln]
            stack_regions = [ln for ln in maps_text.splitlines() if "[stack]" in ln]
            anon_regions = [ln for ln in maps_text.splitlines()
                           if ln.strip().endswith("00:00 0") and "rw" in ln[:30]]
            self.log(f"[memory] Heap regions: {len(heap_regions)}, "
                     f"Stack regions: {len(stack_regions)}, "
                     f"Anonymous RW: {len(anon_regions)}")

        self.status("Memory Analysis", "running", "dumping process memory")
        dump_path = self._device.dump_process_memory(pid, str(out))
        if not dump_path:
            self.log("[memory] Memory dump failed — attempting fridump fallback")
            dump_path = self._fridump_fallback(pid, out)

        if not dump_path:
            self.log("[memory] No memory dump available — skipping scan")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="memory dump failed")

        dump_path = Path(dump_path)
        dump_files = list(dump_path.glob("**/*")) if dump_path.is_dir() else [dump_path]
        dump_files = [f for f in dump_files if f.is_file() and f.stat().st_size > 0]
        total_size = sum(f.stat().st_size for f in dump_files)
        self.log(f"[memory] Scanning {len(dump_files)} dump file(s) "
                 f"({total_size / (1024*1024):.1f} MiB)")

        self.status("Memory Analysis", "running", "scanning for secrets")
        hits: dict[str, list[dict]] = {cat[0]: [] for cat in _CATEGORIES}

        for df in dump_files:
            self.check_pause()
            try:
                data = df.read_bytes()
            except OSError:
                continue

            for cat_id, _title, _sev, _cid, patterns in _CATEGORIES:
                for pat in patterns:
                    for m in pat.finditer(data):
                        start = max(0, m.start() - 32)
                        end = min(len(data), m.end() + 32)
                        ctx = data[start:end]
                        safe_ctx = ctx.decode("utf-8", errors="replace")
                        safe_match = m.group(0).decode("utf-8", errors="replace")
                        if len(safe_match) > 120:
                            safe_match = safe_match[:117] + "..."
                        hits[cat_id].append({
                            "file": df.name,
                            "offset": m.start(),
                            "matched": safe_match,
                            "context": safe_ctx,
                        })

        for cat_id, title, severity, catalogue_id, _pats in _CATEGORIES:
            cat_hits = hits.get(cat_id, [])
            if not cat_hits:
                continue

            evidence_file = out / f"{cat_id}_hits.json"
            evidence_file.write_text(
                json.dumps(cat_hits, indent=2, default=str), encoding="utf-8")

            self.finding(
                title=title,
                severity=severity,
                catalogue_id=catalogue_id,
                description=(
                    f"Found {len(cat_hits)} instance(s) of {title.lower()} "
                    f"in the application's process memory. Sensitive data "
                    f"persisting in memory after use can be extracted via "
                    f"memory dump tools on rooted devices."),
                output=f"Matches: {len(cat_hits)} across {len(dump_files)} dump file(s)",
                output_file=str(evidence_file.relative_to(self._output_dir)),
                affected=pkg,
                remediation=(
                    "Zero out sensitive data in memory immediately after use. "
                    "Use char[] instead of String for passwords in Java/Kotlin. "
                    "In Swift/ObjC, use autoreleasepool and explicit zeroing. "
                    "Avoid caching authentication tokens longer than necessary."),
            )
            findings_count += 1

        self.status("Memory Analysis", "running", "checking clipboard")
        clipboard = ""
        try:
            clipboard = self._device.get_clipboard()
        except Exception:
            pass

        if clipboard and len(clipboard.strip()) > 3:
            clip_file = out / "clipboard.txt"
            clip_file.write_text(clipboard, encoding="utf-8")
            clip_bytes = clipboard.encode("utf-8", errors="replace")
            for cat_id, title, severity, catalogue_id, patterns in _CATEGORIES:
                for pat in patterns:
                    if pat.search(clip_bytes):
                        self.finding(
                            title="Sensitive Data in Clipboard",
                            severity="MEDIUM",
                            catalogue_id="QUILL-MEM-009",
                            description=(
                                f"The device clipboard contains data matching "
                                f"'{title.lower()}' pattern. Clipboard contents "
                                f"are accessible to all apps on older Android "
                                f"(pre-API 30) and via UIPasteboard on iOS."),
                            output=f"Clipboard content matched: {cat_id}",
                            output_file=str(clip_file.relative_to(self._output_dir)),
                            affected=pkg,
                            remediation=(
                                "Clear clipboard after paste operations. "
                                "Use ClipboardManager.clearPrimaryClip() on Android "
                                "or set UIPasteboard expiry on iOS. Consider using "
                                "custom copy controls that auto-expire."),
                        )
                        findings_count += 1
                        break

        self._context.setdefault("memory_analysis", {
            "pid": pid,
            "dump_files": len(dump_files),
            "total_size_bytes": total_size,
            "hit_counts": {k: len(v) for k, v in hits.items() if v},
        })

        self.log(f"[memory] Analysis complete — {findings_count} finding(s)")
        return PhaseResult(phase_name=self.name, findings_count=findings_count)

    def _find_pid(self, package: str) -> int:
        procs = self._device.list_running_processes()
        for p in procs:
            if p.name == package or package in p.cmdline:
                return p.pid
        return 0

    def _fridump_fallback(self, pid: int, out: Path) -> Path | None:
        if not self._device.check_frida():
            return None
        import subprocess, shutil
        fridump = shutil.which("fridump3") or shutil.which("fridump")
        if not fridump:
            self.log("[memory] fridump not installed — cannot dump")
            return None
        dump_dir = out / "fridump"
        dump_dir.mkdir(exist_ok=True)
        try:
            r = subprocess.run(
                [fridump, "-U", "-s", str(pid), "-o", str(dump_dir)],
                capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and any(dump_dir.iterdir()):
                self.log(f"[memory] fridump completed — {sum(1 for _ in dump_dir.iterdir())} files")
                return dump_dir
        except Exception as e:
            self.log(f"[memory] fridump failed: {e}")
        return None
