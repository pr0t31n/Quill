"""Log Analysis phase — scan device logs for leaked secrets and sensitive data."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from phases.base import Phase, PhaseResult


_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}')
_BEARER_RE = re.compile(r'(?i)\b(?:bearer|authorization)[:\s=]+\S{20,}')
_APIKEY_RE = re.compile(
    r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?key'
    r'|client[_-]?secret|app[_-]?key|x-api-key)["\s:=]+["\']?([A-Za-z0-9_\-/.+=]{20,})')
_PASSWORD_RE = re.compile(
    r'(?i)(?:password|passwd|pwd|pass)["\s:=]+["\']?(\S{4,})')
_OAUTH_RE = re.compile(
    r'(?i)(?:refresh[_-]?token|access[_-]?token|id[_-]?token|oauth[_-]?token)'
    r'["\s:=]+["\']?([A-Za-z0-9_\-/.+=]{10,})')
_FIREBASE_RE = re.compile(r'(?i)(?:firebase|fcm|gcm)[_-]?(?:token|key|secret)["\s:=]+\S{15,}')

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_PHONE_RE = re.compile(r'(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)')
_SSN_RE = re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)')
_CC_RE = re.compile(r'(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))'
                    r'[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)')

_INTERNAL_URL_RE = re.compile(
    r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?(?:/\S*)?')

_SENSITIVE_TRACE_RE = re.compile(
    r'(?i)(?:javax\.crypto|java\.security|android\.security\.keystore'
    r'|CCCrypt|SecKey|kSecClass|KeychainWrapper'
    r'|EncryptedSharedPreferences|SQLCipher'
    r'|BiometricPrompt|LAContext'
    r'|RootBeer|SafetyNet|DeviceCheck)')

_DEBUG_TAG_RE = re.compile(r'\b[VDIWEF]/\S+')

_CATEGORIES = [
    ("auth_token",  "Authentication Token Leaked in Logs", "HIGH",    "QUILL-LOG-001",
     [_JWT_RE, _BEARER_RE, _OAUTH_RE]),
    ("api_key",     "API Key Exposed in Logs",             "HIGH",    "QUILL-LOG-002",
     [_APIKEY_RE]),
    ("password",    "Password Leaked in Logs",             "CRITICAL","QUILL-LOG-003",
     [_PASSWORD_RE]),
    ("pii",         "PII Exposed in Logs",                 "MEDIUM",  "QUILL-LOG-004",
     [_EMAIL_RE, _PHONE_RE, _SSN_RE, _CC_RE]),
    ("internal_url","Internal URL Exposed in Logs",        "LOW",     "QUILL-LOG-005",
     [_INTERNAL_URL_RE]),
    ("stack_trace", "Sensitive Stack Trace in Logs",       "INFO",    "QUILL-LOG-006",
     [_SENSITIVE_TRACE_RE]),
    ("firebase",    "Firebase/Cloud Token in Logs",        "HIGH",    "QUILL-LOG-001",
     [_FIREBASE_RE]),
]


class LogsPhase(Phase):

    @property
    def name(self) -> str:
        return "logs"

    @property
    def display_name(self) -> str:
        return "Log Analysis"

    @property
    def description(self) -> str:
        return "Analyze device logs for leaked secrets, credentials, and sensitive data"

    @property
    def order(self) -> int:
        return 650

    @property
    def requires_device(self) -> bool:
        return True

    def run(self) -> PhaseResult:
        self.status("Log Analysis", "running", "collecting logs")
        out = self.phase_dir()
        findings_count = 0

        raw_logs = self._collect_logs()
        if not raw_logs:
            self.log("[logs] No log data available — skipping analysis")
            return PhaseResult(phase_name=self.name, skipped=True,
                               skip_reason="no log data available")

        lines = raw_logs.splitlines()
        self.log(f"[logs] Collected {len(lines)} log lines for analysis")

        pkg = self.package
        if pkg:
            filtered = [ln for ln in lines if pkg in ln]
            self.log(f"[logs] Filtered to {len(filtered)} lines matching package {pkg}")
        else:
            filtered = lines

        log_path = out / "app_logcat.txt"
        log_path.write_text("\n".join(filtered), encoding="utf-8")

        hits: dict[str, list[dict]] = {}
        for cat_id, _title, _sev, _cid, patterns in _CATEGORIES:
            hits[cat_id] = []

        for idx, line in enumerate(filtered):
            for cat_id, title, severity, catalogue_id, patterns in _CATEGORIES:
                for pat in patterns:
                    m = pat.search(line)
                    if m:
                        ctx_start = max(0, idx - 2)
                        ctx_end = min(len(filtered), idx + 3)
                        context_lines = filtered[ctx_start:ctx_end]
                        hits[cat_id].append({
                            "line_number": idx + 1,
                            "matched": m.group(0)[:200],
                            "context": context_lines,
                            "pattern": pat.pattern[:80],
                        })
                        break

        for cat_id, title, severity, catalogue_id, _patterns in _CATEGORIES:
            cat_hits = hits.get(cat_id, [])
            if not cat_hits:
                continue

            evidence_file = out / f"{cat_id}_matches.json"
            evidence_file.write_text(
                json.dumps(cat_hits, indent=2, default=str), encoding="utf-8")

            sample = cat_hits[0]["matched"]
            if len(sample) > 60:
                sample = sample[:57] + "..."

            self.finding(
                title=title,
                severity=severity,
                catalogue_id=catalogue_id,
                description=(
                    f"Found {len(cat_hits)} instance(s) of {title.lower()} "
                    f"in the application's runtime logs. Sample match: {sample}. "
                    f"Application logs can be read by any app on older Android "
                    f"versions (pre-API 16) or by anyone with physical/ADB access."),
                output="\n".join(cat_hits[0].get("context", [])),
                output_file=str(evidence_file.relative_to(self._output_dir)),
                affected=self.package or "application logs",
                remediation=(
                    "Remove sensitive data from log output. Use ProGuard/R8 to "
                    "strip Log.d/Log.v calls in release builds. Never log "
                    "authentication tokens, passwords, PII, or internal URLs."),
            )
            findings_count += 1

        debug_count = sum(1 for ln in filtered if _DEBUG_TAG_RE.search(ln)
                          and any(ln.startswith(f" {t}/") or f" {t}/" in ln[:30]
                                  for t in ("V", "D")))
        total = len(filtered) or 1
        if debug_count > total * 0.4 and total > 50:
            self.finding(
                title="Verbose Logging Enabled in Production",
                severity="LOW",
                catalogue_id="QUILL-LOG-007",
                description=(
                    f"The application produces excessive debug/verbose logging "
                    f"({debug_count} of {total} captured lines are V/D level). "
                    f"This increases the attack surface for information disclosure "
                    f"and can leak implementation details."),
                output=f"Debug/verbose lines: {debug_count}/{total} ({debug_count*100//total}%)",
                output_file=str(log_path.relative_to(self._output_dir)),
                affected=self.package or "application logs",
                remediation=(
                    "Disable verbose and debug logging in production builds. "
                    "Use a logging framework that supports build-type filtering."),
            )
            findings_count += 1

        self._context.setdefault("log_analysis", {
            "total_lines": len(filtered),
            "hit_counts": {k: len(v) for k, v in hits.items() if v},
        })

        self.log(f"[logs] Analysis complete — {findings_count} finding(s)")
        return PhaseResult(phase_name=self.name, findings_count=findings_count)

    def _collect_logs(self) -> str:
        captured = self._context.get("captured_logs")
        if captured:
            self.log("[logs] Using logs captured during interaction phase")
            return captured

        start_ts = self._context.get("interaction_start_time", "")
        if start_ts and self._device:
            self.log(f"[logs] Pulling logs since {start_ts}")
            return self._device.get_logs_since(start_ts, package=self.package)

        if self._device:
            self.log("[logs] No interaction timestamp — pulling last 5 minutes of logs")
            return self._device.get_logs_since("", package=self.package)

        return ""
