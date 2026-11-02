"""Phase interface and orchestrator for Quill's modular analysis pipeline.

Each phase is a self-contained analysis module that:
  - Declares whether it needs user interaction (gates)
  - Can autodetect when a manual gate is satisfied
  - Emits findings, log entries, and action items via Crucible tokens
  - Receives a DeviceConnector and shared context dict
"""
from __future__ import annotations

import json
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from device.base import DeviceConnector


class GateType(Enum):
    NONE = "none"
    MANUAL = "manual"
    AUTO_DETECT = "auto_detect"


@dataclass
class UserGate:
    """A point where Quill pauses for user action on the device."""
    instruction: str
    gate_type: GateType = GateType.MANUAL
    auto_detect_fn: Optional[Callable] = None
    auto_detect_interval: float = 5.0
    auto_detect_timeout: float = 300.0
    prompt_id: str = ""

    def wait_for_user(self, *, tok_fn: Callable, log_fn: Callable,
                      check_pause_fn: Callable = lambda: None) -> bool:
        """Block until the user completes the gate.

        For MANUAL gates, emits a __CRUCIBLE_PROMPT__ and waits for the
        response.  For AUTO_DETECT gates, polls auto_detect_fn until it
        returns True or timeout is reached.

        Returns True if the gate was satisfied, False on timeout/cancel.
        """
        if self.gate_type == GateType.NONE:
            return True

        log_fn(f"[gate] {self.instruction}")

        import os
        _managed = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
        if self.gate_type == GateType.AUTO_DETECT and self.auto_detect_fn and not _managed:
            tok_fn("__CRUCIBLE_STATUS__", json.dumps({
                "phase": "gate", "label": self.instruction,
                "state": "waiting", "step": "auto-detecting",
            }))
            log_fn(f"[gate] Auto-detecting completion (timeout={self.auto_detect_timeout}s)...")
            deadline = time.time() + self.auto_detect_timeout
            while time.time() < deadline:
                check_pause_fn()
                try:
                    if self.auto_detect_fn():
                        log_fn("[gate] Auto-detected: gate satisfied")
                        return True
                except Exception:
                    pass
                time.sleep(self.auto_detect_interval)
            log_fn("[gate] Auto-detect timed out — falling back to manual prompt")
        elif _managed and self.gate_type == GateType.AUTO_DETECT:
            if self.auto_detect_fn:
                try:
                    if self.auto_detect_fn():
                        log_fn("[gate] Managed mode — condition already met, skipping prompt")
                        return True
                except Exception:
                    pass
            log_fn("[gate] Managed mode — prompting user")

        prompt_id = self.prompt_id or f"gate_{int(time.time())}"
        tok_fn("__CRUCIBLE_PROMPT__", json.dumps({
            "prompt_id": prompt_id,
            "message": self.instruction,
            "type": "confirm",
            "options": ["Done", "Skip"],
        }))
        log_fn(f"[gate] Waiting for user confirmation (prompt_id={prompt_id})...")

        import sys
        _answer_queue = getattr(sys.modules.get("quill", None), "_answer_queue", None)
        if _answer_queue is not None:
            try:
                answer = _answer_queue.get(timeout=self.auto_detect_timeout or 600)
                if isinstance(answer, dict):
                    return answer.get("value", "").lower() != "skip"
                return str(answer).lower() != "skip"
            except Exception:
                log_fn("[gate] Prompt timed out waiting for user response")
                return False

        log_fn("[gate] No prompt queue available — assuming standalone mode, continuing")
        return True


@dataclass
class PhaseResult:
    """Result of running a phase."""
    phase_name: str
    success: bool = True
    skipped: bool = False
    skip_reason: str = ""
    findings_count: int = 0
    action_items_count: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    data: dict = field(default_factory=dict)


class Phase(ABC):
    """Base class for all Quill analysis phases.

    Subclasses implement:
      - name, display_name, description (properties)
      - platform_support (which platforms this phase works on)
      - requires_device (whether a connected device is needed)
      - requires_root (whether root/jailbreak is needed)
      - requires_frida (whether Frida is needed)
      - pre_gates / post_gates (user interaction points)
      - run() (the actual analysis logic)
    """

    def __init__(self):
        self._tok_fn: Callable = lambda t, p: None
        self._log_fn: Callable = lambda m: None
        self._err_fn: Callable = lambda m: None
        self._status_fn: Callable = lambda *a, **k: None
        self._finding_fn: Callable = lambda **k: None
        self._check_pause_fn: Callable = lambda: None
        self._device: Optional[DeviceConnector] = None
        self._context: dict = {}
        self._output_dir: Optional[Path] = None

    # ── identity ───────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Short machine-readable name (e.g. 'storage', 'ipc')."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for UI display."""

    @property
    def description(self) -> str:
        return ""

    @property
    def order(self) -> int:
        """Execution order (lower = earlier).  Default phases use 100-900."""
        return 500

    # ── requirements ───────────────────────────────────────────────────

    @property
    def platform_support(self) -> set[str]:
        """Platforms this phase supports.  Default: both."""
        return {"android", "ios"}

    @property
    def requires_device(self) -> bool:
        return True

    @property
    def requires_root(self) -> bool:
        return False

    @property
    def requires_frida(self) -> bool:
        return False

    @property
    def requires_app_binary(self) -> bool:
        return False

    # ── gates ──────────────────────────────────────────────────────────

    def pre_gates(self) -> list[UserGate]:
        """Gates that must be satisfied BEFORE this phase runs."""
        return []

    def post_gates(self) -> list[UserGate]:
        """Gates that must be satisfied AFTER this phase runs."""
        return []

    # ── lifecycle ──────────────────────────────────────────────────────

    def setup(self, *, device: Optional[DeviceConnector],
              context: dict, output_dir: Path,
              tok_fn: Callable, log_fn: Callable, err_fn: Callable,
              status_fn: Callable, finding_fn: Callable,
              check_pause_fn: Callable) -> None:
        """Called by the orchestrator before run().  Injects dependencies."""
        self._device = device
        self._context = context
        self._output_dir = output_dir
        self._tok_fn = tok_fn
        self._log_fn = log_fn
        self._err_fn = err_fn
        self._status_fn = status_fn
        self._finding_fn = finding_fn
        self._check_pause_fn = check_pause_fn

    @abstractmethod
    def run(self) -> PhaseResult:
        """Execute the phase.  Returns a PhaseResult."""

    def teardown(self) -> None:
        """Called after run() completes, even on failure."""

    # ── helpers for subclasses ─────────────────────────────────────────

    def log(self, msg: str) -> None:
        self._log_fn(msg)

    def err(self, msg: str) -> None:
        self._err_fn(msg)

    def status(self, label: str, state: str, step: str = "") -> None:
        self._status_fn(self.name, label, state, step)

    def tok(self, token: str, payload: str) -> None:
        self._tok_fn(token, payload)

    def finding(self, **kwargs) -> None:
        self._finding_fn(**kwargs)

    def check_pause(self) -> None:
        self._check_pause_fn()

    def phase_dir(self, subdir: str = "") -> Path:
        """Return (and create) a phase-specific output subdirectory."""
        d = self._output_dir / self.name
        if subdir:
            d = d / subdir
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def platform(self) -> str:
        return self._context.get("platform", "")

    @property
    def package(self) -> str:
        return self._context.get("package", "")

    @property
    def app_dir(self) -> Optional[Path]:
        v = self._context.get("app_dir")
        return Path(v) if v else None


class PhaseOrchestrator:
    """Runs phases in order, handling gates, requirements, and errors."""

    def __init__(self, *, device: Optional[DeviceConnector],
                 context: dict, output_dir: Path,
                 tok_fn: Callable, log_fn: Callable, err_fn: Callable,
                 status_fn: Callable, finding_fn: Callable,
                 check_pause_fn: Callable):
        self._device = device
        self._context = context
        self._output_dir = output_dir
        self._tok_fn = tok_fn
        self._log_fn = log_fn
        self._err_fn = err_fn
        self._status_fn = status_fn
        self._finding_fn = finding_fn
        self._check_pause_fn = check_pause_fn
        self._phases: list[Phase] = []
        self._results: list[PhaseResult] = []

    def register(self, phase: Phase) -> None:
        self._phases.append(phase)

    def register_all(self, phases: list[Phase]) -> None:
        self._phases.extend(phases)

    def run_all(self, *, enabled_phases: set[str] | None = None) -> list[PhaseResult]:
        """Execute all registered phases in order.

        *enabled_phases*: if provided, only run phases whose name is in
        this set.  If None, run all.
        """
        platform = self._context.get("platform", "")
        ordered = sorted(self._phases, key=lambda p: p.order)

        for phase in ordered:
            if enabled_phases is not None and phase.name not in enabled_phases:
                self._results.append(PhaseResult(
                    phase_name=phase.name, skipped=True,
                    skip_reason="not enabled"))
                continue

            if platform and platform not in phase.platform_support:
                self._log_fn(f"[orchestrator] Skipping {phase.display_name} "
                             f"(not supported on {platform})")
                self._results.append(PhaseResult(
                    phase_name=phase.name, skipped=True,
                    skip_reason=f"not supported on {platform}"))
                continue

            if phase.requires_device and (self._device is None or not self._device.connected):
                self._log_fn(f"[orchestrator] Skipping {phase.display_name} "
                             f"(no connected device)")
                self._results.append(PhaseResult(
                    phase_name=phase.name, skipped=True,
                    skip_reason="no connected device"))
                continue

            if phase.requires_root and self._device and not self._device.is_rooted():
                self._log_fn(f"[orchestrator] Skipping {phase.display_name} "
                             f"(device not rooted)")
                self._results.append(PhaseResult(
                    phase_name=phase.name, skipped=True,
                    skip_reason="device not rooted"))
                continue

            if phase.requires_frida and self._device and not self._device.check_frida():
                self._log_fn(f"[orchestrator] Skipping {phase.display_name} "
                             f"(Frida not available)")
                self._results.append(PhaseResult(
                    phase_name=phase.name, skipped=True,
                    skip_reason="Frida not available"))
                continue

            self._log_fn(f"[orchestrator] Starting phase: {phase.display_name}")
            self._status_fn(phase.name, phase.display_name, "starting")

            phase.setup(
                device=self._device, context=self._context,
                output_dir=self._output_dir,
                tok_fn=self._tok_fn, log_fn=self._log_fn,
                err_fn=self._err_fn, status_fn=self._status_fn,
                finding_fn=self._finding_fn,
                check_pause_fn=self._check_pause_fn)

            for gate in phase.pre_gates():
                if not gate.wait_for_user(
                        tok_fn=self._tok_fn, log_fn=self._log_fn,
                        check_pause_fn=self._check_pause_fn):
                    self._log_fn(f"[orchestrator] Pre-gate skipped for "
                                 f"{phase.display_name}")
                    self._results.append(PhaseResult(
                        phase_name=phase.name, skipped=True,
                        skip_reason="user skipped pre-gate"))
                    break
            else:
                started = time.time()
                result = PhaseResult(phase_name=phase.name)
                try:
                    result = phase.run()
                except Exception as exc:
                    result.success = False
                    result.error = f"{type(exc).__name__}: {exc}"
                    self._err_fn(f"[orchestrator] Phase {phase.name} failed: {exc}")
                    self._err_fn(traceback.format_exc())
                finally:
                    result.duration_seconds = time.time() - started
                    try:
                        phase.teardown()
                    except Exception as exc:
                        self._err_fn(f"[orchestrator] Teardown error for "
                                     f"{phase.name}: {exc}")

                self._results.append(result)

                state = "complete" if result.success else "failed"
                if result.skipped:
                    state = "skipped"
                self._status_fn(phase.name, phase.display_name, state)
                self._log_fn(f"[orchestrator] Phase {phase.display_name}: {state} "
                             f"({result.duration_seconds:.1f}s, "
                             f"{result.findings_count} findings)")

                if result.success:
                    for gate in phase.post_gates():
                        gate.wait_for_user(
                            tok_fn=self._tok_fn, log_fn=self._log_fn,
                            check_pause_fn=self._check_pause_fn)

        return self._results

    @property
    def results(self) -> list[PhaseResult]:
        return list(self._results)
