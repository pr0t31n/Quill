"""Abstract device connector — platform-agnostic interface for mobile devices."""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DeviceInfo:
    platform: str = ""
    device_id: str = ""
    model: str = ""
    os_version: str = ""
    rooted: bool = False
    root_method: str = ""
    arch: str = ""
    hostname: str = ""
    ip_address: str = ""
    wifi_ssid: str = ""
    usb_connected: bool = False
    frida_available: bool = False
    frida_version: str = ""
    extras: dict = field(default_factory=dict)


@dataclass
class AppInfo:
    package_name: str = ""
    version: str = ""
    version_code: str = ""
    install_path: str = ""
    data_dir: str = ""
    uid: int = -1
    target_sdk: int = 0
    min_sdk: int = 0
    debuggable: bool = False
    backup_allowed: bool = False
    permissions: list = field(default_factory=list)
    extras: dict = field(default_factory=dict)


@dataclass
class ProcessInfo:
    pid: int = 0
    name: str = ""
    cmdline: str = ""


class DeviceConnector(ABC):
    """Platform-agnostic interface for interacting with a mobile device.

    Subclasses implement the abstract methods for Android (ADB) and iOS
    (SSH/idevice tooling).  Phase modules call only these methods so they
    work on both platforms without branching.
    """

    def __init__(self, *, device_id: str = "", **kwargs):
        self.device_id = device_id
        self._connected = False
        self._info: Optional[DeviceInfo] = None

    # ── connection ──────────────────────────────────────────────────────

    @abstractmethod
    def connect(self) -> bool:
        """Establish a connection to the device.  Returns True on success."""

    @abstractmethod
    def disconnect(self) -> None:
        """Tear down the device connection."""

    @property
    def connected(self) -> bool:
        return self._connected

    @abstractmethod
    def get_device_info(self) -> DeviceInfo:
        """Probe and return device metadata."""

    # ── shell ───────────────────────────────────────────────────────────

    @abstractmethod
    def shell(self, cmd: str, *, timeout: int = 30,
              root: bool = False) -> tuple[int, str, str]:
        """Run a command on the device.  Returns (exit_code, stdout, stderr).

        When *root* is True, execute with elevated privileges (su / sudo).
        """

    @abstractmethod
    def shell_stream(self, cmd: str, *, timeout: int = 0,
                     root: bool = False):
        """Run a command and yield stdout lines as they arrive.

        Yields (str) lines.  *timeout=0* means no timeout (run until
        killed or EOF).  Caller is responsible for consuming the
        generator or calling .close() to terminate.
        """

    # ── file transfer ──────────────────────────────────────────────────

    @abstractmethod
    def pull(self, remote_path: str, local_path: str | Path) -> bool:
        """Copy a file or directory from device to host.  Returns True on success."""

    @abstractmethod
    def push(self, local_path: str | Path, remote_path: str) -> bool:
        """Copy a file from host to device.  Returns True on success."""

    @abstractmethod
    def file_exists(self, remote_path: str) -> bool:
        """Check whether a file or directory exists on the device."""

    @abstractmethod
    def list_dir(self, remote_path: str) -> list[str]:
        """List entries in a remote directory."""

    # ── app management ─────────────────────────────────────────────────

    @abstractmethod
    def get_app_info(self, package: str) -> Optional[AppInfo]:
        """Return metadata about an installed app, or None."""

    @abstractmethod
    def get_app_data_dir(self, package: str) -> str:
        """Return the app's private data directory path on device."""

    @abstractmethod
    def list_running_processes(self) -> list[ProcessInfo]:
        """Return list of running processes."""

    @abstractmethod
    def is_app_running(self, package: str) -> bool:
        """Check whether the given app/process is currently running."""

    @abstractmethod
    def launch_app(self, package: str) -> bool:
        """Launch the app on the device."""

    @abstractmethod
    def kill_app(self, package: str) -> bool:
        """Force-stop the app on the device."""

    # ── root / jailbreak ───────────────────────────────────────────────

    @abstractmethod
    def is_rooted(self) -> bool:
        """Check whether the device has root/jailbreak access."""

    @abstractmethod
    def get_root_method(self) -> str:
        """Return the root/jailbreak method name (e.g. 'magisk', 'palera1n')."""

    # ── logging ────────────────────────────────────────────────────────

    @abstractmethod
    def start_log_capture(self, *, pid: int = 0, package: str = "",
                          output_file: str | Path = "") -> bool:
        """Start capturing device logs (logcat / syslog).

        Filter by *pid* or *package* when provided.  Writes to
        *output_file* if given, otherwise an internal buffer.
        Returns True on success.
        """

    @abstractmethod
    def stop_log_capture(self) -> str:
        """Stop log capture and return the captured text."""

    @abstractmethod
    def get_logs_since(self, timestamp: str, *, package: str = "") -> str:
        """Return device logs since the given ISO timestamp."""

    # ── network ────────────────────────────────────────────────────────

    @abstractmethod
    def get_ip_address(self) -> str:
        """Return the device's current IP address (WiFi or USB)."""

    @abstractmethod
    def set_proxy(self, host: str, port: int) -> bool:
        """Configure the device to route traffic through a proxy."""

    @abstractmethod
    def clear_proxy(self) -> bool:
        """Remove any configured proxy."""

    # ── frida ──────────────────────────────────────────────────────────

    def check_frida(self) -> bool:
        """Check if frida-server is running on the device."""
        return shutil.which("frida") is not None

    @abstractmethod
    def ensure_frida_server(self) -> bool:
        """Ensure frida-server is running on the device.

        Downloads, pushes, and starts it if needed.  Returns True on success.
        """

    # ── memory ─────────────────────────────────────────────────────────

    @abstractmethod
    def dump_process_memory(self, pid: int, output_dir: str | Path) -> Optional[Path]:
        """Dump process memory to a local file.  Returns the path or None."""

    @abstractmethod
    def read_proc_maps(self, pid: int) -> str:
        """Return the memory map (/proc/<pid>/maps or equivalent)."""

    # ── clipboard ──────────────────────────────────────────────────────

    @abstractmethod
    def get_clipboard(self) -> str:
        """Read the device clipboard contents (requires root on modern Android)."""

    # ── snapshots ──────────────────────────────────────────────────────

    def snapshot_app_data(self, package: str, output_dir: str | Path,
                          label: str = "snapshot") -> Optional[Path]:
        """Pull the app's entire data directory to a local snapshot folder.

        Returns the local path to the snapshot, or None on failure.
        """
        data_dir = self.get_app_data_dir(package)
        if not data_dir:
            return None
        dest = Path(output_dir) / f"{label}_{package}"
        dest.mkdir(parents=True, exist_ok=True)
        if self.pull(data_dir, str(dest)):
            return dest
        return None
