"""iOS device connector — SSH / idevice-based implementation."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from device.base import AppInfo, DeviceConnector, DeviceInfo, ProcessInfo

log = logging.getLogger("quill.device.ios")

_SSH_TIMEOUT = 15
_DEFAULT_SSH_PORT = 22
_DEFAULT_SSH_USER = "root"
_DEFAULT_SSH_PASS = "alpine"


class IOSDevice(DeviceConnector):
    """SSH / idevice-backed device connector for iOS."""

    def __init__(self, *, device_id: str = "", ssh_host: str = "",
                 ssh_port: int = _DEFAULT_SSH_PORT,
                 ssh_user: str = _DEFAULT_SSH_USER,
                 ssh_pass: str = _DEFAULT_SSH_PASS,
                 ssh_key: str = "", **kwargs):
        super().__init__(device_id=device_id, **kwargs)
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_key = ssh_key
        self._syslog_proc: Optional[subprocess.Popen] = None
        self._syslog_buf: list[str] = []
        self._syslog_file: Optional[Path] = None
        self._syslog_thread: Optional[threading.Thread] = None
        self._jb_cache: Optional[bool] = None
        self._jb_method_cache: str = ""

    # ── SSH helpers ────────────────────────────────────────────────────

    def _ssh_cmd(self) -> list[str]:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", f"ConnectTimeout={_SSH_TIMEOUT}",
               "-p", str(self.ssh_port)]
        if self.ssh_key:
            cmd.extend(["-i", self.ssh_key])
        cmd.append(f"{self.ssh_user}@{self.ssh_host}")
        return cmd

    def _sshpass_wrap(self, cmd: list[str]) -> list[str]:
        if self.ssh_key or not self.ssh_pass:
            return cmd
        if shutil.which("sshpass"):
            return ["sshpass", "-p", self.ssh_pass] + cmd
        return cmd

    def _ssh(self, remote_cmd: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
        cmd = self._sshpass_wrap(self._ssh_cmd() + [remote_cmd])
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _idevice(self, tool: str, *args: str,
                 timeout: int = _SSH_TIMEOUT) -> subprocess.CompletedProcess:
        cmd = [tool]
        if self.device_id:
            cmd.extend(["-u", self.device_id])
        cmd.extend(args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    # ── connection ──────────────────────────────────────────────────────

    def connect(self) -> bool:
        if shutil.which("idevice_id"):
            try:
                r = subprocess.run(["idevice_id", "-l"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and r.stdout.strip():
                    ids = r.stdout.strip().splitlines()
                    if not self.device_id:
                        self.device_id = ids[0].strip()
                    if self.device_id not in [i.strip() for i in ids]:
                        log.warning("Device %s not found via idevice_id", self.device_id)
            except Exception as exc:
                log.debug("idevice_id probe failed: %s", exc)

        if self.ssh_host:
            try:
                r = self._ssh("echo CONNECTED", timeout=10)
                if r.returncode == 0 and "CONNECTED" in r.stdout:
                    self._connected = True
                    log.info("Connected to iOS device via SSH: %s@%s:%d",
                             self.ssh_user, self.ssh_host, self.ssh_port)
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                log.warning("SSH connect failed: %s", exc)

        if shutil.which("ideviceinfo") and self.device_id:
            try:
                r = self._idevice("ideviceinfo", "-k", "DeviceName")
                if r.returncode == 0 and r.stdout.strip():
                    self._connected = True
                    log.info("Connected to iOS device via USB: %s", self.device_id)
                    return True
            except Exception:
                pass

        return False

    def disconnect(self) -> None:
        self.stop_log_capture()
        self._connected = False

    def get_device_info(self) -> DeviceInfo:
        if self._info and self._info.device_id == self.device_id:
            return self._info

        model = ""
        os_version = ""
        arch = ""
        hostname = ""

        if shutil.which("ideviceinfo") and self.device_id:
            fields = {
                "ProductType": "", "ProductVersion": "",
                "CPUArchitecture": "", "DeviceName": "",
            }
            for key in fields:
                try:
                    r = self._idevice("ideviceinfo", "-k", key)
                    if r.returncode == 0:
                        fields[key] = r.stdout.strip()
                except Exception:
                    pass
            model = fields["ProductType"] or fields["DeviceName"]
            os_version = fields["ProductVersion"]
            arch = fields["CPUArchitecture"]
            hostname = fields["DeviceName"]

        if self.ssh_host and not model:
            def _remote(cmd: str) -> str:
                try:
                    r = self._ssh(cmd, timeout=5)
                    return r.stdout.strip() if r.returncode == 0 else ""
                except Exception:
                    return ""
            model = model or _remote("uname -m")
            os_version = os_version or _remote(
                "sw_vers -productVersion 2>/dev/null || "
                "grep ProductVersion /System/Library/CoreServices/SystemVersion.plist "
                "| head -1 | sed 's/.*<string>//;s/<.*//'")
            arch = arch or _remote("uname -p")
            hostname = hostname or _remote("hostname")

        ip = self.get_ip_address()
        ssid = ""
        if self.ssh_host:
            try:
                r = self._ssh(
                    "/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport -I 2>/dev/null "
                    "| grep ' SSID' | awk '{print $2}'")
                if r.returncode == 0:
                    ssid = r.stdout.strip()
            except Exception:
                pass

        rooted = self.is_rooted()
        root_method = self.get_root_method() if rooted else ""
        frida_ok = self.check_frida()
        frida_ver = ""
        if frida_ok:
            try:
                r = subprocess.run(["frida", "--version"],
                                   capture_output=True, text=True, timeout=5)
                frida_ver = r.stdout.strip()
            except Exception:
                pass

        self._info = DeviceInfo(
            platform="ios",
            device_id=self.device_id,
            model=model,
            os_version=os_version,
            rooted=rooted,
            root_method=root_method,
            arch=arch,
            hostname=hostname,
            ip_address=ip,
            wifi_ssid=ssid,
            usb_connected=bool(self.device_id),
            frida_available=frida_ok,
            frida_version=frida_ver,
        )
        return self._info

    # ── shell ───────────────────────────────────────────────────────────

    def shell(self, cmd: str, *, timeout: int = 30,
              root: bool = False) -> tuple[int, str, str]:
        if not self.ssh_host:
            return (-1, "", "no SSH host configured")
        try:
            if root and self.ssh_user != "root":
                cmd = f"sudo {cmd}"
            r = self._ssh(cmd, timeout=timeout)
            return (r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired:
            return (-1, "", "timeout")
        except Exception as exc:
            return (-1, "", str(exc))

    def shell_stream(self, cmd: str, *, timeout: int = 0,
                     root: bool = False):
        if not self.ssh_host:
            return
        if root and self.ssh_user != "root":
            cmd = f"sudo {cmd}"
        full_cmd = self._sshpass_wrap(self._ssh_cmd() + [cmd])
        proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + timeout if timeout > 0 else float("inf")
            for line in proc.stdout:
                if time.time() > deadline:
                    break
                yield line.rstrip("\n")
        finally:
            proc.kill()
            proc.wait()

    # ── file transfer ──────────────────────────────────────────────────

    def pull(self, remote_path: str, local_path: str | Path) -> bool:
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)

        if self.ssh_host:
            scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no",
                       "-o", "UserKnownHostsFile=/dev/null",
                       "-P", str(self.ssh_port), "-r"]
            if self.ssh_key:
                scp_cmd.extend(["-i", self.ssh_key])
            scp_cmd.append(f"{self.ssh_user}@{self.ssh_host}:{remote_path}")
            scp_cmd.append(str(local))
            cmd = self._sshpass_wrap(scp_cmd)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                return r.returncode == 0
            except Exception as exc:
                log.warning("scp pull failed: %s", exc)
                return False

        if shutil.which("ideviceinstaller") and self.device_id:
            try:
                r = subprocess.run(
                    ["ifuse", "--documents", remote_path, str(local)],
                    capture_output=True, text=True, timeout=120)
                return r.returncode == 0
            except Exception:
                pass

        return False

    def push(self, local_path: str | Path, remote_path: str) -> bool:
        if not self.ssh_host:
            return False
        scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null",
                   "-P", str(self.ssh_port), "-r"]
        if self.ssh_key:
            scp_cmd.extend(["-i", self.ssh_key])
        scp_cmd.append(str(local_path))
        scp_cmd.append(f"{self.ssh_user}@{self.ssh_host}:{remote_path}")
        cmd = self._sshpass_wrap(scp_cmd)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return r.returncode == 0
        except Exception as exc:
            log.warning("scp push failed: %s", exc)
            return False

    def file_exists(self, remote_path: str) -> bool:
        rc, out, _ = self.shell(f"test -e '{remote_path}' && echo YES || echo NO")
        return "YES" in out

    def list_dir(self, remote_path: str) -> list[str]:
        rc, out, _ = self.shell(f"ls -1 '{remote_path}'")
        if rc != 0:
            return []
        return [l.strip() for l in out.splitlines() if l.strip()]

    # ── app management ─────────────────────────────────────────────────

    def get_app_info(self, package: str) -> Optional[AppInfo]:
        info = AppInfo(package_name=package)

        if shutil.which("ideviceinstaller") and self.device_id:
            try:
                r = self._idevice("ideviceinstaller", "-l", "-o", "list_all")
                for line in r.stdout.splitlines():
                    if package in line:
                        parts = line.split(",")
                        if len(parts) >= 3:
                            info.version = parts[2].strip().strip('"')
                        break
            except Exception:
                pass

        if self.ssh_host:
            rc, out, _ = self.shell(
                f"find /var/containers/Bundle/Application -name Info.plist -path '*{package}*' "
                f"2>/dev/null | head -1", timeout=15)
            if rc == 0 and out.strip():
                plist_path = out.strip()
                info.install_path = str(Path(plist_path).parent)

                rc2, out2, _ = self.shell(
                    f"plutil -p '{plist_path}' 2>/dev/null || "
                    f"cat '{plist_path}'", timeout=10)
                if rc2 == 0:
                    m = re.search(r'"CFBundleShortVersionString"\s*=>\s*"([^"]+)"', out2)
                    if m:
                        info.version = m.group(1)
                    m = re.search(r'"CFBundleVersion"\s*=>\s*"([^"]+)"', out2)
                    if m:
                        info.version_code = m.group(1)

            rc, out, _ = self.shell(
                f"find /var/mobile/Containers/Data/Application -name .com.apple.mobile_container_manager.metadata.plist "
                f"-exec sh -c 'plutil -p \"$1\" 2>/dev/null | grep -q \"{package}\" && dirname \"$1\"' _ {{}} \\; "
                f"2>/dev/null | head -1", timeout=30)
            if rc == 0 and out.strip():
                info.data_dir = out.strip()

        return info if (info.version or info.install_path or info.data_dir) else None

    def get_app_data_dir(self, package: str) -> str:
        ai = self.get_app_info(package)
        if ai and ai.data_dir:
            return ai.data_dir
        return ""

    def list_running_processes(self) -> list[ProcessInfo]:
        rc, out, _ = self.shell("ps -A -o pid,comm", timeout=10)
        if rc != 0:
            return []
        procs = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) >= 2:
                try:
                    procs.append(ProcessInfo(pid=int(parts[0]), name=parts[1].strip()))
                except ValueError:
                    continue
        return procs

    def is_app_running(self, package: str) -> bool:
        rc, out, _ = self.shell(f"ps -A | grep -i '{package}' | grep -v grep")
        return rc == 0 and bool(out.strip())

    def launch_app(self, package: str) -> bool:
        if self.ssh_host:
            rc, _, _ = self.shell(f"open {package} 2>/dev/null || uiopen {package}")
            if rc == 0:
                return True
            rc, _, _ = self.shell(
                f"activator send {package} 2>/dev/null")
            return rc == 0
        return False

    def kill_app(self, package: str) -> bool:
        rc, _, _ = self.shell(f"killall -9 '{package}' 2>/dev/null")
        if rc != 0:
            rc, out, _ = self.shell(f"ps -A | grep -i '{package}' | grep -v grep")
            for line in out.splitlines():
                parts = line.split()
                if parts:
                    self.shell(f"kill -9 {parts[0]}")
            return True
        return rc == 0

    # ── root / jailbreak ───────────────────────────────────────────────

    def is_rooted(self) -> bool:
        if self._jb_cache is not None:
            return self._jb_cache

        checks = [
            "test -f /Applications/Cydia.app/Cydia && echo YES",
            "test -f /Applications/Sileo.app/Sileo && echo YES",
            "test -f /usr/bin/ssh && echo YES",
            "test -d /var/jb && echo YES",
            "test -f /var/lib/dpkg/status && echo YES",
            "test -f /etc/apt/sources.list.d/elucubratus.list && echo YES",
            "test -f /bootstrap/usr/bin/apt && echo YES",
        ]
        for cmd in checks:
            try:
                rc, out, _ = self.shell(cmd, timeout=5)
                if rc == 0 and "YES" in out:
                    self._jb_cache = True
                    return True
            except Exception:
                continue

        if self.ssh_host and self.ssh_user == "root":
            self._jb_cache = True
            return True

        self._jb_cache = False
        return False

    def get_root_method(self) -> str:
        if self._jb_method_cache:
            return self._jb_method_cache

        checks = [
            ("test -d /var/jb && echo YES", "rootless"),
            ("test -f /bootstrap/usr/bin/apt && echo YES", "palera1n"),
            ("test -f /.installed_dopamine && echo YES", "dopamine"),
            ("dpkg -l | grep -qi 'unc0ver' && echo YES", "unc0ver"),
            ("dpkg -l | grep -qi 'checkra1n' && echo YES", "checkra1n"),
            ("test -f /Applications/Sileo.app/Sileo && echo YES", "sileo-based"),
            ("test -f /Applications/Cydia.app/Cydia && echo YES", "cydia-based"),
        ]
        for cmd, name in checks:
            try:
                rc, out, _ = self.shell(cmd, timeout=5)
                if rc == 0 and "YES" in out:
                    self._jb_method_cache = name
                    return name
            except Exception:
                continue

        if self.is_rooted():
            self._jb_method_cache = "unknown"
            return "unknown"
        return ""

    # ── logging ────────────────────────────────────────────────────────

    def start_log_capture(self, *, pid: int = 0, package: str = "",
                          output_file: str | Path = "") -> bool:
        self.stop_log_capture()

        if shutil.which("idevicesyslog") and self.device_id:
            cmd = ["idevicesyslog", "-u", self.device_id]
            if package:
                cmd.extend(["-m", package])
        elif self.ssh_host:
            remote_cmd = "syslog -w 0"
            cmd = self._sshpass_wrap(self._ssh_cmd() + [remote_cmd])
        else:
            return False

        if output_file:
            self._syslog_file = Path(output_file)
            fh = self._syslog_file.open("w", encoding="utf-8")
        else:
            fh = None
            self._syslog_buf = []

        try:
            self._syslog_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception as exc:
            log.warning("syslog start failed: %s", exc)
            if fh:
                fh.close()
            return False

        def _drain():
            for line in self._syslog_proc.stdout:
                stripped = line.rstrip("\n")
                if package and package.lower() not in stripped.lower():
                    continue
                if pid and f"[{pid}]" not in stripped:
                    continue
                if fh:
                    fh.write(stripped + "\n")
                else:
                    self._syslog_buf.append(stripped)
            if fh:
                fh.close()

        self._syslog_thread = threading.Thread(target=_drain, daemon=True)
        self._syslog_thread.start()
        return True

    def stop_log_capture(self) -> str:
        if self._syslog_proc:
            try:
                self._syslog_proc.kill()
                self._syslog_proc.wait(timeout=5)
            except Exception:
                pass
            self._syslog_proc = None

        if self._syslog_thread:
            self._syslog_thread.join(timeout=3)
            self._syslog_thread = None

        if self._syslog_file and self._syslog_file.exists():
            try:
                return self._syslog_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return ""
        text = "\n".join(self._syslog_buf)
        self._syslog_buf = []
        return text

    def get_logs_since(self, timestamp: str, *, package: str = "") -> str:
        if shutil.which("idevicesyslog") and self.device_id:
            try:
                r = subprocess.run(
                    ["idevicesyslog", "-u", self.device_id, "-d"],
                    capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    lines = r.stdout.splitlines()
                    if package:
                        lines = [l for l in lines if package.lower() in l.lower()]
                    return "\n".join(lines)
            except Exception:
                pass

        rc, out, _ = self.shell(
            f"syslog -T '{timestamp}' 2>/dev/null || "
            f"log show --start '{timestamp}' --style syslog 2>/dev/null | head -5000",
            timeout=15)
        if rc == 0 and package:
            return "\n".join(l for l in out.splitlines()
                             if package.lower() in l.lower())
        return out if rc == 0 else ""

    # ── network ────────────────────────────────────────────────────────

    def get_ip_address(self) -> str:
        if self.ssh_host:
            rc, out, _ = self.shell(
                "ifconfig en0 2>/dev/null | grep 'inet ' | awk '{print $2}'", timeout=5)
            if rc == 0 and out.strip():
                return out.strip()

        if shutil.which("ideviceinfo") and self.device_id:
            try:
                r = self._idevice("ideviceinfo", "-k", "WiFiAddress")
                if r.returncode == 0 and r.stdout.strip():
                    pass
            except Exception:
                pass

        return self.ssh_host or ""

    def set_proxy(self, host: str, port: int) -> bool:
        if not self.ssh_host:
            return False
        rc, _, _ = self.shell(
            f"networksetup -setwebproxy Wi-Fi {host} {port} 2>/dev/null; "
            f"networksetup -setsecurewebproxy Wi-Fi {host} {port} 2>/dev/null")
        return rc == 0

    def clear_proxy(self) -> bool:
        if not self.ssh_host:
            return False
        rc, _, _ = self.shell(
            "networksetup -setwebproxystate Wi-Fi off 2>/dev/null; "
            "networksetup -setsecurewebproxystate Wi-Fi off 2>/dev/null")
        return rc == 0

    # ── frida ──────────────────────────────────────────────────────────

    def check_frida(self) -> bool:
        if not shutil.which("frida"):
            return False
        rc, out, _ = self.shell("ps -A | grep frida-server | grep -v grep")
        return "frida-server" in out

    def ensure_frida_server(self) -> bool:
        if self.check_frida():
            return True

        rc, out, _ = self.shell("ls /usr/sbin/frida-server 2>/dev/null || "
                                "ls /usr/local/bin/frida-server 2>/dev/null || "
                                "ls /var/jb/usr/sbin/frida-server 2>/dev/null")
        if rc != 0 or not out.strip():
            log.warning("frida-server not found on device — install via Cydia/Sileo")
            return False

        server_path = out.strip().splitlines()[0]
        self.shell(f"chmod 755 {server_path}", root=True)
        self.shell(f"nohup {server_path} &", root=True, timeout=5)
        time.sleep(2)
        return self.check_frida()

    # ── memory ─────────────────────────────────────────────────────────

    def dump_process_memory(self, pid: int, output_dir: str | Path) -> Optional[Path]:
        if not self.is_rooted():
            log.warning("Memory dump requires jailbreak")
            return None

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        dump_file = out_path / f"memdump_{pid}.bin"

        remote_dump = f"/tmp/_quill_memdump_{pid}"

        rc, _, _ = self.shell(
            f"gdb -batch -ex 'attach {pid}' -ex 'generate-core-file {remote_dump}' "
            f"-ex 'detach' 2>/dev/null || "
            f"lldb -b -o 'process attach --pid {pid}' "
            f"-o 'process save-core {remote_dump}' -o 'detach' 2>/dev/null",
            root=True, timeout=60)

        if self.pull(remote_dump, str(dump_file)):
            self.shell(f"rm -f {remote_dump}", root=True)
            return dump_file

        return None

    def read_proc_maps(self, pid: int) -> str:
        rc, out, _ = self.shell(
            f"vmmap {pid} 2>/dev/null || "
            f"cat /proc/{pid}/maps 2>/dev/null",
            root=True, timeout=10)
        return out if rc == 0 else ""

    # ── clipboard ──────────────────────────────────────────────────────

    def get_clipboard(self) -> str:
        rc, out, _ = self.shell(
            "pbpaste 2>/dev/null", timeout=5)
        if rc == 0 and out.strip():
            return out.strip()
        return ""
