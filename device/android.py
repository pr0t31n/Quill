"""Android device connector — ADB-based implementation."""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from device.base import AppInfo, DeviceConnector, DeviceInfo, ProcessInfo

log = logging.getLogger("quill.device.android")

_ADB_TIMEOUT = 15


def _adb_bin() -> str:
    return shutil.which("adb") or "adb"


class AndroidDevice(DeviceConnector):
    """ADB-backed device connector for Android."""

    def __init__(self, *, device_id: str = "", **kwargs):
        super().__init__(device_id=device_id, **kwargs)
        self._logcat_proc: Optional[subprocess.Popen] = None
        self._logcat_buf: list[str] = []
        self._logcat_file: Optional[Path] = None
        self._logcat_thread: Optional[threading.Thread] = None
        self._root_cache: Optional[bool] = None
        self._root_method_cache: str = ""

    def _adb(self, *args: str, timeout: int = _ADB_TIMEOUT) -> subprocess.CompletedProcess:
        cmd = [_adb_bin()]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _adb_shell(self, cmd: str, *, timeout: int = 30,
                   root: bool = False) -> subprocess.CompletedProcess:
        if root:
            cmd = f"su -c '{cmd}'"
        return self._adb("shell", cmd, timeout=timeout)

    # ── connection ──────────────────────────────────────────────────────

    def connect(self) -> bool:
        try:
            r = self._adb("devices")
            if r.returncode != 0:
                log.warning("adb devices failed: %s", r.stderr)
                return False
            lines = [l.strip() for l in r.stdout.strip().splitlines()[1:]
                     if l.strip() and "offline" not in l]
            if self.device_id:
                found = any(l.startswith(self.device_id) and "device" in l
                            for l in lines)
            else:
                found = any("device" in l for l in lines)
                if found and not self.device_id:
                    self.device_id = lines[0].split()[0]
            self._connected = found
            if found:
                log.info("Connected to Android device: %s", self.device_id)
            else:
                log.warning("Device not found in adb devices output")
            return found
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.warning("adb connect failed: %s", exc)
            return False

    def disconnect(self) -> None:
        self.stop_log_capture()
        self._connected = False

    def get_device_info(self) -> DeviceInfo:
        if self._info and self._info.device_id == self.device_id:
            return self._info

        def _prop(name: str) -> str:
            try:
                r = self._adb_shell(f"getprop {name}")
                return r.stdout.strip() if r.returncode == 0 else ""
            except Exception:
                return ""

        model = _prop("ro.product.model") or _prop("ro.product.name")
        os_version = _prop("ro.build.version.release")
        arch = _prop("ro.product.cpu.abi")
        hostname = _prop("net.hostname") or _prop("persist.sys.usb.config")

        ip = self.get_ip_address()
        ssid = ""
        try:
            r = self._adb_shell("dumpsys wifi | grep 'mWifiInfo'")
            m = re.search(r'SSID:\s*"?([^",]+)', r.stdout)
            if m:
                ssid = m.group(1).strip()
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

        api_level = _prop("ro.build.version.sdk")

        self._info = DeviceInfo(
            platform="android",
            device_id=self.device_id,
            model=model,
            os_version=os_version,
            rooted=rooted,
            root_method=root_method,
            arch=arch,
            hostname=hostname,
            ip_address=ip,
            wifi_ssid=ssid,
            usb_connected=True,
            frida_available=frida_ok,
            frida_version=frida_ver,
            extras={"api_level": api_level},
        )
        return self._info

    # ── shell ───────────────────────────────────────────────────────────

    def shell(self, cmd: str, *, timeout: int = 30,
              root: bool = False) -> tuple[int, str, str]:
        try:
            r = self._adb_shell(cmd, timeout=timeout, root=root)
            return (r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired:
            return (-1, "", "timeout")
        except Exception as exc:
            return (-1, "", str(exc))

    def shell_stream(self, cmd: str, *, timeout: int = 0,
                     root: bool = False):
        full_cmd = [_adb_bin()]
        if self.device_id:
            full_cmd.extend(["-s", self.device_id])
        shell_cmd = f"su -c '{cmd}'" if root else cmd
        full_cmd.extend(["shell", shell_cmd])
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
        try:
            r = self._adb("pull", "-a", remote_path, str(local_path), timeout=120)
            if r.returncode != 0:
                log.warning("adb pull failed for %s: %s", remote_path, r.stderr.strip())
                return False
            return True
        except (subprocess.TimeoutExpired, Exception) as exc:
            log.warning("adb pull error: %s", exc)
            return False

    def push(self, local_path: str | Path, remote_path: str) -> bool:
        try:
            r = self._adb("push", str(local_path), remote_path, timeout=120)
            return r.returncode == 0
        except Exception as exc:
            log.warning("adb push error: %s", exc)
            return False

    def file_exists(self, remote_path: str) -> bool:
        rc, _, _ = self.shell(f"[ -e '{remote_path}' ] && echo YES || echo NO")
        return rc == 0

    def list_dir(self, remote_path: str) -> list[str]:
        rc, out, _ = self.shell(f"ls -1 '{remote_path}'")
        if rc != 0:
            return []
        return [l.strip() for l in out.splitlines() if l.strip()]

    # ── app management ─────────────────────────────────────────────────

    def get_app_info(self, package: str) -> Optional[AppInfo]:
        rc, out, _ = self.shell(f"dumpsys package {package}", timeout=15)
        if rc != 0 or not out.strip():
            return None

        info = AppInfo(package_name=package)

        m = re.search(r"versionName=(\S+)", out)
        if m:
            info.version = m.group(1)
        m = re.search(r"versionCode=(\d+)", out)
        if m:
            info.version_code = m.group(1)
        m = re.search(r"codePath=(\S+)", out)
        if m:
            info.install_path = m.group(1)
        m = re.search(r"dataDir=(\S+)", out)
        if m:
            info.data_dir = m.group(1)
        m = re.search(r"userId=(\d+)", out)
        if m:
            info.uid = int(m.group(1))
        m = re.search(r"targetSdk=(\d+)", out)
        if m:
            info.target_sdk = int(m.group(1))
        m = re.search(r"minSdk=(\d+)", out)
        if m:
            info.min_sdk = int(m.group(1))

        flags_match = re.search(r"flags=\[\s*([^\]]*)\]", out)
        if flags_match:
            flags_str = flags_match.group(1).upper()
            info.debuggable = "DEBUGGABLE" in flags_str
            info.backup_allowed = "ALLOW_BACKUP" in flags_str
        else:
            info.debuggable = "FLAG_DEBUGGABLE" in out.upper()
            info.backup_allowed = "android:allowBackup=\"true\"" in out.lower()

        perms = []
        in_perms = False
        for line in out.splitlines():
            ls = line.strip()
            if "requested permissions:" in ls.lower():
                in_perms = True
                continue
            if in_perms:
                if ls.startswith("android.permission.") or ls.startswith("com."):
                    perms.append(ls.rstrip(":"))
                elif not ls:
                    in_perms = False
        info.permissions = perms

        return info

    def get_app_data_dir(self, package: str) -> str:
        rc, out, _ = self.shell(f"run-as {package} pwd 2>/dev/null || echo /data/data/{package}")
        path = out.strip().splitlines()[-1] if out.strip() else ""
        if path:
            return path
        return f"/data/data/{package}"

    def list_running_processes(self) -> list[ProcessInfo]:
        rc, out, _ = self.shell("ps -A -o PID,NAME 2>/dev/null || ps")
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
        rc, out, _ = self.shell(f"pidof {package}")
        return rc == 0 and out.strip().isdigit()

    def launch_app(self, package: str) -> bool:
        rc, out, _ = self.shell(
            f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
        return rc == 0 and "No activities found" not in out

    def kill_app(self, package: str) -> bool:
        rc, _, _ = self.shell(f"am force-stop {package}")
        return rc == 0

    # ── root / jailbreak ───────────────────────────────────────────────

    def is_rooted(self) -> bool:
        if self._root_cache is not None:
            return self._root_cache

        checks = [
            ("which su", lambda o: "/su" in o),
            ("magisk --version 2>/dev/null", lambda o: bool(o.strip())),
            ("[ -f /system/xbin/su ] && echo YES", lambda o: "YES" in o),
            ("[ -f /sbin/su ] && echo YES", lambda o: "YES" in o),
            ("getprop ro.build.selinux", lambda _: False),
        ]
        for cmd, check in checks:
            try:
                rc, out, _ = self.shell(cmd, timeout=5)
                if rc == 0 and check(out):
                    self._root_cache = True
                    return True
            except Exception:
                continue

        self._root_cache = False
        return False

    def get_root_method(self) -> str:
        if self._root_method_cache:
            return self._root_method_cache

        checks = [
            ("magisk --version 2>/dev/null", "magisk"),
            ("[ -f /data/adb/ksu/version ] && cat /data/adb/ksu/version", "kernelsu"),
            ("[ -f /data/adb/ap/version ] && cat /data/adb/ap/version", "apatch"),
            ("[ -d /data/SuperSU ] && echo YES", "supersu"),
        ]
        for cmd, name in checks:
            try:
                rc, out, _ = self.shell(cmd, timeout=5)
                if rc == 0 and out.strip():
                    self._root_method_cache = name
                    return name
            except Exception:
                continue

        if self.is_rooted():
            self._root_method_cache = "unknown"
            return "unknown"
        return ""

    # ── logging ────────────────────────────────────────────────────────

    def start_log_capture(self, *, pid: int = 0, package: str = "",
                          output_file: str | Path = "") -> bool:
        self.stop_log_capture()

        cmd = [_adb_bin()]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.append("logcat")

        if pid:
            cmd.extend(["--pid", str(pid)])

        if output_file:
            self._logcat_file = Path(output_file)
            fh = self._logcat_file.open("w", encoding="utf-8")
        else:
            fh = None
            self._logcat_buf = []

        try:
            self._logcat_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception as exc:
            log.warning("logcat start failed: %s", exc)
            if fh:
                fh.close()
            return False

        def _drain():
            for line in self._logcat_proc.stdout:
                stripped = line.rstrip("\n")
                if package and package not in stripped:
                    continue
                if fh:
                    fh.write(stripped + "\n")
                else:
                    self._logcat_buf.append(stripped)
            if fh:
                fh.close()

        self._logcat_thread = threading.Thread(target=_drain, daemon=True)
        self._logcat_thread.start()
        return True

    def stop_log_capture(self) -> str:
        if self._logcat_proc:
            try:
                self._logcat_proc.kill()
                self._logcat_proc.wait(timeout=5)
            except Exception:
                pass
            self._logcat_proc = None

        if self._logcat_thread:
            self._logcat_thread.join(timeout=3)
            self._logcat_thread = None

        if self._logcat_file and self._logcat_file.exists():
            try:
                return self._logcat_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return ""
        text = "\n".join(self._logcat_buf)
        self._logcat_buf = []
        return text

    def get_logs_since(self, timestamp: str, *, package: str = "") -> str:
        cmd = f"logcat -d -T '{timestamp}'"
        rc, out, _ = self.shell(cmd, timeout=15)
        if rc != 0 or not out:
            return ""
        if package:
            return "\n".join(l for l in out.splitlines() if package in l)
        return out

    # ── network ────────────────────────────────────────────────────────

    def get_ip_address(self) -> str:
        rc, out, _ = self.shell("ip addr show wlan0", timeout=5)
        if rc == 0:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
            if m:
                return m.group(1)
        rc, out, _ = self.shell("ifconfig wlan0", timeout=5)
        if rc == 0:
            m = re.search(r"inet addr:(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        return ""

    def set_proxy(self, host: str, port: int) -> bool:
        rc, _, _ = self.shell(f"settings put global http_proxy {host}:{port}")
        return rc == 0

    def clear_proxy(self) -> bool:
        rc, _, _ = self.shell("settings put global http_proxy :0")
        if rc != 0:
            rc, _, _ = self.shell("settings delete global http_proxy")
        return rc == 0

    # ── frida ──────────────────────────────────────────────────────────

    def check_frida(self) -> bool:
        if not shutil.which("frida"):
            return False
        rc, out, _ = self.shell("ps -A 2>/dev/null | grep frida-server || ps | grep frida-server")
        return "frida-server" in out

    def ensure_frida_server(self) -> bool:
        if self.check_frida():
            return True

        rc, out, _ = self.shell("ls /data/local/tmp/frida-server* 2>/dev/null")
        if rc != 0 or not out.strip():
            log.warning("frida-server binary not found on device — "
                        "push it to /data/local/tmp/frida-server first")
            return False

        server_path = out.strip().splitlines()[0]
        self.shell(f"chmod 755 {server_path}", root=True)
        self.shell(f"nohup {server_path} &", root=True, timeout=5)
        time.sleep(2)
        return self.check_frida()

    # ── memory ─────────────────────────────────────────────────────────

    def dump_process_memory(self, pid: int, output_dir: str | Path) -> Optional[Path]:
        if not self.is_rooted():
            log.warning("Memory dump requires root access")
            return None

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        dump_file = out_path / f"memdump_{pid}.bin"

        maps = self.read_proc_maps(pid)
        if not maps:
            return None

        remote_dump = f"/data/local/tmp/_quill_memdump_{pid}"
        script = (
            f"cat /proc/{pid}/maps | grep 'rw-p' | head -50 | "
            f"while IFS='-' read start rest; do "
            f"  end=$(echo $rest | cut -d' ' -f1); "
            f"  dd if=/proc/{pid}/mem bs=1 skip=$((16#$start)) "
            f"     count=$(($((16#$end))-$((16#$start)))) "
            f"     >> {remote_dump} 2>/dev/null; "
            f"done"
        )
        self.shell(script, root=True, timeout=60)
        if self.pull(remote_dump, str(dump_file)):
            self.shell(f"rm -f {remote_dump}", root=True)
            return dump_file

        return None

    def read_proc_maps(self, pid: int) -> str:
        rc, out, _ = self.shell(f"cat /proc/{pid}/maps", root=True, timeout=10)
        return out if rc == 0 else ""

    # ── clipboard ──────────────────────────────────────────────────────

    def get_clipboard(self) -> str:
        rc, out, _ = self.shell(
            "service call clipboard 2 i32 1 i32 0 2>/dev/null", root=True, timeout=5)
        if rc == 0 and "String16" in out:
            parts = re.findall(r"'([^']*)'", out)
            if parts:
                return "".join(parts).replace(".", "")

        rc, out, _ = self.shell(
            "am broadcast -a clipper.get 2>/dev/null", timeout=5)
        if rc == 0 and "data=" in out:
            m = re.search(r'data="([^"]*)"', out)
            if m:
                return m.group(1)

        return ""
