#!/usr/bin/env python3
"""Quill installer."""
import subprocess
import sys
import shutil

TOOL_NAME = "Quill"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)



def _dpkg_installed(pkg):
    try:
        r = subprocess.run(["dpkg", "-s", pkg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _rpm_installed(pkg):
    try:
        return subprocess.run(
            ["rpm", "-q", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        return False


def install_system_deps():
    """Ensure strings binary is present."""
    if sys.platform.startswith("linux") and shutil.which("apt-get"):
        if not shutil.which("strings"):
            if not _dpkg_installed("binutils"):
                _run(["apt-get", "install", "-y", "binutils"], check=False)


def install_pip_deps():
    print("[install] No Python packages required (uses stdlib only).")


def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)
    print(f"{TOOL_NAME} v0.2.0 — Installation")
    install_system_deps()
    install_pip_deps()
    print(f"\n{TOOL_NAME} installed.")
    print("Start with: python3 quill.py --ipa path/to/app.ipa")


if __name__ == "__main__":
    main()
