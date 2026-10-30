"""Quill device abstraction layer — platform-agnostic mobile device operations."""
from device.base import DeviceConnector, DeviceInfo
from device.android import AndroidDevice
from device.ios import IOSDevice


def connect(platform: str, device_id: str = "", **kwargs) -> DeviceConnector:
    if platform == "android":
        return AndroidDevice(device_id=device_id, **kwargs)
    elif platform == "ios":
        return IOSDevice(device_id=device_id, **kwargs)
    raise ValueError(f"Unsupported platform: {platform}")
