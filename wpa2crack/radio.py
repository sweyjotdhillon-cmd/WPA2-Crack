"""
Radio backend abstraction layer for WPA2-Crack.
Isolates privileged radio operations (monitor mode, raw capture, packet injection, deauth).
"""

from abc import ABC, abstractmethod
from typing import NoReturn
import sys
from .system import is_android, is_root

class RadioBackendError(Exception):
    """Custom exception raised when radio operations are unsupported or failed."""
    pass

class RadioBackend(ABC):
    """Abstract base class for radio backends."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if live radio features are available."""
        pass

    @abstractmethod
    def get_unsupported_reason(self) -> str:
        """Get the reason why live radio operations are unsupported."""
        pass

    @abstractmethod
    def start_scan(self, interface: str) -> NoReturn:
        """Start Wi-Fi scanning on interface."""
        pass

    @abstractmethod
    def start_capture(self, interface: str, bssid: str, channel: int, output: str | None = None) -> NoReturn:
        """Start capturing 4-way handshakes on interface."""
        pass

    @abstractmethod
    def send_deauth(self, interface: str, bssid: str, client: str = "ff:ff:ff:ff:ff:ff") -> NoReturn:
        """Send deauthentication packets."""
        pass


class UnsupportedAndroidBackend(RadioBackend):
    """
    Backend representing unsupported live radio on non-root Android/Termux or unprivileged environments.
    Guarantees non-root Android never attempts privileged radio operations.
    """

    def __init__(self, reason: str | None = None):
        self.reason = reason or (
            "UNSUPPORTED PRIVILEGED RADIO CAPABILITY:\n"
            "Non-root Android userspace cannot access raw Wi-Fi radio interfaces, "
            "monitor mode, packet capture, packet injection, or deauthentication.\n"
            "This application operates strictly in userspace offline analysis mode on Android."
        )

    def is_available(self) -> bool:
        return False

    def get_unsupported_reason(self) -> str:
        return self.reason

    def _raise_error(self, operation_name: str) -> NoReturn:
        raise RadioBackendError(f"Cannot perform '{operation_name}':\n{self.reason}")

    def start_scan(self, interface: str) -> NoReturn:
        self._raise_error("wifi scan")

    def start_capture(self, interface: str, bssid: str, channel: int, output: str | None = None) -> NoReturn:
        self._raise_error("handshake capture")

    def send_deauth(self, interface: str, bssid: str, client: str = "ff:ff:ff:ff:ff:ff") -> NoReturn:
        self._raise_error("deauth packet injection")


class LinuxReferenceBackend(RadioBackend):
    """Reference backend for desktop Linux environments with root/monitor mode."""

    def is_available(self) -> bool:
        return not is_android() and is_root()

    def get_unsupported_reason(self) -> str:
        if is_android():
            return "Android userspace environment is strictly non-root/offline."
        if not is_root():
            return "Root privileges required for monitor mode and packet injection on desktop Linux."
        return ""

    def start_scan(self, interface: str) -> NoReturn:
        if not self.is_available():
            raise RadioBackendError(self.get_unsupported_reason())
        raise NotImplementedError("LinuxReferenceBackend requires scapy and root monitor interface on desktop Linux.")

    def start_capture(self, interface: str, bssid: str, channel: int, output: str | None = None) -> NoReturn:
        if not self.is_available():
            raise RadioBackendError(self.get_unsupported_reason())
        raise NotImplementedError("LinuxReferenceBackend requires scapy and root monitor interface on desktop Linux.")

    def send_deauth(self, interface: str, bssid: str, client: str = "ff:ff:ff:ff:ff:ff") -> NoReturn:
        if not self.is_available():
            raise RadioBackendError(self.get_unsupported_reason())
        raise NotImplementedError("LinuxReferenceBackend requires scapy and root monitor interface on desktop Linux.")

# Alias for backward compatibility
LinuxMonitorBackend = LinuxReferenceBackend


def get_radio_backend() -> RadioBackend:
    """Factory function to get appropriate radio backend for current system."""
    if is_android() or not is_root():
        return UnsupportedAndroidBackend()
    return LinuxReferenceBackend()
