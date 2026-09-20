"""
System and environment diagnostics module for WPA2-Crack (Android/Termux ARM64 Port).
"""

import os
import platform
import sys
import multiprocessing

def is_termux() -> bool:
    """Check if running in Termux environment on Android."""
    if os.environ.get("TERMUX_VERSION"):
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    return False

def is_android() -> bool:
    """Check if running on Android."""
    if is_termux():
        return True
    if os.path.exists("/system/bin/app_process") or os.path.exists("/system/bin/linker"):
        return True
    if "android" in platform.platform().lower():
        return True
    return False

def is_root() -> bool:
    """Check if running as root user."""
    if hasattr(os, "getuid"):
        return os.getuid() == 0
    return False

def get_cpu_count() -> int:
    """Get count of available CPU cores safely."""
    count = os.cpu_count()
    return count if count and count > 0 else 1

def get_total_ram_mb() -> int | None:
    """Safely detect total physical RAM in MB."""
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) // 1024
        except Exception:
            pass
    return None

def get_available_ram_mb() -> int | None:
    """Safely detect available system memory in MB (distinguished from total RAM)."""
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) // 1024
        except Exception:
            pass
    return None

def check_scapy() -> bool:
    """Check if optional Scapy dependency is installed and importable."""
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False

def check_multiprocessing() -> bool:
    """Check if multiprocessing process pool is operational in current environment."""
    try:
        cpu = get_cpu_count()
        return cpu >= 1
    except Exception:
        return False

def get_environment_info() -> dict:
    """Gather complete diagnostic environment information."""
    total_ram = get_total_ram_mb()
    avail_ram = get_available_ram_mb()

    total_ram_str = f"{total_ram} MB" if total_ram is not None else "Unknown"
    avail_ram_str = f"{avail_ram} MB" if avail_ram is not None else "Unknown"

    scapy_avail = check_scapy()
    root = is_root()
    android = is_android()
    termux = is_termux()

    if android and not root:
        radio_cap = "unsupported on non-root Android"
        radio_reason = (
            "Stock non-root Android permissions and Wi-Fi drivers block monitor mode, "
            "raw 802.11 frame capture, packet injection, and deauthentication. "
            "Use external PCAP captures for offline analysis."
        )
    elif not root:
        radio_cap = "unsupported (root privileges required)"
        radio_reason = "Root/sudo privileges required for live 802.11 monitor mode."
    else:
        radio_cap = "supported (root Linux reference)"
        radio_reason = "N/A"

    return {
        "platform": "Android / Termux" if (android or termux) else sys.platform,
        "is_android": android,
        "is_termux": termux,
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "root": root,
        "cpu_count": get_cpu_count(),
        "total_ram": total_ram_str,
        "available_ram": avail_ram_str,
        "pcap_parser_status": "available (native stdlib)",
        "scapy_available": scapy_avail,
        "crypto_engine": "available (hashlib/hmac)",
        "radio_capability": radio_cap,
        "radio_reason": radio_reason,
        "multiprocessing_status": "operational" if check_multiprocessing() else "unavailable"
    }

def print_doctor_report() -> None:
    """Print the environment diagnostic report (python main.py doctor)."""
    info = get_environment_info()
    print("=== WPA2-Crack Environment Diagnostics ===")
    print(f"Android detected        : {'Yes' if info['is_android'] else 'No'}")
    print(f"Termux detected         : {'Yes' if info['is_termux'] else 'No'}")
    print(f"Architecture            : {info['architecture']}")
    print(f"Python version          : {info['python_version']}")
    print(f"CPU count               : {info['cpu_count']}")
    print(f"Total physical RAM      : {info['total_ram']}")
    print(f"Available system memory : {info['available_ram']}")
    print(f"Root privileges         : {'Yes' if info['root'] else 'No'}")
    print(f"PCAP parser status      : {info['pcap_parser_status']}")
    print(f"Optional Scapy status   : {'installed' if info['scapy_available'] else 'not installed (optional)'}")
    print(f"Radio capability        : {info['radio_capability']}")
    if info['radio_reason'] != "N/A":
        print(f"  Note                  : {info['radio_reason']}")
    print(f"Multiprocessing status  : {info['multiprocessing_status']}")
    print("===========================================")
