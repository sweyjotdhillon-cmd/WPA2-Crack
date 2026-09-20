"""
System and environment diagnostics module for WPA2-Crack.
"""

import os
import platform
import sys
import shutil

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
    """Safely detect available/total RAM in MB without requiring root or external dependencies."""
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

def check_scapy() -> bool:
    """Check if Scapy is installed and importable."""
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False

def get_environment_info() -> dict:
    """Gather diagnostic environment information."""
    os_name = "Android / Termux" if (is_android() or is_termux()) else sys.platform
    ram_mb = get_total_ram_mb()
    ram_str = f"{ram_mb} MB" if ram_mb is not None else "Unknown"

    scapy_avail = check_scapy()
    root = is_root()

    return {
        "platform": os_name,
        "is_android": is_android(),
        "is_termux": is_termux(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "root": root,
        "cpu_count": get_cpu_count(),
        "ram": ram_str,
        "scapy_available": scapy_avail,
        "offline_pcap": "available",
        "crypto_engine": "available",
        "live_monitor_mode": "available" if (root and not is_android()) else "unavailable",
        "live_monitor_reason": (
            "non-root Android does not expose the required privileged monitor/raw 802.11 interface to this application."
            if (is_android() and not root)
            else ("root privileges required" if not root else "N/A")
        )
    }

def print_doctor_report() -> None:
    """Print the environment diagnostic report (python main.py doctor)."""
    info = get_environment_info()
    print("=== WPA2-Crack Environment Diagnostics ===")
    print(f"Platform: {info['platform']}")
    print(f"Architecture: {info['architecture']}")
    print(f"Python: {info['python_version']}")
    print(f"Root: {'yes' if info['root'] else 'no'}")
    print(f"Live monitor mode: {info['live_monitor_mode']}")
    if info['live_monitor_mode'] == "unavailable":
        print(f"  Reason: {info['live_monitor_reason']}")
    print(f"Offline PCAP processing: {info['offline_pcap']}")
    print(f"Cryptographic engine: {info['crypto_engine']}")
    print(f"CPU workers: {info['cpu_count']}")
    print(f"RAM: {info['ram']}")
    print(f"Scapy dependency: {'installed' if info['scapy_available'] else 'missing'}")
    print("===========================================")
