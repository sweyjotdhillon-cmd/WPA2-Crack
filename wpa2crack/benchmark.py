"""
Cryptographic CPU benchmarking module for WPA2-Crack.
Measures local PBKDF2/PTK/MIC computation throughput.
"""

import time
import sys
import platform
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

from .crypto import verify_mic
from .system import get_cpu_count, get_environment_info

def _benchmark_worker(iterations: int) -> int:
    """Run `iterations` PBKDF2+PTK+MIC verification ops in a single process."""
    # Deterministic test parameters
    ssid = "BenchmarkNetwork"
    passphrase = "BenchmarkPassword123"
    ap_mac = b"\x00\x11\x22\x33\x44\x55"
    client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    anonce = b"\x01" * 32
    snonce = b"\x02" * 32
    eapol_zeroed = b"\x00" * 99
    expected_mic = b"\x00" * 16

    completed = 0
    for i in range(iterations):
        # We vary the candidate slightly to prevent compiler/caching optimizations
        pwd = f"{passphrase}_{i}"
        verify_mic(pwd, ssid, ap_mac, client_mac, anonce, snonce, eapol_zeroed, expected_mic)
        completed += 1

    return completed


def run_benchmark(duration_target: float = 3.0, workers: Optional[int] = None) -> dict:
    """
    Run cryptographic CPU benchmark across specified number of workers.
    Measures operations/second for WPA2 PBKDF2/PTK/MIC key derivation.
    """
    total_cpus = get_cpu_count()
    if workers is None or workers <= 0:
        workers = max(1, min(total_cpus // 2, 4)) if total_cpus > 1 else 1

    ops_per_worker = 15  # WPA2 PBKDF2 (4096 sha1) takes ~10-20ms per candidate on mobile CPU

    start_time = time.perf_counter()
    completed_ops = 0

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_benchmark_worker, ops_per_worker) for _ in range(workers)]
        for future in as_completed(futures):
            completed_ops += future.result()

    elapsed = time.perf_counter() - start_time

    # Calculate throughput
    ops_per_sec = completed_ops / elapsed if elapsed > 0 else 0.0

    info = get_environment_info()

    return {
        "duration": elapsed,
        "total_operations": completed_ops,
        "ops_per_second": ops_per_sec,
        "workers": workers,
        "cpu_count": total_cpus,
        "python_version": info["python_version"],
        "architecture": info["architecture"],
        "platform": info["platform"]
    }


def print_benchmark_report(workers: Optional[int] = None) -> None:
    """Run benchmark and display results (python main.py benchmark)."""
    print("[+] Running WPA2 Cryptographic Benchmark...")
    res = run_benchmark(workers=workers)

    print("\n=== WPA2-Crack Benchmark Results ===")
    print(f"Platform: {res['platform']}")
    print(f"Architecture: {res['architecture']}")
    print(f"Python: {res['python_version']}")
    print(f"Workers: {res['workers']} / {res['cpu_count']} CPUs")
    print(f"Total Operations: {res['total_operations']}")
    print(f"Duration: {res['duration']:.3f} seconds")
    print(f"Throughput: {res['ops_per_second']:.2f} ops/sec")
    print("====================================")
    print("Note: Benchmark measures local PBKDF2 HMAC-SHA1 key derivation rate.")
