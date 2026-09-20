"""
Cryptographic CPU benchmarking module for WPA2-Crack (Android/Termux ARM64 Port).
Measures local PBKDF2/PTK/MIC computation throughput with warm-up, repeated trials,
and median throughput calculation.
"""

import time
import statistics
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Dict, Any, List

from .crypto import verify_mic
from .system import get_cpu_count, get_environment_info

def _benchmark_worker(iterations: int) -> int:
    """Worker function executing PBKDF2+PTK+MIC verification iterations."""
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
        pwd = f"{passphrase}_{i}"
        verify_mic(pwd, ssid, ap_mac, client_mac, anonce, snonce, eapol_zeroed, expected_mic)
        completed += 1

    return completed


def run_benchmark(duration_target: float = 2.0, trials: int = 3, workers: Optional[int] = None) -> Dict[str, Any]:
    """
    Runs CPU benchmark with warm-up, repeated measurements, and median calculation.
    """
    total_cpus = get_cpu_count()
    if workers is None or workers <= 0:
        workers = max(1, min(total_cpus // 2, 4)) if total_cpus > 1 else 1

    ops_per_batch = 10

    # 1. Warm-up phase
    try:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            warmup_futures = [executor.submit(_benchmark_worker, 2) for _ in range(workers)]
            for f in as_completed(warmup_futures):
                _ = f.result()
    except Exception as e:
        raise RuntimeError(f"Benchmark worker initialization error: {e}")

    # 2. Repeated Trial Runs
    trial_rates: List[float] = []
    total_ops_executed = 0
    total_duration_measured = 0.0

    for trial in range(trials):
        start_time = time.perf_counter()
        trial_ops = 0

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_benchmark_worker, ops_per_batch) for _ in range(workers)]
            for f in as_completed(futures):
                try:
                    trial_ops += f.result()
                except Exception as e:
                    raise RuntimeError(f"Worker failure during benchmark trial {trial+1}: {e}")

        elapsed = time.perf_counter() - start_time
        if elapsed > 0:
            rate = trial_ops / elapsed
            trial_rates.append(rate)

        total_ops_executed += trial_ops
        total_duration_measured += elapsed

    median_throughput = statistics.median(trial_rates) if trial_rates else 0.0
    info = get_environment_info()

    return {
        "duration": total_duration_measured,
        "total_operations": total_ops_executed,
        "trial_rates": trial_rates,
        "median_throughput": median_throughput,
        "ops_per_second": median_throughput,
        "workers": workers,
        "cpu_count": total_cpus,
        "trials": len(trial_rates),
        "python_version": info["python_version"],
        "architecture": info["architecture"],
        "platform": info["platform"]
    }


def print_benchmark_report(duration_target: float = 2.0, trials: int = 3, workers: Optional[int] = None) -> None:
    """Run benchmark and display detailed report."""
    print("[+] Warming up CPU workers & running WPA2 Cryptographic Benchmark...")
    res = run_benchmark(duration_target=duration_target, trials=trials, workers=workers)

    print("\n=== WPA2-Crack CPU Benchmark Results ===")
    print(f"Platform: {res['platform']}")
    print(f"Architecture: {res['architecture']}")
    print(f"Python version: {res['python_version']}")
    print(f"Worker processes: {res['workers']} (of {res['cpu_count']} available CPU cores)")
    print(f"Completed trials: {res['trials']}")
    print(f"Total operations: {res['total_operations']}")
    print(f"Total time elapsed: {res['duration']:.3f} seconds")
    print(f"Trial rates (ops/s): {', '.join(f'{r:.2f}' for r in res['trial_rates'])}")
    print(f"Median throughput: {res['median_throughput']:.2f} ops/sec")
    print("========================================")
    print("Note: Benchmark measures local PBKDF2 HMAC-SHA1 key derivation throughput.")
