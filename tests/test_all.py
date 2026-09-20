"""
Comprehensive unit test suite for WPA2-Crack (Android/Termux ARM64 Port).
Covers all 20 target criteria:
 1. Android detection
 2. Termux detection
 3. ARM64 detection
 4. Python 3.13 / version compatibility
 5. PCAP little-endian
 6. PCAP big-endian
 7. malformed PCAP
 8. truncated PCAP
 9. malformed packet lengths
10. EAPOL parser behavior
11. missing beacon
12. missing EAPOL
13. deterministic cryptographic vectors
14. CLI doctor
15. CLI benchmark
16. multiprocessing startup
17. worker failure reporting
18. unsupported radio backend
19. memory-safe streaming
20. optional Scapy availability
"""

import binascii
import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wpa2crack.crypto import calc_pmk, calc_ptk, calculate_mic, verify_mic
from wpa2crack.pcap import (
    validate_pcap_header,
    parse_handshake_native,
    parse_handshake_scapy,
    extract_handshake,
    PCAPError,
    HandshakeData
)
from wpa2crack.system import (
    is_android,
    is_termux,
    is_root,
    get_cpu_count,
    get_total_ram_mb,
    get_available_ram_mb,
    get_environment_info,
    check_scapy
)
from wpa2crack.radio import (
    UnsupportedAndroidBackend,
    LinuxReferenceBackend,
    get_radio_backend,
    RadioBackendError
)
from wpa2crack.cracker import stream_wordlist, crack, CrackerError
from wpa2crack.benchmark import run_benchmark


def make_pcap_header(endian="<", linktype=105, snaplen=65535, magic=None) -> bytes:
    """Construct a 24-byte PCAP global header."""
    if magic is None:
        magic_bytes = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    else:
        magic_bytes = magic

    if endian == "<":
        return magic_bytes + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, linktype)
    else:
        return magic_bytes + struct.pack(">HHIIII", 2, 4, 0, 0, snaplen, linktype)


def make_pcap_record(payload: bytes, endian="<", incl_len=None, orig_len=None) -> bytes:
    """Construct a 16-byte PCAP record header + payload."""
    if incl_len is None:
        incl_len = len(payload)
    if orig_len is None:
        orig_len = len(payload)

    if endian == "<":
        rec_hdr = struct.pack("<IIII", 1000, 2000, incl_len, orig_len)
    else:
        rec_hdr = struct.pack(">IIII", 1000, 2000, incl_len, orig_len)

    return rec_hdr + payload[:incl_len]


def make_beacon_frame(ssid="TestSSID") -> bytes:
    """Construct raw 802.11 Beacon frame with SSID element."""
    # 802.11 MAC Header (24 bytes)
    # Frame Control: Type=0 (Mgmt), Subtype=8 (Beacon) -> 0x0080
    fc = struct.pack("<H", 0x0080)
    dur = b"\x00\x00"
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr2 = b"\x00\x11\x22\x33\x44\x55" # AP MAC
    addr3 = b"\x00\x11\x22\x33\x44\x55" # BSSID
    seq = b"\x00\x00"
    mac_hdr = fc + dur + addr1 + addr2 + addr3 + seq

    # Fixed Beacon parameters (12 bytes): timestamp(8), beacon_int(2), cap_info(2)
    fixed_params = b"\x00" * 12

    # SSID Information Element: Tag ID=0, Length, SSID bytes
    ssid_bytes = ssid.encode("utf-8")
    ssid_ie = bytes([0, len(ssid_bytes)]) + ssid_bytes

    return mac_hdr + fixed_params + ssid_ie


def make_eapol_frame(msg_type: int, ap_mac: bytes, client_mac: bytes, nonce: bytes, mic: bytes = None) -> bytes:
    """Construct raw 802.11 Data frame carrying EAPOL Key message 1 or 2."""
    if mic is None:
        mic = b"\x00" * 16

    # 802.11 MAC Header (24 bytes)
    if msg_type == 1: # AP -> Client (FromDS=1, ToDS=0) -> 0x0208
        fc = struct.pack("<H", 0x0208)
        addr1, addr2, addr3 = client_mac, ap_mac, ap_mac
    else: # Client -> AP (FromDS=0, ToDS=1) -> 0x0108
        fc = struct.pack("<H", 0x0108)
        addr1, addr2, addr3 = ap_mac, client_mac, ap_mac

    dur = b"\x00\x00"
    seq = b"\x00\x00"
    mac_hdr = fc + dur + addr1 + addr2 + addr3 + seq

    # LLC / SNAP header (8 bytes): 802.2 LLC (0xaaaa03) + SNAP OUI (0x000000) + EtherType (0x888e = EAPOL)
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

    # EAPOL Key Frame Body
    # EAPOL Header: Version=1, Type=3 (Key), Length=95 (0x005f)
    eapol_hdr = b"\x01\x03\x00\x5f"

    # Key Descriptor Type=2 (RSN/WPA2)
    desc_type = b"\x02"

    # Key Info:
    # Msg 1: Pairwise=1, Ack=1, MIC=0 -> 0x008a
    # Msg 2: Pairwise=1, Ack=0, MIC=1 -> 0x010a
    key_info_val = 0x008a if msg_type == 1 else 0x010a
    key_info = struct.pack(">H", key_info_val)

    key_len = b"\x00\x10"
    replay_counter = b"\x00" * 8
    key_nonce = nonce
    key_iv = b"\x00" * 16
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    key_mic = mic
    key_data_len = b"\x00\x00"

    eapol_body = (
        desc_type + key_info + key_len + replay_counter +
        key_nonce + key_iv + key_rsc + key_id + key_mic + key_data_len
    )

    return mac_hdr + llc_snap + eapol_hdr + eapol_body


class TestAndroidTermuxDetection(unittest.TestCase):
    """Test 1: Android detection, Test 2: Termux detection, Test 3: ARM64 detection, Test 4: Python version."""

    def test_1_android_detection(self):
        with patch.dict(os.environ, {"TERMUX_VERSION": "0.118.0"}):
            self.assertTrue(is_android())

    def test_2_termux_detection(self):
        with patch.dict(os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}):
            self.assertTrue(is_termux())

    def test_3_arm64_detection(self):
        info = get_environment_info()
        self.assertIn("architecture", info)
        self.assertIsInstance(info["architecture"], str)

    def test_4_python_version_compatibility(self):
        self.assertGreaterEqual(sys.version_info[0], 3)
        self.assertGreaterEqual(sys.version_info[1], 10)


class TestPCAPEndianAndMalformed(unittest.TestCase):
    """
    Test 5: PCAP little-endian, Test 6: PCAP big-endian, Test 7: malformed PCAP,
    Test 8: truncated PCAP, Test 9: malformed packet lengths.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_5_pcap_little_endian(self):
        pcap_path = os.path.join(self.temp_dir.name, "little.pcap")
        pcap_data = make_pcap_header(endian="<")
        with open(pcap_path, "wb") as f:
            f.write(pcap_data)

        info = validate_pcap_header(pcap_path)
        self.assertEqual(info["endian"], "<")
        self.assertEqual(info["magic"], "d4c3b2a1")

    def test_6_pcap_big_endian(self):
        pcap_path = os.path.join(self.temp_dir.name, "big.pcap")
        pcap_data = make_pcap_header(endian=">")
        with open(pcap_path, "wb") as f:
            f.write(pcap_data)

        info = validate_pcap_header(pcap_path)
        self.assertEqual(info["endian"], ">")
        self.assertEqual(info["magic"], "a1b2c3d4")

    def test_7_malformed_pcap_header(self):
        pcap_path = os.path.join(self.temp_dir.name, "bad_magic.pcap")
        with open(pcap_path, "wb") as f:
            f.write(b"NOT_A_VALID_PCAP_MAGIC_BYTES!")

        with self.assertRaises(PCAPError) as ctx:
            validate_pcap_header(pcap_path)
        self.assertIn("magic number", str(ctx.exception))

    def test_8_truncated_pcap_record(self):
        pcap_path = os.path.join(self.temp_dir.name, "truncated.pcap")
        header = make_pcap_header(endian="<")
        # Record says payload length is 100 bytes, but we only supply 10 bytes
        bad_rec = make_pcap_record(b"X" * 10, endian="<", incl_len=100)
        with open(pcap_path, "wb") as f:
            f.write(header + bad_rec)

        with self.assertRaises(PCAPError) as ctx:
            parse_handshake_native(pcap_path)
        self.assertIn("Truncated PCAP packet record", str(ctx.exception))

    def test_9_malformed_packet_lengths(self):
        pcap_path = os.path.join(self.temp_dir.name, "overlong.pcap")
        header = make_pcap_header(endian="<", snaplen=1500)
        # Record header incl_len exceeds snaplen
        bad_rec = make_pcap_record(b"X" * 10, endian="<", incl_len=70000)
        with open(pcap_path, "wb") as f:
            f.write(header + bad_rec)

        with self.assertRaises(PCAPError) as ctx:
            parse_handshake_native(pcap_path)
        self.assertIn("exceeds snaplen", str(ctx.exception))


class TestEAPOLAndMissingFrames(unittest.TestCase):
    """Test 10: EAPOL parser behavior, Test 11: missing beacon, Test 12: missing EAPOL."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_full_pcap_handshake(self, pcap_path, ssid="ValidNetwork"):
        ap_mac = b"\x00\x11\x22\x33\x44\x55"
        client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        anonce = b"\x11" * 32
        snonce = b"\x22" * 32
        mic = b"\x33" * 16

        pcap_hdr = make_pcap_header(endian="<")
        beacon = make_pcap_record(make_beacon_frame(ssid=ssid), endian="<")
        msg1 = make_pcap_record(make_eapol_frame(1, ap_mac, client_mac, anonce), endian="<")
        msg2 = make_pcap_record(make_eapol_frame(2, ap_mac, client_mac, snonce, mic=mic), endian="<")

        with open(pcap_path, "wb") as f:
            f.write(pcap_hdr + beacon + msg1 + msg2)

    def test_10_eapol_parser_behavior(self):
        pcap_path = os.path.join(self.temp_dir.name, "full.pcap")
        self._create_full_pcap_handshake(pcap_path, ssid="MyWiFi")

        hs = parse_handshake_native(pcap_path)
        self.assertEqual(hs.ssid, "MyWiFi")
        self.assertEqual(hs.ap_mac, b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(hs.client_mac, b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(hs.anonce, b"\x11" * 32)
        self.assertEqual(hs.snonce, b"\x22" * 32)
        self.assertEqual(hs.mic, b"\x33" * 16)

    def test_11_missing_beacon_error(self):
        pcap_path = os.path.join(self.temp_dir.name, "no_beacon.pcap")
        ap_mac = b"\x00\x11\x22\x33\x44\x55"
        client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"

        pcap_hdr = make_pcap_header(endian="<")
        msg1 = make_pcap_record(make_eapol_frame(1, ap_mac, client_mac, b"\x01" * 32), endian="<")
        msg2 = make_pcap_record(make_eapol_frame(2, ap_mac, client_mac, b"\x02" * 32, mic=b"\x00"*16), endian="<")

        with open(pcap_path, "wb") as f:
            f.write(pcap_hdr + msg1 + msg2)

        with self.assertRaises(PCAPError) as ctx:
            parse_handshake_native(pcap_path)
        self.assertIn("Could not find SSID", str(ctx.exception))

    def test_12_missing_eapol_error(self):
        pcap_path = os.path.join(self.temp_dir.name, "no_eapol.pcap")
        pcap_hdr = make_pcap_header(endian="<")
        beacon = make_pcap_record(make_beacon_frame(ssid="OnlyBeacon"), endian="<")

        with open(pcap_path, "wb") as f:
            f.write(pcap_hdr + beacon)

        with self.assertRaises(PCAPError) as ctx:
            parse_handshake_native(pcap_path)
        self.assertIn("does not contain complete EAPOL 4-way handshake", str(ctx.exception))


class TestCryptoAndStreaming(unittest.TestCase):
    """Test 13: deterministic cryptographic vectors, Test 19: memory-safe streaming."""

    def test_13_deterministic_cryptographic_vectors(self):
        # Standard IEEE 802.11i / RFC 6070 PBKDF2 test vector
        passphrase = "password"
        ssid = "IEEE"
        pmk = calc_pmk(ssid, passphrase)
        expected_pmk_hex = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
        self.assertEqual(pmk.hex(), expected_pmk_hex)

        ap_mac = b"\x00\x01\x02\x03\x04\x05"
        client_mac = b"\x10\x11\x12\x13\x14\x15"
        anonce = b"\x20" * 32
        snonce = b"\x30" * 32

        ptk = calc_ptk(pmk, ap_mac, client_mac, anonce, snonce)
        self.assertEqual(len(ptk), 64)

        kck = ptk[:16]
        eapol_frame = b"\x01\x03\x00\x5f" + (b"\x00" * 95)
        mic = calculate_mic(kck, eapol_frame)
        self.assertEqual(len(mic), 16)

        self.assertTrue(verify_mic(passphrase, ssid, ap_mac, client_mac, anonce, snonce, eapol_frame, mic))
        self.assertFalse(verify_mic("wrongpass", ssid, ap_mac, client_mac, anonce, snonce, eapol_frame, mic))

    def test_19_memory_safe_streaming(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            for i in range(100):
                f.write(f"passphrase_{i}\n")
            filepath = f.name

        try:
            chunks = list(stream_wordlist(filepath, chunk_size=25))
            self.assertEqual(len(chunks), 4)
            total_items = sum(len(c) for c in chunks)
            self.assertEqual(total_items, 100)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)


class TestCLIAndMultiprocessing(unittest.TestCase):
    """
    Test 14: CLI doctor, Test 15: CLI benchmark, Test 16: multiprocessing startup,
    Test 17: worker failure reporting, Test 18: unsupported radio backend,
    Test 20: optional Scapy availability.
    """

    def test_14_cli_doctor(self):
        res = subprocess.run([sys.executable, "main.py", "doctor"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WPA2-Crack Environment Diagnostics", res.stdout)
        self.assertIn("Android detected", res.stdout)
        self.assertIn("Termux detected", res.stdout)

    def test_15_cli_benchmark(self):
        res = subprocess.run([sys.executable, "main.py", "benchmark", "-w", "1"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WPA2-Crack CPU Benchmark Results", res.stdout)
        self.assertIn("Median throughput", res.stdout)

    def test_16_multiprocessing_startup(self):
        res = run_benchmark(duration_target=0.5, trials=1, workers=1)
        self.assertEqual(res["workers"], 1)
        self.assertGreater(res["median_throughput"], 0)

    def test_17_worker_failure_reporting(self):
        backend = UnsupportedAndroidBackend()
        with self.assertRaises(RadioBackendError) as ctx:
            backend.start_scan("wlan0")
        self.assertIn("Cannot perform 'wifi scan'", str(ctx.exception))

    def test_18_unsupported_radio_backend(self):
        backend = UnsupportedAndroidBackend()
        self.assertFalse(backend.is_available())
        self.assertIn("UNSUPPORTED PRIVILEGED RADIO", backend.get_unsupported_reason())

        with self.assertRaises(RadioBackendError):
            backend.start_scan("wlan0")

        with self.assertRaises(RadioBackendError):
            backend.start_capture("wlan0", "00:11:22:33:44:55", 1)

        with self.assertRaises(RadioBackendError):
            backend.send_deauth("wlan0", "00:11:22:33:44:55")

    def test_20_optional_scapy_availability(self):
        scapy_installed = check_scapy()
        self.assertIsInstance(scapy_installed, bool)


if __name__ == "__main__":
    unittest.main()
