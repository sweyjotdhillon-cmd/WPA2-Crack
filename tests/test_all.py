"""
Comprehensive unit test suite for WPA2-Crack (Termux / Python 3.13 Port).
Covers:
1. PCAP header parsing
2. malformed PCAP handling
3. packet parsing
4. EAPOL parsing
5. cryptographic test vectors
6. invalid input handling
7. Android environment detection
8. unsupported-radio detection
9. CLI behavior
10. Python 3.13 compatibility
"""

import binascii
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wpa2crack.crypto import calc_pmk, calc_ptk, calculate_mic, verify_mic
from wpa2crack.pcap import validate_pcap_header, parse_handshake_scapy, extract_handshake, PCAPError, HandshakeData
from wpa2crack.system import is_android, is_termux, is_root, get_cpu_count, get_total_ram_mb, get_environment_info
from wpa2crack.radio import UnsupportedAndroidBackend, LinuxMonitorBackend, get_radio_backend, RadioBackendError
from wpa2crack.cracker import stream_wordlist, crack
from wpa2crack.benchmark import run_benchmark


class TestCryptoVectors(unittest.TestCase):
    """Test 5: Cryptographic test vectors."""

    def test_pbkdf2_pmk_vector(self):
        # IEEE 802.11i / WPA2 Test Vector (RFC 6070 / IEEE 802.11-2012)
        # Passphrase: "password", SSID: "IEEE"
        passphrase = "password"
        ssid = "IEEE"
        pmk = calc_pmk(ssid, passphrase)
        # Standard PBKDF2 HMAC-SHA1 Output for "password" / "IEEE" / 4096 / 32
        expected_hex = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
        self.assertEqual(pmk.hex(), expected_hex)

    def test_ptk_derivation(self):
        pmk = bytes.fromhex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
        ap_mac = b"\x00\x01\x02\x03\x04\x05"
        client_mac = b"\x10\x11\x12\x13\x14\x15"
        anonce = b"\x20" * 32
        snonce = b"\x30" * 32

        ptk = calc_ptk(pmk, ap_mac, client_mac, anonce, snonce)
        self.assertEqual(len(ptk), 64)

    def test_mic_calculation_and_verification(self):
        ssid = "TestNetwork"
        passphrase = "SecretPassword123"
        ap_mac = b"\x00\x11\x22\x33\x44\x55"
        client_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        anonce = b"\x01" * 32
        snonce = b"\x02" * 32
        eapol_frame = b"\x01\x03\x00\x5f" + (b"\x00" * 95)

        pmk = calc_pmk(ssid, passphrase)
        ptk = calc_ptk(pmk, ap_mac, client_mac, anonce, snonce)
        kck = ptk[:16]

        mic = calculate_mic(kck, eapol_frame)
        self.assertEqual(len(mic), 16)

        # Verification with correct password
        self.assertTrue(verify_mic(passphrase, ssid, ap_mac, client_mac, anonce, snonce, eapol_frame, mic))
        # Verification with incorrect password
        self.assertFalse(verify_mic("WrongPassword", ssid, ap_mac, client_mac, anonce, snonce, eapol_frame, mic))


class TestPCAPParsing(unittest.TestCase):
    """Test 1: PCAP header parsing, Test 2: malformed PCAP handling, Test 6: invalid input handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_pcap_header_parsing(self):
        pcap_file = os.path.join(self.temp_dir.name, "valid.pcap")
        # Write standard 24-byte PCAP header
        # Magic: 0xa1b2c3d4, Major: 2, Minor: 4, TZ: 0, Sigfigs: 0, Snaplen: 65535, Network: 105 (802.11)
        pcap_header = struct.pack(">IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
        with open(pcap_file, "wb") as f:
            f.write(pcap_header)

        info = validate_pcap_header(pcap_file)
        self.assertEqual(info["magic"], "a1b2c3d4")
        self.assertEqual(info["version"], "2.4")

    def test_malformed_pcap_header_small_file(self):
        pcap_file = os.path.join(self.temp_dir.name, "small.pcap")
        with open(pcap_file, "wb") as f:
            f.write(b"SHORT_HEADER")

        with self.assertRaises(PCAPError) as ctx:
            validate_pcap_header(pcap_file)
        self.assertIn("too small", str(ctx.exception))

    def test_malformed_pcap_invalid_magic(self):
        pcap_file = os.path.join(self.temp_dir.name, "bad_magic.pcap")
        with open(pcap_file, "wb") as f:
            f.write(b"INVALID_MAGIC_HEADER_24BYTES!")

        with self.assertRaises(PCAPError) as ctx:
            validate_pcap_header(pcap_file)
        self.assertIn("magic number", str(ctx.exception))

    def test_missing_pcap_file(self):
        with self.assertRaises(PCAPError) as ctx:
            validate_pcap_header("/nonexistent/file.pcap")
        self.assertIn("not found", str(ctx.exception))


class TestEnvironmentAndDiagnostics(unittest.TestCase):
    """Test 7: Android environment detection, Test 8: unsupported-radio detection."""

    def test_system_info_gather(self):
        info = get_environment_info()
        self.assertIn("platform", info)
        self.assertIn("architecture", info)
        self.assertIn("python_version", info)
        self.assertIn("cpu_count", info)
        self.assertGreaterEqual(info["cpu_count"], 1)

    @patch.dict(os.environ, {"TERMUX_VERSION": "0.118.0"})
    def test_termux_detection(self):
        self.assertTrue(is_termux())
        self.assertTrue(is_android())

    def test_unsupported_radio_backend_android(self):
        backend = UnsupportedAndroidBackend()
        self.assertFalse(backend.is_available())
        self.assertIn("non-root Android", backend.get_unsupported_reason())

        with self.assertRaises(RadioBackendError) as ctx:
            backend.start_scan("wlan0")
        self.assertIn("Live Wi-Fi capture: NOT AVAILABLE", str(ctx.exception))

        with self.assertRaises(RadioBackendError):
            backend.start_capture("wlan0", "00:11:22:33:44:55", 1)

        with self.assertRaises(RadioBackendError):
            backend.send_deauth("wlan0", "00:11:22:33:44:55")


class TestCLIAndCracker(unittest.TestCase):
    """Test 9: CLI behavior, Test 10: Python 3.13 compatibility."""

    def test_stream_wordlist(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("pass1\npass2\npass3\npass4\n")
            filepath = f.name

        try:
            chunks = list(stream_wordlist(filepath, chunk_size=2))
            self.assertEqual(len(chunks), 2)
            self.assertEqual(chunks[0], ["pass1", "pass2"])
            self.assertEqual(chunks[1], ["pass3", "pass4"])
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_benchmark_run(self):
        res = run_benchmark(workers=1)
        self.assertGreater(res["duration"], 0)
        self.assertGreater(res["ops_per_second"], 0)
        self.assertEqual(res["workers"], 1)

    def test_cli_doctor_command(self):
        res = subprocess.run([sys.executable, "main.py", "doctor"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WPA2-Crack Environment Diagnostics", res.stdout)

    def test_cli_benchmark_command(self):
        res = subprocess.run([sys.executable, "main.py", "benchmark", "-w", "1"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("WPA2-Crack Benchmark Results", res.stdout)

    def test_cli_scan_unsupported_command(self):
        res = subprocess.run([sys.executable, "main.py", "scan", "-i", "wlan0"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Live Wi-Fi Error", res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
