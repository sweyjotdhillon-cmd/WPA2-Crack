# WPA2-Crack (Android Termux / Python 3.13 Port)

A clean, reliable, non-root Android (Termux / ARM64) port of **WPA2-Crack** for offline 4-way handshake analysis, PCAP packet processing, cryptographic key derivation, and CPU benchmarking.

---

## Target Environment & Architecture

- **OS / Platform**: Android (ARM64 / aarch64) in Termux
- **Privilege Level**: NON-ROOT userspace
- **Python Version**: Python 3.13.x (compatible with Python >= 3.10)
- **Execution Mode**: CPU-only execution (multi-core streaming)
- **Dependencies**: Minimal standard-library reliance (`hashlib`, `hmac`, `struct`, `concurrent.futures`, `dataclasses`, `pathlib`). Optional dependency on `scapy>=2.5.0` for 802.11 frame extraction.

---

## Feature Matrix & Capability Separation

The application explicitly separates offline userspace processing from privileged live-radio operations.

| Feature Category | Capability Status | Description |
| :--- | :--- | :--- |
| **Offline PCAP Reading** | **SUPPORTED** | Parses 802.11 PCAP captures and extracts EAPOL 4-way handshakes |
| **PCAP Validation** | **SUPPORTED** | Verifies PCAP headers, magic bytes, snaplen, and frame integrity |
| **Cryptographic Engine** | **SUPPORTED** | PBKDF2 HMAC-SHA1 (4096 iterations), PTK derivation (PRF-512), WPA2 MIC verification |
| **CPU Benchmarking** | **SUPPORTED** | Measures local PBKDF2/PTK/MIC key derivation throughput across CPU cores |
| **Environment Diagnostics** | **SUPPORTED** | `python main.py doctor` reports Android/Termux, CPU count, RAM, and capabilities |
| **Wordlist Cracking** | **SUPPORTED** | Low-memory line-by-line wordlist streaming across configurable worker processes |
| **Live Wi-Fi Scanning** | *UNSUPPORTED* | Requires root & monitor mode (Not available on stock non-root Android) |
| **Handshake Capture** | *UNSUPPORTED* | Requires raw 802.11 packet sniffing in monitor mode |
| **Deauthentication** | *UNSUPPORTED* | Requires raw 802.11 packet injection |

When live radio commands (`scan`, `capture`, `deauth`) are executed on non-root Android, the system cleanly reports:
```
Live Wi-Fi capture: NOT AVAILABLE
Reason: non-root Android does not expose the required privileged monitor/raw 802.11 interface to this application.
Use an externally supplied PCAP/test fixture for offline analysis.
```

---

## Termux Installation Commands

Run the following commands inside Termux on your Android device:

```bash
pkg update && pkg upgrade -y
pkg install python libffi clang -y
git clone https://github.com/Njord0/WPA2-Crack.git
cd WPA2-Crack
pip install -r requirements.txt
```

---

## Usage & Commands

### 1. System Diagnostics (`doctor`)
Inspect system environment, Android/Termux detection, CPU count, RAM, and capability status:
```bash
python main.py doctor
```

### 2. Cryptographic CPU Benchmark (`benchmark`)
Measure local WPA2 PBKDF2 HMAC-SHA1 calculation speed:
```bash
python main.py benchmark
```
Optionally specify worker thread/process count:
```bash
python main.py benchmark -w 4
```

### 3. Passphrase Cracking (`crack`)
Perform offline cracking using a local PCAP file containing an EAPOL 4-way handshake and a wordlist:
```bash
python main.py crack -p handshake.pcap -w wordlist.txt -c 4
```

### 4. Legacy Script Wrappers
The original entry-point scripts are preserved for backwards compatibility and routed through the new architecture:
```bash
python crack_password.py -p handshake.pcap -w wordlist.txt
python capture_handshake.py -i wlan0 -b 00:11:22:33:44:55 -c 1
python scan_wifi.py -i wlan0
python deauth.py -i wlan0 -b 00:11:22:33:44:55
```

---

## Running Automated Tests

Run the complete test suite with `unittest`:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## Project Architecture

```
WPA2-Crack/
├── main.py                  # Main CLI entry point
├── crack_password.py        # Legacy wrapper script
├── capture_handshake.py     # Legacy wrapper script
├── deauth.py                # Legacy wrapper script
├── scan_wifi.py             # Legacy wrapper script
├── requirements.txt         # Dependency specification
├── README.md                # Documentation
├── wpa2crack/               # Core Python package
│   ├── __init__.py
│   ├── system.py            # Android/Termux & hardware diagnostics
│   ├── radio.py             # RadioBackend abstraction layer
│   ├── crypto.py            # PBKDF2, PTK, and MIC verification
│   ├── pcap.py              # PCAP header and 802.11 / EAPOL parser
│   ├── cracker.py           # Multi-process wordlist streaming cracker
│   └── benchmark.py         # CPU crypto benchmark engine
└── tests/                   # Automated unit tests
    └── test_all.py
```

---

## Known Android / Termux Limitations

1. **No Monitor Mode / Raw 802.11 Injection**: Stock Android Wi-Fi drivers and Android userspace permissions block monitor mode and raw socket packet injection without root and kernel patches.
2. **Offline-Only Focus**: Handshake PCAPs must be acquired on external hardware or supported devices and transferred to Termux for local offline analysis.
3. **RAM & Thermal Management**: The cracker uses line-by-line wordlist streaming to prevent out-of-memory errors on mobile devices.
