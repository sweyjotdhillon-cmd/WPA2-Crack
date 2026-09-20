# WPA2-Crack (Android Termux / ARM64 Production Port)

A production-quality Python 3.13 userspace application for offline WPA2 4-way handshake analysis, PCAP parsing, cryptographic key derivation, password strength evaluation, and CPU benchmarking in standard non-root **Android / Termux**.

---

## Primary Workflow: Non-Root Android Userspace

This application is built and optimized specifically for standard non-root Android running in **Termux** on ARM64 (`aarch64`) mobile platforms (such as MediaTek MT6835T with integrated Wi-Fi).

All core operations operate strictly in **userspace** using pure Python standard library routines and do not require root privileges, custom kernels, or modified Wi-Fi drivers.

---

## Feature Separation Matrix

### SUPPORTED ON NON-ROOT ANDROID USERSPACE

| Feature | Description | Primary Engine |
| :--- | :--- | :--- |
| **System Diagnostics** | Environment, RAM, CPU core count, and capability detection | `python main.py doctor` |
| **PCAP Validation** | Magic, endianness, version, snaplen, and linktype validation | `wpa2crack.pcap` (Native stdlib) |
| **802.11 / EAPOL Parsing** | Safe extraction of SSID, MACs, nonces, and MIC from PCAPs | Standard library `struct` |
| **Crypto Derivation** | PBKDF2 HMAC-SHA1 (4096 iter), PTK (PRF-512), MIC verification | Standard library `hashlib`/`hmac` |
| **Passphrase Evaluation** | Defensive security strength, entropy, and pattern analysis | `python main.py password-strength` |
| **CPU Benchmarking** | Warm-up phase, multi-trial, median throughput calculation | `python main.py benchmark` |
| **Wordlist Cracking** | Memory-safe line-by-line streaming across CPU processes | `python main.py crack` |
| **Automated Tests** | Full 20-point test suite with binary parser fixtures | `python -m unittest discover` |

---

### NOT AVAILABLE ON STOCK NON-ROOT ANDROID

The following privileged radio operations are **isolated behind a radio abstraction layer** (`UnsupportedAndroidBackend`) and are **NOT supported on stock non-root Android**:

- Monitor mode
- Raw 802.11 packet capture
- Packet injection
- Deauthentication packets
- Privileged channel switching / radio control

When executed in non-root Android/Termux, commands requesting live radio operations (`scan`, `capture`, `deauth`) cleanly return an explicit unsupported capability message rather than attempting illegal kernel calls or bypassing permissions.

---

## Termux Installation & Quick Start

### 1. Installation in Termux

Execute the following commands in standard Termux (no root or proot needed):

```bash
pkg update && pkg upgrade -y
pkg install python -y
git clone https://github.com/Njord0/WPA2-Crack.git
cd WPA2-Crack
```

### 2. Run System Diagnostics (`doctor`)

Check Android environment, Termux status, CPU count, physical vs process available RAM, and parser status:

```bash
python main.py doctor
```

### 3. Run CPU Benchmark (`benchmark`)

Measure local PBKDF2 HMAC-SHA1 key derivation throughput across CPU worker processes:

```bash
python main.py benchmark
```

Optionally specify worker count:

```bash
python main.py benchmark -w 4
```

### 4. Evaluate Passphrase Strength (`password-strength`)

Analyze a candidate passphrase against WPA2 standards, entropy, character sets, and common weak patterns:

```bash
python main.py password-strength "MyStrongPassphrase123!"
```

### 5. Offline Passphrase Cracking (`crack`)

Crack a WPA2 passphrase using an externally captured PCAP file and a wordlist:

```bash
python main.py crack -p capture.pcap -w wordlist.txt -c 2
```

---

## Running Automated Tests

Run the complete 20-point unit test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## Architecture Overview

```
WPA2-Crack/
├── main.py                     # Unified CLI entry point
├── wpa2crack/                  # Core Python package
│   ├── __init__.py
│   ├── system.py               # Android/Termux & hardware diagnostics
│   ├── pcap.py                 # Pure-Python stdlib PCAP/802.11/EAPOL parser
│   ├── crypto.py               # PBKDF2, PTK, and MIC calculation engine
│   ├── password_strength.py    # Defensive passphrase evaluation engine
│   ├── cracker.py              # Low-memory streaming multi-core cracker
│   ├── benchmark.py            # Warm-up & median CPU benchmark engine
│   └── radio.py                # RadioBackend abstraction (UnsupportedAndroidBackend)
└── tests/
    └── test_all.py             # 20-point comprehensive test suite
```
