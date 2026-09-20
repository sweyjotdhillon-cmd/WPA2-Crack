"""
Cryptographic functions for WPA2 key derivation and Message Integrity Check (MIC) calculation.
Uses Python 3 standard library hashlib and hmac.
"""

import hashlib
import hmac

PKE_LABEL = b"Pairwise key expansion"

def calc_pmk(ssid: str | bytes, passphrase: str | bytes) -> bytes:
    """
    Calculate Pairwise Master Key (PMK) using PBKDF2 HMAC-SHA1.
    4096 iterations, 32 bytes output length.
    """
    if isinstance(ssid, str):
        ssid_bytes = ssid.encode("utf-8")
    else:
        ssid_bytes = ssid

    if isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode("utf-8")
    else:
        passphrase_bytes = passphrase

    return hashlib.pbkdf2_hmac("sha1", passphrase_bytes, ssid_bytes, 4096, 32)


def calc_ptk(pmk: bytes, ap_mac: bytes, client_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """
    Calculate Pairwise Transient Key (PTK) using PRF-512 (HMAC-SHA1).
    PTK length is 64 bytes (512 bits) for WPA2-Personal (CCMP/TKIP).
    Key Data = min(AP, Client) + max(AP, Client) + min(ANonce, SNonce) + max(ANonce, SNonce)
    """
    mac_min = min(ap_mac, client_mac)
    mac_max = max(ap_mac, client_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)

    key_data = mac_min + mac_max + nonce_min + nonce_max

    ptk = b""
    # PRF-512 needs 4 iterations of HMAC-SHA1 (20 bytes * 4 = 80 bytes -> sliced to 64 bytes)
    for i in range(4):
        msg = PKE_LABEL + b"\x00" + key_data + bytes([i])
        ptk += hmac.new(pmk, msg, hashlib.sha1).digest()

    return ptk[:64]


def calculate_mic(kck: bytes, eapol_frame_zeroed: bytes) -> bytes:
    """
    Calculate WPA2 MIC using HMAC-SHA1-128 over zeroed EAPOL frame.
    Returns 16 bytes raw MIC or hex string.
    """
    # KCK is the first 16 bytes of PTK (0..15)
    full_hmac = hmac.new(kck, eapol_frame_zeroed, hashlib.sha1).digest()
    return full_hmac[:16]


def verify_mic(passphrase: str | bytes, ssid: str | bytes, ap_mac: bytes, client_mac: bytes,
               anonce: bytes, snonce: bytes, eapol_frame_zeroed: bytes, expected_mic: bytes) -> bool:
    """
    Verify passphrase against expected MIC.
    """
    pmk = calc_pmk(ssid, passphrase)
    ptk = calc_ptk(pmk, ap_mac, client_mac, anonce, snonce)
    kck = ptk[:16]
    computed_mic = calculate_mic(kck, eapol_frame_zeroed)
    return computed_mic == expected_mic
