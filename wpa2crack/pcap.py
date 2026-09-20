"""
PCAP and 802.11 / EAPOL packet parsing module.
Provides clean extraction of WPA2 4-way handshake metadata from PCAP files.
Includes robust error handling for malformed PCAPs or missing EAPOL frames.
"""

from dataclasses import dataclass
import binascii
import os
import struct
from typing import Dict, Any, Optional

class PCAPError(Exception):
    """Exception raised for PCAP parsing errors."""
    pass

@dataclass
class HandshakeData:
    ssid: str
    ap_mac: bytes        # 6 bytes
    client_mac: bytes    # 6 bytes
    anonce: bytes        # 32 bytes
    snonce: bytes        # 32 bytes
    mic: bytes           # 16 bytes
    eapol_zeroed: bytes  # Raw EAPOL frame bytes with MIC zeroed out

    def ap_mac_str(self) -> str:
        return ":".join(f"{b:02x}" for b in self.ap_mac)

    def client_mac_str(self) -> str:
        return ":".join(f"{b:02x}" for b in self.client_mac)


def validate_pcap_header(filepath: str) -> dict:
    """
    Validate PCAP header (magic number, version, linktype).
    Supports standard PCAP (0xa1b2c3d4) and byte-swapped PCAP.
    """
    if not os.path.exists(filepath):
        raise PCAPError(f"File not found: {filepath}")

    if os.path.getsize(filepath) < 24:
        raise PCAPError("File is too small to be a valid PCAP file (less than 24 bytes header)")

    with open(filepath, "rb") as f:
        header = f.read(24)

    magic = header[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    elif magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"): # nanosecond pcap
        endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
    else:
        raise PCAPError(f"Invalid PCAP magic number: {magic.hex()}")

    ver_major, ver_minor, tz, sigs, snaplen, network = struct.unpack(f"{endian}HHIIII", header[4:24])

    return {
        "magic": magic.hex(),
        "version": f"{ver_major}.{ver_minor}",
        "snaplen": snaplen,
        "network": network,
        "endian": endian
    }


def parse_handshake_scapy(filepath: str) -> HandshakeData:
    """
    Parse 4-way handshake from PCAP file using Scapy if available.
    Fallback or primary parser for 802.11 frame parsing.
    """
    try:
        from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11Elt, Raw
    except ImportError:
        raise PCAPError("Scapy is required to parse PCAP files.")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise PCAPError(f"Failed to read PCAP file: {e}")

    messages = {}
    ssid = None

    for packet in packets:
        if packet.haslayer(Dot11Beacon) and ssid is None:
            try:
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0: # SSID element
                        info = elt.info
                        if isinstance(info, bytes):
                            info = info.decode("utf-8", errors="ignore")
                        if info and "\x00" not in info:
                            ssid = info
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                pass

        if packet.haslayer(EAPOL):
            if not packet.haslayer(Raw):
                continue
            raw_load = bytes(packet[Raw].load)
            hex_load = binascii.hexlify(raw_load).decode()

            if len(hex_load) < 6:
                continue

            msg_type = hex_load[2:6]
            if msg_type == "008a":   # Message 1
                messages["msg1"] = packet
            elif msg_type == "010a": # Message 2
                messages["msg2"] = packet
            elif msg_type == "13ca": # Message 3
                messages["msg3"] = packet
            elif msg_type == "030a": # Message 4
                messages["msg4"] = packet

    if "msg1" not in messages or "msg2" not in messages:
        raise PCAPError("PCAP does not contain complete EAPOL 4-way handshake (Message 1 and Message 2 required).")

    msg1 = messages["msg1"]
    msg2 = messages["msg2"]

    # Extract MAC addresses
    # In 802.11: addr1 = RA (dst), addr2 = TA (src), addr3 = BSSID
    # For Msg 1 (AP -> Client): addr1 = Client MAC, addr2 = AP MAC (or BSSID)
    client_mac_str = msg1.addr1
    ap_mac_str = msg1.addr2

    if not client_mac_str or not ap_mac_str:
        raise PCAPError("Could not extract MAC addresses from EAPOL frames.")

    client_mac = binascii.unhexlify(client_mac_str.replace(":", ""))
    ap_mac = binascii.unhexlify(ap_mac_str.replace(":", ""))

    # Extract nonces
    msg1_raw = bytes(msg1[Raw].load)
    msg2_raw = bytes(msg2[Raw].load)

    if len(msg1_raw) < 45 or len(msg2_raw) < 45:
        raise PCAPError("EAPOL frame load is too short.")

    # Key Nonce offset in WPA EAPOL Key frame: byte 13 to 45 (32 bytes) relative to Raw payload
    anonce = msg1_raw[13:45]
    snonce = msg2_raw[13:45]

    # Extract MIC from Message 2
    # Full EAPOL frame has a 4-byte header (Version, Type, Length).
    # In full EAPOL frame (bytes(msg2[EAPOL])), Key MIC offset is byte 81 to 97 (16 bytes).
    # In Raw load (bytes(msg2[Raw].load)), Key MIC offset is byte 77 to 93 (16 bytes).
    msg2_eapol_bytes = bytes(msg2[EAPOL])
    if len(msg2_eapol_bytes) < 97:
        if len(msg2_raw) < 93:
            raise PCAPError("Invalid EAPOL Message 2 length for MIC extraction.")
        mic = msg2_raw[77:93]
        eapol_zeroed = msg2_eapol_bytes[:81] + (b"\x00" * 16) + msg2_eapol_bytes[97:] if len(msg2_eapol_bytes) >= 97 else b""
    else:
        mic = msg2_eapol_bytes[81:97]
        eapol_zeroed = msg2_eapol_bytes[:81] + (b"\x00" * 16) + msg2_eapol_bytes[97:]

    if not ssid:
        raise PCAPError("Could not extract SSID from Beacon frame in PCAP.")

    return HandshakeData(
        ssid=ssid,
        ap_mac=ap_mac,
        client_mac=client_mac,
        anonce=anonce,
        snonce=snonce,
        mic=mic,
        eapol_zeroed=eapol_zeroed
    )


def extract_handshake(filepath: str) -> HandshakeData:
    """Validate PCAP file and extract handshake data."""
    validate_pcap_header(filepath)
    return parse_handshake_scapy(filepath)
