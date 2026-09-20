"""
PCAP and 802.11 / EAPOL packet parsing module.
Provides native Python standard library extraction of WPA2 4-way handshake metadata.
Includes Scapy as an optional adapter.
"""

from dataclasses import dataclass
import binascii
import os
import struct
from typing import Dict, Any, Optional, Tuple, List

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
    Validate PCAP header (magic number, version, snaplen, linktype).
    Supports standard PCAP (0xa1b2c3d4) and byte-swapped/nanosecond PCAPs.
    """
    if not os.path.exists(filepath):
        raise PCAPError(f"File not found: {filepath}")

    try:
        filesize = os.path.getsize(filepath)
    except OSError as e:
        raise PCAPError(f"Error accessing PCAP file: {e}")

    if filesize < 24:
        raise PCAPError(f"File is too small to be a valid PCAP file ({filesize} bytes, minimum 24 bytes required)")

    try:
        with open(filepath, "rb") as f:
            header = f.read(24)
    except Exception as e:
        raise PCAPError(f"Failed to read PCAP header: {e}")

    if len(header) < 24:
        raise PCAPError("Truncated PCAP header")

    magic = header[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\x3c\x4d": # nanosecond pcap big-endian
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1": # nanosecond pcap little-endian
        endian = "<"
    else:
        raise PCAPError(f"Invalid PCAP magic number: 0x{magic.hex()}")

    try:
        ver_major, ver_minor, tz, sigs, snaplen, network = struct.unpack(f"{endian}HHIIII", header[4:24])
    except struct.error as e:
        raise PCAPError(f"Malformed PCAP global header: {e}")

    if ver_major != 2:
        raise PCAPError(f"Unsupported PCAP version: {ver_major}.{ver_minor} (only version 2.x is supported)")

    return {
        "magic": magic.hex(),
        "version": f"{ver_major}.{ver_minor}",
        "snaplen": snaplen,
        "network": network,
        "endian": endian
    }


def parse_handshake_native(filepath: str) -> HandshakeData:
    """
    Parse 4-way handshake from PCAP file using pure Python standard library.
    Supports Linktypes:
      - 105: LINKTYPE_IEEE802_11 (802.11 raw frames)
      - 127: LINKTYPE_IEEE802_11_RADIOTAP (Radiotap header + 802.11)
      - 1:   LINKTYPE_ETHERNET (Ethernet II frames)
    """
    header_info = validate_pcap_header(filepath)
    endian = header_info["endian"]
    linktype = header_info["network"]
    snaplen = header_info["snaplen"]

    if linktype not in (105, 127, 1):
        raise PCAPError(f"Unsupported PCAP link type: {linktype} (supported: 105=802.11, 127=Radiotap, 1=Ethernet)")

    ssid: Optional[str] = None
    msg1_data: Optional[dict] = None
    msg2_data: Optional[dict] = None

    try:
        f = open(filepath, "rb")
    except Exception as e:
        raise PCAPError(f"Failed opening PCAP file: {e}")

    try:
        f.seek(24) # Skip 24-byte PCAP header
        record_idx = 0
        while True:
            if ssid and msg1_data and msg2_data:
                break

            offset = f.tell()
            rec_header = f.read(16)
            if not rec_header:
                break # EOF reached cleanly
            if len(rec_header) < 16:
                raise PCAPError(f"Truncated PCAP packet record header at offset {offset}: read {len(rec_header)}/16 bytes")

            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec_header)
            except struct.error as e:
                raise PCAPError(f"Malformed PCAP packet record header at offset {offset}: {e}")

            if incl_len > snaplen or incl_len > 65535:
                raise PCAPError(f"Malformed packet length {incl_len} exceeds snaplen {snaplen}")

            if incl_len > orig_len:
                raise PCAPError(f"Invalid packet record length at offset {offset}: captured length ({incl_len}) exceeds original length ({orig_len})")

            pkt = f.read(incl_len)
            if len(pkt) < incl_len:
                raise PCAPError(f"Truncated PCAP packet record at offset {offset}: expected {incl_len} bytes, available {len(pkt)} bytes")

            record_idx += 1

            # Process frame based on linktype
            pkt_offset = 0
            if linktype == 127: # Radiotap header
                if len(pkt) < 4:
                    continue
                try:
                    rt_hdr_len = struct.unpack("<H", pkt[2:4])[0]
                except struct.error:
                    continue
                if rt_hdr_len > len(pkt):
                    continue
                pkt_offset = rt_hdr_len

            raw_frame = pkt[pkt_offset:]
            if not raw_frame:
                continue

            if linktype in (105, 127):
                # Parse 802.11 Frame
                if len(raw_frame) < 24:
                    continue

                fc = struct.unpack("<H", raw_frame[0:2])[0]
                frame_type = (fc >> 2) & 0x03
                frame_subtype = (fc >> 4) & 0x0F
                to_ds = (fc >> 8) & 0x01
                from_ds = (fc >> 9) & 0x01

                # Check Beacon or Probe Response for SSID
                if frame_type == 0 and frame_subtype in (8, 5): # Beacon (8) or Probe Response (5)
                    if len(raw_frame) > 36 and ssid is None:
                        # Skip 24-byte MAC header + 12-byte fixed parameters (timestamp 8, beacon int 2, capability 2)
                        ie_offset = 36
                        while ie_offset + 2 <= len(raw_frame):
                            tag_id = raw_frame[ie_offset]
                            tag_len = raw_frame[ie_offset + 1]
                            if ie_offset + 2 + tag_len > len(raw_frame):
                                break
                            if tag_id == 0: # SSID Tag
                                try:
                                    tag_val = raw_frame[ie_offset + 2:ie_offset + 2 + tag_len]
                                    decoded_ssid = tag_val.decode("utf-8", errors="ignore")
                                    if decoded_ssid and "\x00" not in decoded_ssid:
                                        ssid = decoded_ssid
                                except Exception:
                                    pass
                                break
                            ie_offset += 2 + tag_len

                # Check Data frame for EAPOL
                elif frame_type == 2: # Data frame
                    mac_hdr_len = 24
                    if to_ds and from_ds:
                        mac_hdr_len = 30
                    # Check QoS Control bit (subtype & 0x08)
                    if frame_subtype & 0x08:
                        mac_hdr_len += 2
                    # Check HT Control bit (bit 15 of FC)
                    if fc & 0x8000:
                        mac_hdr_len += 4

                    if len(raw_frame) < mac_hdr_len + 8:
                        continue

                    # Parse MAC addresses
                    # Addr1: RA/DA, Addr2: TA/SA, Addr3: BSSID
                    addr1 = raw_frame[4:10]
                    addr2 = raw_frame[10:16]
                    addr3 = raw_frame[16:22]

                    if to_ds == 0 and from_ds == 1: # AP -> Client
                        client_mac, ap_mac = addr1, addr2
                    elif to_ds == 1 and from_ds == 0: # Client -> AP
                        ap_mac, client_mac = addr1, addr2
                    else:
                        client_mac, ap_mac = addr1, addr2

                    llc_snap = raw_frame[mac_hdr_len:mac_hdr_len + 8]
                    # LLC (0xaaaa03), SNAP OUI (0x000000), EtherType (0x888e = EAPOL)
                    if llc_snap.startswith(b"\xaa\xaa\x03\x00\x00\x00") and llc_snap[6:8] == b"\x88\x8e":
                        eapol_payload = raw_frame[mac_hdr_len + 8:]
                        parsed_eapol = _parse_eapol_frame(eapol_payload, ap_mac, client_mac)
                        if parsed_eapol:
                            if parsed_eapol["msg_type"] == 1 and msg1_data is None:
                                msg1_data = parsed_eapol
                            elif parsed_eapol["msg_type"] == 2 and msg2_data is None:
                                msg2_data = parsed_eapol

            elif linktype == 1: # Ethernet frame
                if len(raw_frame) < 14:
                    continue
                dst_mac = raw_frame[0:6]
                src_mac = raw_frame[6:12]
                ethertype = raw_frame[12:14]
                if ethertype == b"\x88\x8e":
                    eapol_payload = raw_frame[14:]
                    parsed_eapol = _parse_eapol_frame(eapol_payload, src_mac, dst_mac)
                    if parsed_eapol:
                        if parsed_eapol["msg_type"] == 1 and msg1_data is None:
                            msg1_data = parsed_eapol
                        elif parsed_eapol["msg_type"] == 2 and msg2_data is None:
                            msg2_data = parsed_eapol
    finally:
        f.close()

    if not ssid:
        raise PCAPError("Could not find SSID in Beacon/Probe frames in PCAP file.")

    if not msg1_data or not msg2_data:
        raise PCAPError("PCAP file does not contain complete EAPOL 4-way handshake (Message 1 and Message 2 required).")

    return HandshakeData(
        ssid=ssid,
        ap_mac=msg1_data["ap_mac"],
        client_mac=msg1_data["client_mac"],
        anonce=msg1_data["nonce"],
        snonce=msg2_data["nonce"],
        mic=msg2_data["mic"],
        eapol_zeroed=msg2_data["eapol_zeroed"]
    )


def _parse_eapol_frame(eapol_bytes: bytes, ap_mac: bytes, client_mac: bytes) -> Optional[dict]:
    """
    Parse raw EAPOL frame bytes and extract message type, nonce, MIC, and zeroed EAPOL frame.
    """
    if not isinstance(eapol_bytes, (bytes, bytearray)) or len(eapol_bytes) < 99: # Min length for EAPOL-Key frame with MIC
        return None

    try:
        # EAPOL Header: Version (1), Type (1: 3=Key), Length (2)
        eapol_ver, eapol_type, eapol_len = struct.unpack(">BBH", eapol_bytes[0:4])
        if eapol_type != 3: # EAPOL-Key
            return None

        # Check declared EAPOL length vs actual payload (4 bytes header + eapol_len)
        if len(eapol_bytes) < 4 + eapol_len:
            return None

        key_descriptor_type = eapol_bytes[4]
        if key_descriptor_type not in (1, 2): # 1 = RC4, 2 = RSN (WPA2)
            return None

        key_info = struct.unpack(">H", eapol_bytes[5:7])[0]
        key_mic_bit = (key_info >> 8) & 0x01
        key_ack_bit = (key_info >> 7) & 0x01
        pairwise_bit = (key_info >> 3) & 0x01

        if not pairwise_bit:
            return None

        nonce = eapol_bytes[17:49]
        mic = eapol_bytes[81:97]

        # Validate non-zero nonces for Handshake Msg1 and Msg2
        if key_ack_bit == 1 and key_mic_bit == 0:
            msg_type = 1
            if nonce == b"\x00" * 32:
                return None
        elif key_ack_bit == 0 and key_mic_bit == 1:
            msg_type = 2
            if nonce == b"\x00" * 32 or mic == b"\x00" * 16:
                return None
        elif key_ack_bit == 1 and key_mic_bit == 1:
            msg_type = 3
        else:
            msg_type = 4

        eapol_zeroed = eapol_bytes[:81] + (b"\x00" * 16) + eapol_bytes[97:]

        return {
            "msg_type": msg_type,
            "ap_mac": ap_mac,
            "client_mac": client_mac,
            "nonce": nonce,
            "mic": mic,
            "eapol_zeroed": eapol_zeroed
        }
    except (struct.error, IndexError):
        return None


def parse_handshake_scapy(filepath: str) -> HandshakeData:
    """
    Optional Scapy adapter to parse 4-way handshake from PCAP file.
    """
    try:
        from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11Elt, Raw
    except ImportError:
        raise PCAPError("Scapy is not installed. Use native parser or install scapy.")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise PCAPError(f"Failed to read PCAP file via Scapy: {e}")

    messages = {}
    ssid = None

    for packet in packets:
        if packet.haslayer(Dot11Beacon) and ssid is None:
            try:
                elt = packet.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
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
            if msg_type == "008a":
                messages["msg1"] = packet
            elif msg_type == "010a":
                messages["msg2"] = packet
            elif msg_type == "13ca":
                messages["msg3"] = packet
            elif msg_type == "030a":
                messages["msg4"] = packet

    if "msg1" not in messages or "msg2" not in messages:
        raise PCAPError("PCAP does not contain complete EAPOL 4-way handshake (Message 1 and Message 2 required).")

    msg1 = messages["msg1"]
    msg2 = messages["msg2"]

    client_mac_str = msg1.addr1
    ap_mac_str = msg1.addr2

    if not client_mac_str or not ap_mac_str:
        raise PCAPError("Could not extract MAC addresses from EAPOL frames.")

    client_mac = binascii.unhexlify(client_mac_str.replace(":", ""))
    ap_mac = binascii.unhexlify(ap_mac_str.replace(":", ""))

    msg1_raw = bytes(msg1[Raw].load)
    msg2_raw = bytes(msg2[Raw].load)

    if len(msg1_raw) < 45 or len(msg2_raw) < 45:
        raise PCAPError("EAPOL frame load is too short.")

    anonce = msg1_raw[13:45]
    snonce = msg2_raw[13:45]

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


def extract_handshake(filepath: str, use_scapy: bool = False) -> HandshakeData:
    """Validate PCAP file and extract handshake data using native parser (or Scapy if requested)."""
    if use_scapy:
        validate_pcap_header(filepath)
        return parse_handshake_scapy(filepath)
    return parse_handshake_native(filepath)
