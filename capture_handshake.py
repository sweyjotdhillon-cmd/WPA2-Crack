#!/usr/bin/env python3
"""
Legacy wrapper script for WPA2 4-Way Handshake capture.
Author: Njörd
Updated for WPA2-Crack Termux / Python 3.13 Port.
"""

import argparse
import sys
from wpa2crack.radio import get_radio_backend, RadioBackendError

def main():
    parser = argparse.ArgumentParser(description="Capture EAPOL authentication when client connects to AP")
    parser.add_argument("-i", "--interface", help="Network interface where packets will be sniffed", required=True)
    parser.add_argument("-b", "--bssid", help="Access point BSSID", required=True)
    parser.add_argument("-c", "--channel", help="Channel", type=int, required=True)
    parser.add_argument("-o", "--output", help="Output file", required=False)
    args = parser.parse_args()

    radio = get_radio_backend()
    try:
        radio.start_capture(args.interface, args.bssid, args.channel, args.output)
    except RadioBackendError as e:
        sys.exit(f"\n[!] Live Wi-Fi Error:\n{e}\n")

if __name__ == "__main__":
    main()
