#!/usr/bin/env python3
"""
Legacy wrapper script for scanning nearby Wi-Fi networks.
Author: Njörd
Updated for WPA2-Crack Termux / Python 3.13 Port.
"""

import argparse
import sys
from wpa2crack.radio import get_radio_backend, RadioBackendError

def main():
    parser = argparse.ArgumentParser(description="Scan for Wi-Fi networks")
    parser.add_argument("-i", "--interface", help="Network interface where packets will be sniffed", required=True)
    args = parser.parse_args()

    radio = get_radio_backend()
    try:
        radio.start_scan(args.interface)
    except RadioBackendError as e:
        sys.exit(f"\n[!] Live Wi-Fi Error:\n{e}\n")

if __name__ == "__main__":
    main()
