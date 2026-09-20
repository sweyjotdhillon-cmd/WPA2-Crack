#!/usr/bin/env python3
"""
Legacy wrapper script for WPA2 password cracking.
Author: Njörd
Updated for WPA2-Crack Termux / Python 3.13 Port.
"""

import argparse
import os
import sys

from wpa2crack.pcap import extract_handshake, PCAPError
from wpa2crack.cracker import crack

def main():
    parser = argparse.ArgumentParser(description="Find Wi-Fi password from captured EAPOL 4-Way Handshake PCAP")
    parser.add_argument("-w", "--wordlist", help="The wordlist for the bruteforce", required=True)
    parser.add_argument("-p", "--pcap", help="The pcap where EAPOL authentication is", required=True)
    parser.add_argument("-c", "--workers", help="CPU worker process count", type=int, default=None)
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        sys.exit(f"[!] Error: PCAP file not found: {args.pcap}")
    if not os.path.exists(args.wordlist):
        sys.exit(f"[!] Error: Wordlist file not found: {args.wordlist}")

    try:
        handshake = extract_handshake(args.pcap)
    except PCAPError as e:
        sys.exit(f"[!] PCAP Error: {e}")
    except Exception as e:
        sys.exit(f"[!] Error loading PCAP: {e}")

    found_pwd, total_tried, elapsed = crack(handshake, args.wordlist, workers=args.workers)

    if found_pwd:
        print(f"\n[+] Password found: {found_pwd} ({elapsed:.2f} seconds)")
        print(f"[+] Tried {total_tried} passwords")
    else:
        print(f"\n[!] Password not found (tried {total_tried} passwords in {elapsed:.2f} seconds)")

if __name__ == "__main__":
    main()
