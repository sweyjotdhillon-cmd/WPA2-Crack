#!/usr/bin/env python3
"""
WPA2-Crack unified CLI tool for Android/Termux & Linux offline userspace operations.
"""

import argparse
import sys
import os

from wpa2crack.system import print_doctor_report
from wpa2crack.benchmark import print_benchmark_report
from wpa2crack.pcap import extract_handshake, PCAPError
from wpa2crack.cracker import crack, CrackerError
from wpa2crack.radio import get_radio_backend, RadioBackendError
from wpa2crack.password_strength import evaluate_password_strength

def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPA2-Crack: WPA2 4-Way Handshake Cracker & PCAP Analysis (Termux/ARM64 Port)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # doctor
    subparsers.add_parser("doctor", help="Check system, Android/Termux, Python, and dependency diagnostics")

    # benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run local WPA2 PBKDF2/PTK/MIC CPU benchmark")
    bench_parser.add_argument("-w", "--workers", type=int, default=None, help="Number of CPU worker processes")

    # crack
    crack_parser = subparsers.add_parser("crack", help="Crack WPA2 passphrase using PCAP capture and wordlist")
    crack_parser.add_argument("-p", "--pcap", required=True, help="Path to PCAP file containing EAPOL 4-way handshake")
    crack_parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    crack_parser.add_argument("-c", "--workers", type=int, default=None, help="Number of CPU worker processes")

    # password-strength
    strength_parser = subparsers.add_parser("password-strength", help="Defensively evaluate candidate passphrase strength")
    strength_parser.add_argument("passphrase", help="Passphrase string to evaluate")

    # scan (privileged radio)
    scan_parser = subparsers.add_parser("scan", help="Scan for nearby Wi-Fi networks (live radio - unsupported on non-root Android)")
    scan_parser.add_argument("-i", "--interface", required=True, help="Network interface")

    # capture (privileged radio)
    cap_parser = subparsers.add_parser("capture", help="Capture 4-way handshake (live radio - unsupported on non-root Android)")
    cap_parser.add_argument("-i", "--interface", required=True, help="Network interface")
    cap_parser.add_argument("-b", "--bssid", required=True, help="Access point BSSID")
    cap_parser.add_argument("-c", "--channel", type=int, required=True, help="Channel (1-13)")
    cap_parser.add_argument("-o", "--output", required=False, help="Output PCAP file")

    # deauth (privileged radio)
    deauth_parser = subparsers.add_parser("deauth", help="Send deauthentication packets (live radio - unsupported on non-root Android)")
    deauth_parser.add_argument("-i", "--interface", required=True, help="Network interface")
    deauth_parser.add_argument("-b", "--bssid", required=True, help="Access point BSSID")
    deauth_parser.add_argument("-d", "--client", default="ff:ff:ff:ff:ff:ff", help="Client MAC to target")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "doctor":
        print_doctor_report()

    elif args.command == "benchmark":
        print_benchmark_report(workers=args.workers)

    elif args.command == "password-strength":
        res = evaluate_password_strength(args.passphrase)
        print("=== Defensive Password Strength Report ===")
        print(f"Passphrase    : {res['passphrase']}")
        print(f"Length        : {res['length']} chars (Valid WPA2: {res['valid_wpa2_length']})")
        print(f"Entropy       : {res['entropy_bits']} bits")
        print(f"Charset Size  : {res['charset_size']}")
        print(f"Rating        : {res['rating']} (Score: {res['score']}/10)")
        if res['warnings']:
            print("Warnings / Recommendations:")
            for warn in res['warnings']:
                print(f" - {warn}")
        print("==========================================")

    elif args.command == "crack":
        if not os.path.exists(args.pcap):
            sys.exit(f"[!] Error: PCAP file not found: {args.pcap}")
        if not os.path.exists(args.wordlist):
            sys.exit(f"[!] Error: Wordlist file not found: {args.wordlist}")

        try:
            handshake = extract_handshake(args.pcap)
        except PCAPError as e:
            sys.exit(f"[!] PCAP Error: {e}")
        except Exception as e:
            sys.exit(f"[!] Unexpected error loading PCAP: {e}")

        try:
            found_pwd, total_tried, elapsed = crack(handshake, args.wordlist, workers=args.workers)
        except CrackerError as e:
            sys.exit(f"[!] Cracker Error: {e}")

        if found_pwd:
            print(f"\n[+] Password found: {found_pwd} (took {elapsed:.2f} seconds, tried {total_tried} passwords)")
        else:
            print(f"\n[!] Password not found in wordlist (tried {total_tried} passwords in {elapsed:.2f} seconds)")

    elif args.command in ("scan", "capture", "deauth"):
        radio = get_radio_backend()
        try:
            if args.command == "scan":
                radio.start_scan(args.interface)
            elif args.command == "capture":
                radio.start_capture(args.interface, args.bssid, args.channel, args.output)
            elif args.command == "deauth":
                radio.send_deauth(args.interface, args.bssid, args.client)
        except RadioBackendError as e:
            sys.exit(f"\n[!] Live Wi-Fi Error:\n{e}\n")

if __name__ == "__main__":
    main()
