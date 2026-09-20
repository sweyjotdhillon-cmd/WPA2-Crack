"""
Defensive Password Strength Evaluation module for WPA2-Crack.
Evaluates WPA2 passphrases against standards (8-63 characters), calculates entropy,
checks character set diversity, and identifies common weak patterns.
"""

import math
import re
from typing import Dict, Any, List

COMMON_WEAK_PASSWORDS = {
    "password", "12345678", "123456789", "1234567890", "qwertyuiop",
    "administrator", "admin123", "letmein1", "welcome1", "sunshine",
    "iloveyou", "password123", "wpa2password", "wireless1"
}

def evaluate_password_strength(passphrase: str) -> Dict[str, Any]:
    """
    Evaluates the defensive security strength of a candidate WPA2 passphrase.
    Returns a dictionary containing score, rating, entropy, length status, and recommendations.
    """
    reasons: List[str] = []
    length = len(passphrase)

    # WPA2 Standard Check: 8 to 63 ASCII characters (or 64 hex chars)
    valid_wpa2_len = (8 <= length <= 63)
    if length < 8:
        reasons.append("WPA2 requires a minimum passphrase length of 8 characters.")
    elif length > 63:
        reasons.append("WPA2 passphrase exceeds maximum length of 63 characters.")

    # Character set analysis
    has_lower = bool(re.search(r"[a-z]", passphrase))
    has_upper = bool(re.search(r"[A-Z]", passphrase))
    has_digit = bool(re.search(r"\d", passphrase))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", passphrase))

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    if charset_size == 0:
        charset_size = 1

    # Entropy calculation (bits = length * log2(charset_size))
    entropy = length * math.log2(charset_size)

    # Pattern checks
    lower_pwd = passphrase.lower()
    if lower_pwd in COMMON_WEAK_PASSWORDS:
        reasons.append("Passphrase is a known common weak password.")

    if re.search(r"1234|abcd|qwerty|asdf", lower_pwd):
        reasons.append("Passphrase contains obvious sequential patterns.")

    if re.search(r"(.)\1{3,}", passphrase):
        reasons.append("Passphrase contains 4 or more repeated consecutive characters.")

    # Rating determination
    score = 0
    if valid_wpa2_len:
        score += 2
        if length >= 12:
            score += 2
        if length >= 16:
            score += 1

    diversity_count = sum([has_lower, has_upper, has_digit, has_special])
    score += diversity_count

    if lower_pwd in COMMON_WEAK_PASSWORDS:
        score = 0
    elif entropy < 30:
        score = min(score, 2)

    if score <= 2:
        rating = "Very Weak"
    elif score <= 4:
        rating = "Weak"
    elif score <= 6:
        rating = "Moderate"
    elif score <= 8:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {
        "passphrase": passphrase,
        "length": length,
        "valid_wpa2_length": valid_wpa2_len,
        "entropy_bits": round(entropy, 2),
        "charset_size": charset_size,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "score": score,
        "rating": rating,
        "warnings": reasons
    }
