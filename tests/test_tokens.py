#!/usr/bin/env python3
"""
JWT Security Tester — Test Suite
---------------------------------
Tests each vulnerability check with known-vulnerable tokens.
Run: python3 tests/test_tokens.py

These tokens are intentionally vulnerable for testing purposes only.
Never use weak secrets or none-algorithm tokens in production.
"""

import sys
import os
import json
import base64
import hmac
import hashlib

# Add parent directory to path so we can import jwt_tester
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwt_tester import (
    parse_jwt,
    check_none_algorithm,
    check_weak_secret,
    check_algorithm_confusion,
    check_sensitive_data,
    check_expiry,
    check_kid_injection,
    base64url_encode,
    base64url_decode,
    GREEN, RED, YELLOW, CYAN, BOLD, RESET
)


def make_jwt(header: dict, payload: dict, secret: str = "") -> str:
    """
    Helper to create a JWT token for testing.
    Used to generate vulnerable tokens without needing an external library.
    """
    # Encode header and payload
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}".encode()

    alg = header.get("alg", "HS256").upper()

    if alg == "NONE":
        # No signature for none algorithm
        return f"{h}.{p}."
    elif alg == "HS256":
        sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return f"{h}.{p}.{base64url_encode(sig)}"
    elif alg == "HS512":
        sig = hmac.new(secret.encode(), message, hashlib.sha512).digest()
        return f"{h}.{p}.{base64url_encode(sig)}"
    else:
        # For RS256 etc — just use a fake signature for testing
        return f"{h}.{p}.fakesignature"


def run_test(name: str, token: str, expected_status: str, check_func, *args):
    """Run a single test and report pass/fail."""
    print(f"\n  {CYAN}[TEST]{RESET} {name}")

    parsed = parse_jwt(token)
    if not parsed:
        print(f"  {RED}[FAIL]{RESET} Could not parse token")
        return False

    header, payload, signature, parts = parsed

    # Build correct args for each check function
    if check_func == check_none_algorithm:
        result = check_func(header, parts)
    elif check_func == check_weak_secret:
        result = check_func(header, parts, *args)
    elif check_func == check_algorithm_confusion:
        result = check_func(header, parts)
    elif check_func == check_sensitive_data:
        result = check_func(payload)
    elif check_func == check_expiry:
        result = check_func(payload)
    elif check_func == check_kid_injection:
        result = check_func(header)
    else:
        result = check_func(header, payload, parts, *args)

    actual_status = result.get("status", "UNKNOWN")

    if actual_status == expected_status:
        print(f"  {GREEN}[PASS]{RESET} Got expected status: {actual_status}")
        return True
    else:
        print(f"  {RED}[FAIL]{RESET} Expected '{expected_status}', got '{actual_status}'")
        print(f"  Details: {result.get('details', '')}")
        return False


def main():
    print(f"\n{BLUE if True else ''}{BOLD}JWT Security Tester — Test Suite{RESET}")
    print("=" * 50)

    BLUE = "\033[94m"
    wordlist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "common_secrets.txt")

    passed = 0
    failed = 0
    tests = []

    # ── Test 1: None algorithm token ──────────────────────────────────────────
    none_token = make_jwt(
        {"alg": "none", "typ": "JWT"},
        {"user": "admin", "role": "superuser"}
    )
    tests.append(("None Algorithm — Already None",
                   none_token, "CRITICAL", check_none_algorithm))

    # ── Test 2: Normal token — craft none attack ───────────────────────────────
    normal_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "role": "user", "exp": 9999999999},
        "strongrandomsecret"
    )
    tests.append(("None Algorithm — Craft Attack Token",
                   normal_token, "TEST_REQUIRED", check_none_algorithm))

    # ── Test 3: Weak secret ───────────────────────────────────────────────────
    weak_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "role": "admin", "exp": 9999999999},
        "secret"  # This is in our wordlist
    )
    tests.append(("Weak Secret — 'secret' in wordlist",
                   weak_token, "CRITICAL", check_weak_secret, wordlist))

    # ── Test 4: Strong secret ─────────────────────────────────────────────────
    strong_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "role": "user", "exp": 9999999999},
        "xK9#mP2$qR7!nL4@wY6&"  # Not in wordlist
    )
    tests.append(("Weak Secret — Strong secret not in wordlist",
                   strong_token, "PASS", check_weak_secret, wordlist))

    # ── Test 5: RS256 confusion ───────────────────────────────────────────────
    rs256_token = make_jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "rsa-key-1"},
        {"user": "rahul", "exp": 9999999999}
    )
    tests.append(("Algorithm Confusion — RS256 detected",
                   rs256_token, "WARNING", check_algorithm_confusion))

    # ── Test 6: Sensitive data ────────────────────────────────────────────────
    sensitive_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "password": "mypassword123", "exp": 9999999999},
        "secret"
    )
    tests.append(("Sensitive Data — password in payload",
                   sensitive_token, "WARNING", check_sensitive_data))

    # ── Test 7: Missing exp ───────────────────────────────────────────────────
    no_exp_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "role": "admin"},  # No exp field
        "secret"
    )
    tests.append(("Expiry — Missing exp claim",
                   no_exp_token, "CRITICAL", check_expiry))

    # ── Test 8: Expired token ─────────────────────────────────────────────────
    expired_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "exp": 1000000000},  # Year 2001 — long expired
        "secret"
    )
    tests.append(("Expiry — Expired token",
                   expired_token, "WARNING", check_expiry))

    # ── Test 9: kid path traversal ────────────────────────────────────────────
    kid_token = make_jwt(
        {"alg": "HS256", "typ": "JWT", "kid": "../../dev/null"},
        {"user": "rahul", "exp": 9999999999},
        ""  # Empty string — matches /dev/null key
    )
    tests.append(("kid Injection — Path traversal in kid",
                   kid_token, "CRITICAL", check_kid_injection))

    # ── Test 10: Clean token ──────────────────────────────────────────────────
    clean_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "rahul", "role": "user", "exp": 9999999999},
        "xK9#mP2$qR7!nL4@wY6&"
    )
    tests.append(("kid Injection — No kid present",
                   clean_token, "PASS", check_kid_injection))

    # ── Run all tests ─────────────────────────────────────────────────────────
    print(f"\n{BLUE}Running {len(tests)} tests...{RESET}")
    for test_args in tests:
        name, token, expected, func = test_args[0], test_args[1], test_args[2], test_args[3]
        extra = test_args[4:] if len(test_args) > 4 else ()
        if run_test(name, token, expected, func, *extra):
            passed += 1
        else:
            failed += 1

    # ── Results ───────────────────────────────────────────────────────────────
    print(f"\n{'=' * 50}")
    print(f"Results: {GREEN}{passed} passed{RESET}  {RED}{failed} failed{RESET}  (total: {passed + failed})")
    if failed == 0:
        print(f"{GREEN}{BOLD}All tests passed!{RESET}")
    else:
        print(f"{RED}{BOLD}{failed} test(s) failed. Check output above.{RESET}")
    print()


if __name__ == "__main__":
    main()
