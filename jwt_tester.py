#!/usr/bin/env python3
"""
JWT Security Tester v2.0
-------------------------
Advanced CLI tool to test JSON Web Tokens for security vulnerabilities.

Checks:
  Original (v1):
    1.  None Algorithm Attack
    2.  Weak Secret Brute Force
    3.  Algorithm Confusion (RS256 -> HS256)
    4.  Sensitive Data in Payload
    5.  Missing / Expired exp Claim
    6.  kid Header Injection

  Advanced (v2):
    7.  Embedded JWK Injection (jwk header parameter)
    8.  JKU Header Injection (jku / x5u URL redirection)
    9.  x5c Certificate Chain Injection
    10. Claim Tampering Detection (privilege escalation patterns)
    11. Weak RSA Key Size Detection
    12. Missing jti Claim (replay attack risk)

Author: Rahul Mohapatra
GitHub: github.com/RahulMohapatra1
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ── cryptography imports (pip install cryptography) ───────────────────────────
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.x509 as x509

# ── Colours ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Sensitive payload patterns ────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "Password":    re.compile(r"pass(word)?", re.IGNORECASE),
    "Secret Key":  re.compile(r"secret", re.IGNORECASE),
    "API Key":     re.compile(r"api[_-]?key", re.IGNORECASE),
    "Private Key": re.compile(r"private[_-]?key", re.IGNORECASE),
    "Credit Card": re.compile(r"\b\d{16}\b"),
    "Email":       re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "IP Address":  re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "AWS Key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT Secret":  re.compile(r"jwt[_-]?secret", re.IGNORECASE),
}

# ── Privilege escalation claim patterns ───────────────────────────────────────
# These are payload keys / values that suggest a privilege escalation risk
PRIV_ESC_KEYS = [
    "role", "roles", "scope", "scopes", "group", "groups",
    "permission", "permissions", "admin", "isAdmin", "is_admin",
    "superuser", "is_superuser", "staff", "is_staff",
    "privilege", "privileges", "access_level", "level",
    "authority", "authorities", "grant", "grants",
]
PRIV_ESC_VALUES = [
    "admin", "administrator", "superuser", "root", "super",
    "staff", "manager", "owner", "god", "system",
    "write", "readwrite", "all", "*",
]

# ── kid injection patterns ────────────────────────────────────────────────────
KID_INJECTION_PATTERNS = [
    "../", "../../", "/dev/null", "' OR '1'='1",
    "none", "/etc/passwd", "\\",
]

# ── Minimum safe RSA key size (bits) ──────────────────────────────────────────
MIN_RSA_KEY_BITS = 2048


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def base64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data.replace("-", "+").replace("_", "/"))


def base64url_encode(data: bytes) -> str:
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_").rstrip("=")


def parse_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        print(f"{RED}[ERROR]{RESET} Invalid JWT — expected 3 parts, got {len(parts)}")
        return None
    try:
        header  = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        sig     = base64url_decode(parts[2]) if parts[2] else b""
        return header, payload, sig, parts
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Failed to decode JWT: {e}")
        return None


def print_banner():
    """
    Renders JWT Tester banner using pyfiglet slant font.
    Falls back to plain text if pyfiglet is not installed.
    slant font: diagonal style, clean, works on all OS.
    """
    try:
        import pyfiglet
        banner = pyfiglet.figlet_format("JWT Tester", font="slant")
    except ImportError:
        banner = "  JWT Tester\n"

    DOT = "\xb7"
    D   = DOT * 56

    print("")
    for line in banner.rstrip("\n").split("\n"):
        print(f"  {CYAN}{BOLD}{line}{RESET}")
    print("")
    print(f"  {BOLD}{YELLOW}By Rahul Mohapatra{RESET}")
    print(f"  {CYAN}github.com/RahulMohapatra1{RESET}")
    print(f"\n  {BLUE}{D}{RESET}")
    print(f"  Scans a JWT for 12 security vulnerabilities including")
    print(f"  weak secrets, algorithm attacks, claim tampering,")
    print(f"  replay risks, and certificate chain injection.")
    print(f"  {BLUE}{D}{RESET}")
    print(f"\n  {YELLOW}v2.0  {DOT}  12 checks  {DOT}  AppSec Research Tool{RESET}\n")


def print_section(title: str):
    print(f"\n{BLUE}{BOLD}{'─'*55}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'─'*55}{RESET}")


def display_token_info(header: dict, payload: dict):
    print_section("TOKEN INFORMATION")
    print(f"\n{CYAN}[HEADER]{RESET}")
    for k, v in header.items():
        print(f"  {k}: {v}")
    print(f"\n{CYAN}[PAYLOAD]{RESET}")
    for k, v in payload.items():
        if k in ("exp", "iat", "nbf"):
            try:
                dt = datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
                print(f"  {k}: {v}  ({dt})")
            except Exception:
                print(f"  {k}: {v}")
        else:
            print(f"  {k}: {v}")


# ═════════════════════════════════════════════════════════════════════════════
#  ORIGINAL CHECKS (v1)
# ═════════════════════════════════════════════════════════════════════════════

def check_none_algorithm(header: dict, parts: list) -> dict:
    print_section("CHECK 1: None Algorithm Attack")
    alg = header.get("alg", "").lower()

    attack_header     = {**header, "alg": "none"}
    attack_header_b64 = base64url_encode(json.dumps(attack_header, separators=(",", ":")).encode())
    attack_token      = f"{attack_header_b64}.{parts[1]}."

    if alg == "none":
        print(f"  {RED}[CRITICAL]{RESET} Token already uses alg:none — NO signature!")
        return {"check": "None Algorithm Attack", "status": "CRITICAL",
                "details": "Token uses alg:none — no signature verification"}

    print(f"  {YELLOW}[INFO]{RESET} Current algorithm: {header.get('alg')}")
    print(f"  {YELLOW}[TEST]{RESET} Crafted none-algorithm attack token:")
    print(f"\n  {CYAN}{attack_token}{RESET}\n")
    print(f"  {YELLOW}[ACTION]{RESET} Submit this to your target API. If accepted → vulnerable.")
    return {"check": "None Algorithm Attack", "status": "TEST_REQUIRED",
            "details": "Crafted alg:none token — submit to target for manual verification",
            "attack_token": attack_token}


def check_weak_secret(header: dict, parts: list, wordlist_path: str) -> dict:
    print_section("CHECK 2: Weak Secret Brute Force")
    alg     = header.get("alg", "").upper()
    alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

    if alg not in alg_map:
        print(f"  {YELLOW}[SKIP]{RESET} Algorithm '{alg}' is not HMAC-based.")
        return {"check": "Weak Secret Brute Force", "status": "SKIPPED",
                "details": f"Algorithm {alg} is not HMAC-based"}

    hash_func = alg_map[alg]
    message   = f"{parts[0]}.{parts[1]}".encode()

    try:
        original_sig = base64url_decode(parts[2])
    except Exception:
        return {"check": "Weak Secret Brute Force", "status": "ERROR",
                "details": "Could not decode signature"}

    if not os.path.exists(wordlist_path):
        print(f"  {RED}[ERROR]{RESET} Wordlist not found: {wordlist_path}")
        return {"check": "Weak Secret Brute Force", "status": "ERROR",
                "details": "Wordlist not found"}

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [l.strip() for l in f if l.strip()]

    print(f"  {YELLOW}[INFO]{RESET} Testing {len(words)} secrets against {alg}...")
    start = time.time()

    for word in words:
        candidate = hmac.new(word.encode(), message, hash_func).digest()
        if hmac.compare_digest(candidate, original_sig):
            elapsed = time.time() - start
            print(f"  {RED}[CRITICAL]{RESET} SECRET FOUND in {elapsed:.2f}s: '{word}'")
            print(f"  {RED}Attacker can now forge any token signed with this key.{RESET}")
            return {"check": "Weak Secret Brute Force", "status": "CRITICAL",
                    "details": f"Secret cracked: '{word}' in {elapsed:.2f}s"}

    elapsed = time.time() - start
    print(f"  {GREEN}[PASS]{RESET} Not found in {len(words)} words ({elapsed:.2f}s).")
    print(f"  {YELLOW}[NOTE]{RESET} Use a larger wordlist for thorough testing.")
    return {"check": "Weak Secret Brute Force", "status": "PASS",
            "details": f"Not in provided wordlist ({len(words)} words)"}


def check_algorithm_confusion(header: dict, parts: list) -> dict:
    print_section("CHECK 3: Algorithm Confusion (RS256 → HS256)")
    alg            = header.get("alg", "").upper()
    asymmetric_algs = ["RS256","RS384","RS512","ES256","ES384","ES512","PS256","PS384","PS512"]

    if alg in asymmetric_algs:
        print(f"  {YELLOW}[WARNING]{RESET} Asymmetric algorithm detected: {alg}")
        print(f"\n  {CYAN}Attack steps:{RESET}")
        print(f"  1. Obtain the server public key (try /.well-known/jwks.json)")
        print(f"  2. Change header alg from '{alg}' to 'HS256'")
        print(f"  3. Sign modified token with the PUBLIC key as the HMAC secret")
        print(f"  4. Server verifies with same public key → accepts forged token")
        attack_header = {**header, "alg": "HS256"}
        print(f"\n  {YELLOW}Modified header:{RESET} {json.dumps(attack_header)}")
        return {"check": "Algorithm Confusion", "status": "WARNING",
                "details": f"Asymmetric alg {alg} — manual confusion attack testing recommended"}

    print(f"  {GREEN}[PASS]{RESET} Symmetric algorithm ({alg}) — confusion attack not applicable.")
    return {"check": "Algorithm Confusion", "status": "PASS",
            "details": f"Symmetric {alg} — not applicable"}


def check_sensitive_data(payload: dict) -> dict:
    print_section("CHECK 4: Sensitive Data in Payload")
    findings = []
    for pname, pattern in SENSITIVE_PATTERNS.items():
        for k, v in payload.items():
            if pattern.search(str(k)):
                findings.append(f"Key '{k}' matches {pname}")
                print(f"  {RED}[CRITICAL]{RESET} Key '{k}' matches {pname} — value: '{v}'")
            elif pattern.search(str(v)):
                findings.append(f"Value of '{k}' matches {pname}")
                print(f"  {YELLOW}[WARNING]{RESET} Value of '{k}' matches {pname} — '{v}'")
    if not findings:
        print(f"  {GREEN}[PASS]{RESET} No sensitive patterns found.")
    return {"check": "Sensitive Data in Payload", "status": "WARNING" if findings else "PASS",
            "details": "; ".join(findings) if findings else "No patterns matched"}


def check_expiry(payload: dict) -> dict:
    print_section("CHECK 5: Token Expiry (exp Claim)")

    if "exp" not in payload:
        print(f"  {RED}[CRITICAL]{RESET} No 'exp' claim — token NEVER expires!")
        return {"check": "Expiry Claim", "status": "CRITICAL",
                "details": "Missing exp — token never expires"}

    exp = payload["exp"]
    now = datetime.now().timestamp()
    exp_dt = datetime.fromtimestamp(exp)

    if exp < now:
        hours_ago = (now - exp) / 3600
        print(f"  {YELLOW}[WARNING]{RESET} Token expired {hours_ago:.1f}h ago ({exp_dt})")
        print(f"  {YELLOW}[TEST]{RESET} Submit to target — if accepted, exp is not validated.")
        return {"check": "Expiry Claim", "status": "WARNING",
                "details": f"Expired {hours_ago:.1f}h ago — test if server still accepts it"}

    days_left = (exp - now) / 86400
    print(f"  {GREEN}[PASS]{RESET} Expires: {exp_dt}  ({days_left:.1f} days remaining)")
    if days_left > 30:
        print(f"  {YELLOW}[WARNING]{RESET} Lifetime > 30 days — long-lived tokens increase theft risk.")
        return {"check": "Expiry Claim", "status": "WARNING",
                "details": f"Valid for {days_left:.1f} more days — consider shorter lifetime"}

    return {"check": "Expiry Claim", "status": "PASS",
            "details": f"Expires in {days_left:.1f} days"}


def check_kid_injection(header: dict) -> dict:
    print_section("CHECK 6: kid Header Injection")

    if "kid" not in header:
        print(f"  {GREEN}[INFO]{RESET} No kid header present.")
        return {"check": "kid Injection", "status": "PASS", "details": "No kid header"}

    kid = str(header["kid"])
    print(f"  {CYAN}[INFO]{RESET} kid value: '{kid}'")
    found = [p for p in KID_INJECTION_PATTERNS if p.lower() in kid.lower()]

    if found:
        print(f"  {RED}[CRITICAL]{RESET} Suspicious patterns in kid: {found}")
        return {"check": "kid Injection", "status": "CRITICAL",
                "details": f"Suspicious kid patterns: {found}"}

    print(f"  {GREEN}[PASS]{RESET} No obvious injection patterns in kid.")
    return {"check": "kid Injection", "status": "PASS",
            "details": "No injection patterns in kid"}


# ═════════════════════════════════════════════════════════════════════════════
#  ADVANCED CHECKS (v2)
# ═════════════════════════════════════════════════════════════════════════════

def check_embedded_jwk(header: dict, parts: list) -> dict:
    """
    CHECK 7: Embedded JWK Injection

    What is JWK?
    JWK = JSON Web Key. A standard format to represent a cryptographic key as JSON.
    Example: {"kty":"RSA","n":"...","e":"AQAB"}

    The Attack:
    Some JWT libraries support a 'jwk' parameter in the JWT HEADER itself.
    The idea was: "include the public key used to verify this token right here
    in the header so the server knows which key to use."

    The Problem:
    If the server trusts the key embedded in the header WITHOUT checking that
    key against a whitelist of trusted keys — the attacker can:
    1. Generate their own RSA key pair (private + public)
    2. Sign a forged token with their PRIVATE key
    3. Embed their PUBLIC key in the token header as 'jwk'
    4. Server reads the jwk from the header, uses it to verify → accepts forged token

    Real World: This was found in several major JWT libraries (CVE-2018-0114).
    """
    print_section("CHECK 7: Embedded JWK Injection")

    result = {"check": "Embedded JWK Injection", "status": None, "details": ""}

    if "jwk" in header:
        # Token already has an embedded JWK — this is suspicious
        jwk = header["jwk"]
        print(f"  {RED}[CRITICAL]{RESET} Token contains an embedded 'jwk' in header!")
        print(f"  {RED}Embedded key: {json.dumps(jwk)}{RESET}")
        print(f"\n  {CYAN}Why this is dangerous:{RESET}")
        print(f"  If the server uses this embedded key to verify the signature")
        print(f"  without checking it against a trusted key whitelist,")
        print(f"  an attacker can embed their own public key and forge any token.")

        # Check if the embedded key looks like an attacker-controlled key
        kty = jwk.get("kty", "").upper()
        print(f"\n  {YELLOW}Key type detected: {kty}{RESET}")
        if kty == "RSA":
            print(f"  {YELLOW}[TEST]{RESET} Verify: does the server's JWKS endpoint list this key?")
            print(f"  If NO → server is accepting an attacker-controlled key.")

        result["status"] = "CRITICAL"
        result["details"] = f"Embedded jwk in header (kty={jwk.get('kty','?')}) — server may trust attacker-controlled key"

    else:
        # No jwk in header — but we can demonstrate the attack
        print(f"  {GREEN}[INFO]{RESET} No 'jwk' parameter found in header.")
        print(f"\n  {CYAN}Demonstrating attack — generating attacker key pair...{RESET}")

        # Generate a fresh RSA key pair (attacker's keys)
        attacker_private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard RSA public exponent
            key_size=2048,          # 2048-bit key
            backend=default_backend()
        )
        attacker_public_key = attacker_private_key.public_key()

        # Get the public key numbers (n = modulus, e = exponent)
        pub_numbers = attacker_public_key.public_key().public_numbers() if hasattr(attacker_public_key, 'public_key') else attacker_public_key.public_numbers()

        # Convert n and e to base64url for JWK format
        n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, 'big')
        e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, 'big')

        # Build the JWK object that would be embedded
        attacker_jwk = {
            "kty": "RSA",
            "n": base64url_encode(n_bytes),
            "e": base64url_encode(e_bytes),
            "alg": "RS256",
            "use": "sig"
        }

        # Build the attack header with embedded JWK
        attack_header = {**header, "alg": "RS256", "jwk": attacker_jwk}
        print(f"\n  {YELLOW}[DEMO]{RESET} Attack header would contain:")
        print(f"  {CYAN}{{ ...original_claims..., 'jwk': {{attacker_public_key}} }}{RESET}")
        print(f"\n  {YELLOW}[ACTION]{RESET} To fully test:")
        print(f"  1. Generate RSA keypair (openssl genrsa -out attacker.key 2048)")
        print(f"  2. Sign token with your PRIVATE key")
        print(f"  3. Embed your PUBLIC key in header as 'jwk'")
        print(f"  4. Submit — if server accepts → vulnerable")

        result["status"] = "INFO"
        result["details"] = "No embedded jwk in header — attack demo provided for manual testing"

    return result


def check_jku_injection(header: dict) -> dict:
    """
    CHECK 8: JKU / x5u Header Injection (URL Redirection Attack)

    What is jku?
    jku = JSON Web Key Set URL
    Instead of embedding the key in the header (jwk), this points to a URL
    where the server should fetch the public keys from.

    Normal flow:
    Server has a JWKS endpoint: https://myapp.com/.well-known/jwks.json
    JWT header: {"alg": "RS256", "jku": "https://myapp.com/.well-known/jwks.json"}
    Server fetches keys from that URL → uses them to verify

    The Attack:
    Attacker changes jku to their own server:
    {"alg": "RS256", "jku": "https://attacker.com/evil-jwks.json"}
    Attacker's server returns their own public key.
    Attacker signed the token with their private key.
    Server fetches attacker's public key → verifies successfully → accepts forged token.

    x5u is the same concept but for X.509 certificate chains.

    Real World: Found in multiple enterprise SSO systems and API gateways.
    """
    print_section("CHECK 8: JKU / x5u Header Injection")

    result = {"check": "JKU/x5u Injection", "status": None, "details": ""}
    findings = []

    for param in ["jku", "x5u"]:
        if param not in header:
            continue

        url = header[param]
        print(f"  {YELLOW}[WARNING]{RESET} '{param}' header found: {url}")
        findings.append(f"{param}: {url}")

        # Check if URL looks like it could be attacker-controlled
        suspicious_indicators = [
            "localhost", "127.0.0.1", "0.0.0.0",       # Local addresses
            "ngrok", "burpcollaborator", "requestbin",   # Common attacker tools
            "attacker", "evil", "hack",                  # Obvious names
            "192.168.", "10.", "172.16.",                 # Private ranges
        ]

        url_lower = url.lower()
        for indicator in suspicious_indicators:
            if indicator in url_lower:
                print(f"  {RED}[CRITICAL]{RESET} Suspicious URL pattern '{indicator}' in {param}!")
                result["status"] = "CRITICAL"

        # Try to fetch the URL to see what it returns
        print(f"  {CYAN}[FETCH]{RESET} Attempting to retrieve: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "JWT-Security-Tester/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read(2048).decode("utf-8", errors="ignore")
                print(f"  {YELLOW}[RESPONSE]{RESET} Status: {resp.status} | Content-Type: {content_type}")

                # Check if it looks like a JWKS response
                if "keys" in body.lower():
                    try:
                        jwks = json.loads(body)
                        key_count = len(jwks.get("keys", []))
                        print(f"  {CYAN}[JWKS]{RESET} Found {key_count} key(s) at this URL")
                    except json.JSONDecodeError:
                        print(f"  {YELLOW}[WARNING]{RESET} Response not valid JSON")
        except urllib.error.URLError as e:
            print(f"  {YELLOW}[INFO]{RESET} Could not fetch URL: {e.reason}")
        except Exception as e:
            print(f"  {YELLOW}[INFO]{RESET} Fetch error: {e}")

        print(f"\n  {CYAN}Attack steps for {param}:{RESET}")
        print(f"  1. Set up your own JWKS endpoint (e.g., using ngrok + python3 -m http.server)")
        print(f"  2. Host a JWKS file with YOUR public key at that endpoint")
        print(f"  3. Change {param} in header to point to YOUR server")
        print(f"  4. Sign the token with YOUR private key")
        print(f"  5. Server fetches YOUR key → verifies successfully → accepts forged token")

    if not findings:
        print(f"  {GREEN}[PASS]{RESET} No jku or x5u parameters found in header.")
        result["status"] = "PASS"
        result["details"] = "No jku/x5u parameters found"
    else:
        if result["status"] != "CRITICAL":
            result["status"] = "WARNING"
        result["details"] = f"URL-based key parameters found: {', '.join(findings)}"

    return result


def check_x5c_injection(header: dict) -> dict:
    """
    CHECK 9: x5c Certificate Chain Injection

    What is x5c?
    x5c = X.509 Certificate Chain
    It is a header parameter where you embed the full X.509 certificate chain
    (in base64-encoded DER format) inside the JWT header itself.

    The idea was: include the certificate so the server knows which cert was
    used to sign the token.

    The Attack:
    Similar to embedded JWK attack but using X.509 certificates.
    1. Attacker generates a self-signed X.509 certificate
    2. Embeds it in the JWT header as x5c
    3. Signs the token with the private key matching that certificate
    4. If the server trusts the certificate in x5c without validation → forged token accepted

    The server should verify:
    - Certificate is signed by a trusted CA
    - Certificate has not expired
    - Certificate has not been revoked (CRL / OCSP)
    - Certificate Common Name matches expected issuer

    If it just verifies "does this cert's public key match the signature" → vulnerable.

    CVE example: CVE-2022-21449 (Psychic Signatures in Java) affected x5c handling.
    """
    print_section("CHECK 9: x5c Certificate Chain Injection")

    result = {"check": "x5c Certificate Injection", "status": None, "details": ""}

    if "x5c" not in header:
        print(f"  {GREEN}[INFO]{RESET} No x5c parameter in header.")
        result["status"] = "PASS"
        result["details"] = "No x5c parameter found"
        return result

    x5c_chain = header["x5c"]
    if isinstance(x5c_chain, str):
        x5c_chain = [x5c_chain]

    print(f"  {RED}[CRITICAL]{RESET} x5c certificate chain found in header!")
    print(f"  {YELLOW}Chain length: {len(x5c_chain)} certificate(s){RESET}")

    cert_findings = []

    for i, cert_b64 in enumerate(x5c_chain):
        print(f"\n  {CYAN}── Certificate {i+1} ──{RESET}")
        try:
            # x5c certs are base64 (not base64url) encoded DER format
            # Add padding and decode
            cert_der = base64.b64decode(cert_b64 + "==")

            # Parse the certificate using cryptography library
            cert = load_pem_x509_certificate(
                b"-----BEGIN CERTIFICATE-----\n" +
                base64.encodebytes(cert_der) +
                b"-----END CERTIFICATE-----\n",
                default_backend()
            )

            # Extract certificate details
            subject = cert.subject.rfc4514_string()
            issuer  = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            not_after  = cert.not_valid_after_utc  if hasattr(cert, 'not_valid_after_utc')  else cert.not_valid_after

            print(f"  Subject : {subject}")
            print(f"  Issuer  : {issuer}")
            print(f"  Valid   : {not_before} → {not_after}")

            # Check 1: Is it self-signed? (subject == issuer = no CA trust)
            if subject == issuer:
                print(f"  {RED}[CRITICAL]{RESET} Certificate is SELF-SIGNED!")
                print(f"  A self-signed cert has no CA verification — attacker can create their own.")
                cert_findings.append(f"Cert {i+1}: self-signed")

            # Check 2: Is it expired?
            now = datetime.utcnow()
            if hasattr(not_after, 'replace'):
                not_after_naive = not_after.replace(tzinfo=None) if not_after.tzinfo else not_after
            else:
                not_after_naive = not_after

            try:
                if not_after_naive < now:
                    print(f"  {RED}[CRITICAL]{RESET} Certificate has EXPIRED!")
                    cert_findings.append(f"Cert {i+1}: expired")
                else:
                    print(f"  {GREEN}[PASS]{RESET} Certificate not expired.")
            except TypeError:
                print(f"  {YELLOW}[INFO]{RESET} Could not compare expiry dates (timezone issue).")

            # Check 3: Key size
            pub_key = cert.public_key()
            if hasattr(pub_key, 'key_size'):
                key_size = pub_key.key_size
                print(f"  Key size: {key_size} bits")
                if key_size < MIN_RSA_KEY_BITS:
                    print(f"  {RED}[CRITICAL]{RESET} RSA key < {MIN_RSA_KEY_BITS} bits — too weak!")
                    cert_findings.append(f"Cert {i+1}: weak RSA key ({key_size} bits)")

        except Exception as e:
            print(f"  {YELLOW}[WARNING]{RESET} Could not parse certificate {i+1}: {e}")
            cert_findings.append(f"Cert {i+1}: parse error")

    print(f"\n  {CYAN}What to verify manually:{RESET}")
    print(f"  1. Does the server validate the cert against a trusted CA?")
    print(f"  2. Does the server check cert expiry before trusting it?")
    print(f"  3. Does the server verify the cert is in its whitelist?")
    print(f"  If any answer is NO → server is vulnerable to x5c injection.")

    result["status"] = "CRITICAL" if cert_findings else "WARNING"
    result["details"] = (
        f"x5c chain found ({len(x5c_chain)} cert(s)). Issues: {'; '.join(cert_findings)}"
        if cert_findings else
        f"x5c chain found ({len(x5c_chain)} cert(s)) — manual CA trust validation required"
    )
    return result


def check_claim_tampering(payload: dict, parts: list) -> dict:
    """
    CHECK 10: Claim Tampering / Privilege Escalation Detection

    What is claim tampering?
    JWT payloads contain 'claims' — statements about the user.
    Common claims: {"user": "rahul", "role": "user", "exp": 1234567890}

    The Attack:
    If an attacker can:
    A) Modify the payload and the server doesn't verify the signature → direct tampering
    B) Forge a token with a different role claim → privilege escalation

    What this check does:
    1. Detects HIGH-PRIVILEGE values in claims (admin, superuser, root, etc.)
    2. Shows what a tampered token would look like
    3. Checks for missing 'iss' (issuer) and 'aud' (audience) claims
       — Without these, a token issued for one service can be replayed at another

    Why iss and aud matter:
    Imagine you log into Service A and get a JWT. Without 'aud' (audience) claim,
    that token might also be accepted by Service B. This is a cross-service replay attack.
    """
    print_section("CHECK 10: Claim Tampering & Privilege Escalation Detection")

    result   = {"check": "Claim Tampering", "status": None, "details": ""}
    findings = []

    # ── Detect high-privilege claims ──────────────────────────────────────────
    print(f"  {CYAN}[SCAN]{RESET} Checking for privilege-sensitive claims...")
    for key, value in payload.items():
        key_lower = str(key).lower()
        val_lower = str(value).lower()

        # Flag high-privilege KEYS
        if any(pk in key_lower for pk in PRIV_ESC_KEYS):
            print(f"  {YELLOW}[FOUND]{RESET} Privilege-sensitive key: '{key}' = '{value}'")

            # Flag high-privilege VALUES
            if any(pv in val_lower for pv in PRIV_ESC_VALUES):
                print(f"  {RED}[CRITICAL]{RESET} HIGH-PRIVILEGE value detected: '{key}' = '{value}'")
                findings.append(f"High privilege: {key}={value}")

                # Show what a downgraded token would look like
                # (and what an attacker would upgrade from 'user' to 'admin')
                print(f"\n  {CYAN}Tampering demo:{RESET}")
                print(f"  Original : {key} = '{value}'")

                # Suggest what attacker would change to / from
                if val_lower == "user":
                    print(f"  Tampered : {key} = 'admin'")
                elif val_lower == "admin":
                    print(f"  Attacker already has admin role in token")
            else:
                print(f"  {YELLOW}[WARNING]{RESET} Non-admin value but sensitive key: '{key}' = '{value}'")
                findings.append(f"Sensitive key: {key}={value}")

    # ── Check for missing iss (issuer) ────────────────────────────────────────
    print(f"\n  {CYAN}[SCAN]{RESET} Checking for issuer (iss) and audience (aud) claims...")

    if "iss" not in payload:
        print(f"  {YELLOW}[WARNING]{RESET} Missing 'iss' (issuer) claim!")
        print(f"  Without iss, the server cannot verify which service issued this token.")
        print(f"  Risk: Token issued by Service A may be accepted by Service B.")
        findings.append("Missing iss claim")
    else:
        print(f"  {GREEN}[PASS]{RESET} iss claim present: '{payload['iss']}'")

    # ── Check for missing aud (audience) ─────────────────────────────────────
    if "aud" not in payload:
        print(f"  {YELLOW}[WARNING]{RESET} Missing 'aud' (audience) claim!")
        print(f"  Without aud, token issued for one endpoint could be replayed at another.")
        findings.append("Missing aud claim")
    else:
        print(f"  {GREEN}[PASS]{RESET} aud claim present: '{payload['aud']}'")

    # ── Show tampered token demo ───────────────────────────────────────────────
    # We create a tampered payload where we escalate role to admin
    # Note: This token will have an INVALID signature — the point is to show
    # what the attacker would need to submit and what to test for
    tamper_payload = dict(payload)
    tampered = False
    for key in payload:
        if any(pk in key.lower() for pk in ["role", "scope", "admin", "group"]):
            original_val = str(payload[key])
            if original_val.lower() != "admin":
                tamper_payload[key] = "admin"
                tampered = True

    if tampered:
        tamper_b64 = base64url_encode(json.dumps(tamper_payload, separators=(",", ":")).encode())
        tampered_token = f"{parts[0]}.{tamper_b64}.{parts[2]}"
        print(f"\n  {YELLOW}[DEMO]{RESET} Tampered token (role escalated to admin):")
        print(f"  {CYAN}{tampered_token}{RESET}")
        print(f"  {YELLOW}[NOTE]{RESET} Signature is INVALID — if server accepts this → signature verification is BROKEN!")

    # ── CRITICAL LOGIC: role=admin is always CRITICAL regardless of secret ─────
    # Reason: Even if we cannot crack the secret, a token carrying admin/superuser
    # claims is dangerous because:
    # A) The secret might be weak and crackable with a larger wordlist
    # B) The token itself proves the system issues admin-scoped tokens
    # C) Any algorithm attack (none, confusion, jwk) would allow forging this
    # The presence of high-privilege claims ALWAYS warrants CRITICAL attention.
    has_high_priv = any("High privilege" in f for f in findings)
    has_missing_claims = any("Missing" in f for f in findings)

    if not findings:
        print(f"\n  {GREEN}[PASS]{RESET} No privilege escalation patterns found.")
        result["status"] = "PASS"
        result["details"] = "No high-privilege claims or missing iss/aud"
    elif has_high_priv:
        print(f"\n  {RED}[CRITICAL]{RESET} High-privilege role found in token.")
        print(f"  {RED}Even without cracking the secret, this token carries admin-level claims.{RESET}")
        print(f"  {RED}Any successful algorithm attack would allow forging an admin token.{RESET}")
        print(f"  {YELLOW}[NEXT STEPS]{RESET}")
        print(f"  1. Try none-algorithm attack with the crafted token from Check 1")
        print(f"  2. If RS256/ES256: attempt algorithm confusion attack (Check 3)")
        print(f"  3. Check /.well-known/jwks.json for embedded JWK injection")
        print(f"  4. Run brute force with a larger wordlist: -w wordlists/jwt-secrets-full.txt")
        result["status"] = "CRITICAL"
        result["details"] = "; ".join(findings)
    else:
        result["status"] = "WARNING"
        result["details"] = "; ".join(findings)

    return result


def check_weak_rsa_key(header: dict) -> dict:
    """
    CHECK 11: Weak RSA Key Size Detection

    Why RSA key size matters:
    RSA security depends on the difficulty of factoring large numbers.
    - 512-bit RSA: Factored in hours on modern hardware. BROKEN.
    - 1024-bit RSA: Factored by nation-state actors. Deprecated.
    - 2048-bit RSA: Current minimum. Safe for ~10 years.
    - 4096-bit RSA: Strong. Safe for foreseeable future.

    If the JWT uses RS256 and we can get the public key (from JWKS or x5c),
    we can check the key size. A weak RSA key means an attacker can:
    1. Factor the public key to obtain the private key
    2. Sign arbitrary tokens with the private key
    3. All tokens are now forgeable

    This check:
    1. Detects RSA-based algorithms in the header
    2. If a jwk or x5c is present, extracts the key and checks bit length
    3. Reports if key is below 2048 bits
    """
    print_section("CHECK 11: Weak RSA Key Size Detection")

    result = {"check": "Weak RSA Key Size", "status": None, "details": ""}
    alg    = header.get("alg", "").upper()

    rsa_algs = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]

    if alg not in rsa_algs:
        print(f"  {GREEN}[INFO]{RESET} Algorithm '{alg}' is not RSA-based. Check not applicable.")
        result["status"] = "PASS"
        result["details"] = f"Non-RSA algorithm ({alg}) — not applicable"
        return result

    print(f"  {CYAN}[INFO]{RESET} RSA-based algorithm detected: {alg}")

    # Try to extract key from embedded jwk
    key_size = None
    key_source = None

    if "jwk" in header:
        jwk = header["jwk"]
        if jwk.get("kty") == "RSA":
            try:
                # Decode the modulus (n) from base64url — its bit length = key size
                n_bytes = base64url_decode(jwk["n"])
                n_int   = int.from_bytes(n_bytes, 'big')
                key_size = n_int.bit_length()
                key_source = "embedded jwk"
            except Exception as e:
                print(f"  {YELLOW}[WARNING]{RESET} Could not parse jwk modulus: {e}")

    elif "x5c" in header:
        try:
            cert_b64  = header["x5c"][0] if isinstance(header["x5c"], list) else header["x5c"]
            cert_der  = base64.b64decode(cert_b64 + "==")
            cert      = load_pem_x509_certificate(
                b"-----BEGIN CERTIFICATE-----\n" +
                base64.encodebytes(cert_der) +
                b"-----END CERTIFICATE-----\n",
                default_backend()
            )
            pub_key   = cert.public_key()
            if hasattr(pub_key, 'key_size'):
                key_size   = pub_key.key_size
                key_source = "x5c certificate"
        except Exception as e:
            print(f"  {YELLOW}[WARNING]{RESET} Could not extract key from x5c: {e}")

    if key_size is not None:
        print(f"  {CYAN}[INFO]{RESET} RSA key size from {key_source}: {key_size} bits")
        if key_size < 1024:
            print(f"  {RED}[CRITICAL]{RESET} {key_size}-bit RSA key is CRITICALLY WEAK!")
            print(f"  Can be factored in hours. This key MUST be replaced immediately.")
            result["status"] = "CRITICAL"
            result["details"] = f"{key_size}-bit RSA key — critically weak, factoring feasible"
        elif key_size < MIN_RSA_KEY_BITS:
            print(f"  {RED}[CRITICAL]{RESET} {key_size}-bit RSA key is below minimum ({MIN_RSA_KEY_BITS} bits)!")
            print(f"  1024-bit RSA is deprecated and should be considered broken.")
            result["status"] = "CRITICAL"
            result["details"] = f"{key_size}-bit RSA key — below 2048-bit minimum"
        else:
            print(f"  {GREEN}[PASS]{RESET} Key size {key_size} bits meets minimum requirement.")
            result["status"] = "PASS"
            result["details"] = f"RSA key size {key_size} bits — acceptable"
    else:
        print(f"  {YELLOW}[INFO]{RESET} Could not extract key from token headers directly.")
        print(f"  {YELLOW}[ACTION]{RESET} Fetch public key from JWKS endpoint and verify bit length:")
        print(f"  openssl rsa -in public.pem -text -noout | grep 'Public-Key'")
        print(f"  Minimum acceptable: 2048 bits")
        result["status"] = "INFO"
        result["details"] = f"RSA algorithm ({alg}) detected but key not extractable from token — manual check required"

    return result


def check_missing_jti(payload: dict) -> dict:
    """
    CHECK 12: Missing jti Claim (Replay Attack Risk)

    What is jti?
    jti = JWT ID — a unique identifier for this specific token.
    Think of it like a transaction ID or nonce.

    Why it matters:
    Without jti, if an attacker intercepts a valid token (via XSS, network sniffing,
    log exposure, etc.) they can REPLAY it — use it again and again until it expires.

    With jti:
    - Server maintains a list of used jti values (in Redis, database, etc.)
    - When a token is used, server checks: "have I seen this jti before?"
    - If YES → reject (replay attempt)
    - If NO → process and record the jti

    Real-world example:
    - User logs in → gets JWT with jti: "abc123"
    - Attacker sniffs the token from network traffic
    - User logs out (but JWT is still valid until exp)
    - Attacker replays the token → if no jti blocklist, server accepts it

    This check also looks for:
    - 'nbf' (not before) claim — prevents using a token before a certain time
    - 'iat' (issued at) claim — helps detect tokens used suspiciously long after issuance
    """
    print_section("CHECK 12: Missing jti Claim (Replay Attack Risk)")

    result   = {"check": "Missing jti Claim", "status": None, "details": ""}
    findings = []

    # ── Check jti ─────────────────────────────────────────────────────────────
    if "jti" not in payload:
        print(f"  {YELLOW}[WARNING]{RESET} Missing 'jti' (JWT ID) claim!")
        print(f"  Without jti, the server cannot implement token revocation or replay prevention.")
        print(f"  If an attacker intercepts this token, they can reuse it until it expires.")
        findings.append("Missing jti")
    else:
        jti = payload["jti"]
        print(f"  {GREEN}[PASS]{RESET} jti claim present: '{jti}'")
        # Check if jti looks like a real UUID/random value or something predictable
        if len(str(jti)) < 8:
            print(f"  {YELLOW}[WARNING]{RESET} jti value '{jti}' looks predictably short!")
            print(f"  jti should be a UUID or long random string, not a short integer.")
            findings.append(f"Weak jti value: '{jti}' (too short/predictable)")
        elif str(jti).isdigit():
            print(f"  {YELLOW}[WARNING]{RESET} jti '{jti}' is a sequential integer — predictable!")
            print(f"  Sequential jti values allow an attacker to guess/enumerate valid token IDs.")
            findings.append(f"Sequential jti: '{jti}'")
        else:
            print(f"  {GREEN}[PASS]{RESET} jti appears to be a sufficiently random value.")

    # ── Check nbf (not before) ────────────────────────────────────────────────
    if "nbf" not in payload:
        print(f"\n  {YELLOW}[INFO]{RESET} Missing 'nbf' (not before) claim.")
        print(f"  nbf prevents a token from being used before a specific time.")
        print(f"  Not critical but considered best practice for high-security applications.")
    else:
        nbf    = payload["nbf"]
        now    = datetime.now().timestamp()
        nbf_dt = datetime.fromtimestamp(nbf)
        if nbf > now:
            print(f"\n  {YELLOW}[WARNING]{RESET} Token not yet valid! (nbf: {nbf_dt})")
            print(f"  If server accepts this before the nbf time → nbf is not validated.")
            findings.append(f"Token used before nbf ({nbf_dt})")
        else:
            print(f"\n  {GREEN}[PASS]{RESET} nbf satisfied: token valid since {nbf_dt}")

    # ── Check iat (issued at) ─────────────────────────────────────────────────
    if "iat" not in payload:
        print(f"\n  {YELLOW}[INFO]{RESET} Missing 'iat' (issued at) claim.")
        print(f"  iat helps detect tokens being used suspiciously long after issuance.")
    else:
        iat    = payload["iat"]
        now    = datetime.now().timestamp()
        iat_dt = datetime.fromtimestamp(iat)
        age_h  = (now - iat) / 3600
        print(f"\n  {GREEN}[PASS]{RESET} iat claim present. Token issued: {iat_dt} ({age_h:.1f}h ago)")
        if age_h > 24:
            print(f"  {YELLOW}[WARNING]{RESET} Token is {age_h:.1f}h old — consider if this is expected.")

    if not findings:
        print(f"\n  {GREEN}[PASS]{RESET} No replay attack risks detected.")
        result["status"] = "PASS"
        result["details"] = "jti present and looks valid; no replay attack indicators"
    else:
        result["status"] = "WARNING"
        result["details"] = "; ".join(findings)

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def print_summary(results: list):
    print_section("SUMMARY REPORT")

    critical = [r for r in results if r.get("status") == "CRITICAL"]
    warnings = [r for r in results if r.get("status") == "WARNING"]
    passed   = [r for r in results if r.get("status") == "PASS"]
    others   = [r for r in results if r.get("status") not in ("CRITICAL","WARNING","PASS")]

    print(f"\n  {'Check':<38} {'Status':<14} Details")
    print(f"  {'─'*38} {'─'*14} {'─'*30}")

    for r in results:
        s = r.get("status","?")
        c = RED if s=="CRITICAL" else YELLOW if s=="WARNING" else GREEN if s=="PASS" else CYAN
        detail = r.get("details","")[:48]
        print(f"  {r['check']:<38} {c}{s:<14}{RESET} {detail}")

    print(f"\n  {RED}Critical:{len(critical)}{RESET}  "
          f"{YELLOW}Warnings:{len(warnings)}{RESET}  "
          f"{GREEN}Passed:{len(passed)}{RESET}  "
          f"{CYAN}Other:{len(others)}{RESET}")

    if critical:
        print(f"\n  {RED}{BOLD}[!] {len(critical)} CRITICAL issue(s). Immediate action required.{RESET}")
    elif warnings:
        print(f"\n  {YELLOW}{BOLD}[!] {len(warnings)} warning(s). Manual testing recommended.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}[✓] No critical issues found in automated checks.{RESET}")

    print(f"\n  {YELLOW}This tool performs static/offline analysis only.{RESET}")
    print(f"  {YELLOW}Always verify against a live target to confirm exploitability.{RESET}\n")


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="JWT Security Tester v2.0 — 12 vulnerability checks",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )
    parser.add_argument("-t","--token",    required=False, default=None,
                        help="JWT token to analyse (optional — will prompt if not provided)")
    parser.add_argument("-w","--wordlist",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "wordlists","jwt-secrets-top5000.txt"),
        help="Wordlist for brute force (default: wordlists/common_secrets.txt)")
    parser.add_argument("--skip-bruteforce", action="store_true",
        help="Skip brute force check (faster)")
    parser.add_argument("--checks", default="all",
        help="Comma-separated checks: none,brute,confusion,sensitive,expiry,kid,"
             "jwk,jku,x5c,claims,rsa,jti  (default: all)")

    args = parser.parse_args()

    # Interactive token prompt if not passed via -t flag
    DOT = "\xb7"
    if args.token:
        token = args.token.strip()
    else:
        print("  " + BLUE + DOT * 54 + RESET)
        print("  " + BOLD + "Paste your JWT token below and press Enter:" + RESET)
        print("  " + BLUE + DOT * 54 + RESET + "\n")
        try:
            token = input("  " + CYAN + "JWT > " + RESET + " ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  " + YELLOW + "Exiting. Goodbye!" + RESET + "\n")
            sys.exit(0)

        if not token:
            print("\n  " + RED + "[ERROR]" + RESET + " No token provided. Exiting.\n")
            sys.exit(1)

        print()  # blank line before checks start

    parsed = parse_jwt(token)
    if not parsed:
        sys.exit(1)

    header, payload, signature, parts = parsed
    display_token_info(header, payload)

    all_checks = {"none","brute","confusion","sensitive","expiry","kid",
                  "jwk","jku","x5c","claims","rsa","jti"}

    if args.checks == "all":
        run = all_checks
    else:
        run = set(args.checks.lower().split(",")) & all_checks

    results = []

    # v1 checks
    if "none"      in run: results.append(check_none_algorithm(header, parts))
    if "brute"     in run and not args.skip_bruteforce:
        results.append(check_weak_secret(header, parts, args.wordlist))
    elif args.skip_bruteforce:
        results.append({"check":"Weak Secret Brute Force","status":"SKIPPED","details":"Skipped by user"})
    if "confusion" in run: results.append(check_algorithm_confusion(header, parts))
    if "sensitive" in run: results.append(check_sensitive_data(payload))
    if "expiry"    in run: results.append(check_expiry(payload))
    if "kid"       in run: results.append(check_kid_injection(header))

    # v2 checks
    if "jwk"    in run: results.append(check_embedded_jwk(header, parts))
    if "jku"    in run: results.append(check_jku_injection(header))
    if "x5c"    in run: results.append(check_x5c_injection(header))
    if "claims" in run: results.append(check_claim_tampering(payload, parts))
    if "rsa"    in run: results.append(check_weak_rsa_key(header))
    if "jti"    in run: results.append(check_missing_jti(payload))

    print_summary(results)


if __name__ == "__main__":
    main()
