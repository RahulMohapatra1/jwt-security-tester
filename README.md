# JWT Security Tester

A command-line security tool that scans JSON Web Tokens (JWTs) for 12 common vulnerabilities. Built by an Application Security Engineer based on real JWT weaknesses found during web and API penetration testing engagements.

> **Disclaimer:** This tool is intended for authorised security testing only. Only use it on systems you own or have explicit written permission to test.

---

## Compatibility

| Platform | Supported | Tested |
|---|---|---|
| Windows 10 / 11 | ✅ | Python 3.8+ |
| macOS 12+ (Intel & Apple Silicon) | ✅ | Python 3.8+ |
| Linux (Ubuntu, Debian, Kali, Arch) | ✅ | Python 3.8+ |

**Python version required:** 3.8 or higher
**No OS-specific dependencies.** All libraries used (`cryptography`, `pyfiglet`) are pure Python with pre-built wheels for all three platforms.

---

## Installation

Works the same on Windows, macOS, and Linux.

**Step 1 — Clone the repo:**
```bash
git clone https://github.com/RahulMohapatra1/jwt-security-tester
cd jwt-security-tester
```

**Step 2 — Install dependencies:**
```bash
pip install -r requirements.txt
```

That is all. No environment setup, no Docker, no additional configuration.

---

## Usage

### Interactive mode — paste token when prompted (recommended)
```bash
# Windows
python jwt_tester.py

# macOS / Linux
python3 jwt_tester.py
```

### Pass token directly via flag
```bash
python3 jwt_tester.py -t <your_jwt_token>
```

### Use the full 103k wordlist for thorough brute force
```bash
python3 jwt_tester.py -t <token> -w wordlists/jwt-secrets-full.txt
```

### Skip brute force for faster run (all other 11 checks still run)
```bash
python3 jwt_tester.py -t <token> --skip-bruteforce
```

### Run specific checks only
```bash
python3 jwt_tester.py -t <token> --checks none,expiry,claims,jti
```

Available check names: `none`, `brute`, `confusion`, `sensitive`, `expiry`, `kid`, `jwk`, `jku`, `x5c`, `claims`, `rsa`, `jti`

---

## Vulnerability Checks

| # | Check | Severity if Found | Description |
|---|---|---|---|
| 1 | None Algorithm Attack | Critical | Token crafted with `alg:none` — no signature verification |
| 2 | Weak Secret Brute Force | Critical | HMAC secret tested against 5000 high-probability secrets |
| 3 | Algorithm Confusion (RS256→HS256) | High | Asymmetric alg detects confusion attack opportunity |
| 4 | Sensitive Data in Payload | High | Passwords, API keys, PII scanned in decoded payload |
| 5 | Missing / Expired `exp` Claim | Critical / Medium | Token never expires or expiry not validated |
| 6 | `kid` Header Injection | Critical | Path traversal and SQLi patterns in key ID header |
| 7 | Embedded JWK Injection | Critical | Attacker-controlled public key embedded in token header |
| 8 | JKU / x5u URL Injection | High | Key URL redirected to attacker-controlled server |
| 9 | x5c Certificate Chain Injection | Critical | Self-signed or malicious cert embedded in header |
| 10 | Claim Tampering & Privilege Escalation | Critical | Admin/superuser roles detected + tampered token demo |
| 11 | Weak RSA Key Size | Critical | RSA key below 2048 bits detected from embedded JWK/x5c |
| 12 | Missing `jti` Claim | Medium | No JWT ID — token cannot be revoked or replay-protected |

---

## Wordlists

| File | Secrets | Use case |
|---|---|---|
| `wordlists/jwt-secrets-top5000.txt` | 5,000 | **Default.** Smart-ranked by probability — JWT-specific patterns first |
| `wordlists/jwt-secrets-full.txt` | 103,838 | Full scan. Use with `-w` flag when top5000 does not find the secret |
| `wordlists/common_secrets.txt` | 109 | Curated hand-picked list. Subset of top5000 |

**Why top5000 as default?**
The 5000 secrets are ranked by probability — secrets containing `jwt`, `secret`, `token`, `key`, and framework names (`flask`, `django`, `laravel`) are tested first. This hits real-world weak secrets in under 0.02 seconds while keeping the tool fast for every run.

**Update wordlists to latest version:**
```bash
python3 wordlists/update_wordlists.py
```
This pulls the latest from `danielmiessler/SecLists` and `wallarm/jwt-secrets` and merges them into `jwt-secrets-full.txt`.

---

## Example Output

```
   ___  _    _ _____   _____         _
  |_  || |  | |_   _| |_   _|       | |
    | || |  | | | |     | | ___  ___| |_ ___ _ __
    | || |/\| | | |     | |/ _ \/ __| __/ _ \ '__|
/\__/ /\  /\  / | |     | |  __/\__ \ ||  __/ |
\____/  \/  \/ \_/     \_/\___||___/\__\___|_|

  By Rahul Mohapatra
  github.com/RahulMohapatra1

  ········~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Scans a JWT for 12 security vulnerabilities including
  weak secrets, algorithm attacks, claim tampering,
  replay risks, and certificate chain injection.
  ········~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  v2.0  ·  12 checks  ·  AppSec Research Tool

  JWT >  <paste token here>

  ── CHECK 10: Claim Tampering & Privilege Escalation ──
  [CRITICAL] HIGH-PRIVILEGE value detected: 'role' = 'admin'
  [CRITICAL] High-privilege role found in token.
  Even without cracking the secret, this token carries admin-level claims.
  Any successful algorithm attack would allow forging an admin token.

  SUMMARY: Critical:1  Warnings:2  Passed:8  Other:1
```

---

## Project Structure

```
jwt-security-tester/
├── jwt_tester.py                  # Main CLI tool — all 12 checks
├── wordlists/
│   ├── common_secrets.txt         # 109 curated high-probability secrets
│   ├── jwt-secrets-top5000.txt    # 5,000 smart-ranked secrets (default)
│   ├── jwt-secrets-full.txt       # 103,838 secrets (full scan)
│   └── update_wordlists.py        # Pulls latest from SecLists + wallarm
├── tests/
│   └── test_tokens.py             # Automated tests with vulnerable tokens
├── requirements.txt               # cryptography, pyfiglet
└── README.md
```

---

## Running Tests

```bash
python3 tests/test_tokens.py
```

Generates known-vulnerable tokens and tests all checks against them. Covers all 12 vulnerability categories with both positive (vulnerable) and negative (safe) cases.

---

## Wordlist Sources

All sources are MIT licensed public security research repositories:

- **SecLists** — `danielmiessler/SecLists` — `Passwords/scraped-JWT-secrets.txt`
- **Wallarm JWT Secrets** — `wallarm/jwt-secrets` — `jwt.secrets.list`

These are the same lists used by industry-standard tools like `hashcat`, `john`, and `jwt_tool`.

---

## Background

This tool was built to automate JWT security checks performed manually during API penetration testing engagements. During assessments of REST APIs and microservices, JWT misconfigurations were consistently in the top 3 most common findings — particularly weak secrets, missing expiry claims, and admin-role tokens without audience validation.

The checks are based on:
- [OWASP Testing Guide — Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- CVE-2018-0114 (Embedded JWK injection)
- CVE-2022-21449 (ECDSA psychic signatures)

---

## Roadmap

- [ ] `--url` flag — send crafted attack tokens to a live API endpoint and show response codes
- [ ] `--output report.json` — export all findings as structured JSON for developer reports
- [ ] ES256 / ECDSA psychic signatures check (CVE-2022-21449)
- [ ] Numeric role escalation testing (`role: 5` → `role: 0`, `role: 1`)
- [ ] `nbf` bypass crafted token generation
- [ ] Semgrep custom rules for Go microservices (companion project)

---

## Author

**Rahul Mohapatra** — Application Security Engineer
[github.com/RahulMohapatra1](https://github.com/RahulMohapatra1) | [linkedin.com/in/rahul-mohapatra-25428718a](https://linkedin.com/in/rahul-mohapatra-25428718a)

---

*For educational and authorised security testing purposes only.*
