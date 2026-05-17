# Security

This document describes every security control implemented in Secure Auth Gateway, the attack each one defends against, and where in the codebase it lives.

---

## Table of Contents

1. [Password Hashing — Argon2id](#1-password-hashing--argon2id)
2. [Encryption at Rest — AES-256-GCM](#2-encryption-at-rest--aes-256-gcm)
3. [Two-Factor Authentication — TOTP](#3-two-factor-authentication--totp)
4. [Honeypot Bot Detection](#4-honeypot-bot-detection)
5. [Rate Limiting](#5-rate-limiting)
6. [OAuth 2.0 with CSRF Protection](#6-oauth-20-with-csrf-protection)
7. [Timing-Safe Login](#7-timing-safe-login)
8. [OWASP Top 10 Mapping](#8-owasp-top-10-mapping)

---

## 1. Password Hashing — Argon2id

**File:** `auth.py`

### The problem

If the database is ever leaked, an attacker should not be able to recover users' actual passwords. General-purpose hash functions like MD5 and SHA-256 are designed to be as fast as possible — a modern GPU can compute billions of SHA-256 hashes per second, making brute-force and dictionary attacks practical within hours of a leak.

### The solution

Passwords are hashed with **Argon2id**, which won the Password Hashing Competition in 2015 and is the current OWASP recommendation. It is deliberately slow and memory-hard, making GPU-based cracking attacks orders of magnitude more expensive than with fast hash functions.

A unique random **salt** is generated automatically for each password. This ensures that two users with the same password produce completely different hashes, defeating precomputed rainbow table attacks.

### Parameters (OWASP minimum recommendations)

| Parameter | Value | Effect |
|---|---|---|
| `time_cost` | 3 | Runs the algorithm 3 times |
| `memory_cost` | 65 536 | Uses 64 MB of RAM per hash |
| `parallelism` | 4 | Uses 4 CPU threads |

### How it works

- At registration, `hash_password(plaintext)` is called. The plaintext password is never stored anywhere after this point.
- At login, `verify_password(plaintext, stored_hash)` re-derives the hash using the stored salt and compares it using a timing-safe internal comparison.
- The stored value looks like: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

---

## 2. Encryption at Rest — AES-256-GCM

**File:** `encryption.py`

### The problem

The TOTP seed (the secret shared with the user's authenticator app) must be read back in plaintext every time a login code is verified. Because hashing is one-way, symmetric encryption is required instead.

Storing the seed in plaintext would be a critical risk: a leaked database would immediately give an attacker valid TOTP codes for every user.

### The solution

TOTP seeds are encrypted with **AES-256-GCM** before being written to the database.

- **AES-256** is a symmetric block cipher with a 256-bit key. The same key encrypts and decrypts. A 256-bit key space (2²⁵⁶ possible keys) makes brute force completely infeasible.
- **GCM (Galois/Counter Mode)** appends a 16-byte authentication tag to the ciphertext. If even a single byte of the stored ciphertext is modified, decryption will raise an exception rather than silently returning corrupted data. This is called *authenticated encryption*.

### Initialization Vector (IV)

A fresh random 12-byte IV is generated using `os.urandom(12)` for every encryption operation. This ensures that encrypting the same seed twice with the same key produces different ciphertext. The IV is not secret — it is stored in the database alongside the ciphertext — but it must never be reused with the same key.

### Key management

The master encryption key lives in the `ENCRYPTION_KEY` environment variable and is never stored in the source code or the database. An attacker who steals only the database will have useless ciphertext without this key.

### Encryption flow (MFA setup)

1. Generate a random 12-byte IV.
2. Encrypt: `ciphertext = AES-GCM(key, IV, plaintext_seed)` — the 16-byte auth tag is appended automatically.
3. Base64-encode both the ciphertext and the IV.
4. Store both values in the `mfa_secret_enc` and `mfa_iv` columns of the `users` table.

### Decryption flow (login verification)

1. Load `mfa_secret_enc` and `mfa_iv` from the database; base64-decode both.
2. AES-GCM verifies the authentication tag first — raises `InvalidTag` if the data has been tampered with.
3. If the tag is valid, decrypt and return the plaintext seed for TOTP verification.

---

## 3. Two-Factor Authentication — TOTP

**File:** `mfa.py`

### What is TOTP?

Time-based One-Time Password (RFC 6238) is the algorithm behind the 6-digit codes in apps like Google Authenticator and Authy.

### How it works

1. During MFA setup, the server generates a random Base32 seed.
2. The seed is displayed as a QR code. The user scans it with their authenticator app, which stores the seed on their phone.
3. Every 30 seconds, both the server and the phone independently compute:

   ```
   code = HMAC-SHA1(seed, floor(unix_time / 30)) mod 10⁶
   ```

4. Because both use the same seed and the same clock, they produce the same 6-digit number without any network communication.
5. At login, the user enters the code from their app. The server runs the same computation and checks for a match.

### Clock tolerance

A `valid_window=1` tolerance is applied, accepting the previous and next 30-second window as well. This handles minor clock drift between the user's phone and the server without meaningfully weakening security.

### Why it helps

Even if an attacker steals a user's password, they cannot log in without physical access to the user's phone. Each code is valid for at most 30 seconds and is effectively single-use.

The seed itself is stored encrypted in the database (see [Section 2](#2-encryption-at-rest--aes-256-gcm)).

---

## 4. Honeypot Bot Detection

**File:** `app.py` (login and register routes); `templates/login.html`, `templates/register.html`

### The problem

Automated bots perform credential-stuffing and mass registration attacks by submitting login and registration forms programmatically. These attacks can be large-scale and difficult to block purely on rate.

### The solution

Both the login and registration forms contain a hidden `<input>` field named `website`:

```html
<input type="text" name="website"
       style="display:none"
       tabindex="-1"
       autocomplete="off"
       value="">
```

The field is invisible to real users through CSS (`display:none`) and is excluded from keyboard navigation (`tabindex="-1"`). A human user will never see or interact with it. Automated bots that fill out all form fields they find will populate it.

### Server-side check

```python
if request.form.get("website"):
    log_security_event(ip, "HONEYPOT_TRIGGERED", email)
    return jsonify({"error": "Invalid credentials."}), 401
```

The server always returns a generic error message — it never reveals to the bot that it was detected. The event is logged to the `SecurityLog` table with `action = "HONEYPOT_TRIGGERED"`.

---

## 5. Rate Limiting

**File:** `app.py`

### The problem

Brute-force attacks systematically try many passwords against a known email address. Without a limit, an attacker can make an unlimited number of attempts.

### How it works

Every login attempt is recorded in an in-memory dictionary keyed by IP address:

```python
{ "192.168.1.1": [datetime(...), datetime(...), ...] }
```

Before each attempt:

1. Timestamps older than 15 minutes are pruned.
2. If 5 or more attempts remain in the window, the server returns **HTTP 429 Too Many Requests** and logs the event as `RATE_LIMIT_EXCEEDED`.
3. Otherwise the attempt timestamp is recorded and the login proceeds.

### Limits

| Setting | Value |
|---|---|
| Maximum attempts | 5 |
| Time window | 15 minutes |
| HTTP status on block | 429 |

### Limitation

The current implementation stores attempt data in memory. This means limits reset on server restart. For a production deployment, replace the in-memory dictionary with **Redis** so limits persist across restarts and can be shared across multiple server instances.

---

## 6. OAuth 2.0 with CSRF Protection

**File:** `app.py` (`oauth_login`, `oauth_callback` routes)

### Flow (Authorization Code)

1. User clicks *Sign in with GitHub*.
2. The server generates a cryptographically random `state` token (`secrets.token_urlsafe(32)`) and stores it in the session.
3. The user is redirected to GitHub's login page with the `state` token included in the URL.
4. The user authenticates on GitHub's own servers — the application never sees their GitHub password.
5. GitHub redirects back to `/oauth/github/callback` with an authorization code and the `state` token.
6. **The server verifies that the returned `state` matches the value stored in the session.** If it does not match, the request is rejected with HTTP 403.
7. The server exchanges the authorization code for an access token (server-to-server — the token never passes through the browser).
8. The server calls GitHub's API to fetch the user's verified primary email address.
9. A local `User` record is found or created, and the session is started.

### Why the state parameter matters

Without it, an attacker could craft a malicious link that completes an OAuth flow *the attacker initiated*. If a victim follows this link, the attacker's GitHub account gets linked to the victim's local account — giving the attacker full access. The random `state` token, tied to the victim's current session, makes this attack impossible: the attacker cannot know or predict what value the server expects.

---

## 7. Timing-Safe Login

**File:** `app.py` (login route)

### The problem

If the server returns a response faster when an email address is not registered (skipping the password check) versus when it is (running the slow Argon2id verification), an attacker can measure response times to enumerate which email addresses have accounts — without ever needing to know any passwords. This is a *timing side-channel attack*.

### The solution

`verify_password()` is always called, even when the submitted email has no matching user in the database. When no user is found, a pre-computed dummy Argon2id hash is used as the comparison target:

```python
hash_to_check = user.password_hash if user else DUMMY_ARGON2ID_HASH
verify_password(submitted_password, hash_to_check)
```

This ensures the response time is identical whether the email exists or not, making timing measurements useless. The same generic error message is returned in both cases:

> *"Invalid email or password."*

---

## 8. OWASP Top 10 Mapping

| OWASP 2025 Category | Control Implemented |
|---|---|
| **A01 — Broken Access Control** | Session-based authentication on all protected routes. `/dashboard` and `/mfa/setup` check `session["user_id"]` before serving content. |
| **A04 — Cryptographic Failures** | Passwords hashed with Argon2id. TOTP seeds encrypted with AES-256-GCM at rest. Master key stored in environment — never in code or database. |
| **A05 — Injection** | SQLAlchemy ORM used throughout. All database values are parameterized automatically — no raw SQL string concatenation anywhere in the codebase. |
| **A07 — Authentication Failures** | TOTP MFA. Rate limiting (5 attempts / 15 min / IP). Honeypot bot detection. Timing-safe login. OAuth 2.0 with CSRF state verification. |
