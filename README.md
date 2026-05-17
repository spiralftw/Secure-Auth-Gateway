# Secure Auth Gateway

A working authentication service demonstrating secure programming practices, built as a coursework project for **COMP.SEC.300 – Secure Programming** at Tampere University.

## Features

- **Password hashing** — Argon2id (OWASP recommended)
- **Encryption at rest** — AES-256-GCM for TOTP seeds
- **Multi-factor authentication** — TOTP via Google Authenticator, Authy, or any RFC 6238 app
- **Bot detection** — honeypot form field
- **Brute-force protection** — rate limiting (5 attempts / 15 minutes / IP)
- **Third-party login** — GitHub OAuth 2.0 with CSRF state verification
- **Timing-safe login** — prevents user enumeration via response time

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Framework | Flask |
| Database | SQLite (SQLAlchemy ORM) |
| Password hashing | argon2-cffi |
| Encryption | cryptography (AES-256-GCM) |
| TOTP | pyotp |
| OAuth | Authlib |
| Secrets | python-dotenv |

## Project Structure

```
secure_auth_gateway/
├── app.py              # All routes and request handling
├── auth.py             # Password hashing (Argon2id)
├── encryption.py       # AES-256-GCM encrypt / decrypt
├── mfa.py              # TOTP seed generation, QR code, verification
├── database.py         # SQLAlchemy models (User, SecurityLog)
├── requirements.txt
├── .env.example
└── templates/
    ├── base.html        # Shared layout and CSS
    ├── login.html       # Login form (includes honeypot field)
    ├── register.html    # Registration form (includes honeypot field)
    ├── mfa_setup.html   # QR code display and first-code confirmation
    ├── mfa_verify.html  # Code entry during login
    └── dashboard.html   # Protected page shown after login
```

## Installation

### Prerequisites

- Python 3.10 or newer
- pip

### Steps

**1. Clone or download the project and open a terminal in the project folder.**

**2. Install dependencies:**

```bash
pip install -r requirements.txt
```

**3. Generate an encryption key:**

```bash
python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Copy the output.

**4. Create your `.env` file:**

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum:

```
ENCRYPTION_KEY=<paste your generated key here>
SECRET_KEY=<paste a second random key here>
```

> **Never commit `.env` to version control.** It contains secrets that must stay private.

**5. Run the app:**

```bash
python3 app.py
```

Open your browser at [http://localhost:5000](http://localhost:5000).

## Usage

### Register

Go to `/register`, enter an email and password (minimum 8 characters), and click **Create account**. Your password is immediately hashed with Argon2id — the plaintext is never stored.

### Log In

Go to `/login` and enter your credentials. If MFA is not enabled you land on the dashboard directly. If MFA is enabled you are redirected to the code verification page first.

### Enable Two-Factor Authentication

1. Log in and go to the dashboard.
2. Click **Enable MFA**.
3. Scan the QR code with Google Authenticator, Authy, or any TOTP app.
4. Enter the 6-digit code shown in the app to confirm setup.
5. Every subsequent login will require both your password and a fresh code.

### Log In with GitHub

Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in your `.env` file (create an OAuth App at [github.com/settings/developers](https://github.com/settings/developers), callback URL: `http://localhost:5000/oauth/github/callback`), then click **Continue with GitHub** on the login page.

### Log Out

Click **Sign out** in the navigation bar, or visit `/logout` directly.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ENCRYPTION_KEY` | ✅ | Base64-encoded 32-byte AES master key |
| `SECRET_KEY` | ✅ | Random secret for signing session cookies |
| `GITHUB_CLIENT_ID` | Optional | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Optional | GitHub OAuth App client secret |
| `DATABASE_URL` | Optional | Defaults to `sqlite:///database.sqlite` |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET / POST | `/register` | Registration form and handler |
| GET / POST | `/login` | Login form and handler |
| GET / POST | `/mfa/setup` | MFA enrolment (requires login) |
| GET / POST | `/mfa/verify` | TOTP code verification during login |
| GET | `/oauth/github/login` | Start GitHub OAuth flow |
| GET | `/oauth/github/callback` | GitHub OAuth callback |
| GET | `/logout` | Clear session and log out |
| GET | `/dashboard` | Protected dashboard (requires login) |

## Security

See [SECURITY.md](SECURITY.md) for a detailed description of every security control implemented in this project.
