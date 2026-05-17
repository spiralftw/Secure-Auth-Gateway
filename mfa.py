# =============================================================================
# mfa.py — Multi-Factor Authentication with TOTP
# =============================================================================
#
# WHAT IS TOTP?
#   TOTP stands for Time-based One-Time Password (RFC 6238). It is the
#   algorithm behind the 6-digit codes shown by apps like Google Authenticator,
#   Authy, and Microsoft Authenticator.
#
# HOW DOES IT WORK?
#   1. During setup, the server generates a random secret (the "seed").
#   2. The user scans a QR code with their authenticator app — this transfers
#      the seed to their phone.
#   3. Both the server and the phone now share the same secret seed.
#   4. Every 30 seconds, both independently compute:
#        code = HMAC-SHA1(seed + floor(current_unix_time / 30))
#      Because they use the same seed and the same clock, they get the same
#      6-digit number without ever communicating.
#   5. At login, the user types the code from their phone. The server
#      computes the expected code and compares.
#
# WHY IS THIS SECURE?
#   - The code changes every 30 seconds, so intercepted codes are useless.
#   - An attacker who steals the database only gets an encrypted seed
#     (see encryption.py), not a usable one.
#   - Even if an attacker knows your password, they cannot log in without
#     physical access to your phone.
#
# WHAT IS THE QR CODE?
#   The QR code encodes an "otpauth://" URI, which is a standard format
#   understood by all authenticator apps:
#     otpauth://totp/AppName:user@example.com?secret=SEED&issuer=AppName
#   Scanning this URI automatically adds the account to the authenticator app.

import pyotp
import qrcode
import io
import base64


def generate_secret() -> str:
    """
    Generate a cryptographically random Base32 TOTP seed.

    The seed is the shared secret between the server and the user's phone.
    Base32 encoding is used because it is URL-safe and easy to type manually
    if the user cannot scan the QR code.

    IMPORTANT: Encrypt this value (see encryption.py) before storing it in
    the database. Storing it in plaintext is a critical security risk.
    """
    # pyotp.random_base32() uses os.urandom() internally — cryptographically secure.
    return pyotp.random_base32()


def get_qr_uri(secret: str, email: str) -> str:
    """
    Build the otpauth:// URI that encodes the TOTP configuration.

    This URI is converted into a QR code which the user scans with their
    authenticator app. The app parses the URI and adds the account
    automatically with the correct seed and settings.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="SecureAuthGateway"
    )


def get_qr_code_base64(uri: str) -> str:
    """
    Render the otpauth URI as a QR code image and return it as a
    base64-encoded PNG string.

    The result can be embedded directly in an HTML <img> tag:
        <img src="data:image/png;base64,RESULT_HERE">
    This avoids needing to save the image to disk or serve it as a
    separate file.
    """
    # qrcode.make() creates a PIL Image object from the URI string.
    img = qrcode.make(uri)

    # Save the image into an in-memory buffer instead of a file on disk.
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")

    # base64-encode the raw PNG bytes so they can be safely embedded in HTML.
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def verify_code(secret: str, code: str) -> bool:
    """
    Validate a 6-digit TOTP code against the given seed.

    Returns True if the code is valid, False otherwise.

    The valid_window=1 parameter accepts the current 30-second window plus
    one window in either direction (i.e. up to 30 seconds before or after).
    This gracefully handles small clock differences between the server and
    the user's phone without meaningfully weakening security.
    """
    # Strip whitespace in case the user accidentally added spaces.
    code = code.strip()

    return pyotp.TOTP(secret).verify(code, valid_window=1)
