# =============================================================================
# encryption.py — Symmetric Encryption with AES-256-GCM
# =============================================================================
#
# WHY DO WE NEED ENCRYPTION HERE (NOT JUST HASHING)?
# The TOTP seed (the secret shared with the user's authenticator app) must
# be read back in plaintext each time a login code is verified. Hashing is
# one-way and cannot be reversed, so it is unsuitable here. We need
# two-way (symmetric) encryption instead.
#
# WHAT IS AES-256-GCM?
#   AES (Advanced Encryption Standard) is a symmetric block cipher — the
#   same key is used to both encrypt and decrypt. "256" refers to the key
#   length in bits. A 256-bit key means 2^256 possible keys, which is
#   astronomically large and considered unbreakable by brute force.
#
#   GCM (Galois/Counter Mode) is the mode of operation. In addition to
#   encrypting the data, GCM produces an "authentication tag" — a short
#   checksum that proves the ciphertext has not been tampered with since
#   it was encrypted. If even one byte is changed, decryption will fail
#   loudly rather than silently producing garbage output. This property
#   is called "authenticated encryption."
#
# WHAT IS AN IV (INITIALIZATION VECTOR)?
#   The IV is a random value mixed into the encryption process. It must be
#   unique for every single encryption operation that uses the same key.
#   If the same IV is ever reused with the same key, an attacker can
#   potentially recover the plaintext or the key. We use os.urandom(12)
#   to generate a cryptographically secure random 12-byte IV each time.
#   The IV is not secret — it is stored alongside the ciphertext — but
#   it must be unpredictable and never reused.
#
# WHERE DOES THE KEY COME FROM?
#   The master encryption key is stored in the ENCRYPTION_KEY environment
#   variable. It must NEVER be hardcoded in the source code or committed
#   to version control.
#
#   Generate a key (run once):
#     python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
#
#   Set it before running the app:
#     Linux/Mac:  export ENCRYPTION_KEY=<your_key>
#     Windows:    set ENCRYPTION_KEY=<your_key>
#
#   Or add it to a .env file in the project folder:
#     ENCRYPTION_KEY=<your_key>

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_key() -> bytes:
    """
    Load the master encryption key from the ENCRYPTION_KEY environment variable.

    The key is fetched on every call (lazy loading) rather than at module
    import time. This is important because app.py loads the .env file after
    importing this module — if we read the environment at import time, the
    variable would not exist yet and the app would crash before it even starts.
    """
    raw = os.environ.get("ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError(
            "\n\n[encryption.py] ENCRYPTION_KEY is not set!\n"
            "Generate a key with:\n"
            "  python3 -c \"import secrets,base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())\"\n"
            "Then either:\n"
            "  export ENCRYPTION_KEY=<key>         (Linux/Mac)\n"
            "  set ENCRYPTION_KEY=<key>            (Windows)\n"
            "  Add ENCRYPTION_KEY=<key> to .env    (recommended)\n"
        )
    # base64.b64decode converts the text representation back to raw bytes.
    return base64.b64decode(raw)


def encrypt(plaintext: str) -> tuple:
    """
    Encrypt a plaintext string with AES-256-GCM.

    Returns a tuple: (ciphertext_b64, iv_b64)
      - ciphertext_b64: the encrypted data (includes the GCM auth tag)
      - iv_b64:         the initialization vector used during encryption

    Both values must be stored in the database. The IV is needed to decrypt;
    without it, decryption is impossible.
    """
    key = _get_key()
    aesgcm = AESGCM(key)

    # Generate a fresh, cryptographically random 12-byte IV.
    # 12 bytes is the recommended IV size for AES-GCM (96 bits).
    iv = os.urandom(12)

    # Encrypt the data. The AESGCM.encrypt() method returns the ciphertext
    # with the 16-byte GCM authentication tag appended at the end.
    # The third argument (None) is "additional authenticated data" — data
    # that is not encrypted but is covered by the authentication tag.
    # We don't use it here, so we pass None.
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    # Convert raw bytes to base64 text so the values can be stored in the
    # database as ordinary strings. base64 encodes binary data as ASCII text.
    return (
        base64.b64encode(ciphertext_with_tag).decode("utf-8"),
        base64.b64encode(iv).decode("utf-8"),
    )


def decrypt(ciphertext_b64: str, iv_b64: str) -> str:
    """
    Decrypt a ciphertext that was encrypted with encrypt().

    Takes the base64-encoded ciphertext and IV from the database.
    Returns the original plaintext string.

    If the ciphertext has been tampered with (even a single bit changed),
    this function will raise an InvalidTag exception — it will never silently
    return corrupted data. This is the "authenticated" part of AES-GCM.
    """
    key = _get_key()
    aesgcm = AESGCM(key)

    # Decode from base64 back to raw bytes.
    ciphertext_with_tag = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    # decrypt() first verifies the authentication tag, then decrypts.
    # Order matters: authenticate first, decrypt second. This prevents
    # "padding oracle" and similar attacks that exploit decryption errors.
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)

    return plaintext_bytes.decode("utf-8")
