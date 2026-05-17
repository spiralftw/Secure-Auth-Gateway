# =============================================================================
# database.py — Database Models
# =============================================================================
#
# This file defines the structure of the database using SQLAlchemy, which is
# an ORM (Object-Relational Mapper). An ORM lets us work with the database
# using Python classes instead of writing raw SQL queries. This also
# automatically protects against SQL injection attacks, because values are
# always parameterized (never inserted directly into query strings).
#
# We use SQLite for development — it stores everything in a single file
# called "database.sqlite" in the project folder. No server setup needed.

from flask_sqlalchemy import SQLAlchemy
import uuid
from datetime import datetime

# The db object is the central connection point between Flask and the database.
# It is initialized in app.py with the actual Flask app object.
db = SQLAlchemy()


class User(db.Model):
    """
    Represents a single user account in the system.

    This table stores everything needed to authenticate a user:
    - Their email and hashed password (for standard login)
    - Their encrypted TOTP secret (for two-factor authentication)
    - Their OAuth provider info (for GitHub/Google login)
    """

    # UUID as the primary key instead of an auto-incrementing integer.
    # Reason: an integer ID leaks information — an attacker can tell how many
    # users exist (e.g. id=5 means at least 5 users). A UUID reveals nothing.
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # The user's email address, used as their username. Must be unique.
    email = db.Column(db.String, unique=True, nullable=False)

    # The Argon2id hash of the user's password.
    # NEVER store the plaintext password — only this hash.
    # nullable=True because OAuth users don't have a password at all.
    password_hash = db.Column(db.String, nullable=True)

    # Whether the user has enabled two-factor authentication (MFA).
    mfa_enabled = db.Column(db.Boolean, default=False)

    # The TOTP seed, encrypted with AES-256-GCM before being stored here.
    # Storing it in plaintext would be a critical security risk if the
    # database is ever leaked, since it would allow anyone to generate
    # valid one-time codes for all users.
    mfa_secret_enc = db.Column(db.String, nullable=True)  # The encrypted seed

    # The Initialization Vector (IV) used during encryption.
    # The IV is required to decrypt the seed — it is not a secret itself,
    # but it must be stored alongside the ciphertext to allow decryption.
    mfa_iv = db.Column(db.String, nullable=True)

    # Note: The AES-GCM authentication tag is appended to the ciphertext
    # automatically by the cryptography library, so no separate column is
    # needed for it.

    # For users who sign in with GitHub or Google instead of a password.
    # oauth_provider is the name of the service (e.g. "github").
    # oauth_id is the unique user ID assigned by that service.
    oauth_provider = db.Column(db.String, nullable=True)
    oauth_id       = db.Column(db.String, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SecurityLog(db.Model):
    """
    Records suspicious security events for monitoring and auditing.

    Every time something suspicious happens — a bot trips the honeypot,
    someone exceeds the login rate limit, or a login fails — an entry is
    written here. This allows you to review attacks after the fact.
    """

    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String, nullable=False)

    # A short string describing what happened. Examples:
    #   "HONEYPOT_TRIGGERED"  — a bot filled the hidden form field
    #   "RATE_LIMIT_EXCEEDED" — too many login attempts from one IP
    #   "LOGIN_FAILURE"       — wrong email or password submitted
    action = db.Column(db.String, nullable=False)

    # The email that was submitted in the request (if any).
    # Useful for spotting which accounts are being targeted.
    email = db.Column(db.String, nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
