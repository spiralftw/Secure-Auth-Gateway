# =============================================================================
# auth.py — Password Hashing with Argon2id
# =============================================================================
#
# WHY DO WE HASH PASSWORDS INSTEAD OF STORING THEM DIRECTLY?
# If the database is ever leaked (a very common real-world occurrence),
# the attacker would immediately have every user's password in plaintext.
# Many users reuse passwords across sites, so this leads to account takeovers
# on other services as well. Hashing solves this: we store a one-way
# "fingerprint" of the password, not the password itself.
#
# WHY ARGON2ID INSTEAD OF MD5 OR SHA-256?
# MD5 and SHA-256 are general-purpose hash functions designed to be FAST.
# A modern GPU can compute billions of SHA-256 hashes per second, making
# brute-force attacks practical. Argon2id is specifically designed for
# password hashing — it is deliberately SLOW and uses a large amount of
# memory, making GPU-based attacks thousands of times more expensive.
# Argon2id won the Password Hashing Competition (2015) and is the current
# OWASP recommendation for password storage.
#
# WHAT IS A "SALT"?
# A salt is a random value mixed into the hash before it is computed.
# Without a salt, two users with the same password produce the same hash,
# allowing an attacker to crack many passwords at once using precomputed
# "rainbow tables." With a unique random salt per user, each hash is unique
# even if the underlying passwords are identical. Argon2id generates and
# stores the salt automatically — it is embedded in the hash string.

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Create the hasher once at module load time with OWASP-recommended parameters:
#   time_cost=3       — run the algorithm 3 times (increases computation time)
#   memory_cost=65536 — use 64 MB of memory (makes GPU attacks expensive)
#   parallelism=4     — use 4 parallel threads
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(plaintext: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    Returns a self-contained string that includes the algorithm, parameters,
    salt, and hash. Example output:
        $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

    Store this string in the database. Never store the original password.
    """
    # .hash() automatically generates a random salt and appends it to
    # the output string, so you never need to manage salts manually.
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored Argon2id hash.

    Returns True if the password is correct, False otherwise.

    This function is timing-safe: it always takes the same amount of time
    regardless of whether the password is correct or how closely it matches.
    This prevents "timing attacks" where an attacker measures response time
    to learn something about the stored hash.
    """
    try:
        # .verify() re-computes the hash with the stored salt and compares.
        _hasher.verify(stored_hash, plaintext)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # Return False for any verification failure — never reveal details.
        return False
