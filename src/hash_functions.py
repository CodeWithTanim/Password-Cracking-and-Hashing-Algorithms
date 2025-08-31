"""
Implementations of common hash functions:
- MD5
- SHA256
- SHA512
- bcrypt (password-focused)
"""

import hashlib
import bcrypt


def hash_md5(plaintext: str) -> str:
    """Return MD5 hex digest of plaintext."""
    h = hashlib.md5()
    h.update(plaintext.encode("utf-8"))
    return h.hexdigest()


def hash_sha256(plaintext: str) -> str:
    """Return SHA-256 hex digest of plaintext."""
    h = hashlib.sha256()
    h.update(plaintext.encode("utf-8"))
    return h.hexdigest()


def hash_sha512(plaintext: str) -> str:
    """Return SHA-512 hex digest of plaintext."""
    h = hashlib.sha512()
    h.update(plaintext.encode("utf-8"))
    return h.hexdigest()


def hash_bcrypt(plaintext: str, rounds: int = 12) -> str:
    """
    Return a bcrypt hashed password (as a string).
    rounds: cost/work factor (default 12). Lower is faster; higher is slower but safer.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    salt = bcrypt.gensalt(rounds)
    hashed = bcrypt.hashpw(plaintext, salt)
    return hashed.decode("utf-8")


def verify_bcrypt(plaintext: str, hashed: str) -> bool:
    """Verify plaintext against a bcrypt hash."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")
    try:
        return bcrypt.checkpw(plaintext, hashed)
    except ValueError:
        return False
