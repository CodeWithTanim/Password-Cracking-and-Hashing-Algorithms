"""
Simple salting utilities for non-bcrypt hashes.
bcrypt already contains a salt internally, but for MD5/SHA you should add salt manually.
"""

import os
import hashlib
from typing import Tuple


def generate_salt(length: int = 16) -> str:
    """Generate a hex salt of `length` bytes (returned as hex string)."""
    return os.urandom(length).hex()


def hash_with_salt(plaintext: str, salt: str, algo: str = "sha256") -> str:
    """
    Hash plaintext + salt with chosen algorithm.
    - salt is a hex string
    - algo can be 'md5', 'sha256', 'sha512'
    Returns hex digest.
    """
    if algo.lower() == "md5":
        h = hashlib.md5()
    elif algo.lower() == "sha512":
        h = hashlib.sha512()
    else:
        h = hashlib.sha256()
    # It's common to combine as salt + password or password + salt
    combined = (salt + plaintext).encode("utf-8")
    h.update(combined)
    return h.hexdigest()


def verify_hash_with_salt(plaintext: str, salt: str, expected_hash: str, algo: str = "sha256") -> bool:
    """Verify a salted hash."""
    return hash_with_salt(plaintext, salt, algo) == expected_hash
