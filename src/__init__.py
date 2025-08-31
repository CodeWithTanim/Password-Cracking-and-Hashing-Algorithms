"""
Password Cracking and Hashing Algorithms - src package
Expose convenient functions for external usage.
"""
from .hash_functions import (
    hash_md5,
    hash_sha256,
    hash_sha512,
    hash_bcrypt,
    verify_bcrypt,
)
from .salting import hash_with_salt, verify_hash_with_salt
from .password_cracker import PasswordCracker
from .utils import load_wordlist, detect_hash_algorithm, compare_hash

__all__ = [
    "hash_md5",
    "hash_sha256",
    "hash_sha512",
    "hash_bcrypt",
    "verify_bcrypt",
    "hash_with_salt",
    "verify_hash_with_salt",
    "PasswordCracker",
    "load_wordlist",
    "detect_hash_algorithm",
    "compare_hash",
]
