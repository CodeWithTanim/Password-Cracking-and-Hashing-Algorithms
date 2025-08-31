"""
Simple PasswordCracker class implementing:
- dictionary attack
- small brute-force attack (letters + digits) for short passwords
This is for educational/demo purposes only.
"""

import itertools
import string
from typing import Optional, Callable
from .utils import load_wordlist, detect_hash_algorithm
from .hash_functions import hash_md5, hash_sha256, hash_sha512, verify_bcrypt
from .salting import hash_with_salt


class PasswordCracker:
    def __init__(self, target_hash: str, algorithm: Optional[str] = None, salt: Optional[str] = None):
        """
        target_hash: the hash to crack
        algorithm: optional, if not provided we try to detect
        salt: optional, hex salt for salted hashes (for MD5/SHA variants)
        """
        self.target_hash = target_hash
        self.algorithm = algorithm or detect_hash_algorithm(target_hash)
        self.salt = salt

    def _hash_candidate(self, candidate: str) -> str:
        """Hash candidate based on selected algorithm."""
        algo = self.algorithm
        if algo == "md5":
            return hash_md5(candidate)
        if algo == "sha512":
            return hash_sha512(candidate)
        if algo == "sha256":
            return hash_sha256(candidate)
        # bcrypt: we do not compute a raw bcrypt digest; instead use verify_bcrypt
        return candidate  # for bcrypt path, we compare differently

    def dictionary_attack(self, wordlist_path: str) -> Optional[str]:
        """Try each word in wordlist to match the target hash."""
        words = load_wordlist(wordlist_path)
        for word in words:
            if self.salt and self.algorithm in ("sha256", "sha512", "md5"):
                cand_hash = hash_with_salt(word, self.salt, algo=self.algorithm)
                if cand_hash.lower() == self.target_hash.lower():
                    return word
            elif self.algorithm == "bcrypt":
                if verify_bcrypt(word, self.target_hash):
                    return word
            else:
                cand_hash = self._hash_candidate(word)
                if cand_hash.lower() == self.target_hash.lower():
                    return word
        return None

    def brute_force(self, max_len: int = 4, charset: Optional[str] = None) -> Optional[str]:
        """
        Very small brute-force generator for demo:
        - max_len: max length to attempt (keep small for performance)
        - charset: string of characters to try; default is lowercase + digits
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        # For bcrypt, brute force will use verify_bcrypt for each candidate.
        for length in range(1, max_len + 1):
            for tup in itertools.product(charset, repeat=length):
                candidate = "".join(tup)
                # salted hashing
                if self.salt and self.algorithm in ("sha256", "sha512", "md5"):
                    cand_hash = hash_with_salt(candidate, self.salt, algo=self.algorithm)
                    if cand_hash.lower() == self.target_hash.lower():
                        return candidate
                elif self.algorithm == "bcrypt":
                    if verify_bcrypt(candidate, self.target_hash):
                        return candidate
                else:
                    cand_hash = self._hash_candidate(candidate)
                    if cand_hash.lower() == self.target_hash.lower():
                        return candidate
        return None
