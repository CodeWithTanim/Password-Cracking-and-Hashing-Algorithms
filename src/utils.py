"""
Helper utilities:
- load_wordlist
- compare_hash
- detect_hash_algorithm (simple heuristic)
"""

from typing import List, Optional
import os


def load_wordlist(path: str) -> List[str]:
    """Load lines from a wordlist, stripping whitespace and skipping blank lines."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def compare_hash(candidate_hash: str, target_hash: str) -> bool:
    """Compare two hashes (case-insensitive)."""
    return candidate_hash.lower() == target_hash.lower()


def detect_hash_algorithm(hash_str: str) -> Optional[str]:
    """
    Very simple detector based on length/format:
    - MD5: 32 hex chars
    - SHA256: 64 hex chars
    - SHA512: 128 hex chars
    - bcrypt: starts with $2b$ or $2a$ and contains salt rounds, typical length ~60
    Returns 'md5', 'sha256', 'sha512', 'bcrypt' or None
    """
    s = hash_str.strip()
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        return "bcrypt"
    hex_len = len(s)
    # ensure hex only for MD5/SHA
    try:
        int(s, 16)
        if hex_len == 32:
            return "md5"
        if hex_len == 64:
            return "sha256"
        if hex_len == 128:
            return "sha512"
    except ValueError:
        pass
    return None
