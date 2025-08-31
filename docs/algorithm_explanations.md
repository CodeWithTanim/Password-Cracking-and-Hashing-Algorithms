# Algorithm Explanations (student-friendly)

## MD5
- Produces a 128-bit hash.
- Fast but cryptographically broken for collision resistance.
- Use only for legacy or non-security uses.

## SHA-256 / SHA-512
- Part of SHA-2 family.
- SHA-256 produces 256-bit digest; SHA-512 produces 512-bit digest.
- Stronger than MD5, widely used for integrity and signatures.

## bcrypt
- A password hashing function that is intentionally slow and adaptive via a cost factor.
- Adds internal salt and is recommended for password storage instead of raw SHA or MD5.
- Resistant to GPU-based brute force better than general-purpose hashes.

## Salting
- Salt = random bytes appended/prepended to password before hashing.
- Prevents precomputed rainbow table attacks.
- For bcrypt, the library manages salt automatically but you can supply your own.
