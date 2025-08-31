"""
Demo: hashing using various algorithms
Run: python examples/demo_hashing.py
"""
from src.hash_functions import hash_md5, hash_sha256, hash_sha512, hash_bcrypt, verify_bcrypt

def main():
    plaintext = "password123"
    print("Plaintext:", plaintext)
    print("MD5:", hash_md5(plaintext))
    print("SHA256:", hash_sha256(plaintext))
    print("SHA512:", hash_sha512(plaintext))

    bcrypt_hash = hash_bcrypt(plaintext, rounds=12)
    print("bcrypt:", bcrypt_hash)
    print("bcrypt verify (correct):", verify_bcrypt(plaintext, bcrypt_hash))
    print("bcrypt verify (wrong):", verify_bcrypt("badpass", bcrypt_hash))

if __name__ == "__main__":
    main()
