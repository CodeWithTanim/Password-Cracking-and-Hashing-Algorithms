"""
Demo: salting for non-bcrypt hashes (MD5/SHA)
Run: python examples/demo_salting.py
"""
from src.salting import generate_salt, hash_with_salt, verify_hash_with_salt

def main():
    pw = "mysecret"
    salt = generate_salt(8)  # 8 bytes -> 16 hex chars
    print("Salt (hex):", salt)
    hashed = hash_with_salt(pw, salt, algo="sha256")
    print("Salted SHA256:", hashed)
    print("Verify correct:", verify_hash_with_salt(pw, salt, hashed, algo="sha256"))
    print("Verify wrong:", verify_hash_with_salt("wrong", salt, hashed, algo="sha256"))

if __name__ == "__main__":
    main()
