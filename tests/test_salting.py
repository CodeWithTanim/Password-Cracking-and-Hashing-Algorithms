from src.salting import generate_salt, hash_with_salt, verify_hash_with_salt

def test_salt_and_verify():
    pw = "xyz"
    salt = generate_salt(4)  # 4 bytes
    h = hash_with_salt(pw, salt, algo="sha256")
    assert verify_hash_with_salt(pw, salt, h, algo="sha256")
    assert not verify_hash_with_salt("bad", salt, h, algo="sha256")
