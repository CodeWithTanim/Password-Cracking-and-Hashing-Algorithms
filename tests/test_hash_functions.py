import re
from src.hash_functions import hash_md5, hash_sha256, hash_sha512, hash_bcrypt, verify_bcrypt

def test_md5_length():
    h = hash_md5("abc")
    assert isinstance(h, str)
    assert len(h) == 32
    assert re.fullmatch(r"[0-9a-f]{32}", h)

def test_sha256_length():
    h = hash_sha256("abc")
    assert len(h) == 64

def test_sha512_length():
    h = hash_sha512("abc")
    assert len(h) == 128

def test_bcrypt_roundtrip():
    pw = "testpw"
    h = hash_bcrypt(pw, rounds=4)  # use small rounds for test speed
    assert verify_bcrypt(pw, h)
    assert not verify_bcrypt("wrong", h)
