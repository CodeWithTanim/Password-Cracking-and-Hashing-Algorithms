import os
from src.hash_functions import hash_md5, hash_bcrypt
from src.password_cracker import PasswordCracker

# Prepare a tiny wordlist file for the test
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "tmp_wordlist.txt")

def setup_module(module):
    with open(WORDLIST_PATH, "w") as f:
        f.write("\n".join(["abc", "testpw", "password123", "hello123"]))

def teardown_module(module):
    try:
        os.remove(WORDLIST_PATH)
    except OSError:
        pass

def test_dictionary_attack_md5():
    target = hash_md5("password123")
    cracker = PasswordCracker(target, algorithm="md5")
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "password123"

def test_dictionary_attack_bcrypt():
    target = hash_bcrypt("testpw", rounds=4)
    cracker = PasswordCracker(target, algorithm="bcrypt")
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "testpw"

def test_bruteforce_small():
    # simple test: try to crack "ab" with md5 using brute_force with charset 'ab'
    import hashlib
    pw = "ab"
    target = hashlib.md5(pw.encode()).hexdigest()
    cracker = PasswordCracker(target, algorithm="md5")
    found = cracker.brute_force(max_len=2, charset="ab")
    assert found == "ab"
