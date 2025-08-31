"""
Demo cracker script (CLI)
Examples:
  python examples/demo_cracker.py --mode dictionary --hash "<hash>" --wordlist examples/wordlist_small.txt
  python examples/demo_cracker.py --mode brute --hash "<hash>" --max-len 3
"""
import argparse
from src.password_cracker import PasswordCracker
from src.utils import detect_hash_algorithm

def main():
    parser = argparse.ArgumentParser(description="Demo password cracker (educational).")
    parser.add_argument("--mode", choices=["dictionary", "brute"], required=True, help="Attack mode")
    parser.add_argument("--hash", dest="target_hash", required=True, help="Target hash to crack")
    parser.add_argument("--wordlist", help="Path to wordlist for dictionary attack")
    parser.add_argument("--max-len", type=int, default=4, help="Max length for brute-force (small!)")
    parser.add_argument("--salt", help="Hex salt (if target is salted sha/md5)")
    parser.add_argument("--charset", help="Custom charset for brute force")
    args = parser.parse_args()

    algo = detect_hash_algorithm(args.target_hash)
    print("Detected algorithm:", algo)
    cracker = PasswordCracker(args.target_hash, algorithm=algo, salt=args.salt)

    if args.mode == "dictionary":
        if not args.wordlist:
            print("Dictionary mode requires --wordlist")
            return
        found = cracker.dictionary_attack(args.wordlist)
        if found:
            print("FOUND:", found)
        else:
            print("Not found in wordlist.")
    else:
        found = cracker.brute_force(max_len=args.max_len, charset=args.charset)
        if found:
            print("FOUND:", found)
        else:
            print("Not found with brute-force up to length", args.max_len)

if __name__ == "__main__":
    main()
