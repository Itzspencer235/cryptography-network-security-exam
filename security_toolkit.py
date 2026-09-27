#!/usr/bin/env python3
"""
security_toolkit.py

A small command-line security toolkit for the ULK Polytechnic student
records system.

Features:
  - Generate an encryption key (stored OUTSIDE the repo, e.g. key.key)
  - Encrypt a student record file
  - Decrypt a student record file and verify it matches the original
  - Compute a SHA-256 hash of a file and detect later tampering

Usage:
  python security_toolkit.py generate-key [--key-file key.key]
  python security_toolkit.py encrypt <input_file> <output_file> [--key-file key.key]
  python security_toolkit.py decrypt <input_file> <output_file> [--key-file key.key]
  python security_toolkit.py hash <file> [--save hash.txt]
  python security_toolkit.py verify <file> --hash-file hash.txt

See README.md for full setup and example commands.
"""

import argparse
import hashlib
import os
import sys

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Error: the 'cryptography' package is required.\n"
          "Install it with: pip install cryptography", file=sys.stderr)
    sys.exit(1)


DEFAULT_KEY_FILE = "key.key"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key(key_file: str = DEFAULT_KEY_FILE) -> None:
    """Generate a new Fernet key and save it to key_file."""
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    print(f"New encryption key written to: {key_file}")
    print("Keep this file safe and OUTSIDE the git repository "
          "(it should be listed in .gitignore).")


def load_key(key_file: str) -> bytes:
    """Load a Fernet key from disk, with a clear error if it's missing/invalid."""
    if not os.path.isfile(key_file):
        raise FileNotFoundError(
            f"Key file '{key_file}' not found. "
            f"Run 'generate-key' first, or pass --key-file to point at your key."
        )
    with open(key_file, "rb") as f:
        key = f.read().strip()
    try:
        Fernet(key)  # validates the key format
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Key file '{key_file}' does not contain a valid Fernet key.") from exc
    return key


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_file(input_path: str, output_path: str, key_file: str) -> None:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file '{input_path}' does not exist.")

    key = load_key(key_file)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"Encrypted '{input_path}' -> '{output_path}'")


def decrypt_file(input_path: str, output_path: str, key_file: str) -> None:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Encrypted file '{input_path}' does not exist.")

    key = load_key(key_file)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed: wrong key, or the file is corrupted/not a "
            "valid encrypted file produced by this toolkit."
        ) from exc

    with open(output_path, "wb") as f:
        f.write(decrypted)

    print(f"Decrypted '{input_path}' -> '{output_path}'")


def verify_roundtrip(original_path: str, decrypted_path: str) -> bool:
    """Compare two files byte-for-byte (used to prove decrypt(encrypt(x)) == x)."""
    with open(original_path, "rb") as f1, open(decrypted_path, "rb") as f2:
        return f1.read() == f2.read()


# ---------------------------------------------------------------------------
# Integrity (SHA-256)
# ---------------------------------------------------------------------------

def compute_sha256(path: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File '{path}' does not exist.")

    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_hash(path: str, hash_file: str) -> None:
    digest = compute_sha256(path)
    with open(hash_file, "w") as f:
        f.write(digest + "\n")
    print(f"SHA-256 of '{path}': {digest}")
    print(f"Saved to '{hash_file}'")


def verify_hash(path: str, hash_file: str) -> bool:
    if not os.path.isfile(hash_file):
        raise FileNotFoundError(f"Hash file '{hash_file}' does not exist.")

    with open(hash_file, "r") as f:
        expected = f.read().strip()

    actual = compute_sha256(path)

    if actual == expected:
        print(f"OK: '{path}' matches the recorded hash. No tampering detected.")
        return True
    else:
        print(f"WARNING: '{path}' does NOT match the recorded hash!")
        print(f"  expected: {expected}")
        print(f"  actual:   {actual}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Student records security toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-key", help="Generate a new encryption key")
    p_gen.add_argument("--key-file", default=DEFAULT_KEY_FILE)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("input_file")
    p_enc.add_argument("output_file")
    p_enc.add_argument("--key-file", default=DEFAULT_KEY_FILE)

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("input_file")
    p_dec.add_argument("output_file")
    p_dec.add_argument("--key-file", default=DEFAULT_KEY_FILE)

    p_hash = sub.add_parser("hash", help="Compute and optionally save a SHA-256 hash")
    p_hash.add_argument("file")
    p_hash.add_argument("--save", default=None, help="Save the hash to this file")

    p_verify = sub.add_parser("verify", help="Verify a file against a saved hash")
    p_verify.add_argument("file")
    p_verify.add_argument("--hash-file", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "generate-key":
            generate_key(args.key_file)

        elif args.command == "encrypt":
            encrypt_file(args.input_file, args.output_file, args.key_file)

        elif args.command == "decrypt":
            decrypt_file(args.input_file, args.output_file, args.key_file)

        elif args.command == "hash":
            if args.save:
                save_hash(args.file, args.save)
            else:
                print(compute_sha256(args.file))

        elif args.command == "verify":
            ok = verify_hash(args.file, args.hash_file)
            sys.exit(0 if ok else 1)

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # last-resort guard: never crash with a raw traceback
        print(f"Unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
