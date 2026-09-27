# Cryptography & Network Security — Integrated Situation

ETTCS801, ULK Polytechnic Institute. Toolkit for encrypting, decrypting, and
integrity-checking student record files.

## 1. Installation

Requires Python 3.8+.

```bash
pip install cryptography
```

## 2. Files

| File | Purpose |
|---|---|
| `security_toolkit.py` | Main CLI tool: encrypt, decrypt, hash, verify |
| `sample_student_record.csv` | Sample data file used for testing |
| `risk_assessment.md` | Part 1 — risk assessment |
| `key.key` | Generated encryption key — **not committed to git** (see `.gitignore`) |

## 3. Usage

**Generate an encryption key** (do this once; keep `key.key` private/outside the repo):
```bash
python3 security_toolkit.py generate-key --key-file key.key
```

**Encrypt a file:**
```bash
python3 security_toolkit.py encrypt sample_student_record.csv sample_student_record.enc --key-file key.key
```

**Decrypt a file:**
```bash
python3 security_toolkit.py decrypt sample_student_record.enc sample_student_record.decrypted.csv --key-file key.key
```
Compare `sample_student_record.csv` and `sample_student_record.decrypted.csv` (e.g. `diff` on Linux/Mac, `fc` on Windows) — they should be identical.

**Compute and save a SHA-256 hash (for later tamper-detection):**
```bash
python3 security_toolkit.py hash sample_student_record.csv --save sample_student_record.sha256
```

**Verify a file against a previously saved hash:**
```bash
python3 security_toolkit.py verify sample_student_record.csv --hash-file sample_student_record.sha256
```
Prints `OK` if unchanged, or a `WARNING` with both hashes if the file has been modified, and exits with a non-zero status code on mismatch.

## 4. Error handling

The tool exits cleanly with a readable error message (not a crash/traceback) when:
- The input file, key file, or hash file does not exist
- The key file is invalid or the wrong key is used to decrypt
- Any other unexpected error occurs

## 5. Reproducing the test evidence

```bash
python3 security_toolkit.py generate-key --key-file key.key
python3 security_toolkit.py encrypt sample_student_record.csv sample_student_record.enc --key-file key.key
python3 security_toolkit.py decrypt sample_student_record.enc sample_student_record.decrypted.csv --key-file key.key
diff sample_student_record.csv sample_student_record.decrypted.csv   # should print nothing (identical)
python3 security_toolkit.py hash sample_student_record.csv --save sample_student_record.sha256
python3 security_toolkit.py verify sample_student_record.csv --hash-file sample_student_record.sha256   # OK
echo "tampered" >> sample_student_record.csv
python3 security_toolkit.py verify sample_student_record.csv --hash-file sample_student_record.sha256   # WARNING
```
