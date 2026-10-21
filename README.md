# Secure File Encryption and Decryption Tool

A Python desktop application for encrypting a file with a password and decrypting it later using the same password. The tool uses AES-256-GCM for authenticated encryption and Scrypt to derive a 256-bit key from the password. The original file is left unchanged.

## Technologies

- Python 3.11+
- Tkinter for the graphical interface (included with standard Python on Windows)
- [`cryptography`](https://cryptography.io/) for AES-GCM and Scrypt
- Python standard library: `pathlib`, `os`, `secrets`, `tempfile`, `threading`, and `unittest`

## Dataset and test data

This project does not require an external dataset. It encrypts files selected by the user. Automated tests create synthetic text, PDF-like, image-like, empty, and binary data in temporary folders; see [`tests/test_encryption.py`](tests/test_encryption.py) and [`tests/test_file_handler.py`](tests/test_file_handler.py). No personal or sensitive data is required to run the tests.

## Setup

In PowerShell, open the project directory and create a virtual environment:

```powershell
cd "C:\Projects\File Encryption-Decryption Tool\Encryption-Decryption Tool"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`requirements.txt` lists the third-party dependency, `cryptography`. Tkinter and the other listed technologies are part of Python's standard library.

## Run the application

From the project root:

```powershell
python main.py
```

Choose a file, select an output directory, enter and confirm a password, then choose **Encrypt File**. To restore a file, select its `.enc` file, enter the same password, and choose **Decrypt File**. The application rejects an output path that already exists rather than silently overwriting it.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The test suite covers encryption/decryption round trips, invalid passwords, tampering, format validation, output collision handling, and preservation of the original input. In the reported validation run, all 17 tests passed.

## Key security information

- Every encryption uses a fresh random 16-byte salt and 12-byte nonce.
- Scrypt derives the 32-byte AES key; the password and derived key are not stored in the encrypted file.
- AES-GCM authenticates ciphertext and the versioned header. Decryption fails if the password is incorrect or the encrypted file has been altered.
- Anyone with the password can decrypt the file. Forgotten passwords cannot be recovered.
- File names, file sizes, and other filesystem details may remain visible.
- This is an educational project, not professionally audited software. The current implementation reads the entire file into memory and is not intended for very large files.

## Encrypted file format

The version 1 `.enc` file consists of the `FET1` magic identifier (4 bytes), version (1 byte), random salt (16 bytes), nonce (12 bytes), then AES-GCM ciphertext and its 16-byte authentication tag. The header is authenticated as associated data.

## Project layout

- [`main.py`](main.py) — application launcher
- [`file_encryption_tool/gui.py`](file_encryption_tool/gui.py) — Tkinter user interface
- [`file_encryption_tool/encryption.py`](file_encryption_tool/encryption.py) — key derivation, encryption, decryption, and file format
- [`file_encryption_tool/file_handler.py`](file_encryption_tool/file_handler.py) — input validation and output-name helpers
- [`tests/`](tests/) — automated tests
- [`PROJECT_REPORT.md`](PROJECT_REPORT.md) — detailed project report
