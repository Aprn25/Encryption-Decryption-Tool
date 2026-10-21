# Project Report

## Secure File Encryption and Decryption Tool Using AES-256

**Project type:** Desktop application  
**Programming language:** Python 3  
**User interface:** Tkinter  
**Cryptographic library:** Python `cryptography`  
**Operating system target:** Windows 10 / Windows 11  
**Student:** [Your name]  
**Institution:** [Your institution]  
**Course / class:** [Your course]  
**Submission date:** [Insert date]

---

## Abstract

This project implements a desktop tool for protecting files with a password. It encrypts files using AES-256-GCM, an authenticated encryption mode, and derives the encryption key from the password with Scrypt. A random salt and nonce are generated for every encryption. The encrypted output includes a small versioned header and the encrypted data. During decryption, AES-GCM verifies the authentication tag before the plaintext is written. A wrong password or a modified encrypted file therefore results in failure rather than an output file containing unauthenticated plaintext.

The application is written in Python and provides a Tkinter interface for selecting files and an output directory, entering a password, and starting encryption or decryption. Its cryptographic operations are separated from GUI and file-path handling code. The test suite uses Python's `unittest` framework and temporary test files. In the validation run for this report, all 17 tests passed.

This is an educational project, not a professionally audited product. Its current implementation reads each complete file into memory, so it is best suited to small and medium-sized files.

## 1. Introduction

Digital files may contain personal, academic, or business information. When files are stored or transferred without protection, someone with access to them may be able to read or modify their contents. This project demonstrates how a password-based file encryption application can provide confidentiality and detect tampering.

The program creates an encrypted copy of a selected file. It does not intentionally remove or modify the source file. A user can later decrypt the encrypted copy with the same password. Passwords are not stored in the encrypted file, and the application cannot recover a forgotten password.

## 2. Problem Statement

Users need a straightforward way to protect individual files without manually operating cryptographic commands. The application should provide a simple interface while relying on a well-established cryptographic library, rather than implementing an encryption algorithm itself. It should also detect an incorrect password or altered ciphertext and avoid silently replacing existing output files.

## 3. Aim and Objectives

### Aim

To develop an educational desktop application that encrypts and decrypts files using password-derived AES-256-GCM keys.

### Objectives

1. Provide a Tkinter graphical interface for choosing files and output folders.
2. Derive a 256-bit key from a non-empty password using Scrypt.
3. Generate a fresh random salt and nonce for every encryption.
4. Use AES-GCM to provide confidentiality and authentication.
5. Store version and required cryptographic metadata alongside the ciphertext.
6. Reject wrong passwords, corrupted headers, unsupported versions, and modified ciphertext.
7. Keep the original input file unchanged.
8. Reject an existing output path instead of silently overwriting it.
9. Test cryptographic and file-handling behaviour with `unittest`.

## 4. Scope

The application supports password-based encryption and decryption of files selected by the user. It can handle arbitrary file bytes at the cryptographic-function level, including empty inputs. The GUI uses a worker thread for file processing so the Tkinter event loop can continue responding while work is in progress.

The current implementation does not provide:

- Streaming or chunked encryption for very large files
- Recovery of forgotten passwords
- Preservation of the original file extension in the default decrypted filename
- A professional security audit or a guarantee of security on a compromised computer
- Automatic backup, cloud storage, or key recovery

## 5. Software and Hardware Requirements

### Software

- Windows 10 or Windows 11
- Python 3.11 or later
- Tkinter, normally included with the standard Windows Python installation
- `cryptography` Python package (dependency declared in `requirements.txt`)
- VS Code, PyCharm, or another Python editor (optional)

### Hardware

- A computer capable of running Python 3
- At least 4 GB of RAM recommended
- Enough free storage space for the encrypted or decrypted output

The current whole-file implementation may require substantially more memory than the file size because it holds file data and cryptographic output in memory at the same time.

## 6. System Architecture

```text
┌───────────────────┐
│       User        │
└─────────┬─────────┘
          │ chooses file, password and output folder
          ▼
┌───────────────────┐
│  Tkinter GUI      │  gui.py
│  input + status   │
└─────────┬─────────┘
          │ calls reusable functions
          ▼
┌───────────────────┐       ┌────────────────────┐
│ File/path checks  │──────▶│ Encryption module  │
│ file_handler.py   │       │ encryption.py      │
└───────────────────┘       └──────────┬─────────┘
                                       │
                           ┌───────────┴──────────┐
                           │ Scrypt key derivation │
                           │ AES-256-GCM           │
                           └───────────┬──────────┘
                                       │
                                       ▼
                             Encrypted/decrypted file
```

The GUI handles presentation and user input. `file_handler.py` contains path validation and default output-name helpers. `encryption.py` owns key derivation, file format parsing, encryption, authentication, and output writing. `main.py` starts the application.

### Project files

| File | Purpose |
|---|---|
| `main.py` | Root-level application launcher |
| `file_encryption_tool/main.py` | Package entry point that runs the GUI |
| `file_encryption_tool/gui.py` | Tkinter controls, validation, status and background worker |
| `file_encryption_tool/encryption.py` | Scrypt, AES-GCM, encrypted format, and file operations |
| `file_encryption_tool/file_handler.py` | Input validation and default output-path helpers |
| `file_encryption_tool/__init__.py` | Exposes the package's common encryption functions |
| `requirements.txt` | Declares the `cryptography` dependency |
| `tests/test_encryption.py` | Encryption/decryption and integrity tests |
| `tests/test_file_handler.py` | Path and default-name helper tests |
| `README.md` | Short installation, running, security, and format guide |

## 7. Cryptographic Design

### 7.1 AES-256-GCM

AES is a symmetric block cipher: the same secret key is used to encrypt and decrypt data. The application uses AES with a 256-bit key in Galois/Counter Mode (GCM). GCM is an authenticated encryption mode. It protects the confidentiality of the content and produces an authentication tag that detects incorrect keys or modification.

The application calls `AESGCM` from the established `cryptography` package. It does not implement AES itself. During decryption, the library verifies the tag before returning plaintext. If verification fails, the program raises an error and does not write a final decrypted output file.

### 7.2 Scrypt password-based key derivation

The user password is not used directly as the AES key. Instead, `Scrypt` derives a 32-byte (256-bit) key using:

| Parameter | Value |
|---|---:|
| Output key length | 32 bytes |
| `n` (CPU/memory cost) | 16,384 (`2^14`) |
| `r` (block size) | 8 |
| `p` (parallelisation) | 1 |
| Salt length | 16 bytes |

Scrypt is deliberately more expensive than a simple hash and uses memory as well as computation. This increases the cost of trying many guessed passwords. These parameters are a project configuration and should be reviewed for the target hardware and current security guidance before production use.

### 7.3 Random salt and nonce

Each encryption uses Python's `secrets` module to obtain:

- A 16-byte salt, which makes the derived key specific to that encrypted file.
- A 12-byte (96-bit) GCM nonce, which must not be reused with the same key.

The salt and nonce are not secret. They are stored in the file so the same key can be derived and the decryption operation can be performed later. The password and derived key are not written to the file.

### 7.4 Associated authenticated data

The fixed-format header is supplied to AES-GCM as associated authenticated data (AAD). AAD is not encrypted, but its integrity is checked along with the ciphertext. Changing the header's magic value, version, salt, or nonce prevents successful authentication (invalid magic and version are also rejected during format validation).

### 7.5 Encrypted file format

Version 1 uses the following layout:

| Offset / size | Field | Description |
|---|---|---|
| 0–3 / 4 bytes | Magic | `FET1`, identifies this application's format |
| 4 / 1 byte | Version | `1` for the current format |
| 5–20 / 16 bytes | Salt | Random Scrypt salt |
| 21–32 / 12 bytes | Nonce | Random AES-GCM nonce |
| 33 onward | Ciphertext and tag | AES-GCM output; the final 16 bytes are the authentication tag |

The fixed-size header lets the reader validate and parse the format without ambiguous metadata lengths. A future incompatible format can use a different version and a corresponding parser. The current implementation rejects unknown versions.

## 8. Application Workflow

### 8.1 Encryption

1. The user chooses a source file and output directory.
2. The GUI checks that a file was selected and that the password is non-empty and matches its confirmation.
3. The file-processing worker validates the source path and rejects an output path equal to the input or an output file that already exists.
4. The encryption function reads the source bytes, generates a fresh salt and nonce, and derives a key with Scrypt.
5. AES-256-GCM encrypts the data and authenticates the header as AAD.
6. The program writes the header, ciphertext, and tag to a temporary file in the destination directory, then moves it to the requested output path.
7. The GUI displays the result path or an error. The source file is not intentionally altered.

### 8.2 Decryption

1. The user selects the encrypted file and enters the password.
2. The program checks the file path and reads the encrypted bytes.
3. The decryption function validates the minimum length, magic header, and supported version.
4. It extracts the salt and nonce, derives the key, and asks AES-GCM to authenticate and decrypt the payload.
5. If authentication fails, the function raises an error and does not write a final plaintext file.
6. If authentication succeeds, the plaintext is written to a temporary file and moved to the destination.
7. The GUI reports success or a clear failure message.

### Flow summary

```text
Encryption: Select file → validate → random salt + nonce → Scrypt → AES-GCM
            → temporary output → final .enc file

Decryption: Select .enc → validate header → Scrypt → authenticate + decrypt
            → temporary plaintext output → final output file
```

## 9. User Interface

The Tkinter window includes:

- Project title and short description
- File picker and selected-path field
- Password and confirmation entries
- Show/hide password control
- Output-directory chooser
- Encrypt, decrypt, clear, and exit buttons
- Status text and success/error dialogs

The GUI starts a background thread for file operations, then schedules completion feedback through Tkinter's `after` mechanism so UI updates are made on the GUI event loop. The current interface reports a processing status but does not show a percentage-based progress bar.

## 10. Installation and Operation

Open PowerShell in the project root directory:

```powershell
cd "C:\Projects\File Encryption-Decryption Tool\Encryption-Decryption Tool"
```

Check that Python is installed:

```powershell
python --version
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation, use the Python executable inside the virtual environment directly, or adjust the execution policy only in accordance with your organisation's guidance.

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

Launch the application:

```powershell
python main.py
```

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

For encryption, select a file, choose an output directory, enter a password twice, and select **Encrypt File**. For decryption, select the `.enc` file, enter the same password, choose an output directory, and select **Decrypt File**. The original file and encrypted input are retained.

## 11. Testing and Results

Automated tests use `unittest` and Python temporary directories so test data is isolated and disposable. The tests cover:

- Text, synthetic PDF-like bytes, synthetic image-like bytes, empty data, and arbitrary binary data
- Successful round trips and byte-for-byte equality
- Wrong password rejection
- Modified ciphertext detection
- Corrupted magic header detection
- Unsupported version rejection
- Original input preservation
- Existing output rejection
- Different outputs for repeated encryption of the same source
- Missing input paths
- Default output-name helpers and path validation

**Validation result:** `python -m unittest discover -s tests -v` completed successfully with **17 tests run and 17 passing**.

The PDF and image cases use representative byte sequences created by the tests; they are not integration tests against complex real-world documents. The tests confirm code behaviour for those byte sequences, not compatibility with every file type or size.

## 12. Security and Privacy Considerations

- AES is provided by the `cryptography` library rather than handwritten code.
- AES-GCM provides encryption and an authentication tag.
- Salt and nonce are generated randomly for each encryption.
- The password and derived key are not stored in the encrypted file.
- Authentication must succeed before the decryption function returns plaintext for output.
- The source file is preserved by the normal workflow.
- Passwords should be long and unique. Scrypt cannot make a weak password strong.
- Anyone who knows the password and has the encrypted file can decrypt it.
- A forgotten password cannot be recovered by this program.
- The encrypted file exposes its format header and encrypted file length. File names can also reveal information through the output filename and the surrounding filesystem.
- A compromised computer, keylogger, malware, insecure backups, or shoulder-surfing can expose passwords or plaintext.
- This project has not undergone a professional security audit.

## 13. Limitations and Future Improvements

1. **Memory use:** Current file operations use `read_bytes()` and the AES-GCM one-shot API. The complete file and output may be held in memory. A future large-file design should use a carefully specified, authenticated streaming format rather than splitting a file into arbitrary GCM chunks.
2. **Output naming:** The default decrypted output name appends `_decrypted` but does not restore the original extension. A future version could store or request a safe output name, while carefully authenticating any stored metadata.
3. **Progress reporting:** The GUI shows a text status, not progress percentage or cancellation.
4. **Overwrite race:** The application rejects an output path that already exists before processing, but a race between the existence check and final replacement is not fully eliminated on every platform. A production version should use an atomic create-if-absent strategy.
5. **Disk space:** There is no reliable preflight check for free disk space; write failures are reported as operating-system errors.
6. **GUI hardening:** The interface could disable controls while work is underway, improve password clearing after completion, and provide more specific handling for expected exceptions.
7. **Password policy:** The application rejects empty passwords but does not enforce a minimum length or provide a strength estimate.
8. **Additional validation:** Future tests could include real sample files generated within the test suite, larger files, output write failures, and Windows-specific path edge cases.
9. **Parameter agility:** Future format versions could record supported KDF parameters, with strict bounds to prevent malicious resource-exhaustion values.

## 14. Demonstration Plan

1. Show the project structure and explain the responsibility of each module.
2. Run the application and select a disposable sample file.
3. Encrypt it with a test password and show that the original remains available.
4. Open the `.enc` file in a text editor only to demonstrate that it is binary-looking data; do not infer security solely from unreadability.
5. Decrypt with the correct password and compare the output bytes with the original.
6. Try a wrong password and demonstrate that no decrypted output is created.
7. Demonstrate duplicate-output protection.
8. Run the unit tests and show the successful test summary.

Use only synthetic or non-sensitive demonstration content and a temporary directory.

## 15. Viva Questions and Answers

1. **What is encryption?**  
   Encryption transforms readable data into ciphertext using a key so that it cannot be understood without the appropriate key.

2. **What is decryption?**  
   Decryption uses the corresponding key to recover the original data from ciphertext.

3. **How is encryption different from hashing?**  
   Encryption is designed to be reversible with a key. A cryptographic hash is generally one-way and is used to represent or verify data, not recover it.

4. **Why is AES used in this project?**  
   AES is a widely used symmetric cipher supported by the cryptography library and suitable for protecting file contents.

5. **What does AES-256 mean?**  
   It indicates a 256-bit AES key. It does not by itself describe the mode of operation or guarantee secure application design.

6. **Why use GCM mode?**  
   GCM provides authenticated encryption: it protects confidentiality and detects changes to ciphertext or authenticated metadata.

7. **What is an authentication tag?**  
   It is a cryptographic value verified during decryption. If verification fails, the data is not accepted as authentic.

8. **What is a nonce?**  
   A nonce is a value used for one encryption operation. GCM requires that a nonce not be reused with the same key.

9. **What is a salt?**  
   A salt is a random value supplied to password-based key derivation, making derived keys unique even when passwords are reused.

10. **Why are salt and nonce stored with ciphertext?**  
    They are required to derive the same key and perform decryption, but neither value needs to be secret.

11. **Why use Scrypt?**  
    Scrypt is a password-based key derivation function that increases the memory and computation required for each password guess.

12. **Does Scrypt encrypt the file?**  
    No. Scrypt derives the encryption key from the password and salt. AES-GCM encrypts and authenticates the file data.

13. **What is the difference between AES and RSA?**  
    AES is symmetric and uses the same key to encrypt and decrypt. RSA is asymmetric and uses a public/private key pair; this project uses AES, not RSA.

14. **What is confidentiality?**  
    Confidentiality means preventing unauthorised parties from reading protected data.

15. **What is integrity?**  
    Integrity means being able to detect unauthorised changes to data.

16. **What happens if the password is wrong?**  
    The derived key differs, AES-GCM authentication fails, and the program reports a decryption error without writing a final plaintext output.

17. **Can a forgotten password be recovered?**  
    No. The application has no password recovery mechanism, so the user must retain the password securely.

18. **Why does the encrypted file contain a version field?**  
    The version identifies the format rules and allows a future implementation to evolve the format while rejecting unknown versions safely.

19. **Does the encrypted file hide every detail about the original file?**  
    No. Its size and surrounding filename/path information may reveal details. This version does not encrypt filesystem metadata such as the source file name inside the payload.

20. **Has the project been professionally audited?**  
    No. It is an educational implementation and should not be presented as professionally audited software.

## 16. Conclusion

The project demonstrates an end-to-end password-based file encryption workflow with a graphical interface. It separates the GUI, file-path helpers, and cryptographic operations, uses library-provided AES-256-GCM and Scrypt, and validates important failure cases through automated tests. Its 17-test suite passed in the recorded validation run.

The main areas to address before use with large or highly sensitive files are a secure authenticated streaming format, stronger atomic no-overwrite behaviour, improved output-name handling, and independent security review. Users should keep strong passwords safe because the application cannot recover lost passwords.

## References

- Python documentation: `https://docs.python.org/3/`
- Python `unittest` documentation: `https://docs.python.org/3/library/unittest.html`
- Python `secrets` documentation: `https://docs.python.org/3/library/secrets.html`
- `cryptography` documentation: `https://cryptography.io/en/latest/`
- NIST FIPS 197, Advanced Encryption Standard (AES)
- NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- RFC 7914, The scrypt Password-Based Key Derivation Function
