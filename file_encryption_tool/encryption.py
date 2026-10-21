import os
import secrets
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FET1"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    """Create a 32-byte AES key from a password using Scrypt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Salt must be exactly 16 bytes long.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt arbitrary bytes using AES-256-GCM and return a versioned file blob."""
    if data is None:
        raise TypeError("Data to encrypt cannot be None.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    ciphertext = aesgcm.encrypt(nonce, data, header)
    return header + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a blob created with encrypt_bytes()."""
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("Encrypted payload must be bytes-like.")

    encoded = bytes(blob)
    if len(encoded) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("Encrypted file is too short or corrupted.")

    magic = encoded[: len(MAGIC)]
    version = encoded[len(MAGIC)]
    if magic != MAGIC:
        raise ValueError("Invalid encrypted file header.")
    if version != VERSION:
        raise ValueError(f"Unsupported encrypted file version: {version}")

    salt_start = len(MAGIC) + 1
    salt_end = salt_start + SALT_SIZE
    nonce_end = salt_end + NONCE_SIZE
    salt = encoded[salt_start:salt_end]
    nonce = encoded[salt_end:nonce_end]
    ciphertext = encoded[nonce_end:]

    if len(ciphertext) < TAG_SIZE:
        raise ValueError("Encrypted file is missing its authentication tag.")

    key = derive_key(password, salt)
    aad = MAGIC + bytes([VERSION]) + salt + nonce
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed. The password may be incorrect, or the encrypted file may have been modified or corrupted."
        ) from exc


def _write_atomic(path: str | os.PathLike[str], data: bytes) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(destination.parent)) as handle:
            temp_path = Path(handle.name)
            handle.write(data)
        os.replace(temp_path, destination)
    except OSError:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def encrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str], password: str) -> str:
    """Encrypt a file and write the output to a new file path."""
    source = Path(input_path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    if not os.access(source, os.R_OK):
        raise PermissionError(f"Input file is not readable: {source}")

    destination = Path(output_path)
    if destination.resolve() == source.resolve():
        raise ValueError("Output file must be different from the input file.")
    if destination.exists():
        raise FileExistsError(f"Output file already exists: {destination}")

    payload = encrypt_bytes(source.read_bytes(), password)
    _write_atomic(destination, payload)
    return str(destination)


def decrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str], password: str) -> str:
    """Decrypt an encrypted file and save the plaintext to a new file path."""
    source = Path(input_path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source}")
    if not os.access(source, os.R_OK):
        raise PermissionError(f"Encrypted file is not readable: {source}")

    destination = Path(output_path)
    if destination.resolve() == source.resolve():
        raise ValueError("Output file must be different from the encrypted input file.")
    if destination.exists():
        raise FileExistsError(f"Output file already exists: {destination}")

    encrypted_blob = source.read_bytes()
    plaintext = decrypt_bytes(encrypted_blob, password)
    _write_atomic(destination, plaintext)
    return str(destination)
