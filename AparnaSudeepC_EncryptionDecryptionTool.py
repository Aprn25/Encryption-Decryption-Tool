"""Secure File Encryption and Decryption Tool

Standalone submission version based on the project's GitHub source.
Features: AES-256-GCM encryption, password-based key derivation using Scrypt,
file encryption/decryption, safe output writing, and a Tkinter graphical interface.

Dependency: cryptography (install with: python -m pip install cryptography)
Run: python AparnaSudeepC_EncryptionDecryptionTool.py
"""

import os
import secrets
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

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
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt bytes with AES-256-GCM and return a versioned encrypted blob."""
    if data is None:
        raise TypeError("Data to encrypt cannot be None.")
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    return header + AESGCM(key).encrypt(nonce, data, header)


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a blob created by encrypt_bytes()."""
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("Encrypted payload must be bytes-like.")
    encoded = bytes(blob)
    if len(encoded) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("Encrypted file is too short or corrupted.")
    if encoded[:len(MAGIC)] != MAGIC:
        raise ValueError("Invalid encrypted file header.")
    version = encoded[len(MAGIC)]
    if version != VERSION:
        raise ValueError(f"Unsupported encrypted file version: {version}")
    salt_start = len(MAGIC) + 1
    salt_end = salt_start + SALT_SIZE
    nonce_end = salt_end + NONCE_SIZE
    salt, nonce = encoded[salt_start:salt_end], encoded[salt_end:nonce_end]
    ciphertext = encoded[nonce_end:]
    if len(ciphertext) < TAG_SIZE:
        raise ValueError("Encrypted file is missing its authentication tag.")
    key = derive_key(password, salt)
    aad = MAGIC + bytes([VERSION]) + salt + nonce
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Decryption failed. The password may be incorrect, or the encrypted file may have been modified or corrupted.") from exc


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
    """Encrypt an input file into a new output file."""
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
    _write_atomic(destination, encrypt_bytes(source.read_bytes(), password))
    return str(destination)


def decrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str], password: str) -> str:
    """Decrypt an encrypted input file into a new output file."""
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
    _write_atomic(destination, decrypt_bytes(source.read_bytes(), password))
    return str(destination)


def ensure_parent_directory(path: str | os.PathLike[str]) -> Path:
    destination = Path(path)
    if not destination.parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")
    return destination


def default_encrypted_output_path(source_path: str | os.PathLike[str], output_dir: str | os.PathLike[str]) -> str:
    source, directory = Path(source_path), Path(output_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Output directory is invalid: {directory}")
    name = source.name
    base_name = name[:-4] if name.lower().endswith(".enc") else source.stem
    return str(directory / f"{base_name}.enc")


def default_decrypted_output_path(encrypted_path: str | os.PathLike[str], output_dir: str | os.PathLike[str]) -> str:
    encrypted, directory = Path(encrypted_path), Path(output_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Output directory is invalid: {directory}")
    name = encrypted.name
    base_name = name[:-4] if name.lower().endswith(".enc") else encrypted.stem
    return str(directory / f"{base_name}_decrypted")


def validate_input_path(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"Input file does not exist: {candidate}")
    if not os.access(candidate, os.R_OK):
        raise PermissionError(f"Input file is not readable: {candidate}")
    return candidate


def safe_write_bytes(path: str | os.PathLike[str], payload: bytes, overwrite: bool = False) -> str:
    destination = ensure_parent_directory(path)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {destination}")
    _write_atomic(destination, payload)
    return str(destination)


class EncryptionApp:
    """Tkinter interface for file encryption and decryption."""
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure File Encryption and Decryption Tool")
        self.root.geometry("760x540")
        self.root.minsize(680, 500)
        self.selected_path = tk.StringVar()
        self.output_directory = tk.StringVar(value=str(Path.home()))
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self._build_ui()

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=20)
        container.pack(fill=tk.BOTH, expand=True)
        ttk.Label(container, text="Secure File Encryption and Decryption Tool", font=("Arial", 18, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(container, text="Encrypt and decrypt files using AES-256-GCM with a password.").pack(anchor="w", pady=(0, 16))
        file_frame = ttk.LabelFrame(container, text="File Selection", padding=(12, 10))
        file_frame.pack(fill=tk.X, pady=(0, 10))
        row1 = ttk.Frame(file_frame)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Selected file:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Entry(row1, textvariable=self.selected_path, width=65).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row1, text="Browse", command=self.select_file).pack(side=tk.LEFT, padx=(8, 0))
        password_frame = ttk.LabelFrame(container, text="Password", padding=(12, 10))
        password_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Label(password_frame, text="Confirm password:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        self.confirm_entry = ttk.Entry(password_frame, textvariable=self.confirm_password_var, show="*", width=40)
        self.confirm_entry.grid(row=1, column=1, sticky="ew", pady=6)
        toggle_row = ttk.Frame(password_frame)
        toggle_row.grid(row=2, column=1, sticky="w", pady=(0, 6))
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toggle_row, text="Show password", variable=self.show_password_var, command=self.toggle_password_visibility).pack(anchor="w")
        output_frame = ttk.LabelFrame(container, text="Output Settings", padding=(12, 10))
        output_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(output_frame, text="Output directory:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(output_frame, textvariable=self.output_directory, width=50).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(output_frame, text="Choose folder", command=self.select_output_directory).grid(row=0, column=2, padx=(8, 0), pady=6)
        buttons = ttk.Frame(container)
        buttons.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(buttons, text="Encrypt File", command=self.handle_encrypt).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Decrypt File", command=self.handle_decrypt).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Clear", command=self.clear_form).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Exit", command=self.root.destroy).pack(side=tk.RIGHT)
        ttk.Label(container, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padding=(8, 4)).pack(fill=tk.X, pady=(6, 0))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def toggle_password_visibility(self):
        mask = "" if self.show_password_var.get() else "*"
        self.password_entry.configure(show=mask)
        self.confirm_entry.configure(show=mask)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("All files", "*.*")])
        if file_path:
            self.selected_path.set(file_path)
            self.output_directory.set(str(Path(file_path).parent))

    def select_output_directory(self):
        directory = filedialog.askdirectory(title="Choose output directory")
        if directory:
            self.output_directory.set(directory)

    def clear_form(self):
        self.selected_path.set("")
        self.password_var.set("")
        self.confirm_password_var.set("")
        self.status_var.set("Ready")

    def _start_background_task(self, task_name: str, action, input_path: str, output_path: str, password: str):
        def worker():
            try:
                result_path = action(input_path, output_path, password)
                self.root.after(0, lambda: self._show_success(task_name, result_path))
            except Exception as exc:
                self.root.after(0, lambda message=str(exc): self._show_error(task_name, message))
        threading.Thread(target=worker, daemon=True).start()

    def _show_success(self, operation: str, output_path: str):
        self.status_var.set(f"{operation} completed successfully. Output: {output_path}")
        messagebox.showinfo("Success", f"{operation} completed successfully.\nOutput: {output_path}")

    def _show_error(self, operation: str, message: str):
        self.status_var.set(f"{operation} failed: {message}")
        messagebox.showerror("Error", message)

    def handle_encrypt(self):
        source = self.selected_path.get().strip()
        if not source:
            self._show_error("Encryption", "Please select a file to encrypt.")
            return
        try:
            validate_input_path(source)
        except Exception as exc:
            self._show_error("Encryption", str(exc))
            return
        password, confirm = self.password_var.get(), self.confirm_password_var.get()
        if not password:
            self._show_error("Encryption", "Password cannot be empty.")
            return
        if password != confirm:
            self._show_error("Encryption", "Passwords do not match.")
            return
        directory = self.output_directory.get().strip() or str(Path(source).parent)
        try:
            output_path = default_encrypted_output_path(source, directory)
        except FileNotFoundError as exc:
            self._show_error("Encryption", str(exc))
            return
        self.status_var.set("Encrypting file in the background...")
        self._start_background_task("Encryption", encrypt_file, source, output_path, password)

    def handle_decrypt(self):
        source = self.selected_path.get().strip()
        if not source:
            self._show_error("Decryption", "Please select an encrypted file to decrypt.")
            return
        try:
            validate_input_path(source)
        except Exception as exc:
            self._show_error("Decryption", str(exc))
            return
        password = self.password_var.get()
        if not password:
            self._show_error("Decryption", "Password cannot be empty.")
            return
        directory = self.output_directory.get().strip() or str(Path(source).parent)
        try:
            output_path = default_decrypted_output_path(source, directory)
        except FileNotFoundError as exc:
            self._show_error("Decryption", str(exc))
            return
        self.status_var.set("Decrypting file in the background...")
        self._start_background_task("Decryption", decrypt_file, source, output_path, password)


def main() -> None:
    root = tk.Tk()
    EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
