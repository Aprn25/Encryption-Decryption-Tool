import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .encryption import decrypt_file, encrypt_file
from .file_handler import default_decrypted_output_path, default_encrypted_output_path, validate_input_path


class EncryptionApp:
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

        title = ttk.Label(container, text="Secure File Encryption and Decryption Tool", font=("Arial", 18, "bold"))
        title.pack(anchor="w", pady=(0, 8))

        subtitle = ttk.Label(container, text="Encrypt and decrypt files using AES-256-GCM with a password.")
        subtitle.pack(anchor="w", pady=(0, 16))

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

        status_bar = ttk.Label(container, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padding=(8, 4))
        status_bar.pack(fill=tk.X, pady=(6, 0))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def toggle_password_visibility(self):
        show = self.show_password_var.get()
        mask = "" if show else "*"
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
            except Exception as exc:  # pragma: no cover - GUI feedback only
                self.root.after(0, lambda: self._show_error(task_name, str(exc)))

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

        password = self.password_var.get()
        confirm = self.confirm_password_var.get()
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
    app = EncryptionApp(root)
    root.mainloop()
