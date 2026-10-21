import tempfile
import unittest
from pathlib import Path

from file_encryption_tool.encryption import decrypt_bytes, encrypt_bytes, encrypt_file, decrypt_file


class EncryptionTests(unittest.TestCase):
    def test_encrypt_and_decrypt_text_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "secret.txt"
            source.write_text("This is a secret message for AES-GCM.", encoding="utf-8")
            encrypted_path = Path(tmp_dir) / "secret.enc"
            decrypted_path = Path(tmp_dir) / "secret_decoded.txt"

            encrypt_file(source, encrypted_path, "StrongPass!123")
            decrypt_file(encrypted_path, decrypted_path, "StrongPass!123")

            self.assertEqual(source.read_bytes(), decrypted_path.read_bytes())

    def test_encrypt_and_decrypt_pdf_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
            source = Path(tmp_dir) / "report.pdf"
            source.write_bytes(pdf_data)
            encrypted_path = Path(tmp_dir) / "report.enc"
            decrypted_path = Path(tmp_dir) / "report_decoded.pdf"

            encrypt_file(source, encrypted_path, "pdf_password")
            decrypt_file(encrypted_path, decrypted_path, "pdf_password")

            self.assertEqual(pdf_data, decrypted_path.read_bytes())

    def test_encrypt_and_decrypt_image_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_bytes = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + (b"\x00" * 32)
            source = Path(tmp_dir) / "photo.png"
            source.write_bytes(image_bytes)
            encrypted_path = Path(tmp_dir) / "photo.enc"
            decrypted_path = Path(tmp_dir) / "photo_decoded.png"

            encrypt_file(source, encrypted_path, "imageSecret01")
            decrypt_file(encrypted_path, decrypted_path, "imageSecret01")

            self.assertEqual(image_bytes, decrypted_path.read_bytes())

    def test_encrypt_and_decrypt_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "empty.bin"
            source.write_bytes(b"")
            encrypted_path = Path(tmp_dir) / "empty.enc"
            decrypted_path = Path(tmp_dir) / "empty_decoded.bin"

            encrypt_file(source, encrypted_path, "emptyPass")
            decrypt_file(encrypted_path, decrypted_path, "emptyPass")

            self.assertEqual(b"", decrypted_path.read_bytes())

    def test_encrypt_and_decrypt_binary_data(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = bytes(range(256)) * 16 + b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
            source = Path(tmp_dir) / "binary.dat"
            source.write_bytes(payload)
            encrypted_path = Path(tmp_dir) / "binary.enc"
            decrypted_path = Path(tmp_dir) / "binary_decoded.dat"

            encrypt_file(source, encrypted_path, "Binary!Pass")
            decrypt_file(encrypted_path, decrypted_path, "Binary!Pass")

            self.assertEqual(payload, decrypted_path.read_bytes())

    def test_wrong_password_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "wrong.txt"
            source.write_text("wrong password test", encoding="utf-8")
            encrypted_path = Path(tmp_dir) / "wrong.enc"
            decrypt_path = Path(tmp_dir) / "wrong_decrypted.txt"

            encrypt_file(source, encrypted_path, "correctPass")
            with self.assertRaises(ValueError):
                decrypt_file(encrypted_path, decrypt_path, "wrongPass")

    def test_modified_ciphertext_detected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = b"modified ciphertext check"
            encrypted = encrypt_bytes(payload, "secret")
            modified = bytearray(encrypted)
            modified[-1] ^= 0xFF

            with self.assertRaises(ValueError):
                decrypt_bytes(bytes(modified), "secret")

    def test_corrupted_file_header_detected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            encrypted = encrypt_bytes(b"header check", "secret")
            corrupted = bytearray(encrypted)
            corrupted[0:4] = b"BAD!"

            with self.assertRaises(ValueError):
                decrypt_bytes(bytes(corrupted), "secret")

    def test_unsupported_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            encrypted = encrypt_bytes(b"version check", "secret")
            corrupted = bytearray(encrypted)
            corrupted[4] = 99

            with self.assertRaises(ValueError):
                decrypt_bytes(bytes(corrupted), "secret")

    def test_original_file_remains_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "original.txt"
            original = b"keep the original content"
            source.write_bytes(original)
            encrypted_path = Path(tmp_dir) / "original.enc"
            decrypt_path = Path(tmp_dir) / "original_decrypted.txt"

            encrypt_file(source, encrypted_path, "unchanged")
            decrypt_file(encrypted_path, decrypt_path, "unchanged")

            self.assertEqual(original, source.read_bytes())
            self.assertEqual(original, decrypt_path.read_bytes())

    def test_duplicate_output_name_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "duplicate.txt"
            source.write_text("duplicate", encoding="utf-8")
            output = Path(tmp_dir) / "duplicate.enc"
            output.write_bytes(b"not empty")

            with self.assertRaises(FileExistsError):
                encrypt_file(source, output, "ash")

    def test_decrypted_bytes_match_original_exactly(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC" * 128
            source = Path(tmp_dir) / "raw.bin"
            source.write_bytes(payload)
            encrypted = Path(tmp_dir) / "raw.enc"
            decrypted = Path(tmp_dir) / "raw.out"

            encrypt_file(source, encrypted, "rawPass")
            decrypt_file(encrypted, decrypted, "rawPass")

            self.assertEqual(payload, decrypted.read_bytes())

    def test_same_file_encrypts_differently_each_time(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "same.txt"
            source.write_text("Same file, different encryption output", encoding="utf-8")

            first_output = Path(tmp_dir) / "first.enc"
            second_output = Path(tmp_dir) / "second.enc"
            encrypt_file(source, first_output, "password")
            encrypt_file(source, second_output, "password")

            self.assertNotEqual(first_output.read_bytes(), second_output.read_bytes())

    def test_invalid_input_paths_handled(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_source = Path(tmp_dir) / "nope.txt"
            output_path = Path(tmp_dir) / "result.enc"

            with self.assertRaises(FileNotFoundError):
                encrypt_file(missing_source, output_path, "pass")

            with self.assertRaises(FileNotFoundError):
                decrypt_file(missing_source, output_path, "pass")


if __name__ == "__main__":
    unittest.main()
