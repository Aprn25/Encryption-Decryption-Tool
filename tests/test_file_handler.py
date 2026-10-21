import tempfile
import unittest
from pathlib import Path

from file_encryption_tool.file_handler import default_decrypted_output_path, default_encrypted_output_path, validate_input_path


class FileHandlerTests(unittest.TestCase):
    def test_default_encrypted_output_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "notes.txt"
            source.write_text("example", encoding="utf-8")
            output_dir = Path(tmp_dir) / "out"
            output_dir.mkdir()

            self.assertEqual(str(output_dir / "notes.enc"), default_encrypted_output_path(source, output_dir))

    def test_default_decrypted_output_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            encrypted = Path(tmp_dir) / "notes.enc"
            output_dir = Path(tmp_dir) / "out"
            output_dir.mkdir()

            self.assertEqual(str(output_dir / "notes_decrypted"), default_decrypted_output_path(encrypted, output_dir))

    def test_validate_input_path_rejects_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing = Path(tmp_dir) / "missing.txt"
            with self.assertRaises(FileNotFoundError):
                validate_input_path(missing)


if __name__ == "__main__":
    unittest.main()
