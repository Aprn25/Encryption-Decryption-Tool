import os
import tempfile
from pathlib import Path


def ensure_parent_directory(path: str | os.PathLike[str]) -> Path:
    destination = Path(path)
    if not destination.parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")
    return destination


def default_encrypted_output_path(source_path: str | os.PathLike[str], output_dir: str | os.PathLike[str]) -> str:
    source = Path(source_path)
    directory = Path(output_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Output directory is invalid: {directory}")

    name = source.name
    if name.lower().endswith(".enc"):
        base_name = name[:-4]
    else:
        base_name = source.stem
    return str(directory / f"{base_name}.enc")


def default_decrypted_output_path(encrypted_path: str | os.PathLike[str], output_dir: str | os.PathLike[str]) -> str:
    encrypted = Path(encrypted_path)
    directory = Path(output_dir)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Output directory is invalid: {directory}")

    name = encrypted.name
    if name.lower().endswith(".enc"):
        base_name = name[:-4]
    else:
        base_name = encrypted.stem
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

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(destination.parent)) as handle:
            temp_path = Path(handle.name)
            handle.write(payload)
        os.replace(temp_path, destination)
    except OSError:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise
    return str(destination)
