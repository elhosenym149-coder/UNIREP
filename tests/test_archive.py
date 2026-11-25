from pathlib import Path
import zipfile
import pytest

from unirep.engines.archive import ArchiveLimitError, inspect_zip, extract_zip_guarded


def test_inspect_and_extract_zip(tmp_path):
    source = tmp_path / "sample.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("src/main.py", "print('ok')")
    info = inspect_zip(source)
    assert info["files"] == 1
    out = tmp_path / "out"
    result = extract_zip_guarded(source, out)
    assert result["extracted_files"] == 1
    assert (out / "src/main.py").read_text() == "print('ok')"


def test_rejects_zip_slip(tmp_path):
    source = tmp_path / "bad.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("../escape.txt", "bad")
    with pytest.raises(ArchiveLimitError):
        inspect_zip(source)


def test_rejects_windows_drive_and_size_limit(tmp_path):
    source = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("C:/outside.txt", "bad")
    with pytest.raises(ArchiveLimitError):
        inspect_zip(source)

    source2 = tmp_path / "large.zip"
    with zipfile.ZipFile(source2, "w") as z:
        z.writestr("large.bin", "x" * 20)
    with pytest.raises(ArchiveLimitError):
        inspect_zip(source2, max_single_file=10)


def test_rejects_symlink_destination(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this platform")
    source = tmp_path / "sample.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("file.txt", "data")
    with pytest.raises(ArchiveLimitError):
        extract_zip_guarded(source, link)
