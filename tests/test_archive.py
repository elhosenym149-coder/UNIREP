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
