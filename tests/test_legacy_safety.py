from pathlib import Path
import zipfile
import pytest

from reforge import safe_join, unzip


def test_legacy_safe_join_rejects_traversal_and_windows_drive(tmp_path):
    with pytest.raises(ValueError):
        safe_join(tmp_path, "../escape.txt")
    with pytest.raises(ValueError):
        safe_join(tmp_path, "C:/escape.txt")


def test_legacy_unzip_extracts_normal_archive(tmp_path):
    source = tmp_path / "ok.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("folder/file.txt", "safe")
    out = tmp_path / "out"
    assert unzip(source, out) == 1
    assert (out / "folder/file.txt").read_text() == "safe"


def test_legacy_unzip_rejects_zip_slip(tmp_path):
    source = tmp_path / "bad.zip"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("../escape.txt", "unsafe")
    with pytest.raises(ValueError):
        unzip(source, tmp_path / "out")


def test_legacy_adapter_returns_report_without_retaining_temp_files(tmp_path):
    from unirep.core.models import AnalysisTarget
    from unirep.engines.legacy import LegacyPackageEngine
    source = tmp_path / "simple.txt"
    source.write_text("hello")
    result = LegacyPackageEngine().analyze(AnalysisTarget(str(source), "file"))
    assert result.engine == "legacy_package"
    assert result.findings["temporary_extraction_retained"] is False


def test_legacy_adapter_explains_temporary_extraction_cleanup(tmp_path):
    import zipfile
    from unirep.core.models import AnalysisTarget
    from unirep.engines.legacy import LegacyPackageEngine
    archive = tmp_path / "package.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("app.txt", "hello")
    result = LegacyPackageEngine().analyze(AnalysisTarget(str(archive), "file"))
    assert any("discarded" in warning for warning in result.warnings)
