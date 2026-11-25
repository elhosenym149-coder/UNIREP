import hashlib

from unirep.core.models import AnalysisTarget
from unirep.engines.python_dependencies import PythonDependencyEngine


def test_python_dependency_inventory_records_declarations_and_manifest_hash(tmp_path):
    content = (
        "# requirements for app\n"
        "Requests[security]>=2.31,<3\n"
        "internal-lib @ https://user:secret@example.invalid/internal.whl\n"
        "-r base.txt\n"
    )
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.findings["dependency_count"] == 2
    request = result.findings["dependencies"][0]
    assert request["normalized_name"] == "requests"
    assert request["specifier"] == ">=2.31,<3"
    direct = result.findings["dependencies"][1]
    assert direct["direct_reference"] is True
    assert "secret" not in str(direct)
    assert result.findings["manifest_hashes"][0]["sha256"] == expected_hash
    assert result.findings["vulnerability_assessment_performed"] is False
    assert any("include/option" in warning for warning in result.warnings)


def test_python_dependency_inventory_handles_single_file_and_safe_comments(tmp_path):
    path = tmp_path / "requirements-dev.txt"
    path.write_text("pytest>=8  # test runner\n# comment\n", encoding="utf-8")
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(path), "file"))
    assert result.findings["dependency_count"] == 1
    assert result.findings["dependencies"][0]["name"] == "pytest"


def test_python_dependency_inventory_does_not_follow_symlinked_manifest(tmp_path):
    actual = tmp_path / "actual.txt"
    actual.write_text("requests>=2\n", encoding="utf-8")
    link = tmp_path / "requirements-link.txt"
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        return
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.findings["dependency_count"] == 0
