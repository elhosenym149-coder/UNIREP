import hashlib
import json

from unirep.core.models import AnalysisTarget
from unirep.engines.python_dependencies import PythonDependencyEngine


def test_python_dependency_inventory_records_declarations_and_manifest_hash(tmp_path):
    content = (
        "# requirements for app\\n"
        "Requests[security]>=2.31,<3\\n"
        "pinned-lib==1.4.2\\n"
        "internal-lib @ https://user:secret@example.invalid/internal.whl\\n"
        "-r base.txt\\n"
    )
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.findings["dependency_count"] == 3
    request = result.findings["dependencies"][0]
    assert request["normalized_name"] == "requests"
    assert request["specifier"] == ">=2.31,<3"
    pinned = result.findings["dependencies"][1]
    assert pinned["exact_version"] == "1.4.2"
    direct = result.findings["dependencies"][2]
    assert direct["direct_reference"] is True
    assert "secret" not in str(direct)
    assert result.findings["manifest_hashes"][0]["sha256"] == expected_hash
    assert result.findings["vulnerability_assessment_performed"] is False
    assert any("include/option" in warning for warning in result.warnings)


def test_python_dependency_inventory_handles_single_file_and_safe_comments(tmp_path):
    path = tmp_path / "requirements-dev.txt"
    path.write_text("pytest>=8  # test runner\\n# comment\\n", encoding="utf-8")
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(path), "file"))
    assert result.findings["dependency_count"] == 1
    assert result.findings["dependencies"][0]["name"] == "pytest"


def test_python_dependency_inventory_does_not_follow_symlinked_manifest(tmp_path):
    actual = tmp_path / "actual.txt"
    actual.write_text("requests>=2\\n", encoding="utf-8")
    link = tmp_path / "requirements-link.txt"
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        return
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.findings["dependency_count"] == 0


def test_pipfile_lock_inventory_extracts_exact_versions_without_leaking_sources(tmp_path):
    path = tmp_path / "Pipfile.lock"
    path.write_text(json.dumps({
        "_meta": {"sources": [{"url": "https://user:secret@example.invalid/simple"}]},
        "default": {"Requests": {"version": "==2.32.3", "hashes": ["sha256:abc"]}},
        "develop": {"pytest": {"version": "==8.3.2", "hashes": []}},
    }), encoding="utf-8")
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    deps = result.findings["dependencies"]
    assert len(deps) == 2
    assert deps[0]["normalized_name"] == "requests"
    assert deps[0]["exact_version"] == "2.32.3"
    assert deps[0]["hash_count"] == 1
    assert deps[1]["exact_version"] == "8.3.2"
    assert "secret" not in str(result.findings)


def test_poetry_and_uv_lockfiles_extract_exact_versions_when_toml_parser_available(tmp_path):
    import pytest
    pytest.importorskip("tomllib")
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\\nname = "requests"\\nversion = "2.32.3"\\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        '[[package]]\\nname = "httpx"\\nversion = "0.27.2"\\n',
        encoding="utf-8",
    )
    result = PythonDependencyEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    by_name = {item["normalized_name"]: item for item in result.findings["dependencies"]}
    assert by_name["requests"]["exact_version"] == "2.32.3"
    assert by_name["httpx"]["exact_version"] == "0.27.2"
