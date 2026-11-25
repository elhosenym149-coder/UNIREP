from unirep.core.models import AnalysisTarget
from unirep.engines.security_static import StaticSecurityEngine


def test_static_security_detects_risky_patterns_without_executing_them(tmp_path):
    (tmp_path / "app.py").write_text(
        "import subprocess\nimport os\nimport pickle\n"
        "def run(user_value):\n"
        "    subprocess.run(user_value, shell=True)\n"
        "    os.system('echo fixed')\n"
        "    return pickle.loads(b'not executed')\n",
        encoding="utf-8",
    )
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    rules = {item["rule_id"] for item in result.findings["findings"]}
    assert "python.shell-true" in rules
    assert "python.os-system" in rules
    assert "python.pickle-load" in rules
    assert result.findings["remediation_performed"] is False
    assert all(item["classification"] == "suspicious" for item in result.findings["findings"])


def test_static_security_does_not_flag_safe_subprocess_without_shell(tmp_path):
    (tmp_path / "safe.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'hello'], shell=False)\n",
        encoding="utf-8",
    )
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.findings["findings"] == []
    assert "not proof of safety" in result.warnings[0]


def test_static_security_reports_parse_errors_and_skips_symlinks(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    assert result.status == "partial"
    assert result.findings["parse_errors"]
    assert result.findings["coverage_complete"] is False


def test_static_security_supports_single_python_file(tmp_path):
    path = tmp_path / "single.py"
    path.write_text("eval('1 + 1')\n", encoding="utf-8")
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(path), "file"))
    assert result.findings["files_scanned"] == 1
    assert result.findings["findings"][0]["rule_id"] == "python.dynamic-eval"


def test_static_security_maps_python_dependants_without_claiming_essentiality(tmp_path):
    package = tmp_path / "sample"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "danger.py").write_text(
        "import subprocess\nsubprocess.run('echo fixed', shell=True)\n",
        encoding="utf-8",
    )
    (package / "service.py").write_text(
        "from . import danger\ndef run(): return danger\n",
        encoding="utf-8",
    )
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    finding = next(item for item in result.findings["findings"]
                   if item["rule_id"] == "python.shell-true")
    component = finding["component"]
    assert component["module"] == "sample.danger"
    assert component["static_dependant_count"] >= 1
    assert any(item["module"] == "sample.service" for item in component["dependants"])
    assert "do not reveal runtime plugins" in component["role_caveat"]
