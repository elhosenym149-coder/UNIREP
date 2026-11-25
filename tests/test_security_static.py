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


def test_static_security_hashes_evidence_and_detects_encoded_execution(tmp_path):
    source = (
        "import base64\n"
        "payload = 'ZWNobyBoaQ=='\n"
        "exec(base64.b64decode(payload))\n"
    )
    path = tmp_path / "loader.py"
    path.write_text(source, encoding="utf-8")
    import hashlib
    expected = hashlib.sha256(source.encode("utf-8")).hexdigest()
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    findings = result.findings["findings"]
    encoded = next(item for item in findings if item["rule_id"] == "python.encoded-execution")
    assert encoded["sha256"] == expected
    assert result.findings["scanned_file_hashes"] == [{"file": "loader.py", "sha256": expected}]
    evidence = next(item for item in result.evidence
                    if item.details.get("rule_id") == "python.encoded-execution")
    assert evidence.details["sha256"] == expected


def test_static_security_marks_network_api_as_indicator_not_exfiltration(tmp_path):
    (tmp_path / "client.py").write_text(
        "import requests\nrequests.post('https://example.invalid/telemetry', json={'ok': True})\n",
        encoding="utf-8",
    )
    result = StaticSecurityEngine().analyze(AnalysisTarget(str(tmp_path), "folder"))
    finding = next(item for item in result.findings["findings"]
                   if item["rule_id"] == "python.network-send")
    assert finding["classification"] == "suspicious"
    assert finding["severity"] == "medium"
    assert "not proof of exfiltration" in finding["false_positive_caveat"]
