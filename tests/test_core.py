from pathlib import Path
from unirep.core.models import AnalysisTarget, AnalysisJob, JobStatus, EngineResult
from unirep.core.registry import EngineRegistry
from unirep.core.runner import AnalysisRunner
from unirep.engines.inventory import InventoryEngine
from unirep.engines.signatures import SignatureEngine


def test_inventory_and_signatures(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")
    (tmp_path / "main.py").write_text("print('hello')")
    reg = EngineRegistry()
    reg.register(InventoryEngine())
    reg.register(SignatureEngine())
    job = AnalysisRunner(reg).run(AnalysisJob(AnalysisTarget(str(tmp_path), "folder")))
    assert job.status == JobStatus.SUCCEEDED
    by_name = {r.engine: r for r in job.results}
    assert by_name["inventory"].findings["files_scanned"] == 2
    assert "Python project" in by_name["signatures"].findings["technology_hints"]
    assert by_name["inventory"].evidence[0].kind == "observed"
    assert by_name["signatures"].evidence[0].source == "pyproject.toml"


def test_runner_reports_partial_failure(tmp_path):
    class Broken:
        name = "broken"
        description = "test"
        supported_kinds = {"folder"}
        def analyze(self, target, options=None):
            raise RuntimeError("expected")
    reg = EngineRegistry()
    reg.register(InventoryEngine())
    reg.register(Broken())
    job = AnalysisRunner(reg).run(AnalysisJob(AnalysisTarget(str(tmp_path), "folder")))
    assert job.status == JobStatus.PARTIAL
    assert any("expected" in x for x in job.errors)


def test_python_architecture_graph(tmp_path):
    pkg = tmp_path / "samplepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from . import service")
    (pkg / "service.py").write_text("from .utils import helper\ndef run(): return helper()\n")
    (pkg / "utils.py").write_text("def helper(): return 1\n")
    reg = EngineRegistry()
    from unirep.engines.architecture import PythonArchitectureEngine
    reg.register(PythonArchitectureEngine())
    job = AnalysisRunner(reg).run(AnalysisJob(AnalysisTarget(str(tmp_path), "folder")))
    assert job.status == JobStatus.SUCCEEDED
    graph = job.results[0].findings
    assert len(graph["nodes"]) == 3
    assert any(edge["source"] == "samplepkg.service" and edge["target"] == "samplepkg.utils"
               for edge in graph["edges"])


def test_job_manager_restricts_targets_to_configured_roots(tmp_path):
    from unirep.service.server import JobManager
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    sample = allowed / "sample.txt"
    sample.write_text("safe")
    manager = JobManager([allowed])
    try:
        assert manager._resolve_target(str(sample), "file") == sample.resolve()
        import pytest
        with pytest.raises(PermissionError):
            manager._resolve_target(str(denied), "folder")
    finally:
        manager.close()


def test_desktop_module_does_not_require_qt_at_import_time():
    import unirep.desktop
    assert callable(unirep.desktop.main)


def test_job_manager_browses_only_allowed_directory_entries(tmp_path):
    from unirep.service.server import JobManager
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "project.txt").write_text("ok")
    outside = tmp_path / "outside"
    outside.mkdir()
    manager = JobManager([root])
    try:
        entries = manager.browse(str(root))
        assert [x["name"] for x in entries] == ["project.txt"]
        assert manager.list_roots() == [str(root.resolve())]
    finally:
        manager.close()


def test_registry_exposes_modular_engines():
    from unirep.cli import build_registry
    names = {item["name"] for item in build_registry().list()}
    assert {"inventory", "signatures", "python_architecture", "web_browser", "legacy_package", "security_static", "python_dependencies"} <= names


def test_job_serialization_includes_evidence():
    from unirep.core.models import Evidence
    job = AnalysisJob(AnalysisTarget(".", "folder"))
    job.results.append(EngineResult(
        engine="test", status="ok", summary="observed",
        evidence=[Evidence(claim="A file was found", source="x.py", confidence=1.0)]
    ))
    data = job.to_dict()
    assert data["results"][0]["evidence"][0]["claim"] == "A file was found"
