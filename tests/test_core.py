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
