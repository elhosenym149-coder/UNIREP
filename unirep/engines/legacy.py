"""Compatibility adapter for the preserved Reforge analyzer (file packages only)."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult


class LegacyPackageEngine(AnalysisEngine):
    name = "legacy_package"
    description = "Runs the preserved read-only Reforge package analyzer with external tools disabled."
    supported_kinds = {"file"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        if not target.path.is_file():
            raise ValueError("Legacy package engine accepts one file at a time")
        try:
            import reforge
        except ImportError as exc:
            raise RuntimeError("Legacy analyzer module is not installed with this distribution") from exc
        with TemporaryDirectory(prefix="unirep-legacy-") as temp:
            output = Path(temp) / "analysis"
            facts = reforge.analyze(target.path, output, external=False, copy_models=False)
            findings = dict(facts)
            findings["temporary_extraction_retained"] = False
            findings["report_path"] = None
        warnings = list(facts.get("warnings", [])) + list(facts.get("notes", []))
        if facts.get("unpacked_files") or facts.get("pyinstaller"):
            warnings.append("Extracted package files were analyzed in a temporary workspace and discarded; this adapter returns metadata only.")
        return EngineResult(
            engine=self.name,
            status="partial" if warnings else "ok",
            summary=f"Legacy analyzer identified {facts.get('kind')} with {len(facts.get('stack', []))} technology hint(s).",
            findings=findings,
            warnings=warnings,
            confidence=0.8
        )
