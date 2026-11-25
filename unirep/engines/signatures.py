"""Conservative technology and package signature detection."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult

SIGNATURES = {
    "package.json": "Node.js / JavaScript project",
    "pyproject.toml": "Python project",
    "requirements.txt": "Python dependencies",
    "Cargo.toml": "Rust project",
    "go.mod": "Go project",
    "pom.xml": "Java Maven project",
    "build.gradle": "Gradle project",
    "pubspec.yaml": "Flutter / Dart project",
    "Gemfile": "Ruby project",
    "composer.json": "PHP Composer project",
    "Dockerfile": "Docker build configuration",
    "CMakeLists.txt": "CMake native project",
}


class SignatureEngine(AnalysisEngine):
    name = "signatures"
    description = "Detects common project manifests and technology hints; does not infer source internals."
    supported_kinds = {"folder"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        root = target.path.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Signature engine requires a directory")
        found: list[dict[str, str]] = []
        warnings: list[str] = []
        max_files = int((options or {}).get("max_files", 30000))
        count = 0
        for p in root.rglob("*"):
            if not p.is_file() or any(x in {".git", "node_modules", ".venv", "venv"} for x in p.parts):
                continue
            count += 1
            if count > max_files:
                warnings.append("Manifest scan limit reached; results may be incomplete.")
                break
            if p.name in SIGNATURES:
                found.append({"file": str(p.relative_to(root)), "technology": SIGNATURES[p.name]})
        technologies = sorted({x["technology"] for x in found})
        return EngineResult(
            engine=self.name, status="partial" if warnings else "ok",
            summary=f"Detected {len(found)} project manifest(s).",
            findings={"manifests": found, "technology_hints": technologies},
            warnings=warnings, confidence=0.85
        )
