"""Static Python module dependency graph. Source files are parsed, never imported or executed."""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any
from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult

IGNORED = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}


def _module_name(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_relative(module: str, level: int, imported: str | None) -> str:
    package = module.split(".")[:-1]
    if level > 1:
        package = package[: max(0, len(package) - (level - 1))]
    base = ".".join(package)
    return ".".join(x for x in (base, imported or "") if x)


class PythonArchitectureEngine(AnalysisEngine):
    name = "python_architecture"
    description = "Builds a static Python module/import graph from AST without importing project code."
    supported_kinds = {"folder"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        root = target.path.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Python architecture analysis requires a directory")
        opts = options or {}
        max_files = min(max(int(opts.get("max_files", 5000)), 1), 50000)
        max_source_bytes = min(max(int(opts.get("max_source_bytes", 5 << 20)), 1024), 50 << 20)
        paths: list[Path] = []
        for path in root.rglob("*.py"):
            rel = path.relative_to(root)
            if any(part in IGNORED for part in rel.parts) or path.is_symlink():
                continue
            paths.append(path)
            if len(paths) >= max_files:
                break

        module_to_path = {_module_name(root, p): p for p in paths}
        local_modules = set(module_to_path)
        nodes = [{"id": name, "path": str(path.relative_to(root)), "kind": "python_module"}
                 for name, path in sorted(module_to_path.items())]
        edges: set[tuple[str, str]] = set()
        stdlib: set[str] = set()
        third_party: set[str] = set()
        parse_errors: list[str] = []
        unresolved: set[str] = set()

        for source_module, path in module_to_path.items():
            try:
                if path.stat().st_size > max_source_bytes:
                    parse_errors.append(f"{path.relative_to(root)}: skipped source larger than {max_source_bytes} bytes")
                    continue
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as exc:
                parse_errors.append(f"{path.relative_to(root)}: {type(exc).__name__}: {exc}")
                continue
            for node in ast.walk(tree):
                imported_names: list[str] = []
                if isinstance(node, ast.Import):
                    imported_names.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    base = _resolve_relative(source_module, node.level, node.module)
                    if base:
                        imported_names.append(base)
                    for alias in node.names:
                        if alias.name != "*":
                            imported_names.append(".".join(x for x in (base, alias.name) if x))
                for imported in imported_names:
                    match = next((candidate for candidate in sorted(local_modules, key=len, reverse=True)
                                  if imported == candidate or imported.startswith(candidate + ".")), None)
                    if match:
                        edges.add((source_module, match))
                    elif imported and not imported.startswith("."):
                        root_name = imported.split(".")[0]
                        if root_name in sys.stdlib_module_names:
                            stdlib.add(root_name)
                        else:
                            third_party.add(root_name)
                        unresolved.add(imported)

        warnings = [f"Could not parse or safely inspect {len(parse_errors)} Python file(s)."] if parse_errors else []
        if len(paths) >= max_files:
            warnings.append(f"Scan limit max_files={max_files} reached; graph may be incomplete.")
        return EngineResult(
            engine=self.name, status="partial" if warnings else "ok",
            summary=f"Mapped {len(nodes)} Python modules and {len(edges)} internal import edges.",
            findings={
                "nodes": nodes,
                "edges": [{"source": a, "target": b, "type": "imports"} for a, b in sorted(edges)],
                "stdlib_import_roots": sorted(stdlib),
                "third_party_import_roots": sorted(third_party),
                "unresolved_imports": sorted(unresolved)[:500],
                "parse_errors": parse_errors[:100],
                "complete": len(paths) < max_files,
            },
            warnings=warnings,
            confidence=0.9
        )
