"""Safe, read-only filesystem inventory engine."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence

DEFAULT_IGNORES = {".git", ".venv", "venv", "__pycache__", "node_modules", ".next", "dist", "build"}


class InventoryEngine(AnalysisEngine):
    name = "inventory"
    description = "Summarizes files, extensions and largest files without executing target code."
    supported_kinds = {"folder", "file"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        started = perf_counter()
        opts = options or {}
        max_files = int(opts.get("max_files", 20000))
        max_depth = int(opts.get("max_depth", 20))
        max_file_bytes = int(opts.get("max_file_bytes", 1 << 40))
        ignores = DEFAULT_IGNORES | set(opts.get("ignore_dirs", []))
        root = target.path.resolve(strict=True)
        if root.is_file():
            files = [root]
            base = root.parent
        elif root.is_dir():
            base = root
            files = []
            for item in root.rglob("*"):
                try:
                    rel = item.relative_to(root)
                    if len(rel.parts) > max_depth or any(p in ignores for p in rel.parts):
                        continue
                    if item.is_file() and not item.is_symlink():
                        files.append(item)
                    if len(files) >= max_files:
                        break
                except OSError:
                    continue
        else:
            raise ValueError("Target must be a regular file or directory")

        extensions: Counter[str] = Counter()
        largest: list[tuple[int, str]] = []
        total_bytes = 0
        scanned = 0
        warnings: list[str] = []
        for item in files:
            try:
                size = item.stat().st_size
                if size > max_file_bytes:
                    warnings.append(f"Skipped oversized file: {item.relative_to(base)}")
                    continue
                total_bytes += size
                extensions[item.suffix.lower() or "(no extension)"] += 1
                largest.append((size, str(item.relative_to(base))))
                scanned += 1
            except OSError as exc:
                warnings.append(f"Could not stat {item}: {exc}")

        largest.sort(reverse=True)
        if len(files) >= max_files:
            warnings.append(f"File scan reached max_files={max_files}; inventory may be incomplete.")
        return EngineResult(
            engine=self.name,
            status="partial" if warnings else "ok",
            summary=f"Inventoried {scanned} files ({total_bytes} bytes).",
            findings={
                "root": str(root),
                "files_scanned": scanned,
                "total_bytes": total_bytes,
                "extensions": dict(extensions.most_common(40)),
                "largest_files": [{"size": s, "path": p} for s, p in largest[:30]],
                "complete": len(files) < max_files,
            },
            warnings=warnings,
            evidence=[Evidence(claim=f"Scanned {scanned} regular file(s)", source=str(root), confidence=1.0,
                              details={"total_bytes": total_bytes})],
            confidence=1.0,
            duration_seconds=round(perf_counter() - started, 6),
        )
