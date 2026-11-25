"""Read-only Python dependency manifest inventory.

This engine inventories declared requirements. It does not install packages,
resolve versions, contact package registries, or claim vulnerability status.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence

MAX_MANIFEST_BYTES = 2 << 20
MAX_MANIFESTS = 2000
NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([A-Za-z0-9_,.-]+)\])?\s*(.*)$")


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_requirement(line: str, manifest: str, line_number: int) -> dict[str, Any] | None:
    value = line.strip()
    if not value or value.startswith("#"):
        return None
    if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "-e ", "--editable ")):
        return {"kind": "include_or_option", "manifest": manifest, "line": line_number,
                "directive": value.split(maxsplit=1)[0]}
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    match = NAME_RE.match(value)
    if not match:
        return {"kind": "unparsed", "manifest": manifest, "line": line_number,
                "raw_redacted": "unrecognized requirement syntax"}
    name, extras, tail = match.groups()
    direct = "@" in tail
    specifier = "direct reference (URL or VCS details redacted)" if direct else tail.strip()[:240]
    return {
        "kind": "dependency", "ecosystem": "pypi", "name": name,
        "normalized_name": _normalize_name(name),
        "extras": [x.strip() for x in extras.split(",")] if extras else [],
        "specifier": specifier, "direct_reference": direct,
        "manifest": manifest, "line": line_number,
    }


class PythonDependencyEngine(AnalysisEngine):
    name = "python_dependencies"
    description = "Inventories declared Python dependencies from requirements manifests without resolving or installing them."
    supported_kinds = {"folder", "file"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        opts = options or {}
        max_manifests = min(max(int(opts.get("max_manifests", 500)), 1), MAX_MANIFESTS)
        max_bytes = min(max(int(opts.get("max_manifest_bytes", MAX_MANIFEST_BYTES)), 1024), MAX_MANIFEST_BYTES)
        requested = target.path
        if requested.is_symlink():
            raise ValueError("Dependency inventory refuses a symlink target")
        root = requested.resolve(strict=True)
        if root.is_file():
            candidates = [root] if root.name.lower().startswith(("requirements", "constraints")) and root.suffix.lower() == ".txt" else []
            base = root.parent
        elif root.is_dir():
            base = root
            candidates = []
            for path in root.rglob("*.txt"):
                rel = path.relative_to(root)
                if path.is_symlink() or any(part in {".git", ".venv", "venv", "node_modules", "dist", "build"} for part in rel.parts):
                    continue
                if path.name.lower().startswith(("requirements", "constraints")):
                    candidates.append(path)
                if len(candidates) >= max_manifests:
                    break
        else:
            raise ValueError("Dependency inventory requires a regular file or directory")

        dependencies: list[dict[str, Any]] = []
        warnings: list[str] = []
        manifest_hashes: list[dict[str, str]] = []
        scanned = 0
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                raw = path.read_bytes()
                if len(raw) > max_bytes:
                    warnings.append(f"Skipped oversized manifest: {path.relative_to(base)}")
                    continue
                digest = hashlib.sha256(raw).hexdigest()
                manifest = str(path.relative_to(base))
                manifest_hashes.append({"file": manifest, "sha256": digest})
                text = raw.decode("utf-8-sig")
                scanned += 1
                for number, line in enumerate(text.splitlines(), 1):
                    item = _parse_requirement(line, manifest, number)
                    if item is None:
                        continue
                    if item["kind"] == "include_or_option":
                        warnings.append(f"Unresolved pip include/option at {manifest}:{number}; referenced files are not followed.")
                    elif item["kind"] == "unparsed":
                        warnings.append(f"Unparsed requirement syntax at {manifest}:{number}.")
                    else:
                        item["manifest_sha256"] = digest
                        dependencies.append(item)
            except (OSError, UnicodeError) as exc:
                warnings.append(f"Could not read {path.relative_to(base)}: {type(exc).__name__}: {exc}")

        if len(candidates) >= max_manifests:
            warnings.append(f"Manifest limit max_manifests={max_manifests} reached; inventory may be incomplete.")
        return EngineResult(
            engine=self.name,
            status="partial" if warnings else "ok",
            summary=f"Read {scanned} Python dependency manifest(s); found {len(dependencies)} declaration(s).",
            findings={
                "scope": "requirements and constraints text manifests only",
                "manifests_scanned": scanned,
                "manifest_hashes": manifest_hashes,
                "dependencies": dependencies,
                "dependency_count": len(dependencies),
                "vulnerability_assessment_performed": False,
                "install_or_resolution_performed": False,
            },
            warnings=warnings + [
                "This is a declaration inventory only; it does not resolve installed versions or assess known vulnerabilities.",
                "Pip include and constraint directives are reported but not followed.",
            ],
            evidence=[
                Evidence(
                    claim=f"Declared Python dependency {item['name']} in {item['manifest']}:{item['line']}",
                    kind="observed", source=item["manifest"], confidence=0.99,
                    details={"normalized_name": item["normalized_name"], "specifier": item["specifier"],
                             "manifest_sha256": item["manifest_sha256"]},
                )
                for item in dependencies
            ],
            confidence=0.95 if not warnings else 0.8,
        )
