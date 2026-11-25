"""Read-only Python dependency manifest and lockfile inventory.

This engine inventories declarations and exact versions recorded by lockfiles.
It does not install packages, resolve dependencies, contact registries, or
claim vulnerability status.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence

MAX_MANIFEST_BYTES = 2 << 20
MAX_MANIFESTS = 2000
LOCK_NAMES = {"poetry.lock", "uv.lock", "pipfile.lock", "pdm.lock"}
NAME_RE = re.compile(r"^\\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\\[([A-Za-z0-9_,.-]+)\\])?\\s*(.*)$")


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_requirement(line: str, manifest: str, line_number: int) -> dict[str, Any] | None:
    value = line.strip()
    if not value or value.startswith("#"):
        return None
    if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "-e ", "--editable ")):
        return {"kind": "include_or_option", "manifest": manifest, "line": line_number,
                "directive": value.split(maxsplit=1)[0]}
    value = re.split(r"\\s+#", value, maxsplit=1)[0].strip()
    match = NAME_RE.match(value)
    if not match:
        return {"kind": "unparsed", "manifest": manifest, "line": line_number,
                "raw_redacted": "unrecognized requirement syntax"}
    name, extras, tail = match.groups()
    direct = "@" in tail
    specifier = "direct reference (URL or VCS details redacted)" if direct else tail.strip()[:240]
    pinned = re.search(r"(?:^|,)\\s*==\\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)", specifier)
    return {
        "kind": "dependency", "ecosystem": "pypi", "name": name,
        "normalized_name": _normalize_name(name),
        "extras": [x.strip() for x in extras.split(",")] if extras else [],
        "specifier": specifier, "exact_version": pinned.group(1) if pinned else None,
        "direct_reference": direct, "manifest": manifest, "line": line_number,
    }


def _toml_data(text: str) -> dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise RuntimeError("TOML lockfile parsing requires Python 3.11+ or the optional tomli package") from exc
    data = tomllib.loads(text)
    if not isinstance(data, dict):
        raise ValueError("TOML root must be a table")
    return data


def _lock_packages(data: dict[str, Any], filename: str) -> list[tuple[str, Any]]:
    lower = filename.lower()
    if lower == "pipfile.lock":
        packages = []
        for section in ("default", "develop"):
            section_data = data.get(section, {})
            if isinstance(section_data, dict):
                packages.extend((name, item) for name, item in section_data.items())
        return packages
    # Poetry and uv use [[package]]; PDM commonly uses a packages array.
    raw = data.get("package", data.get("packages", []))
    if isinstance(raw, dict):
        return list(raw.items())
    if isinstance(raw, list):
        return [(str(item.get("name", "")), item) for item in raw if isinstance(item, dict)]
    return []


def _parse_lockfile(raw: bytes, filename: str, manifest: str) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    text = raw.decode("utf-8-sig")
    if filename.lower() == "pipfile.lock":
        data = json.loads(text)
    elif filename.lower() in {"poetry.lock", "uv.lock", "pdm.lock"}:
        data = _toml_data(text)
    else:
        return [], [f"Unsupported lockfile format: {manifest}"]

    packages = _lock_packages(data, filename)
    if not packages:
        warnings.append(f"No recognized package records found in lockfile: {manifest}")
    results: list[dict[str, Any]] = []
    for raw_name, item in packages[:MAX_MANIFESTS * 100]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or raw_name).strip()
        version = item.get("version")
        if not name or not version:
            warnings.append(f"Lockfile package without a name or exact version in {manifest}")
            continue
        version_text = str(version).strip()
        if not version_text:
            continue
        markers = item.get("markers") or item.get("marker")
        groups = item.get("groups")
        entry: dict[str, Any] = {
            "kind": "dependency", "ecosystem": "pypi", "name": name,
            "normalized_name": _normalize_name(name), "extras": [],
            "specifier": "==" + version_text, "exact_version": version_text,
            "direct_reference": False, "manifest": manifest, "line": None,
            "lockfile": True,
        }
        if markers:
            entry["markers"] = str(markers)[:500]
        if isinstance(groups, list):
            entry["groups"] = [str(x)[:100] for x in groups[:30]]
        hashes = item.get("hashes")
        if isinstance(hashes, list):
            entry["hash_count"] = len(hashes)
        results.append(entry)
    return results, warnings


class PythonDependencyEngine(AnalysisEngine):
    name = "python_dependencies"
    description = "Inventories Python requirements and lockfiles without resolving or installing dependencies."
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
            valid = (root.name.lower() in LOCK_NAMES or
                     (root.name.lower().startswith(("requirements", "constraints")) and root.suffix.lower() == ".txt"))
            candidates = [root] if valid else []
            base = root.parent
        elif root.is_dir():
            base = root
            candidates = []
            for path in root.rglob("*"):
                rel = path.relative_to(root)
                if path.is_symlink() or any(part in {".git", ".venv", "venv", "node_modules", "dist", "build"} for part in rel.parts):
                    continue
                if not path.is_file():
                    continue
                if path.name.lower() in LOCK_NAMES or (
                    path.name.lower().startswith(("requirements", "constraints")) and path.suffix.lower() == ".txt"
                ):
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
                scanned += 1
                if path.name.lower() in LOCK_NAMES:
                    parsed, parse_warnings = _parse_lockfile(raw, path.name, manifest)
                    warnings.extend(parse_warnings)
                    for item in parsed:
                        item["manifest_sha256"] = digest
                    dependencies.extend(parsed)
                else:
                    text = raw.decode("utf-8-sig")
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
            except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
                warnings.append(f"Could not parse {path.relative_to(base)}: {type(exc).__name__}: {exc}")

        if len(candidates) >= max_manifests:
            warnings.append(f"Manifest limit max_manifests={max_manifests} reached; inventory may be incomplete.")
        return EngineResult(
            engine=self.name,
            status="partial" if warnings else "ok",
            summary=f"Read {scanned} Python dependency manifest/lockfile(s); found {len(dependencies)} record(s).",
            findings={
                "scope": "requirements/constraints text manifests, Poetry/uv/PDM TOML locks and Pipfile.lock JSON",
                "manifests_scanned": scanned,
                "manifest_hashes": manifest_hashes,
                "dependencies": dependencies,
                "dependency_count": len(dependencies),
                "exact_versions_recorded": sum(1 for item in dependencies if item.get("exact_version")),
                "vulnerability_assessment_performed": False,
                "install_or_resolution_performed": False,
            },
            warnings=warnings + [
                "This is a declaration/lockfile inventory only; it does not verify the installed environment or assess known vulnerabilities.",
                "Pip include and constraint directives are reported but not followed; TOML lock parsing on Python 3.10 requires optional tomli.",
            ],
            evidence=[
                Evidence(
                    claim=f"Python dependency {item['name']} recorded in {item['manifest']}",
                    kind="observed", source=item["manifest"], confidence=0.99,
                    details={"normalized_name": item["normalized_name"], "specifier": item["specifier"],
                             "exact_version": item.get("exact_version"), "manifest_sha256": item["manifest_sha256"]},
                )
                for item in dependencies
            ],
            confidence=0.95 if not warnings else 0.8,
        )
