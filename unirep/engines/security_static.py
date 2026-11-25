"""Conservative, read-only static security indicators for Python source trees.

This engine reports suspicious constructs, not malware verdicts. It never imports,
executes, modifies, quarantines, or deletes target files.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence

IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}
MAX_FILES_HARD_LIMIT = 50000
MAX_SOURCE_HARD_LIMIT = 10 << 20

RULES = {
    "python.dynamic-eval": {
        "title": "Dynamic code evaluation",
        "severity": "high",
        "confidence": 0.78,
        "description": "eval/exec can execute dynamically supplied code; inspect the data source and call path.",
        "caveat": "Legitimate interpreters, formula engines and developer tools may use dynamic evaluation.",
    },
    "python.shell-true": {
        "title": "Shell invocation with shell=True",
        "severity": "high",
        "confidence": 0.86,
        "description": "A subprocess call enables shell parsing, which can become command injection if inputs are untrusted.",
        "caveat": "A fixed, trusted command may be intentional; input provenance determines exploitability.",
    },
    "python.os-system": {
        "title": "Direct operating-system shell command",
        "severity": "high",
        "confidence": 0.82,
        "description": "os.system/os.popen invoke a command shell and require review of command construction.",
        "caveat": "May be legitimate in controlled build or administration scripts.",
    },
    "python.pickle-load": {
        "title": "Python pickle deserialization",
        "severity": "high",
        "confidence": 0.80,
        "description": "Untrusted pickle data can execute code during deserialization.",
        "caveat": "Risk depends on whether the serialized input is trusted and integrity-protected.",
    },
    "python.dynamic-import": {
        "title": "Dynamic module import",
        "severity": "low",
        "confidence": 0.58,
        "description": "Dynamic imports can obscure dependencies and runtime behavior.",
        "caveat": "Common in plugin systems and optional-feature loaders; not malicious by itself.",
    },
}

def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, (ast.Attribute, ast.Name)):
        if isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        else:
            parts.append(current.id)
            break
    return ".".join(reversed(parts))

def _matches(tree: ast.AST) -> list[tuple[str, ast.AST, str]]:
    matches: list[tuple[str, ast.AST, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            matches.append(("python.dynamic-eval", node, name))
        elif name in {"os.system", "os.popen"}:
            matches.append(("python.os-system", node, name))
        elif name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            matches.append(("python.pickle-load", node, name))
        elif name in {"__import__", "importlib.import_module"}:
            matches.append(("python.dynamic-import", node, name))
        elif name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                       "subprocess.check_call", "subprocess.check_output"}:
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                   and keyword.value.value is True for keyword in node.keywords):
                matches.append(("python.shell-true", node, name))
    return matches

class StaticSecurityEngine(AnalysisEngine):
    name = "security_static"
    description = "Read-only Python AST checks for risky execution/deserialization patterns; findings are indicators, not malware verdicts."
    supported_kinds = {"folder", "file"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        opts = options or {}
        max_files = min(max(int(opts.get("max_files", 5000)), 1), MAX_FILES_HARD_LIMIT)
        max_source_bytes = min(max(int(opts.get("max_source_bytes", 2 << 20)), 1024), MAX_SOURCE_HARD_LIMIT)
        root = target.path.resolve(strict=True)
        if root.is_symlink() or (not root.is_file() and not root.is_dir()):
            raise ValueError("Security analysis requires a regular file or directory, not a symlink")
        if root.is_file():
            candidates = [root] if root.suffix.lower() == ".py" else []
            base = root.parent
        else:
            base = root
            candidates = []
            for path in root.rglob("*.py"):
                rel = path.relative_to(root)
                if path.is_symlink() or any(part in IGNORED_DIRS for part in rel.parts):
                    continue
                candidates.append(path)
                if len(candidates) >= max_files:
                    break

        findings: list[dict[str, Any]] = []
        parse_errors: list[str] = []
        scanned = 0
        skipped_large = 0
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > max_source_bytes:
                    skipped_large += 1
                    continue
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as exc:
                parse_errors.append(f"{path.relative_to(base)}: {type(exc).__name__}: {exc}")
                continue
            scanned += 1
            lines = source.splitlines()
            for rule_id, node, symbol in _matches(tree):
                rule = RULES[rule_id]
                line = getattr(node, "lineno", 1)
                snippet = lines[line - 1].strip()[:240] if 0 < line <= len(lines) else ""
                findings.append({
                    "id": f"{rule_id}:{path.relative_to(base)}:{line}",
                    "rule_id": rule_id,
                    "title": rule["title"],
                    "classification": "suspicious",
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "file": str(path.relative_to(base)),
                    "line": line,
                    "symbol": symbol,
                    "snippet": snippet,
                    "description": rule["description"],
                    "false_positive_caveat": rule["caveat"],
                    "action": "review_only",
                })

        findings.sort(key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 4),
                                        item["file"], item["line"], item["rule_id"]))
        warnings: list[str] = [
            "Static indicators are not proof of malware and absence of findings is not proof of safety.",
            "No target code was executed or modified; no remediation action was performed.",
        ]
        if parse_errors:
            warnings.append(f"{len(parse_errors)} Python file(s) could not be parsed; coverage is incomplete.")
        if skipped_large:
            warnings.append(f"Skipped {skipped_large} file(s) above max_source_bytes.")
        if len(candidates) >= max_files:
            warnings.append(f"Scan limit max_files={max_files} reached; results may be incomplete.")

        evidence = [
            Evidence(
                claim=f"{item['title']} indicator at {item['file']}:{item['line']}",
                kind="observed",
                source=item["file"],
                confidence=item["confidence"],
                details={"rule_id": item["rule_id"], "severity": item["severity"],
                         "classification": "suspicious", "symbol": item["symbol"]},
            )
            for item in findings
        ]
        return EngineResult(
            engine=self.name,
            status="partial" if parse_errors or skipped_large or len(candidates) >= max_files else "ok",
            summary=f"Scanned {scanned} Python source file(s); reported {len(findings)} suspicious indicator(s).",
            findings={
                "classification_policy": "Indicators are suspicious only; this engine never declares a file malicious.",
                "files_scanned": scanned,
                "findings": findings,
                "parse_errors": parse_errors[:100],
                "coverage_complete": not (parse_errors or skipped_large or len(candidates) >= max_files),
                "remediation_performed": False,
            },
            warnings=warnings,
            evidence=evidence,
            confidence=0.75 if findings else 0.55,
        )
