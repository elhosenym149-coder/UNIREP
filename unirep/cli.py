"""Command line entry point for the modular UNIREP platform."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unirep import __version__
from unirep.core.models import AnalysisJob, AnalysisTarget
from unirep.core.registry import EngineRegistry
from unirep.core.runner import AnalysisRunner
from unirep.engines.inventory import InventoryEngine
from unirep.engines.signatures import SignatureEngine
from unirep.engines.architecture import PythonArchitectureEngine
from unirep.engines.web.browser import BrowserInspectionEngine
from unirep.engines.legacy import LegacyPackageEngine
from unirep.engines.binary import BinaryMetadataEngine
from unirep.engines.security_static import StaticSecurityEngine


def build_registry() -> EngineRegistry:
    registry = EngineRegistry()
    registry.register(InventoryEngine())
    registry.register(SignatureEngine())
    registry.register(PythonArchitectureEngine())
    registry.register(BrowserInspectionEngine())
    registry.register(LegacyPackageEngine())
    registry.register(BinaryMetadataEngine())
    registry.register(StaticSecurityEngine())
    return registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unirep", description="UNIREP / Reforge modular analysis workspace")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("engines", help="List installed analysis engines")
    doctor = sub.add_parser("doctor", help="Check optional libraries and external tools")
    doctor.add_argument("--json", action="store_true")
    sub.add_parser("desktop", help="Launch the optional desktop interface")
    rebuild = sub.add_parser("rebuild", help="Generate a starter project from a reviewed JSON spec")
    rebuild.add_argument("spec")
    rebuild.add_argument("--out", required=True)
    serve = sub.add_parser("serve", help="Start authenticated local/LAN control API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--root", action="append", default=[], help="Allowed local path root (repeatable)")
    serve.add_argument("--token", default=os.environ.get("UNIREP_API_TOKEN"), help="Bearer token; prefer UNIREP_API_TOKEN environment variable, otherwise generated at startup")
    serve.add_argument("--cert", default=None, help="TLS certificate PEM for HTTPS LAN access")
    serve.add_argument("--key", default=None, help="TLS private key PEM for HTTPS LAN access")
    serve.add_argument("--insecure-lan", action="store_true", help="Explicitly allow unencrypted non-loopback access (development only)")
    web = sub.add_parser("web", help="Inspect an authorized website in read-only mode")
    web.add_argument("url")
    web.add_argument("--authorized", action="store_true", help="Confirm you own or are authorized to assess this site")
    web.add_argument("--allow-host", action="append", default=[], help="Allow an additional host for page resources")
    web.add_argument("--out", default="unirep-web-report.json")
    analyze = sub.add_parser("analyze", help="Analyze a local file or folder (read-only)")
    analyze.add_argument("target")
    analyze.add_argument("--kind", choices=["file", "folder"], default=None)
    analyze.add_argument("--engine", action="append", dest="engines")
    analyze.add_argument("--out", default="unirep-report.json")
    args = parser.parse_args(argv)

    registry = build_registry()
    if args.command == "rebuild":
        from unirep.reconstruction.generator import generate_project
        result = generate_project(Path(args.spec), Path(args.out))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.command == "serve":
        from unirep.service.server import serve as serve_api
        serve_api(args.host, args.port, args.root or None, args.token, args.cert, args.key, args.insecure_lan)
        return 0
    if args.command == "doctor":
        from unirep.doctor import collect_diagnostics, render_diagnostics
        report = collect_diagnostics()
        print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_diagnostics(report))
        return 0
    if args.command == "desktop":
        from unirep.desktop import main as desktop_main
        return desktop_main([])
    if args.command == "engines":
        print(json.dumps(registry.list(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "web":
        if not args.authorized:
            parser.error("web inspection requires --authorized")
        target = AnalysisTarget(value=args.url, kind="url", authorized=True)
        result = BrowserInspectionEngine().analyze(target, {"allowed_hosts": args.allow_host})
        output_path = Path(args.out).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result.__dict__ if hasattr(result, "__dict__") else {
            "engine": result.engine, "status": result.status, "summary": result.summary,
            "findings": result.findings, "warnings": result.warnings, "errors": result.errors,
            "evidence": [{"claim": e.claim, "kind": e.kind, "source": e.source, "confidence": e.confidence, "details": e.details} for e in result.evidence],
            "confidence": result.confidence, "duration_seconds": result.duration_seconds
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Web inspection complete: {Path(args.out).resolve()}")
        return 0
    path = Path(args.target).expanduser()
    if not path.exists():
        parser.error(f"Target does not exist: {path}")
    kind = args.kind or ("folder" if path.is_dir() else "file")
    target = AnalysisTarget(value=str(path), kind=kind, authorized=False)
    job = AnalysisRunner(registry).run(AnalysisJob(target=target, requested_engines=args.engines or []))
    output_path = Path(args.out).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(job.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Job {job.job_id}: {job.status.value}; {len(job.results)} engine result(s)")
    print(f"Report: {Path(args.out).resolve()}")
    return 0 if job.status.value in {"succeeded", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
