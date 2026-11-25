"""Command line entry point for the modular UNIREP platform."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from unirep import __version__
from unirep.core.models import AnalysisJob, AnalysisTarget
from unirep.core.registry import EngineRegistry
from unirep.core.runner import AnalysisRunner
from unirep.engines.inventory import InventoryEngine
from unirep.engines.signatures import SignatureEngine


def build_registry() -> EngineRegistry:
    registry = EngineRegistry()
    registry.register(InventoryEngine())
    registry.register(SignatureEngine())
    return registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unirep", description="UNIREP / Reforge modular analysis workspace")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("engines", help="List installed analysis engines")
    analyze = sub.add_parser("analyze", help="Analyze a local file or folder (read-only)")
    analyze.add_argument("target")
    analyze.add_argument("--kind", choices=["file", "folder"], default=None)
    analyze.add_argument("--engine", action="append", dest="engines")
    analyze.add_argument("--out", default="unirep-report.json")
    args = parser.parse_args(argv)

    registry = build_registry()
    if args.command == "engines":
        print(json.dumps(registry.list(), indent=2, ensure_ascii=False))
        return 0
    path = Path(args.target).expanduser()
    if not path.exists():
        parser.error(f"Target does not exist: {path}")
    kind = args.kind or ("folder" if path.is_dir() else "file")
    target = AnalysisTarget(value=str(path), kind=kind, authorized=False)
    job = AnalysisRunner(registry).run(AnalysisJob(target=target, requested_engines=args.engines or []))
    Path(args.out).write_text(json.dumps(job.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Job {job.job_id}: {job.status.value}; {len(job.results)} engine result(s)")
    print(f"Report: {Path(args.out).resolve()}")
    return 0 if job.status.value in {"succeeded", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
