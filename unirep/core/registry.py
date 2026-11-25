"""Explicit registry for analysis engines."""
from __future__ import annotations

from .engine import AnalysisEngine


class EngineRegistry:
    def __init__(self) -> None:
        self._engines: dict[str, AnalysisEngine] = {}

    def register(self, engine: AnalysisEngine) -> None:
        if not getattr(engine, "name", "").strip():
            raise ValueError("Engine name must not be empty")
        if engine.name in self._engines:
            raise ValueError(f"Engine already registered: {engine.name}")
        self._engines[engine.name] = engine

    def get(self, name: str) -> AnalysisEngine:
        try:
            return self._engines[name]
        except KeyError as exc:
            raise KeyError(f"Unknown engine: {name}") from exc

    def list(self) -> list[dict[str, object]]:
        return [
            {"name": e.name, "description": e.description,
             "supported_kinds": sorted(e.supported_kinds)}
            for e in sorted(self._engines.values(), key=lambda x: x.name)
        ]
