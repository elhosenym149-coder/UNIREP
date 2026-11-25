"""Engine plugin contract."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from .models import AnalysisTarget, EngineResult


class AnalysisEngine(ABC):
    name: str
    description: str
    supported_kinds: set[str] = set()

    @abstractmethod
    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        """Analyze an explicitly selected target without changing it."""
