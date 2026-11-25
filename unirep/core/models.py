"""Shared data contracts for analysis jobs and engine results."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
import uuid


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(slots=True)
class AnalysisTarget:
    value: str
    kind: str
    authorized: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> Path:
        return Path(self.value).expanduser()


@dataclass(slots=True)
class Evidence:
    claim: str
    kind: str = "observed"  # observed | inferred
    source: str | None = None
    confidence: float | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EngineResult:
    engine: str
    status: str
    summary: str
    findings: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float | None = None
    duration_seconds: float | None = None


@dataclass(slots=True)
class AnalysisJob:
    target: AnalysisTarget
    requested_engines: list[str] = field(default_factory=list)
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: JobStatus = JobStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list[EngineResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
