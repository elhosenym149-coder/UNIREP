"""Orchestrates engines and records partial failures without hiding them."""
from __future__ import annotations

from time import perf_counter
from .models import AnalysisJob, JobStatus


class AnalysisRunner:
    def __init__(self, registry):
        self.registry = registry

    def run(self, job: AnalysisJob) -> AnalysisJob:
        job.status = JobStatus.RUNNING
        names = job.requested_engines or [x["name"] for x in self.registry.list()]
        for name in names:
            started = perf_counter()
            try:
                engine = self.registry.get(name)
                if engine.supported_kinds and job.target.kind not in engine.supported_kinds:
                    continue
                result = engine.analyze(job.target)
                result.duration_seconds = round(perf_counter() - started, 6)
                job.results.append(result)
                if result.errors:
                    job.errors.extend(f"{name}: {e}" for e in result.errors)
            except Exception as exc:  # engine failures must not erase other results
                job.errors.append(f"{name}: {type(exc).__name__}: {exc}")
        if job.errors and job.results:
            job.status = JobStatus.PARTIAL
        elif job.errors:
            job.status = JobStatus.FAILED
        else:
            job.status = JobStatus.SUCCEEDED
        return job
