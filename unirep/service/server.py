"""Small authenticated control server; binds to localhost unless explicitly configured otherwise."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock
from typing import Any
import hmac
import json
import secrets
import ssl
import sys
from urllib.parse import urlparse

from unirep.core.models import AnalysisJob, AnalysisTarget, JobStatus
from unirep.core.runner import AnalysisRunner
from unirep.cli import build_registry


class JobManager:
    def __init__(self, roots: list[Path], max_workers: int = 2):
        self.roots = [p.expanduser().resolve(strict=True) for p in roots]
        if not self.roots or any(not p.is_dir() for p in self.roots):
            raise ValueError("At least one existing allowed directory root is required")
        self.registry = build_registry()
        self.runner = AnalysisRunner(self.registry)
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="unirep")
        self.jobs: dict[str, AnalysisJob] = {}
        self.lock = RLock()

    def _resolve_target(self, value: str, kind: str) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("target must be a non-empty path string")
        if kind not in {"file", "folder"}:
            raise ValueError("Only local file and folder targets are supported")
        path = Path(value).expanduser().resolve(strict=True)
        if not any(path == root or root in path.parents for root in self.roots):
            raise PermissionError("Target is outside the server's allowed roots")
        if kind == "file" and not path.is_file():
            raise ValueError("Target is not a regular file")
        if kind == "folder" and not path.is_dir():
            raise ValueError("Target is not a directory")
        return path

    def submit(self, payload: dict[str, Any]) -> AnalysisJob:
        path = self._resolve_target(payload.get("target"), payload.get("kind"))
        engines = payload.get("engines", [])
        if not isinstance(engines, list) or len(engines) > 32 or not all(isinstance(x, str) for x in engines):
            raise ValueError("engines must be a list of at most 32 engine names")
        for name in engines:
            self.registry.get(name)
        job = AnalysisJob(
            target=AnalysisTarget(value=str(path), kind=payload["kind"]),
            requested_engines=engines
        )
        with self.lock:
            if len(self.jobs) >= 100:
                finished = [key for key, item in self.jobs.items()
                            if item.status in {JobStatus.SUCCEEDED, JobStatus.PARTIAL, JobStatus.FAILED}]
                for key in finished[:50]:
                    self.jobs.pop(key, None)
            if len(self.jobs) >= 100:
                raise RuntimeError("Job queue is full; wait for current analyses to finish")
            self.jobs[job.job_id] = job
        self.executor.submit(self._run, job)
        return job

    def _run(self, job: AnalysisJob) -> None:
        try:
            self.runner.run(job)
        except Exception as exc:
            job.status = JobStatus.FAILED
            job.errors.append(f"{type(exc).__name__}: {exc}")

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self.lock:
            job = self.jobs.get(job_id)
            return job.to_dict() if job else None

    def engines(self) -> list[dict[str, object]]:
        return self.registry.list()

    def list_roots(self) -> list[str]:
        return [str(root) for root in self.roots]

    def browse(self, value: str) -> list[dict[str, Any]]:
        folder = self._resolve_target(value, "folder")
        entries = []
        for item in sorted(folder.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                if item.is_symlink():
                    continue
                resolved = item.resolve(strict=True)
                if not any(resolved == root or root in resolved.parents for root in self.roots):
                    continue
                info = {"name": item.name, "path": str(resolved),
                        "kind": "folder" if resolved.is_dir() else "file"}
                if resolved.is_file():
                    info["size"] = resolved.stat().st_size
                entries.append(info)
                if len(entries) >= 500:
                    break
            except OSError:
                continue
        return entries

    def close(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=True)


def serve(host: str = "127.0.0.1", port: int = 8765,
          roots: list[str] | None = None, token: str | None = None,
          certfile: str | None = None, keyfile: str | None = None,
          insecure_lan: bool = False) -> None:
    allowed_roots = [Path(x) for x in (roots or [str(Path.cwd())])]
    manager = JobManager(allowed_roots)
    if token is not None and len(token) < 24:
        raise ValueError("Explicit bearer tokens must contain at least 24 characters")
    if bool(certfile) != bool(keyfile):
        raise ValueError("Both --cert and --key must be provided together")
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if not loopback and not certfile and not insecure_lan:
        raise ValueError("Non-loopback binding requires TLS (--cert/--key) or explicit --insecure-lan")
    auth_token = token or secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        server_version = "UNIREP-Control/0.1"
        sys_version = ""

        def _send(self, status: int, data: dict[str, Any]) -> None:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            expected = f"Bearer {auth_token}"
            if not hmac.compare_digest(supplied, expected):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self._authorized():
                return
            parsed = urlparse(self.path)
            route = parsed.path
            if route == "/v1/health":
                self._send(200, {"status": "ok", "service": "unirep"})
            elif route == "/v1/engines":
                self._send(200, {"engines": manager.engines()})
            elif route == "/v1/roots":
                self._send(200, {"roots": manager.list_roots()})
            elif route == "/v1/browse":
                from urllib.parse import parse_qs
                query = parse_qs(parsed.query)
                path = query.get("path", manager.list_roots()[0])[0]
                try:
                    self._send(200, {"path": path, "entries": manager.browse(path)})
                except PermissionError as exc:
                    self._send(403, {"error": str(exc)})
                except (ValueError, OSError) as exc:
                    self._send(400, {"error": str(exc)})
            elif route.startswith("/v1/jobs/"):
                job_id = route.rsplit("/", 1)[-1]
                result = manager.get(job_id)
                self._send(200 if result else 404, result or {"error": "job_not_found"})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            if not self._authorized():
                return
            if urlparse(self.path).path != "/v1/jobs":
                self._send(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 65536:
                    raise ValueError("Request body must be between 1 and 65536 bytes")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON body must be an object")
                job = manager.submit(payload)
                self._send(202, {"job_id": job.job_id, "status": job.status.value})
            except PermissionError as exc:
                self._send(403, {"error": str(exc)})
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                self._send(400, {"error": str(exc)})
            except RuntimeError as exc:
                self._send(429, {"error": str(exc)})

        def log_message(self, fmt, *args):
            # Do not log Authorization headers or request bodies.
            sys.stderr.write("UNIREP API: " + (fmt % args) + "\n")

    httpd = ThreadingHTTPServer((host, port), Handler)
    scheme = "http"
    if certfile and keyfile:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certfile=certfile, keyfile=keyfile)
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"UNIREP control API listening on {scheme}://{host}:{port}")
    print(f"Allowed roots: {', '.join(str(x.resolve()) for x in allowed_roots)}")
    print(f"Bearer token (keep private): {auth_token}")
    if not loopback and insecure_lan and not certfile:
        print("WARNING: INSECURE LAN mode: bearer tokens and analysis data are unencrypted. Use only on a trusted isolated network.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UNIREP control API.")
    finally:
        httpd.server_close()
        manager.close()
