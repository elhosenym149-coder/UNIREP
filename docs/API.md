# Reforge local control API

The API is intended for the desktop UI and companion clients. It is not a public internet service.

## Authentication

Every endpoint requires:

```http
Authorization: Bearer <token>
```

The token is generated at server startup unless `UNIREP_API_TOKEN` is configured. Use HTTPS for non-loopback access. Binding to a non-loopback interface without a certificate is rejected unless the operator explicitly supplies the development-only `--insecure-lan` flag.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/health` | Service health |
| GET | `/v1/engines` | Registered engine metadata |
| GET | `/v1/roots` | Configured allowed directories |
| GET | `/v1/browse?path=<absolute-path>` | List a directory within allowed roots |
| POST | `/v1/jobs` | Submit a background local analysis |
| GET | `/v1/jobs/<job-id>` | Retrieve job status and report |

## Submit a job

```json
{
  "target": "/srv/projects/example",
  "kind": "folder",
  "engines": ["inventory", "signatures", "python_architecture"]
}
```

- `target` must resolve inside a configured allowed root.
- `kind` is `file` or `folder`.
- `engines` is a list of registered engine names. An empty list means all compatible engines.
- The server accepts local paths only. Website inspection remains an explicit CLI action in this version.
- The job is queued and returns HTTP 202 with a job ID.
- The in-memory queue is limited to 100 jobs and uses at most two worker threads.
- Job history is not persistent; restarting the server clears it.

## Security boundaries

- No CORS headers are enabled.
- Request bodies are limited to 64 KiB.
- Filesystem browsing and job targets are constrained to configured roots.
- Symlink entries are omitted from browsing and resolved targets are checked against allowed roots.
- Static analyzers do not execute target code.
- The API does not accept arbitrary shell commands, uploads, or dynamic-analysis instructions.
- LAN mode without TLS is intentionally opt-in and unsafe on untrusted networks.
