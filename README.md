# UNIREP — Reforge

**Universal software analysis and reconstruction workspace.**

Reforge is being developed as a modular platform for inspecting software that you own or are authorized to assess, documenting observable behavior, mapping architecture, and generating a new implementation that can be tested against verified requirements.

> Important: reverse engineering does not guarantee recovery of original source code. Server-side code, proprietary model weights, protected assets and private services are not assumed to be accessible. The project does not bypass DRM, authentication, CAPTCHAs, paywalls or other access controls.

## Project status

The original `reforge.py` analyzer is preserved as the legacy implementation. The new modular package is being built alongside it so that capabilities can be migrated only after tests and parity checks.

Current modular foundation:
- Engine contracts, registry, fault-isolated job runner and evidence/provenance records.
- Read-only filesystem inventory and project-manifest detection.
- ZIP inspection/extraction with entry, size, path-traversal and symlink safeguards.
- Optional Playwright-based read-only browser inspection of an explicitly authorized website, including sanitized request/response metadata.
- Static Python AST import graphing, a read-only Python security-indicator engine (dynamic execution, shell invocation and unsafe deserialization patterns), native PE/ELF/Mach-O header inspection, and a compatibility adapter for the original package analyzer.
- Early Android companion source plus a GitHub Actions debug-APK build workflow.
- JSON job reports and a command-line interface.
- Initial P8 security-analysis slices implemented: Python AST indicators include dynamic execution, shell invocation, unsafe deserialization, selected encoded-execution patterns and selected outbound network APIs. Findings include source location, severity, confidence, false-positive caveats and SHA-256 provenance; static Python dependency impact is mapped. A separate engine inventories Python requirements/constraints manifests without resolving versions or assessing vulnerabilities. These are not malware/exfiltration verdicts and no remediation is performed. Dependency impact, broader-language coverage, trusted repair, Merge Studio, branding and release installers remain planned.
- Initial automated tests and architecture/roadmap documents.

This is an early development branch, not a production-ready universal decompiler or one-click clone tool.

## Install directly from GitHub

Install the command-line package and optional desktop/browser features from the active development branch:

```bash
python -m pip install "unirep-reforge[desktop,web] @ git+https://github.com/elhosenym149-coder/UNIREP.git@work/reforge-validation"
```

For a reproducible environment, pin to a reviewed commit SHA rather than a moving branch.

## Quick start

Python 3.10 or newer:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

python -m pip install -e ".[test]"
python -m pytest
```

On Windows, run `scripts\install_windows.bat` once, then `scripts\run_windows.bat`. To build a portable folder containing `Reforge.exe`, run `scripts\build_windows_portable.bat`. A separate Windows CI workflow checks this packaging path.

Launch the optional Windows/Linux desktop interface:

```bash
python -m pip install -e ".[desktop]"
unirep desktop
```

Generate a clean Python or web starter from an analyst-reviewed reconstruction specification:

```bash
unirep rebuild examples/reconstruction-spec.json --out ./generated-project
```

The generator creates a scaffold from explicit requirements; it does not claim to recover hidden server code, private model weights or the original source tree.

Start the authenticated local control API for companion clients:

```bash
mkdir workspace
unirep serve --root ./workspace
```

The server prints a generated bearer token at startup. For a fixed token, set `UNIREP_API_TOKEN` in the environment rather than putting secrets in shell history or command-line arguments. By default it listens only on `127.0.0.1`. Non-loopback access requires TLS (`--cert cert.pem --key key.pem`) or the explicit development-only `--insecure-lan` flag. Prefer HTTPS with a certificate trusted by the phone. Unencrypted LAN mode exposes bearer tokens and analysis data to interception; use it only on an isolated trusted network. Never expose this API directly to the public internet.

Check which optional tools and libraries are installed:

```bash
unirep doctor
unirep doctor --json
```

The doctor command reports missing tools and installation hints; it does not install software automatically.

List engines:

```bash
unirep engines
```

Analyze a local folder (read-only; includes the `security_static` engine):

```bash
unirep analyze ./path/to/project --out analysis.json
```

Inspect an explicitly authorized website (read-only):

```bash
unirep web https://your-owned-site.example --authorized --out reports/site.json
```

Additional resource hosts can be allowlisted with `--allow-host cdn.your-owned-site.example`. Query strings and URL fragments are removed from captured network metadata.

Install optional browser support:

```bash
python -m pip install -e ".[web]"
python -m playwright install chromium
```

Browser inspection is available through the Python engine API and requires the caller to explicitly mark the target as authorized. It does not submit forms or attempt to evade site controls.

Android companion source is under `apps/android`. Build and connection instructions are in [apps/android/README.md](apps/android/README.md). The local control API is documented in [docs/API.md](docs/API.md).

## Repository layout

```text
unirep/
  core/       Shared contracts, registry and orchestration
  engines/    Independent analysis engines
tests/        Automated tests
docs/         Architecture and delivery roadmap
reforge.py    Preserved legacy analyzer
```

## Safety model

- Static inspection does not execute analyzed programs.
- Extracted code and binaries are never run by the archive engine.
- Optional dynamic analysis will require disposable, isolated environments and explicit operator approval.
- Findings should include provenance and confidence; inferred behavior must not be presented as observed fact.
- Resource limits and safe path handling are mandatory for parsers and extractors.

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), [Security & Repair](docs/SECURITY_REPAIR.md), [Merge Studio](docs/MERGE_STUDIO.md), and [Product UX & Delivery](docs/DELIVERY_UX.md).
