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
- Static Python AST import graphing, native PE/ELF/Mach-O header inspection, and a compatibility adapter for the original package analyzer.
- Early Android companion source plus a GitHub Actions debug-APK build workflow.
- JSON job reports and a command-line interface.
- Initial automated tests and architecture/roadmap documents.

This is an early development branch, not a production-ready universal decompiler or one-click clone tool.

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

The server prints a bearer token at startup. By default it listens only on `127.0.0.1`; to connect a phone on the same trusted Wi-Fi network, explicitly bind to your computer's LAN interface (for example `--host 0.0.0.0`), use a strong private token, and keep the port firewalled. The API is not designed for direct internet exposure and does not provide TLS.

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

Analyze a local folder (read-only):

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

Android companion source is under `apps/android`. Build and connection instructions are in [apps/android/README.md](apps/android/README.md).

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

See [Architecture](docs/ARCHITECTURE.md) and [Roadmap](docs/ROADMAP.md).
