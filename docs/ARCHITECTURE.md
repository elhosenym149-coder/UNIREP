# UNIREP / Reforge architecture

## Principles
- Preserve the original `reforge.py` legacy analyzer until parity tests exist.
- Keep analysis engines isolated behind a small contract.
- Read-only by default. No execution of analyzed binaries or extracted scripts.
- Every finding should distinguish observed facts from inferred hypotheses and include confidence where meaningful.
- Optional capabilities must fail with actionable dependency messages, not silently pretend to work.
- All extraction, parsing, and browser work must have resource limits and explicit authorization.

## Current modular foundation
- `core.models`: target, job, result, evidence and lifecycle contracts.
- `core.registry`: explicit engine registration.
- `core.runner`: fault-isolated sequential orchestration.
- `engines.inventory`: bounded file inventory.
- `engines.signatures`: project manifest detection.
- `engines.architecture`: static Python AST import graph.
- `engines.binary`: PE, ELF and Mach-O header metadata.
- `engines.archive`: guarded ZIP inspection and extraction.
- `engines.legacy`: compatibility adapter around the preserved analyzer.
- `engines.web.browser`: optional read-only Playwright DOM and sanitized network metadata.
- `reconstruction.generator`: reviewed-spec Python/web scaffold generation.
- `service.server`: authenticated local/LAN control API with allowed-root browsing.
- `desktop`: optional PySide6 front end; `apps/android`: companion client source.

## Planned engine boundaries
- Static analysis: source, bytecode, package manifests and binary metadata.
- Dynamic analysis: isolated disposable environments, process/network telemetry and user-approved execution.
- Web analysis: rendered DOM, navigation, accessibility, resources and observable API traffic.
- Binary analysis: PE, ELF, Mach-O and managed runtimes through established tools.
- Mobile analysis: APK/AAB/IPA package structure, resources and manifests.
- AI model analysis: architecture metadata and tensor inventories; never load untrusted weights into an execution runtime by default.
- Architecture graph: modules, interfaces, dependencies, data flows and evidence provenance.
- Reconstruction: generate a new project from verified specifications, then run tests and visual/behavioral comparisons.

## Reconstruction limits
A compiled or hosted product cannot generally be reconstructed byte-for-byte. Source maps, symbols, debug builds, exported data and authorized APIs can improve fidelity. Server-side logic, model weights, private services and protected assets are not assumed accessible.
