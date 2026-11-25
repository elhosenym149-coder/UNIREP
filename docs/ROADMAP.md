# Reforge delivery roadmap

Status is evidence-based: a feature is complete only after its tests pass.

| Phase | Scope | Status |
|---|---|---|
| P0 | Preserve legacy implementation; establish tests and safe extraction boundaries | Legacy ZIP extraction hardened; parser fuzzing and additional resource-limit coverage remain |
| P1 | Modular core, engine registry, job runner and CLI | Core, CLI, diagnostics and regression suite implemented; latest CI rerun pending |
| P2 | Web inspection and browser telemetry | Read-only DOM plus sanitized request/response metadata; host allowlist |
| P3 | Static source/package analyzers and richer PE/ELF/mobile metadata | Python AST import graph, PE/ELF/Mach-O metadata engine and legacy package adapter implemented; broader formats planned |
| P4 | Architecture graph and evidence/provenance model | Python AST import graph and structured observed/inferred evidence records implemented; broader languages planned |
| P5 | Controlled dynamic analysis in disposable sandboxes | Planned |
| P6 | Reconstruction workspace, templates and regression comparisons | Safe Python/web scaffold generator from reviewed JSON specifications implemented; behavioral reconstruction and comparison planned |
| P7 | Windows desktop packaging and Android companion/controller | Windows portable build and Android debug APK build verified in CI; release signing, device testing, installer and pairing polish remain |
| P8 | Evidence-led malware analysis, dependency impact and reversible repair/trusted component rebuild | Architecture specified; implementation and validation planned |
| P9 | Multi-app capability comparison, feature selection, conflict resolution and Merge Studio | Architecture specified; implementation planned |
| P10 | Full visual design/branding editor and platform-specific packaging/install handoff | UX and delivery requirements specified; implementation planned |

## Acceptance gates
1. Unit tests and static checks pass.
2. No target code is executed by static analysis.
3. Resource limits and path traversal tests cover archive operations.
4. Every engine reports unsupported formats and partial results honestly.
5. Generated projects include reproducible dependencies and tests.
6. Desktop/mobile interfaces call the same versioned core API.
7. Security repair preserves originals, requires approval, records evidence and supports rollback; core replacements pass contract and regression tests.
8. Merge Studio shows source, dependency, license and permission implications for every selected capability.
9. Installable outputs report platform, architecture, hash, signing state and validation results; installation is explicitly user-initiated.
