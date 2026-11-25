# Reforge delivery roadmap

Status is evidence-based: a feature is complete only after its tests pass.

| Phase | Scope | Status |
|---|---|---|
| P0 | Preserve legacy implementation; establish tests and safe extraction boundaries | In progress |
| P1 | Modular core, engine registry, job runner and CLI | Foundation implemented; tests pending CI |
| P2 | Web inspection and browser telemetry | Read-only DOM inspection scaffold implemented |
| P3 | Static source/package analyzers and richer PE/ELF/mobile metadata | Planned |
| P4 | Architecture graph and evidence/provenance model | Planned |
| P5 | Controlled dynamic analysis in disposable sandboxes | Planned |
| P6 | Reconstruction workspace, templates and regression comparisons | Planned |
| P7 | Windows desktop packaging and Android companion/controller | Planned |

## Acceptance gates
1. Unit tests and static checks pass.
2. No target code is executed by static analysis.
3. Resource limits and path traversal tests cover archive operations.
4. Every engine reports unsupported formats and partial results honestly.
5. Generated projects include reproducible dependencies and tests.
6. Desktop/mobile interfaces call the same versioned core API.
