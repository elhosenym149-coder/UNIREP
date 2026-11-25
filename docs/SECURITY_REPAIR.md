# Reforge security analysis, component repair and trusted rebuild

## Goal

Reforge should reverse-engineer software architecture deeply enough to identify malicious or compromised components, explain their role, and offer a controlled repair path without destroying legitimate functionality. This is a defensive analysis and remediation workflow for software the operator owns or is authorized to assess.

## Non-negotiable safety rules

1. Preserve the original input. Work on a verified copy in a separate workspace; calculate cryptographic hashes before and after each stage.
2. Static analysis is read-only. Never execute a target, extracted script, installer, macro, or unknown binary as part of static inspection.
3. No automatic deletion, patching, replacement, or disabling based on a filename, one heuristic, or a single antivirus label.
4. Findings must include evidence, source location, affected artifact, detection method, confidence, severity, false-positive caveats, and the reason the item is considered malicious or suspicious.
5. Distinguish confirmed malicious behavior, suspicious behavior, vulnerable code, unwanted but legitimate functionality, and unknown/unclassified code.
6. Require explicit operator approval before quarantine, removal, patching, component replacement, rebuilding, signing, or installation.
7. Every change must be reversible where technically possible and recorded in an append-only repair manifest. Preserve the original component and its hash.
8. If Reforge cannot establish what a component does, what depends on it, or how to preserve its contract, it must not replace it automatically.

## Detection pipeline

- Inventory packages, modules, binaries, scripts, resources, manifests, dependencies, signatures and entry points.
- Build a component/dependency graph and map privilege boundaries, startup paths, persistence mechanisms, network endpoints and sensitive data flows.
- Combine multiple evidence sources: cryptographic reputation/signature checks where available, YARA-style rules, static code patterns, import/API analysis, package provenance, dependency advisories, configuration analysis, and optional sandbox telemetry.
- Use maintained threat-intelligence/rule feeds with source, version, timestamp, license and update status. Never treat a rule match alone as proof.
- Correlate findings across layers and show the analyst the exact evidence and confidence rationale.
- Keep a clear boundary between offline static analysis and optional dynamic analysis in a disposable, network-restricted sandbox. Dynamic execution requires a separate explicit approval.

## Risk-aware repair workflow

1. Create a snapshot and baseline hashes; identify the exact affected package/component and its dependants.
2. Explain the finding and classify it. Show the evidence, likely impact, confidence, and possible false positives.
3. Present repair choices: leave unchanged, disable/quarantine reversibly, remove only a proven nonessential payload, restore a trusted vendor/original component, or rebuild a replacement component.
4. For a core component or engine, do not substitute a stub or delete it. Rebuild or restore a functionally equivalent implementation that satisfies the documented interface/ABI/API, data formats, lifecycle and dependency contracts.
5. Prefer clean, authenticated upstream packages or verified source over reconstructing an unknown implementation. Verify signatures and provenance where available.
6. Run unit, integration, compatibility, security and regression tests; compare expected features and data handling. Scan the repaired output again.
7. Generate a repair report containing before/after hashes, actions, approvals, replacement provenance, test results, unresolved risks and rollback instructions.
8. If equivalence or safety cannot be demonstrated, stop and report that manual review is required.

## Replacement acceptance gate

A replacement for a core engine is acceptable only when:
- its required inputs, outputs, errors, state transitions and compatibility expectations are documented;
- its public interface and required behavior are preserved;
- dependent components pass integration tests;
- security tests and regression tests pass;
- the replacement has clear source/build provenance and a reproducible build record;
- the user approves the proposed change.

"Looks similar" or "the application launches" is not sufficient evidence of equivalence.

## Repair output

The output is a new repaired build, never an in-place silent rewrite of the only original copy. Include a signed or hash-anchored repair manifest where signing keys are available, a software bill of materials, licenses, provenance, scan results, test report and rollback package.

## Current status

The first implementation slice now exists: `security_static` performs bounded, read-only Python AST inspection for selected risky execution, deserialization, encoded-execution and outbound-network API patterns. It correlates findings with the existing Python import graph to show direct and transitive static dependants and a limited role hint. It emits evidence, source locations, severity, confidence, false-positive caveats and SHA-256 hashes for scanned Python source files; every result remains `suspicious`, never a malware or exfiltration verdict. Static import mapping is not a complete runtime dependency-impact analysis. It does not inspect native code, Java/Kotlin, JavaScript, .NET or package advisories, and it does not perform repair, quarantine or dynamic sandboxing. The broader detection, component replacement and repair workflow remains planned and requires curated rule sources, isolated execution infrastructure and extensive validation.
