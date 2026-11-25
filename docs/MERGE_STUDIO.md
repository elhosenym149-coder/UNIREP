# Reforge Merge Studio: capability composition and product design

## Goal

Allow an operator to analyze two or more owned or authorized applications, compare their capabilities and dependencies, select the features to retain, and compose a new product with a deliberate interface and identity.

This is capability-level composition, not blind binary concatenation. Opaque applications, inaccessible server-side features, incompatible licenses, and undocumented protocols may prevent a feature from being transferred.

## Workflow

1. **Import and analyze**: add source applications/packages/projects; identify platform, version, modules, features, screens, APIs, assets, dependencies, permissions, data stores and licenses.
2. **Build capability cards**: summarize each feature with its purpose, user-visible behavior, inputs/outputs, dependencies, permissions, evidence, confidence and transferability.
3. **Compare**: show shared features, unique features, conflicts, duplicate implementations, stronger/weaker alternatives, platform incompatibilities and license constraints.
4. **Select composition**: the operator selects the desired capabilities from each source. Reforge displays required dependencies and warns when a selection pulls in extra permissions, libraries, data or licensing obligations.
5. **Resolve conflicts**: propose explicit choices for naming collisions, API contracts, shared data models, navigation, authentication, storage, background tasks, permissions, UI patterns and dependency versions.
6. **Design the new product**: choose product name, app/package identifier, logo, icon, color system, typography, navigation, screen layouts and branding. Preview responsive layouts and platform-specific variants.
7. **Generate and validate**: create a new project using documented interfaces/adapters, then run build, unit, integration, security, accessibility and visual/behavioral regression checks.
8. **Package**: create a platform-appropriate installable or portable artifact, with version, signing configuration, license notices, SBOM, provenance and test report.

## Capability comparison model

Each capability card should show:
- source application and exact version/hash;
- capability name, description and observed evidence;
- required modules, services, libraries and permissions;
- API/data contracts and integration points;
- source/license/provenance and redistribution constraints;
- platform compatibility and transferability status;
- estimated integration effort and known risks.

Comparison must distinguish observed features from inferred ones. Do not claim that a feature can be transplanted until its implementation path and dependencies are understood.

## Composition architecture

Use adapters and explicit contracts rather than merging arbitrary binaries:
- shared domain models and versioned internal APIs;
- adapters around source-specific capabilities;
- isolated modules/plugins for optional features;
- a unified navigation shell and design system;
- explicit identity, permission, storage and lifecycle boundaries;
- conflict-resolution records and traceable source attribution.

Where source code is unavailable, Reforge may implement a clean-room equivalent from observable, authorized requirements. It must not copy proprietary code or assets without rights.

## Branding and interface editor

The operator can change:
- product display name and internal package/bundle identifier;
- logo, launcher icon, splash screen and app imagery;
- colors, typography, spacing, component shapes and themes;
- navigation structure, screen order, labels and supported layouts;
- light/dark modes, responsive breakpoints and accessibility settings.

Preview changes before generating the build. Validate icon dimensions, contrast, text scaling, localization and platform-specific asset requirements.

## Current status

The current reconstruction generator produces basic Python/web scaffolds from reviewed specifications. The multi-application capability graph, visual comparison board, interactive selection composer, branding editor and merge validation pipeline are planned, not implemented yet.
