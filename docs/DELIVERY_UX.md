# Reforge product interface and installation delivery

## Product experience

The desktop experience should feel like a professional engineering workbench, not a terminal wrapped in buttons. The same versioned core API powers desktop and mobile companion clients.

### Main workspaces

- **Projects**: recent projects, imported packages, analysis history and snapshots.
- **Analyze**: guided file/folder/app/website selection, platform detection, analysis profile and progress.
- **Security & Repair**: findings inbox, evidence viewer, dependency impact graph, repair proposal, approval and rollback history.
- **Architecture**: interactive component graph, interfaces, dependencies, data flows and confidence/provenance.
- **Merge Studio**: side-by-side capability comparison, feature selection, dependency/conflict resolution and composition preview.
- **UI & Branding Studio**: product name, logo, icon, theme, screens, navigation and responsive previews.
- **Build & Install**: target platform, output format, signing, build logs, validation and install handoff.
- **Reports**: technical report, SBOM, licenses, provenance, security findings, tests and change history.

### Guided workflow

Use a persistent project pipeline:
Import → Analyze → Review → Select/Repair/Compose → Validate → Package → Install/Export.

Each stage displays prerequisites, progress, warnings and evidence. Advanced options remain available without forcing beginners to understand every engine.

## Output formats and installation handoff

- Windows: portable folder/ZIP first; then MSI/MSIX or EXE installer when packaging and signing are configured.
- Android: APK for direct user-approved installation; AAB for Play distribution. A companion phone can receive the artifact from the paired desktop or a trusted project workspace.
- Linux: AppImage, Flatpak or distribution package as appropriate.
- macOS: app bundle/DMG/PKG when signing and notarization requirements are met.
- iOS: signed IPA only through supported Apple provisioning/distribution workflows; do not promise arbitrary direct installation.

The build stage must verify target platform, architecture, dependencies, package identifier, version, signature state, hashes, license notices and test results. If a signing identity is unavailable, label the package unsigned and explain installation restrictions.

## Install action

After a successful build, show:
- the exact artifact and its size/hash;
- platform and architecture;
- signing/verification state;
- test and security scan summary;
- save location and expiry/retention information;
- actions to open output folder, transfer to a paired phone, or initiate installation.

Installation always requires an explicit user action and normal OS permission prompts. Never silently install, bypass Android unknown-source prompts, bypass platform signing, or expose an artifact through an unauthenticated public URL.

## Visual system

Provide reusable components, consistent spacing/typography, keyboard navigation, screen-reader labels, scalable text, high-contrast states, light/dark themes, empty/loading/error/success states and responsive layouts. Use a clean professional engineering aesthetic; avoid cluttering the main flow with raw logs.

## Current status

The current project has an early PySide6 desktop UI, an Android companion scaffold and Windows portable/Android debug build workflows. The complete workspace navigation, Merge Studio, branding editor, cross-device artifact transfer, production installers and release signing remain planned.
