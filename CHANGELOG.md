# Changelog

All notable changes are documented here. CmdTrail follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Added a privacy-conscious adoption report form that captures evaluation,
  repeat-use, limitations, evidence, and public-listing permission.
- Added a monthly maintainer-continuity drill that recovers the public Git
  mirror and verifies signed tags, release checksums, build/SBOM attestations,
  and the released native binary without repository write access.

## [0.2.0] - 2026-07-29

### Compatibility

- Preserved the public v0.1 CLI and `cmdtrail.receipt.v1` contracts. The v0.2
  verifier accepts the digest-pinned v0.1 receipt corpus byte-for-byte; no
  migration is required.

### Added

- Digest-pinned `cmdtrail.receipt.v1` golden corpus, twelve fail-closed
  mutations, exact serialization checks, and an independent standard-library
  verifier.
- Deterministic 1k-file, 10k-file, and 100k-entry performance trees with weekly
  raw wall-time, memory, output-size, snapshot, and integrity artifacts.

### Planned

- Calibrated native observation backends and published fixture coverage.
- Optional authenticated runtime receipt signatures.

## [0.1.0] - 2026-07-28

### Added

- Portable pre/post filesystem snapshot backend for Linux, macOS, and Windows.
- Direct execution with a mandatory `--` separator and no implicit shell.
- `record`, `show`, `diff`, `verify`, `schema`, `capabilities`, `contract`, and
  `completions` commands.
- Strict versioned JSON receipts with RFC 8785 canonicalization, SHA-256
  event-chain integrity, aggregate event digests, and derived receipt IDs.
- Bounded entry, event, file-hash, total-hash, timeout, and receipt-input limits.
- New-file-only private receipt output and strict unknown-field rejection.
- Pattern-based argument and path redaction, exact secret redaction from named
  environment variables, and omitted digests for redacted arguments.
- Cross-platform fixture tests for effects, child failure, timeout,
  interruption, limits, drops, redaction, overwrite refusal, tampering, strict
  parsing, verification, summaries, and diff.
- Signed native release archives, checksums, CycloneDX SBOM, and GitHub
  attestations.

[Unreleased]: https://github.com/yhay81/cmdtrail/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yhay81/cmdtrail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yhay81/cmdtrail/releases/tag/v0.1.0
