# Roadmap

CmdTrail advances only when capability claims are supported by fixtures and
published measurements. Feature count is not a release criterion.

## v0.1.0 release gate

- [x] Stable `cmdtrail.receipt.v1` and machine-readable CLI contract.
- [x] Portable backend on Linux, macOS, and Windows.
- [x] Direct-child outcome and persistent file-delta receipts.
- [x] Explicit static capabilities and dynamic blind spots.
- [x] Strict bounds, redaction, no-overwrite output, and offline verification.
- [x] Adversarial and lifecycle tests on all supported operating systems.
- [x] Declared Rust 1.85 MSRV and dependency audit.
- [x] Signed tag, four native archives, checksums, CycloneDX SBOM, provenance,
  and independent release-asset verification.

## v0.2 calibration

- Publish a reproducible fixture corpus covering:
  - create, write, same-size write, metadata change, rename, delete, and symlink;
  - inaccessible paths, concurrent mutation, entry truncation, hash budgets,
    and event drops;
  - direct-child exit, signal, timeout, interruption, and spawn failure;
  - supported redaction patterns and known escape classes.
- [x] Add golden receipt compatibility tests and an external verifier fixture.
- Publish benchmark methodology and raw results for 1k, 10k, and 100k-entry
  trees.
- Evaluate opt-in Linux native tracing without changing the public receipt
  envelope.

## v0.5 native evidence

- Add at least one calibrated Linux backend for transient filesystem and
  process-tree evidence.
- Report kernel, privilege, namespace, and drop-related degradation explicitly.
- Add network endpoint metadata only if fixture recall, privacy behavior, and
  privilege boundaries are measurable.
- Preserve the portable backend as the no-privilege fallback.
- Add optional detached-descendant observation windows with hard duration and
  event bounds.

## v1.0 quality criteria

CmdTrail v1.0 requires all of the following:

### Product and compatibility

- The portable backend remains supported on Linux x86_64, macOS x86_64 and
  Apple Silicon, and Windows x86_64.
- `cmdtrail.receipt.v1` has at least two released compatibility cycles and
  golden files accepted by the current verifier.
- Breaking schema or CLI changes are either absent or delivered through a new
  major schema/version with a migration guide.
- A native backend never silently falls back or upgrades a capability level.

### Correctness and security

- 100% rejection of the published receipt mutation corpus.
- 100% recall and precision for persistent portable fixture deltas that remain
  inside declared roots and limits.
- At least 95% recall and 99% precision for every event class claimed `full` by
  a native backend, with missed classes converted to `partial`.
- Zero escapes in the supported-pattern redaction corpus; unsupported
  arbitrary-secret limitations remain prominent.
- Zero known critical or high-severity vulnerabilities at release time.
- An external security and privacy review of receipt metadata, redaction,
  symlink handling, races, and authenticity boundaries is resolved.

### Performance and bounds

- Default portable snapshots of the published 10k-file fixture add no more
  than 2 seconds p95 on the documented GitHub-hosted runner.
- Peak resident memory remains under 256 MiB for the 100k-entry bounded fixture.
- Receipt storage never exceeds the configured event bound plus documented
  constant metadata overhead.
- Limit exhaustion, read errors, and observer drops are always reflected in
  summary completeness and per-root evidence.

### Delivery and maintenance

- Required CI is green on all supported operating systems for 30 consecutive
  days before tagging.
- Releases come only from protected `main` via signed annotated tags.
- Every archive has verified checksums, GitHub-hosted provenance, and a
  CycloneDX SBOM attestation.
- At least two maintainers can execute the documented release and incident
  process, or the governance document explicitly records the single-maintainer
  continuity risk and a tested recovery procedure.
- Security reports receive acknowledgement within 3 business days and an
  initial assessment within 7.

### Adoption evidence

- At least three independent users or teams are listed in `ADOPTERS.md` or
  provide privacy-preserving equivalent evidence.
- At least two adopters report repeat use separated by 30 days.
- At least one non-maintainer issue, discussion, documentation change, test,
  or code contribution is resolved and credited.
- At least one public workflow demonstrates a decision improved by a CmdTrail
  receipt rather than only installation or curiosity.

These adoption gates cannot be satisfied by maintainer-authored fixtures,
automated downloads, stars, or synthetic accounts.
