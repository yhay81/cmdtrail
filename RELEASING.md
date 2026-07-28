# Releasing

Releases are built only from signed annotated `vX.Y.Z` tags that point to the
protected `main` branch.

1. Confirm the version in `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`.
2. Run:

   ```bash
   cargo fmt --check
   cargo clippy --all-targets --all-features --locked -- -D warnings
   cargo test --all-targets --locked
   cargo +1.85.0 check --all-targets --locked
   cargo audit
   cargo package --locked --allow-dirty
   ```

3. Exercise `record`, `verify`, `show`, and `diff` with a fresh external
   temporary directory. Confirm child output does not contaminate stdout.
4. Merge through protected `main` and confirm every required check.
5. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.2.0 -m "CmdTrail v0.2.0"
   git push origin v0.2.0
   ```

6. The release workflow validates the tag, builds four native archives, runs
   tests, creates completions and machine contracts, generates checksums and a
   CycloneDX SBOM, attaches GitHub attestations, and publishes the release.
7. Independently download every asset and verify:

   ```bash
   shasum -a 256 -c SHA256SUMS
   gh attestation verify <archive> --repo yhay81/cmdtrail
   gh attestation verify <archive> \
     --repo yhay81/cmdtrail \
     --predicate-type https://cyclonedx.org/bom
   ```

8. Extract a native archive and run `--version`, `capabilities`, `contract`,
   completion generation, a complete record/verify/show lifecycle, tamper
   refusal, and overwrite refusal using the released binary.

Never reuse or move a release tag. Publish a new patch release for corrections.
