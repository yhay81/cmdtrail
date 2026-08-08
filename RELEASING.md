# Releasing

Releases are built only from signed annotated `vX.Y.Z` tags that point to the
protected `main` branch.

## v1 evidence gate

Every release validates the checked-in evidence manifest structure:

```bash
python3 scripts/verify_v1_evidence.py \
  .github/v1-evidence.json --check-structure
```

For every v1 or later release, update the manifest with public, reviewable
evidence for the exact target version and run:

```bash
python3 scripts/verify_v1_evidence.py \
  .github/v1-evidence.json \
  --require-ready \
  --release-version 1.0.0
```

The verifier derives readiness from the evidence. Do not add a bypass, count
maintainer activity as adoption, suppress a failed gate, or move evidence dates
forward. The continuous window must end on `as_of` and include one public
successful-run URL for every required track on every date.

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
   git tag -s v0.3.0 -m "CmdTrail v0.3.0"
   git push origin v0.3.0
   ```

6. The release workflow validates the tag, builds four native archives, runs
   tests, creates completions and machine contracts, generates checksums and a
   CycloneDX SBOM, attaches GitHub attestations and downloadable
   `.intoto.jsonl` provenance bundles, and publishes the release.
7. Independently download every asset and verify:

   ```bash
   shasum -a 256 -c SHA256SUMS
   gh attestation verify <archive> --repo yhay81/cmdtrail
   gh attestation verify <archive> \
     --repo yhay81/cmdtrail \
     --bundle <archive>.intoto.jsonl \
     --signer-workflow yhay81/cmdtrail/.github/workflows/release.yml
   gh attestation verify <archive> \
     --repo yhay81/cmdtrail \
     --predicate-type https://cyclonedx.org/bom
   ```

8. Extract a native archive and run `--version`, `capabilities`, `contract`,
   completion generation, a complete record/verify/show lifecycle, tamper
   refusal, and overwrite refusal using the released binary.

## crates.io

The first crates.io release must be published manually because Trusted
Publishing can only be configured after the crate exists. From the exact signed
release commit, repeat `cargo publish --dry-run --locked`, review
`cargo package --list --locked`, then publish:

```bash
cargo publish --locked
```

Use a Cargo credential provider backed by the operating-system credential
store. Never put a crates.io token in Git, workflow YAML, logs, or a
repository-level Actions secret. If Cargo times out after upload, check the
crates.io page and index before retrying; an accepted version is immutable.

After the first manual release:

1. Add the crate's Trusted Publisher in crates.io, restricted to
   `yhay81/cmdtrail`, the dedicated publish workflow filename, and the protected
   `crates-io` GitHub environment.
2. Add that workflow only after the mapping exists. Grant only
   `contents: read` and `id-token: write`, pin every action to an immutable
   commit, exchange OIDC with `rust-lang/crates-io-auth-action`, and run
   `cargo publish --locked`.
3. Remove any temporary API token, verify registry ownership and account
   recovery without recording secrets, and require environment approval for
   every publish.
4. Install the exact version from crates.io in a clean environment and repeat
   the record/verify/show smoke checks.

Never reuse or move a release tag. Publish a new patch release for corrections.
