# CmdTrail

Bounded, capability-declared receipts for observable command side effects.

[![CI](https://github.com/yhay81/cmdtrail/actions/workflows/ci.yml/badge.svg)](https://github.com/yhay81/cmdtrail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CmdTrail runs one direct command and writes a strict JSON receipt describing:

- the redacted command representation and direct-child outcome;
- persistent filesystem changes visible between bounded snapshots;
- the exact observation capabilities, limits, errors, drops, and blind spots;
- an RFC 8785 canonical receipt digest and SHA-256 event hash chain.

It is built for coding agents, maintainers, and supply-chain tooling that need a
durable answer to “what did this command observably change?” without pretending
that a portable snapshot is a complete system trace.

## Status

CmdTrail v0.3.0 uses the `portable_pre_post_snapshot` backend on Linux, macOS,
and Windows. It is useful for controlled project directories, but it is not a
sandbox or complete tracer.

| Capability | v0.3.0 coverage | Why |
| --- | --- | --- |
| Direct child spawn and outcome | Full | CmdTrail owns the direct child handle |
| Persistent file delta under declared roots | Partial | Bounded pre/post metadata and content-digest snapshots |
| Descendant process tree | Unavailable | No process instrumentation in the portable backend |
| Transient file effects | Unavailable | A create/write/delete between snapshots leaves no final delta |
| Network and listening ports | Unavailable | No socket instrumentation in v0.3.0 |
| Resource totals | Unavailable | No portable per-tree accounting in v0.3.0 |
| Detached or delayed descendants | Unavailable | The post-snapshot starts when the direct child exits |

Run `cmdtrail capabilities --format json` for the machine-readable declaration.
Every receipt repeats the effective capabilities and blind spots.

## Quick start

The literal `--` separator is mandatory. CmdTrail executes the argument vector
directly and never inserts a shell.

```bash
cmdtrail record \
  --out npm-install.receipt.json \
  --root . \
  --timeout 10m \
  -- npm install
```

The observed command's stdout and stderr are streamed to CmdTrail's stderr and
are not persisted. CmdTrail reserves stdout for exactly one JSON result:

```json
{
  "schema_version": "cmdtrail.record-result.v1",
  "receipt_id": "ct_...",
  "command_state": "exited",
  "command_success": true,
  "file_effect_counts": {
    "created": 12,
    "modified": 3
  },
  "observation_complete": false
}
```

`observation_complete` is false for the portable backend because transient,
descendant, and network effects remain outside its coverage even when no limit
was reached.

Verify and inspect the receipt:

```bash
cmdtrail verify npm-install.receipt.json --format json
cmdtrail show npm-install.receipt.json --summary --format json
cmdtrail diff first.receipt.json second.receipt.json --format json
```

`record` exits zero when a valid receipt was written, even if the observed
command failed. Always inspect `command_success`, `command_state`, and
`command.outcome.exit_code`.

## Observation roots and bounds

Without `--root`, CmdTrail observes the command working directory. Repeat
`--root` for multiple non-overlapping directories. Relative roots are resolved
against `--cwd`. Root order is semantic for `diff`; preserve it when comparing
equivalent runs in different directories.

```bash
cmdtrail record \
  --out build.receipt.json \
  --cwd ./project \
  --root src \
  --root generated \
  --max-entries 100000 \
  --max-events 20000 \
  --max-file-hash-bytes 1048576 \
  --max-total-hash-bytes 67108864 \
  -- cargo build
```

The default backend:

- does not follow directory symlinks;
- records symlink-target digests, not target text;
- hashes regular files up to 1 MiB each and 64 MiB per snapshot;
- skips content digests for sensitive-looking paths;
- stops at the entry limit and marks omitted counts unknown;
- counts exact dropped file events when the event limit is reached;
- records traversal and read failures by safe error class.

Content digests detect same-size changes but can read sensitive data and affect
access times. Set the hash limits to zero for metadata-only observation:

```bash
cmdtrail record \
  --out metadata-only.receipt.json \
  --max-file-hash-bytes 0 \
  --max-total-hash-bytes 0 \
  -- command arg
```

## Privacy defaults

CmdTrail does not persist environment values, stdout, stderr, file contents, or
network payloads.

It redacts common secret-bearing flags, URL user information and queries,
non-UTF-8 argument displays, and sensitive path components such as `.env`,
private keys, credentials, and password files. Provide exact additional secret
values through named environment variables:

```bash
export BUILD_SECRET='value-not-for-the-receipt'
cmdtrail record \
  --redact-env BUILD_SECRET \
  --out build.receipt.json \
  -- tool --custom-argument "$BUILD_SECRET"
```

The environment variable name is passed on the command line, not its value.
Digests for redacted arguments are omitted. `command_sha256` binds only the
redacted command representation.

Redaction is pattern-based and cannot identify arbitrary positional secrets.
Opaque path and executable SHA-256 handles can also be susceptible to dictionary
guessing. Treat receipts as sensitive operational metadata and review
[the safety model](docs/safety-model.md) before sharing them.

## Integrity is not authenticity

`cmdtrail verify` checks:

- strict schema parsing with unknown fields rejected;
- RFC 8785 JSON Canonicalization Scheme serialization;
- each event digest, sequence, and previous-event link;
- the aggregate event-array digest;
- the canonical receipt digest and derived receipt ID.

This detects accidental or malicious modification of an existing receipt. It
does **not** prove who produced the receipt, that the host was trustworthy, or
that unobserved effects did not occur. An attacker who can replace the whole
receipt can create a new internally consistent receipt. Release artifact
attestations authenticate CmdTrail binaries, not runtime receipts.

See [contracts](docs/contracts.md) for the independent verification algorithm.
The repository also publishes a digest-pinned
[v0.1 receipt corpus](tests/fixtures/contracts/README.md) with twelve declared
fail-closed mutations and a standard-library-only independent verifier.

Performance observations use deterministic 1k-file, 10k-file, and 100k-entry
trees. The [benchmark methodology](benchmarks/README.md) documents snapshot
boundaries, raw measurements, integrity checks, and the distinction between the
current baseline and future v1.0 regression thresholds.

## Commands

| Command | Purpose |
| --- | --- |
| `record` | Run one direct command and create a new receipt |
| `show` | Return a complete verified receipt or compact `--summary` |
| `diff` | Compare retained effects in two verified receipts |
| `verify` | Verify schema, receipt digest, event digest, and event chain |
| `schema` | Describe stable receipt fields, enums, and integrity rules |
| `capabilities` | Declare backend coverage and safety defaults |
| `contract` | Describe commands, streams, exit codes, and child-failure semantics |
| `completions` | Generate Bash, Zsh, Fish, PowerShell, or Elvish completion |

All data commands emit one JSON document to stdout. Runtime errors emit one
`cmdtrail.error.v1` JSON document to stderr. Clap help and usage errors use
exit code 2.

## Installation

Download the native archive for Linux x86_64, macOS Apple Silicon or Intel, or
Windows x86_64 from
[GitHub Releases](https://github.com/yhay81/cmdtrail/releases).

See [INSTALL.md](INSTALL.md) for platform-specific asset selection,
checksum- and provenance-verified installation, updating, and removal.

Every release contains:

- the native binary, documentation, completions, and machine contract;
- `SHA256SUMS`;
- a CycloneDX 1.5 SBOM;
- GitHub artifact attestations for build provenance and the SBOM.

Verify an archive:

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify \
  cmdtrail-v0.3.0-macos-aarch64.tar.gz \
  --repo yhay81/cmdtrail
```

Build from source with the declared Rust 1.85 MSRV:

```bash
git clone https://github.com/yhay81/cmdtrail.git
cd cmdtrail
cargo build --release --locked
```

## Development and project health

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo audit
cargo package --locked --allow-dirty
```

The same behavior suite runs on Linux, macOS, and Windows. The protected `main`
branch requires formatting, lint, audit, MSRV, package, contract, and all three
platform test jobs.

- [Concept and evidence model](CONCEPT.md)
- [Safety and threat model](docs/safety-model.md)
- [Machine contracts](docs/contracts.md)
- [Roadmap and v1.0 gates](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)
- [Adopters and feedback](ADOPTERS.md)

## License

[MIT](LICENSE)
