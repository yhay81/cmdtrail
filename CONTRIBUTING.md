# Contributing

Contributions that improve declaration accuracy, fixture coverage, privacy,
portability, verification, or documentation are welcome.

## Before opening a change

For behavior or schema changes, open an issue describing:

- the observable user problem;
- affected backend and operating systems;
- proposed capability level and blind spots;
- limits, privacy impact, and failure behavior;
- a fixture that can prove the claim.

Small documentation and test corrections can go directly to a pull request.

## Local setup

CmdTrail declares Rust 1.85 as its minimum supported Rust version.

```bash
git clone https://github.com/yhay81/cmdtrail.git
cd cmdtrail
cargo test --all-targets --locked
```

Before submitting:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo +1.85.0 check --all-targets --locked
cargo audit
cargo package --locked --allow-dirty
```

## Evidence requirements

- New observation claims need a deterministic fixture and explicit degraded
  cases.
- Schema changes need golden compatibility tests and contract documentation.
- Redaction changes need both positive and negative tests without real secrets.
- Limit behavior must record drops or unknown omission counts.
- Platform-specific behavior must compile and run in its CI job.
- Avoid tests that assume an implicit shell.

Do not weaken a capability declaration merely to hide a failing fixture. If a
claim is not supported, lower the declared level and explain why.

## Pull requests

Keep pull requests focused. Include:

- problem and intended outcome;
- non-goals;
- capability or schema impact;
- privacy and security impact;
- commands run and platforms covered;
- documentation and changelog changes when user-visible.

All commits merged to `main` must be signed. The project uses squash merging,
so the final repository commit is created and signed through the protected
workflow.

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
