# Fuzzing CmdTrail

CmdTrail continuously fuzzes its untrusted receipt boundary with
AddressSanitizer. The `receipt_integrity` target exercises the production
receipt size bound and typed JSON parser, then verifies aggregate digests,
event sequence, previous-hash links, chain head, receipt digest, and derived
identifier for every document that parses.

Install a current nightly toolchain and the pinned local runner, then run:

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
mkdir -p fuzz/corpus/receipt_integrity
cp tests/fixtures/contracts/v0.1/portable.receipt.json \
  fuzz/corpus/receipt_integrity/
cargo +nightly fuzz run receipt_integrity
```

Pull requests receive a five-minute ClusterFuzzLite code-change run. A
15-minute batch run executes weekly on `main`, seeded by the versioned portable
receipt, and publishes machine-readable findings to GitHub code scanning.
Each code-changing `main` update also saves a comparison build so later pull
requests can distinguish newly introduced crashes. The accumulated corpus is
pruned after every weekly batch.

Receipts can contain commands, paths, and observed filesystem metadata. Keep
minimized crashes private until reviewed, add a deterministic regression test,
and use [SECURITY.md](SECURITY.md) for security-relevant findings.
