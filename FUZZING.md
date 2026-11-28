# Fuzzing CmdTrail

CmdTrail fuzzes its untrusted receipt boundary with
AddressSanitizer. The `receipt_integrity` target exercises the production
receipt size bound and typed JSON parser, then verifies aggregate digests,
event sequence, previous-hash links, chain head, receipt digest, and derived
identifier for every document that parses.

To fuzz a pull request locally, check out its branch and run:

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
mkdir -p fuzz/corpus/receipt_integrity
cp tests/fixtures/contracts/v0.1/portable.receipt.json \
  fuzz/corpus/receipt_integrity/
cargo +nightly fuzz run receipt_integrity -- -max_total_time=300
```

The local run spends five minutes fuzzing after compilation. Omit
`-max_total_time=300` for a longer session. Pull requests run the deterministic
receipt compatibility corpus against the current code. The full
AddressSanitizer fuzz run is optional.

## Manual maintenance

Use the same nightly toolchain and seeded corpus above. From the repository
root, run the command for the task you need:

| Task | Local command |
| --- | --- |
| Build the fuzzer | `cargo +nightly fuzz build receipt_integrity` |
| Fuzz for 15 minutes after compilation | `cargo +nightly fuzz run receipt_integrity -- -max_total_time=900` |
| Minimize the local corpus | `cargo +nightly fuzz cmin receipt_integrity` |

To request the GitHub artifact or code-scanning integration, open **Actions**,
select **ClusterFuzzLite comparison build**, **ClusterFuzzLite batch fuzzing**,
or **ClusterFuzzLite corpus pruning**, and choose **Run workflow** on `main`.
These workflows run only on request. The hosted runner has a one-minute job
limit, including setup. Use the local commands for the full run. A local run
keeps its corpus on disk; the GitHub workflows manage Actions artifacts and
the batch workflow can upload SARIF when it completes.

Receipts can contain commands, paths, and observed filesystem metadata. Keep
minimized crashes private until reviewed, add a deterministic regression test,
and use [SECURITY.md](SECURITY.md) for security-relevant findings.
