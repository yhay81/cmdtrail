# CmdTrail performance baseline

This directory defines the reproducible, observation-only baseline used to
calibrate CmdTrail's v1.0 performance thresholds. Timing and memory are not yet
required pull-request checks.

## Workloads

`generate_tree.py` creates deterministic, shallow directory trees with fixed
names and 18-byte payload files:

- 1,000 files plus 10 directories;
- 10,000 files plus 100 directories;
- 99,000 files plus 1,000 directories, exactly 100,000 snapshot entries.

The last case exercises the default 100,000-entry bound without truncation.
Every measurement captures complete default pre/post hashing around
`/usr/bin/true`; receipts are written outside the observed tree. The generator,
fixtures, and outputs are synthetic project artifacts covered by the
repository's MIT license.

The harness runs the three sizes once, without warm-up, and records GNU `time`
wall time and peak resident memory, CmdTrail's internal duration and snapshot
statistics, output and receipt bytes, fixture content digests, offline receipt
verification, runner identity, and the exact CmdTrail commit.

## Run

The supported measurement environment is the `ubuntu-latest` GitHub-hosted
runner selected by `.github/workflows/benchmark.yml`. Run it manually with the
**Benchmark** workflow, or on a compatible Linux machine:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

GNU `time`, GNU `stat`, `timeout`, `/usr/bin/true`, `jq`, Python 3, Git, Cargo,
and the locked Rust dependency graph are required. Build and tree-generation
time are excluded. Generated trees and receipts are temporary and are not
uploaded.

The workflow retains raw JSON for 90 days. Shared hosted runners are noisy, so
a single run is not a regression. Before enabling v1.0 gates, publish the
runner image, warm-up policy, sample count, p95 calculation, baseline window,
and noise-aware regression rule with the raw measurements.
