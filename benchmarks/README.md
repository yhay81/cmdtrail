# CmdTrail performance baseline

This directory defines and enforces CmdTrail's reproducible v1.0 performance
thresholds on pull requests and in the weekly scheduled benchmark.

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

Each sample performs untimed build and tree generation. The workflow discards
one warm-up and captures 20 samples across the three sizes. It records GNU
`time` wall time and peak resident memory, CmdTrail's internal duration and
snapshot statistics, output and receipt bytes, fixture content digests,
offline receipt verification, runner identity, and the exact CmdTrail commit.

## Enforced thresholds

The versioned policy in `thresholds.json` enforces:

- the complete portable 10,000-file snapshot below 2 seconds p95;
- peak RSS no greater than 256 MiB in every 1k, 10k, and 100k sample.

Twenty samples make nearest-rank p95 the second-slowest observation. Once
`baseline-ubuntu24.json` is present, metrics must also remain within the
stricter of the absolute limit and the versioned noise allowance: 1.5 times
baseline or baseline plus 100 ms for time and 16 MiB for memory.

## Run

The supported measurement environment is the `ubuntu-24.04` x86_64
GitHub-hosted runner selected by `.github/workflows/benchmark.yml`. Run one raw
sample on a compatible Linux machine with:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

Run evaluator tests with:

```bash
python3 -m unittest benchmarks/test_evaluate.py
```

GNU `time`, GNU `stat`, `timeout`, `/usr/bin/true`, `jq`, Python 3, Git, Cargo,
and the locked Rust dependency graph are required. Build and tree-generation
time are excluded. Generated trees and receipts are temporary and are not
uploaded.

The workflow uploads all 20 raw samples and the aggregate evaluation for 90
days, including raw samples from a failed threshold evaluation. The checked-in
baseline is refreshed only from a successful protected-runner evaluation.
