# CmdTrail concept

## One-line thesis

CmdTrail records a bounded, capability-declared, integrity-verifiable receipt
of command effects that its selected observation backend can actually see.

## Problem

Agents frequently run installers, build scripts, generators, and unfamiliar
tools. Exit status and terminal output do not answer:

- which persistent files were created, changed, or deleted;
- whether a command timed out, was interrupted, or failed to spawn;
- which effects the observation mechanism could not see;
- whether a saved account of those effects was modified later.

Platform tracers can expose raw events, but they are operating-system-specific,
privilege-sensitive, verbose, and easy to overclaim. A safe agent contract must
distinguish observed facts from both inference and unavailable evidence.

## Target users and jobs

- Coding agents checking a generator, installer, or build command.
- Maintainers comparing command behavior across versions.
- Sandbox and policy authors collecting evidence before enforcing policy.
- Reproducible-build and supply-chain tools consuming stable JSON.

The primary job is:

> Run one direct command under declared observation capabilities and return a
> compact, bounded receipt of retained effects, drops, errors, and blind spots.

## Product principles

1. Coverage claims are explicit and machine-readable.
2. Unavailable evidence is never converted into a negative fact.
3. Raw observations remain distinct from summarized effects.
4. Limits, drops, races, and read failures are first-class receipt fields.
5. Shell interpretation occurs only when the caller explicitly invokes a shell.
6. Payloads, environment values, and file contents are not persisted.
7. Secret-bearing displays are redacted before normal output.
8. Receipt integrity is distinct from producer authenticity and observation
   completeness.
9. Observation is separate from prevention.

## v0.1 backend

The first release deliberately starts with a portable pre/post snapshot backend
instead of a Linux-only kernel tracer. This provides one honest contract on
Linux, macOS, and Windows while native backends are calibrated.

The backend:

- resolves one or more non-overlapping directory roots;
- takes bounded, deterministic, non-symlink-following snapshots;
- records metadata and bounded regular-file content digests;
- starts one direct child without an implicit shell;
- streams child output without persisting it;
- captures direct-child spawn, exit, signal, timeout, or interruption state;
- takes a second bounded snapshot;
- emits created, modified, deleted, and type-changed file effects;
- seals events and receipt metadata with RFC 8785 JCS and SHA-256.

It cannot see transient file operations whose final state matches the initial
state. It does not attribute a delta to a process and does not observe
descendant process trees, network activity, ports, resource totals, or detached
descendant effects.

## Command contract

```text
cmdtrail schema --brief --format json
cmdtrail capabilities --format json
cmdtrail contract --format json
cmdtrail record --out receipt.json --root . -- npm install
cmdtrail show receipt.json --summary --format json
cmdtrail diff before.json after.json --format json
cmdtrail verify receipt.json --format json
```

The `--` separator is mandatory. The remaining argument vector is passed
directly to the operating system. A caller that wants shell behavior can
explicitly run `sh -c`, `cmd /C`, or another shell.

Data commands reserve stdout for one JSON document. The observed command's
stdout and stderr are streamed to CmdTrail's stderr and are not stored.

Receipt creation success is separate from observed-command success. A receipt
with a failed child is still a successfully recorded fact, so `record` exits
zero after writing it and callers inspect `command.outcome`.

## Capability model

Each capability is `full`, `partial`, `unavailable`, or `unknown`, with a
backend and reason. The v0.1 portable backend declares:

- direct process lifecycle: `full`;
- persistent filesystem delta under declared roots: `partial`;
- descendant process tree: `unavailable`;
- network connections and listening ports: `unavailable`;
- resource totals: `unavailable`;
- delayed descendant effects: `unavailable`;
- payload capture: `unavailable` by privacy policy.

Dynamic changes such as scan truncation, traversal errors, and event drops are
recorded in addition to the static capability declaration.

## Event and receipt model

The retained event stream contains:

- `command_requested`;
- `command_finished`;
- `file_effect`.

File effects use opaque root and path handles plus a redacted relative display.
They contain before/after typed state for retained file facts. Repeated raw
filesystem operations are not inferred from a single final-state delta.

A receipt includes:

- schema and tool versions;
- derived receipt ID and full receipt digest;
- operating system and architecture;
- redacted command displays and omitted secret digests;
- direct-child outcome;
- observation time envelope, backend, and working-directory handle;
- effective capabilities and known blind spots;
- configured limits and per-root scan statistics;
- bounded hash-chained events;
- summary counts, drops, errors, and incompleteness;
- redaction actions and limitations.

Verification re-parses a strict typed receipt, canonicalizes it with RFC 8785,
and checks the event chain, event-array digest, receipt digest, and derived ID.
It does not authenticate the producer. Optional runtime receipt signing is a
v1.0 candidate.

## Threat boundaries

CmdTrail assumes the local operating system, CmdTrail process, selected binary,
and receipt output path are not already controlled by an attacker with equal or
greater privileges. A hostile command running as the same user can race
snapshot reads, mutate paths after observation, tamper with the host, or create
a separate forged receipt.

The snapshot backend minimizes claims in that environment. It is evidence
collection, not containment.

## Non-goals

- A sandbox, firewall, or policy enforcement engine.
- Malware detection or semantic intent classification.
- Employee monitoring or remote telemetry.
- Capturing stdout, stderr, environment values, network payloads, keystrokes,
  or complete file contents.
- Claiming that unobserved effects did not happen.
- Replacing dependency locks, build manifests, or platform-native tracers.

## Differentiation

CmdTrail's value is not another raw trace format. It is a stable agent-facing
evidence envelope that:

- calibrates every coverage claim;
- preserves limit and error evidence;
- separates observable facts from inference;
- defaults to bounded storage and privacy-aware displays;
- provides offline semantic integrity verification;
- permits portable and native backends to share one contract.

## Measures

The project tracks:

- recall and precision against controlled fixtures for each supported backend;
- declaration accuracy for unsupported and degraded capabilities;
- dropped-event and traversal-error accounting;
- runtime, CPU, memory, and storage overhead;
- supported-pattern secret-redaction escape rate;
- integrity mutation rejection rate;
- agent task success and review-token reduction;
- repeat adoption and external feedback.

Quantified v1.0 gates are defined in [ROADMAP.md](ROADMAP.md).
