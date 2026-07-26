# SysReceipt concept

## One-line thesis

SysReceipt records a bounded, capability-declared receipt of the observable
filesystem, process, and network side effects caused by a command.

## Problem

Agents frequently run installers, build scripts, generators, and unfamiliar
tools. Exit status and terminal output do not answer:

- which files were created, changed, renamed, or deleted;
- which child processes ran;
- which hosts were contacted or ports opened;
- which effects occurred after the parent process exited;
- which activity the observation mechanism could not see.

System tracers can expose raw events, but they are platform-specific, verbose,
privilege-sensitive, and difficult for agents to interpret safely.

## Target users and jobs

- Coding agents validating what a command actually changed.
- Maintainers reviewing installer and build behavior.
- Sandbox and policy authors gathering evidence before enforcing rules.
- Reproducible-build and supply-chain tooling.

The primary job is: **run a command under declared observation capabilities and
return a compact receipt of observable effects and blind spots.**

## Product principles

1. Coverage claims are explicit and machine-readable.
2. Raw observations are separate from summarized effects.
3. Missing privileges reduce declared coverage; they do not create false
   completeness.
4. Process trees and delayed effects are tracked where capability permits.
5. Payloads and file contents are not captured by default.
6. Secrets and sensitive paths are redacted before normal output.
7. Observation is separate from prevention.

## Proposed command contract

```text
sysreceipt schema --brief --format json
sysreceipt capabilities --format json
sysreceipt record --out receipt.json -- npm install
sysreceipt show receipt.json --summary --format json
sysreceipt diff before.json after.json --format json
sysreceipt verify receipt.json --format json
```

The `--` separator is mandatory before the recorded argument vector. Shell
interpretation happens only when explicitly requested.

## Capability model

Before recording, SysReceipt reports coverage for:

- process start, exec, exit, and parent relationships;
- filesystem create, write, metadata change, rename, and delete;
- network connect, accept, listen, and resolved endpoint information;
- resource summaries;
- descendant tracking and observation duration.

Each capability is `full`, `partial`, `unavailable`, or `unknown`, with a reason
and observation backend. The receipt repeats the effective capability set.

## Event and effect model

Raw events are normalized into versioned records such as:

- `process.start`, `process.exec`, and `process.exit`;
- `file.create`, `file.write`, `file.rename`, and `file.delete`;
- `network.connect` and `network.listen`;
- `resource.summary`;
- `observer.drop` and `coverage.change`.

A bounded effect summary groups repeated events by process, path, and endpoint.
Complete retained events are content-addressed and referenced by digest.

## Receipt model

A receipt includes:

- source command, working directory, and redacted environment summary;
- operating system, kernel, SysReceipt version, and backend;
- effective user identity and privilege class;
- observation start/end and descendant policy;
- capability matrix and known blind spots;
- process tree and exit outcomes;
- bounded file and network effect summaries;
- dropped-event counts and truncation;
- raw-event and optional snapshot digests;
- canonical receipt digest.

Verification checks receipt integrity. It does not prove that unobserved effects
did not occur.

## Initial scope

Version 0.1 will be Linux-first and will:

- record a local command and descendants;
- capture process, filesystem, and network metadata where supported;
- provide an unprivileged fallback with reduced declared coverage;
- avoid payload and file-content capture by default;
- emit bounded JSON receipts and content-addressed event streams;
- include adversarial fixture programs that test coverage and dropped events.

Backend selection may combine kernel tracing and process-level mechanisms, but
the public schema must not depend on one Linux API.

## Non-goals

- A sandbox, firewall, or policy enforcement engine.
- Malware detection or semantic intent classification.
- Remote telemetry or employee monitoring.
- Capturing network payloads, keystrokes, or complete file contents by default.
- Claiming complete system observation on unsupported kernels or privileges.
- Replacing language-specific dependency or build manifests.

## Differentiation and defensibility

SysReceipt translates noisy operating-system evidence into a stable, honest
agent contract. Its largest moat is technical: cross-backend normalization,
coverage calibration, low-overhead capture, redaction, and a rigorous fixture
suite for completeness claims.

## Success measures

- Event recall and precision against controlled fixture programs.
- Dropped-event rate under load.
- Runtime, CPU, memory, and storage overhead.
- Accuracy of declared capability and blind-spot reporting.
- Secret-redaction escape rate.
- Agent success and token reduction when reviewing command effects.

## Key risks and open questions

- Kernel APIs, privileges, containers, and namespaces change observability.
- A recorder can perturb timing and behavior.
- Complete file-effect attribution is difficult with shared or long-lived
  processes.
- Paths and endpoints can themselves contain sensitive information.
- Cross-platform support may tempt the project to overstate equivalence.

SysReceipt must earn trust through calibrated limitations. A partial receipt
that says exactly what it missed is more useful than an unqualified claim of
completeness.
