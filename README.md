# CmdTrail

Structured receipts for the observable side effects of a command.

> Status: research concept. System-wide tracing has platform-specific limits and the first release will not claim complete observation.

CmdTrail runs or attaches to a command and records observable file, process, network, port, and resource effects in one bounded event model.

```bash
cmdtrail record -- npm install
cmdtrail show rcpt_01J... --fields files,processes,network
cmdtrail diff rcpt_01J... rcpt_01K...
cmdtrail verify rcpt_01J...
```

## Why

An exit code and stdout do not explain what a command changed. Agents need a durable answer to “what actually happened?” without parsing platform-specific traces or trusting the command's own summary.

## Product principles

- Observed fact is distinct from inferred meaning.
- Completeness claims are explicit per platform and capability.
- Secrets and payloads are redacted by default.
- Event volume is bounded and summarized without discarding raw handles.
- Receipts are hash-addressed and independently verifiable.
- Observation comes before policy enforcement.

## Initial scope

Linux first: process trees, filesystem changes, network endpoints, listening ports, exit state, duration, and resource totals. macOS and Windows follow with explicitly different capability matrices.

See [CONCEPT.md](CONCEPT.md) for the evidence model, threat boundaries, and MVP.

## License

MIT
