# Machine contracts

## Stream contract

Data commands emit one compact JSON document plus a newline to stdout.
Completion generation emits a shell script.

`record` streams the observed command's stdout and stderr to CmdTrail's stderr
without persisting them. Runtime errors emit a final `cmdtrail.error.v1` JSON
document to stderr. Consumers that need error JSON isolated from child output
should capture the receipt result from stdout and treat stderr as an
unstructured passthrough channel.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Operation succeeded; for `record`, a receipt was written regardless of child success |
| 1 | Receipt input/output or other I/O failure |
| 2 | Usage or Clap parsing failure |
| 3 | Receipt integrity failure |
| 4 | Configured or receipt-input limit failure |
| 5 | Execution setup failed before a receipt could be written |

Observed command exit state is stored under `command.outcome`; it is not
propagated as CmdTrail's process exit code.

## Receipt schemas

- receipt: `cmdtrail.receipt.v1`
- event array entries: embedded in the receipt
- verification result: `cmdtrail.verification.v1`
- record result: `cmdtrail.record-result.v1`
- show summary: `cmdtrail.show.v1`
- diff result: `cmdtrail.diff.v1`
- capabilities: `cmdtrail.capabilities.v1`
- CLI contract: `cmdtrail.contract.v1`
- schema inventory: `cmdtrail.schema.v1`
- runtime error: `cmdtrail.error.v1`

Unknown fields are rejected when a receipt is read. Enum strings and nested
objects are strict. This prevents a verifier from silently accepting semantics
it does not understand.

Exact file sizes and nanosecond modification timestamps are decimal strings,
not JSON numbers. This avoids precision loss outside the IEEE-754 safe integer
range in independent RFC 8785 implementations.

Observation-root order is semantic. `root_id` is the zero-based configured
position (`root_0000`, `root_0001`, and so on), while `path_handle` binds the
actual canonical root without disclosing it. File path handles bind `root_id`
and relative path bytes, allowing receipts from equivalent roots in different
directories to be compared when callers preserve root order.

## Independent verification

All digests are lowercase hexadecimal SHA-256. Integrity material uses RFC 8785
JSON Canonicalization Scheme bytes.

The domain-separated hash function is:

```text
SHA256(
  "cmdtrail.integrity.v1" ||
  0x00 ||
  UTF8(domain) ||
  0x00 ||
  UINT64_BE(length(JCS(value))) ||
  JCS(value)
)
```

### Event

For each event in array order:

1. `sequence` must equal its zero-based array index.
2. `previous_event_sha256` must be `null` for index zero and the previous
   event's stored digest otherwise.
3. Copy the event and set `event_sha256` to the empty string.
4. Hash it with domain `event`.
5. Compare the result with the stored `event_sha256`.

`event_chain_head_sha256` must equal the final event digest, or the empty string
for an empty event array.

### Event array

Canonicalize the complete stored `events` array, including stored event
digests, and hash it with domain `events`. Compare with `events_sha256`.

### Receipt

1. Strictly parse `cmdtrail.receipt.v1`.
2. Copy the receipt.
3. Set both `receipt_id` and `receipt_sha256` to empty strings.
4. Hash the copy with domain `receipt`.
5. Compare with the stored `receipt_sha256`.
6. Derive `receipt_id` as `ct_` followed by the first 24 hexadecimal
   characters of the receipt digest.

Verification succeeds only when the schema, every event, the chain head, event
array, receipt digest, and derived ID all pass.

## Semantic cautions

Integrity validation does not authenticate the creator and does not raise a
capability level. Consumers must inspect:

- `capabilities`;
- `observation.coverage`;
- `observation.known_blind_spots`;
- per-root before/after statistics;
- `summary.snapshot_truncated`;
- `summary.traversal_errors`;
- `summary.dropped_file_effects`;
- `summary.observation_complete`;
- `command.outcome`.

An absent event is not proof of an absent effect when its capability is not
`full` or any dynamic completeness evidence is degraded.
