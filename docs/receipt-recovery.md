# Receipt recovery after command execution

CmdTrail validates the requested receipt filename, parent directory, and
no-overwrite target before it starts the observed command. Failures detected
by this preflight do not execute the command.

The destination can still change, fill, or become unavailable while the
command runs. A receipt failure at that point is a reconciliation event:
command effects may already exist and repeating `record` could duplicate them.

## Structured recovery signal

After the command observation has been finalized, CmdTrail first attempts the
requested receipt path. If that write fails, it retains every existing path
and attempts to save the same integrity-sealed receipt beside the requested
path as:

```text
.cmdtrail-recovery-<receipt-id>.json
```

Both writes use create-new semantics. CmdTrail never overwrites or deletes the
requested path, a partial receipt, or a recovery path.

The CLI exits with code 6 and emits a final `cmdtrail.error.v1` line containing
either `receipt_recovery_required` or `receipt_recovery_failed`. Its `recovery`
object includes:

- `action: "do_not_retry_record"`;
- the receipt ID and SHA-256;
- the observed direct-command state;
- the requested and recovery receipt paths;
- whether the recovery receipt was persisted;
- stable error codes for the primary and recovery writes.

The observed command's output may precede this JSON on stderr. Consumers should
read the final stderr line when handling exit 6.

## Reconciliation procedure

1. Do not rerun `cmdtrail record`.
2. Preserve the requested path, recovery path, error JSON, and observed
   filesystem state.
3. If `recovery_receipt_persisted` is `true`, run
   `cmdtrail verify <recovery_receipt> --format json`.
4. Confirm the verified receipt's `receipt_id`, `receipt_sha256`, and
   `command.outcome.state` match the error.
5. Inspect the receipt and actual system state before deciding whether any
   command work must be resumed or compensated.
6. If a receipt is needed at the original destination, copy the verified
   recovery receipt with no-overwrite semantics after resolving the conflict.

If recovery persistence also failed, CmdTrail cannot reconstruct the complete
receipt from the compact error. The identifiers still distinguish this from a
pre-execution failure and prohibit blind retry. Investigate storage capacity,
permissions, path races, and filesystem health while preserving the observed
state.

A process crash or power loss can occur before CmdTrail emits this recovery
signal. CmdTrail does not claim a transaction across arbitrary command effects
and receipt persistence.
