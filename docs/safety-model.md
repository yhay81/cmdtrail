# Safety and threat model

## What CmdTrail protects

CmdTrail is designed to:

- avoid an implicit shell and argument re-interpretation;
- keep machine-readable stdout separate from observed-command output;
- avoid persisting environment values and output payloads;
- redact supported secret-bearing argument and path patterns;
- bound filesystem entries, file hashing, total hashing, events, receipt input,
  and direct-child execution time;
- prevent accidental receipt overwrite;
- expose truncation, drops, read errors, and unavailable capability classes;
- detect semantic modification of a saved receipt.

## What CmdTrail does not protect

CmdTrail does not restrict the requested command. The command inherits the
caller's identity, environment, filesystem authority, network authority, and
other operating-system permissions.

Do not use CmdTrail as a sandbox, malware detector, endpoint security product,
firewall, transaction system, or proof that no other effects occurred.

## Trust assumptions

The v0.1 model assumes:

- the CmdTrail binary and host are trusted enough to observe honestly;
- the caller selected appropriate roots and limits;
- the receipt destination is controlled after creation;
- the local user account and kernel are not already compromised;
- clocks and filesystem metadata may be inaccurate but are still useful facts.

A same-user hostile child can race snapshot reads, mutate files repeatedly,
delete or replace paths, leave detached descendants, consume resources, or
interfere with receipt creation.

## Snapshot-specific blind spots

Pre/post snapshots do not observe:

- a file created and deleted before the second snapshot;
- writes that restore all retained metadata and content digest;
- which process caused a final-state delta;
- operations outside declared roots;
- descendant process lifecycle;
- network activity, listening ports, or resource totals;
- delayed effects after the direct child exits;
- files omitted by entry bounds;
- contents skipped by sensitivity, size, total budget, race, or read failure.

File content hashing is not an atomic snapshot. A concurrently changing file
can produce a digest of the bytes observed during the read rather than one
stable filesystem instant. Snapshot walking, hashing, and output piping also
perturb timing, metadata access, and scheduling.

Directory symlinks are not followed. Symlink targets are stored only as
digests. An observed command can still change a symlink or its target between
checks, so the receipt describes observations, not an atomic filesystem
transaction.

## Command execution

The literal `--` separator is mandatory. CmdTrail calls the selected executable
directly. Shell syntax has no meaning unless the caller explicitly selects a
shell executable.

The direct child's stdout and stderr are piped and streamed to CmdTrail's
stderr. They are not stored in the receipt. This separation means CmdTrail's
stdout remains one JSON result, but sensitive child output can still reach the
caller's terminal or stderr capture.

On timeout or Ctrl-C, CmdTrail attempts to terminate and reap the direct child.
It does not create a process group or job object in v0.1, so descendants may
survive. An unconfirmed termination is recorded as a blind spot.

`record` exit zero means the receipt was written. It does not mean the observed
command succeeded.

## Receipt output

Receipt files are created with no-overwrite semantics. Unix files use mode
`0600`; Windows uses the caller's inherited ACL. Existing paths, including
symlinks, are refused before execution and checked again at creation. The
filename and parent directory are also validated before command execution.

A power loss or storage error can leave a partial newly created file. Strict
parsing and integrity verification reject it. CmdTrail does not claim a
filesystem transaction across the command and receipt write.

If a write fails after command execution, CmdTrail does not remove the
requested path or repeat the command. It attempts a no-clobber recovery receipt
beside the requested path and returns exit 6 with `do_not_retry_record`, receipt
identity, command state, and recovery status. See
[receipt recovery](receipt-recovery.md). A crash or power loss can prevent this
signal from being emitted.

## Privacy and redaction

CmdTrail stores:

- relative redacted path displays and opaque handles;
- executable basename and opaque executable digest;
- redacted argument displays;
- digests only for arguments not classified as redacted;
- the redacted-command fingerprint;
- metadata and bounded content digests for non-sensitive-looking regular files.

It does not store environment values, stdout, stderr, or file contents.

Redaction handles common secret flags, URL credentials and queries, configured
exact values, non-UTF-8 displays, and sensitive path patterns. It cannot
reliably classify arbitrary positional strings. Users should pass exact
additional secret values using `--redact-env`.

SHA-256 handles and content digests can reveal low-entropy values through
dictionary guessing. Receipts should be treated as sensitive metadata.

## Integrity and authenticity

Receipt integrity uses RFC 8785 JCS, SHA-256 domain separation, an event hash
chain, an aggregate event-array digest, and a canonical receipt digest.

This detects changes to a specific receipt. It does not authenticate the
producer. Anyone who can replace the complete receipt can create a fresh,
internally consistent forgery. Runtime signing, trusted execution, or an
external transparency log is required for stronger provenance and remains
outside v0.1.

GitHub release attestations authenticate distributed CmdTrail archives. They do
not authenticate receipts produced later on user machines.
