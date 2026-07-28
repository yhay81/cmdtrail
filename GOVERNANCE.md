# Governance

CmdTrail currently uses a maintainer-led model.

## Roles

- Contributors propose issues, tests, documentation, and code.
- Reviewers evaluate evidence, portability, privacy, and contract impact.
- Maintainers approve releases, security fixes, capability claims, and
  governance changes.

The current lead maintainer is the repository owner, `@yhay81`.

## Decision principles

1. Observed evidence outranks intended behavior.
2. An honest `partial` or `unavailable` declaration outranks an uncalibrated
   `full` claim.
3. Privacy and bounded operation are release-blocking requirements.
4. Stable machine contracts require migration paths.
5. Decisions and dissent should be recorded in public issues when security or
   privacy does not require confidentiality.

Routine changes are decided in pull-request review. Material schema,
capability, governance, or privacy changes should have an issue and at least
seven days for community comment once the project has external users.

## Releases

Only maintainers may create signed release tags. Releases follow
[RELEASING.md](RELEASING.md), protected branch checks, immutable tags, and an
independent asset audit.

## Continuity

The project currently has a single-maintainer risk. Before v1.0, either a second
release-capable maintainer must be established or the v1.0 release notes must
explicitly retain that risk with a tested repository and signing-key recovery
procedure.
