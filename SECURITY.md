# Security policy

## Supported versions

Until v1.0, only the latest minor release receives security fixes.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Older | No |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for
[`yhay81/cmdtrail`](https://github.com/yhay81/cmdtrail/security/advisories/new).
Do not open a public issue for an unpatched vulnerability.

Include, when possible:

- affected CmdTrail version and operating system;
- observation roots, limits, and backend;
- minimal reproduction without real secrets;
- impact on confidentiality, integrity, availability, or coverage claims;
- whether a hostile observed command is required;
- suggested remediation or fixture.

Expect acknowledgement within 3 business days and an initial assessment within
7 business days. Coordinated disclosure timing will reflect exploitability,
release availability, and downstream risk.

## Important boundaries

CmdTrail is not a sandbox. It runs the requested command with the caller's user,
environment, filesystem, and network authority.

Receipt integrity is not authenticity. A valid receipt proves internal semantic
consistency under CmdTrail's RFC 8785 and SHA-256 rules; it does not prove who
created it or that the host and recorder were trustworthy.

The portable backend cannot observe transient file effects, descendants,
network activity, ports, resource totals, or delayed detached work. Missing
coverage must not be interpreted as proof that an effect did not occur.

See [the full safety model](docs/safety-model.md).
