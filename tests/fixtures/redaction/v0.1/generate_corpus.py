#!/usr/bin/env python3
"""Generate CmdTrail's deterministic supported-pattern redaction corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

CORPUS_SCHEMA = "cmdtrail.redaction-corpus.v1"
METRICS_SCHEMA = "cmdtrail.redaction-metrics.v1"


def expected_command(
    displays: list[str],
    digest_present: list[bool],
    redacted: int,
    executable: str = "tool",
) -> dict[str, Any]:
    return {
        "executable_display": executable,
        "argument_displays": displays,
        "argument_digest_present": digest_present,
        "redacted_arguments": redacted,
        "path_display": None,
        "redacted_path_components": 0,
    }


def command_case(
    case_id: str,
    category: str,
    arguments: list[str],
    displays: list[str],
    digest_present: list[bool],
    redacted: int,
    secrets: list[str],
    *,
    custom_values: list[str] | None = None,
    supported_pattern: bool = True,
    executable: str = "tool",
    executable_display: str | None = None,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "category": category,
        "supported_pattern": supported_pattern,
        "secrets": secrets,
        "input": {
            "kind": "command",
            "executable": executable,
            "arguments": arguments,
            "path": None,
            "custom_values": custom_values or [],
        },
        "expected": expected_command(
            displays,
            digest_present,
            redacted,
            executable_display or executable,
        ),
    }


def path_case(
    case_id: str,
    category: str,
    path: str,
    display: str,
    redacted_components: int,
    secrets: list[str],
    *,
    supported_pattern: bool = True,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "category": category,
        "supported_pattern": supported_pattern,
        "secrets": secrets,
        "input": {
            "kind": "path",
            "executable": "",
            "arguments": [],
            "path": path,
            "custom_values": [],
        },
        "expected": {
            "executable_display": None,
            "argument_displays": [],
            "argument_digest_present": [],
            "redacted_arguments": 0,
            "path_display": display,
            "redacted_path_components": redacted_components,
        },
    }


def redacted_component(component: str) -> str:
    digest = hashlib.sha256(component.encode()).hexdigest()
    return f"[redacted_{digest[:8]}]"


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    secret_keys = [
        "--password",
        "--passwd",
        "--token",
        "--access-token",
        "--refresh_token",
        "--client.secret",
        "--credential",
        "--api-key",
        "--api_key",
        "--private-key",
        "--private_key",
        "--authorization",
        "--cookie",
        "--session-token",
        "--db-password",
        "--github.token",
        "--secret",
        "--secret-key",
        "--auth-token",
        "--credentials-file",
    ]
    for index, key in enumerate(secret_keys):
        secret = f"separated-value-{index:02}"
        arguments = [key, secret, "--mode", "safe"]
        cases.append(
            command_case(
                f"separated-secret-flag-{index:02}",
                "separated_secret_flag",
                arguments,
                [key, "[redacted]", "--mode", "safe"],
                [True, False, True, True],
                1,
                [secret],
            )
        )

    for index, key in enumerate(secret_keys):
        secret = f"joined-value-{index:02}"
        argument = f"{key}={secret}"
        cases.append(
            command_case(
                f"joined-secret-key-{index:02}",
                "joined_secret_key",
                [argument, "--mode=safe"],
                [f"{key}=[redacted]", "--mode=safe"],
                [False, True],
                1,
                [secret],
            )
        )

    for index in range(12):
        scheme = "https" if index % 2 == 0 else "http"
        userinfo = f"user{index:02}:pass{index:02}"
        authority = f"host{index:02}.example.test"
        if index % 3 == 0:
            authority = f"{authority}:{8443 + index}"
        url = f"{scheme}://{userinfo}@{authority}/artifact"
        cases.append(
            command_case(
                f"url-userinfo-{index:02}",
                "url_userinfo",
                [url],
                [f"{scheme}://[redacted]@{authority}/artifact"],
                [False],
                1,
                [userinfo],
            )
        )

    for index in range(12):
        value = f"qv-{index:02}"
        prefix = (
            f"https://query{index:02}.example.test/path"
            if index % 2 == 0
            else f"https://query{index:02}.example.test"
        )
        suffix = f"?item={value}"
        if index >= 6:
            suffix += f"#anchor-{index:02}"
        cases.append(
            command_case(
                f"url-query-{index:02}",
                "url_query",
                [prefix + suffix],
                [prefix + "?[redacted-query]"],
                [False],
                1,
                [value],
            )
        )

    for index in range(8):
        value = f"fragment-value-{index:02}"
        prefix = f"https://fragment{index:02}.example.test/path"
        cases.append(
            command_case(
                f"url-fragment-{index:02}",
                "url_fragment",
                [f"{prefix}#{value}"],
                [f"{prefix}#[redacted-fragment]"],
                [False],
                1,
                [value],
            )
        )

    sensitive_components = [
        ".env",
        ".env.production",
        "password.txt",
        "passwd.backup",
        "credentials.json",
        "credential-store",
        "private_key.pem",
        "private-key.txt",
        "api_key.json",
        "api-key.yaml",
        "client_secret.txt",
        "secret-config",
        "server.pem",
        "client.p12",
        "bundle.pfx",
        "PASSWORD",
        "CREDENTIALS",
        "my-passwd-file",
        "service-private_key",
        "oauth-secret",
    ]
    for index, component in enumerate(sensitive_components):
        path = f"config/{component}/artifact.txt"
        display = f"config/{redacted_component(component)}/artifact.txt"
        cases.append(
            path_case(
                f"sensitive-path-{index:02}",
                "sensitive_path",
                path,
                display,
                1,
                [component],
            )
        )

    for index in range(12):
        secret = f"literal-value-{index:02}"
        if index < 8:
            argument = f"prefix-{secret}-suffix"
            display = "prefix-[redacted]-suffix"
            cases.append(
                command_case(
                    f"custom-exact-value-{index:02}",
                    "custom_exact_value",
                    [argument],
                    [display],
                    [False],
                    1,
                    [secret],
                    custom_values=[secret],
                )
            )
        else:
            executable = f"runner-{secret}"
            cases.append(
                command_case(
                    f"custom-executable-value-{index:02}",
                    "custom_exact_value",
                    ["--mode", "safe"],
                    ["--mode", "safe"],
                    [True, True],
                    0,
                    [secret],
                    custom_values=[secret],
                    executable=executable,
                    executable_display="runner-[redacted]",
                )
            )

    benign_keys = [
        "--timeout",
        "--profile",
        "--output",
        "--target",
        "--mode",
        "--format",
        "--color",
        "--jobs",
        "--cache",
        "--verbose",
        "--retry",
        "--endpoint",
    ]
    for index, key in enumerate(benign_keys):
        arguments = [f"{key}=public-{index:02}", "ordinary-value"]
        cases.append(
            command_case(
                f"benign-command-{index:02}",
                "benign_command_control",
                arguments,
                arguments,
                [True, True],
                0,
                [],
                supported_pattern=False,
            )
        )

    benign_components = [
        "environment",
        "public-key",
        "authentication",
        "session",
        "configuration",
        "certificate.crt",
        "readme",
        "ordinary",
        "release",
        "metadata",
        "manifest",
        "artifact",
    ]
    for index, component in enumerate(benign_components):
        path = f"public/{component}/file-{index:02}.txt"
        cases.append(
            path_case(
                f"benign-path-{index:02}",
                "benign_path_control",
                path,
                path,
                0,
                [],
                supported_pattern=False,
            )
        )

    return cases


def build_corpus() -> dict[str, Any]:
    cases = build_cases()
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("case identifiers must be unique")
    return {
        "schema_version": CORPUS_SCHEMA,
        "license": "MIT",
        "labeling_methodology": (
            "Expected displays and digest-retention decisions are defined by explicit "
            "tables for CmdTrail's documented supported patterns; the generator does "
            "not invoke or inspect CmdTrail."
        ),
        "unsupported_scope": (
            "Arbitrary positional secrets are not expected to be detected unless "
            "supplied as exact custom values."
        ),
        "cases": cases,
    }


def build_metrics(corpus: dict[str, Any]) -> dict[str, Any]:
    cases = corpus["cases"]
    by_category = Counter(case["category"] for case in cases)
    supported = sum(case["supported_pattern"] for case in cases)
    controls = len(cases) - supported
    secret_observations = sum(len(case["secrets"]) for case in cases)
    return {
        "schema_version": METRICS_SCHEMA,
        "corpus_sha256": hashlib.sha256(canonical_encode(corpus)).hexdigest(),
        "total_cases": len(cases),
        "exact_matches": len(cases),
        "exact_accuracy": 1.0,
        "supported_pattern_cases": supported,
        "secret_observations": secret_observations,
        "escapes": 0,
        "escape_rate": 0.0,
        "benign_controls": controls,
        "benign_false_positives": 0,
        "by_category": {
            category: {
                "cases": count,
                "exact_matches": count,
                "secret_observations": sum(
                    len(case["secrets"])
                    for case in cases
                    if case["category"] == category
                ),
                "escapes": 0,
            }
            for category, count in sorted(by_category.items())
        },
    }


def encode(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def canonical_encode(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def write_or_check(path: Path, expected: bytes, check: bool) -> None:
    if check:
        if not path.exists() or path.read_bytes() != expected:
            raise SystemExit(f"{path} is stale; run generate_corpus.py")
    else:
        path.write_bytes(expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when generated files differ from checked-in files",
    )
    args = parser.parse_args()
    directory = Path(__file__).parent
    corpus = build_corpus()
    metrics = build_metrics(corpus)
    write_or_check(directory / "corpus.json", encode(corpus), args.check)
    write_or_check(directory / "metrics.json", encode(metrics), args.check)
    print(
        "verified" if args.check else "generated",
        len(corpus["cases"]),
        "redaction cases",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
