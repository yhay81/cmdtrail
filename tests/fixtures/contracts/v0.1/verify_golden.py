#!/usr/bin/env python3
"""Independent verifier for the CmdTrail v0.1 golden receipt."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
from typing import Any

PREFIX = b"cmdtrail.integrity.v1\0"
SUPPORTED_SCHEMA = "cmdtrail.receipt.v1"


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key: {key}")
        result[key] = value
    return result


def utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise ValueError("CmdTrail v0.1 receipts do not contain floating-point values")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if isinstance(value, list):
        return b"[" + b",".join(canonicalize(item) for item in value) + b"]"
    if isinstance(value, dict):
        members = []
        for key in sorted(value, key=utf16_sort_key):
            members.append(canonicalize(key) + b":" + canonicalize(value[key]))
        return b"{" + b",".join(members) + b"}"
    raise ValueError(f"unsupported JSON value: {type(value).__name__}")


def domain_hash(domain: str, value: Any) -> str:
    encoded = canonicalize(value)
    material = (
        PREFIX
        + domain.encode("utf-8")
        + b"\0"
        + len(encoded).to_bytes(8, "big")
        + encoded
    )
    return hashlib.sha256(material).hexdigest()


def object_with_keys(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise ValueError(f"{context} fields differ: missing={missing}, unknown={unknown}")
    return value


def require_string(value: Any, context: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")


def require_bool(value: Any, context: str) -> None:
    if type(value) is not bool:
        raise ValueError(f"{context} must be a boolean")


def require_uint(value: Any, maximum: int, context: str) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{context} must be an unsigned integer up to {maximum}")


def require_optional_string(value: Any, context: str) -> None:
    if value is not None:
        require_string(value, context)


def require_optional_i32(value: Any, context: str) -> None:
    if value is not None and (
        type(value) is not int or not -(2**31) <= value < 2**31
    ):
        raise ValueError(f"{context} must be null or a signed 32-bit integer")


def validate_outcome(value: Any, context: str) -> None:
    outcome = object_with_keys(
        value,
        {"state", "exit_code", "signal", "success", "spawn_error_kind"},
        context,
    )
    require_string(outcome["state"], f"{context}.state")
    if outcome["state"] not in {
        "exited",
        "signaled",
        "timed_out",
        "interrupted",
        "spawn_failed",
        "observer_failed",
    }:
        raise ValueError(f"{context}.state is unsupported")
    require_optional_i32(outcome["exit_code"], f"{context}.exit_code")
    require_optional_i32(outcome["signal"], f"{context}.signal")
    require_bool(outcome["success"], f"{context}.success")
    require_optional_string(outcome["spawn_error_kind"], f"{context}.spawn_error_kind")


def validate_snapshot(value: Any, context: str) -> None:
    snapshot = object_with_keys(
        value,
        {
            "retained_entries",
            "scanned_entries",
            "hashed_files",
            "hashed_bytes",
            "skipped_hashes",
            "traversal_errors",
            "error_classes",
            "truncated",
            "omitted_count_known",
        },
        context,
    )
    for key in {
        "retained_entries",
        "scanned_entries",
        "hashed_files",
        "hashed_bytes",
        "skipped_hashes",
        "traversal_errors",
    }:
        require_uint(snapshot[key], 2**64 - 1, f"{context}.{key}")
    errors = snapshot["error_classes"]
    if not isinstance(errors, dict):
        raise ValueError(f"{context}.error_classes must be an object")
    for key, count in errors.items():
        require_string(key, f"{context}.error_classes key")
        require_uint(count, 2**64 - 1, f"{context}.error_classes.{key}")
    require_bool(snapshot["truncated"], f"{context}.truncated")
    require_bool(snapshot["omitted_count_known"], f"{context}.omitted_count_known")


def validate_entry(value: Any, context: str) -> None:
    entry = object_with_keys(
        value,
        {
            "kind",
            "size_bytes",
            "modified_at_unix_ns",
            "readonly",
            "unix_mode",
            "content_sha256",
            "content_hash_state",
            "symlink_target_sha256",
        },
        context,
    )
    require_string(entry["kind"], f"{context}.kind")
    if entry["kind"] not in {"file", "directory", "symlink", "other"}:
        raise ValueError(f"{context}.kind is unsupported")
    require_optional_string(entry["size_bytes"], f"{context}.size_bytes")
    require_optional_string(
        entry["modified_at_unix_ns"], f"{context}.modified_at_unix_ns"
    )
    require_bool(entry["readonly"], f"{context}.readonly")
    if entry["unix_mode"] is not None:
        require_uint(entry["unix_mode"], 2**32 - 1, f"{context}.unix_mode")
    require_optional_string(entry["content_sha256"], f"{context}.content_sha256")
    require_string(entry["content_hash_state"], f"{context}.content_hash_state")
    if entry["content_hash_state"] not in {
        "hashed",
        "not_regular_file",
        "skipped_sensitive_path",
        "skipped_file_too_large",
        "skipped_total_budget",
        "read_error",
        "changed_during_read",
    }:
        raise ValueError(f"{context}.content_hash_state is unsupported")
    require_optional_string(
        entry["symlink_target_sha256"], f"{context}.symlink_target_sha256"
    )


def validate_event(value: Any, index: int) -> None:
    context = f"events[{index}]"
    event = object_with_keys(
        value,
        {
            "sequence",
            "observed_at_unix_ms",
            "previous_event_sha256",
            "event",
            "event_sha256",
        },
        context,
    )
    require_uint(event["sequence"], 2**64 - 1, f"{context}.sequence")
    require_uint(
        event["observed_at_unix_ms"], 2**64 - 1, f"{context}.observed_at_unix_ms"
    )
    require_optional_string(
        event["previous_event_sha256"], f"{context}.previous_event_sha256"
    )
    require_string(event["event_sha256"], f"{context}.event_sha256")
    data = object_with_keys(event["event"], {"type", "details"}, f"{context}.event")
    require_string(data["type"], f"{context}.event.type")
    details_context = f"{context}.event.details"
    if data["type"] == "command_requested":
        details = object_with_keys(
            data["details"],
            {"executable_sha256", "command_sha256"},
            details_context,
        )
        require_string(details["executable_sha256"], f"{details_context}.executable_sha256")
        require_string(details["command_sha256"], f"{details_context}.command_sha256")
    elif data["type"] == "command_finished":
        validate_outcome(data["details"], details_context)
    elif data["type"] == "file_effect":
        details = object_with_keys(
            data["details"],
            {
                "root_id",
                "path_handle",
                "display_path",
                "effect",
                "before",
                "after",
            },
            details_context,
        )
        for key in {"root_id", "path_handle", "display_path", "effect"}:
            require_string(details[key], f"{details_context}.{key}")
        if details["effect"] not in {"created", "modified", "deleted", "type_changed"}:
            raise ValueError(f"{details_context}.effect is unsupported")
        if details["before"] is not None:
            validate_entry(details["before"], f"{details_context}.before")
        if details["after"] is not None:
            validate_entry(details["after"], f"{details_context}.after")
    else:
        raise ValueError(f"{context}.event.type is unsupported")


def validate_receipt(value: Any) -> dict[str, Any]:
    receipt = object_with_keys(
        value,
        {
            "schema_version",
            "tool_version",
            "receipt_id",
            "receipt_sha256",
            "platform",
            "command",
            "observation",
            "capabilities",
            "limits",
            "roots",
            "events",
            "events_sha256",
            "event_chain_head_sha256",
            "summary",
            "redaction",
        },
        "receipt",
    )
    for key in {
        "schema_version",
        "tool_version",
        "receipt_id",
        "receipt_sha256",
        "events_sha256",
        "event_chain_head_sha256",
    }:
        require_string(receipt[key], f"receipt.{key}")

    platform = object_with_keys(
        receipt["platform"], {"os", "architecture", "family"}, "receipt.platform"
    )
    for key in platform:
        require_string(platform[key], f"receipt.platform.{key}")

    command = object_with_keys(
        receipt["command"],
        {
            "executable_display",
            "executable_sha256",
            "argument_displays",
            "argument_sha256",
            "command_sha256",
            "environment_captured",
            "outcome",
        },
        "receipt.command",
    )
    for key in {"executable_display", "executable_sha256", "command_sha256"}:
        require_string(command[key], f"receipt.command.{key}")
    if not isinstance(command["argument_displays"], list):
        raise ValueError("receipt.command.argument_displays must be an array")
    for index, item in enumerate(command["argument_displays"]):
        require_string(item, f"receipt.command.argument_displays[{index}]")
    if not isinstance(command["argument_sha256"], list):
        raise ValueError("receipt.command.argument_sha256 must be an array")
    for index, item in enumerate(command["argument_sha256"]):
        require_optional_string(item, f"receipt.command.argument_sha256[{index}]")
    require_bool(command["environment_captured"], "receipt.command.environment_captured")
    validate_outcome(command["outcome"], "receipt.command.outcome")

    observation = object_with_keys(
        receipt["observation"],
        {
            "backend",
            "started_at_unix_ms",
            "finished_at_unix_ms",
            "duration_ms",
            "working_directory_handle",
            "working_directory_display",
            "coverage",
            "known_blind_spots",
        },
        "receipt.observation",
    )
    for key in {"backend", "working_directory_handle", "working_directory_display"}:
        require_string(observation[key], f"receipt.observation.{key}")
    for key in {"started_at_unix_ms", "finished_at_unix_ms", "duration_ms"}:
        require_uint(observation[key], 2**64 - 1, f"receipt.observation.{key}")
    require_string(observation["coverage"], "receipt.observation.coverage")
    if observation["coverage"] not in {"full", "partial", "unavailable", "unknown"}:
        raise ValueError("receipt.observation.coverage is unsupported")
    if not isinstance(observation["known_blind_spots"], list):
        raise ValueError("receipt.observation.known_blind_spots must be an array")
    for index, item in enumerate(observation["known_blind_spots"]):
        require_string(item, f"receipt.observation.known_blind_spots[{index}]")

    if not isinstance(receipt["capabilities"], list):
        raise ValueError("receipt.capabilities must be an array")
    for index, value in enumerate(receipt["capabilities"]):
        context = f"receipt.capabilities[{index}]"
        capability = object_with_keys(
            value, {"name", "level", "backend", "reason"}, context
        )
        for key in capability:
            require_string(capability[key], f"{context}.{key}")
        if capability["level"] not in {"full", "partial", "unavailable", "unknown"}:
            raise ValueError(f"{context}.level is unsupported")

    limits = object_with_keys(
        receipt["limits"],
        {
            "max_entries_per_snapshot",
            "max_events",
            "max_file_hash_bytes",
            "max_total_hash_bytes_per_snapshot",
            "command_timeout_ms",
        },
        "receipt.limits",
    )
    for key in {
        "max_entries_per_snapshot",
        "max_events",
        "max_file_hash_bytes",
        "max_total_hash_bytes_per_snapshot",
    }:
        require_uint(limits[key], 2**64 - 1, f"receipt.limits.{key}")
    if limits["command_timeout_ms"] is not None:
        require_uint(
            limits["command_timeout_ms"],
            2**64 - 1,
            "receipt.limits.command_timeout_ms",
        )

    if not isinstance(receipt["roots"], list):
        raise ValueError("receipt.roots must be an array")
    for index, value in enumerate(receipt["roots"]):
        context = f"receipt.roots[{index}]"
        root = object_with_keys(
            value,
            {"root_id", "path_handle", "display_name", "before", "after"},
            context,
        )
        for key in {"root_id", "path_handle", "display_name"}:
            require_string(root[key], f"{context}.{key}")
        validate_snapshot(root["before"], f"{context}.before")
        validate_snapshot(root["after"], f"{context}.after")

    if not isinstance(receipt["events"], list):
        raise ValueError("receipt.events must be an array")
    for index, event in enumerate(receipt["events"]):
        validate_event(event, index)

    summary = object_with_keys(
        receipt["summary"],
        {
            "command_state",
            "command_success",
            "file_effect_counts",
            "retained_file_effects",
            "dropped_file_effects",
            "snapshot_truncated",
            "traversal_errors",
            "observation_complete",
        },
        "receipt.summary",
    )
    require_string(summary["command_state"], "receipt.summary.command_state")
    if summary["command_state"] not in {
        "exited",
        "signaled",
        "timed_out",
        "interrupted",
        "spawn_failed",
        "observer_failed",
    }:
        raise ValueError("receipt.summary.command_state is unsupported")
    require_bool(summary["command_success"], "receipt.summary.command_success")
    counts = summary["file_effect_counts"]
    if not isinstance(counts, dict):
        raise ValueError("receipt.summary.file_effect_counts must be an object")
    for key, count in counts.items():
        require_string(key, "receipt.summary.file_effect_counts key")
        require_uint(count, 2**64 - 1, f"receipt.summary.file_effect_counts.{key}")
    for key in {"retained_file_effects", "dropped_file_effects", "traversal_errors"}:
        require_uint(summary[key], 2**64 - 1, f"receipt.summary.{key}")
    for key in {"snapshot_truncated", "observation_complete"}:
        require_bool(summary[key], f"receipt.summary.{key}")

    redaction = object_with_keys(
        receipt["redaction"],
        {
            "mode",
            "environment_values_captured",
            "custom_secret_values_loaded",
            "redacted_arguments",
            "redacted_path_components",
            "sensitive_file_hashes_skipped",
            "limitations",
        },
        "receipt.redaction",
    )
    require_string(redaction["mode"], "receipt.redaction.mode")
    require_bool(
        redaction["environment_values_captured"],
        "receipt.redaction.environment_values_captured",
    )
    for key in {
        "custom_secret_values_loaded",
        "redacted_arguments",
        "redacted_path_components",
        "sensitive_file_hashes_skipped",
    }:
        require_uint(redaction[key], 2**64 - 1, f"receipt.redaction.{key}")
    if not isinstance(redaction["limitations"], list):
        raise ValueError("receipt.redaction.limitations must be an array")
    for index, item in enumerate(redaction["limitations"]):
        require_string(item, f"receipt.redaction.limitations[{index}]")
    return receipt


def verify(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if receipt.get("schema_version") != SUPPORTED_SCHEMA:
        errors.append("unsupported_schema")

    events = receipt.get("events")
    if not isinstance(events, list):
        return errors + ["events_not_array"]
    if receipt.get("events_sha256") != domain_hash("events", events):
        errors.append("events_digest_mismatch")

    previous = None
    event_chain_valid = True
    for index, event in enumerate(events):
        if event.get("sequence") != index:
            event_chain_valid = False
        if event.get("previous_event_sha256") != previous:
            event_chain_valid = False
        material = copy.deepcopy(event)
        material["event_sha256"] = ""
        expected = domain_hash("event", material)
        if event.get("event_sha256") != expected:
            event_chain_valid = False
        previous = event.get("event_sha256")

    if receipt.get("event_chain_head_sha256") != (previous or ""):
        event_chain_valid = False
    if not event_chain_valid:
        errors.append("event_chain_invalid")

    material = copy.deepcopy(receipt)
    material["receipt_id"] = ""
    material["receipt_sha256"] = ""
    digest = domain_hash("receipt", material)
    if receipt.get("receipt_sha256") != digest:
        errors.append("receipt_digest_mismatch")
    if receipt.get("receipt_id") != f"ct_{digest[:24]}":
        errors.append("receipt_id_mismatch")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_golden.py RECEIPT", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    try:
        receipt = validate_receipt(
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=reject_duplicate_keys,
            )
        )
        errors = verify(receipt)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"invalid receipt: {error}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"verified {receipt['receipt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
