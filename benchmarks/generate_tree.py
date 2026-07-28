#!/usr/bin/env python3
"""Generate a deterministic directory tree for CmdTrail benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def update_digest(digest: hashlib._Hash, relative: str, content: bytes) -> None:
    relative_bytes = relative.encode()
    digest.update(len(relative_bytes).to_bytes(8, "little"))
    digest.update(relative_bytes)
    digest.update(len(content).to_bytes(8, "little"))
    digest.update(content)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", required=True, type=positive_integer)
    parser.add_argument("--directories", required=True, type=positive_integer)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if args.directories > args.files:
        parser.error("directories cannot exceed files")
    if args.output.exists():
        parser.error("output must not already exist")

    args.output.mkdir(parents=True)
    directories: list[pathlib.Path] = []
    digest = hashlib.sha256()
    for index in range(args.directories):
        relative = pathlib.Path(f"d{index:06d}")
        directory = args.output / relative
        directory.mkdir()
        directories.append(directory)
        update_digest(digest, f"{relative.as_posix()}/", b"")

    for index in range(args.files):
        directory_index = index % args.directories
        relative = pathlib.Path(f"d{directory_index:06d}") / f"f{index:09d}.txt"
        content = f"fixture-{index:09d}\n".encode()
        (args.output / relative).write_bytes(content)
        update_digest(digest, relative.as_posix(), content)

    print(
        json.dumps(
            {
                "schema_version": "cmdtrail.benchmark-tree.v1",
                "files": args.files,
                "directories": args.directories,
                "entries": args.files + args.directories,
                "content_sha256": digest.hexdigest(),
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
