#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
result_path="${1:-${root_dir}/benchmark-results.json}"
binary="${root_dir}/target/release/cmdtrail"
generator="${root_dir}/benchmarks/generate_tree.py"

for dependency in cargo git jq python3 stat timeout uname; do
  command -v "${dependency}" >/dev/null || {
    printf 'missing benchmark dependency: %s\n' "${dependency}" >&2
    exit 1
  }
done

if ! /usr/bin/time --version 2>&1 | grep -qi 'GNU time'; then
  printf 'benchmarks/run.sh requires GNU /usr/bin/time (the Ubuntu runner provides it)\n' >&2
  exit 1
fi

test -x /usr/bin/true
temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT

tree_1k="${temp_dir}/tree-1k"
tree_10k="${temp_dir}/tree-10k"
tree_100k="${temp_dir}/tree-100k"
fixture_1k="${temp_dir}/tree-1k.json"
fixture_10k="${temp_dir}/tree-10k.json"
fixture_100k="${temp_dir}/tree-100k.json"

cd "${root_dir}"
cargo build --release --locked
python3 "${generator}" \
  --files 1000 --directories 10 --output "${tree_1k}" >"${fixture_1k}"
python3 "${generator}" \
  --files 10000 --directories 100 --output "${tree_10k}" >"${fixture_10k}"
python3 "${generator}" \
  --files 99000 --directories 1000 --output "${tree_100k}" >"${fixture_100k}"

measure_record() {
  local tree="$1"
  local receipt="$2"
  local metrics="$3"
  local output="$4"
  local verification="$5"

  /usr/bin/time \
    -f '{"wall_seconds": %e, "max_rss_kib": %M, "exit_code": %x}' \
    -o "${metrics}" \
    timeout --signal=KILL 120s \
    "${binary}" record \
    --out "${receipt}" \
    --cwd "${tree}" \
    --root . \
    --max-entries 100000 \
    --max-events 20000 \
    --max-file-hash-bytes 1048576 \
    --max-total-hash-bytes 67108864 \
    --timeout 30s \
    -- /usr/bin/true >"${output}"
  jq -e . "${metrics}" >/dev/null
  jq -e . "${output}" >/dev/null
  "${binary}" verify "${receipt}" --format json >"${verification}"
  jq -e '.integrity_valid' "${verification}" >/dev/null
}

receipt_1k="${temp_dir}/tree-1k.receipt.json"
metrics_1k="${temp_dir}/tree-1k.metrics.json"
output_1k="${temp_dir}/tree-1k.output.json"
verify_1k="${temp_dir}/tree-1k.verify.json"
receipt_10k="${temp_dir}/tree-10k.receipt.json"
metrics_10k="${temp_dir}/tree-10k.metrics.json"
output_10k="${temp_dir}/tree-10k.output.json"
verify_10k="${temp_dir}/tree-10k.verify.json"
receipt_100k="${temp_dir}/tree-100k.receipt.json"
metrics_100k="${temp_dir}/tree-100k.metrics.json"
output_100k="${temp_dir}/tree-100k.output.json"
verify_100k="${temp_dir}/tree-100k.verify.json"

measure_record \
  "${tree_1k}" "${receipt_1k}" "${metrics_1k}" "${output_1k}" "${verify_1k}"
measure_record \
  "${tree_10k}" "${receipt_10k}" "${metrics_10k}" "${output_10k}" "${verify_10k}"
measure_record \
  "${tree_100k}" "${receipt_100k}" "${metrics_100k}" "${output_100k}" "${verify_100k}"

mkdir -p "$(dirname "${result_path}")"
jq -n \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg git_sha "$(git rev-parse HEAD)" \
  --arg runner_os "${RUNNER_OS:-Linux}" \
  --arg runner_arch "$(uname -m)" \
  --arg runner_image "${ImageOS:-unknown}" \
  --arg runner_image_version "${ImageVersion:-unknown}" \
  --argjson output_1k_bytes "$(stat -c '%s' "${output_1k}")" \
  --argjson receipt_1k_bytes "$(stat -c '%s' "${receipt_1k}")" \
  --argjson output_10k_bytes "$(stat -c '%s' "${output_10k}")" \
  --argjson receipt_10k_bytes "$(stat -c '%s' "${receipt_10k}")" \
  --argjson output_100k_bytes "$(stat -c '%s' "${output_100k}")" \
  --argjson receipt_100k_bytes "$(stat -c '%s' "${receipt_100k}")" \
  --slurpfile fixture_1k "${fixture_1k}" \
  --slurpfile fixture_10k "${fixture_10k}" \
  --slurpfile fixture_100k "${fixture_100k}" \
  --slurpfile metrics_1k "${metrics_1k}" \
  --slurpfile output_1k "${output_1k}" \
  --slurpfile receipt_1k "${receipt_1k}" \
  --slurpfile verify_1k "${verify_1k}" \
  --slurpfile metrics_10k "${metrics_10k}" \
  --slurpfile output_10k "${output_10k}" \
  --slurpfile receipt_10k "${receipt_10k}" \
  --slurpfile verify_10k "${verify_10k}" \
  --slurpfile metrics_100k "${metrics_100k}" \
  --slurpfile output_100k "${output_100k}" \
  --slurpfile receipt_100k "${receipt_100k}" \
  --slurpfile verify_100k "${verify_100k}" \
  '{
    schema_version: "cmdtrail.benchmark.v1",
    generated_at: $generated_at,
    git_sha: $git_sha,
    runner: {
      os: $runner_os,
      arch: $runner_arch,
      image: $runner_image,
      image_version: $runner_image_version
    },
    fixtures: [$fixture_1k[0], $fixture_10k[0], $fixture_100k[0]],
    measurements: [
      {
        id: "portable_snapshot_1k_files",
        fixture: "tree-1k",
        process: $metrics_1k[0],
        output_bytes: $output_1k_bytes,
        receipt_bytes: $receipt_1k_bytes,
        result: {
          schema_version: $output_1k[0].schema_version,
          command_success: $output_1k[0].command_success,
          retained_entries: $receipt_1k[0].roots[0].after.retained_entries,
          scanned_entries: $receipt_1k[0].roots[0].after.scanned_entries,
          snapshot_truncated: $receipt_1k[0].summary.snapshot_truncated,
          traversal_errors: $receipt_1k[0].summary.traversal_errors,
          internal_duration_ms: $receipt_1k[0].observation.duration_ms,
          integrity_valid: $verify_1k[0].integrity_valid
        }
      },
      {
        id: "portable_snapshot_10k_files",
        fixture: "tree-10k",
        process: $metrics_10k[0],
        output_bytes: $output_10k_bytes,
        receipt_bytes: $receipt_10k_bytes,
        result: {
          schema_version: $output_10k[0].schema_version,
          command_success: $output_10k[0].command_success,
          retained_entries: $receipt_10k[0].roots[0].after.retained_entries,
          scanned_entries: $receipt_10k[0].roots[0].after.scanned_entries,
          snapshot_truncated: $receipt_10k[0].summary.snapshot_truncated,
          traversal_errors: $receipt_10k[0].summary.traversal_errors,
          internal_duration_ms: $receipt_10k[0].observation.duration_ms,
          integrity_valid: $verify_10k[0].integrity_valid
        }
      },
      {
        id: "portable_snapshot_100k_entries",
        fixture: "tree-100k",
        process: $metrics_100k[0],
        output_bytes: $output_100k_bytes,
        receipt_bytes: $receipt_100k_bytes,
        result: {
          schema_version: $output_100k[0].schema_version,
          command_success: $output_100k[0].command_success,
          retained_entries: $receipt_100k[0].roots[0].after.retained_entries,
          scanned_entries: $receipt_100k[0].roots[0].after.scanned_entries,
          snapshot_truncated: $receipt_100k[0].summary.snapshot_truncated,
          traversal_errors: $receipt_100k[0].summary.traversal_errors,
          internal_duration_ms: $receipt_100k[0].observation.duration_ms,
          integrity_valid: $verify_100k[0].integrity_valid
        }
      }
    ],
    derived: {
      max_peak_rss_mib:
        ([
          $metrics_1k[0].max_rss_kib,
          $metrics_10k[0].max_rss_kib,
          $metrics_100k[0].max_rss_kib
        ] | max | . / 1024)
    },
    threshold_status: "raw_sample"
  }' >"${result_path}"

jq -e '
  .schema_version == "cmdtrail.benchmark.v1"
  and (.fixtures | map(.entries)) == [1010, 10100, 100000]
  and all(
    .measurements[];
    .process.exit_code == 0
      and .process.wall_seconds >= 0
      and .process.max_rss_kib > 0
      and .output_bytes > 0
      and .receipt_bytes > 0
      and .result.command_success
      and (.result.snapshot_truncated | not)
      and .result.traversal_errors == 0
      and .result.integrity_valid
  )
  and any(
    .measurements[];
    .id == "portable_snapshot_10k_files"
      and .result.retained_entries == 10100
      and .result.scanned_entries == 10100
  )
  and any(
    .measurements[];
    .id == "portable_snapshot_100k_entries"
      and .result.retained_entries == 100000
      and .result.scanned_entries == 100000
  )
' "${result_path}" >/dev/null

printf 'wrote %s\n' "${result_path}"
