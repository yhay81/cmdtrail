#!/bin/bash -eu

cd "$SRC/cmdtrail"
cargo fuzz build -O --debug-assertions

fuzz_output="fuzz/target/x86_64-unknown-linux-gnu/release"
for source in fuzz/fuzz_targets/*.rs; do
    target="$(basename "${source%.*}")"
    cp "$fuzz_output/$target" "$OUT/$target"
done

zip -q -j "$OUT/receipt_integrity_seed_corpus.zip" \
    tests/fixtures/contracts/v0.1/portable.receipt.json
