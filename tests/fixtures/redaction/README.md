# Redaction corpus

`v0.1/corpus.json` is a deterministic, MIT-licensed calibration corpus for the
redaction patterns CmdTrail documents as supported. It contains 128 labeled
cases:

- separated secret-bearing flags and their following values;
- `key=value` secret-bearing arguments;
- URL user information, queries, and fragments;
- sensitive path components;
- exact additional values supplied through `--redact-env`;
- benign command and path controls.

The labels are generated from explicit case tables in `generate_corpus.py`.
The generator does not import, invoke, or inspect CmdTrail. The production
`Redactor` is evaluated independently by `src/redact/corpus_tests.rs`, which
requires exact display and digest-retention agreement in addition to checking
for supported secret escapes.

`metrics.json` pins the expected results and the canonical parsed-JSON SHA-256
of the corpus, so the evidence is independent of checkout line endings.

Regenerate and verify the fixtures with:

```bash
python3 tests/fixtures/redaction/v0.1/generate_corpus.py
python3 tests/fixtures/redaction/v0.1/generate_corpus.py --check
cargo test redact::corpus_tests::published_redaction_metrics_are_reproducible
```

The corpus deliberately does not claim detection of arbitrary positional
secrets. Those values remain outside the supported pattern boundary unless the
caller supplies them explicitly with `--redact-env`.
