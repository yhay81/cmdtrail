use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: String,
    license: String,
    labeling_methodology: String,
    unsupported_scope: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    category: String,
    supported_pattern: bool,
    secrets: Vec<String>,
    input: CaseInput,
    expected: Observation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    kind: String,
    executable: String,
    arguments: Vec<String>,
    path: Option<String>,
    custom_values: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Observation {
    executable_display: Option<String>,
    argument_displays: Vec<String>,
    argument_digest_present: Vec<bool>,
    redacted_arguments: u64,
    path_display: Option<String>,
    redacted_path_components: u64,
}

#[derive(Debug, Default)]
struct CategoryMetrics {
    cases: usize,
    exact_matches: usize,
    secret_observations: usize,
    escapes: usize,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redaction/v0.1")
}

fn observe(case: &Case) -> Observation {
    let redactor = Redactor {
        custom_values: case.input.custom_values.clone(),
    };
    match case.input.kind.as_str() {
        "command" => {
            assert!(case.input.path.is_none(), "{} command path", case.id);
            let command = std::iter::once(&case.input.executable)
                .chain(case.input.arguments.iter())
                .map(OsString::from)
                .collect::<Vec<_>>();
            let actual = redactor.command(&command);
            Observation {
                executable_display: Some(actual.executable_display),
                argument_displays: actual.argument_displays,
                argument_digest_present: actual
                    .argument_sha256
                    .iter()
                    .map(Option::is_some)
                    .collect(),
                redacted_arguments: actual.redacted_arguments,
                path_display: None,
                redacted_path_components: 0,
            }
        }
        "path" => {
            assert!(
                case.input.executable.is_empty(),
                "{} path executable",
                case.id
            );
            assert!(
                case.input.arguments.is_empty(),
                "{} path arguments",
                case.id
            );
            let path = case.input.path.as_deref().expect("path case value");
            let (display, count) = redactor.path_display(Path::new(path));
            Observation {
                executable_display: None,
                argument_displays: Vec::new(),
                argument_digest_present: Vec::new(),
                redacted_arguments: 0,
                path_display: Some(display),
                redacted_path_components: count,
            }
        }
        other => panic!("{} has unknown input kind {other}", case.id),
    }
}

fn displayed_text(observation: &Observation) -> String {
    observation
        .executable_display
        .iter()
        .chain(observation.argument_displays.iter())
        .chain(observation.path_display.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        let numerator = u32::try_from(numerator).expect("corpus numerator fits u32");
        let denominator = u32::try_from(denominator).expect("corpus denominator fits u32");
        f64::from(numerator) / f64::from(denominator)
    }
}

#[test]
fn published_redaction_metrics_are_reproducible() {
    let root = fixture_root();
    let corpus_bytes = fs::read(root.join("corpus.json")).expect("read corpus");
    let corpus_value: Value = serde_json::from_slice(&corpus_bytes).expect("corpus JSON");
    let canonical_corpus =
        serde_json::to_vec(&corpus_value).expect("canonical corpus serialization");
    let corpus_text = String::from_utf8(corpus_bytes).expect("corpus is UTF-8");
    let crlf_text = corpus_text.replace("\r\n", "\n").replace('\n', "\r\n");
    let crlf_value: Value = serde_json::from_str(&crlf_text).expect("CRLF corpus JSON");
    assert_eq!(
        serde_json::to_vec(&crlf_value).expect("canonical CRLF corpus"),
        canonical_corpus,
        "logical corpus digest must not depend on checkout line endings"
    );

    let corpus: Corpus = serde_json::from_value(corpus_value).expect("corpus shape");
    assert_eq!(corpus.schema_version, "cmdtrail.redaction-corpus.v1");
    assert_eq!(corpus.license, "MIT");
    assert!(!corpus.labeling_methodology.is_empty());
    assert!(corpus.unsupported_scope.contains("Arbitrary positional"));
    assert_eq!(corpus.cases.len(), 128);

    let mut identifiers = BTreeSet::new();
    let mut exact_matches = 0;
    let mut supported_pattern_cases = 0;
    let mut secret_observations = 0;
    let mut escapes = 0;
    let mut benign_controls = 0;
    let mut benign_false_positives = 0;
    let mut by_category = BTreeMap::<String, CategoryMetrics>::new();

    for case in &corpus.cases {
        assert!(identifiers.insert(&case.id), "duplicate case {}", case.id);
        let actual = observe(case);
        let exact = actual == case.expected;
        exact_matches += usize::from(exact);
        let display = displayed_text(&actual);
        let case_escapes = case
            .secrets
            .iter()
            .filter(|secret| display.contains(secret.as_str()))
            .count();
        escapes += case_escapes;
        secret_observations += case.secrets.len();
        if case.supported_pattern {
            supported_pattern_cases += 1;
            assert!(
                !case.secrets.is_empty(),
                "{} supported case needs a secret label",
                case.id
            );
        } else {
            benign_controls += 1;
            benign_false_positives += usize::from(!exact);
            assert!(
                case.secrets.is_empty(),
                "{} benign control cannot label a secret",
                case.id
            );
        }
        assert_eq!(actual, case.expected, "exact observation for {}", case.id);
        assert_eq!(case_escapes, 0, "supported secret escaped in {}", case.id);

        let category = by_category.entry(case.category.clone()).or_default();
        category.cases += 1;
        category.exact_matches += usize::from(exact);
        category.secret_observations += case.secrets.len();
        category.escapes += case_escapes;
    }

    let category_metrics = by_category
        .into_iter()
        .map(|(category, metrics)| {
            (
                category,
                json!({
                    "cases": metrics.cases,
                    "exact_matches": metrics.exact_matches,
                    "secret_observations": metrics.secret_observations,
                    "escapes": metrics.escapes,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let actual_metrics = json!({
        "schema_version": "cmdtrail.redaction-metrics.v1",
        "corpus_sha256": crate::integrity::sha256_bytes(&canonical_corpus),
        "total_cases": corpus.cases.len(),
        "exact_matches": exact_matches,
        "exact_accuracy": ratio(exact_matches, corpus.cases.len()),
        "supported_pattern_cases": supported_pattern_cases,
        "secret_observations": secret_observations,
        "escapes": escapes,
        "escape_rate": ratio(escapes, secret_observations),
        "benign_controls": benign_controls,
        "benign_false_positives": benign_false_positives,
        "by_category": category_metrics,
    });
    let expected_metrics: Value =
        serde_json::from_slice(&fs::read(root.join("metrics.json")).expect("read metrics"))
            .expect("metrics JSON");
    assert_eq!(actual_metrics, expected_metrics);
}
