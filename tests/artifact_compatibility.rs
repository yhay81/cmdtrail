#![allow(clippy::expect_used, clippy::panic)]

use cmdtrail::integrity::{sha256_bytes, verify_receipt};
use cmdtrail::model::Receipt;
use cmdtrail::receipt::read_receipt;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contracts/v0.1")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON fixture")).expect("parse JSON fixture")
}

fn mutate(document: &mut Value, operation: &str, pointer: &str, value: Value) {
    match operation {
        "replace" => *document.pointer_mut(pointer).expect("replace target") = value,
        "add" => {
            let (parent_pointer, key) = pointer.rsplit_once('/').expect("pointer parent");
            let parent = if parent_pointer.is_empty() {
                document
            } else {
                document
                    .pointer_mut(parent_pointer)
                    .expect("mutation parent")
            };
            assert!(parent
                .as_object_mut()
                .expect("object parent")
                .insert(key.to_owned(), value)
                .is_none());
        }
        other => panic!("unsupported mutation {other}"),
    }
}

#[test]
fn current_reader_accepts_exact_v01_receipt() {
    let root = corpus_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"], "cmdtrail.receipt-corpus.v1");
    let accepted = manifest["accepted"].as_array().expect("accepted artifacts");
    assert_eq!(accepted.len(), 1);
    let relative = accepted[0]["path"].as_str().expect("accepted path");
    let path = root.join(relative);
    let bytes = fs::read(&path).expect("read accepted receipt");
    assert_eq!(sha256_bytes(&bytes), accepted[0]["sha256"]);

    let receipt = read_receipt(&path).expect("read strict golden receipt");
    let mut serialized = serde_json::to_vec_pretty(&receipt).expect("serialize golden receipt");
    serialized.push(b'\n');
    assert_eq!(serialized, bytes);

    let report = verify_receipt(&receipt);
    assert!(report.integrity_valid);
    assert_eq!(receipt.events.len(), 3);
    let event_types = receipt
        .events
        .iter()
        .map(|event| match event.event {
            cmdtrail::model::EventData::CommandRequested(_) => "command_requested",
            cmdtrail::model::EventData::CommandFinished(_) => "command_finished",
            cmdtrail::model::EventData::FileEffect(_) => "file_effect",
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        event_types,
        BTreeSet::from(["command_finished", "command_requested", "file_effect"])
    );
}

#[test]
fn declared_v01_mutations_fail_closed() {
    let root = corpus_root();
    let manifest = read_json(&root.join("manifest.json"));
    let golden = read_json(&root.join("portable.receipt.json"));
    let mut ids = BTreeSet::new();

    for case in manifest["rejections"].as_array().expect("rejection cases") {
        let id = case["id"].as_str().expect("case ID");
        assert!(ids.insert(id.to_owned()));
        let mut document = golden.clone();
        mutate(
            &mut document,
            case["operation"].as_str().expect("operation"),
            case["pointer"].as_str().expect("pointer"),
            case["value"].clone(),
        );
        if case["class"] == "parse" {
            serde_json::from_value::<Receipt>(document)
                .expect_err("strict-shape mutation must fail parsing");
        } else {
            let receipt =
                serde_json::from_value::<Receipt>(document).expect("integrity mutation parses");
            let report = verify_receipt(&receipt);
            assert!(!report.integrity_valid, "mutation {id} must fail");
            let expected = case["expected_error"].as_str().expect("expected error");
            assert!(
                report.errors.iter().any(|error| error == expected),
                "mutation {id} errors {:?} must include {expected}",
                report.errors
            );
        }
    }
    assert_eq!(ids.len(), 12);
}
