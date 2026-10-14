//! The shipped operation catalog matches its pinned digest and public reference.

extern crate alloc;

use alloc::collections::BTreeSet;
use std::{fs, path::Path};

use logbrew_mcp::{catalog::Catalog, error::Kind};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// # Errors
/// Returns an error if the shipped file cannot be read.
fn read(path: &str) -> TestResult<Vec<u8>> {
    Ok(fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))?)
}

/// Decode the pinned `sha256sum` line for `operations.json`.
///
/// # Errors
/// Returns an error unless the pin is one line with 64 hexadecimal digits.
fn pinned() -> TestResult<[u8; 32]> {
    let line = String::from_utf8(read("catalog/operations.json.sha256")?)?;
    let hex = line
        .strip_suffix("  operations.json\n")
        .filter(|hex| hex.len() == 64)
        .ok_or("one sha256sum line")?;
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair)?, 16)?;
    }
    Ok(digest)
}

/// Collect every operation through bounded discovery pages.
///
/// # Errors
/// Returns an error if a discovery page is rejected or malformed.
fn discovered(catalog: &Catalog) -> TestResult<Vec<Value>> {
    let mut operations = Vec::new();
    let mut after = String::new();
    loop {
        let page = catalog.search(&json!({"query":"","after":after,"limit":10_u32}))?;
        operations.extend(
            page.get("operations")
                .and_then(Value::as_array)
                .ok_or("operations")?
                .iter()
                .cloned(),
        );
        page.get("next_cursor")
            .and_then(Value::as_str)
            .ok_or("cursor")?
            .clone_into(&mut after);
        if after.is_empty() {
            return Ok(operations);
        }
    }
}

#[test]
/// # Panics
///
/// Panics if the shipped catalog does not match its pin, loads under a wrong
/// digest or after a one-byte change, or differs from the operation reference.
fn shipped_catalog_matches_its_pin_and_the_operation_reference() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let digest = pinned().expect("pin");
    assert_eq!(Sha256::digest(&bytes).as_slice(), digest);
    let catalog = Catalog::load(&bytes, &digest).expect("pinned catalog");
    let mut wrong = digest;
    if let Some(first) = wrong.first_mut() {
        *first ^= 1;
    }
    let mut changed = bytes.clone();
    changed.push(b' ');
    for (artifact, expected) in [(&bytes, &wrong), (&changed, &digest)] {
        let failure = Catalog::load(artifact, expected).err().expect("rejected");
        assert_eq!(failure.kind, Kind::Configuration);
    }
    let operations = discovered(&catalog).expect("operations");
    for operation in &operations {
        assert_eq!(operation.pointer("/info/permission"), Some(&json!("read")));
        assert_eq!(operation.pointer("/info/safety"), Some(&json!("read_only")));
    }
    let ids: BTreeSet<&str> = operations
        .iter()
        .filter_map(|operation| operation.get("id").and_then(Value::as_str))
        .collect();
    let reference =
        String::from_utf8(read("docs/operations.md").expect("reference")).expect("UTF-8");
    let documented: BTreeSet<&str> = reference
        .lines()
        .filter_map(|line| line.strip_prefix("| `")?.split_once('`'))
        .map(|(id, _)| id)
        .collect();
    assert_eq!(ids.len(), operations.len());
    assert_eq!(ids, documented);
}

#[test]
/// # Panics
///
/// Panics if shipped input contracts accept unknown fields, pinned contract
/// fields, or path identifiers that could change the selected resource.
fn shipped_input_contracts_reject_smuggled_fields() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let catalog = Catalog::load(&bytes, &pinned().expect("pin")).expect("pinned catalog");
    for operation in discovered(&catalog).expect("operations") {
        let id = operation.get("id").and_then(Value::as_str).expect("id");
        let failure = catalog
            .input(id, &json!({"unexpected_field":"x"}))
            .expect_err("unknown field");
        assert_eq!(failure.kind, Kind::InvalidInput, "{id}");
    }
    let log = "0b9f7c4e-2f2a-4a8e-9a65-2d2a7e8f1c11";
    catalog
        .input("logs.investigate.v1", &json!({"log_id":log}))
        .expect("path identifier");
    for (id, input) in [
        ("logs.investigate.v1", json!({})),
        ("logs.investigate.v1", json!({"log_id":"../usage"})),
        ("logs.investigate.v1", json!({"log_id":"a?project_ids=x"})),
        ("logs.investigate.v1", json!({"log_id":"a/b"})),
        (
            "issues.investigate.v12",
            json!({"issue_id":log,"response_version":1_u32}),
        ),
        ("logs.list.v1", json!({"pagination":"offset"})),
    ] {
        let failure = catalog.input(id, &input).expect_err("smuggled field");
        assert_eq!(failure.kind, Kind::InvalidInput, "{id} {input}");
    }
}

#[test]
/// # Panics
///
/// Panics if a shipped query input accepts `null`, which the API cannot send
/// in a query string, or a list `limit` outside the API's 1 to 500 range.
fn shipped_query_inputs_match_backend_validation() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let catalog = Catalog::load(&bytes, &pinned().expect("pin")).expect("pinned catalog");
    for id in [
        "logs.list.v1",
        "issues.list.v1",
        "traces.list.v1",
        "actions.list.v1",
        "metrics.list.v1",
        "releases.list.v1",
    ] {
        for limit in [1_u32, 500_u32] {
            catalog
                .input(id, &json!({"limit":limit}))
                .expect("limit in range");
        }
        for input in [
            json!({"limit":0_u32}),
            json!({"limit":501_u32}),
            json!({"limit":null}),
            json!({"since":null}),
        ] {
            let failure = catalog.input(id, &input).expect_err("rejected input");
            assert_eq!(failure.kind, Kind::InvalidInput, "{id} {input}");
        }
    }
}
