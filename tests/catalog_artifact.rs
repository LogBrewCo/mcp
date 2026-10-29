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
        let effects = (
            operation.pointer("/info/permission"),
            operation.pointer("/info/safety"),
        );
        if operation.pointer("/info/hints/readOnlyHint") == Some(&json!(false)) {
            assert_eq!(effects, (Some(&json!("write")), Some(&json!("write"))));
            assert!(
                operation
                    .pointer("/info/title")
                    .is_some_and(Value::is_string)
            );
        } else {
            assert_eq!(effects, (Some(&json!("read")), Some(&json!("read_only"))));
        }
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
            "issues.investigate.v13",
            json!({"issue_id":log,"response_version":1_u32}),
        ),
        (
            "issues.investigate.v14",
            json!({"issue_id":log,"response_version":13_u32}),
        ),
        (
            "issues.investigate.v15",
            json!({"issue_id":log,"response_version":14_u32}),
        ),
        (
            "issues.investigate.v16",
            json!({"issue_id":log,"response_version":15_u32}),
        ),
        (
            "issues.investigate.v17",
            json!({"issue_id":log,"response_version":16_u32}),
        ),
        ("issues.list.v5", json!({"response_version":4_u32})),
        ("logs.list.v1", json!({"pagination":"offset"})),
        ("issues.list.v2", json!({"response_version":1_u32})),
        ("issues.list.v2", json!({"priority":null})),
        ("issues.list.v3", json!({"response_version":2_u32})),
        ("issues.list.v3", json!({"assignee":null})),
        ("issues.owners.v1", json!({})),
        ("issues.owners.v1", json!({"issue_id":log,"limit":5_u32})),
        (
            "issues.activity.v1",
            json!({"issue_id":log,"limit":201_u32}),
        ),
        (
            "issues.activity.v1",
            json!({"issue_id":log,"pagination":"cursor"}),
        ),
        ("issues.ownership.v1", json!({})),
    ] {
        let failure = catalog.input(id, &input).expect_err("smuggled field");
        assert_eq!(failure.kind, Kind::InvalidInput, "{id} {input}");
    }
}

#[test]
/// # Panics
///
/// Panics if a shipped query input accepts `null`, which the API cannot send
/// in a query string, a list `limit` outside the API's 1 to 500 range, or a
/// list rejects a bounded `since` and `until` range.
fn shipped_query_inputs_match_backend_validation() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let catalog = Catalog::load(&bytes, &pinned().expect("pin")).expect("pinned catalog");
    for id in [
        "logs.list.v1",
        "issues.list.v1",
        "issues.list.v2",
        "issues.list.v3",
        "issues.list.v4",
        "issues.list.v5",
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
        catalog
            .input(
                id,
                &json!({"since":"2026-05-01T00:00:00Z","until":"2026-06-01T00:00:00Z"}),
            )
            .expect("bounded time range");
        for input in [
            json!({"limit":0_u32}),
            json!({"limit":501_u32}),
            json!({"limit":null}),
            json!({"since":null}),
            json!({"until":null}),
        ] {
            let failure = catalog.input(id, &input).expect_err("rejected input");
            assert_eq!(failure.kind, Kind::InvalidInput, "{id} {input}");
        }
    }
    catalog
        .input(
            "issues.list.v2",
            &json!({"status":"archived","priority":"high"}),
        )
        .expect("archived status and priority filters");
    for assignee in ["me", "none", "00000000-0000-4000-8000-000000000001"] {
        catalog
            .input("issues.list.v3", &json!({"assignee":assignee}))
            .expect("assignee filter");
    }
    let issue = "0b9f7c4e-2f2a-4a8e-9a65-2d2a7e8f1c11";
    catalog
        .input("issues.owners.v1", &json!({"issue_id":issue}))
        .expect("issue owners");
    catalog
        .input(
            "issues.activity.v1",
            &json!({"issue_id":issue,"limit":200_u32,"cursor_time":"2026-10-19T00:00:00Z","cursor_id":issue}),
        )
        .expect("activity page");
    catalog
        .input("issues.ownership.v1", &json!({"project_id":issue}))
        .expect("project ownership");
    for assignee in ["my_teams", "team:0b9f7c4e-2f2a-4a8e-9a65-2d2a7e8f1c11"] {
        catalog
            .input("issues.list.v4", &json!({"assignee":assignee}))
            .expect("team filters");
    }
    catalog
        .input("issues.owners.v2", &json!({"issue_id":issue}))
        .expect("team owners");
    catalog
        .input(
            "issues.activity.v2",
            &json!({"issue_id":issue,"limit":10_u32}),
        )
        .expect("team activity");
    catalog
        .input(
            "issues.activity.v3",
            &json!({"issue_id":issue,"limit":10_u32}),
        )
        .expect("archive activity");
    catalog
        .input("issues.investigate.v15", &json!({"issue_id":issue}))
        .expect("archived investigation");
    catalog
        .input("issues.investigate.v16", &json!({"issue_id":issue}))
        .expect("related issue investigation");
    catalog
        .input("issues.investigate.v17", &json!({"issue_id":issue}))
        .expect("suspect commit investigation");
}

/// Every shipped write operation: identifier, whether it asks for
/// confirmation first, and whether it takes an idempotency key.
const WRITES: [(&str, bool, bool); 12] = [
    ("issues.archive.v1", true, false),
    ("issues.assign.v1", false, false),
    ("issues.reopen.v1", false, false),
    ("issues.resolve.v1", false, false),
    ("issues.set_priority.v1", false, false),
    ("issues.unassign.v1", false, false),
    ("projects.create.v1", false, true),
    ("projects.keys.create.v1", false, true),
    ("projects.keys.revoke.v1", true, false),
    ("projects.sample_data.load.v1", false, false),
    ("projects.sample_data.remove.v1", true, false),
    ("projects.test_event.send.v1", false, false),
];

#[test]
/// # Panics
///
/// Panics if a write operation is missing, declares the wrong hints, offers a
/// confirmation or idempotency key it does not use, a confirmation answers an
/// operation that changes data at once, or its output contract rejects a
/// result the API returns.
fn shipped_write_contracts_confirm_destructive_changes() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let catalog = Catalog::load(&bytes, &pinned().expect("pin")).expect("pinned catalog");
    let writes: Vec<Value> = discovered(&catalog)
        .expect("operations")
        .into_iter()
        .filter(|operation| operation.pointer("/info/permission") == Some(&json!("write")))
        .collect();
    let ids: Vec<&str> = writes
        .iter()
        .filter_map(|operation| operation.get("id").and_then(Value::as_str))
        .collect();
    assert_eq!(ids, WRITES.map(|(id, _, _)| id));
    let outputs: Value =
        serde_json::from_slice(&read("tests/write_outputs.json").expect("outputs")).expect("JSON");
    let confirmation = outputs.get("confirmation").expect("confirmation");
    for (id, destructive, keyed) in WRITES {
        let contract = catalog.search(&json!({"operation":id})).expect(id);
        assert_eq!(
            contract.pointer("/info/hints/destructiveHint"),
            Some(&json!(destructive)),
            "{id}"
        );
        let title = contract.pointer("/info/title").and_then(Value::as_str);
        assert!(title.is_some_and(|title| title.len() <= 64), "{id}");
        let properties = contract
            .pointer("/input_schema/properties")
            .and_then(Value::as_object)
            .expect(id);
        assert_eq!(properties.contains_key("confirmation"), destructive, "{id}");
        assert_eq!(properties.contains_key("idempotency_key"), keyed, "{id}");
        assert_eq!(
            catalog.output(id, confirmation).is_ok(),
            destructive,
            "{id}"
        );
        // A result recorded from the API, with synthetic names and secrets.
        let result = outputs.get(id).expect(id);
        catalog
            .output(id, result)
            .unwrap_or_else(|_| panic!("{id} result"));
    }
}

#[test]
/// # Panics
///
/// Panics if a write input accepts a missing required field, a field another
/// operation sets, a confirmation where none is asked, or an idempotency key
/// on an operation that cannot create twice.
fn shipped_write_inputs_take_only_their_own_fields() {
    let bytes = read("catalog/operations.json").expect("catalog");
    let catalog = Catalog::load(&bytes, &pinned().expect("pin")).expect("pinned catalog");
    let issue = "0b9f7c4e-2f2a-4a8e-9a65-2d2a7e8f1c11";
    for (id, input) in [
        ("issues.resolve.v1", json!({"issue_id":issue})),
        ("issues.archive.v1", json!({"issue_id":issue})),
        (
            "issues.archive.v1",
            json!({"issue_id":issue,"archive":{"until":"time","duration":"24h"},"confirmation":"a.b.c"}),
        ),
        (
            "issues.set_priority.v1",
            json!({"issue_id":issue,"priority":"high"}),
        ),
        (
            "issues.assign.v1",
            json!({"issue_id":issue,"assignee":"me"}),
        ),
        (
            "issues.assign.v1",
            json!({"issue_id":issue,"assignee":format!("team:{issue}")}),
        ),
        (
            "projects.create.v1",
            json!({"name":"Checkout","runtime":"node","source":"sdk"}),
        ),
        (
            "projects.keys.create.v1",
            json!({"project_id":issue,"label":"CI","kind":"server","idempotency_key":"ci-1"}),
        ),
        (
            "projects.keys.revoke.v1",
            json!({"project_id":issue,"key_id":issue}),
        ),
        (
            "projects.test_event.send.v1",
            json!({"project_id":issue,"ingest_key":"lbw_ingest_example"}),
        ),
        ("projects.test_event.send.v1", json!({"project_id":issue})),
        ("projects.sample_data.load.v1", json!({"project_id":issue})),
        (
            "projects.sample_data.remove.v1",
            json!({"project_id":issue,"confirmation":"a.b.c"}),
        ),
    ] {
        catalog
            .input(id, &input)
            .unwrap_or_else(|_| panic!("{id} {input}"));
    }
    for (id, input) in [
        (
            "issues.resolve.v1",
            json!({"issue_id":issue,"status":"archived"}),
        ),
        (
            "issues.resolve.v1",
            json!({"issue_id":issue,"confirmation":"a.b.c"}),
        ),
        (
            "issues.resolve.v1",
            json!({"issue_id":issue,"idempotency_key":"k"}),
        ),
        (
            "issues.unassign.v1",
            json!({"issue_id":issue,"assignee":"me"}),
        ),
        ("issues.set_priority.v1", json!({"issue_id":issue})),
        (
            "issues.set_priority.v1",
            json!({"issue_id":issue,"priority":"urgent"}),
        ),
        (
            "issues.assign.v1",
            json!({"issue_id":issue,"assignee":"everyone"}),
        ),
        (
            "issues.archive.v1",
            json!({"issue_id":issue,"archive":{"until":"later"}}),
        ),
        (
            "projects.create.v1",
            json!({"name":"Checkout","source":"sdk"}),
        ),
        (
            "projects.create.v1",
            json!({"name":"Checkout","runtime":"node","source":"sdk","idempotency_key":"line\nbreak"}),
        ),
        (
            "projects.keys.create.v1",
            json!({"project_id":issue,"label":"CI"}),
        ),
        ("projects.keys.revoke.v1", json!({"project_id":issue})),
    ] {
        let failure = catalog.input(id, &input).expect_err("rejected input");
        assert_eq!(failure.kind, Kind::InvalidInput, "{id} {input}");
    }
}
