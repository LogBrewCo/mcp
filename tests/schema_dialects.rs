//! Catalog schemas use their declared dialect without external retrieval.

use logbrew_mcp::{Failure, catalog::Catalog, error::Kind};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Build a synthetic catalog with the supplied schema and expected checksum.
///
/// # Errors
/// Propagates rejection of the synthetic catalog or supplied schema contract.
fn load(schema: &Value) -> Result<std::sync::Arc<Catalog>, Failure> {
    let bytes = json!({"format_version":1_i32,"operations":[{
        "id":"logs.read.v1","info":{"summary":"Read selected logs","permission":"logs:read",
            "documentation":"https://docs.example/logs","stability":"stable",
            "cost":"one read","safety":"read_only"},
        "input_schema":schema,"output_schema":schema
    }]})
    .to_string()
    .into_bytes();
    Catalog::load(&bytes, &Sha256::digest(&bytes).into())
}

/// Check accepted tuples and rejection categories through both operation contracts.
///
/// # Errors
/// Propagates rejection of the expected valid tuple by either contract.
///
/// # Panics
/// Fails when an invalid tuple has the wrong input or output rejection category.
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions must retain their failure and comparison diagnostics."
)]
fn check_tuple(catalog: &Catalog) -> Result<(), Failure> {
    let allowed = json!({"values":["preserved"]});
    catalog.input("logs.read.v1", &allowed)?;
    catalog.output("logs.read.v1", &allowed)?;
    for rejected in [
        json!({"values":[42_i32]}),
        json!({"values":["preserved","extra"]}),
        json!({"values":[]}),
        json!({}),
    ] {
        assert_eq!(
            catalog
                .input("logs.read.v1", &rejected)
                .err()
                .map(|error| error.kind),
            Some(Kind::InvalidInput)
        );
        assert_eq!(
            catalog
                .output("logs.read.v1", &rejected)
                .err()
                .map(|error| error.kind),
            Some(Kind::InvalidOutput)
        );
    }
    Ok(())
}

/// Check legacy tuple validation and exact discovery schema preservation.
///
/// # Panics
/// Fails when a supported dialect cannot load, validates an unexpected tuple
/// or changes the schema returned by discovery.
#[test]
fn declared_legacy_dialects_preserve_input_and_output_tuple_contracts() {
    for dialect in [
        "http://json-schema.org/draft-04/schema#",
        "http://json-schema.org/draft-06/schema#",
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema",
    ] {
        let schema = json!({"$schema":dialect,"type":"object",
            "required":["values"],"additionalProperties":false,
            "properties":{"values":{"type":"array","minItems":1_i32,
                "items":[{"type":"string"}],"additionalItems":false}}});
        let catalog = load(&schema).expect("declared tuple dialect");
        check_tuple(&catalog).expect("legacy tuple validation");
        let found = catalog
            .search(&json!({"operation":"logs.read.v1"}))
            .expect("discovered contract");
        assert_eq!(found.get("input_schema"), Some(&schema));
        assert_eq!(found.get("output_schema"), Some(&schema));
    }
}

/// Check implicit and explicit 2020-12 prefix-item validation.
///
/// # Panics
/// Fails when a supported schema cannot load or tuple validation changes.
#[test]
fn absent_and_explicit_2020_dialects_preserve_prefix_item_contracts() {
    let base = json!({"type":"object","required":["values"],"additionalProperties":false,
        "properties":{"values":{"type":"array","minItems":1_i32,
            "prefixItems":[{"type":"string"}],"items":false}}});
    for dialect in [
        None,
        Some("https://json-schema.org/draft/2020-12/schema"),
        Some("http://json-schema.org/draft/2020-12/schema#"),
    ] {
        let mut schema = base.clone();
        if let Some(dialect) = dialect {
            drop(
                schema
                    .as_object_mut()
                    .expect("schema")
                    .insert("$schema".to_owned(), json!(dialect)),
            );
        }
        check_tuple(&load(&schema).expect("2020-12 tuple contract"))
            .expect("2020-12 tuple validation");
    }
}

/// Check malformed declarations and embedded dialects fail without disclosure.
///
/// # Panics
/// Fails when a declaration loads, returns the wrong failure category
/// or repeats the synthetic private marker.
#[test]
fn unknown_or_malformed_dialects_fail_without_repeating_the_declaration() {
    for dialect in [
        json!("https://schemas.invalid/SYNTHETIC_PRIVATE_DIALECT"),
        json!("file:///SYNTHETIC_PRIVATE_DIALECT"),
        json!(""),
        Value::Null,
        json!(false),
        json!(17_i32),
        json!(["https://json-schema.org/draft/2020-12/schema"]),
    ] {
        let schema = json!({"$schema":dialect,"type":"object"});
        let failure = load(&schema).err().expect("unsupported declaration");
        assert_eq!(failure.kind, Kind::Configuration);
        assert!(!failure.to_string().contains("SYNTHETIC_PRIVATE_DIALECT"));
    }
    let schema = json!({"type":"object","required":["value"],"properties":{
        "value":{"$ref":"#/$defs/value"}},"$defs":{"value":{
            "$id":"https://schemas.invalid/local",
            "$schema":"https://schemas.invalid/SYNTHETIC_PRIVATE_DIALECT",
            "type":"string"}}});
    let failure = load(&schema)
        .err()
        .expect("unsupported embedded declaration");
    assert_eq!(failure.kind, Kind::Configuration);
    assert!(!failure.to_string().contains("SYNTHETIC_PRIVATE_DIALECT"));
}

/// Check `$schema` properties and annotations remain ordinary instance data.
///
/// # Panics
/// Fails when the schema cannot load, rejects the valid instance
/// or accepts an instance that violates its constant value.
#[test]
fn ordinary_schema_keys_and_annotations_remain_instance_data() {
    let data = json!({"$schema":"https://schemas.invalid/SYNTHETIC_PRIVATE_DIALECT"});
    let schema = json!({"type":"object","required":["$schema"],
        "additionalProperties":false,"properties":{"$schema":{"type":"string"}},
        "const":data,"default":data,"examples":[data]});
    let catalog = load(&schema).expect("ordinary schema-named data");
    catalog.input("logs.read.v1", &data).unwrap();
    catalog.output("logs.read.v1", &data).unwrap();
    let different = json!({"$schema":"changed"});
    assert!(catalog.input("logs.read.v1", &different).is_err());
    assert!(catalog.output("logs.read.v1", &different).is_err());
}
