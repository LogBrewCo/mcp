//! Adversarial contract and startup regressions use synthetic data only.

use logbrew_mcp::{catalog::Catalog, json, startup::Config};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn artifact(schema: &Value) -> Vec<u8> {
    json!({"format_version":1,"operations":[{
        "id":"logs.read.v1","info":{"summary":"Read selected logs","permission":"logs:read",
            "documentation":"https://docs.example/logs","stability":"stable","cost":"one read","safety":"read_only"},
        "input_schema":schema,"output_schema":{"type":"object","additionalProperties":false,
            "required":["count"],"properties":{"count":{"type":"integer"}}}
    }]}).to_string().into_bytes()
}

#[test]
/// # Panics
///
/// Panics if strict parsing accepts a duplicate key, invalid UTF-8, a trailing
/// document or a non-object root, or rejects the valid Unicode fixture.
fn decoded_duplicates_utf8_and_trailing_documents_are_rejected() {
    for bytes in [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"{\"a\":{\"x\":0,\"\\u0078\":1}}",
        b"{\"a\":[{\"x\":0,\"x\":1}]}",
        b"{\"a\":\"\xff\"}",
        b"{}{}",
        b"[]",
        b"null",
    ] {
        assert!(
            json::object(bytes, 1024).is_err(),
            "strict parsing accepted invalid evidence"
        );
    }
    drop(json::object("{\"text\":\"\u{130}stanbul, \u{fffd}\"}".as_bytes(), 1024).unwrap());
}

#[test]
/// # Panics
///
/// Panics if the fixture cannot be parsed or ordinary object keys lose their
/// values because they match serializer control names.
fn ordinary_object_keys_do_not_become_serializer_control_records() {
    let raw = br#"{"data":{"$serde_json::private::Number":"123","context":"preserved"},"raw":{"$serde_json::private::RawValue":"null"}}"#;
    let value = json::object(raw, 1024).expect("ordinary object keys");
    assert_eq!(
        value.pointer("/data/$serde_json::private::Number"),
        Some(&json!("123"))
    );
    assert_eq!(value.pointer("/data/context"), Some(&json!("preserved")));
    assert_eq!(
        value.pointer("/raw/$serde_json::private::RawValue"),
        Some(&json!("null"))
    );
}

#[test]
/// # Panics
///
/// Panics if fixture construction fails or schema validation and discovery do
/// not preserve ordinary property names that match serializer control names.
fn ordinary_property_names_keep_their_schema_contracts_in_catalog_loading() {
    for name in [
        "$serde_json::private::Number",
        "$serde_json::private::RawValue",
    ] {
        let schema = json!({"type":"object","required":[name],"additionalProperties":false,
            "properties":{name:{"type":"string"}}});
        let mut value = json::object(&artifact(&schema), 8 << 20).expect("artifact");
        *value
            .pointer_mut("/operations/0/output_schema")
            .expect("output schema") = schema.clone();
        let bytes = serde_json::to_vec(&value).expect("encoded artifact");
        let catalog = Catalog::load(&bytes, &Sha256::digest(&bytes).into())
            .expect("ordinary property contract");
        catalog
            .input("logs.read.v1", &json!({name:"preserved"}))
            .unwrap();
        assert!(
            catalog
                .input("logs.read.v1", &json!({name:123_i32}))
                .is_err()
        );
        catalog
            .output("logs.read.v1", &json!({name:"preserved"}))
            .unwrap();
        assert!(
            catalog
                .output("logs.read.v1", &json!({name:123_i32}))
                .is_err()
        );
        let exact = catalog
            .search(&json!({"operation":"logs.read.v1"}))
            .expect("contract");
        assert_eq!(exact.get("input_schema"), Some(&schema));
        assert_eq!(exact.get("output_schema"), Some(&schema));
    }
}

#[test]
/// # Panics
///
/// Panics if fixture construction fails, malformed catalog fields are accepted,
/// a rejection has the wrong kind, or an error reveals the private marker.
fn malformed_catalog_structure_cannot_replace_or_extend_declared_contract_fields() {
    let base = json::object(&artifact(&json!({"type":"object"})), 8 << 20).expect("artifact");
    for case in 0_i32..8_i32 {
        let mut value = base.clone();
        match case {
            0_i32 => {
                drop(
                    value
                        .as_object_mut()
                        .expect("root")
                        .insert("private".to_owned(), json!("SYNTHETIC_PRIVATE_MARKER")),
                );
            }
            1_i32 => {
                *value.get_mut("format_version").expect("version") = json!(1.5_f64);
            }
            2_i32 => {
                *value.get_mut("operations").expect("operations") = json!([]);
            }
            3_i32 => {
                *value.get_mut("operations").expect("operations") = json!({});
            }
            4_i32 => {
                drop(
                    value
                        .pointer_mut("/operations/0")
                        .and_then(Value::as_object_mut)
                        .expect("operation")
                        .remove("input_schema"),
                );
            }
            5_i32 => {
                drop(
                    value
                        .pointer_mut("/operations/0")
                        .and_then(Value::as_object_mut)
                        .expect("operation")
                        .insert("extra".to_owned(), json!("SYNTHETIC_PRIVATE_MARKER")),
                );
            }
            6_i32 => {
                drop(
                    value
                        .pointer_mut("/operations/0/info")
                        .and_then(Value::as_object_mut)
                        .expect("info")
                        .insert("extra".to_owned(), json!("SYNTHETIC_PRIVATE_MARKER")),
                );
            }
            _ => {
                *value.pointer_mut("/operations/0/id").expect("id") = Value::Null;
            }
        }
        let bytes = serde_json::to_vec(&value).expect("encoded artifact");
        let failure = Catalog::load(&bytes, &Sha256::digest(&bytes).into())
            .err()
            .expect("rejected catalog");
        assert_eq!(
            failure.kind,
            logbrew_mcp::error::Kind::Configuration,
            "case {case}"
        );
        assert!(!failure.to_string().contains("SYNTHETIC_PRIVATE_MARKER"));
    }
}

#[test]
/// # Panics
///
/// Panics if a valid HTTPS identifier is rejected or an unsafe scheme,
/// credential-bearing URL, query or fragment is accepted.
fn authority_identifier_strings_keep_the_existing_root_url_form() {
    for value in [
        "https://issuer.example",
        "https://issuer.example/",
        "https://service.example/execute",
    ] {
        drop(logbrew_mcp::upstream::canonical_https(value).unwrap());
    }
    for value in [
        "http://issuer.example/",
        "https://machine:secret@issuer.example/",
        "https://issuer.example/?token=synthetic",
        "https://issuer.example/#fragment",
    ] {
        let _: logbrew_mcp::Failure = logbrew_mcp::upstream::canonical_https(value).unwrap_err();
    }
}

#[test]
/// # Panics
///
/// Panics if exact integer or decimal values change, byte, numeric or nesting
/// limits accept invalid input, or the maximum supported nesting is rejected.
fn exact_numbers_and_resource_limits_are_preserved() {
    let bytes = b"{\"integer\":9007199254740993,\"decimal\":0.12345678901234567890123456789,\"large\":1e1024}";
    let parsed = json::object(bytes, bytes.len()).expect("bounded exact values");
    assert_eq!(
        parsed.get("integer").expect("integer").to_string(),
        "9007199254740993"
    );
    assert_eq!(
        parsed.get("decimal").expect("decimal").to_string(),
        "0.12345678901234567890123456789"
    );
    let _: logbrew_mcp::Failure = json::object(bytes, bytes.len().saturating_sub(1)).unwrap_err();
    for value in ["1e1025", "1e-1025", &"9".repeat(257)] {
        let data = format!("{{\"number\":{value}}}");
        let _: logbrew_mcp::Failure = json::object(data.as_bytes(), 1024).unwrap_err();
    }
    let over_nested = format!("{}0{}", "{\"v\":".repeat(65), "}".repeat(65));
    let _: logbrew_mcp::Failure = json::object(over_nested.as_bytes(), 1024).unwrap_err();
    let max_nested = format!("{}0{}", "{\"v\":".repeat(64), "}".repeat(64));
    drop(json::object(max_nested.as_bytes(), 1024).unwrap());
}

#[test]
/// # Panics
///
/// Panics if the trusted fixture cannot be loaded or validated, or catalog
/// integrity, external schema isolation, format or operation checks fail.
fn catalog_integrity_schema_isolation_and_format_assertions_are_required() {
    let schema = json!({"type":"object","required":["email"],"additionalProperties":false,
        "properties":{"email":{"type":"string","format":"email"}}});
    let bytes = artifact(&schema);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let catalog = Catalog::load(&bytes, &digest).expect("trusted catalog");
    assert!(Catalog::load(&bytes, &[0; 32]).is_err());
    catalog
        .input("logs.read.v1", &json!({"email":"reader@example.com"}))
        .unwrap();
    assert!(
        catalog
            .input("logs.read.v1", &json!({"email":"broken"}))
            .is_err()
    );
    assert!(catalog.input("missing.read.v1", &json!({})).is_err());
    assert!(
        catalog
            .output("logs.read.v1", &json!({"count":"unproven"}))
            .is_err()
    );
    let remote_schema =
        artifact(&json!({"type":"object","$ref":"https://schemas.invalid/private"}));
    assert!(Catalog::load(&remote_schema, &Sha256::digest(&remote_schema).into()).is_err());
}

#[test]
/// # Panics
///
/// Panics if fixture loading or search fails, the selected summary or contract
/// changes, or search accepts an invalid query field, limit or cursor.
fn search_is_small_deterministic_and_does_not_grant_access() {
    let bytes = artifact(&json!({"type":"object"}));
    let catalog = Catalog::load(&bytes, &Sha256::digest(&bytes).into()).expect("catalog");
    let page = catalog
        .search(&json!({"query":"selected logs","limit":1_i32}))
        .expect("search");
    let entry = page
        .get("operations")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("summary");
    assert_eq!(entry.get("id"), Some(&json!("logs.read.v1")));
    assert!(entry.get("input_schema").is_none());
    let exact = catalog
        .search(&json!({"operation":"logs.read.v1"}))
        .expect("selected contract");
    assert!(exact.get("input_schema").is_some());
    for input in [
        json!({"operation":"logs.read.v1","query":""}),
        json!({"query":"","limit":0_i32}),
        json!({"query":"","after":"unknown.read.v1"}),
        json!({"query":"","token":"synthetic"}),
    ] {
        let _: logbrew_mcp::Failure = catalog.search(&input).unwrap_err();
    }
}

#[test]
/// # Panics
///
/// Panics if fixture encoding fails or configuration defaults, secret-reference
/// handling, debug privacy, versions or invalid-field rejection change.
fn configuration_never_accepts_inline_secrets_or_duplicate_fields() {
    let fields = json!({"version":"1","listen":"127.0.0.1:8080","resource":"https://resource.example/mcp",
        "issuer":"https://issuer.example/","required_scope":"mcp:read","introspection_endpoint":"https://issuer.example/introspect",
        "introspection_client_id":"machine","introspection_secret_file":"/synthetic/introspection",
        "execution_endpoint":"https://service.example/execute","execution_client_id":"machine-execution",
        "execution_secret_file":"/synthetic/execution","catalog_file":"/synthetic/catalog",
        "catalog_sha256":"00".repeat(32),"certificate_file":"/synthetic/certificate","private_key_file":"/synthetic/key"});
    let bytes = serde_json::to_vec(&fields).expect("configuration");
    let config = Config::decode(&bytes).expect("secret references only");
    let _: (std::net::SocketAddr, [u8; 32]) = config.address_digest().unwrap();
    assert!(!format!("{config:?}").contains("synthetic"));
    assert!(config.client_allowlist_file.is_none());
    let mut policy = fields.clone();
    *policy.get_mut("version").expect("version") = json!("2");
    let _: logbrew_mcp::Failure =
        Config::decode(&serde_json::to_vec(&policy).expect("version 2")).unwrap_err();
    for reference in [json!(""), json!(null), json!([]), json!(42_i32)] {
        drop(
            policy
                .as_object_mut()
                .expect("configuration")
                .insert("client_allowlist_file".to_owned(), reference),
        );
        let _: logbrew_mcp::Failure =
            Config::decode(&serde_json::to_vec(&policy).expect("invalid reference")).unwrap_err();
    }
    *policy.get_mut("client_allowlist_file").expect("reference") = json!("/synthetic/clients.json");
    let policy_bytes = serde_json::to_vec(&policy).expect("policy reference");
    assert_eq!(
        Config::decode(&policy_bytes)
            .expect("version 2")
            .client_allowlist_file
            .as_deref(),
        Some("/synthetic/clients.json")
    );
    *policy.get_mut("version").expect("version") = json!("1");
    drop(Config::decode(&serde_json::to_vec(&policy).expect("additive policy")).unwrap());
    *policy.get_mut("version").expect("version") = json!("3");
    let _: logbrew_mcp::Failure =
        Config::decode(&serde_json::to_vec(&policy).expect("unsupported version")).unwrap_err();
    let mut inline = fields;
    drop(inline.as_object_mut().expect("object").insert(
        "client_secret".to_owned(),
        json!("SYNTHETIC_PRIVATE_MARKER"),
    ));
    let _: logbrew_mcp::Failure =
        Config::decode(&serde_json::to_vec(&inline).expect("inline field")).unwrap_err();
    let _: logbrew_mcp::Failure =
        Config::decode(b"{\"version\":\"1\",\"version\":\"1\"}").unwrap_err();
}
