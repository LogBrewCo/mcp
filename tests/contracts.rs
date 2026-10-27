//! Adversarial contract and startup regressions use synthetic data only.

extern crate alloc;

use alloc::sync::Arc;

use logbrew_mcp::{catalog::Catalog, json, startup::Config};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn artifact(schema: &Value) -> Vec<u8> {
    json!({"format_version":1,"operations":[{
        "id":"logs.read.v1","info":{"summary":"Read selected logs","permission":"read",
            "documentation":"https://docs.example/logs","stability":"stable","cost":"one read","safety":"read_only"},
        "input_schema":schema,"output_schema":{"type":"object","additionalProperties":false,
            "required":["count"],"properties":{"count":{"type":"integer"}}}
    }]}).to_string().into_bytes()
}

#[test]
/// # Panics
///
/// Panics if catalog lookup classifies invalid identifiers as unknown operations
/// or counts Unicode bytes instead of schema characters on any boundary.
fn operation_identifier_errors_agree_across_catalog_boundaries() {
    let bytes = artifact(&json!({"type":"object"}));
    let catalog = Catalog::load(&bytes, &Sha256::digest(&bytes).into()).expect("catalog");
    for (id, expected) in [
        (String::new(), logbrew_mcp::error::Kind::InvalidInput),
        ("a".repeat(129), logbrew_mcp::error::Kind::InvalidInput),
        (
            "\u{1f980}".repeat(129),
            logbrew_mcp::error::Kind::InvalidInput,
        ),
        (
            "\u{1f980}".repeat(128),
            logbrew_mcp::error::Kind::UnknownOperation,
        ),
    ] {
        assert_eq!(
            catalog
                .search(&json!({"operation":id}))
                .expect_err("selection")
                .kind,
            expected
        );
        assert_eq!(
            catalog.input(&id, &json!({})).expect_err("input").kind,
            expected
        );
        assert_eq!(
            catalog
                .output(&id, &json!({"count":3_i32}))
                .expect_err("output")
                .kind,
            expected
        );
    }
}

/// Build a catalog with the same pattern on both validation boundaries.
///
/// # Errors
/// Returns an error if synthetic catalog decoding or validation fails.
fn pattern_catalog(pattern: &str) -> Result<Arc<Catalog>, logbrew_mcp::Failure> {
    let schema = json!({"type":"object","required":["text"],"additionalProperties":false,
        "properties":{"text":{"type":"string","pattern":pattern}}});
    let mut document = json::object(&artifact(&schema), 8 << 20)?;
    *document
        .pointer_mut("/operations/0/output_schema")
        .ok_or(logbrew_mcp::error::Kind::Configuration)? = schema;
    let bytes = document.to_string().into_bytes();
    Catalog::load(&bytes, &Sha256::digest(&bytes).into())
}

#[test]
/// # Panics
///
/// Panics if contract patterns reject ECMAScript whitespace or accept characters
/// outside that set on either the input or output boundary.
fn unicode_whitespace_patterns_preserve_input_and_output_contracts() {
    let catalog = pattern_catalog(r"^\s+$").expect("whitespace contract");
    for accepted in [
        "\t", "\n", "\u{b}", "\u{c}", "\r", " ", "\u{a0}", "\u{1680}", "\u{2000}", "\u{2001}",
        "\u{2002}", "\u{2003}", "\u{2004}", "\u{2005}", "\u{2006}", "\u{2007}", "\u{2008}",
        "\u{2009}", "\u{200a}", "\u{2028}", "\u{2029}", "\u{202f}", "\u{205f}", "\u{3000}",
        "\u{feff}",
    ] {
        let value = json!({"text":accepted});
        catalog
            .input("logs.read.v1", &value)
            .expect("permitted input");
        catalog
            .output("logs.read.v1", &value)
            .expect("permitted output");
    }
    for rejected in ["", "A", "\u{85}", "\u{200b}"] {
        let value = json!({"text":rejected});
        assert!(catalog.input("logs.read.v1", &value).is_err());
        assert!(catalog.output("logs.read.v1", &value).is_err());
    }
}

#[test]
/// # Panics
///
/// Panics if literal characters in contract patterns become Rust set operators
/// or characters outside the declared class pass either validation boundary.
fn character_class_literals_preserve_input_and_output_contracts() {
    let catalog = pattern_catalog("^[a&&b~~c]+$").expect("literal character contract");
    for accepted in ["a", "&", "b", "~", "c", "a&b~c", "a&&b~~c"] {
        let value = json!({"text":accepted});
        catalog
            .input("logs.read.v1", &value)
            .expect("permitted input");
        catalog
            .output("logs.read.v1", &value)
            .expect("permitted output");
    }
    for rejected in ["", "d", "a-d", "\n"] {
        let value = json!({"text":rejected});
        assert!(catalog.input("logs.read.v1", &value).is_err());
        assert!(catalog.output("logs.read.v1", &value).is_err());
    }
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
/// Panics if the loader admits an operation that needs a scope other than
/// `read` or `write`, or that is not read-only, or rejects a `write` permission.
fn catalog_admits_read_or_write_permissions_and_only_read_only_operations() {
    for (field, value) in [
        ("permission", "logs:read"),
        ("permission", "READ"),
        ("permission", "WRITE"),
        ("permission", "read write"),
        ("permission", "write read"),
        ("permission", "admin"),
        ("safety", "write"),
        ("safety", "destructive"),
    ] {
        let mut document: Value =
            serde_json::from_slice(&artifact(&json!({"type":"object"}))).expect("artifact");
        *document
            .pointer_mut(&format!("/operations/0/info/{field}"))
            .expect("field") = json!(value);
        let bytes = serde_json::to_vec(&document).expect("encoded artifact");
        let failure = Catalog::load(&bytes, &Sha256::digest(&bytes).into())
            .err()
            .expect("rejected catalog");
        assert_eq!(failure.kind, logbrew_mcp::error::Kind::Configuration);
    }
    let mut document: Value =
        serde_json::from_slice(&artifact(&json!({"type":"object"}))).expect("artifact");
    *document
        .pointer_mut("/operations/0/info/permission")
        .expect("permission") = json!("write");
    let bytes = serde_json::to_vec(&document).expect("encoded artifact");
    let catalog = Catalog::load(&bytes, &Sha256::digest(&bytes).into()).expect("write catalog");
    assert_eq!(
        catalog
            .search(&json!({"operation":"logs.read.v1"}))
            .expect("contract")
            .pointer("/info/permission"),
        Some(&json!("write"))
    );
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

/// A complete version 5 configuration with synthetic file references.
fn configuration_fields() -> serde_json::Value {
    json!({"version":"5","listen":"127.0.0.1:8080","resource":"https://resource.example/mcp",
        "admission":{"burst":16_u32,"per_minute":600_u32,"tracked_clients":1_024_u32,"rejected_token_seconds":30_u32},
        "issuer":"https://issuer.example",
        "introspection_endpoint":"https://service.example/introspect",
        "execution_endpoint":"https://service.example/execute",
        "service_client_id":"machine","service_secret_file":"/synthetic/service",
        "catalog_file":"/synthetic/catalog","catalog_sha256":"00".repeat(32),
        "certificate_file":"/synthetic/certificate","private_key_file":"/synthetic/key"})
}

#[test]
/// # Panics
///
/// Panics if fixture encoding fails, or if a version 4 configuration or a
/// `client_allowlist_file` field is accepted, with or without the other change.
fn configuration_rejects_version_4_and_the_removed_client_allowlist_file() {
    let decode = |value: &serde_json::Value| {
        Config::decode(&serde_json::to_vec(value).expect("configuration"))
    };
    let current = configuration_fields();
    drop(decode(&current).expect("version 5 without a client allowlist"));
    let mut previous = current.clone();
    *previous.get_mut("version").expect("version") = json!("4");
    let mut listed = current;
    drop(listed.as_object_mut().expect("object").insert(
        "client_allowlist_file".to_owned(),
        json!("/synthetic/clients.json"),
    ));
    let mut previous_listed = listed.clone();
    *previous_listed.get_mut("version").expect("version") = json!("4");
    for rejected in [previous, listed, previous_listed] {
        let failure = decode(&rejected).unwrap_err();
        assert_eq!(failure.kind, logbrew_mcp::error::Kind::Configuration);
    }
}

#[test]
/// # Panics
///
/// Panics if a telemetry endpoint is accepted without its key file or the
/// reverse, or if a complete pair is rejected or changed.
fn telemetry_export_needs_an_endpoint_and_a_key_file_together() {
    let fields = configuration_fields();
    let decode = |value: &serde_json::Value| {
        Config::decode(&serde_json::to_vec(value).expect("configuration"))
    };
    let config = decode(&fields).expect("no telemetry export");
    assert_eq!(config.telemetry_endpoint, None);
    let mut exported = fields.clone();
    for (field, value) in [
        ("telemetry_endpoint", "https://ingest.example/v1/events"),
        ("telemetry_key_file", "/synthetic/ingest-key"),
    ] {
        let mut alone = fields.clone();
        let object = alone.as_object_mut().expect("object");
        drop(object.insert(field.to_owned(), json!(value)));
        let _: logbrew_mcp::Failure = decode(&alone).unwrap_err();
        drop(
            exported
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), json!(value)),
        );
    }
    let exported = decode(&exported).expect("telemetry export");
    assert_eq!(
        exported.telemetry_key_file.as_deref(),
        Some("/synthetic/ingest-key")
    );
}

#[test]
/// # Panics
///
/// Panics if fixture encoding fails or version 5 stops requiring one service
/// login, secret-file references and bounded admission limits, or accepts other
/// versions, superseded fields, inline secrets or duplicate fields.
fn configuration_requires_one_service_login_and_secret_file_references() {
    let fields = configuration_fields();
    let decode = |value: &serde_json::Value| {
        Config::decode(&serde_json::to_vec(value).expect("configuration"))
    };
    let config = decode(&fields).expect("secret references only");
    let _: (core::net::SocketAddr, [u8; 32]) = config.address_digest().unwrap();
    assert!(!format!("{config:?}").contains("synthetic"));
    assert_eq!(config.service_secret_file, "/synthetic/service");
    for version in ["1", "2", "3", "4", "6"] {
        let mut changed = fields.clone();
        *changed.get_mut("version").expect("version") = json!(version);
        let _: logbrew_mcp::Failure = decode(&changed).unwrap_err();
    }
    for field in ["service_client_id", "service_secret_file"] {
        let mut missing = fields.clone();
        drop(missing.as_object_mut().expect("object").remove(field));
        let _: logbrew_mcp::Failure = decode(&missing).unwrap_err();
        for reference in [json!(""), json!(null), json!([]), json!(42_i32)] {
            let mut invalid = fields.clone();
            *invalid.get_mut(field).expect("field") = reference;
            let _: logbrew_mcp::Failure = decode(&invalid).unwrap_err();
        }
    }
    for (field, value) in [
        ("required_scope", "read"),
        ("introspection_client_id", "machine"),
        ("execution_secret_file", "/synthetic/execution"),
        ("client_secret", "SYNTHETIC_PRIVATE_MARKER"),
    ] {
        let mut extra = fields.clone();
        drop(
            extra
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), json!(value)),
        );
        let _: logbrew_mcp::Failure = decode(&extra).unwrap_err();
    }
    let _: logbrew_mcp::Failure =
        Config::decode(b"{\"version\":\"5\",\"version\":\"5\"}").unwrap_err();
    assert_eq!(config.admission.burst, 16);
    assert_eq!(config.admission.trusted_proxy, None);
    let limits = json!({"burst":16_u32,"per_minute":600_u32,"tracked_clients":1_024_u32,"rejected_token_seconds":30_u32});
    let mut proxied = fields.clone();
    *proxied.pointer_mut("/admission").expect("admission") = json!({"burst":1_u32,"per_minute":1_u32,"tracked_clients":1_u32,"rejected_token_seconds":0_u32,"trusted_proxy":"127.0.0.1"});
    assert!(
        decode(&proxied)
            .expect("proxied")
            .admission
            .trusted_proxy
            .is_some()
    );
    let mut missing = fields.clone();
    drop(missing.as_object_mut().expect("object").remove("admission"));
    let _: logbrew_mcp::Failure = decode(&missing).unwrap_err();
    for (field, value) in [
        ("burst", json!(0_i32)),
        ("burst", json!(65_i32)),
        ("per_minute", json!(0_i32)),
        ("tracked_clients", json!(0_i32)),
        ("rejected_token_seconds", json!(301_i32)),
        ("trusted_proxy", json!("proxy.example")),
        ("burst", json!("16")),
        ("unknown", json!(1_i32)),
    ] {
        let mut changed = fields.clone();
        let mut admission = limits.clone();
        drop(
            admission
                .as_object_mut()
                .expect("limits")
                .insert(field.to_owned(), value),
        );
        *changed.pointer_mut("/admission").expect("admission") = admission;
        let _: logbrew_mcp::Failure = decode(&changed).unwrap_err();
    }
}
