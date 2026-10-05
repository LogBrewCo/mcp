//! Trusted allowlists reject ambiguous policy before serving requests.

use logbrew_mcp::{
    clients::ClientAllowlist,
    error::Kind,
    upstream::{MachineCredential, Principal, Upstream, UpstreamOptions},
};
use serde_json::json;
use zeroize::Zeroizing;

#[test]
fn client_policy_rejects_invalid_and_ambiguous_documents() {
    for document in [
        b"[]".as_slice(),
        b"{\"version\":\"1\"}",
        b"{\"version\":1,\"clients\":[]}",
        b"{\"version\":\"2\",\"clients\":[]}",
        b"{\"version\":\"1\",\"clients\":null}",
        b"{\"version\":\"1\",\"clients\":[1]}",
        b"{\"version\":\"1\",\"clients\":[\"\"]}",
        b"{\"version\":\"1\",\"clients\":[\"invalid client\"]}",
        b"{\"version\":\"1\",\"clients\":[\"invalid,client\"]}",
        b"{\"version\":\"1\",\"clients\":[\"client\\n\"]}",
        b"{\"version\":\"1\",\"clients\":[\"client\",\"client\"]}",
        b"{\"version\":\"1\",\"clients\":[\"client\",\"\\u0063\\u006c\\u0069\\u0065\\u006e\\u0074\"]}",
        b"{\"version\":\"1\",\"clients\":[],\"clients\":[]}",
        b"{\"version\":\"1\",\"clients\":[],\"mode\":\"allow_all\"}",
        b"{\"version\":\"1\",\"clients\":[]} trailing",
    ] {
        let _: logbrew_mcp::Failure = ClientAllowlist::decode(document).unwrap_err();
    }
}

#[test]
/// # Panics
///
/// Panics if a synthetic policy cannot be encoded, an entry, identifier or
/// document bound changes, or debug output reveals a client identifier.
fn client_policy_has_exact_entry_id_and_document_bounds() {
    let encode = |clients| serde_json::to_vec(&json!({"version":"1","clients":clients}));
    for count in [0_i32, 1_i32, 64_i32, 65_i32] {
        let clients: Vec<_> = (0_i32..count)
            .map(|n| format!("synthetic-client-{n}"))
            .collect();
        assert_eq!(
            ClientAllowlist::decode(&encode(clients).expect("policy")).is_ok(),
            count <= 64_i32
        );
    }
    for length in [2048, 2049] {
        assert_eq!(
            ClientAllowlist::decode(&encode(vec!["x".repeat(length)]).expect("policy")).is_ok(),
            length == 2048
        );
    }
    let mut bytes =
        encode(vec!["https://client.example/metadata.json".to_owned()]).expect("URL ID");
    bytes.resize(16 << 10, b' ');
    let policy = ClientAllowlist::decode(&bytes).expect("exact document limit");
    assert!(!format!("{policy:?}").contains("client.example"));
    bytes.push(b' ');
    let _: logbrew_mcp::Failure = ClientAllowlist::decode(&bytes).unwrap_err();
}

#[tokio::test]
/// # Panics
///
/// Panics if the synthetic client cannot be constructed or a missing or empty
/// allowlist does not deny execution before contacting the unavailable service.
async fn direct_execution_cannot_bypass_missing_or_empty_client_policy() {
    let credential = || {
        MachineCredential::new(
            "synthetic-machine".to_owned(),
            Zeroizing::new("SYNTHETIC_SECRET".to_owned()),
        )
        .expect("machine credential")
    };
    let principal = Principal {
        credential_id: "synthetic-credential".to_owned(),
        client_id: "synthetic-client".to_owned(),
    };
    for policy in [None, Some(ClientAllowlist::default())] {
        let mut upstream = Upstream::new(UpstreamOptions {
            introspection_endpoint: "https://127.0.0.1:1/introspect".to_owned(),
            execution_endpoint: "https://127.0.0.1:1/execute".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            resource: "https://resource.example/mcp".to_owned(),
            required_scope: "mcp:read".to_owned(),
            introspection_credential: credential(),
            execution_credential: credential(),
        })
        .expect("offline client");
        upstream = match policy {
            Some(policy) => upstream.with_client_allowlist(policy),
            None => upstream,
        };
        let failure = upstream
            .execute(&principal, "SYNTHETIC_TOKEN", "logs.read.v1", &json!({}))
            .await
            .expect_err("unlisted client rejected before unavailable endpoint");
        assert_eq!(failure.kind, Kind::PermissionDenied);
    }
}
