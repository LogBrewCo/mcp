//! Issuer scope lists grant only complete, case-sensitive RFC 6749 tokens.

use core::sync::atomic::Ordering;

use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use super::http::{Fixture, TOKEN};

#[tokio::test]
/// # Panics
///
/// Panics if token order changes access, a partial or case-folded grant permits
/// execution, fresh authority does not recover, or private scopes are disclosed.
async fn scope_grants_require_complete_case_sensitive_tokens() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let params = json!({"name":"execute",
        "arguments":{"operation":"logs.read.v1","input":{}}});
    for scope in [
        "mcp:read",
        "mcp:read extra:scope",
        "extra:scope mcp:read",
        "extra:scope mcp:read another:scope",
        "mcp:read mcp:read",
    ] {
        let mut claims = base.clone();
        *claims.get_mut("scope").expect("scope claim") = json!(scope);
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("complete scope grant");
        let (status, result) = fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("authorized execution");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    let mut executions = 5;
    for scope in [
        "mcp:reader",
        "prefix:mcp:read",
        "mcp:read,extra:scope",
        "MCP:READ",
        "mcp:reaD",
        "offline_access",
        "SYNTHETIC_PRIVATE_SCOPE mcp:reader",
    ] {
        let mut claims = base.clone();
        *claims.get_mut("scope").expect("scope claim") = json!(scope);
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("different scope grant");
        let (status, result) = fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("scope denial");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!result.to_string().contains("SYNTHETIC_PRIVATE"));
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), executions);
        fixture
            .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
            .expect("fresh complete grant");
        assert_eq!(
            fixture
                .request("tools/call", params.clone(), TOKEN)
                .await
                .expect("scope recovery")
                .0,
            StatusCode::OK
        );
        executions += 1;
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), executions);
    }
    assert_eq!(executions, 12);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 19);
    let observations =
        serde_json::to_string(&fixture.telemetry().snapshot().expect("observations"))
            .expect("telemetry JSON");
    assert!(!observations.contains(TOKEN));
    assert!(!observations.contains("SYNTHETIC_PRIVATE"));
}

#[tokio::test]
/// # Panics
///
/// Panics if a complete token rescues malformed scope syntax, rejection starts
/// execution, private authority is disclosed, or repaired authority cannot recover.
async fn malformed_scope_lists_cannot_be_rescued_by_complete_tokens() {
    let fixture = Fixture::new().await.expect("fixture");
    let base = fixture.authority().expect("issuer claims");
    let params = json!({"name":"execute",
        "arguments":{"operation":"logs.read.v1","input":{}}});
    for scope in [
        "",
        " mcp:read",
        "mcp:read ",
        "mcp:read  SYNTHETIC_PRIVATE_SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\tSCOPE",
        "mcp:read SYNTHETIC_PRIVATE\nSCOPE",
        "mcp:read SYNTHETIC_PRIVATE\rSCOPE",
        "mcp:read SYNTHETIC_PRIVATE\u{000b}SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\0SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\u{007f}SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\"SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\\SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\u{00a0}SCOPE",
        "mcp:read SYNTHETIC_PRIVATE\u{00e9}SCOPE",
    ]
    .map(str::to_owned)
    .into_iter()
    .chain(core::iter::once(format!("mcp:read {}", "s".repeat(8193))))
    {
        let mut claims = base.clone();
        *claims.get_mut("scope").expect("scope claim") = json!(scope);
        fixture
            .introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())
            .expect("malformed issuer grant");
        let (status, result) = fixture
            .request("tools/call", params.clone(), TOKEN)
            .await
            .expect("invalid grant rejection");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!result.to_string().contains("SYNTHETIC_PRIVATE"));
        assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 0);
    }
    fixture
        .introspection_reply(StatusCode::OK, base.to_string(), HeaderMap::new())
        .expect("repaired issuer grant");
    assert_eq!(
        fixture
            .request("tools/call", params, TOKEN)
            .await
            .expect("scope recovery")
            .0,
        StatusCode::OK
    );
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 16);
}

#[tokio::test]
/// # Panics
///
/// Panics if RFC scope punctuation or an exact-limit token is rejected, token
/// placement changes access, or an accepted grant does not start one execution.
async fn rfc_scope_characters_and_exact_token_byte_limit_allow_execution() {
    // RFC 6749 section 3.3: %x21 / %x23-5B / %x5D-7E.
    let alphabet = concat!(
        "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[",
        "]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    );
    for required in [alphabet.to_owned(), "s".repeat(8192)] {
        assert_scope_positions(&required)
            .await
            .expect("scope positions");
    }
}

/// # Errors
///
/// Returns fixture, claim or request errors without replacing their diagnostics.
///
/// # Panics
///
/// Panics if a permitted token fails in any position or execution totals change.
async fn assert_scope_positions(required: &str) -> super::TestResult<()> {
    let fixture = Fixture::with_scope(required.to_owned()).await?;
    let base = fixture.authority()?;
    for scope in [
        format!("{required} extra:scope"),
        format!("extra:scope {required} another:scope"),
        format!("extra:scope {required}"),
    ] {
        let mut claims = base.clone();
        *claims.get_mut("scope").ok_or("scope claim")? = json!(scope);
        fixture.introspection_reply(StatusCode::OK, claims.to_string(), HeaderMap::new())?;
        let (status, result) = fixture
            .request(
                "tools/call",
                json!({"name":"execute",
                        "arguments":{"operation":"logs.read.v1","input":{}}}),
                TOKEN,
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result.pointer("/result/structuredContent/data/count"),
            Some(&json!(3_i32))
        );
    }
    assert_eq!(fixture.state().calls().load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state().verifies().load(Ordering::SeqCst), 3);
    Ok(())
}
