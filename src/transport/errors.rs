use axum::{
    Json,
    body::{Body, to_bytes},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
};
use rmcp::ErrorData;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::identifiers::Reply;
use crate::{REQUEST_BYTES, media};

// Bound buffering even if SDK diagnostics quote body fields and routing headers.
const ERROR_BYTES: usize = 4 * REQUEST_BYTES;

#[derive(Deserialize)]
struct ErrorCode {
    code: i32,
}

#[derive(Serialize)]
struct FixedHeaderError<'a> {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a RawValue>,
    error: ErrorData,
}

pub async fn fixed_header_error(response: Response) -> Response {
    if response.status() != StatusCode::BAD_REQUEST || !media::json(response.headers()) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, ERROR_BYTES).await else {
        return unavailable();
    };
    let encoded = serde_json::from_slice::<Reply<'_>>(&bytes)
        .ok()
        .filter(|reply| reply.jsonrpc() == "2.0" && reply.result().is_none())
        .filter(|reply| {
            reply.error().is_some_and(|error| {
                serde_json::from_str::<ErrorCode>(error.get())
                    .is_ok_and(|error| error.code == -32020_i32)
            })
        })
        .map(|reply| {
            serde_json::to_vec(&FixedHeaderError {
                jsonrpc: "2.0",
                id: reply.id(),
                error: ErrorData::header_mismatch("invalid request headers", None),
            })
        });
    match encoded {
        Some(Ok(encoded)) => {
            drop(parts.headers.remove(header::CONTENT_LENGTH));
            Response::from_parts(parts, Body::from(encoded))
        }
        Some(Err(_)) => unavailable(),
        None => Response::from_parts(parts, Body::from(bytes)),
    }
}

fn unavailable() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "jsonrpc":"2.0","error":{"code":-32603,"message":"response unavailable"}
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use core::{
        pin::Pin,
        task::{Context, Poll},
    };
    use std::io;

    use super::*;

    type TestResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

    /// Verify that an unrelated response retains its status, headers and body bytes.
    ///
    /// # Errors
    /// Returns an error if response construction or bounded body reading fails.
    ///
    /// # Panics
    /// Panics if the status, content headers or exact body bytes change.
    async fn assert_unchanged(
        status: StatusCode,
        media_type: &str,
        bytes: &'static str,
    ) -> TestResult<()> {
        let response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, media_type)
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Body::from(bytes))?;
        let response = fixed_header_error(response).await;
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(media_type)
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(bytes.len().to_string().as_str())
        );
        assert_eq!(to_bytes(response.into_body(), ERROR_BYTES).await?, bytes);
        Ok(())
    }

    /// Verify that a rejected error body produces the fixed unavailable response.
    ///
    /// # Errors
    /// Returns an error if response construction or bounded body reading fails.
    ///
    /// # Panics
    /// Panics if the status, media type or fixed body differs from the contract.
    async fn assert_unavailable(body: Body) -> TestResult<()> {
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)?;
        let response = fixed_header_error(response).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            to_bytes(response.into_body(), 256).await?,
            r#"{"error":{"code":-32603,"message":"response unavailable"},"jsonrpc":"2.0"}"#
        );
        Ok(())
    }

    /// Check unrelated JSON, plain-text and malformed replies for exact preservation.
    ///
    /// # Errors
    /// Returns an error if fixture response construction or body reading fails.
    ///
    /// # Panics
    /// Panics if an unrelated reply's status, content headers or body changes.
    async fn unchanged_replies() -> TestResult<()> {
        for (status, media_type, bytes) in [
            (
                StatusCode::OK,
                "application/json",
                r#"{"jsonrpc":"2.0","id":1,"result":{"number":18446744073709551616}}"#,
            ),
            (
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"unsupported version","data":{"supported":["2026-07-28"]}}}"#,
            ),
            (
                StatusCode::BAD_REQUEST,
                "text/plain",
                "invalid content type",
            ),
            (
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"unexpected"},"result":null}"#,
            ),
            (StatusCode::BAD_REQUEST, "application/json", "invalid JSON"),
        ] {
            assert_unchanged(status, media_type, bytes).await?;
        }
        Ok(())
    }

    /// Preserve unrelated response bytes, including exact large JSON numbers.
    ///
    /// # Errors
    /// Returns an error if fixture response construction or body reading fails.
    ///
    /// # Panics
    /// Panics if an unrelated reply's status, content headers or body changes.
    #[tokio::test]
    async fn unrelated_replies_remain_byte_exact() -> TestResult<()> {
        unchanged_replies().await
    }

    struct FailedBody;

    impl http_body::Body for FailedBody {
        type Data = axum::body::Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err(io::Error::other(
                "SYNTHETIC_PRIVATE_BODY_FAILURE",
            ))))
        }
    }

    /// Replace oversized and failed SDK error bodies with fixed private-safe errors.
    ///
    /// # Errors
    /// Returns an error if fixture response construction or body reading fails.
    ///
    /// # Panics
    /// Panics if either rejection changes the fixed status, media type or error body.
    #[tokio::test]
    async fn oversized_and_failed_error_bodies_are_fixed() -> TestResult<()> {
        let failed = Body::new(FailedBody);
        assert_unavailable(Body::from(vec![b'x'; ERROR_BYTES + 1])).await?;
        assert_unavailable(failed).await?;
        Ok(())
    }
}
