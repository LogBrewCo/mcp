//! Admission lasts while a response body or any of its output buffers is retained.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    body::{Body, Bytes, HttpBody},
    response::Response,
};
use http_body::{Frame, SizeHint};
use tokio::sync::OwnedSemaphorePermit;

use crate::delivery::{Connection, Delivery};
use crate::telemetry::{Stage, Telemetry};

struct Admission {
    _permit: Arc<OwnedSemaphorePermit>,
    _delivery: Delivery,
}

struct AdmittedBody {
    inner: Body,
    admission: Arc<Admission>,
}

struct AdmittedBytes {
    inner: Bytes,
    _admission: Arc<Admission>,
}

impl AsRef<[u8]> for AdmittedBytes {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

pub fn hold(
    response: Response,
    permit: OwnedSemaphorePermit,
    connection: Option<Connection>,
    telemetry: &Telemetry,
) -> Response {
    response.map(|inner| {
        if inner.is_end_stream() {
            drop(permit);
            inner
        } else {
            let permit = Arc::new(permit);
            Body::new(AdmittedBody {
                inner,
                admission: Arc::new(Admission {
                    _delivery: Delivery::new(
                        connection,
                        Arc::clone(&permit),
                        telemetry.begin(Stage::ResponseRetained),
                    ),
                    _permit: permit,
                }),
            })
        }
    })
}

impl HttpBody for AdmittedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_frame(cx)
            .map(|frame| frame.map(|frame| frame.map(|frame| hold_frame(frame, &this.admission))))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn hold_frame(frame: Frame<Bytes>, admission: &Arc<Admission>) -> Frame<Bytes> {
    frame.map_data(|inner| {
        Bytes::from_owner(AdmittedBytes {
            inner,
            _admission: Arc::clone(admission),
        })
    })
}
