//! Response delivery expires independently of body polling and flow control.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::telemetry::{Measurement, Outcome};

const RETAINED: u8 = 0;
const RELEASED: u8 = 1;
const EXPIRED: u8 = 2;

#[derive(Clone)]
pub struct Connection(pub CancellationToken);

pub struct Delivery {
    finished: CancellationToken,
    state: Arc<AtomicU8>,
    connection: Option<Connection>,
    measurement: Option<Measurement>,
}

impl Delivery {
    pub fn new(
        connection: Option<Connection>,
        permit: Arc<OwnedSemaphorePermit>,
        measurement: Measurement,
    ) -> Self {
        let finished = CancellationToken::new();
        let state = Arc::new(AtomicU8::new(RETAINED));
        if let Some(connection) = connection.clone() {
            let completion = finished.clone();
            let retained = Arc::clone(&state);
            let now = Instant::now();
            let deadline = now.checked_add(Duration::from_secs(10)).unwrap_or(now);
            drop(tokio::spawn(retain_until_finished(
                connection, permit, completion, retained, deadline,
            )));
        }
        Self {
            finished,
            state,
            connection,
            measurement: Some(measurement),
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        let state =
            self.state
                .compare_exchange(RETAINED, RELEASED, Ordering::AcqRel, Ordering::Acquire);
        self.finished.cancel();
        if let Some(measurement) = self.measurement.take() {
            measurement.finish(delivery_outcome(state, self.connection.as_ref()));
        }
    }
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio select uses remainder for fair branch polling; this is not cryptographic arithmetic."
)]
async fn retain_until_finished(
    connection: Connection,
    permit: Arc<OwnedSemaphorePermit>,
    completion: CancellationToken,
    retained: Arc<AtomicU8>,
    deadline: Instant,
) {
    tokio::select! {
        () = completion.cancelled() => {},
        () = tokio::time::sleep_until(deadline) => {
            // Close the owning connection so Hyper drops its retained
            // buffers before admission can be reused. PING activity
            // and stream window changes cannot refresh this deadline.
            if retained.compare_exchange(
                RETAINED, EXPIRED, Ordering::AcqRel, Ordering::Acquire
            ).is_ok() {
                connection.0.cancel();
            }
        }
    }
    // A timer retains admission until it exits. Completed bodies
    // cannot create an unbounded queue of unpolled timer tasks.
    drop(permit);
}

fn delivery_outcome(state: Result<u8, u8>, connection: Option<&Connection>) -> Outcome {
    if state == Err(EXPIRED) {
        Outcome::Deadline
    } else if connection.is_some_and(|connection| connection.0.is_cancelled()) {
        Outcome::Cancelled
    } else {
        Outcome::Released
    }
}
