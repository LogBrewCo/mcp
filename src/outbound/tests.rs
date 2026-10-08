//! Connection completion and ownership at the deadline boundary.

use alloc::sync::Arc;
use core::{
    future::{pending, poll_fn, ready},
    task::Poll,
    time::Duration,
};
use std::io;

use super::{ConnectError, connect};

/// Reject a late ready connection and drop its returned resource.
///
/// # Panics
/// Fails if the completed poll bypasses the budget or retains its resource.
#[tokio::test]
async fn late_ready_connection_is_rejected_and_released() {
    let resource = Arc::new(());
    let observed = Arc::downgrade(&resource);
    let connecting = poll_fn(move |_| {
        std::thread::sleep(Duration::from_millis(20));
        Poll::Ready(Ok(Arc::clone(&resource)))
    });
    let result = connect(Duration::from_millis(5), connecting).await;
    assert_eq!(
        result.map_err(|error| error.downcast_ref::<io::Error>().map(io::Error::kind)),
        Err(Some(io::ErrorKind::TimedOut))
    );
    assert!(observed.upgrade().is_none());
}

/// Preserve promptly completed connection values and original connector errors.
///
/// # Panics
/// Fails if timely success or the original failure classification changes.
#[tokio::test]
async fn prompt_connection_success_and_failure_are_preserved() {
    assert_eq!(
        connect(Duration::from_secs(1), ready(Ok(7_i32)))
            .await
            .map_err(|error| error.downcast_ref::<io::Error>().map(io::Error::kind)),
        Ok(7_i32)
    );
    let failure: ConnectError = io::Error::from(io::ErrorKind::ConnectionRefused).into();
    assert_eq!(
        connect(
            Duration::from_secs(1),
            ready(Err::<(), ConnectError>(failure))
        )
        .await
        .map_err(|error| error.downcast_ref::<io::Error>().map(io::Error::kind)),
        Err(Some(io::ErrorKind::ConnectionRefused))
    );
}

/// Drop expired pending connection work and allow a later connection to complete.
///
/// # Panics
/// Fails if expiration retains the pending resource or prevents recovery.
#[tokio::test]
async fn pending_connection_expires_releases_ownership_and_recovers() {
    let resource = Arc::new(());
    let observed = Arc::downgrade(&resource);
    let connecting = async move {
        let completion = pending::<Result<(), ConnectError>>().await;
        drop(resource);
        completion
    };
    let result = connect(Duration::from_millis(5), connecting).await;
    assert!(observed.upgrade().is_none());
    assert_eq!(
        result.map_err(|error| error.downcast_ref::<io::Error>().map(io::Error::kind)),
        Err(Some(io::ErrorKind::TimedOut))
    );
    assert_eq!(
        connect(Duration::from_secs(1), ready(Ok(11_i32)))
            .await
            .map_err(|error| error.downcast_ref::<io::Error>().map(io::Error::kind)),
        Ok(11_i32)
    );
}
