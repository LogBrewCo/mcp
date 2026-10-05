use std::{future::Future, time::Duration};

pub async fn within<T>(budget: Duration, work: impl Future<Output = T>) -> Option<T> {
    let deadline = tokio::time::Instant::now().checked_add(budget)?;
    // Timeout polls work before its timer. Reject a late completed result too.
    match tokio::time::timeout_at(deadline, work).await {
        Ok(result) if tokio::time::Instant::now() < deadline => Some(result),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, pending, poll_fn, ready},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    use tokio::sync::{OwnedSemaphorePermit, Semaphore};

    use super::within;

    fn delayed_ready() -> impl Future<Output = i32> {
        poll_fn(|_| {
            std::thread::sleep(Duration::from_millis(20));
            Poll::Ready(7_i32)
        })
    }

    async fn held_pending(permit: OwnedSemaphorePermit, polled: &AtomicBool) {
        let _permit = permit;
        polled.store(true, Ordering::SeqCst);
        pending::<()>().await;
    }

    /// Accept work completed before its representable deadline.
    ///
    /// # Panics
    /// Panics if a promptly completed future is rejected or its result changes.
    #[tokio::test]
    async fn accepts_completion_before_deadline() {
        assert_eq!(
            within(Duration::from_secs(1), ready(7_i32)).await,
            Some(7_i32)
        );
    }

    /// Reject a result whose poll completes after the deadline.
    ///
    /// # Panics
    /// Panics if the late completed result is accepted.
    #[tokio::test]
    async fn rejects_ready_completion_after_deadline() {
        assert_eq!(
            within(Duration::from_millis(5), delayed_ready()).await,
            None
        );
    }

    /// Drop expired pending work and recover its semaphore capacity.
    ///
    /// # Errors
    /// Returns an error if the initial or recovered semaphore permit is unavailable.
    ///
    /// # Panics
    /// Panics if pending work is not polled or rejected, or timely recovery fails.
    #[tokio::test]
    // Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions must retain their failure and comparison diagnostics."
    )]
    async fn expiry_drops_pending_work_and_allows_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let slots = Arc::new(Semaphore::new(1));
        let polled = AtomicBool::new(false);
        let work = held_pending(Arc::clone(&slots).try_acquire_owned()?, &polled);
        assert_eq!(within(Duration::from_millis(5), work).await, None);
        assert!(polled.load(Ordering::SeqCst));
        let _recovered = slots.try_acquire()?;
        assert_eq!(
            within(Duration::from_secs(1), ready(7_i32)).await,
            Some(7_i32)
        );
        Ok(())
    }

    /// Reject an unrepresentable deadline before polling work and release its permit.
    ///
    /// # Errors
    /// Returns an error if the initial or recovered semaphore permit is unavailable.
    ///
    /// # Panics
    /// Panics if invalid-budget work is polled or accepted, or timely recovery fails.
    #[tokio::test]
    // Reviewed 2026-10-05; review by 2026-11-05 or on source/toolchain change.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions must retain their failure and comparison diagnostics."
    )]
    async fn unrepresentable_deadline_drops_work_without_polling_and_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let slots = Arc::new(Semaphore::new(1));
        let polled = AtomicBool::new(false);
        let work = held_pending(Arc::clone(&slots).try_acquire_owned()?, &polled);
        assert_eq!(within(Duration::MAX, work).await, None);
        assert!(!polled.load(Ordering::SeqCst));
        let _recovered = slots.try_acquire()?;
        assert_eq!(
            within(Duration::from_secs(1), ready(7_i32)).await,
            Some(7_i32)
        );
        Ok(())
    }
}
