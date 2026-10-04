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
        future::{pending, ready},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::Semaphore;

    use super::within;

    #[tokio::test]
    async fn accepts_completion_before_deadline() {
        assert_eq!(
            within(Duration::from_secs(1), ready(7_i32)).await,
            Some(7_i32)
        );
    }

    #[tokio::test]
    async fn rejects_ready_completion_after_deadline() {
        let work = async {
            std::thread::sleep(Duration::from_millis(20));
            7_i32
        };
        assert_eq!(within(Duration::from_millis(5), work).await, None);
    }

    #[tokio::test]
    async fn expiry_drops_pending_work_and_allows_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned()?;
        let polled = AtomicBool::new(false);
        let work = async {
            let _permit = permit;
            polled.store(true, Ordering::SeqCst);
            pending::<()>().await;
        };
        assert_eq!(within(Duration::from_millis(5), work).await, None);
        assert!(polled.load(Ordering::SeqCst));
        let _recovered = slots.try_acquire()?;
        assert_eq!(
            within(Duration::from_secs(1), ready(7_i32)).await,
            Some(7_i32)
        );
        Ok(())
    }

    #[tokio::test]
    async fn unrepresentable_deadline_drops_work_without_polling_and_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned()?;
        let polled = AtomicBool::new(false);
        let work = async {
            let _permit = permit;
            polled.store(true, Ordering::SeqCst);
            pending::<()>().await;
        };
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
