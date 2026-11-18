//! Await whichever of two futures finishes first.

use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};

/// The output of the future that finished first.
pub enum First<Left, Right> {
    /// The left future finished first, or both finished on the same poll.
    Left(Left),
    /// The right future finished first.
    Right(Right),
}

/// Poll the left future, then the right one, until one of them finishes.
pub async fn first<Left, Right>(left: Left, right: Right) -> First<Left::Output, Right::Output>
where
    Left: Future,
    Right: Future,
{
    let mut left = pin!(left);
    let mut right = pin!(right);
    poll_fn(|context| match left.as_mut().poll(context) {
        Poll::Ready(output) => Poll::Ready(First::Left(output)),
        Poll::Pending => right.as_mut().poll(context).map(First::Right),
    })
    .await
}
