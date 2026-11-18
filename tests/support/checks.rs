//! Test checks that return an error instead of panicking.
//!
//! Tests that return `Result` use these in place of the assert macros, so a
//! failed check reports the same location, expression and values without a
//! panic inside a function that returns `Result`.

use core::fmt;

/// A failed check, shown verbatim when a test returns it.
pub struct Failed(pub String);

impl fmt::Debug for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for Failed {}

/// Return an error from the enclosing function when the condition is false.
macro_rules! ensure {
    ($condition:expr $(,)?) => {
        $crate::checks::ensure!($condition, "check failed: {}", stringify!($condition))
    };
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err($crate::checks::Failed(format!(
                "{}:{}: {}",
                file!(),
                line!(),
                format_args!($($message)+)
            ))
            .into());
        }
    };
}

/// Return an error from the enclosing function when the values are not equal.
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => $crate::checks::ensure!(
                *left == *right,
                "`{}` == `{}` failed\n  left: {:?}\n right: {:?}",
                stringify!($left),
                stringify!($right),
                left,
                right
            ),
        }
    };
}

pub(crate) use {ensure, ensure_eq};
