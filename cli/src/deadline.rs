// SPDX-License-Identifier: Apache-2.0

//! Command-wide monotonic deadlines and cancellation checks.

use std::time::{Duration, Instant};

use crate::CliError;

/// Cooperative cancellation source for command execution.
pub trait Cancellation: Send + Sync {
    /// Returns true when the operation must stop.
    fn is_cancelled(&self) -> bool;
}

/// A cancellation source which never cancels.
#[derive(Debug, Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A command-wide timeout measured from construction using a monotonic clock.
#[derive(Debug, Clone)]
pub struct Deadline(Option<(Instant, Duration)>);

impl Deadline {
    /// Creates an optional deadline. A zero timeout is immediately expired.
    pub fn new(timeout: Option<Duration>) -> Self {
        Self(timeout.map(|duration| (Instant::now(), duration)))
    }

    /// Returns the time left, or `None` when no timeout was configured.
    pub fn remaining(&self) -> Option<Duration> {
        self.0
            .map(|(started, timeout)| timeout.saturating_sub(started.elapsed()))
    }

    /// Checks this deadline and a cooperative cancellation source.
    pub fn check(&self, cancellation: &dyn Cancellation) -> Result<(), CliError> {
        if cancellation.is_cancelled() {
            return Err(CliError::Cancelled);
        }
        if self
            .remaining()
            .is_some_and(|remaining| remaining.is_zero())
        {
            return Err(CliError::Timeout);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cancelled;
    impl Cancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn zero_deadline_is_expired_and_remaining_is_monotonic() {
        let deadline = Deadline::new(Some(Duration::ZERO));
        assert_eq!(deadline.remaining(), Some(Duration::ZERO));
        assert!(matches!(
            deadline.check(&NeverCancelled),
            Err(CliError::Timeout)
        ));
        assert_eq!(Deadline::new(None).remaining(), None);
    }

    #[test]
    fn cancellation_is_distinct_from_timeout() {
        assert!(matches!(
            Deadline::new(None).check(&Cancelled),
            Err(CliError::Cancelled)
        ));
    }
}
