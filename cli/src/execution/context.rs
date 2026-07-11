// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Cancellation, CliError};

/// Wall-clock source used only for persisted snapshot timestamps.
pub trait Clock: Send + Sync {
    /// Returns checked nanoseconds since the Unix epoch.
    fn unix_time_ns(&self) -> Result<u64, CliError>;
}

/// Production wall-clock implementation.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_time_ns(&self) -> Result<u64, CliError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                CliError::Fatal(format!("system clock precedes Unix epoch: {error}"))
            })?;
        u64::try_from(duration.as_nanos())
            .map_err(|_| CliError::Fatal("system clock nanoseconds overflow u64".into()))
    }
}

/// Explicit host-owned execution dependencies.
pub struct ExecutionContext<'a> {
    pub cwd: PathBuf,
    pub cache_base: Option<PathBuf>,
    pub cancellation: &'a dyn Cancellation,
    pub clock: &'a dyn Clock,
}

impl<'a> ExecutionContext<'a> {
    /// Constructs a context without consulting process-global state.
    pub fn new(
        cwd: PathBuf,
        cache_base: Option<PathBuf>,
        cancellation: &'a dyn Cancellation,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            cwd,
            cache_base,
            cancellation,
            clock,
        }
    }
}
