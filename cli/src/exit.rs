// SPDX-License-Identifier: Apache-2.0

/// Stable process exit codes for the `code2graph` executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    NoMatch = 1,
    Usage = 2,
    Ambiguous = 3,
    Operational = 4,
}

impl ExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_process_code_is_frozen() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::NoMatch.as_i32(), 1);
        assert_eq!(ExitCode::Usage.as_i32(), 2);
        assert_eq!(ExitCode::Ambiguous.as_i32(), 3);
        assert_eq!(ExitCode::Operational.as_i32(), 4);
    }
}
