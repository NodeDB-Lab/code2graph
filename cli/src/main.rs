// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::process::ExitCode as ProcessExitCode;

use code2graph_cli::{CliError, ErrorEnvelope, OutputStatus, parse_from};

fn main() -> ProcessExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let requested_json = requests_json(&args);
    match parse_from(args) {
        Ok(request) => finish(
            request.global.json,
            CliError::Unavailable {
                command: request.command.name().to_owned(),
            },
        ),
        Err(error) => finish(requested_json, error),
    }
}

fn finish(json: bool, error: CliError) -> ProcessExitCode {
    if json {
        let status = OutputStatus::from(&error);
        match serde_json::to_string(&ErrorEnvelope::new(status, error.to_string())) {
            Ok(envelope) => println!("{envelope}"),
            Err(serialization_error) => {
                eprintln!("failed to serialize error envelope: {serialization_error}")
            }
        }
    }
    eprintln!("error: {error}");
    ProcessExitCode::from(error.exit_code().as_i32() as u8)
}

fn requests_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|argument| argument.as_os_str() != "--")
        .any(|argument| argument == "--json")
}
