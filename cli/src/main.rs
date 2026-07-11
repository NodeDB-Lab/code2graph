// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::process::ExitCode as ProcessExitCode;

use code2graph_cli::{
    CliError, CommandOutput, ErrorEnvelope, ExecutionContext, ExitCode, NeverCancelled,
    OutputStatus, ParseOutcome, SystemClock, execute, is_worker_invocation, parse_from,
    render_human, run_worker,
};

fn main() -> ProcessExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    if is_worker_invocation(&args) {
        return match run_worker(&mut std::io::stdin().lock(), &mut std::io::stdout().lock()) {
            Ok(()) => ProcessExitCode::SUCCESS,
            Err(_) => ProcessExitCode::from(ExitCode::Operational.as_i32() as u8),
        };
    }
    let requested_json = requests_json(&args);
    match parse_from(args) {
        Ok(ParseOutcome::Request(request)) => {
            let cwd = match std::env::current_dir() {
                Ok(cwd) => cwd,
                Err(error) => {
                    return finish(request.global.json, CliError::Fatal(error.to_string()));
                }
            };
            let cancellation = NeverCancelled;
            let clock = SystemClock;
            let context = ExecutionContext::new(cwd, None, &cancellation, &clock);
            match execute(request.clone(), &context) {
                Ok(output) => finish_success(request.global.json, output),
                Err(error) => finish(request.global.json, error),
            }
        }
        Ok(ParseOutcome::Display(text)) => {
            print!("{text}");
            ProcessExitCode::SUCCESS
        }
        Err(error) => finish(requested_json, error),
    }
}

fn finish_success(json: bool, output: CommandOutput) -> ProcessExitCode {
    if json {
        let serialized = match &output {
            CommandOutput::Index(envelope) => serde_json::to_string(envelope),
            CommandOutput::Status(envelope) => serde_json::to_string(envelope),
            CommandOutput::Symbols(envelope) => serde_json::to_string(envelope),
            CommandOutput::Def(envelope) => serde_json::to_string(envelope),
            CommandOutput::Callers(envelope) => serde_json::to_string(envelope),
            CommandOutput::Callees(envelope) => serde_json::to_string(envelope),
            CommandOutput::Usages(envelope) => serde_json::to_string(envelope),
            CommandOutput::Impact(envelope) => serde_json::to_string(envelope),
            CommandOutput::Imports(envelope) => serde_json::to_string(envelope),
            CommandOutput::References(envelope) => serde_json::to_string(envelope),
            CommandOutput::ModuleDeps(envelope) => serde_json::to_string(envelope),
            CommandOutput::LoadedGraph(_) => {
                eprintln!("graph loading is not a command output");
                return ProcessExitCode::from(ExitCode::Operational.as_i32() as u8);
            }
        };
        match serialized {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("failed to serialize output envelope: {error}");
                return ProcessExitCode::from(ExitCode::Operational.as_i32() as u8);
            }
        }
    } else {
        print!("{}", render_human(&output));
    }
    ProcessExitCode::SUCCESS
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
