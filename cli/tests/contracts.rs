// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::process::{Command, Stdio};

use code2graph::{Descriptor, SymbolId};
use code2graph_cli::worker::{PROTOCOL_VERSION, WorkerRequest, WorkerResponse, validate_response};
use code2graph_cli::{
    CommandRequest, OutputEnvelope, OutputStatus, ParseOutcome, Selector, SelectorOutput,
    WORKER_SENTINEL, parse_from,
};

fn parse_request<I, T>(args: I) -> code2graph_cli::CliRequest
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    match parse_from(args).unwrap() {
        ParseOutcome::Request(request) => request,
        ParseOutcome::Display(text) => panic!("expected request, got display output: {text}"),
    }
}

#[test]
fn every_documented_usage_accepts_global_flags_after_the_command() {
    let cases: &[&[&str]] = &[
        &[
            "code2graph",
            "index",
            ".",
            "--force",
            "--trust-mtime",
            "--json",
        ],
        &["code2graph", "status", "--json"],
        &[
            "code2graph",
            "symbols",
            "run",
            "--file",
            "src/main.rs",
            "--kind",
            "function",
            "--case-sensitive",
            "--json",
        ],
        &["code2graph", "def", "run", "--require-unique", "--json"],
        &["code2graph", "callers", "run", "--role", "call", "--json"],
        &[
            "code2graph",
            "callees",
            "run",
            "--role",
            "type-ref",
            "--json",
        ],
        &["code2graph", "impact", "run", "--depth", "3", "--json"],
        &["code2graph", "usages", "run", "--role", "read", "--json"],
        &["code2graph", "imports", "src/main.rs", "--json"],
        &["code2graph", "module-deps", "--json"],
        &[
            "code2graph",
            "references",
            "src/main.rs",
            "--name",
            "run",
            "--role",
            "call",
            "--json",
        ],
    ];

    for args in cases {
        assert!(
            matches!(
                parse_from(args.iter().copied()),
                Ok(ParseOutcome::Request(_))
            ),
            "{args:?}"
        );
    }
}

#[test]
fn windows_drive_paths_are_only_positions_when_explicitly_selected() {
    let bare = parse_request(["code2graph", "def", r"C:\src\main.rs"]);
    let CommandRequest::Def {
        selector: Selector::Name(name),
        ..
    } = bare.command
    else {
        panic!("bare positional selectors must remain names")
    };
    assert_eq!(name, r"C:\src\main.rs");

    let explicit = parse_request([
        "code2graph",
        "def",
        "--at-file",
        r"C:\src\main.rs",
        "--line",
        "2",
    ]);
    assert!(matches!(
        explicit.command,
        CommandRequest::Def {
            selector: Selector::Position(_),
            ..
        }
    ));
}

#[test]
fn selector_adversaries_are_rejected_without_guessing() {
    let bad: &[&[&str]] = &[
        &["code2graph", "def"],
        &["code2graph", "def", "run", "--scip", "local run"],
        &["code2graph", "def", "--line", "1"],
        &[
            "code2graph",
            "def",
            "--at-file",
            "src/main.rs",
            "--line",
            "1",
            "--column",
            "0",
        ],
        &[
            "code2graph",
            "def",
            "--id-json",
            r#"{"version":1,"scip":"local x","file":"src/a.rs","unknown":0}"#,
        ],
        &[
            "code2graph",
            "def",
            "--id-json",
            r#"{"version":1,"scip":"local x","file":"src/a.rs"}"#,
            "--kind",
            "other",
        ],
        &["code2graph", "index", "--frozen"],
    ];

    for args in bad {
        assert!(parse_from(args.iter().copied()).is_err(), "{args:?}");
    }
}

#[test]
fn lossless_ids_survive_selector_and_output_json() {
    let local_json = r#"{"version":1,"scip":"local x","file":"src/a.rs"}"#;
    let request = parse_request(["code2graph", "def", "--id-json", local_json]);
    let CommandRequest::Def {
        selector: Selector::Id(local),
        ..
    } = request.command
    else {
        panic!("expected exact ID selector")
    };

    let global = SymbolId::global("rust", vec![Descriptor::Term("x".into())]);
    let mut envelope = OutputEnvelope::new(OutputStatus::Ok, Vec::<String>::new());
    envelope.selector = Some(SelectorOutput {
        matched: 2,
        ambiguous: true,
        ids: vec![global, local],
        symbols: Vec::new(),
    });
    let value = serde_json::to_value(envelope).unwrap();
    let ids = value["selector"]["ids"].as_array().unwrap();
    assert_eq!(ids[0]["lang"], "rust");
    assert!(ids[0].get("file").is_none());
    assert_eq!(ids[1]["file"], "src/a.rs");
    assert!(ids[1].get("lang").is_none());
}

#[test]
fn binary_keeps_unimplemented_commands_operational_failures() {
    let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .args(["symbols", "run"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("symbols execution is not implemented")
    );
}

#[test]
fn binary_json_failures_keep_stdout_machine_only_and_stderr_diagnostic() {
    let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .args(["symbols", "run", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["status"], "unsupported");
    assert!(
        value["error"]
            .as_str()
            .unwrap()
            .contains("symbols execution")
    );
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: ")
    );
}

#[test]
fn binary_help_and_version_are_successful_stdout_display_only() {
    for flag in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success(), "{flag}");
        assert!(!output.stdout.is_empty(), "{flag}");
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn binary_usage_errors_map_to_two_and_emit_json_when_requested() {
    let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .args(["def", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: ")
    );
}

#[test]
fn binary_index_uses_the_same_binary_worker_and_keeps_success_channels_clean() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("a.rs"), "pub fn run() {}\n").unwrap();

    let json = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["index", "--no-cache", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["status"], "ok");
    assert_eq!(value["project"]["cache"], "disabled");
    assert_eq!(value["results"]["inventory_file_count"], 1);
    assert_eq!(value["results"]["changed"], 1);

    let human = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["index", "--no-cache"])
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(human.stderr.is_empty());
    assert_eq!(
        String::from_utf8(human.stdout).unwrap(),
        "indexed 1 files; 1 changed, 0 deleted; complete\n"
    );
}

#[test]
fn same_binary_hidden_worker_succeeds_before_clap_and_stays_out_of_help() {
    let request = WorkerRequest {
        version: PROTOCOL_VERSION,
        kind: 1,
        request_id: 73,
        path: "src/a.rs".into(),
        language: 0,
        source: b"fn run() {}".to_vec(),
    };
    let payload = zerompk::to_msgpack_vec(&request).unwrap();
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);

    let mut child = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .arg(WORKER_SENTINEL)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&frame).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let length = u32::from_be_bytes(output.stdout[..4].try_into().unwrap()) as usize;
    assert_eq!(output.stdout.len(), length + 4);
    let response: WorkerResponse = zerompk::from_msgpack(&output.stdout[4..]).unwrap();
    assert!(validate_response(&response, &request).unwrap().is_ok());

    let help = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(!help.contains(WORKER_SENTINEL));
}
