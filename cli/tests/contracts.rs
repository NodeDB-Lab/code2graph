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
fn binary_imports_missing_snapshot_file_is_a_no_match() {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .args([
            "--root",
            project.path().to_str().unwrap(),
            "--no-cache",
            "imports",
            "src/a.rs",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["status"], "no-match");
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
fn binary_symbols_and_def_query_a_real_no_cache_project_losslessly() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("alpha.rs"),
        "pub fn alpha_helper() {}\npub fn display_target() {}\n",
    )
    .unwrap();
    std::fs::write(project.path().join("beta.rs"), "pub fn beta_helper() {}\n").unwrap();

    let symbols = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["symbols", "HELPER", "--no-cache", "--json", "--limit", "1"])
        .output()
        .unwrap();
    assert!(symbols.status.success());
    assert!(symbols.stderr.is_empty());
    let symbols: serde_json::Value = serde_json::from_slice(&symbols.stdout).unwrap();
    assert_eq!(symbols["status"], "ok");
    assert_eq!(symbols["project"]["cache"], "disabled");
    assert_eq!(symbols["returned"], 1);
    assert_eq!(symbols["total"], 2);
    assert_eq!(symbols["truncated"], true);
    assert_eq!(symbols["results"][0]["name"], "alpha_helper");
    assert_eq!(symbols["results"][0]["id"]["version"], 1);
    let output_id: SymbolId = serde_json::from_value(symbols["results"][0]["id"].clone()).unwrap();
    assert_eq!(
        output_id.to_scip_string(),
        symbols["results"][0]["idDisplay"].as_str().unwrap()
    );

    let filtered = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args([
            "symbols",
            "helper",
            "--file",
            "beta.rs",
            "--kind",
            "function",
            "--no-cache",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(filtered.status.success());
    assert!(filtered.stderr.is_empty());
    let filtered: serde_json::Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(filtered["total"], 1);
    assert_eq!(filtered["results"][0]["name"], "beta_helper");

    let definition = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args([
            "def",
            "alpha_helper",
            "--no-cache",
            "--json",
            "--limit",
            "0",
        ])
        .output()
        .unwrap();
    assert!(definition.status.success());
    assert!(definition.stderr.is_empty());
    let definition: serde_json::Value = serde_json::from_slice(&definition.stdout).unwrap();
    assert_eq!(definition["status"], "ok");
    assert_eq!(definition["returned"], 0);
    assert_eq!(definition["total"], 1);
    assert_eq!(definition["truncated"], true);
    assert_eq!(definition["selector"]["matched"], 1);
    assert_eq!(definition["selector"]["ambiguous"], false);
    assert_eq!(definition["selector"]["ids"].as_array().unwrap().len(), 1);
    assert_eq!(
        definition["selector"]["symbols"].as_array().unwrap().len(),
        1
    );
    assert_eq!(definition["selector"]["symbols"][0]["id"]["version"], 1);
}

#[test]
fn binary_query_no_match_has_typed_json_human_output_and_exit_code() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("lib.rs"), "pub fn present() {}\n").unwrap();

    let json = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["symbols", "missing", "--no-cache", "--json"])
        .output()
        .unwrap();
    assert_eq!(json.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["schemaVersion"], 1);
    assert_eq!(json["status"], "no-match");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("no matching result")
    );

    let human = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["def", "missing", "--no-cache"])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(1));
    assert!(human.stdout.is_empty());
    assert!(
        String::from_utf8(human.stderr)
            .unwrap()
            .contains("error: no matching result")
    );
}

#[test]
fn binary_relations_and_impact_cover_filters_limits_coordinates_and_no_match() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("lib.rs"),
        concat!(
            "pub fn target() {}\n",
            "pub fn middle() { target(); }\n",
            "pub fn sibling() { target(); }\n",
            "pub fn top() { middle(); }\n",
        ),
    )
    .unwrap();

    let json = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
            .current_dir(project.path())
            .args(args)
            .args(["--no-cache", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{args:?}");
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let callers = json(&["callers", "target"]);
    assert_eq!(callers["total"], 2);
    assert_eq!(callers["returned"], 2);
    assert_eq!(callers["truncated"], false);
    assert_eq!(callers["selector"]["matched"], 1);
    assert!(
        callers["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["role"] == "call" && row["confidence"] == "scoped")
    );
    assert!(
        callers["results"][0]["occurrence"]["line"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(callers["results"][0]["occurrence"]["column"].is_u64());

    let callees = json(&["callees", "middle"]);
    assert_eq!(callees["total"], 1);
    assert_eq!(callees["results"][0]["to"], callers["selector"]["ids"][0]);

    let usages = json(&["usages", "target"]);
    assert_eq!(usages["total"], 2, "usages defaults to every role");
    let read_only = json(&["usages", "target", "--role", "read"]);
    assert_eq!(read_only["total"], 0);

    let exact_only = json(&["callers", "target", "--min-confidence", "exact"]);
    assert_eq!(
        exact_only["total"], 0,
        "explicit confidence overrides tier default"
    );
    let name_tier = json(&["callers", "target", "--tier", "name"]);
    assert_eq!(name_tier["total"], 2);
    assert!(
        name_tier["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["confidence"] == "scoped"),
        "the name tier admits its uniquely resolved scoped edges under the name-only default"
    );

    let limited = json(&["callers", "target", "--limit", "1"]);
    assert_eq!(limited["total"], 2);
    assert_eq!(limited["returned"], 1);
    assert_eq!(limited["truncated"], true);
    assert_eq!(limited["selector"]["matched"], 1);

    let impact = json(&["impact", "target", "--depth", "5", "--limit", "2"]);
    assert_eq!(impact["total"], 2);
    assert_eq!(impact["returned"], 2);
    assert_eq!(impact["truncated"], true);
    assert!(
        impact["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["seed"] == impact["selector"]["ids"][0])
    );

    let human = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["callers", "target", "--no-cache", "--limit", "1"])
        .output()
        .unwrap();
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    let json_line = limited["results"][0]["occurrence"]["line"]
        .as_u64()
        .unwrap();
    let json_column = limited["results"][0]["occurrence"]["column"]
        .as_u64()
        .unwrap();
    assert!(
        human.contains(&format!(":{json_line}:{} ", json_column + 1)),
        "human columns must be one-based: {human}"
    );
    assert!(human.contains("truncated: returned 1 of 2 results"));

    let impact_human = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args([
            "impact",
            "target",
            "--depth",
            "5",
            "--limit",
            "2",
            "--no-cache",
        ])
        .output()
        .unwrap();
    assert!(impact_human.status.success());
    let impact_human = String::from_utf8(impact_human.stdout).unwrap();
    assert!(impact_human.contains("seed codegraph"));
    assert!(impact_human.contains("truncated: traversal bound omitted reachable results"));

    let missing = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args(["callers", "missing", "--no-cache", "--json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    let missing: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing["status"], "no-match");
}

#[test]
fn binary_imports_references_and_module_deps_cover_resolved_raw_and_aggregate_contracts() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("src")).unwrap();
    std::fs::write(
        project.path().join("src/main.rs"),
        concat!(
            "mod dep;\n",
            "use crate::dep::helper;\n",
            "fn run() { dep::helper(); missing::call(); }\n",
        ),
    )
    .unwrap();
    std::fs::write(project.path().join("src/dep.rs"), "pub fn helper() {}\n").unwrap();

    let run_json = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
            .current_dir(project.path())
            .args(args)
            .args(["--no-cache", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let imports = run_json(&["imports", "src//main.rs"]);
    assert_eq!(imports["status"], "ok");
    assert!(imports["total"].as_u64().unwrap() >= 1);
    assert!(imports["results"].as_array().unwrap().iter().all(|row| {
        matches!(row["role"].as_str(), Some("import" | "module-ref"))
            && row["confidence"].is_string()
            && row["occurrence"]["file"] == "src/main.rs"
    }));

    let references = run_json(&["references", "src//main.rs"]);
    assert_eq!(references["status"], "ok");
    assert!(references["results"].as_array().unwrap().iter().all(|row| {
        row.get("confidence").is_none() && row["occurrence"]["file"] == "src/main.rs"
    }));
    let qualified = references["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "call")
        .unwrap();
    assert_eq!(qualified["qualifier"], "missing");
    assert_eq!(qualified["role"], "call");

    let unresolved = run_json(&[
        "references",
        "src/main.rs",
        "--name",
        "call",
        "--role",
        "call",
    ]);
    assert_eq!(unresolved["total"], 1);
    assert_eq!(unresolved["results"][0]["name"], "call");
    assert!(unresolved["results"][0].get("confidence").is_none());

    let dependencies = run_json(&["module-deps"]);
    assert_eq!(dependencies["status"], "ok");
    assert!(dependencies["total"].as_u64().unwrap() >= 1);
    assert!(
        dependencies["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| {
                row["source_file"] == "src/main.rs"
                    && row["count"] == row["evidence"].as_array().unwrap().len()
                    && !row["evidence"].as_array().unwrap().is_empty()
            })
    );

    let limited = run_json(&["module-deps", "--limit", "0"]);
    assert_eq!(limited["returned"], 0);
    assert_eq!(limited["truncated"], true);
    assert!(limited["total"].as_u64().unwrap() >= 1);

    for args in [
        &["imports", "src/main.rs"][..],
        &["references", "src/main.rs"][..],
        &["module-deps"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_code2graph"))
            .current_dir(project.path())
            .args(args)
            .args(["--no-cache"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}");
        assert!(!output.stdout.is_empty(), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }

    let no_match = Command::new(env!("CARGO_BIN_EXE_code2graph"))
        .current_dir(project.path())
        .args([
            "references",
            "src/main.rs",
            "--name",
            "absent",
            "--no-cache",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(no_match.status.code(), Some(1));
    let no_match: serde_json::Value = serde_json::from_slice(&no_match.stdout).unwrap();
    assert_eq!(no_match["status"], "no-match");
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
