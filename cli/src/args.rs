// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::time::Duration;

use crate::config::{
    DEFAULT_IMPACT_DEPTH, DEFAULT_LIMIT, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, GlobalOptions, ResolverTier, ResourceLimits,
};
use crate::error::CliError;
use crate::request::{CliRequest, CommandRequest, Selector, SourcePosition};
use clap::{ArgGroup, Args, Parser, Subcommand};
use code2graph::{Confidence, RefRole, SymbolId, SymbolIdWire, SymbolKind};

/// Parse an owned request without reading the filesystem or invoking a resolver.
pub fn parse_from<I, T>(args: I) -> Result<CliRequest, CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed =
        RawCli::try_parse_from(args).map_err(|error| CliError::Usage(error.to_string()))?;
    parsed.into_request()
}

#[derive(Parser)]
#[command(name = "code2graph", disable_help_subcommand = true)]
struct RawCli {
    #[command(flatten)]
    global: RawGlobal,
    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Args)]
struct RawGlobal {
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<std::path::PathBuf>,
    #[arg(long, global = true, default_value = "scope")]
    tier: RawTier,
    #[arg(long, global = true, value_parser = parse_confidence)]
    min_confidence: Option<Confidence>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_FILES)]
    max_files: usize,
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_FILE_BYTES)]
    max_file_bytes: usize,
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_TOTAL_BYTES)]
    max_total_bytes: usize,
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_DEPTH)]
    max_depth: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_LIMIT)]
    limit: usize,
    #[arg(long, global = true, value_parser = parse_duration)]
    timeout: Option<Duration>,
    #[arg(long, global = true)]
    include_hidden: bool,
    #[arg(long, global = true)]
    frozen: bool,
    #[arg(long, global = true)]
    allow_stale: bool,
    #[arg(long, global = true)]
    allow_partial: bool,
    #[arg(long, global = true)]
    no_cache: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum RawTier {
    Name,
    Scope,
    Dense,
}

#[derive(Subcommand)]
enum RawCommand {
    Index {
        path: Option<std::path::PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        trust_mtime: bool,
    },
    Status,
    Symbols {
        text: String,
        #[arg(long)]
        file: Option<String>,
        #[arg(long, value_parser = parse_kind)]
        kind: Option<SymbolKind>,
        #[arg(long)]
        case_sensitive: bool,
    },
    Def(SelectorCommand),
    Callers(RelationCommand),
    Callees(RelationCommand),
    Impact(ImpactCommand),
    Usages(RelationCommand),
    Imports {
        file: String,
    },
    #[command(name = "module-deps")]
    ModuleDeps,
    References {
        file: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_parser = parse_role)]
        role: Option<RefRole>,
    },
}

#[derive(Args)]
#[command(group(ArgGroup::new("selector").args(["name", "id_json", "scip", "at_file"]).required(true).multiple(false)))]
struct SelectorArgs {
    name: Option<String>,
    #[arg(long, value_name = "LOSSLESS_SYMBOL_ID", value_parser = parse_symbol_id)]
    id_json: Option<SymbolId>,
    #[arg(long, value_name = "DISPLAY")]
    scip: Option<String>,
    #[arg(long, requires = "line", value_name = "FILE")]
    at_file: Option<String>,
    #[arg(long, requires = "at_file", value_parser = positive_u32)]
    line: Option<u32>,
    #[arg(long, requires = "at_file", value_parser = positive_u32)]
    column: Option<u32>,
}

#[derive(Args)]
struct SelectorCommand {
    #[command(flatten)]
    selector: SelectorArgs,
    #[arg(long)]
    file: Option<String>,
    #[arg(long, value_parser = parse_kind)]
    kind: Option<SymbolKind>,
    #[arg(long)]
    require_unique: bool,
}

#[derive(Args)]
struct RelationCommand {
    #[command(flatten)]
    selector: SelectorArgs,
    #[arg(long)]
    file: Option<String>,
    #[arg(long, value_parser = parse_kind)]
    kind: Option<SymbolKind>,
    #[arg(long)]
    require_unique: bool,
    #[arg(long, value_parser = parse_role)]
    role: Option<RefRole>,
}

#[derive(Args)]
struct ImpactCommand {
    #[command(flatten)]
    selector: SelectorArgs,
    #[arg(long)]
    file: Option<String>,
    #[arg(long, value_parser = parse_kind)]
    kind: Option<SymbolKind>,
    #[arg(long)]
    require_unique: bool,
    #[arg(long, value_parser = parse_role)]
    role: Option<RefRole>,
    #[arg(long, default_value_t = DEFAULT_IMPACT_DEPTH)]
    depth: u32,
}

impl RawCli {
    fn into_request(self) -> Result<CliRequest, CliError> {
        let global = GlobalOptions {
            root: self.global.root,
            tier: match self.global.tier {
                RawTier::Name => ResolverTier::Name,
                RawTier::Scope => ResolverTier::Scope,
                RawTier::Dense => ResolverTier::Dense,
            },
            min_confidence: self.global.min_confidence,
            json: self.global.json,
            limits: ResourceLimits {
                max_files: self.global.max_files,
                max_file_bytes: self.global.max_file_bytes,
                max_total_bytes: self.global.max_total_bytes,
                max_depth: self.global.max_depth,
                result_limit: self.global.limit,
                timeout: self.global.timeout,
            },
            include_hidden: self.global.include_hidden,
            frozen: self.global.frozen,
            allow_stale: self.global.allow_stale,
            allow_partial: self.global.allow_partial,
            no_cache: self.global.no_cache,
        };
        let command = match self.command {
            RawCommand::Index {
                path,
                force,
                trust_mtime,
            } => {
                if global.frozen {
                    return Err(CliError::Usage(
                        "--frozen is a query flag and cannot be used with index".into(),
                    ));
                }
                CommandRequest::Index {
                    path,
                    force,
                    trust_mtime,
                }
            }
            RawCommand::Status => CommandRequest::Status,
            RawCommand::Symbols {
                text,
                file,
                kind,
                case_sensitive,
            } => CommandRequest::Symbols {
                text,
                file,
                kind,
                case_sensitive,
            },
            RawCommand::Def(value) => {
                let (selector, file, kind, require_unique) = selector_command(value)?;
                CommandRequest::Def {
                    selector,
                    file,
                    kind,
                    require_unique,
                }
            }
            RawCommand::Callers(value) => {
                relation_command(value, |selector, file, kind, require_unique, role| {
                    CommandRequest::Callers {
                        selector,
                        file,
                        kind,
                        require_unique,
                        role,
                    }
                })?
            }
            RawCommand::Callees(value) => {
                relation_command(value, |selector, file, kind, require_unique, role| {
                    CommandRequest::Callees {
                        selector,
                        file,
                        kind,
                        require_unique,
                        role,
                    }
                })?
            }
            RawCommand::Usages(value) => {
                relation_command(value, |selector, file, kind, require_unique, role| {
                    CommandRequest::Usages {
                        selector,
                        file,
                        kind,
                        require_unique,
                        role,
                    }
                })?
            }
            RawCommand::Impact(value) => {
                let selector = selector(value.selector)?;
                validate_narrowing_filters(&selector, &value.file, &value.kind)?;
                CommandRequest::Impact {
                    selector,
                    file: value.file,
                    kind: value.kind,
                    require_unique: value.require_unique,
                    role: value.role,
                    depth: value.depth,
                }
            }
            RawCommand::Imports { file } => CommandRequest::Imports { file },
            RawCommand::ModuleDeps => CommandRequest::ModuleDeps,
            RawCommand::References { file, name, role } => {
                CommandRequest::References { file, name, role }
            }
        };
        Ok(CliRequest { global, command })
    }
}

fn selector_command(
    value: SelectorCommand,
) -> Result<(Selector, Option<String>, Option<SymbolKind>, bool), CliError> {
    let selector = selector(value.selector)?;
    validate_narrowing_filters(&selector, &value.file, &value.kind)?;
    Ok((selector, value.file, value.kind, value.require_unique))
}
fn relation_command<F>(value: RelationCommand, build: F) -> Result<CommandRequest, CliError>
where
    F: FnOnce(
        Selector,
        Option<String>,
        Option<SymbolKind>,
        bool,
        Option<RefRole>,
    ) -> CommandRequest,
{
    let selector = selector(value.selector)?;
    validate_narrowing_filters(&selector, &value.file, &value.kind)?;
    Ok(build(
        selector,
        value.file,
        value.kind,
        value.require_unique,
        value.role,
    ))
}
fn selector(value: SelectorArgs) -> Result<Selector, CliError> {
    if let Some(name) = value.name {
        Ok(Selector::Name(name))
    } else if let Some(id) = value.id_json {
        Ok(Selector::Id(id))
    } else if let Some(scip) = value.scip {
        Ok(Selector::Scip(scip))
    } else if let (Some(file), Some(line)) = (value.at_file, value.line) {
        Ok(Selector::Position(SourcePosition {
            file,
            line,
            column: value.column.unwrap_or(1),
        }))
    } else {
        Err(CliError::Usage("exactly one selector is required".into()))
    }
}

fn validate_narrowing_filters(
    selector: &Selector,
    file: &Option<String>,
    kind: &Option<SymbolKind>,
) -> Result<(), CliError> {
    if (file.is_some() || kind.is_some())
        && !matches!(selector, Selector::Name(_) | Selector::Scip(_))
    {
        return Err(CliError::Usage(
            "--file and --kind only narrow name or SCIP-display selectors".into(),
        ));
    }
    Ok(())
}

fn positive_u32(value: &str) -> Result<u32, String> {
    let value = value
        .parse::<u32>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if value == 0 {
        Err("must be at least 1".into())
    } else {
        Ok(value)
    }
}
fn parse_symbol_id(value: &str) -> Result<SymbolId, String> {
    let wire: SymbolIdWire = serde_json::from_str(value)
        .map_err(|error| format!("invalid lossless SymbolId JSON: {error}"))?;
    SymbolId::try_from_wire(wire)
        .map_err(|error| format!("invalid lossless SymbolId JSON: {error}"))
}
fn parse_duration(value: &str) -> Result<Duration, String> {
    let units = [("ms", 1_u64), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)];
    for (unit, millis) in units {
        if let Some(number) = value.strip_suffix(unit) {
            let amount = number
                .parse::<u64>()
                .map_err(|_| "duration must be an integer followed by ms, s, m, or h".to_owned())?;
            return amount
                .checked_mul(millis)
                .map(Duration::from_millis)
                .ok_or_else(|| "duration is too large".into());
        }
    }
    Err("duration must be an integer followed by ms, s, m, or h".into())
}
fn parse_confidence(value: &str) -> Result<Confidence, String> {
    match value {
        "heuristic" => Ok(Confidence::Heuristic),
        "name-only" => Ok(Confidence::NameOnly),
        "scoped" => Ok(Confidence::Scoped),
        "exact" => Ok(Confidence::Exact),
        _ => Err("expected heuristic, name-only, scoped, or exact".into()),
    }
}
fn parse_role(value: &str) -> Result<RefRole, String> {
    match value {
        "call" => Ok(RefRole::Call),
        "is-implementation" => Ok(RefRole::IsImplementation),
        "import" => Ok(RefRole::Import),
        "module-ref" => Ok(RefRole::ModuleRef),
        "type-ref" => Ok(RefRole::TypeRef),
        "read" => Ok(RefRole::Read),
        "write" => Ok(RefRole::Write),
        _ => Err("invalid reference role".into()),
    }
}
fn parse_kind(value: &str) -> Result<SymbolKind, String> {
    match value {
        "function" => Ok(SymbolKind::Function),
        "method" => Ok(SymbolKind::Method),
        "struct" => Ok(SymbolKind::Struct),
        "enum" => Ok(SymbolKind::Enum),
        "trait" => Ok(SymbolKind::Trait),
        "interface" => Ok(SymbolKind::Interface),
        "class" => Ok(SymbolKind::Class),
        "type-alias" => Ok(SymbolKind::TypeAlias),
        "const" => Ok(SymbolKind::Const),
        "static" => Ok(SymbolKind::Static),
        "module" => Ok(SymbolKind::Module),
        "impl" => Ok(SymbolKind::Impl),
        "table" => Ok(SymbolKind::Table),
        "view" => Ok(SymbolKind::View),
        "column" => Ok(SymbolKind::Column),
        "resource" => Ok(SymbolKind::Resource),
        "other" => Ok(SymbolKind::Other),
        _ => Err("invalid symbol kind".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_parses() {
        let cases: &[&[&str]] = &[
            &["code2graph", "index"],
            &["code2graph", "status"],
            &["code2graph", "symbols", "run"],
            &["code2graph", "def", "run"],
            &["code2graph", "callers", "run"],
            &["code2graph", "callees", "run"],
            &["code2graph", "impact", "run"],
            &["code2graph", "usages", "run"],
            &["code2graph", "imports", "src/a.rs"],
            &["code2graph", "module-deps"],
            &["code2graph", "references", "src/a.rs"],
        ];
        for args in cases {
            assert!(parse_from(args.iter().copied()).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn selectors_are_exclusive_and_positions_are_one_based() {
        assert!(parse_from(["code2graph", "def", "name", "--scip", "local x"]).is_err());
        assert!(parse_from(["code2graph", "def", "--at-file", "src/a.rs", "--line", "0"]).is_err());
        let request =
            parse_from(["code2graph", "def", "--at-file", "src/a.rs", "--line", "3"]).unwrap();
        let CommandRequest::Def {
            selector: Selector::Position(position),
            ..
        } = request.command
        else {
            panic!("expected position selector")
        };
        assert_eq!(
            position,
            SourcePosition {
                file: "src/a.rs".into(),
                line: 3,
                column: 1
            }
        );
    }

    #[test]
    fn id_json_is_lossless_and_versioned() {
        let request = parse_from([
            "code2graph",
            "def",
            "--id-json",
            r#"{"version":1,"scip":"local x","file":"src/a.rs"}"#,
        ])
        .unwrap();
        let CommandRequest::Def {
            selector: Selector::Id(id),
            ..
        } = request.command
        else {
            panic!("expected id selector")
        };
        assert_eq!(id, SymbolId::local("src/a.rs", "x"));
        let global = parse_from([
            "code2graph",
            "def",
            "--id-json",
            r#"{"version":1,"scip":"codegraph . . . run.","lang":"rust"}"#,
        ])
        .unwrap();
        let CommandRequest::Def {
            selector: Selector::Id(id),
            ..
        } = global.command
        else {
            panic!("expected global id selector")
        };
        assert_eq!(id.language(), Some("rust"));
        assert!(
            parse_from([
                "code2graph",
                "def",
                "--id-json",
                r#"{"version":2,"scip":"local x","file":"src/a.rs"}"#
            ])
            .is_err()
        );
        assert!(parse_from(["code2graph", "def", "--id-json", "local x"]).is_err());
        assert!(
            parse_from([
                "code2graph",
                "def",
                "--id-json",
                r#"{"scip":"local x","file":"src/a.rs"}"#
            ])
            .is_err()
        );
        assert!(
            parse_from([
                "code2graph",
                "def",
                "--id-json",
                r#"{"version":1,"scip":"local x","file":"src/a.rs","extra":true}"#
            ])
            .is_err()
        );
    }

    #[test]
    fn defaults_and_duration_units_are_preserved() {
        let request = parse_from(["code2graph", "--timeout", "2m", "impact", "run"]).unwrap();
        assert_eq!(
            request.global.limits,
            ResourceLimits {
                timeout: Some(Duration::from_secs(120)),
                ..ResourceLimits::default()
            }
        );
        let CommandRequest::Impact { depth, .. } = request.command else {
            panic!("expected impact");
        };
        assert_eq!(depth, DEFAULT_IMPACT_DEPTH);

        let callers = parse_from(["code2graph", "callers", "run"]).unwrap();
        assert_eq!(
            callers.command.effective_relation_role(),
            Some(RefRole::Call)
        );
        let usages = parse_from(["code2graph", "usages", "run"]).unwrap();
        assert_eq!(usages.command.effective_relation_role(), None);
    }

    #[test]
    fn global_flags_work_after_commands_and_frozen_index_is_still_rejected() {
        let request = parse_from([
            "code2graph",
            "status",
            "--json",
            "--tier",
            "dense",
            "--include-hidden",
        ])
        .unwrap();
        assert!(request.global.json);
        assert!(request.global.include_hidden);
        assert_eq!(request.global.tier, ResolverTier::Dense);
        assert!(parse_from(["code2graph", "index", "--frozen"]).is_err());
    }

    #[test]
    fn narrowing_filters_only_apply_to_name_and_display_selectors() {
        assert!(
            parse_from([
                "code2graph",
                "def",
                "--id-json",
                r#"{"version":1,"scip":"local x","file":"src/a.rs"}"#,
                "--file",
                "src/a.rs"
            ])
            .is_err()
        );
        assert!(
            parse_from([
                "code2graph",
                "impact",
                "--at-file",
                "src/a.rs",
                "--line",
                "1",
                "--kind",
                "function"
            ])
            .is_err()
        );
        assert!(parse_from(["code2graph", "def", "run", "--file", "src/a.rs"]).is_ok());
        assert!(
            parse_from([
                "code2graph",
                "callers",
                "--scip",
                "local x",
                "--kind",
                "other"
            ])
            .is_ok()
        );
    }

    #[test]
    fn duration_parser_is_integer_unit_strict_and_overflow_safe() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7_200));
        for value in ["", "1", "1.5s", "-1s", "1d", "18446744073709551615h"] {
            assert!(parse_duration(value).is_err(), "{value}");
        }
    }

    #[test]
    fn invalid_values_and_index_frozen_are_usage_errors() {
        for args in [
            vec!["code2graph", "--tier", "wrong", "status"],
            vec!["code2graph", "--timeout", "1d", "status"],
            vec!["code2graph", "callers", "x", "--role", "wrong"],
            vec!["code2graph", "symbols", "x", "--kind", "wrong"],
            vec!["code2graph", "--frozen", "index"],
        ] {
            assert!(parse_from(args).is_err());
        }
    }
}
