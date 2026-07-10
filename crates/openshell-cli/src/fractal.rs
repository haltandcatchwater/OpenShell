//! `openshell fractal` — Fractal Code integration commands.
//!
//! Subcommands for running Fractal cells and scaffolds inside OpenShell
//! sandboxes, validating cells against the constitution, and compiling
//! channel declarations to OpenShell policy YAML.

use clap::{ArgValueCompleter, Subcommand, ValueHint};
use miette::Result;
use std::path::PathBuf;

use openshell_fractal::{
    cell_runner, channel_mapper, constitution,
    schema::{FractalCell, FractalScaffold},
};

/// Help text for the `fractal run` subcommand.
const FRACTAL_RUN_HELP: &str = "\
EXAMPLES:
  openshell fractal run cell ./my_cell.fc --input '{\"prompt\": \"hello\"}'
  openshell fractal run scaffold ./my_pipeline.fc
  openshell fractal run scaffold ./my_pipeline.fc --pause-after extract_pii

Run a Fractal cell or scaffold pipeline inside an OpenShell sandbox. Each cell
gets its own sandbox with policies derived from its channel declarations.
Scaffolds execute cells in topological order, threading outputs between them.
";

const FRACTAL_VALIDATE_HELP: &str = "\
EXAMPLES:
  openshell fractal validate ./my_cell.fc
  openshell fractal validate ./cells/ --recursive

Run constitutional checks against one or more Fractal cells. Checks include
structural hashing, banned-pattern scanning, classification consistency, and
declassifier authorization. A cell must pass ALL checks before it can execute.
";

const FRACTAL_CHANNELS_HELP: &str = "\
EXAMPLES:
  openshell fractal channels ./my_cell.fc
  openshell fractal channels ./my_cell.fc --output policy.yaml

Compile a cell's channel declarations into OpenShell policy YAML. Each channel
kind (file, http, anthropic, github, git, package) maps to the corresponding
OpenShell policy block. Channels that duplicate platform-native RBAC (postgres,
stripe, AWS IAM) are skipped with documented reasons.
";

/// Top-level `fractal` subcommand.
#[derive(Debug, clap::Args)]
#[command(
    name = "fractal",
    about = "Execute and validate Fractal Code cells inside OpenShell sandboxes",
    long_about = "Fractal Code is a constitutional programming language where computation \
                  is organized into validated cells and scaffolds. Each cell runs inside an \
                  OpenShell sandbox with policies derived from its channel declarations. \
                  Constitutional checks (banned patterns, structural signatures, taint \
                  inheritance) are enforced before any cell executes.",
    help_template = "\
{usage-heading} {usage}

{about-section}
{before-help}{about-with-newline}
{all-args}{after-help}
"
)]
pub struct FractalArgs {
    #[command(subcommand)]
    pub command: FractalCommands,
}

#[derive(Subcommand, Debug)]
pub enum FractalCommands {
    /// Run a Fractal cell or scaffold pipeline.
    #[command(
        after_help = FRACTAL_RUN_HELP,
        help_template = "\
{usage-heading} {usage}

{about-section}
{before-help}{about-with-newline}
{all-args}{after-help}
"
    )]
    Run {
        #[command(subcommand)]
        command: FractalRunCommands,
    },

    /// Validate cells against the Fractal constitution.
    #[command(
        after_help = FRACTAL_VALIDATE_HELP,
        help_template = "\
{usage-heading} {usage}

{about-section}
{before-help}{about-with-newline}
{all-args}{after-help}
"
    )]
    Validate {
        /// Path to a .fc file or directory of .fc files.
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,

        /// Recursively validate all .fc files in subdirectories.
        #[arg(short, long)]
        recursive: bool,

        /// Output format: text (default), json, or quiet (exit code only).
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show the channel→policy mapping for a cell.
    #[command(
        after_help = FRACTAL_CHANNELS_HELP,
        help_template = "\
{usage-heading} {usage}

{about-section}
{before-help}{about-with-newline}
{all-args}{after-help}
"
    )]
    Channels {
        /// Path to a .fc file.
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,

        /// Write the compiled policy to a file instead of stdout.
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Generate OpenShell policy YAML from a Fractal cell.
    #[command(
        help_template = "\
{usage-heading} {usage}

{about-section}
{before-help}{about-with-newline}
{all-args}{after-help}
"
    )]
    Policy {
        /// Path to a .fc file.
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,

        /// Write policy to a file.
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum FractalRunCommands {
    /// Run a single Fractal cell.
    Cell {
        /// Path to the .fc cell file.
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,

        /// JSON input for the cell.
        #[arg(short, long, default_value = "{}")]
        input: String,
    },

    /// Run a Fractal scaffold (pipeline of cells).
    Scaffold {
        /// Path to the scaffold directory containing .fc files.
        #[arg(value_hint = ValueHint::FilePath)]
        path: PathBuf,

        /// JSON initial input for the first cell in the pipeline.
        #[arg(short, long, default_value = "{}")]
        input: String,

        /// Pause execution after these cell names for human review.
        #[arg(long, value_delimiter = ',')]
        pause_after: Vec<String>,
    },
}

// ── Command handlers ──────────────────────────────────────────────────────

pub async fn handle_fractal_command(args: FractalArgs) -> Result<()> {
    match args.command {
        FractalCommands::Run { command } => handle_run(command).await,
        FractalCommands::Validate { path, recursive, format } => {
            handle_validate(&path, recursive, &format).await
        }
        FractalCommands::Channels { path, output } => {
            handle_channels(&path, output.as_deref()).await
        }
        FractalCommands::Policy { path, output } => {
            handle_policy(&path, output.as_deref()).await
        }
    }
}

async fn handle_run(command: FractalRunCommands) -> Result<()> {
    match command {
        FractalRunCommands::Cell { path, input } => {
            let input: serde_json::Value = serde_json::from_str(&input)
                .map_err(|e| miette::miette!("Invalid JSON input: {}", e))?;

            let cell = load_cell(&path)?;

            println!("Cell: {} v{}", cell.identity.name, cell.identity.version);
            println!("Type: {:?}", cell.identity.cell_type);

            // Constitutional validation
            let check = constitution::validate_cell(&cell);
            println!(
                "Constitution: {}/{} checks passed",
                check.checks_passed, check.checks_total
            );

            if !check.pattern_scan.passed {
                eprintln!("❌ Pattern scan FAILED:");
                for v in &check.pattern_scan.violations {
                    eprintln!("  - {} ({:?})", v.pattern, v.severity);
                }
                std::process::exit(1);
            }

            // Channel mapping
            let results = channel_mapper::map_all(&cell.channels);
            for r in &results {
                match r {
                    channel_mapper::MappingResult::Mapped(m) => {
                        println!(
                            "  Channel: {} → {} network policies, {} fs policies",
                            m.channel_name,
                            m.network_policies.len(),
                            if m.filesystem.is_some() { 1 } else { 0 }
                        );
                    }
                    channel_mapper::MappingResult::Skipped(s) => {
                        println!("  Channel: {} (skipped: {})", s.channel_name, s.reason);
                    }
                }
            }

            println!("✓ Cell validated. Run with `openshell sandbox create` to execute.");
            Ok(())
        }
        FractalRunCommands::Scaffold { path, input, pause_after } => {
            let input: serde_json::Value = serde_json::from_str(&input)
                .map_err(|e| miette::miette!("Invalid JSON input: {}", e))?;

            // Load all .fc files from the scaffold directory
            let cells = load_scaffold_cells(&path)?;
            let names: Vec<String> = cells.iter().map(|c| c.identity.name.clone()).collect();

            let scaffold = FractalScaffold {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unnamed".into()),
                cells,
                execution_order: names,
                pause_after,
            };

            println!("Scaffold: {} ({} cells)", scaffold.name, scaffold.cells.len());
            for (i, name) in scaffold.execution_order.iter().enumerate() {
                println!("  {}. {}", i + 1, name);
            }

            // Validate all cells
            let mut all_passed = true;
            for cell in &scaffold.cells {
                let check = constitution::validate_cell(cell);
                if !check.pattern_scan.passed {
                    eprintln!("❌ {}: pattern scan FAILED", cell.identity.name);
                    all_passed = false;
                } else {
                    println!("  ✓ {} ({}/{})", cell.identity.name, check.checks_passed, check.checks_total);
                }
            }

            if !all_passed {
                std::process::exit(1);
            }

            println!("✓ All cells validated. Run with `openshell sandbox create` to execute.");
            Ok(())
        }
    }
}

async fn handle_validate(path: &PathBuf, recursive: bool, format: &str) -> Result<()> {
    let cells = if path.is_dir() {
        load_cells_from_dir(path, *recursive)?
    } else {
        vec![load_cell(path)?]
    };

    let mut total_checks: u8 = 0;
    let mut total_passed: u8 = 0;
    let mut failures = Vec::new();

    for cell in &cells {
        let check = constitution::validate_cell(cell);
        total_checks += check.checks_total;
        total_passed += check.checks_passed;

        if !check.pattern_scan.passed {
            failures.push((cell.identity.name.clone(), check));
        }
    }

    match format {
        "json" => {
            let output = serde_json::json!({
                "cells_validated": cells.len(),
                "checks_total": total_checks,
                "checks_passed": total_passed,
                "failures": failures.iter().map(|(name, check)| {
                    serde_json::json!({
                        "cell": name,
                        "structural_hash": check.structural_hash,
                        "violations": check.pattern_scan.violations.iter().map(|v| {
                            serde_json::json!({
                                "pattern": v.pattern,
                                "severity": format!("{:?}", v.severity),
                                "location": v.location,
                            })
                        }).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        "quiet" => {
            if !failures.is_empty() {
                std::process::exit(1);
            }
        }
        _ => {
            println!("Cells validated: {}", cells.len());
            println!("Checks: {}/{} passed", total_passed, total_checks);
            if failures.is_empty() {
                println!("✓ All cells pass constitutional validation.");
            } else {
                eprintln!("❌ {} cells failed:", failures.len());
                for (name, check) in &failures {
                    eprintln!("  {}: {}/{} checks passed", name, check.checks_passed, check.checks_total);
                    for v in &check.pattern_scan.violations {
                        eprintln!("    - {} ({:?})", v.pattern, v.severity);
                    }
                }
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

async fn handle_channels(path: &PathBuf, output: Option<&PathBuf>) -> Result<()> {
    let cell = load_cell(path)?;
    let results = channel_mapper::map_all(&cell.channels);

    let yaml_output = format_channel_results(&cell.identity.name, &results);
    let yaml_str = serde_yaml::to_string(&yaml_output)
        .map_err(|e| miette::miette!("YAML serialization error: {}", e))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &yaml_str)?;
        println!("Policy written to {}", out_path.display());
    } else {
        println!("{}", yaml_str);
    }

    // Print skipped channels to stderr
    for r in &results {
        if let channel_mapper::MappingResult::Skipped(s) = r {
            eprintln!("Note: {} ({}): {}", s.channel_name, s.kind, s.reason);
        }
    }

    Ok(())
}

async fn handle_policy(path: &PathBuf, output: Option<&PathBuf>) -> Result<()> {
    // `policy` is an alias for `channels --output` with a simpler interface
    handle_channels(path, output).await
}

// ── File loading helpers ──────────────────────────────────────────────────

fn load_cell(path: &PathBuf) -> Result<FractalCell, miette::Report> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("Cannot read {}: {}", path.display(), e))?;

    // Parse .fc YAML frontmatter + JS logic
    parse_fc_file(&content, path)
}

fn load_scaffold_cells(dir: &PathBuf) -> Result<Vec<FractalCell>, miette::Report> {
    let mut cells = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|e| miette::miette!("Cannot read directory {}: {}", dir.display(), e))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "fc").unwrap_or(false) {
            cells.push(load_cell(&path)?);
        }
    }
    if cells.is_empty() {
        return Err(miette::miette!("No .fc files found in {}", dir.display()));
    }
    Ok(cells)
}

fn load_cells_from_dir(dir: &PathBuf, recursive: bool) -> Result<Vec<FractalCell>, miette::Report> {
    let mut cells = Vec::new();
    if recursive {
        load_cells_recursive(dir, &mut cells)?;
    } else {
        cells = load_scaffold_cells(dir)?;
    }
    Ok(cells)
}

fn load_cells_recursive(dir: &PathBuf, cells: &mut Vec<FractalCell>) -> Result<(), miette::Report> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| miette::miette!("Cannot read directory {}: {}", dir.display(), e))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            load_cells_recursive(&path, cells)?;
        } else if path.extension().map(|e| e == "fc").unwrap_or(false) {
            cells.push(load_cell(&path)?);
        }
    }
    Ok(())
}

/// Parse a .fc file: YAML `cell:` document with embedded logic.
///
/// Real Fractal .fc files use the format:
/// ```yaml
/// cell:
///   identity:
///     name: "greet"
///     version: "1.0.0"
///     type: "Transformer"
///   contract:
///     input: "object"
///     output: "object"
///   logic:
///     lang: "typescript"
///     process: |
///       return ...;
///   lineage:
///     source: "..."
///     trigger: "..."
///     justification: "..."
///     parent_context_hash: "..."
///   signature: "0x..."
/// ```
fn parse_fc_file(content: &str, path: &PathBuf) -> Result<FractalCell, miette::Report> {
    let yaml_value: serde_json::Value = serde_yaml::from_str(content)
        .map_err(|e| miette::miette!("YAML parse error in {}: {}", path.display(), e))?;

    let cell_node = yaml_value
        .get("cell")
        .ok_or_else(|| miette::miette!("Missing 'cell:' key in {}", path.display()))?;

    let cell = parse_cell_from_yaml(cell_node)
        .map_err(|e| miette::miette!("Invalid cell in {}: {}", path.display(), e))?;

    Ok(cell)
}

fn parse_cell_from_yaml(cell: &serde_json::Value) -> Result<FractalCell, String> {
    let identity = cell.get("identity").ok_or("missing identity")?;
    let contract = cell.get("contract").ok_or("missing contract")?;
    let logic_node = cell.get("logic").ok_or("missing logic")?;

    // Logic is embedded in logic.process as a YAML block scalar
    let logic = logic_node
        .get("process")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Channels may be defined inline (typed-channels style) or absent
    let channels = cell
        .get("channels")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let channels: Vec<openshell_fractal::TypedChannelConfig> = channels
        .iter()
        .map(|c| openshell_fractal::TypedChannelConfig {
            name: c.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").into(),
            kind: c.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
            scope: c.get("scope").cloned().unwrap_or(serde_json::json!({})),
        })
        .collect();

    // Identity uses "type" not "cellType" in the real format
    let lineage_node = cell.get("lineage");

    Ok(FractalCell {
        identity: openshell_fractal::schema::CellIdentity {
            name: identity.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").into(),
            cell_type: identity
                .get("type")
                .and_then(|v| v.as_str())
                .map(parse_cell_type)
                .unwrap_or(openshell_fractal::schema::CellType::Transformer),
            version: identity.get("version").and_then(|v| v.as_str()).unwrap_or("0.1.0").into(),
        },
        contract: openshell_fractal::schema::CellContract {
            input: contract.get("input").cloned().unwrap_or(serde_json::json!({})),
            output: contract.get("output").cloned().unwrap_or(serde_json::json!({})),
        },
        channels,
        logic,
        lineage: openshell_fractal::schema::CellLineage {
            source: lineage_node
                .and_then(|l| l.get("source"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .into(),
            trigger: lineage_node
                .and_then(|l| l.get("trigger"))
                .and_then(|v| v.as_str())
                .unwrap_or("manual")
                .into(),
            justification: lineage_node
                .and_then(|l| l.get("justification"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
            signature: lineage_node
                .and_then(|l| l.get("parent_context_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
        },
        signature: cell
            .get("signature")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

fn parse_cell_type(s: &str) -> openshell_fractal::schema::CellType {
    match s.to_lowercase().as_str() {
        "transformer" => openshell_fractal::schema::CellType::Transformer,
        "reactor" => openshell_fractal::schema::CellType::Reactor,
        "keeper" => openshell_fractal::schema::CellType::Keeper,
        "channel" => openshell_fractal::schema::CellType::Channel,
        _ => openshell_fractal::schema::CellType::Transformer,
    }
}

fn format_channel_results(
    cell_name: &str,
    results: &[channel_mapper::MappingResult],
) -> serde_yaml::Value {
    let mut policies = Vec::new();

    for r in results {
        match r {
            channel_mapper::MappingResult::Mapped(m) => {
                if let Some(ref fs) = m.filesystem {
                    policies.push(serde_yaml::to_value(fs).unwrap_or_default());
                }
                for (_, np) in &m.network_policies {
                    policies.push(serde_yaml::to_value(np).unwrap_or_default());
                }
            }
            channel_mapper::MappingResult::Skipped(s) => {
                // Emit as comment-like entry for audit trail
                let note = serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String(format!("_skipped_{}", s.channel_name)),
                        serde_yaml::Value::String(format!(
                            "{} channel: {}",
                            s.kind, s.reason
                        )),
                    );
                    map
                });
                policies.push(note);
            }
        }
    }

    serde_yaml::Value::Mapping({
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("fractal_cell".into()),
            serde_yaml::Value::String(cell_name.into()),
        );
        map.insert(
            serde_yaml::Value::String("policies".into()),
            serde_yaml::Value::Sequence(policies),
        );
        map
    })
}
