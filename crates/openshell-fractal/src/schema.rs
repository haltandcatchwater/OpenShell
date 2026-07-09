//! Types and configuration schema for Fractal Code integration.
//!
//! Defines the data structures that represent Fractal cells, scaffolds,
//! channel configurations, and constitutional check results within the
//! OpenShell type system.

use serde::{Deserialize, Serialize};

/// A Fractal cell — the fundamental unit of computation.
///
/// Every cell has an identity, input/output schemas, channel declarations,
/// and bare JavaScript logic that executes inside the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FractalCell {
    pub identity: CellIdentity,
    pub contract: CellContract,
    pub channels: Vec<TypedChannelConfig>,
    pub logic: String,
    pub lineage: CellLineage,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellIdentity {
    pub name: String,
    #[serde(rename = "cellType")]
    pub cell_type: CellType,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CellType {
    Transformer,
    Reactor,
    Keeper,
    Channel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellContract {
    pub input: serde_json::Value,
    pub output: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellLineage {
    pub source: String,
    pub trigger: String,
    pub justification: String,
    pub signature: String,
}

/// A typed channel configuration — declares WHAT a cell can do.
///
/// This maps directly to Fractal's `.fc` channel declarations and
/// is the input to the channel→policy compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedChannelConfig {
    pub name: String,
    pub kind: String,
    pub scope: serde_json::Value,
}

/// Output from executing a single cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellOutput {
    pub data: serde_json::Value,
    pub classification: ClassificationLevel,
    pub health: CellHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClassificationLevel {
    Public,
    Internal,
    Pii,
    Secret,
}

impl ClassificationLevel {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Pii => 2,
            Self::Secret => 3,
        }
    }

    /// Taint inheritance: output level must be >= max input level.
    pub fn dominates(&self, other: &ClassificationLevel) -> bool {
        self.rank() >= other.rank()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellHealth {
    pub status: HealthStatus,
    pub budget_remaining: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    #[serde(rename = "safe-mode")]
    SafeMode,
}

/// A Fractal scaffold — a pipeline of cells connected by channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FractalScaffold {
    pub name: String,
    pub cells: Vec<FractalCell>,
    /// Topological order of cell execution.
    pub execution_order: Vec<String>,
    /// Named pause points for human-in-the-loop review.
    pub pause_after: Vec<String>,
}

/// Constitutional check result — emitted by the prover gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionalCheck {
    pub structural_hash: String,
    pub pattern_scan: PatternScanResult,
    pub classification_valid: bool,
    pub declassifier_approved: Option<bool>,
    pub checks_passed: u8,
    pub checks_total: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternScanResult {
    pub passed: bool,
    pub violations: Vec<PatternViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternViolation {
    pub pattern: String,
    pub location: Option<String>,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViolationSeverity {
    /// Hard constitutional violation — execution must be blocked.
    Block,
    /// Warn but allow (e.g., console.log in non-debug code).
    Warn,
}

/// Runner configuration loaded from YAML/TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FractalConfig {
    pub runtime: RuntimeConfig,
    pub constitution: ConstitutionConfig,
    pub channels: ChannelDefaults,
    pub pipeline_defaults: PipelineDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_wasm_engine")]
    pub wasm_engine: String,
    #[serde(default = "default_max_memory")]
    pub max_cell_memory_mb: u32,
    #[serde(default = "default_timeout")]
    pub cell_timeout_secs: u32,
    #[serde(default = "default_max_depth")]
    pub max_pipeline_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub banned_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub require_signatures: bool,
    #[serde(default)]
    pub classification_mode: ClassificationMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ClassificationMode {
    #[default]
    Strict,
    Permissive,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDefaults {
    pub file: Option<FileDefaults>,
    pub http: Option<HttpDefaults>,
    pub git: Option<GitDefaults>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDefaults {
    pub default_allowed_paths: Vec<String>,
    pub max_file_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDefaults {
    pub default_allowed_hosts: Vec<String>,
    pub default_allowed_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitDefaults {
    pub allowed_refs: Vec<String>,
    pub protected_refs: Vec<String>,
    pub require_signed_commits: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDefaults {
    #[serde(default = "default_true")]
    pub auto_resume_on_approval: bool,
    #[serde(default)]
    pub store_intermediates: bool,
    #[serde(default = "default_true")]
    pub notify_on_completion: bool,
}

// ── Default value helpers ────────────────────────────────────────────────

fn default_true() -> bool { true }
fn default_wasm_engine() -> String { "wasmtime".into() }
fn default_max_memory() -> u32 { 256 }
fn default_timeout() -> u32 { 300 }
fn default_max_depth() -> u32 { 20 }
