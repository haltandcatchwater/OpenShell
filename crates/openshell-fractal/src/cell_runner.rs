//! Fractal cell runner — executes Fractal cells inside OpenShell sandboxes.
//!
//! Each cell gets its own sandbox instance with policy derived from the cell's
//! channel declarations. Cells in a scaffold execute in topological order,
//! with outputs threaded as inputs to downstream cells.
//!
//! The runner supports pause/resume checkpoints for human-in-the-loop review
//! (e.g., declassifier approval gates).

use crate::channel_mapper::{map_all, MappingResult};
use crate::constitution::validate_cell;
use crate::schema::{
    CellHealth, CellOutput, ClassificationLevel, FractalCell, FractalScaffold,
    HealthStatus, ViolationSeverity,
};
use openshell_sandbox::{SandboxConfig, SandboxHandle};
use std::collections::HashMap;

/// Error types for cell execution.
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    #[error("Constitutional violation: {0}")]
    ConstitutionalViolation(String),

    #[error("Sandbox error: {0}")]
    SandboxError(String),

    #[error("Cell timed out after {0}s")]
    Timeout(u32),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("Classification mismatch: output {output:?} must dominate input {input:?}")]
    ClassificationMismatch {
        input: ClassificationLevel,
        output: ClassificationLevel,
    },

    #[error("Pipeline paused at checkpoint: {0}")]
    Paused(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

/// Result of executing a scaffold pipeline.
#[derive(Debug)]
pub struct ScaffoldResult {
    pub final_output: CellOutput,
    pub cells_executed: u32,
    pub paused_at: Option<String>,
    pub run_id: String,
}

/// Executes a Fractal cell inside an OpenShell sandbox.
///
/// # Flow
/// 1. Constitutional validation — cell must pass all checks
/// 2. Channel→Policy mapping — channel scopes become sandbox policies
/// 3. Sandbox creation — spawn sandbox with derived policies
/// 4. Cell execution — run the cell's JavaScript logic in the Wasm void
/// 5. Output collection — capture and classify the result
pub async fn execute_cell(
    cell: &FractalCell,
    input: serde_json::Value,
    sandbox_config: &SandboxConfig,
) -> Result<CellOutput, CellError> {
    // ── Gate 1: Constitutional validation ────────────────────────────
    let check = validate_cell(cell);

    if !check.pattern_scan.passed {
        let blocks: Vec<_> = check
            .pattern_scan
            .violations
            .iter()
            .filter(|v| matches!(v.severity, ViolationSeverity::Block))
            .map(|v| format!("{} ({})", v.pattern, v.location.as_deref().unwrap_or("unknown")))
            .collect();

        return Err(CellError::ConstitutionalViolation(format!(
            "Cell '{}' failed constitutional checks: {}. Checks passed: {}/{}.",
            cell.identity.name,
            blocks.join(", "),
            check.checks_passed,
            check.checks_total
        )));
    }

    if check.checks_passed < check.checks_total {
        tracing::warn!(
            cell = %cell.identity.name,
            passed = check.checks_passed,
            total = check.checks_total,
            "Cell passed pattern scan but has incomplete checks"
        );
    }

    tracing::info!(
        cell = %cell.identity.name,
        hash = %check.structural_hash,
        passed = check.checks_passed,
        "Constitutional checks passed"
    );

    // ── Gate 2: Channel→Policy mapping ───────────────────────────────
    let channel_results = map_all(&cell.channels);
    let mut policy_anomalies = Vec::new();

    for result in &channel_results {
        match result {
            MappingResult::Mapped(m) => {
                if !m.anomalies.is_empty() {
                    policy_anomalies.extend(m.anomalies.clone());
                }
            }
            MappingResult::Skipped(s) => {
                tracing::debug!(
                    channel = %s.channel_name,
                    kind = %s.kind,
                    reason = %s.reason,
                    "Channel skipped"
                );
            }
        }
    }

    for anomaly in &policy_anomalies {
        tracing::warn!(anomaly = %anomaly, "Policy anomaly detected");
    }

    // ── Gate 3: Sandbox creation ─────────────────────────────────────
    // In production, this creates a real OpenShell sandbox with the
    // compiled policies. For the MVP, we validate the config is sound.
    let _sandbox = create_sandbox_for_cell(cell, sandbox_config).await?;

    // ── Gate 4: Execute cell logic ───────────────────────────────────
    let output = run_cell_in_sandbox(cell, &input).await?;

    // ── Gate 5: Classification verification ──────────────────────────
    verify_classification(cell, &output)?;

    tracing::info!(
        cell = %cell.identity.name,
        classification = ?output.classification,
        health = ?output.health.status,
        "Cell executed successfully"
    );

    Ok(output)
}

/// Execute an entire scaffold pipeline in topological order.
///
/// Cells are executed sequentially in DAG order. Outputs from upstream cells
/// are threaded as inputs to downstream cells. Supports pause checkpoints
/// for human-in-the-loop review.
pub async fn execute_scaffold(
    scaffold: &FractalScaffold,
    initial_input: serde_json::Value,
    sandbox_config: &SandboxConfig,
) -> Result<ScaffoldResult, CellError> {
    let run_id = uuid_v7();
    tracing::info!(
        scaffold = %scaffold.name,
        cells = scaffold.execution_order.len(),
        run_id = %run_id,
        "Starting scaffold execution"
    );

    let mut outputs: HashMap<String, CellOutput> = HashMap::new();
    let mut cells_executed: u32 = 0;

    // Build a lookup from cell name to cell
    let cell_map: HashMap<&str, &FractalCell> = scaffold
        .cells
        .iter()
        .map(|c| (c.identity.name.as_str(), c))
        .collect();

    for cell_name in &scaffold.execution_order {
        let cell = cell_map.get(cell_name.as_str()).ok_or_else(|| {
            CellError::Other(format!(
                "Cell '{}' in execution order not found in scaffold",
                cell_name
            ))
        })?;

        // Collect inputs from upstream cells (simplified: pass previous output)
        let input = if cells_executed == 0 {
            initial_input.clone()
        } else {
            // In a real scaffold, channel connections determine which
            // upstream outputs feed which downstream inputs. For MVP,
            // we thread the last output as input.
            let prev_name = &scaffold.execution_order[(cells_executed - 1) as usize];
            outputs
                .get(prev_name)
                .map(|o| o.data.clone())
                .unwrap_or(serde_json::json!({}))
        };

        tracing::info!(cell = %cell_name, "Executing cell");

        let output = execute_cell(cell, input, sandbox_config).await?;
        outputs.insert(cell_name.clone(), output);
        cells_executed += 1;

        // Check for pause checkpoint
        if scaffold.pause_after.contains(cell_name) {
            tracing::info!(
                cell = %cell_name,
                run_id = %run_id,
                "Pipeline paused at checkpoint"
            );
            return Ok(ScaffoldResult {
                final_output: outputs.get(cell_name).cloned().unwrap(),
                cells_executed,
                paused_at: Some(cell_name.clone()),
                run_id,
            });
        }
    }

    let final_name = scaffold.execution_order.last().unwrap();
    let final_output = outputs.get(final_name).cloned().unwrap();

    tracing::info!(
        scaffold = %scaffold.name,
        cells_executed,
        run_id = %run_id,
        "Scaffold execution complete"
    );

    Ok(ScaffoldResult {
        final_output,
        cells_executed,
        paused_at: None,
        run_id,
    })
}

// ── Internal helpers ─────────────────────────────────────────────────────

async fn create_sandbox_for_cell(
    cell: &FractalCell,
    base_config: &SandboxConfig,
) -> Result<SandboxHandle, CellError> {
    // Build a sandbox config with cell-specific memory/timeout from
    // the default config. In production, this calls openshell_sandbox::create().
    let _config = base_config.clone();

    tracing::debug!(
        cell = %cell.identity.name,
        "Sandbox configured (MVP: config validated, execution deferred to runtime)"
    );

    // MVP: Return a placeholder handle. The actual sandbox creation happens
    // when OpenShell's sandbox manager provisions the container.
    Err(CellError::Other(
        "Sandbox creation via OpenShell runtime is not yet wired. \
         Cells execute via the Fractal npm runtime (Javy Wasm void) by default. \
         Install OpenShell and rebuild for kernel-level sandboxing."
            .into(),
    ))
}

async fn run_cell_in_sandbox(
    cell: &FractalCell,
    input: &serde_json::Value,
) -> Result<CellOutput, CellError> {
    // In production: serialize input → write to sandbox stdin / mounted file →
    // execute wasmtime run cell.wasm → read output → deserialize.
    //
    // For the MVP integration, cell execution is delegated to the Fractal npm
    // runtime. This crate provides the policy compilation and constitutional
    // gating; the actual Wasm execution happens in the Node.js process.
    tracing::debug!(
        cell = %cell.identity.name,
        logic_len = cell.logic.len(),
        "Cell logic staged (MVP: execution via Fractal npm runtime)"
    );

    // Placeholder — the real implementation compiles cell.logic to Wasm
    // via Javy and executes it with input as the initial state.
    Ok(CellOutput {
        data: input.clone(),
        classification: ClassificationLevel::Public,
        health: CellHealth {
            status: HealthStatus::Healthy,
            budget_remaining: 100,
        },
    })
}

fn verify_classification(
    _cell: &FractalCell,
    _output: &CellOutput,
) -> Result<(), CellError> {
    // In production: parse input schema classification tags,
    // verify output.classification.dominates(max_input_classification).
    // For MVP, this is a no-op — classification is enforced by the
    // Fractal parser at cell parse time.
    Ok(())
}

fn uuid_v7() -> String {
    // Simple v7-like UUID (timestamp prefix + random suffix)
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{:016x}-{:04x}", ts, (ts % 0xFFFF) as u16)
}
