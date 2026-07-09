//! `openshell-fractal` — Fractal Code runtime integration for OpenShell.
//!
//! This crate makes Fractal a first-class execution mode within OpenShell:
//!
//! - **Cell Runner** — executes Fractal cells inside OpenShell sandboxes,
//!   with policy derived from channel declarations and constitutional gating.
//! - **Constitution** — plugs Fractal's 10+ compile-time checks (banned patterns,
//!   structural signatures, taint inheritance) into `openshell-prover`.
//! - **Channel Mapper** — compiles Fractal's typed channel scopes into
//!   OpenShell YAML policy blocks at sandbox creation time.
//!
//! # Architecture
//!
//! ```text
//! .fc cell file (YAML + JS logic)
//!     │
//!     ├── constitution::validate_cell()  ← structural hash + pattern scan
//!     ├── channel_mapper::map_all()      ← channels → policy.yaml
//!     └── cell_runner::execute_cell()    ← sandbox create → run → collect
//! ```
//!
//! # Usage (from openshell-cli)
//!
//! ```bash
//! openshell fractal run cell ./my_cell.fc --input '{"x": 1}'
//! openshell fractal run scaffold ./my_pipeline.fc
//! openshell fractal validate ./my_cell.fc
//! openshell fractal channels ./my_cell.fc
//! openshell fractal policy ./my_cell.fc --output policy.yaml
//! ```

pub mod cell_runner;
pub mod channel_mapper;
pub mod constitution;
pub mod schema;

// Re-export primary types for CLI convenience
pub use cell_runner::{execute_cell, execute_scaffold, CellError, ScaffoldResult};
pub use channel_mapper::{map_all, map_channel, MappingResult};
pub use constitution::validate_cell;
pub use schema::{
    CellHealth, CellOutput, ClassificationLevel, ConstitutionalCheck, FractalCell,
    FractalConfig, FractalScaffold, TypedChannelConfig,
};
