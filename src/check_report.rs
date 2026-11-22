//! Generation-scoped migration check results.
//!
//! A [`CheckReport`] ties together one snapshot of the migration manifest, the
//! per-file check outcomes for that snapshot, and the information needed to
//! decide whether the invocation succeeded.  Reports are deliberately plain
//! values: a retry builds a new report for a new generation instead of
//! appending to, or reusing, the results of a previous attempt.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::same_name_method)]
#![allow(clippy::similar_names)]

use crate::adapters::MigrationFile;
use crate::violation::{Severity, Violation};
use crate::ViolationList;
use camino::Utf8PathBuf;
use serde::Serialize;
use std::fmt;

/// Identifies one snapshot of a migration manifest and the checks run against
/// that snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CheckGeneration(pub u64);

impl CheckGeneration {
    /// The first generation produced by a checker.
    pub const FIRST: Self = Self(1);

    /// Construct a generation from its numeric identifier.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The first generation produced by a checker.
    #[must_use]
    pub fn first() -> Self {
        Self::FIRST
    }

    /// The raw numeric identifier of this generation.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Derive the generation that follows this one.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl Default for CheckGeneration {
    fn default() -> Self {
        Self::FIRST
    }
}

impl From<u64> for CheckGeneration {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<CheckGeneration> for u64 {
    fn from(generation: CheckGeneration) -> Self {
        generation.0
    }
}

impl PartialEq<u64> for CheckGeneration {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<CheckGeneration> for u64 {
    fn eq(&self, other: &CheckGeneration) -> bool {
        *self == other.0
    }
}

impl fmt::Display for CheckGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Compatibility name for the generation of one migration check run.
pub type MigrationGeneration = CheckGeneration;

/// Compatibility name for a scan generation.
pub type ScanGeneration = CheckGeneration;

/// A migration file that could not be read, parsed, or checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct CheckFailure {
    /// Path of the migration file that failed.
    pub path: String,
    /// Compatibility alias for [`CheckFailure::path`].
    pub file: String,
    /// Human-readable failure message.
    pub message: String,
    /// Compatibility alias for [`CheckFailure::message`].
    pub error: String,
}

impl CheckFailure {
    /// Create a failure for `path`.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            file: String::new(),
            message: message.into(),
            error: String::new(),
        }
        .with_aliases()
    }

    /// Path of the failed migration file.
    #[must_use]
    pub fn path(&self) -> &str {
        if self.path.is_empty() {
            &self.file
        } else {
            &self.path
        }
    }

    /// Compatibility accessor for callers that call the failed path a file.
    #[must_use]
    pub fn file(&self) -> &str {
        if self.file.is_empty() {
            &self.path
        } else {
            &self.file
        }
    }

    /// Human-readable failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        if self.message.is_empty() {
            &self.error
        } else {
            &self.message
        }
    }

    /// Compatibility accessor for callers that call the message an error.
    #[must_use]
    pub fn error(&self) -> &str {
        if self.error.is_empty() {
            &self.message
        } else {
            &self.error
        }
    }

    fn with_aliases(mut self) -> Self {
        self.file.clone_from(&self.path);
        self.error.clone_from(&self.message);
        self
    }

    /// Render this failure as a blocking violation.
    ///
    /// This is used by the legacy `Vec<(String, ViolationList)>` API so a
    /// caller cannot mistake a directory with failed files for a clean run.
    #[must_use]
    pub fn as_violation(&self) -> Violation {
        let message = self.message();
        let operation = if message.to_ascii_lowercase().contains("parse") {
            "FAILED TO PARSE SQL"
        } else {
            "FAILED TO CHECK MIGRATION"
        };
        Violation::new(
            operation,
            message.to_string(),
            "Fix the migration file (or remove it from the directory), then rerun diesel-guard.",
        )
        .with_check_name("MigrationCheckFailure")
        .with_severity(Severity::Error)
    }
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path(), self.message())
    }
}

/// Outcome of checking one migration file in a generation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FileCheckOutcome {
    /// Path of the migration file.
    pub path: String,
    /// Violations found in the file. Empty means the file was checked and is
    /// clean, unless `failure` is set.
    pub violations: ViolationList,
    /// Why the file could not be checked.
    pub failure: Option<CheckFailure>,
}

impl FileCheckOutcome {
    /// A file that was checked successfully.
    pub fn success(path: impl Into<String>, violations: ViolationList) -> Self {
        Self {
            path: path.into(),
            violations,
            failure: None,
        }
    }

    /// A file that could not be checked.
    pub fn failed(failure: CheckFailure) -> Self {
        let path = failure.path().to_string();
        Self {
            path,
            violations: Vec::new(),
            failure: Some(failure),
        }
    }

    /// Whether this file could not be checked.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.failure.is_some()
    }

    /// Whether this file was checked successfully and produced no violations.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failure.is_none() && self.violations.is_empty()
    }

    /// Number of error-severity violations in this file.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.violations
            .iter()
            .filter(|(_, violation)| violation.severity == Severity::Error)
            .count()
    }

    /// Number of warning-severity violations in this file.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.violations
            .iter()
            .filter(|(_, violation)| violation.severity == Severity::Warning)
            .count()
    }
}

/// Snapshot of the migration files that belong to one check generation.
#[derive(Debug, Clone, Default)]
pub struct MigrationManifest {
    /// Generation shared by this manifest and its check results.
    pub generation: CheckGeneration,
    /// Migration files in the order they were checked.
    pub files: Vec<MigrationFile>,
}

impl MigrationManifest {
    /// Create an empty manifest for `generation`.
    #[must_use]
    pub fn new(generation: impl Into<CheckGeneration>) -> Self {
        Self {
            generation: generation.into(),
            files: Vec::new(),
        }
    }

    /// Add a migration file to the manifest.
    pub fn add(&mut self, file: MigrationFile) {
        self.files.push(file);
    }

    /// Number of migration files in the manifest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the manifest contains no migration files.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Paths of the migration files in manifest order.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|file| file.path.to_string())
            .collect()
    }
}

/// Results of one generation of migration checks.
///
/// `manifest` and `outcomes` always contain the same files in the same order.
/// `results` contains only files with violations and `failures` contains only
/// files that could not be checked, so neither collection can accidentally
/// stand in for the complete generation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CheckReport {
    /// Generation of this report.
    pub generation: CheckGeneration,
    /// Migration files included in this generation.
    pub manifest: Vec<String>,
    /// Rich migration file snapshot in manifest order.
    #[serde(skip_serializing)]
    pub manifest_files: Vec<MigrationFile>,
    /// Compatibility alias for [`CheckReport::manifest_files`].
    #[serde(skip_serializing)]
    pub migration_files: Vec<MigrationFile>,
    /// Rich snapshot of the migration manifest.
    #[serde(skip_serializing)]
    pub migration_manifest: MigrationManifest,
    /// Per-file outcomes in manifest order.
    pub outcomes: Vec<FileCheckOutcome>,
    /// Per-file violations, with files that have no violations omitted.
    pub results: Vec<(String, ViolationList)>,
    /// Files that could not be read, parsed, or checked.
    pub failures: Vec<CheckFailure>,
    /// Compatibility alias for [`CheckReport::failures`].
    pub failed_files: Vec<CheckFailure>,
}

impl CheckReport {
    /// Create an empty report for `generation`.
    #[must_use]
    pub fn new(generation: impl Into<CheckGeneration>) -> Self {
        let generation = generation.into();
        Self {
            generation,
            manifest: Vec::new(),
            manifest_files: Vec::new(),
            migration_files: Vec::new(),
            migration_manifest: MigrationManifest::new(generation),
            outcomes: Vec::new(),
            results: Vec::new(),
            failures: Vec::new(),
            failed_files: Vec::new(),
        }
    }

    /// Compatibility alias for constructors that call the report an outcome.
    #[must_use]
    pub fn with_generation(generation: impl Into<CheckGeneration>) -> Self {
        Self::new(generation)
    }

    /// Create an empty report in the first generation.
    #[must_use]
    pub fn first() -> Self {
        Self::new(CheckGeneration::FIRST)
    }

    /// Add a path that belongs to the generation without adapter metadata.
    pub fn add_manifest_path(&mut self, path: impl Into<String>) {
        let path = path.into();
        self.ensure_manifest_path(&path);
    }

    /// Add a migration file from the adapter to the manifest snapshot.
    pub fn add_manifest_file(&mut self, file: MigrationFile) {
        self.manifest.push(file.path.to_string());
        self.manifest_files.push(file.clone());
        self.migration_files.push(file.clone());
        self.migration_manifest.add(file);
    }

    /// Record a successfully checked file.
    pub fn record_violations(&mut self, path: impl Into<String>, violations: ViolationList) {
        let path = path.into();
        self.ensure_manifest_path(&path);
        if !violations.is_empty() {
            self.results.push((path.clone(), violations.clone()));
        }
        self.outcomes
            .push(FileCheckOutcome::success(path, violations));
    }

    /// Record a file that could not be checked.
    pub fn record_failure(&mut self, failure: CheckFailure) {
        self.ensure_manifest_path(failure.path());
        self.failures.push(failure.clone());
        self.failed_files.push(failure.clone());
        self.outcomes.push(FileCheckOutcome::failed(failure));
    }

    fn ensure_manifest_path(&mut self, path: &str) {
        if self
            .manifest
            .iter()
            .any(|existing| existing.as_str() == path)
        {
            return;
        }

        let file = MigrationFile::new(Utf8PathBuf::from(path), String::new());
        self.manifest.push(path.to_string());
        self.manifest_files.push(file.clone());
        self.migration_files.push(file.clone());
        self.migration_manifest.add(file);
    }

    /// Migration files included in this report.
    #[must_use]
    pub fn migration_files(&self) -> &[MigrationFile] {
        &self.migration_files
    }

    /// Rich migration file snapshot in manifest order.
    #[must_use]
    pub fn manifest_files(&self) -> &[MigrationFile] {
        &self.manifest_files
    }

    /// Paths of every migration in this generation, in manifest order.
    #[must_use]
    pub fn manifest_paths(&self) -> &[String] {
        &self.manifest
    }

    /// Per-file outcomes in manifest order.
    #[must_use]
    pub fn files(&self) -> &[FileCheckOutcome] {
        &self.outcomes
    }

    /// Files that could not be checked.
    #[must_use]
    pub fn failed_files(&self) -> &[CheckFailure] {
        &self.failed_files
    }

    /// Files that could not be checked.
    #[must_use]
    pub fn failures(&self) -> &[CheckFailure] {
        &self.failures
    }

    /// Compatibility alias for callers that name failed files explicitly.
    #[must_use]
    pub fn has_failed_files(&self) -> bool {
        self.has_failures()
    }

    /// Per-file violations in manifest order.
    #[must_use]
    pub fn violations(&self) -> &[(String, ViolationList)] {
        &self.results
    }

    /// Per-file violations in manifest order.
    #[must_use]
    pub fn results(&self) -> &[(String, ViolationList)] {
        &self.results
    }

    /// Paths of files that could not be checked.
    #[must_use]
    pub fn failed_paths(&self) -> Vec<&str> {
        self.failures
            .iter()
            .map(CheckFailure::path)
            .collect()
    }

    /// Numeric identifier of this report's generation.
    #[must_use]
    pub fn generation_id(&self) -> u64 {
        self.generation.as_u64()
    }

    /// Generation of this report.
    #[must_use]
    pub fn generation(&self) -> CheckGeneration {
        self.generation
    }

    /// Number of files that could not be checked.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Whether at least one file could not be checked.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Number of error-severity violations across all checked files.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .flat_map(|(_, violations)| violations)
            .filter(|(_, violation)| violation.severity == Severity::Error)
            .count()
    }

    /// Number of blocking issues: error violations plus failed files.
    #[must_use]
    pub fn blocking_error_count(&self) -> usize {
        self.error_count() + self.failures.len()
    }

    /// Number of warning-severity violations across all checked files.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.results
            .iter()
            .flat_map(|(_, violations)| violations)
            .filter(|(_, violation)| violation.severity == Severity::Warning)
            .count()
    }

    /// Whether this generation has any blocking error.
    ///
    /// A file that could not be checked is a blocking error even when it did
    /// not produce a violation.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.has_error_violations() || self.has_failures()
    }

    /// Whether any error-severity violation exists.
    #[must_use]
    pub fn has_error_violations(&self) -> bool {
        self.error_count() > 0
    }

    /// Whether any warning-severity violation exists.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.warning_count() > 0
    }

    /// Whether every file in the manifest was checked.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.has_failures()
    }

    /// Compatibility alias for [`CheckReport::is_complete`].
    #[must_use]
    pub fn all_files_checked(&self) -> bool {
        self.is_complete()
    }

    /// Whether the generation is successful: no errors and no failed files.
    /// Warnings do not make a generation fail.
    #[must_use]
    pub fn is_success(&self) -> bool {
        !self.has_errors()
    }

    /// Compatibility alias for [`CheckReport::is_success`].
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.is_success()
    }

    /// Whether the generation is clean: no violations at all and no failures.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.results.is_empty() && !self.has_failures()
    }

    /// Process exit status implied by this report.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.is_success() {
            0
        } else {
            1
        }
    }

    /// Convert the report to the historical result shape.
    ///
    /// Files that failed become blocking `MigrationCheckFailure` violations so
    /// legacy callers cannot accidentally treat an incomplete generation as
    /// clean. New callers should inspect `failures` directly.
    #[must_use]
    pub fn results_with_failures(&self) -> Vec<(String, ViolationList)> {
        if self.failures.is_empty() {
            return self.results.clone();
        }

        let mut merged = Vec::with_capacity(self.outcomes.len());
        for outcome in &self.outcomes {
            if let Some(failure) = &outcome.failure {
                merged.push((
                    outcome.path.clone(),
                    vec![(1usize, failure.as_violation())],
                ));
            } else if !outcome.violations.is_empty() {
                merged.push((outcome.path.clone(), outcome.violations.clone()));
            }
        }
        merged
    }
}

/// Compatibility name for a one-shot check report.
pub type CheckOutcome = CheckReport;

/// Compatibility name for a migration check report.
pub type MigrationCheckReport = CheckReport;

/// Compatibility name for a migration check result.
pub type CheckResult = CheckReport;

/// Compatibility name for one check batch/generation.
pub type CheckBatch = CheckReport;
