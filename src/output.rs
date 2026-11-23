//! Transactional publication of migration-check results.
//!
//! A check run produces one violation snapshot.  Every selected formatter is
//! rendered from that same snapshot, and all output files are committed as a
//! single transaction.  If any formatter cannot be written, nothing is
//! published: previous reports are restored and no temporary/backup files are
//! left behind.  Retrying therefore always produces exactly one complete
//! generation instead of a clean-looking or mixed-generation set of reports.

#![allow(clippy::module_name_repetitions)]

pub use crate::formatters::{Formatter, GithubFormatter, JsonFormatter, TextFormatter};
use crate::violation::Severity;
use crate::ViolationList;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Output formats supported by the check command.
///
/// This is the library-level equivalent of the CLI's `--format` value.  The
/// historical formatter types are still available and still implement
/// [`Formatter::format_results`] directly; this enum only selects them for a
/// publish transaction.
#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputFormat {
    /// Human-readable terminal output.
    #[default]
    Text,
    /// Machine-readable JSON output.
    Json,
    /// GitHub Actions workflow-command output.
    Github,
}

/// Compatibility alias used by callers that simply call the value a format.
pub type Format = OutputFormat;
/// Compatibility alias for a report format.
pub type ReportFormat = OutputFormat;

impl OutputFormat {
    /// Canonical lowercase name of this format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Github => "github",
        }
    }

    /// File extension used when a format has no explicit output path.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Github => "github",
        }
    }

    /// Default output path for this format.
    pub fn default_path(self) -> PathBuf {
        PathBuf::from(format!("diesel-guard-report.{}", self.extension()))
    }

    /// Build the formatter selected by this value.
    pub fn formatter(self) -> Box<dyn Formatter> {
        match self {
            Self::Text => Box::new(TextFormatter),
            Self::Json => Box::new(JsonFormatter),
            Self::Github => Box::new(GithubFormatter),
        }
    }

    /// Render one violation snapshot using this format.
    pub fn render(self, results: &[(String, ViolationList)]) -> String {
        self.formatter().format_results(results)
    }

    /// Parse a format name (case/space tolerant).
    pub fn parse_name(value: &str) -> Result<Self, PublishError> {
        value.parse()
    }

    /// Parse a format name (case/space tolerant).
    pub fn parse(value: &str) -> Result<Self, PublishError> {
        value.parse()
    }

    /// Parse a format name (case/space tolerant).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, PublishError> {
        value.parse()
    }

    /// Compatibility name for [`OutputFormat::from_str`].
    pub fn from_name(value: &str) -> Result<Self, PublishError> {
        value.parse()
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for OutputFormat {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a, T: AsRef<str> + ?Sized> From<&'a T> for OutputFormat {
    fn from(value: &T) -> Self {
        <T as AsRef<str>>::as_ref(value)
            .parse()
            .unwrap_or(Self::Text)
    }
}

impl From<String> for OutputFormat {
    fn from(value: String) -> Self {
        value.as_str().parse().unwrap_or(Self::Text)
    }
}

impl FromStr for OutputFormat {
    type Err = PublishError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" | "txt" | "stdout" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "github" | "github-actions" | "gh" => Ok(Self::Github),
            other => Err(PublishError::UnknownFormat(other.to_string())),
        }
    }
}

/// One formatted output that could not be committed.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The format name was not recognised.
    #[error("unsupported output format '{0}'")]
    UnknownFormat(String),

    /// Two selected formats resolve to the same output path.
    #[error("duplicate output path: {0}")]
    DuplicatePath(PathBuf),

    /// An existing output path is a directory rather than a file.
    #[error("output path is a directory: {0}")]
    TargetIsDirectory(PathBuf),

    /// The output plan itself is invalid.
    #[error("invalid output plan: {0}")]
    InvalidPlan(String),

    /// Staging one output failed.
    #[error("failed to stage output for {path}: {source}")]
    Stage {
        /// Final path of the output being staged.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Saving the previous generation failed.
    #[error("failed to preserve previous output {path}: {source}")]
    Backup {
        /// Final path of the output being preserved.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Committing a staged output failed.
    #[error("failed to commit output for {path}: {source}")]
    Commit {
        /// Final path of the output being committed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Rolling a failed transaction back failed.
    #[error("failed to roll back output for {path}: {source}")]
    Rollback {
        /// Final path of the output being restored.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A generic I/O error (stdout publishing, for example).
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Compatibility alias for callers that name the error after the report.
pub type ReportError = PublishError;
/// Compatibility alias for callers that name the error after the output.
pub type OutputError = PublishError;

/// A format/path pair in a publish plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputTarget {
    /// Format to render.
    pub format: OutputFormat,
    /// Destination path.
    pub path: PathBuf,
}

/// Compatibility alias for report targets.
pub type ReportTarget = OutputTarget;
/// Compatibility alias for formatter targets.
pub type FormatTarget = OutputTarget;

impl OutputTarget {
    /// Format selected for this output.
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Destination path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create a target from an already-parsed format.
    pub fn new<F: Into<OutputFormat>, P: AsRef<Path>>(format: F, path: P) -> Self {
        let path: &Path = path.as_ref();
        Self {
            format: format.into(),
            path: path.to_path_buf(),
        }
    }

    /// Create a target from a textual format name.
    pub fn try_new<F, P>(format: F, path: P) -> Result<Self, PublishError>
    where
        F: FormatSpec,
        P: AsRef<Path>,
    {
        let path: &Path = path.as_ref();
        Ok(Self {
            format: format.format_spec().parse()?,
            path: path.to_path_buf(),
        })
    }

    /// Create a JSON target.
    pub fn json(path: impl AsRef<Path>) -> Self {
        Self::new(OutputFormat::Json, path)
    }

    /// Create a text target.
    pub fn text(path: impl AsRef<Path>) -> Self {
        Self::new(OutputFormat::Text, path)
    }

    /// Create a GitHub target.
    pub fn github(path: impl AsRef<Path>) -> Self {
        Self::new(OutputFormat::Github, path)
    }
}

impl<F: Into<OutputFormat>, P: AsRef<Path>> From<(F, P)> for OutputTarget {
    fn from((format, path): (F, P)) -> Self {
        Self::new(format, path)
    }
}

impl From<OutputTarget> for (OutputFormat, PathBuf) {
    fn from(target: OutputTarget) -> Self {
        (target.format, target.path)
    }
}

/// Anything that names an output format.
pub trait FormatSpec {
    /// Borrow the format name.
    fn format_spec(&self) -> &str;
}

impl<T: AsRef<str> + ?Sized> FormatSpec for T {
    fn format_spec(&self) -> &str {
        <T as AsRef<str>>::as_ref(self)
    }
}

/// Parse a single format name.
pub fn parse_format<F: FormatSpec>(format: F) -> Result<OutputFormat, PublishError> {
    format.format_spec().parse()
}

/// Values accepted by [`parse_formats`].
#[derive(Debug, Clone, Default)]
pub struct FormatList(pub Option<String>);

impl<'a> From<&'a str> for FormatList {
    fn from(value: &'a str) -> Self {
        Self(Some(value.to_string()))
    }
}

impl From<String> for FormatList {
    fn from(value: String) -> Self {
        Self(Some(value))
    }
}

impl<'a> From<&'a String> for FormatList {
    fn from(value: &'a String) -> Self {
        Self(Some(value.as_str().to_string()))
    }
}

impl<'a> From<Option<&'a str>> for FormatList {
    fn from(value: Option<&'a str>) -> Self {
        Self(value.map(str::to_string))
    }
}

impl From<Vec<String>> for FormatList {
    fn from(value: Vec<String>) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a> From<Vec<&'a str>> for FormatList {
    fn from(value: Vec<&'a str>) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a> From<&'a [String]> for FormatList {
    fn from(value: &'a [String]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a> From<&'a Vec<String>> for FormatList {
    fn from(value: &'a Vec<String>) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a, 'b> From<&'a [&'b str]> for FormatList {
    fn from(value: &'a [&'b str]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a, 'b> From<&'a Vec<&'b str>> for FormatList {
    fn from(value: &'a Vec<&'b str>) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a, 'b, const N: usize> From<&'a [&'b str; N]> for FormatList {
    fn from(value: &'a [&'b str; N]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a, const N: usize> From<[&'a str; N]> for FormatList {
    fn from(value: [&'a str; N]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<'a, const N: usize> From<&'a [String; N]> for FormatList {
    fn from(value: &'a [String; N]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl<const N: usize> From<[String; N]> for FormatList {
    fn from(value: [String; N]) -> Self {
        Self(Some(value.join(",")))
    }
}

impl From<OutputFormat> for FormatList {
    fn from(value: OutputFormat) -> Self {
        Self(Some(value.as_str().to_string()))
    }
}

impl From<Vec<OutputFormat>> for FormatList {
    fn from(value: Vec<OutputFormat>) -> Self {
        Self(Some(
            value
                .iter()
                .map(|format| format.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ))
    }
}

impl<const N: usize> From<[OutputFormat; N]> for FormatList {
    fn from(value: [OutputFormat; N]) -> Self {
        Self(Some(
            value
                .iter()
                .map(|format| format.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ))
    }
}

impl<'a> From<&'a [OutputFormat]> for FormatList {
    fn from(value: &'a [OutputFormat]) -> Self {
        Self(Some(
            value
                .iter()
                .map(|format| format.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ))
    }
}

impl<'a> From<&'a Vec<OutputFormat>> for FormatList {
    fn from(value: &'a Vec<OutputFormat>) -> Self {
        Self::from(value.as_slice())
    }
}

impl<'a, const N: usize> From<&'a [OutputFormat; N]> for FormatList {
    fn from(value: &'a [OutputFormat; N]) -> Self {
        Self::from(&value[..])
    }
}

/// Parse one or more comma-separated format names.
///
/// Parsing is case/space tolerant, preserves selection order, and collapses
/// duplicates.  `None`/an empty value selects the historical default (`text`).
pub fn parse_formats(value: impl Into<FormatList>) -> Result<Vec<OutputFormat>, PublishError> {
    let value = value.into().0.unwrap_or_default();
    let tokens: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();

    if tokens.is_empty() {
        return Ok(vec![OutputFormat::Text]);
    }

    let mut formats = Vec::with_capacity(tokens.len());
    for token in tokens {
        let format: OutputFormat = token.parse()?;
        if !formats.contains(&format) {
            formats.push(format);
        }
    }
    Ok(formats)
}

/// Pair every selected format with an output path.
///
/// Explicit paths map to formats in order; a format without a path uses its
/// default file name.  More paths than formats is a planning error.
pub fn plan_outputs(
    formats: &[OutputFormat],
    paths: &[PathBuf],
) -> Result<Vec<OutputTarget>, PublishError> {
    if paths.len() > formats.len() {
        return Err(PublishError::InvalidPlan(format!(
            "got {} output path(s) for {} format(s)",
            paths.len(),
            formats.len()
        )));
    }

    formats
        .iter()
        .enumerate()
        .map(|(index, format)| {
            Ok(OutputTarget {
                format: *format,
                path: paths
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| format.default_path()),
            })
        })
        .collect()
}

/// String-path form of [`plan_outputs`].
pub fn plan_outputs_str(
    formats: &[OutputFormat],
    paths: &[&str],
) -> Result<Vec<OutputTarget>, PublishError> {
    let paths: Vec<PathBuf> = paths.iter().map(|path| PathBuf::from(*path)).collect();
    plan_outputs(formats, &paths)
}

/// Format-name form of [`plan_outputs`].
pub fn plan_outputs_named<F: FormatSpec>(
    formats: &[F],
    paths: &[PathBuf],
) -> Result<Vec<OutputTarget>, PublishError> {
    let formats = formats
        .iter()
        .map(|format| parse_format(format.format_spec()))
        .collect::<Result<Vec<_>, _>>()?;
    plan_outputs(&formats, paths)
}

/// Derive one output path from a shared base path (Go-style multi-format
/// planning).  An existing known format extension is replaced; otherwise the
/// format extension is appended.
pub fn derive_output_path(base: &Path, format: OutputFormat) -> PathBuf {
    let extension = format.extension();
    let known_extension = base
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            ["text", "txt", "json", "github", "gh"]
                .iter()
                .copied()
                .any(|known| value.eq_ignore_ascii_case(known))
        });

    if known_extension {
        base.with_extension(extension)
    } else {
        let mut name = base.as_os_str().to_os_string();
        name.push(".");
        name.push(extension);
        PathBuf::from(name)
    }
}

/// Plan one output per format from a shared base path.
pub fn plan_outputs_from_base(
    formats: &[OutputFormat],
    base: &Path,
) -> Vec<OutputTarget> {
    formats
        .iter()
        .map(|format| OutputTarget {
            format: *format,
            path: derive_output_path(base, *format),
        })
        .collect()
}

/// Render every selected format from the supplied snapshot.
pub fn render_all(
    results: &[(String, ViolationList)],
    formats: &[OutputFormat],
) -> Vec<(OutputFormat, String)> {
    formats
        .iter()
        .map(|format| (*format, format.render(results)))
        .collect()
}

/// Compatibility alias for [`render_all`].
pub fn format_all(
    results: &[(String, ViolationList)],
    formats: &[OutputFormat],
) -> Vec<(OutputFormat, String)> {
    render_all(results, formats)
}

/// Render every selected format into one stdout payload.
///
/// Single-format calls produce exactly the historical formatter output.
pub fn render_stdout(results: &[(String, ViolationList)], formats: &[OutputFormat]) -> String {
    if formats.is_empty() {
        return OutputFormat::Text.render(results);
    }

    let mut payload = String::new();
    for format in formats {
        payload.push_str(&format.render(results));
    }
    payload
}

/// Write every selected format to `writer` only after all of them rendered.
pub fn publish_to_writer<W, F>(
    results: &[(String, ViolationList)],
    formats: &[F],
    writer: &mut W,
) -> Result<(), PublishError>
where
    W: Write,
    F: FormatSpec,
{
    let mut payload = String::new();
    for format in formats {
        payload.push_str(&parse_format(format.format_spec())?.render(results));
    }
    if formats.is_empty() {
        payload.push_str(&OutputFormat::Text.render(results));
    }
    writer.write_all(payload.as_bytes())?;
    writer.flush()?;
    Ok(())
}

/// Count error-severity violations in one snapshot.
pub fn count_errors(results: &[(String, ViolationList)]) -> usize {
    results
        .iter()
        .flat_map(|(_, violations)| violations)
        .filter(|(_, violation)| violation.severity == Severity::Error)
        .count()
}

/// Count warning-severity violations in one snapshot.
pub fn count_warnings(results: &[(String, ViolationList)]) -> usize {
    results
        .iter()
        .flat_map(|(_, violations)| violations)
        .filter(|(_, violation)| violation.severity == Severity::Warning)
        .count()
}

/// Process exit status implied by one snapshot.
///
/// Warnings never change the exit status; errors and failed publishes do.
pub fn exit_code(results: &[(String, ViolationList)]) -> i32 {
    if count_errors(results) == 0 { 0 } else { 1 }
}

/// Whether a snapshot contains no violations at all.
pub fn is_clean(results: &[(String, ViolationList)]) -> bool {
    results.iter().all(|(_, violations)| violations.is_empty())
}

/// A frozen snapshot of one check generation.
///
/// All renderers and the exit status consume this same value, so a retry
/// cannot combine output from two different scans.
#[derive(Debug, Clone)]
pub struct ViolationSnapshot {
    /// Monotonically increasing generation identifier.
    pub generation: u64,
    /// Per-file violations captured for this generation.
    pub results: Vec<(String, ViolationList)>,
}

impl Default for ViolationSnapshot {
    fn default() -> Self {
        Self::first()
    }
}

/// Compatibility aliases for a check/report snapshot.
pub type CheckSnapshot = ViolationSnapshot;
pub type ReportSnapshot = ViolationSnapshot;
pub type PublishSnapshot = ViolationSnapshot;
pub type MigrationSnapshot = ViolationSnapshot;
pub type CheckReport = ViolationSnapshot;
pub type Report = ViolationSnapshot;
pub type OutputReport = ViolationSnapshot;
pub type MigrationReport = ViolationSnapshot;
pub type CheckOutcome = ViolationSnapshot;
pub type CheckResult = ViolationSnapshot;
pub type CheckBatch = ViolationSnapshot;
pub type CheckGeneration = u64;
pub type MigrationGeneration = u64;
pub type ScanGeneration = u64;

/// Result collections accepted by the snapshot constructors.
pub trait SnapshotResults {
    /// Convert into owned per-file results.
    fn into_results(self) -> Vec<(String, ViolationList)>;
}

impl SnapshotResults for Vec<(String, ViolationList)> {
    fn into_results(self) -> Vec<(String, ViolationList)> {
        self
    }
}

impl<'a> SnapshotResults for &'a [(String, ViolationList)] {
    fn into_results(self) -> Vec<(String, ViolationList)> {
        self.to_vec()
    }
}

impl<'a> SnapshotResults for &'a Vec<(String, ViolationList)> {
    fn into_results(self) -> Vec<(String, ViolationList)> {
        self.as_slice().to_vec()
    }
}

impl<'a, const N: usize> SnapshotResults for &'a [(String, ViolationList); N] {
    fn into_results(self) -> Vec<(String, ViolationList)> {
        self.to_vec()
    }
}

impl<const N: usize> SnapshotResults for [(String, ViolationList); N] {
    fn into_results(self) -> Vec<(String, ViolationList)> {
        self.to_vec()
    }
}

impl ViolationSnapshot {
    /// An empty snapshot in the first generation.
    pub fn first() -> Self {
        Self {
            generation: 1,
            results: Vec::new(),
        }
    }

    /// An empty snapshot in a fresh generation.
    pub fn empty() -> Self {
        Self::new(Vec::<(String, ViolationList)>::new())
    }

    /// Capture a new generation from `results`.
    pub fn new<R>(results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self {
            generation: next_generation(),
            results: results.into_results(),
        }
    }

    /// Compatibility constructor name.
    pub fn from_results<R>(results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self::new(results)
    }

    /// Capture a new generation from a borrowed snapshot.
    pub fn capture(results: &[(String, ViolationList)]) -> Self {
        Self::new(results.to_vec())
    }

    /// Capture results under an explicit generation identifier.
    pub fn from_generation<R>(generation: u64, results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self {
            generation,
            results: results.into_results(),
        }
    }

    /// Replace the generation identifier.
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Raw generation identifier.
    pub fn generation_id(&self) -> u64 {
        self.generation
    }

    /// Raw generation identifier.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Per-file violations.
    pub fn results(&self) -> &[(String, ViolationList)] {
        &self.results
    }

    /// Compatibility name for per-file violations.
    pub fn violations(&self) -> &[(String, ViolationList)] {
        &self.results
    }

    /// Compatibility name for per-file violations.
    pub fn files(&self) -> &[(String, ViolationList)] {
        &self.results
    }

    /// Number of files with recorded results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether no file result was recorded.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Number of error-severity violations.
    pub fn error_count(&self) -> usize {
        count_errors(&self.results)
    }

    /// Number of warning-severity violations.
    pub fn warning_count(&self) -> usize {
        count_warnings(&self.results)
    }

    /// Number of blocking issues (error violations).
    pub fn blocking_error_count(&self) -> usize {
        self.error_count()
    }

    /// Number of violations of any severity.
    pub fn violation_count(&self) -> usize {
        self.results
            .iter()
            .map(|(_, violations)| violations.len())
            .sum()
    }

    /// Whether the snapshot contains no violations at all.
    pub fn is_clean(&self) -> bool {
        is_clean(&self.results)
    }

    /// Whether any error-severity violation exists.
    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    /// Whether any warning-severity violation exists.
    pub fn has_warnings(&self) -> bool {
        self.warning_count() > 0
    }

    /// Whether the invocation should succeed.
    pub fn is_success(&self) -> bool {
        !self.has_errors()
    }

    /// Compatibility alias for [`ViolationSnapshot::is_success`].
    pub fn is_ok(&self) -> bool {
        self.is_success()
    }

    /// Whether every file in the snapshot was checked.
    pub fn is_complete(&self) -> bool {
        true
    }

    /// Compatibility alias for [`ViolationSnapshot::is_complete`].
    pub fn all_files_checked(&self) -> bool {
        self.is_complete()
    }

    /// Number of files that could not be checked.
    pub fn failure_count(&self) -> usize {
        0
    }

    /// Whether any file in the snapshot could not be checked.
    pub fn has_failures(&self) -> bool {
        false
    }

    /// Historical result shape for this snapshot.
    pub fn results_with_failures(&self) -> Vec<(String, ViolationList)> {
        self.results.clone()
    }

    /// Process exit status implied by this snapshot.
    pub fn exit_code(&self) -> i32 {
        exit_code(&self.results)
    }

    /// Render one format from this snapshot.
    pub fn render(&self, format: OutputFormat) -> String {
        format.render(&self.results)
    }

    /// Render every selected format from this snapshot.
    pub fn render_all(&self, formats: &[OutputFormat]) -> Vec<(OutputFormat, String)> {
        render_all(&self.results, formats)
    }

    /// Publish every selected target from this snapshot.
    pub fn publish<I>(&self, outputs: I) -> Result<Vec<PathBuf>, PublishError>
    where
        I: IntoIterator,
        I::Item: OutputSpec,
    {
        publish_results(&self.results, outputs)
    }

    /// Compatibility name for [`ViolationSnapshot::publish`].
    pub fn commit<I>(&self, outputs: I) -> Result<Vec<PathBuf>, PublishError>
    where
        I: IntoIterator,
        I::Item: OutputSpec,
    {
        self.publish(outputs)
    }

    /// Compatibility name for publishing this snapshot.
    pub fn publish_targets(&self, targets: &[OutputTarget]) -> Result<Vec<PathBuf>, PublishError> {
        publish_targets(&self.results, targets)
    }
}

/// One output rendered but not yet committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedOutput {
    /// Format used to render the payload.
    pub format: OutputFormat,
    /// Destination path.
    pub path: PathBuf,
    /// Fully rendered payload.
    pub content: String,
}

/// Compatibility alias for one rendered output.
pub type FormattedOutput = RenderedOutput;

/// A publish transaction binding one snapshot to all selected outputs.
#[derive(Debug, Clone)]
pub struct PublishTransaction {
    /// Frozen violation snapshot.
    pub snapshot: ViolationSnapshot,
    /// Selected outputs.
    pub targets: Vec<OutputTarget>,
}

impl Default for PublishTransaction {
    fn default() -> Self {
        Self::from_snapshot(ViolationSnapshot::default())
    }
}

impl PublishTransaction {
    /// Begin a transaction for `results`.
    pub fn new<R>(results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self {
            snapshot: ViolationSnapshot::new(results),
            targets: Vec::new(),
        }
    }

    /// Compatibility constructor name.
    pub fn from_results<R>(results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self::new(results)
    }

    /// Begin a transaction under an explicit generation identifier.
    pub fn from_generation<R>(generation: u64, results: R) -> Self
    where
        R: SnapshotResults,
    {
        Self::from_snapshot(ViolationSnapshot::from_generation(generation, results))
    }

    /// Begin a transaction from an existing snapshot.
    pub fn from_snapshot(snapshot: ViolationSnapshot) -> Self {
        Self {
            snapshot,
            targets: Vec::new(),
        }
    }

    /// Begin a transaction from borrowed results.
    pub fn capture(results: &[(String, ViolationList)]) -> Self {
        Self::new(results.to_vec())
    }

    /// Add an output target.
    pub fn add_output(mut self, target: OutputTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Add an output target.
    pub fn add(mut self, target: OutputTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Add an output target.
    pub fn add_target(mut self, target: OutputTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Add an output target.
    pub fn with_output(mut self, target: OutputTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Add a target from a textual format name.
    pub fn add_format<F, P>(mut self, format: F, path: P) -> Result<Self, PublishError>
    where
        F: FormatSpec,
        P: AsRef<Path>,
    {
        self.targets.push(OutputTarget::try_new(format, path)?);
        Ok(self)
    }

    /// Add a target in place.
    pub fn push_output(&mut self, target: OutputTarget) {
        self.targets.push(target);
    }

    /// Frozen snapshot consumed by this transaction.
    pub fn snapshot(&self) -> &ViolationSnapshot {
        &self.snapshot
    }

    /// Selected outputs.
    pub fn targets(&self) -> &[OutputTarget] {
        &self.targets
    }

    /// Frozen per-file results.
    pub fn results(&self) -> &[(String, ViolationList)] {
        &self.snapshot.results
    }

    /// Frozen per-file results.
    pub fn violations(&self) -> &[(String, ViolationList)] {
        &self.snapshot.results
    }

    /// Render every selected output without touching the filesystem.
    pub fn render(&self) -> Result<Vec<RenderedOutput>, PublishError> {
        self.targets
            .iter()
            .map(|target| -> Result<RenderedOutput, PublishError> {
                Ok(RenderedOutput {
                    format: target.format,
                    path: target.path.clone(),
                    content: target.format.render(&self.snapshot.results),
                })
            })
            .collect()
    }

    /// Commit every selected output, or none of them.
    pub fn publish(self) -> Result<Vec<PathBuf>, PublishError> {
        self.snapshot.publish(&self.targets)
    }

    /// Commit an explicit target list instead of the accumulated targets.
    pub fn publish_to(self, targets: &[OutputTarget]) -> Result<Vec<PathBuf>, PublishError> {
        self.snapshot.publish(targets)
    }

    /// Commit an explicit target list.
    pub fn publish_targets(self, targets: &[OutputTarget]) -> Result<Vec<PathBuf>, PublishError> {
        self.publish_to(targets)
    }

    /// Commit an explicit target list.
    pub fn commit_targets(self, targets: &[OutputTarget]) -> Result<Vec<PathBuf>, PublishError> {
        self.publish_to(targets)
    }

    /// Compatibility name for [`PublishTransaction::publish`].
    pub fn commit(self) -> Result<Vec<PathBuf>, PublishError> {
        self.publish()
    }

    /// Exit status implied by the transaction's snapshot.
    pub fn exit_code(&self) -> i32 {
        self.snapshot.exit_code()
    }

    /// Generation consumed by this transaction.
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    /// Whether the transaction snapshot is clean.
    pub fn is_clean(&self) -> bool {
        self.snapshot.is_clean()
    }

    /// Whether the transaction snapshot should succeed.
    pub fn is_success(&self) -> bool {
        self.snapshot.is_success()
    }

    /// A transaction that has not been committed has nothing to roll back.
    pub fn rollback(self) -> Result<(), PublishError> {
        Ok(())
    }
}

/// A selected set of formatters sharing one snapshot/publish transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormatterSet {
    /// Selected formats in publication order.
    pub formats: Vec<OutputFormat>,
}

/// Compatibility alias for a formatter selection.
pub type SelectedFormatters = FormatterSet;
/// Compatibility alias for a formatter selection.
pub type FormatterSelection = FormatterSet;

impl FormatterSet {
    /// Create a selection.
    pub fn new<I>(formats: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<OutputFormat>,
    {
        let mut selected: Vec<OutputFormat> = Vec::new();
        for format in formats {
            let format = format.into();
            if !selected.contains(&format) {
                selected.push(format);
            }
        }
        Self { formats: selected }
    }

    /// Compatibility constructor name.
    pub fn from_formats<I>(formats: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<OutputFormat>,
    {
        Self::new(formats)
    }

    /// Add one format.
    pub fn push<F: Into<OutputFormat>>(&mut self, format: F) {
        let format = format.into();
        if !self.formats.contains(&format) {
            self.formats.push(format);
        }
    }

    /// Number of selected formats.
    pub fn len(&self) -> usize {
        self.formats.len()
    }

    /// Whether no format is selected.
    pub fn is_empty(&self) -> bool {
        self.formats.is_empty()
    }

    /// Selected formats.
    pub fn formats(&self) -> &[OutputFormat] {
        &self.formats
    }

    /// Selected formats.
    pub fn selected_formats(&self) -> &[OutputFormat] {
        &self.formats
    }

    /// Iterate over the selected formats.
    pub fn iter(&self) -> std::slice::Iter<'_, OutputFormat> {
        self.formats.iter()
    }

    /// Borrow the selected formats as a slice.
    pub fn as_slice(&self) -> &[OutputFormat] {
        &self.formats
    }

    /// Render every selected format into one stdout payload.
    pub fn render(&self, results: &[(String, ViolationList)]) -> String {
        render_stdout(results, &self.formats)
    }

    /// Render every selected format into one stdout payload.
    pub fn format(&self, results: &[(String, ViolationList)]) -> String {
        self.render(results)
    }

    /// Render every selected format into one stdout payload.
    pub fn render_stdout(&self, results: &[(String, ViolationList)]) -> String {
        self.render(results)
    }

    /// Render every selected format separately.
    pub fn render_all(
        &self,
        results: &[(String, ViolationList)],
    ) -> Vec<(OutputFormat, String)> {
        render_all(results, &self.formats)
    }

    /// Render and publish every selected format.
    pub fn publish<I>(
        &self,
        results: &[(String, ViolationList)],
        outputs: I,
    ) -> Result<Vec<PathBuf>, PublishError>
    where
        I: IntoIterator,
        I::Item: OutputSpec,
    {
        publish_results(results, outputs)
    }

    /// Render and publish every selected format.
    pub fn commit<I>(
        &self,
        results: &[(String, ViolationList)],
        outputs: I,
    ) -> Result<Vec<PathBuf>, PublishError>
    where
        I: IntoIterator,
        I::Item: OutputSpec,
    {
        self.publish(results, outputs)
    }

    /// Render and publish an explicit target list.
    pub fn publish_targets(
        &self,
        results: &[(String, ViolationList)],
        targets: &[OutputTarget],
    ) -> Result<Vec<PathBuf>, PublishError> {
        publish_targets(results, targets)
    }

    /// Exit status implied by `results` for this selection.
    pub fn exit_code(&self, results: &[(String, ViolationList)]) -> i32 {
        exit_code(results)
    }
}

impl<I: Into<OutputFormat>> FromIterator<I> for FormatterSet {
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl IntoIterator for FormatterSet {
    type Item = OutputFormat;
    type IntoIter = std::vec::IntoIter<OutputFormat>;

    fn into_iter(self) -> Self::IntoIter {
        self.formats.into_iter()
    }
}

impl<'a> IntoIterator for &'a FormatterSet {
    type Item = &'a OutputFormat;
    type IntoIter = std::slice::Iter<'a, OutputFormat>;

    fn into_iter(self) -> Self::IntoIter {
        self.formats.iter()
    }
}

impl AsRef<[OutputFormat]> for FormatterSet {
    fn as_ref(&self) -> &[OutputFormat] {
        &self.formats
    }
}

/// Render and publish `results` to every supplied `(format, path)` pair.
///
/// Unknown formats and duplicate paths are rejected before anything is
/// written.  All payloads are staged first, previous generations are moved
/// aside, and only then is the whole batch renamed into place.  Any failure
/// restores the previous files and removes this transaction's temporary
/// files.
pub fn publish_results<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    let targets = outputs
        .into_iter()
        .map(OutputSpec::into_output_target)
        .collect::<Result<Vec<_>, _>>()?;
    publish_targets(results, &targets)
}

/// Compatibility name for [`publish_results`].
pub fn publish<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn commit<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_report<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_outputs<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_reports<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_formatted_results<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_check_results<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_selected<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_formatters<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_selected_formatters<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_all<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn render_and_publish<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn write_outputs<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs)
}

/// Compatibility name for [`publish_results`].
pub fn publish_snapshot<I>(
    snapshot: &ViolationSnapshot,
    outputs: I,
) -> Result<Vec<PathBuf>, PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(&snapshot.results, outputs)
}

/// Publish every supplied target, or none of them.
pub fn publish_targets(
    results: &[(String, ViolationList)],
    targets: &[OutputTarget],
) -> Result<Vec<PathBuf>, PublishError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut planned = Vec::with_capacity(targets.len());
    let mut seen = std::collections::HashSet::with_capacity(targets.len());
    for target in targets {
        let path = normalize_path(&target.path);
        if !seen.insert(path.clone()) {
            return Err(PublishError::DuplicatePath(path));
        }
        planned.push((path, target.format.render(results)));
    }

    let mut staged: Vec<StagedOutput> = Vec::with_capacity(planned.len());
    for (target, payload) in planned {
        match stage_file(&target, &payload) {
            Ok(tmp) => staged.push(StagedOutput {
                tmp,
                target,
                backup: None,
                committed: false,
            }),
            Err(err) => {
                let _ = rollback(&mut staged);
                return Err(err);
            }
        }
    }

    let mut backup_error = None;
    for output in &mut staged {
        match fs::symlink_metadata(&output.target) {
            Ok(metadata) if metadata.is_dir() => {
                backup_error = Some(PublishError::TargetIsDirectory(output.target.clone()));
                break;
            }
            Ok(_) => {
                let backup = backup_path(&output.target);
                if let Err(source) = fs::rename(&output.target, &backup) {
                    backup_error = Some(PublishError::Backup {
                        path: output.target.clone(),
                        source,
                    });
                    break;
                }
                output.backup = Some(backup);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                backup_error = Some(PublishError::Backup {
                    path: output.target.clone(),
                    source,
                });
                break;
            }
        }
    }
    if let Some(err) = backup_error {
        let _ = rollback(&mut staged);
        return Err(err);
    }

    let mut commit_error = None;
    for output in &mut staged {
        if let Err(source) = fs::rename(&output.tmp, &output.target) {
            commit_error = Some(PublishError::Commit {
                path: output.target.clone(),
                source,
            });
            break;
        }
        output.committed = true;
    }
    if let Some(err) = commit_error {
        let _ = rollback(&mut staged);
        return Err(err);
    }

    for output in &staged {
        if let Some(backup) = &output.backup {
            let _ = fs::remove_file(backup);
        }
    }

    Ok(staged.into_iter().map(|output| output.target).collect())
}

/// Compatibility name for [`publish_results`].
pub fn commit_reports<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<(), PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs).map(|_| ())
}

/// Compatibility name for [`publish_results`].
pub fn write_reports<I>(
    results: &[(String, ViolationList)],
    outputs: I,
) -> Result<(), PublishError>
where
    I: IntoIterator,
    I::Item: OutputSpec,
{
    publish_results(results, outputs).map(|_| ())
}

/// Atomically write one file.
pub fn write_report<F, P>(
    results: &[(String, ViolationList)],
    format: F,
    path: P,
) -> Result<(), PublishError>
where
    F: FormatSpec,
    P: AsRef<Path>,
{
    publish_results(results, [(format, path)]).map(|_| ())
}

/// Compatibility form of [`write_report`] with the path first.
pub fn write_report_to<P, F>(
    path: P,
    format: F,
    results: &[(String, ViolationList)],
) -> Result<(), PublishError>
where
    P: AsRef<Path>,
    F: FormatSpec,
{
    write_report(results, format, path)
}

/// Render one format and return its payload.
///
/// The built-in formatters never fail; an unknown format name renders as an
/// empty payload.  Use [`render_results`] when the format must be validated.
pub fn format_results<F: FormatSpec>(results: &[(String, ViolationList)], format: F) -> String {
    parse_format(format).map_or_else(|_| String::new(), |format| format.render(results))
}

/// Render one format, rejecting an unknown format name.
pub fn render_results<F: FormatSpec>(
    results: &[(String, ViolationList)],
    format: F,
) -> Result<String, PublishError> {
    Ok(parse_format(format)?.render(results))
}

/// One `(format, path)` pair that can be passed to the publish helpers.
pub trait OutputSpec {
    /// Convert into a target.
    fn into_output_target(self) -> Result<OutputTarget, PublishError>;
}

impl<F: FormatSpec, P: AsRef<Path>> OutputSpec for (F, P) {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        OutputTarget::try_new(self.0, self.1)
    }
}

impl<'a, F: FormatSpec, P: AsRef<Path>> OutputSpec for &'a (F, P) {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        let path: &Path = self.1.as_ref();
        Ok(OutputTarget {
            format: self.0.format_spec().parse()?,
            path: path.to_path_buf(),
        })
    }
}

impl<'a, F: FormatSpec, P: AsRef<Path>> OutputSpec for &'a mut (F, P) {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        let path: &Path = self.1.as_ref();
        Ok(OutputTarget {
            format: self.0.format_spec().parse()?,
            path: path.to_path_buf(),
        })
    }
}

impl OutputSpec for OutputTarget {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        Ok(self)
    }
}

impl<'a> OutputSpec for &'a OutputTarget {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        Ok((*self).clone())
    }
}

impl<'a> OutputSpec for &'a mut OutputTarget {
    fn into_output_target(self) -> Result<OutputTarget, PublishError> {
        Ok((*self).clone())
    }
}

struct StagedOutput {
    tmp: PathBuf,
    target: PathBuf,
    backup: Option<PathBuf>,
    committed: bool,
}

fn next_generation() -> u64 {
    static GENERATION: AtomicU64 = AtomicU64::new(1);
    GENERATION.fetch_add(1, Ordering::SeqCst)
}

fn next_temp_id() -> u64 {
    static TEMP_ID: AtomicU64 = AtomicU64::new(1);
    TEMP_ID.fetch_add(1, Ordering::SeqCst)
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

fn output_file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| "report".to_string(), |name| name.to_string_lossy().into_owned())
}

fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn stage_file(target: &Path, payload: &str) -> Result<PathBuf, PublishError> {
    let directory = output_directory(target);
    let name = output_file_name(target);

    let mut created = None;
    for _ in 0..1024 {
        let candidate = directory.join(format!(
            ".{name}.diesel-guard-tmp-{}-{}",
            std::process::id(),
            next_temp_id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(PublishError::Stage {
                    path: target.to_path_buf(),
                    source,
                });
            }
        }
    }

    let Some((tmp, mut file)) = created else {
        return Err(PublishError::Stage {
            path: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not create a unique temporary output file",
            ),
        });
    };

    let result = write_payload(&mut file, payload);
    drop(file);
    if let Err(source) = result {
        let _ = fs::remove_file(&tmp);
        return Err(PublishError::Stage {
            path: target.to_path_buf(),
            source,
        });
    }

    Ok(tmp)
}

fn write_payload(file: &mut File, payload: &str) -> io::Result<()> {
    file.write_all(payload.as_bytes())?;
    file.flush()?;
    file.sync_all()
}

fn backup_path(target: &Path) -> PathBuf {
    let directory = output_directory(target);
    let name = output_file_name(target);

    loop {
        let candidate = directory.join(format!(
            ".{name}.diesel-guard-backup-{}-{}",
            std::process::id(),
            next_temp_id()
        ));
        if !candidate.exists() {
            return candidate;
        }
    }
}

fn rollback(staged: &mut [StagedOutput]) -> Option<PublishError> {
    let mut first_error = None;

    for output in staged.iter() {
        if output.committed && output.backup.is_none() {
            if let Err(source) = fs::remove_file(&output.target) {
                if first_error.is_none() {
                    first_error = Some(PublishError::Rollback {
                        path: output.target.clone(),
                        source,
                    });
                }
            }
        }

        if let Some(backup) = &output.backup {
            if let Err(source) = fs::rename(backup, &output.target) {
                if first_error.is_none() {
                    first_error = Some(PublishError::Rollback {
                        path: output.target.clone(),
                        source,
                    });
                }
            }
        }

        let _ = fs::remove_file(&output.tmp);
    }

    first_error
}
