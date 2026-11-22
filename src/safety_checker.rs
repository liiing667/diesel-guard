use crate::ViolationList;
use crate::adapters::{DieselAdapter, MigrationAdapter, SqlxAdapter};
use crate::checks::{MigrationContext, Registry};
use crate::config::Config;
use crate::error::Result;
use crate::parser;
use crate::scripting;
use crate::violation::RuleGeneration;
use camino::Utf8Path;
use std::fs;
use std::io::{self, BufRead, BufReader};

pub struct SafetyChecker {
    registry: Registry,
    config: Config,
    known_check_names: Vec<String>,
    /// Generation shared by the built-in rules, the loaded custom scripts,
    /// and every violation this checker produces.
    generation: RuleGeneration,
}

impl SafetyChecker {
    /// Create with specific configuration (useful for testing)
    ///
    /// # Errors
    ///
    /// Returns [`crate::config::ConfigError::InvalidCheckName`] if any name in `enable_checks`,
    /// `disable_checks`, or `warn_checks` is not a known check name (built-in or
    /// custom script stem from `custom_checks_dir`).
    ///
    /// Returns [`crate::config::ConfigError::ScriptLoadError`] if a custom
    /// script cannot be read or compiled. The whole build fails rather than
    /// silently dropping the broken script: a checker must never report
    /// "all rules passed" while running only part of the configured rule set.
    pub fn with_config(config: Config) -> std::result::Result<Self, crate::config::ConfigError> {
        Self::build(config, RuleGeneration::FIRST)
    }

    /// Construct a checker whose entire rule set (built-in checks plus every
    /// custom script) belongs to `generation`. All violation evidence the
    /// checker produces is stamped with the same generation.
    fn build(
        config: Config,
        generation: RuleGeneration,
    ) -> std::result::Result<Self, crate::config::ConfigError> {
        let mut registry = Registry::with_config_and_generation(&config, generation);

        if let Some(ref dir) = config.custom_checks_dir {
            let dir = Utf8Path::new(dir);
            if dir.exists() {
                // Strict loading: any broken script aborts the build so the
                // checker can never run a half-loaded custom rule set.
                let checks = scripting::load_custom_checks_strict(dir, &config)?;
                for check in checks {
                    registry.add_check(check);
                }
            }
        }

        // Validate check names against all built-in names and custom script stems.
        let builtin_names = Registry::builtin_check_names();
        let custom_names: Vec<String> = config
            .custom_checks_dir
            .as_deref()
            .and_then(|d| {
                let dir = Utf8Path::new(d);
                if dir.exists() {
                    std::fs::read_dir(dir).ok()
                } else {
                    None
                }
            })
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("rhai") {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .map(std::string::ToString::to_string)
                } else {
                    None
                }
            })
            .collect();
        let known_check_names = builtin_names
            .iter()
            .map(|name| (*name).to_string())
            .chain(custom_names.iter().cloned())
            .collect::<Vec<_>>();

        let validate_names = |names: &[String]| {
            for name in names {
                if !known_check_names.iter().any(|known| known == name) {
                    return Err(crate::config::ConfigError::InvalidCheckName {
                        invalid_name: name.clone(),
                    });
                }
            }
            Ok(())
        };

        validate_names(&config.disable_checks)?;
        validate_names(&config.enable_checks)?;
        validate_names(&config.warn_checks)?;

        Ok(Self {
            registry,
            config,
            known_check_names,
            generation,
        })
    }

    /// Expose the registry for introspection (e.g. list-checks, explain).
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Generation of the rule set currently backing this checker.
    ///
    /// The built-in rules, the loaded custom script collection, and all
    /// violation evidence returned by this checker share this generation.
    #[must_use]
    pub fn rule_generation(&self) -> RuleGeneration {
        self.generation
    }

    /// Atomically reload every rule (built-in checks and custom scripts) from
    /// disk using the same configuration.
    ///
    /// On success the checker moves to a fresh rule generation and
    /// [`SafetyChecker::rule_generation`] reflects it. If anything fails
    /// (e.g. a newly added script does not compile), the rebuild is discarded:
    /// the checker keeps its previous, fully loaded generation and still
    /// runs the complete previous rule set. A failed hot reload therefore can
    /// never leave the checker running half a rule set while claiming success.
    ///
    /// # Errors
    ///
    /// Forwards the same errors as [`SafetyChecker::with_config`]; on error
    /// the checker is left unchanged.
    pub fn reload(&mut self) -> std::result::Result<RuleGeneration, crate::config::ConfigError> {
        let next_generation = self.generation.next();
        // Build the full replacement before touching `self` so any failure
        // leaves the current generation completely intact.
        let rebuilt = Self::build(self.config.clone(), next_generation)?;
        *self = rebuilt;
        Ok(next_generation)
    }

    /// Build the migration adapter for the configured framework.
    fn adapter(&self) -> Result<Box<dyn MigrationAdapter>> {
        match self.config.framework.as_str() {
            "diesel" => Ok(Box::new(DieselAdapter)),
            "sqlx" => Ok(Box::new(SqlxAdapter)),
            _ => Err(crate::config::ConfigError::InvalidFramework {
                framework: self.config.framework.clone(),
            }
            .into()),
        }
    }

    fn warn_unknown_migration_disabled_checks(&self, disabled_checks: &[String], source: &str) {
        let mut warned_names = Vec::new();

        for name in disabled_checks {
            let name = name.as_str();
            if warned_names.contains(&name) {
                continue;
            }
            warned_names.push(name);

            if !self
                .known_check_names
                .iter()
                .any(|known| known.as_str() == name)
            {
                eprintln!(
                    "Warning: Unknown check name '{name}' in {source}. Run list-checks to see available checks."
                );
            }
        }
    }

    /// Check SQL string for violations
    pub fn check_sql(&self, sql: &str) -> Result<ViolationList> {
        let parsed = parser::parse_with_metadata(sql)?;
        let ctx = MigrationContext::default().with_disabled_checks(&parsed.disabled_checks);
        self.warn_unknown_migration_disabled_checks(
            &ctx.disabled_checks,
            "migration-scoped disable_checks",
        );
        Ok(self.registry.check_stmts_with_context(
            &parsed.stmts,
            &parsed.sql,
            &parsed.ignore_ranges,
            &self.config,
            &ctx,
        ))
    }

    /// Check a single migration file
    pub fn check_file(&self, path: &Utf8Path) -> Result<ViolationList> {
        let sql = fs::read_to_string(path)?;

        let adapter = self.adapter()?;
        let ctx = adapter.extract_migration_metadata(path);

        match parser::parse_with_metadata(&sql) {
            Ok(parsed) => {
                let ctx = ctx.with_disabled_checks(&parsed.disabled_checks);
                self.warn_unknown_migration_disabled_checks(
                    &ctx.disabled_checks,
                    &format!("{path} migration-scoped disable_checks"),
                );
                Ok(self.registry.check_stmts_with_context(
                    &parsed.stmts,
                    &parsed.sql,
                    &parsed.ignore_ranges,
                    &self.config,
                    &ctx,
                ))
            }
            Err(e) => Err(e.with_file_context(path.as_str(), sql)),
        }
    }

    /// Check all migration files in a directory
    pub fn check_directory(&self, dir: &Utf8Path) -> Result<Vec<(String, ViolationList)>> {
        let adapter = self.adapter()?;

        if let Some(start_after) = self.config.start_after.as_deref() {
            adapter
                .validate_timestamp(start_after)
                .map_err(|e| crate::config::ConfigError::InvalidTimestampFormat(e.to_string()))?;
        }

        let migration_files = adapter
            .collect_migration_files(
                dir,
                self.config.start_after.as_deref(),
                self.config.check_down,
            )
            .map_err(|e| crate::error::DieselGuardError::parse_error(e.to_string()))?;

        let mut results = Vec::new();

        for mig_file in migration_files {
            let sql = fs::read_to_string(&mig_file.path)?;

            let ctx = adapter.extract_migration_metadata(&mig_file.path);

            match parser::parse_with_metadata(&sql) {
                Ok(parsed) => {
                    let ctx = ctx.with_disabled_checks(&parsed.disabled_checks);
                    self.warn_unknown_migration_disabled_checks(
                        &ctx.disabled_checks,
                        &format!("{} migration-scoped disable_checks", mig_file.path),
                    );
                    let violations = self.registry.check_stmts_with_context(
                        &parsed.stmts,
                        &parsed.sql,
                        &parsed.ignore_ranges,
                        &self.config,
                        &ctx,
                    );
                    if !violations.is_empty() {
                        results.push((mig_file.path.to_string(), violations));
                    }
                }
                Err(e) => {
                    return Err(e.with_file_context(mig_file.path.as_str(), sql));
                }
            }
        }

        Ok(results)
    }

    // check a migration string from a buffer
    fn check_buffer(&self, reader: &mut dyn BufRead) -> Result<ViolationList> {
        let mut buffer = String::new();
        reader.read_to_string(&mut buffer)?;
        self.check_sql(&buffer)
    }

    /// Check a path (file, directory or stdin)
    pub fn check_path(&self, path: &Utf8Path) -> Result<Vec<(String, ViolationList)>> {
        // "-" means we're using stdin as an input.
        if path.as_str() == "-" {
            let violations = self.check_buffer(&mut BufReader::new(io::stdin().lock()))?;
            if violations.is_empty() {
                Ok(vec![])
            } else {
                Ok(vec![(path.to_string(), violations)])
            }
        } else if path.is_dir() {
            self.check_directory(path)
        } else {
            let violations = self.check_file(path)?;
            if violations.is_empty() {
                Ok(vec![])
            } else {
                Ok(vec![(path.to_string(), violations)])
            }
        }
    }
}

impl Default for SafetyChecker {
    fn default() -> Self {
        Self::with_config(Config::default()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_check_safe_sql() {
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["AddColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let sql = "ALTER TABLE users ADD COLUMN email VARCHAR(255);";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_check_unsafe_sql() {
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["AddColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let sql = "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_with_disabled_checks() {
        let config = Config {
            disable_checks: vec!["AddColumnCheck".to_string()],
            ..Default::default()
        };
        let checker = SafetyChecker::with_config(config).unwrap();

        let sql = "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;";
        let violations = checker.check_sql(sql).unwrap();
        assert!(
            !violations
                .iter()
                .any(|(_, violation)| violation.operation == "ADD COLUMN with DEFAULT"),
            "AddColumnCheck should be disabled"
        );
    }

    #[test]
    fn test_reindex_without_concurrently_detected() {
        let checker = SafetyChecker::default();
        let sql = "REINDEX INDEX idx_users_email;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1.operation, "REINDEX without CONCURRENTLY");
    }

    #[test]
    fn test_reindex_table_without_concurrently_detected() {
        let checker = SafetyChecker::default();
        let sql = "REINDEX TABLE users;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1.operation, "REINDEX without CONCURRENTLY");
    }

    #[test]
    fn test_reindex_concurrently_in_transaction_detected() {
        // check_sql uses MigrationContext::default() (run_in_transaction=true),
        // so REINDEX CONCURRENTLY is flagged as requiring no-transaction context.
        let checker = SafetyChecker::default();
        let sql = "REINDEX INDEX CONCURRENTLY idx_users_email;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].1.operation,
            "REINDEX CONCURRENTLY inside a transaction"
        );
    }

    #[test]
    fn test_reindex_check_can_be_disabled() {
        let config = Config {
            disable_checks: vec!["ReindexCheck".to_string()],
            ..Default::default()
        };
        let checker = SafetyChecker::with_config(config).unwrap();

        let sql = "REINDEX INDEX idx_users_email;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_multiple_reindex_violations() {
        let checker = SafetyChecker::default();
        let sql = r"
            REINDEX INDEX idx_users_email;
            REINDEX TABLE posts;
        ";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_unknown_framework_returns_error() {
        let config = Config {
            framework: "unknown".to_string(),
            ..Default::default()
        };
        let checker = SafetyChecker::with_config(config).unwrap();
        let result = checker.check_directory(camino::Utf8Path::new("."));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid framework \"unknown\". Expected \"diesel\" or \"sqlx\"."
        );
    }

    #[test]
    fn test_check_file_unknown_framework_returns_error() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir.path().join("migration.sql");
        fs::write(&file_path, "ALTER TABLE users ADD COLUMN email TEXT;").unwrap();

        let checker = SafetyChecker::with_config(Config {
            framework: "unknown".to_string(),
            ..Default::default()
        })
        .unwrap();
        let path = camino::Utf8Path::from_path(&file_path).unwrap();

        // check_file must propagate the invalid-framework error rather than
        // silently falling back to default metadata.
        let err = checker.check_file(path).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid framework \"unknown\". Expected \"diesel\" or \"sqlx\"."
        );

        // check_path on a file routes through check_file, so it must error too.
        let err = checker.check_path(path).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid framework \"unknown\". Expected \"diesel\" or \"sqlx\"."
        );
    }

    #[test]
    fn test_buffer_input_safe_sql() {
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["AddColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let input_data = "ALTER TABLE users ADD COLUMN foo TEXT;";
        let violations = checker
            .check_buffer(&mut BufReader::new(Cursor::new(input_data)))
            .unwrap();
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_buffer_input_unsafe_sql() {
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["AddColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let input_data = "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;";
        let violations = checker
            .check_buffer(&mut BufReader::new(Cursor::new(input_data)))
            .unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_custom_checks_dir_ignores_non_rhai_files() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        std::fs::write(temp_dir.path().join("readme.txt"), "not a check").unwrap();
        let config = Config {
            custom_checks_dir: Some(temp_dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        };
        // Should not panic; .txt file is silently ignored
        let checker = SafetyChecker::with_config(config).unwrap();
        let violations = checker
            .check_sql("ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;")
            .unwrap();
        assert!(
            violations
                .iter()
                .any(|(_, violation)| violation.operation == "ADD COLUMN with DEFAULT"),
            "Built-in checks should still run"
        );
    }

    #[test]
    fn test_unknown_check_name_in_enable_checks_errors() {
        let result = SafetyChecker::with_config(Config {
            enable_checks: vec!["NonExistentCheck".to_string()],
            ..Default::default()
        });
        assert_eq!(
            result.err().unwrap().to_string(),
            "Invalid check name: NonExistentCheck"
        );
    }

    #[test]
    fn test_check_file_parse_error_points_to_failing_statement_line() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir.path().join("bad_migration.sql");
        // Line 1: "CREATE TABLE a ();\n"
        // Line 2: "CREATE TABLE b ();\n"
        // Line 3: "CREATE TABLE @bad;"    ← this one fails
        let sql = "CREATE TABLE a ();\nCREATE TABLE b ();\nCREATE TABLE @bad;";
        fs::write(&file_path, sql).unwrap();

        let checker = SafetyChecker::default();
        let path = camino::Utf8Path::from_path(&file_path).unwrap();
        let err = checker.check_file(path).unwrap_err();

        let mut rendered = String::new();
        miette::NarratableReportHandler::new()
            .render_report(&mut rendered, &err)
            .unwrap();

        // Normalize the temp path so the assertion is stable across runs.
        let rendered = rendered.replace(file_path.to_str().unwrap(), "bad_migration.sql");

        assert_eq!(
            rendered,
            "Failed to parse SQL: Invalid statement: syntax error at or near \"@\"\n    Diagnostic severity: error\nBegin snippet for bad_migration.sql starting at line 2, column 1\n\nsnippet line 2: CREATE TABLE b ();\nsnippet line 3: CREATE TABLE @bad;\n    label at line 3, column 1: problematic SQL\ndiagnostic help: Check that your SQL syntax is valid\n"
        );
    }

    #[test]
    fn test_unknown_check_name_in_disable_checks_errors() {
        let result = SafetyChecker::with_config(Config {
            disable_checks: vec!["NonExistentCheck".to_string()],
            ..Default::default()
        });
        assert_eq!(
            result.err().unwrap().to_string(),
            "Invalid check name: NonExistentCheck"
        );
    }

    #[test]
    fn test_unknown_check_name_in_warn_checks_errors() {
        let result = SafetyChecker::with_config(Config {
            warn_checks: vec!["NonExistentCheck".to_string()],
            ..Default::default()
        });
        assert_eq!(
            result.err().unwrap().to_string(),
            "Invalid check name: NonExistentCheck"
        );
    }

    #[test]
    fn test_buffer_empty_string() {
        let checker = SafetyChecker::default();
        let input_data = "";
        let violations = checker
            .check_buffer(&mut BufReader::new(Cursor::new(input_data)))
            .unwrap();
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_buffer_input_multiple_lines() {
        let checker = SafetyChecker::default();
        let input_data = r"
            REINDEX INDEX idx_users_email;
            REINDEX TABLE posts;
        ";
        let violations = checker
            .check_buffer(&mut BufReader::new(Cursor::new(input_data)))
            .unwrap();
        assert_eq!(violations.len(), 2);
    }

    // --- Integration tests: metadata-aware CONCURRENTLY detection ---

    #[test]
    fn test_diesel_concurrently_without_metadata_toml_is_violation() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let migration_dir = temp_dir.path().join("2024_01_01_000000_add_idx");
        fs::create_dir(&migration_dir).unwrap();
        fs::write(
            migration_dir.join("up.sql"),
            "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);",
        )
        .unwrap();
        // No metadata.toml — defaults to run_in_transaction=true

        let config = Config {
            framework: "diesel".to_string(),
            enable_checks: vec!["AddIndexCheck".to_string()],
            ..Default::default()
        };
        let checker = SafetyChecker::with_config(config).unwrap();
        let dir_path =
            camino::Utf8Path::from_path(temp_dir.path()).expect("path should be valid UTF-8");

        let results = checker.check_directory(dir_path).unwrap();
        let total_violations: usize = results.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(
            total_violations, 1,
            "Expected 1 violation (CONCURRENTLY in transaction)"
        );
        assert_eq!(
            results[0].1[0].1.operation,
            "CREATE INDEX CONCURRENTLY inside a transaction"
        );
    }

    #[test]
    fn test_diesel_concurrently_with_metadata_toml_is_safe() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let migration_dir = temp_dir.path().join("2024_01_01_000000_add_idx");
        fs::create_dir(&migration_dir).unwrap();
        fs::write(
            migration_dir.join("up.sql"),
            "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);",
        )
        .unwrap();
        fs::write(
            migration_dir.join("metadata.toml"),
            "run_in_transaction = false\n",
        )
        .unwrap();

        let config = Config {
            framework: "diesel".to_string(),
            enable_checks: vec!["AddIndexCheck".to_string()],
            ..Default::default()
        };
        let checker = SafetyChecker::with_config(config).unwrap();
        let dir_path =
            camino::Utf8Path::from_path(temp_dir.path()).expect("path should be valid UTF-8");

        let results = checker.check_directory(dir_path).unwrap();
        let total_violations: usize = results.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(
            total_violations, 0,
            "Expected no violations with metadata.toml"
        );
    }

    #[test]
    fn test_sqlx_concurrently_without_directive_is_violation() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        fs::write(
            temp_dir.path().join("20240101000000_add_idx.up.sql"),
            "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);",
        )
        .unwrap();
        // No -- no-transaction directive

        let checker = SafetyChecker::with_config(Config {
            framework: "sqlx".to_string(),
            enable_checks: vec!["AddIndexCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let dir_path =
            camino::Utf8Path::from_path(temp_dir.path()).expect("path should be valid UTF-8");

        let results = checker.check_directory(dir_path).unwrap();
        let total_violations: usize = results.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(
            total_violations, 1,
            "Expected 1 violation (CONCURRENTLY inside a transaction)"
        );
        assert_eq!(
            results[0].1[0].1.operation,
            "CREATE INDEX CONCURRENTLY inside a transaction"
        );
    }

    #[test]
    fn test_sqlx_concurrently_with_directive_is_safe() {
        use std::fs;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        fs::write(
            temp_dir.path().join("20240101000000_add_idx.up.sql"),
            "-- no-transaction\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email);",
        )
        .unwrap();

        let checker = SafetyChecker::with_config(Config {
            framework: "sqlx".to_string(),
            enable_checks: vec!["AddIndexCheck".to_string()],
            ..Default::default()
        })
        .unwrap();
        let dir_path =
            camino::Utf8Path::from_path(temp_dir.path()).expect("path should be valid UTF-8");

        let results = checker.check_directory(dir_path).unwrap();
        let total_violations: usize = results.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(
            total_violations, 0,
            "Expected no violations with -- no-transaction"
        );
    }

    // --- Line number integration tests (full pipeline through check_sql) ---

    fn line_number_checker() -> SafetyChecker {
        SafetyChecker::with_config(Config {
            enable_checks: vec!["DropColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap()
    }

    fn violation_lines(checker: &SafetyChecker, sql: &str) -> Vec<usize> {
        let mut lines: Vec<usize> = checker
            .check_sql(sql)
            .unwrap()
            .iter()
            .map(|(l, _)| *l)
            .collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn test_line_numbers_two_stmts_on_sequential_lines() {
        let checker = line_number_checker();
        let sql = "ALTER TABLE users DROP COLUMN email;\nALTER TABLE posts DROP COLUMN body;";
        assert_eq!(violation_lines(&checker, sql), vec![1, 2]);
    }

    #[test]
    fn test_line_numbers_stmts_separated_by_blank_line() {
        let checker = line_number_checker();
        let sql = "ALTER TABLE users DROP COLUMN email;\n\nALTER TABLE posts DROP COLUMN body;";
        assert_eq!(violation_lines(&checker, sql), vec![1, 3]);
    }

    #[test]
    fn test_line_numbers_stmts_with_interleaved_line_comments() {
        let checker = line_number_checker();
        let sql = "-- first op\nALTER TABLE users DROP COLUMN email;\n-- second op\nALTER TABLE posts DROP COLUMN body;";
        assert_eq!(violation_lines(&checker, sql), vec![2, 4]);
    }

    #[test]
    fn test_line_numbers_stmt_just_after_safety_assured_block() {
        let checker = line_number_checker();
        // Lines: 1=start directive, 2=suppressed DROP, 3=end directive, 4=blank, 5=active DROP
        let sql = "-- safety-assured:start\nALTER TABLE users DROP COLUMN email;\n-- safety-assured:end\n\nALTER TABLE posts DROP COLUMN body;";
        assert_eq!(violation_lines(&checker, sql), vec![5]);
    }

    #[test]
    fn test_line_numbers_multiple_violations_from_one_stmt_share_same_line() {
        let checker = line_number_checker();
        // Two DROP COLUMN clauses in one ALTER TABLE on line 3
        let sql = "\n\nALTER TABLE users DROP COLUMN a, DROP COLUMN b;";
        let violations = checker.check_sql(sql).unwrap();
        assert_eq!(violations.len(), 2);
        assert!(
            violations.iter().all(|(l, _)| *l == 3),
            "Both violations must reference line 3, got {:?}",
            violations.iter().map(|(l, _)| l).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_registry_returns_inner_registry() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.registry().active_check_names().len(),
            Registry::builtin_check_names().len()
        );
    }

    #[test]
    fn test_default_creates_checker() {
        let checker = SafetyChecker::default();
        assert_ne!(checker.registry().active_check_names().len(), 0);
    }

    #[test]
    fn test_rule_generation_is_shared_by_registry_and_evidence() {
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["DropColumnCheck".to_string()],
            ..Default::default()
        })
        .unwrap();

        let generation = checker.rule_generation();
        assert_eq!(generation, RuleGeneration::FIRST);
        assert_eq!(checker.registry().generation(), generation);

        let violations = checker
            .check_sql("ALTER TABLE users DROP COLUMN email;")
            .unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1.rule_generation(), generation);
    }

    #[test]
    fn test_reload_without_custom_dir_advances_generation() {
        let mut checker = SafetyChecker::default();
        let first = checker.rule_generation();

        let next = checker.reload().expect("reload of built-ins succeeds");
        assert_eq!(next, first.next());
        assert_eq!(checker.rule_generation(), next);
        assert_eq!(checker.registry().generation(), next);

        // A fresh checker still starts at the first generation.
        let fresh = SafetyChecker::default();
        assert_eq!(fresh.rule_generation(), RuleGeneration::FIRST);
    }

    #[test]
    fn test_check_path_file_no_violations() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("migration.sql");
        std::fs::write(&file, "CREATE TABLE users (id BIGINT);").unwrap();
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["DropTableCheck".to_string()],
            ..Config::default()
        })
        .unwrap();
        let path = Utf8Path::from_path(&file).unwrap();
        let results = checker.check_path(path).unwrap();
        assert!(results.is_empty(), "Safe SQL should produce no violations");
    }

    #[test]
    fn test_check_path_file_with_violations() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("migration.sql");
        std::fs::write(&file, "DROP TABLE users;").unwrap();
        let checker = SafetyChecker::with_config(Config {
            enable_checks: vec!["DropTableCheck".to_string()],
            ..Config::default()
        })
        .unwrap();
        let path = Utf8Path::from_path(&file).unwrap();
        let results = checker.check_path(path).unwrap();
        assert_eq!(results.len(), 1, "Expected one file with violations");
        assert!(results[0].0.contains("migration.sql"));
        assert!(!results[0].1.is_empty());
    }

    #[test]
    fn test_check_sql_warns_on_duplicate_migration_disabled_checks() {
        let checker = SafetyChecker::default();
        // Duplicate name in disable directive — warn_unknown_migration_disabled_checks deduplicates.
        let sql = "-- diesel-guard:disable AddColumnCheck,AddColumnCheck\nALTER TABLE t ADD COLUMN x TEXT;";
        // Should not panic or error; just runs (warning goes to stderr).
        let _ = checker.check_sql(sql).unwrap();
    }

    #[test]
    fn test_check_sql_warns_on_unknown_migration_disabled_check() {
        let checker = SafetyChecker::default();
        // FakeCheck is not a known check name — triggers the eprintln warning path.
        let sql =
            "-- diesel-guard:disable FakeCheckThatDoesNotExist\nALTER TABLE t ADD COLUMN x TEXT;";
        let _ = checker.check_sql(sql).unwrap();
    }
}
