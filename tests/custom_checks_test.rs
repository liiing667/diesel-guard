use camino::Utf8Path;
use diesel_guard::{Config, SafetyChecker, ViolationList};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_custom_check_fires_alongside_builtin() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Write a custom check that flags non-concurrent indexes
    fs::write(
        dir.path().join("require_concurrent.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        if !stmt.concurrent {
            #{
                operation: "CUSTOM: INDEX without CONCURRENTLY",
                problem: "Blocks writes on the table",
                safe_alternative: "Use CREATE INDEX CONCURRENTLY"
            }
        }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    // This SQL triggers both the built-in AddIndexCheck and our custom check
    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();

    // Should have at least 2 violations: built-in + custom
    assert!(
        violations.len() >= 2,
        "Expected at least 2 violations (built-in + custom), got {}",
        violations.len()
    );

    // Verify custom violation is present with correct check_name
    let custom = violations
        .iter()
        .find(|(_, v)| v.operation == "CUSTOM: INDEX without CONCURRENTLY")
        .expect("Custom check violation should be present");
    assert_eq!(
        custom.1.check_name, "require_concurrent",
        "check_name should be the .rhai file stem"
    );

    // Verify built-in violation is also present
    assert!(
        violations
            .iter()
            .any(|(_, v)| v.operation.contains("ADD INDEX")),
        "Built-in AddIndexCheck violation should be present"
    );
}

#[test]
fn test_disable_checks_works_for_custom_check() {
    let dir = tempdir().expect("Failed to create temp dir");

    fs::write(
        dir.path().join("my_custom.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{
            operation: "custom violation",
            problem: "p",
            safe_alternative: "s"
        }
        "#,
    )
    .unwrap();

    // Disable the custom check by its filename stem
    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        disable_checks: vec!["my_custom".to_string()],
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();

    // Custom check should be disabled — no "custom violation"
    assert!(
        !violations
            .iter()
            .any(|(_, v)| v.operation == "custom violation"),
        "Disabled custom check should not fire"
    );
}

#[test]
fn test_safety_assured_blocks_skip_custom_checks() {
    let dir = tempdir().expect("Failed to create temp dir");

    fs::write(
        dir.path().join("always_fires.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{
            operation: "always fires",
            problem: "p",
            safe_alternative: "s"
        }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let sql = r"
-- safety-assured:start
CREATE INDEX idx ON users(email);
-- safety-assured:end
    ";

    let violations = checker.check_sql(sql).unwrap();

    // Both built-in and custom checks should be skipped in safety-assured block
    assert!(
        violations.is_empty(),
        "No violations should fire inside safety-assured block, got {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_custom_check_in_migration_directory() {
    let checks_dir = tempdir().expect("Failed to create temp dir");
    let migrations_dir = tempdir().expect("Failed to create temp dir");

    // Write a custom check
    fs::write(
        checks_dir.path().join("no_drop.rhai"),
        r#"
        let stmt = node.DropStmt;
        if stmt == () { return; }
        #{
            operation: "CUSTOM DROP",
            problem: "dropping things is scary",
            safe_alternative: "don't do it"
        }
        "#,
    )
    .unwrap();

    // Create a migration directory with a drop statement
    let mig_dir = migrations_dir.path().join("2024_01_01_000000_test");
    fs::create_dir(&mig_dir).unwrap();
    fs::write(mig_dir.join("up.sql"), "DROP TABLE IF EXISTS old_table;").unwrap();

    let config = Config {
        custom_checks_dir: Some(checks_dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let results = checker
        .check_path(Utf8Path::from_path(migrations_dir.path()).unwrap())
        .unwrap();

    // Should have violations from both built-in DropTableCheck and custom no_drop
    assert!(!results.is_empty());
    let violations: Vec<_> = results.iter().flat_map(|(_, v)| v).collect();
    assert!(
        violations.iter().any(|(_, v)| v.operation == "CUSTOM DROP"),
        "Custom check should fire on migration files"
    );
}

#[test]
fn test_nonexistent_custom_checks_dir_is_ignored() {
    let config = Config {
        custom_checks_dir: Some("/nonexistent/path/to/checks".to_string()),
        ..Default::default()
    };

    // Should not panic or error — just ignored
    let checker = SafetyChecker::with_config(config).unwrap();
    let violations = checker.check_sql("SELECT 1;").unwrap();
    assert!(violations.is_empty());
}

#[test]
fn test_registry_check_names_includes_custom_checks() {
    let dir = tempdir().expect("Failed to create temp dir");

    fs::write(
        dir.path().join("my_custom.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{
            operation: "custom violation",
            problem: "p",
            safe_alternative: "s"
        }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let registry = diesel_guard::checks::Registry::with_config(&config);

    // Before adding custom checks, my_custom should NOT be in the list
    let names_before = registry.active_check_names();
    assert!(
        !names_before.contains(&"my_custom"),
        "Custom check should not appear in registry before loading"
    );

    // After building SafetyChecker (which loads custom checks), rebuild
    // a registry that includes custom checks to verify check_names works
    let mut registry = diesel_guard::checks::Registry::with_config(&config);
    let (checks, _) = diesel_guard::scripting::load_custom_checks(
        Utf8Path::new(dir.path().to_str().unwrap()),
        &config,
    );
    for check in checks {
        registry.add_check(check);
    }

    let names_after = registry.active_check_names();
    assert!(
        names_after.contains(&"my_custom"),
        "Custom check 'my_custom' should appear in check_names after loading, got: {names_after:?}"
    );
}

#[test]
fn test_unknown_check_name_not_raised_for_custom_check() {
    // When a disable_checks entry matches a custom check script name,
    // SafetyChecker::with_config() should NOT error about it.
    // The validation checks .rhai file stems on disk, not just what was
    // loaded into the registry (disabled checks are skipped during loading).
    let dir = tempdir().expect("Failed to create temp dir");

    fs::write(
        dir.path().join("my_custom.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{
            operation: "custom violation",
            problem: "p",
            safe_alternative: "s"
        }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        disable_checks: vec!["my_custom".to_string()],
        ..Default::default()
    };

    // Building SafetyChecker should not error: "my_custom" matches a .rhai file stem.
    let checker = SafetyChecker::with_config(config).unwrap();

    // Verify the custom check is actually disabled
    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|(_, v)| v.operation == "custom violation"),
        "Disabled custom check should not fire"
    );
}

#[test]
fn test_unknown_check_name_errors_after_custom_checks_loaded() {
    let dir = tempdir().expect("Failed to create temp dir");

    fs::write(
        dir.path().join("my_custom.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{
            operation: "custom violation",
            problem: "p",
            safe_alternative: "s"
        }
        "#,
    )
    .unwrap();

    let result = SafetyChecker::with_config(Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        disable_checks: vec!["TotallyBogusCheckName".to_string()],
        ..Default::default()
    });
    assert_eq!(
        result.err().unwrap().to_string(),
        "Invalid check name: TotallyBogusCheckName"
    );
}

// ---------------------------------------------------------------------------
// Example script validation tests
// ---------------------------------------------------------------------------

/// Run SQL through the real `examples/` directory with all built-in checks
/// disabled so only example Rhai scripts produce violations.
fn check_with_examples(sql: &str) -> ViolationList {
    let config = Config {
        custom_checks_dir: Some("examples".to_string()),
        disable_checks: vec![
            "AddColumnCheck".into(),
            "AddIndexCheck".into(),
            "AddJsonColumnCheck".into(),
            "AddNotNullCheck".into(),
            "AddPrimaryKeyCheck".into(),
            "AddSerialColumnCheck".into(),
            "AddUniqueConstraintCheck".into(),
            "AlterColumnTypeCheck".into(),
            "CharTypeCheck".into(),
            "CreateExtensionCheck".into(),
            "DropColumnCheck".into(),
            "DropDatabaseCheck".into(),
            "DropIndexCheck".into(),
            "DropPrimaryKeyCheck".into(),
            "DropTableCheck".into(),
            "GeneratedColumnCheck".into(),
            "ReindexCheck".into(),
            "RenameColumnCheck".into(),
            "RenameTableCheck".into(),
            "ShortIntegerPrimaryKeyCheck".into(),
            "TimestampTypeCheck".into(),
            "TruncateTableCheck".into(),
            "UnnamedConstraintCheck".into(),
            "WideIndexCheck".into(),
        ],
        ..Default::default()
    };
    SafetyChecker::with_config(config)
        .unwrap()
        .check_sql(sql)
        .unwrap()
}

fn has_violation_containing(violations: &ViolationList, substring: &str) -> bool {
    violations
        .iter()
        .any(|(_, v)| v.operation.contains(substring))
}

// -- require_concurrent_index.rhai --

#[test]
fn test_example_require_concurrent_index_detects() {
    let violations = check_with_examples("CREATE INDEX idx ON users(email);");
    assert!(
        has_violation_containing(&violations, "INDEX without CONCURRENTLY"),
        "Expected violation for non-concurrent index, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_example_require_concurrent_index_allows() {
    let violations = check_with_examples("CREATE INDEX CONCURRENTLY idx ON users(email);");
    assert!(
        !has_violation_containing(&violations, "INDEX without CONCURRENTLY"),
        "Concurrent index should not trigger violation"
    );
}

// -- no_truncate_in_production.rhai --

#[test]
fn test_example_no_truncate_detects_single() {
    let violations = check_with_examples("TRUNCATE users;");
    let truncate_violations: Vec<_> = violations
        .iter()
        .filter(|(_, v)| v.operation.starts_with("TRUNCATE:"))
        .collect();
    assert_eq!(
        truncate_violations.len(),
        1,
        "Expected 1 TRUNCATE violation, got {truncate_violations:?}"
    );
}

#[test]
fn test_example_no_truncate_detects_multiple() {
    let violations = check_with_examples("TRUNCATE users, orders;");
    let truncate_violations: Vec<_> = violations
        .iter()
        .filter(|(_, v)| v.operation.starts_with("TRUNCATE:"))
        .collect();
    assert_eq!(
        truncate_violations.len(),
        2,
        "Expected 2 TRUNCATE violations (one per table), got {truncate_violations:?}"
    );
}

#[test]
fn test_example_no_truncate_ignores_unrelated() {
    let violations = check_with_examples("DROP TABLE users;");
    assert!(
        !has_violation_containing(&violations, "TRUNCATE"),
        "DROP TABLE should not trigger TRUNCATE violation"
    );
}

// -- require_if_exists_on_drop.rhai --

#[test]
fn test_example_require_if_exists_on_drop_detects() {
    let violations = check_with_examples("DROP TABLE users;");
    assert!(
        has_violation_containing(&violations, "DROP TABLE without IF EXISTS"),
        "Expected violation for DROP TABLE without IF EXISTS, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_example_require_if_exists_on_drop_allows() {
    let violations = check_with_examples("DROP TABLE IF EXISTS users;");
    assert!(
        !has_violation_containing(&violations, "DROP TABLE without IF EXISTS"),
        "DROP TABLE IF EXISTS should not trigger violation"
    );
}

// -- require_index_name_prefix.rhai --

#[test]
fn test_example_require_index_name_prefix_detects() {
    let violations = check_with_examples("CREATE INDEX CONCURRENTLY users_email ON users(email);");
    assert!(
        has_violation_containing(&violations, "Index naming violation"),
        "Expected violation for missing idx_ prefix, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_example_require_index_name_prefix_allows() {
    let violations =
        check_with_examples("CREATE INDEX CONCURRENTLY idx_users_email ON users(email);");
    assert!(
        !has_violation_containing(&violations, "Index naming violation"),
        "idx_ prefixed index should not trigger naming violation"
    );
}

// -- limit_columns_per_index.rhai --

#[test]
fn test_example_limit_columns_per_index_detects() {
    let violations = check_with_examples("CREATE INDEX CONCURRENTLY idx_t ON t(a, b, c, d);");
    assert!(
        has_violation_containing(&violations, "Wide index"),
        "Expected violation for 4-column index, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_custom_check_returning_array_of_violations() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Script that always returns an array of 3 violations for any IndexStmt
    fs::write(
        dir.path().join("triple.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        [
            #{ operation: "v1", problem: "p1", safe_alternative: "s1" },
            #{ operation: "v2", problem: "p2", safe_alternative: "s2" },
            #{ operation: "v3", problem: "p3", safe_alternative: "s3" }
        ]
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();

    // Filter to only our custom violations
    let custom: Vec<_> = violations
        .iter()
        .filter(|(_, v)| ["v1", "v2", "v3"].contains(&v.operation.as_str()))
        .collect();
    assert_eq!(
        custom.len(),
        3,
        "Script returning array of 3 maps should produce exactly 3 custom violations, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_custom_check_using_pg_constants() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Script that uses pg::OBJECT_TABLE to detect DROP TABLE
    fs::write(
        dir.path().join("detect_drop_table.rhai"),
        r#"
        let stmt = node.DropStmt;
        if stmt == () { return; }
        if stmt.remove_type == pg::OBJECT_TABLE {
            #{
                operation: "CUSTOM: DROP TABLE detected",
                problem: "Table drops are dangerous",
                safe_alternative: "Use soft deletes"
            }
        }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    // DROP TABLE should fire
    let violations_table = checker.check_sql("DROP TABLE users;").unwrap();
    assert!(
        violations_table
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM: DROP TABLE detected"),
        "Script using pg::OBJECT_TABLE should fire on DROP TABLE"
    );

    // DROP INDEX should NOT fire
    let violations_index = checker.check_sql("DROP INDEX idx_users_email;").unwrap();
    assert!(
        !violations_index
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM: DROP TABLE detected"),
        "Script checking for OBJECT_TABLE should not fire on DROP INDEX"
    );
}

#[test]
fn test_multiple_custom_checks_loaded_in_sorted_order() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Two scripts that both fire on IndexStmt — named to test sort order
    fs::write(
        dir.path().join("aaa_check.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{ operation: "aaa_check", problem: "p", safe_alternative: "s" }
        "#,
    )
    .unwrap();

    fs::write(
        dir.path().join("zzz_check.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{ operation: "zzz_check", problem: "p", safe_alternative: "s" }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();

    let custom_ops: Vec<&str> = violations
        .iter()
        .map(|(_, v)| v.operation.as_str())
        .filter(|op| *op == "aaa_check" || *op == "zzz_check")
        .collect();

    assert_eq!(custom_ops.len(), 2, "Both custom checks should fire");

    // aaa should come before zzz (alphabetical load order)
    let aaa_pos = custom_ops.iter().position(|&op| op == "aaa_check").unwrap();
    let zzz_pos = custom_ops.iter().position(|&op| op == "zzz_check").unwrap();
    assert!(
        aaa_pos < zzz_pos,
        "aaa_check should appear before zzz_check (alphabetical order)"
    );

    // Each violation must carry its own check's name
    let aaa_violation = violations
        .iter()
        .find(|(_, v)| v.operation == "aaa_check")
        .unwrap();
    assert_eq!(aaa_violation.1.check_name, "aaa_check");

    let zzz_violation = violations
        .iter()
        .find(|(_, v)| v.operation == "zzz_check")
        .unwrap();
    assert_eq!(zzz_violation.1.check_name, "zzz_check");
}

#[test]
fn test_custom_check_name_conflicts_with_builtin() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Script with the same name as a built-in check
    fs::write(
        dir.path().join("AddColumnCheck.rhai"),
        r#"
        let stmt = node.AlterTableStmt;
        if stmt == () { return; }
        #{ operation: "CUSTOM AddColumnCheck", problem: "p", safe_alternative: "s" }
        "#,
    )
    .unwrap();

    // Disabling "AddColumnCheck" should disable BOTH the built-in and the custom check
    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        disable_checks: vec!["AddColumnCheck".to_string()],
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let violations = checker
        .check_sql("ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;")
        .unwrap();

    // Built-in AddColumnCheck should be disabled
    assert!(
        !violations
            .iter()
            .any(|(_, v)| v.operation == "ADD COLUMN with DEFAULT"),
        "Built-in AddColumnCheck should be disabled"
    );

    // Custom AddColumnCheck.rhai should also be disabled (same name used by is_check_enabled)
    assert!(
        !violations
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM AddColumnCheck"),
        "Custom check with same name as built-in should also be disabled"
    );
}

#[test]
fn test_custom_check_compilation_error_is_fatal() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Broken script (invalid syntax)
    fs::write(dir.path().join("broken.rhai"), "this is not valid rhai {{{").unwrap();

    // Valid script
    fs::write(
        dir.path().join("valid.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{ operation: "valid_check", problem: "p", safe_alternative: "s" }
        "#,
    )
    .unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let result = SafetyChecker::with_config(config);

    // A broken sibling script must abort checker construction. Silently
    // skipping it would run only half the configured rules while still
    // reporting "all rules passed".
    let err = result.expect_err("broken custom script must fail checker build");
    let rendered = err.to_string();
    assert!(
        rendered.contains("broken.rhai"),
        "error should name the offending script, got: {rendered}"
    );
    assert!(
        rendered.contains("Compilation error"),
        "error should describe the compilation failure, got: {rendered}"
    );
}

#[test]
fn test_custom_check_unreadable_script_is_fatal() {
    let dir = tempdir().expect("Failed to create temp dir");

    // A directory at the .rhai path always fails fs::read_to_string.
    let script_path = dir.path().join("unreadable.rhai");
    fs::create_dir(&script_path).unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let result = SafetyChecker::with_config(config);
    let err = result.expect_err("unreadable custom script must fail checker build");
    assert!(
        err.to_string().contains("unreadable.rhai"),
        "error should name the unreadable script, got: {}",
        err
    );
}

#[test]
fn test_example_limit_columns_per_index_allows() {
    let violations = check_with_examples("CREATE INDEX CONCURRENTLY idx_t ON t(a, b, c);");
    assert!(
        !has_violation_containing(&violations, "Wide index"),
        "3-column index should not trigger wide index violation"
    );
}

// -- config variable in custom checks --

#[test]
fn test_custom_check_can_read_postgres_version() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Script that skips the violation when postgres_version >= 14
    fs::write(
        dir.path().join("version_aware.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        if config.postgres_version != () && config.postgres_version >= 14 { return; }
        #{
            operation: "CUSTOM: needs pg14",
            problem: "only needed below pg14",
            safe_alternative: "upgrade postgres"
        }
        "#,
    )
    .unwrap();

    let dir_path = dir.path().to_str().unwrap().to_string();

    // With postgres_version = 14: no violation
    let config_pg14 = Config {
        custom_checks_dir: Some(dir_path.clone()),
        postgres_version: Some(14),
        ..Default::default()
    };
    let violations = SafetyChecker::with_config(config_pg14)
        .unwrap()
        .check_sql("CREATE INDEX CONCURRENTLY idx ON users(email);")
        .unwrap();
    assert!(
        !violations
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM: needs pg14"),
        "Version-aware custom check should not fire on pg14"
    );

    // With postgres_version = 13: violation
    let config_pg13 = Config {
        custom_checks_dir: Some(dir_path.clone()),
        postgres_version: Some(13),
        ..Default::default()
    };
    let violations = SafetyChecker::with_config(config_pg13)
        .unwrap()
        .check_sql("CREATE INDEX CONCURRENTLY idx ON users(email);")
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM: needs pg14"),
        "Version-aware custom check should fire on pg13"
    );

    // With no postgres_version set: violation (None → () in Rhai, condition is skipped)
    let config_no_ver = Config {
        custom_checks_dir: Some(dir_path),
        postgres_version: None,
        ..Default::default()
    };
    let violations = SafetyChecker::with_config(config_no_ver)
        .unwrap()
        .check_sql("CREATE INDEX CONCURRENTLY idx ON users(email);")
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|(_, v)| v.operation == "CUSTOM: needs pg14"),
        "Version-aware custom check should fire when no version is set"
    );
}

// -- runtime error handling --

#[test]
fn test_custom_check_runtime_error_yields_script_error_violation() {
    let dir = tempdir().expect("Failed to create temp dir");
    fs::write(dir.path().join("bad.rhai"), "let x = 1 / 0;").unwrap();
    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();
    // SELECT doesn't trigger any built-in check, so the only violation comes from the script.
    let violations = checker.check_sql("SELECT 1;").unwrap();
    assert_eq!(
        violations.len(),
        1,
        "expected 1 SCRIPT ERROR violation, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
    assert!(
        violations[0].1.operation.starts_with("SCRIPT ERROR:"),
        "expected operation to start with 'SCRIPT ERROR:', got: {}",
        violations[0].1.operation
    );
}

#[test]
fn test_custom_check_max_operations_yields_script_error() {
    // An infinite loop hits the max_operations budget (ErrorTooManyOperations).
    // This must surface as a SCRIPT ERROR violation — a broken script must not
    // silently disable a safety check.
    let dir = tempdir().expect("Failed to create temp dir");
    fs::write(dir.path().join("looping.rhai"), "loop {}").unwrap();
    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();
    let violations = checker.check_sql("SELECT 1;").unwrap();
    assert_eq!(
        violations.len(),
        1,
        "ErrorTooManyOperations must produce a SCRIPT ERROR violation, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
    assert!(
        violations[0].1.operation.starts_with("SCRIPT ERROR:"),
        "expected SCRIPT ERROR violation, got: {}",
        violations[0].1.operation
    );
}

// -- no_unlogged_tables.rhai --

#[test]
fn test_example_no_unlogged_tables_detects() {
    let violations = check_with_examples("CREATE UNLOGGED TABLE t (id INT);");
    assert!(
        has_violation_containing(&violations, "UNLOGGED TABLE"),
        "Expected violation for UNLOGGED TABLE, got: {:?}",
        violations
            .iter()
            .map(|(_, v)| &v.operation)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_example_no_unlogged_tables_allows() {
    let violations = check_with_examples("CREATE TABLE t (id INT);");
    assert!(
        !has_violation_containing(&violations, "UNLOGGED TABLE"),
        "Regular table should not trigger UNLOGGED violation"
    );
}

// ---------------------------------------------------------------------------
// Rule generation: built-in rules, custom scripts and check evidence must all
// share one consistent rule generation.
// ---------------------------------------------------------------------------

fn index_firing_custom_script() -> &'static str {
    r#"
    let stmt = node.IndexStmt;
    if stmt == () { return; }
    #{ operation: "custom_index_rule", problem: "p", safe_alternative: "s" }
    "#
}

#[test]
fn test_builtin_and_custom_checks_share_the_same_generation() {
    let dir = tempdir().expect("Failed to create temp dir");
    fs::write(dir.path().join("my_custom.rhai"), index_firing_custom_script()).unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };
    let checker = SafetyChecker::with_config(config).unwrap();

    let generation = checker.rule_generation();
    assert_eq!(generation.as_u64(), 1);
    assert_eq!(checker.registry().generation(), generation);

    // Evidence from both built-in and custom checks carries the same generation.
    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();
    assert!(
        violations.len() >= 2,
        "expected built-in + custom violations, got: {violations:?}"
    );
    for (_, violation) in &violations {
        assert_eq!(
            violation.rule_generation(),
            generation,
            "violation {:?} must share the checker's rule generation",
            violation.operation
        );
    }
}

#[test]
fn test_successful_reload_advances_generation_and_keeps_full_rule_set() {
    let dir = tempdir().expect("Failed to create temp dir");
    let checks_dir = dir.path().to_str().unwrap().to_string();
    fs::write(dir.path().join("my_custom.rhai"), index_firing_custom_script()).unwrap();

    let config = Config {
        custom_checks_dir: Some(checks_dir),
        ..Default::default()
    };
    let mut checker = SafetyChecker::with_config(config).unwrap();
    let first_generation = checker.rule_generation();
    assert_eq!(first_generation.as_u64(), 1);

    // Add a second script, then hot-reload.
    fs::write(
        dir.path().join("second_custom.rhai"),
        r#"
        let stmt = node.IndexStmt;
        if stmt == () { return; }
        #{ operation: "second_custom_rule", problem: "p", safe_alternative: "s" }
        "#,
    )
    .unwrap();

    let new_generation = checker.reload().expect("reload with valid scripts succeeds");
    assert_eq!(new_generation, first_generation.next());
    assert_eq!(checker.rule_generation(), new_generation);
    assert_eq!(checker.registry().generation(), new_generation);

    // The reloaded checker still runs the complete rule set: built-in plus
    // both custom scripts, all stamped with the new generation.
    let violations = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();
    let operations: Vec<&str> = violations.iter().map(|(_, v)| v.operation.as_str()).collect();
    assert!(operations.contains(&"custom_index_rule"));
    assert!(operations.contains(&"second_custom_rule"));
    assert!(
        operations.iter().any(|op| op.contains("ADD INDEX")),
        "built-in rule must still run after reload, got: {operations:?}"
    );
    for (_, violation) in &violations {
        assert_eq!(violation.rule_generation(), new_generation);
    }
}

#[test]
fn test_failed_reload_keeps_previous_generation_and_full_rule_set() {
    let dir = tempdir().expect("Failed to create temp dir");
    let checks_dir = dir.path().to_str().unwrap().to_string();
    fs::write(dir.path().join("my_custom.rhai"), index_firing_custom_script()).unwrap();

    let config = Config {
        custom_checks_dir: Some(checks_dir),
        ..Default::default()
    };
    let mut checker = SafetyChecker::with_config(config).unwrap();
    let stable_generation = checker.rule_generation();

    // A previously working migration passes and its evidence uses generation 1.
    let before = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();
    assert!(
        before
            .iter()
            .any(|(_, v)| v.operation == "custom_index_rule")
    );
    assert!(before.iter().all(|(_, v)| v.rule_generation() == stable_generation));

    // Drop a broken script into the directory and attempt a hot reload.
    fs::write(dir.path().join("broken.rhai"), "this is not valid rhai {{{").unwrap();
    let reload_err = checker
        .reload()
        .expect_err("reload must fail when a script does not compile");
    assert!(reload_err.to_string().contains("broken.rhai"));

    // The failed reload must not advance the generation or replace the
    // registry: the checker still runs the previous, fully loaded rule set
    // and must never report success against a half-loaded set.
    assert_eq!(checker.rule_generation(), stable_generation);
    assert_eq!(checker.registry().generation(), stable_generation);

    let after = checker
        .check_sql("CREATE INDEX idx ON users(email);")
        .unwrap();
    let operations: Vec<&str> = after.iter().map(|(_, v)| v.operation.as_str()).collect();
    assert!(
        operations.contains(&"custom_index_rule"),
        "previously loaded custom rule must keep running after failed reload"
    );
    assert!(
        operations.iter().any(|op| op.contains("ADD INDEX")),
        "built-in rules must keep running after failed reload"
    );
    assert!(after.iter().all(|(_, v)| v.rule_generation() == stable_generation));

    // Fix the script and reload — the checker advances to a fresh generation.
    fs::write(dir.path().join("broken.rhai"), "return;").unwrap();
    let recovered = checker.reload().expect("reload succeeds once scripts are fixed");
    assert_eq!(recovered, stable_generation.next());
    assert_eq!(checker.rule_generation(), recovered);
}

#[test]
fn test_broken_script_never_allows_clean_pass() {
    let dir = tempdir().expect("Failed to create temp dir");
    // Only a broken script lives in the custom directory.
    fs::write(dir.path().join("broken.rhai"), "this is not valid rhai {{{").unwrap();

    let config = Config {
        custom_checks_dir: Some(dir.path().to_str().unwrap().to_string()),
        ..Default::default()
    };

    // Construction fails, so callers cannot obtain a checker that would run
    // only the built-ins and claim the full rule set passed.
    let result = SafetyChecker::with_config(config);
    assert!(result.is_err(), "broken script must prevent checker creation");
}
