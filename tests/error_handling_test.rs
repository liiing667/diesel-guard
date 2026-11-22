use camino::Utf8Path;
use diesel_guard::{Config, SafetyChecker};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_invalid_sql_produces_parse_error() {
    let checker = SafetyChecker::default();
    let result = checker.check_sql("NOT VALID SQL;");
    assert!(result.is_err(), "Invalid SQL should produce an error");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("parse"),
        "Error should mention 'parse', got: {err_msg}"
    );
}

#[test]
fn test_invalid_sql_in_migration_file_has_file_context() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("up.sql");
    fs::write(&file_path, "NOT VALID SQL;").unwrap();

    let checker = SafetyChecker::default();
    let utf8_path = Utf8Path::from_path(&file_path).unwrap();
    let result = checker.check_file(utf8_path);

    assert!(
        result.is_err(),
        "Invalid SQL in file should produce an error"
    );

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains(utf8_path.as_str()),
        "Error should contain the file path '{utf8_path}', got: {err_msg}"
    );
}

#[test]
fn test_empty_migration_file() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("up.sql");
    fs::write(&file_path, "").unwrap();

    let checker = SafetyChecker::default();
    let utf8_path = Utf8Path::from_path(&file_path).unwrap();
    let result = checker.check_file(utf8_path);

    assert!(result.is_ok(), "Empty file should parse successfully");
    assert_eq!(
        result.unwrap().len(),
        0,
        "Empty file should have 0 violations"
    );
}

#[test]
fn test_migration_file_with_only_comments() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("up.sql");
    fs::write(&file_path, "-- comment\n-- another comment\n").unwrap();

    let checker = SafetyChecker::default();
    let utf8_path = Utf8Path::from_path(&file_path).unwrap();
    let result = checker.check_file(utf8_path);

    assert!(
        result.is_ok(),
        "Comments-only file should parse successfully"
    );
    assert_eq!(
        result.unwrap().len(),
        0,
        "Comments-only file should have 0 violations"
    );
}

#[test]
fn test_nonexistent_file_returns_error() {
    let checker = SafetyChecker::default();
    let result = checker.check_file(Utf8Path::new("/nonexistent/path/to/migration.sql"));
    assert!(result.is_err(), "Nonexistent file should return an error");
}

#[test]
fn test_nonexistent_path_returns_error() {
    let checker = SafetyChecker::default();
    let result = checker.check_path(Utf8Path::new("/nonexistent/path/to/migrations"));
    assert!(result.is_err(), "Nonexistent path should return an error");
}

#[test]
fn test_check_directory_fails_on_invalid_sql_file() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    // First migration: valid SQL
    let valid_dir = temp_dir.path().join("2024_01_01_000000_valid");
    fs::create_dir(&valid_dir).unwrap();
    fs::write(
        valid_dir.join("up.sql"),
        "ALTER TABLE users ADD COLUMN email VARCHAR(255);",
    )
    .unwrap();

    // Second migration: invalid SQL
    let invalid_dir = temp_dir.path().join("2024_06_01_000000_invalid");
    fs::create_dir(&invalid_dir).unwrap();
    fs::write(invalid_dir.join("up.sql"), "NOT VALID SQL SYNTAX HERE;").unwrap();

    let checker = SafetyChecker::default();
    let dir = Utf8Path::from_path(temp_dir.path()).unwrap();
    let report = checker
        .check_directory_report(dir)
        .expect("directory check should return a report");

    // The generation is incomplete, but the valid file's outcome is kept and
    // the invalid file is identified explicitly.
    assert!(report.has_failures());
    assert!(!report.is_success());
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.failures.len(), 1);
    assert!(report.failures[0].path.contains("invalid"));
    assert!(
        report.failures[0]
            .message
            .to_lowercase()
            .contains("parse"),
        "failure should describe the parse error, got: {}",
        report.failures[0].message
    );
    assert_eq!(
        report.manifest.len(),
        2,
        "both migrations belong to the same generation"
    );

    // The legacy result shape must not look clean when a file failed.
    let legacy = checker
        .check_directory(dir)
        .expect("partial results are returned instead of being discarded");
    let failed_entry = legacy
        .iter()
        .find(|entry| entry.0.contains("invalid"))
        .expect("failed migration must appear in the legacy result shape");
    assert_eq!(failed_entry.1[0].1.check_name, "MigrationCheckFailure");
}

#[test]
fn test_mixed_migration_retry_keeps_per_file_results_and_exit_consistent() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    let unsafe_dir = temp_dir.path().join("2024_01_01_000000_unsafe");
    fs::create_dir(&unsafe_dir).unwrap();
    fs::write(unsafe_dir.join("up.sql"), "DROP TABLE users;").unwrap();

    let invalid_dir = temp_dir.path().join("2024_02_01_000000_invalid");
    fs::create_dir(&invalid_dir).unwrap();
    fs::write(invalid_dir.join("up.sql"), "NOT VALID SQL SYNTAX HERE;").unwrap();

    let safe_dir = temp_dir.path().join("2024_03_01_000000_safe");
    fs::create_dir(&safe_dir).unwrap();
    fs::write(
        safe_dir.join("up.sql"),
        "ALTER TABLE users ADD COLUMN email VARCHAR(255);",
    )
    .unwrap();

    let checker = SafetyChecker::with_config(Config {
        enable_checks: vec!["DropTableCheck".to_string()],
        ..Default::default()
    })
    .unwrap();
    let dir = Utf8Path::from_path(temp_dir.path()).unwrap();

    let first = checker.check_directory_report(dir).unwrap();
    assert_eq!(first.results.len(), 1);
    assert!(first.results[0].0.contains("unsafe"));
    assert_eq!(first.failures.len(), 1);
    assert!(first.failures[0].path.contains("invalid"));
    assert!(!first.is_clean());
    assert_eq!(first.exit_code(), 1);

    // A retry after removing the broken migration is a fresh generation with
    // only the current manifest and results.
    fs::remove_dir_all(&invalid_dir).unwrap();
    let second = checker.check_directory_report(dir).unwrap();
    assert_ne!(second.generation, first.generation);
    assert!(second.failures.is_empty());
    assert_eq!(second.manifest.len(), 2);
    assert_eq!(second.results.len(), 1);
    assert!(second.results[0].0.contains("unsafe"));
    assert_eq!(second.exit_code(), 1);
}

#[test]
fn test_empty_directory_returns_no_results() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    let checker = SafetyChecker::default();
    let result = checker
        .check_directory(Utf8Path::from_path(temp_dir.path()).unwrap())
        .unwrap();

    assert!(
        result.is_empty(),
        "Empty directory should return no results"
    );
}

#[test]
fn test_directory_with_non_sql_files_ignored() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    fs::write(temp_dir.path().join("readme.txt"), "Hello").unwrap();
    fs::write(temp_dir.path().join("notes.md"), "# Notes").unwrap();

    let config = Config::default();
    let checker = SafetyChecker::with_config(config).unwrap();
    let result = checker
        .check_directory(Utf8Path::from_path(temp_dir.path()).unwrap())
        .unwrap();

    assert!(
        result.is_empty(),
        "Directory with only non-SQL files should return no results"
    );
}
