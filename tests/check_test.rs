use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

/// Run `diesel-guard check -` over stdin and return (success, stdout, stderr).
fn check_stdin(sql: &str) -> (bool, String, String) {
    let output = Command::cargo_bin("diesel-guard")
        .unwrap()
        .args(["check", "-"])
        .write_stdin(sql)
        .ok()
        .unwrap_or_else(|failed| failed.as_output().unwrap().clone());
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        // miette wraps long messages across lines, so compare on a
        // whitespace-normalized copy.
        String::from_utf8_lossy(&output.stderr)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[test]
fn test_default_migrations_dir() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let migrations_dir = temp_dir.path().join("migrations");
    fs::create_dir(&migrations_dir).expect("Failed to create migrations dir");
    fs::write(migrations_dir.join("up.sql"), "SELECT 1;").expect("Failed to write migration");

    Command::cargo_bin("diesel-guard")
        .unwrap()
        .arg("check")
        .current_dir(temp_dir.path())
        .assert()
        .success()
        .stdout("✅ No unsafe migrations detected!\n");
}

#[test]
fn test_stdin_input_safe() {
    Command::cargo_bin("diesel-guard")
        .unwrap()
        .args(["check", "-"])
        .write_stdin("SELECT 1;")
        .assert()
        .success()
        .stdout("✅ No unsafe migrations detected!\n");
}

#[test]
fn test_directive_inside_dollar_quoted_function_body_does_not_suppress_drop_table() {
    // The safety-assured-looking lines live inside the dollar-quoted function
    // body and are SQL data. The DROP TABLE after the body must still be flagged.
    let sql = r"
CREATE OR REPLACE FUNCTION do_thing() RETURNS void AS $$
BEGIN
    -- safety-assured:start
    PERFORM 1;
    -- safety-assured:end
END;
$$ LANGUAGE plpgsql;

DROP TABLE legacy_users;
";

    let (success, stdout, stderr) = check_stdin(sql);
    assert!(
        !success,
        "unguarded DROP TABLE must fail the check: {stderr}"
    );
    assert!(
        stdout.contains("DROP TABLE"),
        "stdout should report the DROP TABLE violation, got: {stdout}"
    );
}

#[test]
fn test_disable_directive_inside_string_literal_does_not_apply() {
    // A disable directive embedded in a string literal must not suppress the
    // check; the unguarded DROP TABLE must still be reported.
    let sql = r"
INSERT INTO notes (body) VALUES ('-- diesel-guard:disable DropTableCheck');
DROP TABLE legacy_users;
";

    let (success, stdout, stderr) = check_stdin(sql);
    assert!(
        !success,
        "unguarded DROP TABLE must fail the check: {stderr}"
    );
    assert!(
        stdout.contains("DROP TABLE"),
        "stdout should report the DROP TABLE violation, got: {stdout}"
    );
}

#[test]
fn test_unknown_disable_name_fails_closed() {
    // An unknown check name in a migration-scoped disable directive must abort
    // the run instead of being silently ignored.
    let sql = "-- diesel-guard:disable FakeCheckThatDoesNotExist\nDROP TABLE legacy_users;";

    let (success, _, stderr) = check_stdin(sql);
    assert!(!success, "unknown disable name must fail closed");
    assert!(
        stderr.contains("Unknown check name 'FakeCheckThatDoesNotExist'"),
        "stderr should name the unknown check, got: {stderr}"
    );
}

#[test]
fn test_conflicting_duplicate_disable_name_fails_closed() {
    // Listing the same check twice is a conflicting directive and must abort.
    let sql =
        "-- diesel-guard:disable AddColumnCheck, AddColumnCheck\nALTER TABLE t ADD COLUMN x TEXT;";

    let (success, _, stderr) = check_stdin(sql);
    assert!(!success, "duplicate disable names must fail closed");
    assert!(
        stderr.contains("Conflicting check name 'AddColumnCheck'"),
        "stderr should report the conflicting name, got: {stderr}"
    );
}

#[test]
fn test_real_directives_still_work_alongside_dollar_quoted_body() {
    // A genuine safety-assured block after a dollar-quoted body still applies.
    let sql = r"
CREATE FUNCTION f() RETURNS int AS $$
SELECT 1;
$$ LANGUAGE sql;

-- safety-assured:start
DROP TABLE legacy_users;
-- safety-assured:end
";

    let (success, _, stderr) = check_stdin(sql);
    assert!(
        success,
        "a real safety-assured block must still pass: {stderr}"
    );
}
