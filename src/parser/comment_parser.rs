//! Parse safety-assured directives from SQL comments.
//!
//! Directives are only recognized in line comments emitted by PostgreSQL's
//! scanner. Directive-looking text inside string literals, quoted identifiers,
//! dollar-quoted strings, and block comments is SQL data, not a linter
//! instruction.

use crate::error::{DieselGuardError, Result};
use derive_more::Display;
use pg_query::protobuf::Token;
use regex::Regex;
use std::sync::LazyLock;

/// Regex pattern for matching safety-assured:start directive
/// Matches: optional whitespace, --, optional whitespace, safety-assured:start, optional whitespace
/// Case-insensitive
static START_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*--\s*safety-assured:start\s*$").unwrap());

/// Regex pattern for matching safety-assured:end directive
/// Matches: optional whitespace, --, optional whitespace, safety-assured:end, optional whitespace
/// Case-insensitive
static END_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*--\s*safety-assured:end\s*$").unwrap());

/// Regex pattern for matching whole-migration check disable directives.
/// Matches: -- diesel-guard:disable AddColumnCheck, DropColumnCheck
/// Case-insensitive for the directive prefix; check names retain their original case.
static DISABLE_CHECKS_DIRECTIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*--\s*diesel-guard:disable\s+(.+?)\s*$").unwrap());

/// Represents a range of lines that should be ignored
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display("lines {}-{}", start_line, end_line)]
pub struct IgnoreRange {
    pub start_line: usize,
    pub end_line: usize,
}

/// Directive metadata produced by one scan of one SQL source string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectiveMetadata {
    pub ignore_ranges: Vec<IgnoreRange>,
    pub disabled_checks: Vec<String>,
}

/// A real SQL line comment, located outside of quoted SQL and block comments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LineComment {
    /// 1-indexed line number on which the comment starts.
    line_num: usize,
    /// Comment text beginning at `--` and ending before the line terminator.
    text: String,
}

pub struct CommentParser;

impl CommentParser {
    /// Extract all directives in a single scan of `sql`.
    ///
    /// Ranges and disabled checks returned here are derived from the same
    /// immutable source snapshot. Callers must not combine them with metadata
    /// produced from a different scan.
    ///
    /// # Errors
    ///
    /// Returns an error when safety-assured directives are unbalanced or nested.
    pub fn parse(sql: &str) -> Result<DirectiveMetadata> {
        let comments = Self::line_comments(sql);

        Ok(DirectiveMetadata {
            ignore_ranges: Self::ignore_ranges_from_comments(&comments)?,
            disabled_checks: Self::disabled_checks_from_comments(&comments),
        })
    }

    /// Parse SQL and extract safety-assured blocks
    /// Returns: `Vec<IgnoreRange>` and validates matching start/end pairs
    pub fn parse_ignore_ranges(sql: &str) -> Result<Vec<IgnoreRange>> {
        Ok(Self::parse(sql)?.ignore_ranges)
    }

    /// Parse whole-migration check disable directives.
    ///
    /// Directives are comma-separated and apply to the entire SQL string:
    /// `-- diesel-guard:disable AddColumnCheck, DropColumnCheck`
    pub fn parse_disabled_checks(sql: &str) -> Vec<String> {
        Self::disabled_checks_from_comments(&Self::line_comments(sql))
    }

    /// Return the first check name listed by disable directives more than once.
    ///
    /// Duplicates are conflicting instructions and must fail closed instead of
    /// being silently deduplicated downstream.
    pub fn find_duplicate_disabled_check(sql: &str) -> Option<String> {
        Self::duplicate_disabled_check(&Self::parse_disabled_checks(sql))
    }

    pub(crate) fn duplicate_disabled_check(disabled_checks: &[String]) -> Option<String> {
        let mut seen: Vec<&str> = Vec::new();
        for name in disabled_checks {
            if seen.contains(&name.as_str()) {
                return Some(name.clone());
            }
            seen.push(name.as_str());
        }
        None
    }

    fn ignore_ranges_from_comments(comments: &[LineComment]) -> Result<Vec<IgnoreRange>> {
        let mut ranges = Vec::new();
        let mut current_start: Option<usize> = None;

        for comment in comments {
            let line_num = comment.line_num;
            // Match start directive
            if Self::is_start_directive(&comment.text) {
                if current_start.is_some() {
                    return Err(DieselGuardError::parse_error(format!(
                        "Nested 'safety-assured:start' at line {line_num}. Nested blocks are not supported. Close the previous block before starting a new one."
                    )));
                }
                current_start = Some(line_num);
            }
            // Match end directive
            else if Self::is_end_directive(&comment.text) {
                match current_start.take() {
                    Some(start_line) => {
                        ranges.push(IgnoreRange {
                            start_line,
                            end_line: line_num,
                        });
                    }
                    None => {
                        return Err(DieselGuardError::parse_error(format!(
                            "Unmatched 'safety-assured:end' at line {line_num}. Each 'safety-assured:end' must have a matching 'safety-assured:start' before it."
                        )));
                    }
                }
            }
        }

        // Check for unclosed blocks
        if let Some(start_line) = current_start {
            return Err(DieselGuardError::parse_error(format!(
                "Unclosed 'safety-assured:start' at line {start_line}. Did you forget to add 'safety-assured:end'?"
            )));
        }

        Ok(ranges)
    }

    fn disabled_checks_from_comments(comments: &[LineComment]) -> Vec<String> {
        comments
            .iter()
            .filter_map(|comment| Self::parse_disabled_checks_line(&comment.text))
            .flatten()
            .collect()
    }

    /// Return line comments that the PostgreSQL scanner recognizes outside
    /// quoted strings, quoted identifiers, dollar-quoted strings, and block
    /// comments.
    ///
    /// A fresh scan is performed for every call. No comment or directive state
    /// is retained between parses, so correcting a migration and parsing it
    /// again cannot reuse a previous generation's ignore ranges.
    ///
    /// If PostgreSQL's scanner rejects the input, no directives are returned.
    /// The migration parser reports the syntax error separately; failing with
    /// zero directives keeps a partial scan from suppressing dangerous SQL.
    fn line_comments(sql: &str) -> Vec<LineComment> {
        let Ok(scan) = pg_query::scan(sql) else {
            return Vec::new();
        };

        scan.tokens
            .iter()
            .filter(|token| token.token == Token::SqlComment as i32)
            .filter_map(|token| Self::line_comment_from_token(sql, token.start, token.end))
            .collect()
    }

    fn line_comment_from_token(sql: &str, start: i32, end: i32) -> Option<LineComment> {
        let token_start = usize::try_from(start).ok()?;
        let token_end = usize::try_from(end).ok()?.min(sql.len());
        let raw = sql.get(token_start..token_end)?;
        let comment_start = token_start.checked_add(raw.find("--")?)?;

        // Directives must occupy their own line. A trailing comment after SQL
        // code is not a directive.
        let line_start = sql[..comment_start].rfind('\n').map_or(0, |pos| pos + 1);
        if !sql
            .get(line_start..comment_start)?
            .chars()
            .all(char::is_whitespace)
        {
            return None;
        }

        let line_end = sql[comment_start..]
            .find(|c| c == '\r' || c == '\n')
            .map_or(sql.len(), |pos| comment_start + pos);
        let text = sql.get(comment_start..line_end)?;

        Some(LineComment {
            line_num: byte_offset_to_line(sql, comment_start),
            text: text.to_string(),
        })
    }

    /// Check if line is a start directive
    fn is_start_directive(line: &str) -> bool {
        START_DIRECTIVE.is_match(line)
    }

    /// Check if line is an end directive
    fn is_end_directive(line: &str) -> bool {
        END_DIRECTIVE.is_match(line)
    }

    fn parse_disabled_checks_line(line: &str) -> Option<Vec<String>> {
        let captures = DISABLE_CHECKS_DIRECTIVE.captures(line)?;
        let checks = captures
            .get(1)?
            .as_str()
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();

        if checks.is_empty() {
            None
        } else {
            Some(checks)
        }
    }
}

/// Convert a byte offset to a 1-indexed line number.
fn byte_offset_to_line(sql: &str, byte_offset: usize) -> usize {
    let offset = byte_offset.min(sql.len());
    sql.as_bytes()[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_block() {
        let sql = r"
-- safety-assured:start
ALTER TABLE users DROP COLUMN email;
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 4);
    }

    #[test]
    fn test_multiple_blocks() {
        let sql = r"
-- safety-assured:start
ALTER TABLE users DROP COLUMN email;
-- safety-assured:end

ALTER TABLE posts ADD COLUMN body TEXT;

-- safety-assured:start
DROP INDEX old_index;
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 4);
        assert_eq!(ranges[1].start_line, 8);
        assert_eq!(ranges[1].end_line, 10);
    }

    #[test]
    fn test_case_insensitive() {
        let sql = r"
-- SAFETY-ASSURED:START
ALTER TABLE users DROP COLUMN email;
-- safety-ASSURED:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_unmatched_end() {
        let sql = r"
ALTER TABLE users DROP COLUMN email;
-- safety-assured:end
        ";

        let err = CommentParser::parse_ignore_ranges(sql).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse SQL: Unmatched 'safety-assured:end' at line 3. Each 'safety-assured:end' must have a matching 'safety-assured:start' before it."
        );
    }

    #[test]
    fn test_unclosed_start() {
        let sql = r"
-- safety-assured:start
ALTER TABLE users DROP COLUMN email;
        ";

        let err = CommentParser::parse_ignore_ranges(sql).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse SQL: Unclosed 'safety-assured:start' at line 2. Did you forget to add 'safety-assured:end'?"
        );
    }

    #[test]
    fn test_nested_blocks_error() {
        let sql = r"
-- safety-assured:start
ALTER TABLE users DROP COLUMN email;
-- safety-assured:start
ALTER TABLE posts DROP COLUMN body;
-- safety-assured:end
-- safety-assured:end
        ";

        // Nested blocks should be rejected with clear error
        let err = CommentParser::parse_ignore_ranges(sql).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse SQL: Nested 'safety-assured:start' at line 4. Nested blocks are not supported. Close the previous block before starting a new one."
        );
    }

    #[test]
    fn test_empty_block() {
        let sql = r"
-- safety-assured:start
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 3);
    }

    #[test]
    fn test_block_with_comments() {
        let sql = r"
-- safety-assured:start
-- This column was deprecated
ALTER TABLE users DROP COLUMN email;
-- All references removed
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 6);
    }

    #[test]
    fn test_no_blocks() {
        let sql = r"
ALTER TABLE users DROP COLUMN email;
ALTER TABLE posts ADD COLUMN body TEXT;
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_parse_disabled_checks_directive() {
        let sql = r"
-- diesel-guard:disable AddColumnCheck, DropColumnCheck
ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(disabled, vec!["AddColumnCheck", "DropColumnCheck"]);
    }

    #[test]
    fn test_parse_disabled_checks_directive_is_case_insensitive() {
        let sql = r"
-- DIESEL-GUARD:DISABLE AddColumnCheck
ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(disabled, vec!["AddColumnCheck"]);
    }

    #[test]
    fn test_parse_multiple_disabled_checks_directives() {
        let sql = r"
-- diesel-guard:disable AddColumnCheck
-- diesel-guard:disable DropColumnCheck, ReindexCheck
ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(
            disabled,
            vec!["AddColumnCheck", "DropColumnCheck", "ReindexCheck"]
        );
    }

    #[test]
    fn test_find_duplicate_disabled_check() {
        let sql = r"
-- diesel-guard:disable AddColumnCheck
-- diesel-guard:disable DropColumnCheck, AddColumnCheck
        ";

        assert_eq!(
            CommentParser::find_duplicate_disabled_check(sql),
            Some("AddColumnCheck".to_string())
        );
    }

    #[test]
    fn test_find_duplicate_disabled_check_ignores_quoted_text() {
        let sql = r"
SELECT '
-- diesel-guard:disable AddColumnCheck
';
-- diesel-guard:disable AddColumnCheck
        ";

        assert_eq!(CommentParser::find_duplicate_disabled_check(sql), None);
    }

    #[test]
    fn test_directive_variations() {
        // Test different whitespace and formatting
        assert!(CommentParser::is_start_directive("-- safety-assured:start"));
        assert!(CommentParser::is_start_directive("--safety-assured:start"));
        assert!(CommentParser::is_start_directive(
            "  -- safety-assured:start  "
        ));
        assert!(CommentParser::is_start_directive("-- SAFETY-ASSURED:START"));

        // Not start directives
        assert!(!CommentParser::is_start_directive("-- safety-assured:end"));
        assert!(!CommentParser::is_start_directive("ALTER TABLE users"));
        assert!(!CommentParser::is_start_directive("-- some comment"));
    }

    #[test]
    fn test_directive_requires_exact_match() {
        // These should NOT match - no extra characters allowed
        assert!(!CommentParser::is_start_directive(
            "-- safety-assured:start111"
        ));
        assert!(!CommentParser::is_start_directive(
            "-- safety-assured:startx"
        ));
        assert!(!CommentParser::is_start_directive(
            "-- xsafety-assured:start"
        ));
        assert!(!CommentParser::is_start_directive(
            "-- safety-assured:start extra text"
        ));

        assert!(!CommentParser::is_end_directive("-- safety-assured:end222"));
        assert!(!CommentParser::is_end_directive("-- safety-assured:endx"));
        assert!(!CommentParser::is_end_directive(
            "-- safety-assured:end extra text"
        ));

        // Invalid directive should cause an error (unmatched end)
        let sql = r"
-- safety-assured:start111
ALTER TABLE users DROP COLUMN email;
-- safety-assured:end
        ";

        let err = CommentParser::parse_ignore_ranges(sql)
            .expect_err("Invalid start directive should not be recognized");
        assert_eq!(
            err.to_string(),
            "Failed to parse SQL: Unmatched 'safety-assured:end' at line 4. Each 'safety-assured:end' must have a matching 'safety-assured:start' before it."
        );
    }

    #[test]
    fn test_parse_disabled_checks_returns_none_for_empty_list() {
        // After splitting "," by comma and filtering empty strings, the list is empty → None.
        let result = CommentParser::parse_disabled_checks_line("-- diesel-guard:disable ,");
        assert!(result.is_none());
    }

    #[test]
    fn test_directive_inside_dollar_quoted_body_is_ignored() {
        let sql = r"
CREATE FUNCTION f() RETURNS text AS $body$
BEGIN
    -- safety-assured:start
    RETURN 'ok';
    -- safety-assured:end
END;
$body$ LANGUAGE plpgsql;

DROP TABLE legacy_users;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "dollar-quoted directives must not create ignore ranges"
        );
    }

    #[test]
    fn test_directives_inside_separate_dollar_quotes_do_not_hide_drop() {
        let sql = r"
CREATE FUNCTION f() RETURNS int AS $$
-- safety-assured:start
SELECT 1;
$$ LANGUAGE sql;

DROP TABLE legacy_users;

CREATE FUNCTION g() RETURNS int AS $$
-- safety-assured:end
SELECT 1;
$$ LANGUAGE sql;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "pseudo-directives inside separate quotes must not span real SQL"
        );
    }

    #[test]
    fn test_directive_inside_string_literal_is_ignored() {
        let sql = r"
INSERT INTO notes (body) VALUES ('
-- safety-assured:start
some text
-- safety-assured:end
');
DROP TABLE legacy_users;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "string contents must not create ignore ranges"
        );
    }

    #[test]
    fn test_directive_inside_quoted_identifier_is_ignored() {
        let sql = "CREATE TABLE \"weird\n-- safety-assured:start\nname\" (id int);\nDROP TABLE t;";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "quoted identifiers must not create ignore ranges"
        );
    }

    #[test]
    fn test_directive_inside_block_comment_is_ignored() {
        let sql = r"
/*
  -- safety-assured:start
  documentation text
*/
DROP TABLE legacy_users;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "block comment contents must not create ignore ranges"
        );
    }

    #[test]
    fn test_disable_directive_inside_string_or_dollar_quote_is_ignored() {
        let sql = r"
INSERT INTO notes (body) VALUES ('
-- diesel-guard:disable DropTableCheck
');

CREATE FUNCTION f() RETURNS text AS $$
BEGIN
    -- diesel-guard:disable AddColumnCheck
    RETURN 'ok';
END;
$$ LANGUAGE plpgsql;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.disabled_checks.is_empty(),
            "quoted text must not disable checks"
        );
    }

    #[test]
    fn test_real_directives_still_work_after_quoted_decoys() {
        let sql = r"
SELECT '-- safety-assured:start' AS decoy;
SELECT $$-- safety-assured:end$$ AS decoy;

-- SAFETY-ASSURED:START
DROP TABLE first_legacy_table;
-- safety-ASSURED:end

-- diesel-guard:disable DropTableCheck
DROP TABLE second_legacy_table;
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert_eq!(
            directives.ignore_ranges,
            vec![IgnoreRange {
                start_line: 5,
                end_line: 7,
            }]
        );
        assert_eq!(directives.disabled_checks, vec!["DropTableCheck"]);
    }

    #[test]
    fn test_nested_real_blocks_still_error() {
        let sql = r"
-- safety-assured:start
DROP TABLE first_legacy_table;
-- safety-assured:start
DROP TABLE second_legacy_table;
-- safety-assured:end
-- safety-assured:end
        ";

        let err = CommentParser::parse(sql).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse SQL: Nested 'safety-assured:start' at line 4. Nested blocks are not supported. Close the previous block before starting a new one."
        );
    }

    #[test]
    fn test_quoted_directive_does_not_create_a_nested_block() {
        let sql = r"
-- safety-assured:start
SELECT '-- safety-assured:start' AS decoy;
DROP TABLE legacy_users;
-- safety-assured:end
        ";

        let directives = CommentParser::parse(sql).unwrap();
        assert_eq!(
            directives.ignore_ranges,
            vec![IgnoreRange {
                start_line: 2,
                end_line: 5,
            }]
        );
    }

    #[test]
    fn test_crlf_line_numbers_are_preserved() {
        let sql = "\r\n-- safety-assured:start\r\nDROP TABLE t;\r\n-- safety-assured:end\r\n";

        let directives = CommentParser::parse(sql).unwrap();
        assert_eq!(
            directives.ignore_ranges,
            vec![IgnoreRange {
                start_line: 2,
                end_line: 4,
            }]
        );
    }

    #[test]
    fn test_trailing_comment_after_code_is_not_a_directive() {
        let sql = "SELECT 1; -- safety-assured:start\nDROP TABLE t;\n-- safety-assured:end\n";

        let err = CommentParser::parse(sql).unwrap_err();
        assert!(
            err.to_string()
                .contains("Unmatched 'safety-assured:end' at line 3"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_unterminated_dollar_quote_fails_closed() {
        let sql = "CREATE FUNCTION f() RETURNS text AS $$\n-- safety-assured:start\nSELECT 1;\n";

        let directives = CommentParser::parse(sql).unwrap();
        assert!(
            directives.ignore_ranges.is_empty(),
            "an incomplete scan must not publish ignore ranges"
        );
        assert!(directives.disabled_checks.is_empty());
    }

    #[test]
    fn test_fresh_parse_does_not_reuse_previous_generation_ranges() {
        let pseudo = r"
CREATE FUNCTION f() RETURNS int AS $$
-- safety-assured:start
SELECT 1;
$$ LANGUAGE sql;
DROP TABLE legacy_users;
CREATE FUNCTION g() RETURNS int AS $$
-- safety-assured:end
SELECT 1;
$$ LANGUAGE sql;
        ";

        let first = CommentParser::parse(pseudo).unwrap();
        assert!(first.ignore_ranges.is_empty());

        let repaired = r"
CREATE FUNCTION f() RETURNS int AS $$
SELECT 1;
$$ LANGUAGE sql;
DROP TABLE legacy_users;
        ";

        let second = CommentParser::parse(repaired).unwrap();
        assert!(
            second.ignore_ranges.is_empty(),
            "a retry must start with a fresh directive generation"
        );
    }
}
