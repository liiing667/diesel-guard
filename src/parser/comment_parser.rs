//! Parse safety-assured directives from SQL comments.
//!
//! Directives are only recognized in SQL line comments (`-- ...`) that appear
//! *outside* of string literals, quoted identifiers, dollar-quoted strings
//! (e.g. function bodies) and block comments. Text inside those constructs is
//! SQL data, not instructions for the linter, so a `-- safety-assured:start`
//! embedded in a `$$ ... $$` body or a string literal must be ignored.

use crate::error::{DieselGuardError, Result};
use derive_more::Display;
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

/// A SQL line comment found outside of strings, dollar quotes and block comments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LineComment {
    /// 1-indexed line number on which the comment starts.
    line_num: usize,
    /// Slice of the source line starting at the `--` marker.
    text: String,
}

/// Represents a range of lines that should be ignored
#[derive(Debug, Clone, PartialEq, Display)]
#[display("lines {}-{}", start_line, end_line)]
pub struct IgnoreRange {
    pub start_line: usize,
    pub end_line: usize,
}

pub struct CommentParser;

impl CommentParser {
    /// Parse SQL and extract safety-assured blocks
    /// Returns: `Vec<IgnoreRange>` and validates matching start/end pairs
    pub fn parse_ignore_ranges(sql: &str) -> Result<Vec<IgnoreRange>> {
        let mut ranges = Vec::new();
        let mut current_start: Option<usize> = None;

        for comment in Self::line_comments(sql) {
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

    /// Parse whole-migration check disable directives.
    ///
    /// Directives are comma-separated and apply to the entire SQL string:
    /// `-- diesel-guard:disable AddColumnCheck, DropColumnCheck`
    pub fn parse_disabled_checks(sql: &str) -> Vec<String> {
        Self::line_comments(sql)
            .iter()
            .filter_map(|comment| Self::parse_disabled_checks_line(&comment.text))
            .flatten()
            .collect()
    }

    /// Return the first check name listed by a disable directive more than once.
    ///
    /// Duplicates are conflicting instructions and must fail closed instead of
    /// being silently deduplicated downstream.
    pub fn find_duplicate_disabled_check(sql: &str) -> Option<String> {
        let mut seen = Vec::new();
        for name in Self::parse_disabled_checks(sql) {
            if seen.contains(&name) {
                return Some(name);
            }
            seen.push(name);
        }
        None
    }

    /// Scan SQL and return every line comment that starts outside of string
    /// literals, quoted identifiers, dollar-quoted strings and block comments.
    ///
    /// Line numbers are 1-indexed. A trailing `\r` (CRLF line endings) is part
    /// of neither the comment text nor the line count, so CRLF and LF files
    /// produce identical results.
    fn line_comments(sql: &str) -> Vec<LineComment> {
        SqlCommentLexer::new(sql).scan()
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

/// Lexical states tracked while scanning for real SQL line comments.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LexerState {
    Normal,
    SingleQuote,
    DoubleQuote,
    BlockComment,
    DollarQuote,
}

/// Minimal SQL lexer that records line comments located outside of string
/// literals, quoted identifiers, dollar-quoted strings and block comments.
struct SqlCommentLexer<'a> {
    sql: &'a str,
    bytes: &'a [u8],
    state: LexerState,
    block_comment_depth: usize,
    dollar_tag: Option<&'a str>,
    comments: Vec<LineComment>,
    index: usize,
    line_num: usize,
}

impl<'a> SqlCommentLexer<'a> {
    fn new(sql: &'a str) -> Self {
        Self {
            sql,
            bytes: sql.as_bytes(),
            state: LexerState::Normal,
            block_comment_depth: 0,
            dollar_tag: None,
            comments: Vec::new(),
            index: 0,
            line_num: 1,
        }
    }

    fn scan(mut self) -> Vec<LineComment> {
        while self.index < self.bytes.len() {
            match self.state {
                LexerState::Normal => self.scan_normal(),
                LexerState::SingleQuote => self.scan_single_quote(),
                LexerState::DoubleQuote => self.scan_double_quote(),
                LexerState::BlockComment => self.scan_block_comment(),
                LexerState::DollarQuote => self.scan_dollar_quote(),
            }
        }
        self.comments
    }

    fn scan_normal(&mut self) {
        let byte = self.bytes[self.index];

        // Line comment: record and skip to the end of the line.
        if byte == b'-' && self.bytes.get(self.index + 1) == Some(&b'-') {
            self.record_line_comment();
            self.index += 2;
            while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                self.index += 1;
            }
        }
        // Block comment: block comments nest in PostgreSQL.
        else if byte == b'/' && self.bytes.get(self.index + 1) == Some(&b'*') {
            self.state = LexerState::BlockComment;
            self.block_comment_depth = 1;
            self.index += 2;
        }
        // Standard or escape (E'...') string literal.
        else if byte == b'\'' {
            self.state = LexerState::SingleQuote;
            self.index += 1;
        }
        // Quoted identifier.
        else if byte == b'"' {
            self.state = LexerState::DoubleQuote;
            self.index += 1;
        }
        // Dollar-quoted string: $tag$ ... $tag$ (tag may be empty).
        else if byte == b'$' {
            self.enter_dollar_quote();
        } else {
            self.advance(byte);
        }
    }

    fn scan_single_quote(&mut self) {
        let byte = self.bytes[self.index];
        // A doubled quote is an escaped quote and stays in the string.
        if byte == b'\'' && self.bytes.get(self.index + 1) == Some(&b'\'') {
            self.index += 2;
        } else if byte == b'\'' {
            self.state = LexerState::Normal;
            self.index += 1;
        } else if byte == b'\\' {
            // Backslash escape in E'...' strings; skip the escaped byte.
            self.index += 2.min(self.bytes.len() - self.index);
        } else {
            self.advance(byte);
        }
    }

    fn scan_double_quote(&mut self) {
        let byte = self.bytes[self.index];
        if byte == b'"' && self.bytes.get(self.index + 1) == Some(&b'"') {
            self.index += 2;
        } else if byte == b'"' {
            self.state = LexerState::Normal;
            self.index += 1;
        } else {
            self.advance(byte);
        }
    }

    fn scan_block_comment(&mut self) {
        let byte = self.bytes[self.index];
        if byte == b'*' && self.bytes.get(self.index + 1) == Some(&b'/') {
            self.block_comment_depth -= 1;
            if self.block_comment_depth == 0 {
                self.state = LexerState::Normal;
            }
            self.index += 2;
        } else if byte == b'/' && self.bytes.get(self.index + 1) == Some(&b'*') {
            self.block_comment_depth += 1;
            self.index += 2;
        } else {
            self.advance(byte);
        }
    }

    fn scan_dollar_quote(&mut self) {
        let byte = self.bytes[self.index];
        let tag = self.dollar_tag.expect("dollar quote state requires a tag");
        if self.sql[self.index..].starts_with(tag) {
            self.state = LexerState::Normal;
            self.dollar_tag = None;
            self.index += tag.len();
        } else {
            self.advance(byte);
        }
    }

    fn enter_dollar_quote(&mut self) {
        match Self::match_dollar_tag(&self.sql[self.index..]) {
            Some((tag, len)) => {
                self.dollar_tag = Some(tag);
                self.state = LexerState::DollarQuote;
                self.index += len;
            }
            None => self.index += 1,
        }
    }

    fn record_line_comment(&mut self) {
        let line_start = self.sql[..self.index].rfind('\n').map_or(0, |pos| pos + 1);
        // A directive must occupy the whole line; a trailing comment after
        // SQL code is never one.
        let whole_line_comment = self.sql[line_start..self.index]
            .bytes()
            .all(|byte| byte.is_ascii_whitespace());
        if whole_line_comment {
            self.comments.push(LineComment {
                line_num: self.line_num,
                text: self.sql[self.index..]
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }

    fn advance(&mut self, byte: u8) {
        if byte == b'\n' {
            self.line_num += 1;
        }
        self.index += 1;
    }

    /// Match a PostgreSQL dollar-quote opener such as `$tag$` or `$$`.
    ///
    /// Returns the full opening token (which is also the closing token) and its
    /// byte length, or `None` when the input does not start with a valid tag.
    fn match_dollar_tag(input: &str) -> Option<(&str, usize)> {
        let bytes = input.as_bytes();
        if bytes.first() != Some(&b'$') {
            return None;
        }
        let mut end = 1;
        while end < bytes.len() && bytes[end] != b'$' {
            let byte = bytes[end];
            let is_tag_byte = byte.is_ascii_alphanumeric() || byte == b'_';
            if !is_tag_byte {
                return None;
            }
            end += 1;
        }
        if end >= bytes.len() {
            return None;
        }
        Some((&input[..=end], end + 1))
    }
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
    fn test_directive_inside_dollar_quoted_function_body_is_ignored() {
        // The `-- safety-assured:start` line is SQL data inside the dollar-quoted
        // function body, so it must not open an ignore range. The subsequent
        // DROP TABLE therefore stays fully visible to the checks.
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

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0, "dollar-quoted directives must be ignored");
    }

    #[test]
    fn test_directive_inside_named_dollar_quote_is_ignored() {
        let sql = r"
CREATE FUNCTION f() RETURNS int AS $body$
-- safety-assured:start
SELECT 1;
$body$ LANGUAGE sql;
-- safety-assured:end
        ";

        // Only the comment after the closing $body$ is real SQL; it is an
        // unmatched end, proving the in-body start was not recognized.
        let err = CommentParser::parse_ignore_ranges(sql).unwrap_err();
        assert!(
            err.to_string().contains("Unmatched 'safety-assured:end'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_directive_after_dollar_quoted_body_is_recognized() {
        let sql = r"
CREATE FUNCTION f() RETURNS int AS $$
SELECT 1;
$$ LANGUAGE sql;

-- safety-assured:start
DROP TABLE legacy_users;
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 6);
        assert_eq!(ranges[0].end_line, 8);
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

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0, "string contents must be ignored");
    }

    #[test]
    fn test_disable_directive_inside_string_literal_is_ignored() {
        let sql = r"
INSERT INTO notes (body) VALUES ('-- diesel-guard:disable DropTableCheck');
DROP TABLE legacy_users;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(disabled.len(), 0, "string contents must not disable checks");
    }

    #[test]
    fn test_disable_directive_inside_dollar_quote_is_ignored() {
        let sql = r"
CREATE FUNCTION f() RETURNS text AS $$
BEGIN
    RETURN '-- diesel-guard:disable DropTableCheck';
END;
$$ LANGUAGE plpgsql;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(
            disabled.len(),
            0,
            "dollar-quoted contents must not disable checks"
        );
    }

    #[test]
    fn test_disable_directive_outside_strings_still_parses() {
        let sql = r"
-- diesel-guard:disable DropTableCheck, AddColumnCheck
DROP TABLE legacy_users;
        ";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(disabled, vec!["DropTableCheck", "AddColumnCheck"]);
    }

    #[test]
    fn test_doubled_single_quote_does_not_terminate_string() {
        // The doubled '' is an escaped quote, so the directive-looking text on
        // the next line remains inside the string and must be ignored.
        let sql =
            "INSERT INTO t (a) VALUES ('it''s text\n-- safety-assured:start\n');\nDROP TABLE t;";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_escaped_quote_in_e_string_does_not_terminate_string() {
        let sql = "SELECT E'line\\'s\n-- safety-assured:start\n';\nDROP TABLE t;";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_directive_inside_quoted_identifier_is_ignored() {
        let sql = "CREATE TABLE \"weird -- safety-assured:start\nname\" (id int);\nDROP TABLE t;";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
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

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0, "block comment contents must be ignored");
    }

    #[test]
    fn test_nested_block_comment_is_skipped() {
        let sql = r"
/* outer /* nested */ still outer
  -- safety-assured:start
*/
-- safety-assured:end
        ";

        let err = CommentParser::parse_ignore_ranges(sql).unwrap_err();
        assert!(
            err.to_string().contains("Unmatched 'safety-assured:end'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_crlf_line_endings_keep_line_numbers() {
        let sql = "\r\n-- safety-assured:start\r\nDROP TABLE t;\r\n-- safety-assured:end\r\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 4);
    }

    #[test]
    fn test_crlf_directives_inside_dollar_quote_are_ignored() {
        let sql = "CREATE FUNCTION f() RETURNS int AS $$\r\n-- safety-assured:start\r\nSELECT 1;\r\n$$ LANGUAGE sql;\r\nDROP TABLE t;\r\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_mixed_real_and_quoted_directives() {
        // A quoted decoy followed by a real block outside the quote.
        let sql = r"
SELECT '-- safety-assured:start' AS decoy;
-- safety-assured:start
DROP TABLE legacy_users;
-- safety-assured:end
        ";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 3);
        assert_eq!(ranges[0].end_line, 5);
    }

    #[test]
    fn test_inline_comment_after_code_is_not_a_directive() {
        // Directives must occupy their own (whitespace-prefixed) line; a trailing
        // comment after SQL code is never a directive.
        let sql = "SELECT 1; -- safety-assured:start\nDROP TABLE t;";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_unterminated_dollar_quote_consumes_rest_of_input() {
        // Without a closing tag the body runs to EOF, so the directive-looking
        // line stays inside the quote and is ignored (no phantom unclosed block).
        let sql = "CREATE FUNCTION f() RETURNS int AS $$\n-- safety-assured:start\nSELECT 1;\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_dollar_sign_that_is_not_a_tag_is_plain_text() {
        // `$1` is a parameter placeholder, not a dollar-quote opener, so the
        // directive on the next line is normal SQL and must be recognized.
        let sql =
            "PREPARE p AS SELECT $1;\n-- safety-assured:start\nSELECT 1;\n-- safety-assured:end\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
        assert_eq!(ranges[0].end_line, 4);
    }

    #[test]
    fn test_dollar_tag_rejects_invalid_characters() {
        // A tag may only contain alphanumerics and underscores; `$a-b$` is not
        // a valid opener, so the later directive remains real SQL.
        let sql =
            "SELECT '$a-b$' AS x;\n-- safety-assured:start\nSELECT 1;\n-- safety-assured:end\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_backslash_escaped_quote_then_real_directive() {
        // After the E'...' string closes, a directive on a later line is real.
        let sql = "SELECT E'a\\'b';\n-- safety-assured:start\nSELECT 1;\n-- safety-assured:end\n";

        let ranges = CommentParser::parse_ignore_ranges(sql).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 2);
    }

    #[test]
    fn test_comment_token_inside_dollar_body_with_crlf() {
        let sql = "CREATE FUNCTION f() RETURNS int AS $$\r\n-- diesel-guard:disable DropTableCheck\r\nSELECT 1;\r\n$$ LANGUAGE sql;\r\n";

        let disabled = CommentParser::parse_disabled_checks(sql);
        assert_eq!(disabled.len(), 0);
    }
}
