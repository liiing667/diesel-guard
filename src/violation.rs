use derive_more::Display;
use serde::Serialize;

/// Identifies one consistent generation of the full rule set.
///
/// A generation covers the built-in checks, every successfully loaded custom
/// script, and all [`Violation`] evidence those checks produce. Built-in
/// checks and custom scripts that were compiled together always share the same
/// generation. A successful [`crate::SafetyChecker::reload`] moves the checker
/// to a fresh generation; a failed reload leaves the previous generation
/// untouched, so a checker can never run a half-loaded rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct RuleGeneration(u64);

impl RuleGeneration {
    /// The first generation assigned to a freshly built checker.
    pub const FIRST: Self = Self(1);

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

impl Default for RuleGeneration {
    fn default() -> Self {
        Self::FIRST
    }
}

impl std::fmt::Display for RuleGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Display)]
#[display("{}: {}", operation, problem)]
pub struct Violation {
    pub check_name: String,
    pub operation: String,
    pub problem: String,
    pub safe_alternative: String,
    #[serde(default)]
    pub severity: Severity,
    /// Rule generation whose checks produced this evidence.
    ///
    /// Not part of the wire format: JSON consumers keep the historical
    /// `severity`-only schema, while in-process callers can compare
    /// generations via [`Violation::rule_generation`].
    #[serde(skip_serializing)]
    pub rule_generation: RuleGeneration,
}

impl Violation {
    pub fn new(
        operation: impl Into<String>,
        problem: impl Into<String>,
        safe_alternative: impl Into<String>,
    ) -> Self {
        Self {
            check_name: String::new(),
            operation: operation.into(),
            problem: problem.into(),
            safe_alternative: safe_alternative.into(),
            severity: Severity::Error,
            rule_generation: RuleGeneration::FIRST,
        }
    }

    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    #[must_use]
    pub fn with_check_name(mut self, name: &str) -> Self {
        self.check_name = name.to_string();
        self
    }

    /// Stamp this piece of evidence with the generation of the rule set that
    /// produced it.
    #[must_use]
    pub fn with_rule_generation(mut self, generation: RuleGeneration) -> Self {
        self.rule_generation = generation;
        self
    }

    /// Generation of the rule set whose check produced this violation.
    #[must_use]
    pub fn rule_generation(&self) -> RuleGeneration {
        self.rule_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_empty_check_name() {
        let v = Violation::new("op", "prob", "alt");
        assert_eq!(v.check_name, "");
    }

    #[test]
    fn test_with_check_name() {
        let v = Violation::new("op", "prob", "alt").with_check_name("AddIndexCheck");
        assert_eq!(v.check_name, "AddIndexCheck");
    }

    #[test]
    fn test_rule_generation_defaults_to_first() {
        let v = Violation::new("op", "prob", "alt");
        assert_eq!(v.rule_generation(), RuleGeneration::FIRST);
        assert_eq!(v.rule_generation().as_u64(), 1);
    }

    #[test]
    fn test_rule_generation_stamping_and_advance() {
        let next = RuleGeneration::FIRST.next();
        assert_eq!(next.as_u64(), 2);
        let v = Violation::new("op", "prob", "alt").with_rule_generation(next);
        assert_eq!(v.rule_generation(), next);
        assert_ne!(v.rule_generation(), RuleGeneration::FIRST);
    }
}
