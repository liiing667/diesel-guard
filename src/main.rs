use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use diesel_guard::ast_dump;
use diesel_guard::formatters::Formatter;
use diesel_guard::output::{
    exit_code, parse_formats, plan_outputs, plan_outputs_from_base, publish_snapshot,
    render_stdout, ViolationSnapshot,
};
use diesel_guard::output::OutputFormat;
use diesel_guard::{Config, SafetyChecker};
use miette::{IntoDiagnostic, Result};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

const CONFIG_TEMPLATE: &str = include_str!("../diesel-guard.toml.example");

#[derive(Parser)]
#[command(
    name = "diesel-guard",
    version,
    about = "Catch unsafe Postgres migrations in Diesel and SQLx before they take down production",
    long_about = "Catch unsafe Postgres migrations in Diesel and SQLx before they take down production.

diesel-guard parses SQL with PostgreSQL's own parser (libpg_query) and flags operations
that acquire dangerous locks or cause table rewrites.

QUICK START:
  diesel-guard init              Create diesel-guard.toml in the current directory
  diesel-guard check             Check all migrations in ./migrations/
  diesel-guard check up.sql      Check a single file
  diesel-guard check -           Read SQL from stdin

Exit codes:
  0  No violations found (warnings do not affect exit code)
  1  One or more errors found (or a fatal error occurred)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check migrations for unsafe operations
    #[command(long_about = "Check migrations for unsafe operations.

PATH can be:
  - A directory — scans all up.sql files recursively
  - A single .sql file
  - \"-\" to read from stdin

If PATH is omitted, defaults to \"migrations/\".

diesel-guard looks for diesel-guard.toml in the current directory. If no config
file is found, default settings are used.

Exit codes:
  0  No errors found (warnings do not affect exit code)
  1  One or more errors found

EXAMPLES:
  diesel-guard check
  diesel-guard check migrations/
  diesel-guard check db/migrate/20240101_add_users/up.sql
  cat migration.sql | diesel-guard check -
  diesel-guard check migrations/ --format json")]
    Check {
        /// Path to migration file or directory, or "-" for stdin (default: "migrations/")
        path: Option<Utf8PathBuf>,

        /// Output format(s): text, json, github (repeat or comma-separate)
        #[arg(
            long,
            short = 'f',
            visible_alias = "report-format",
            value_delimiter = ',',
            action = clap::ArgAction::Append
        )]
        format: Vec<String>,

        /// Write a report to this path; repeat to map several formats in order
        #[arg(
            long,
            short = 'o',
            visible_aliases = ["output-file", "report-path", "report"],
            action = clap::ArgAction::Append
        )]
        output: Vec<Utf8PathBuf>,
    },

    /// Initialize diesel-guard configuration file
    #[command(long_about = "Initialize diesel-guard configuration file.

Creates diesel-guard.toml in the current directory with all available options
documented. Edit the file to set your migration framework (\"diesel\" or \"sqlx\")
and any other options.

Use --force to regenerate the config file and reset it to defaults.

EXAMPLES:
  diesel-guard init
  diesel-guard init --force")]
    Init {
        /// Overwrite existing config file if it exists
        #[arg(long)]
        force: bool,
    },

    /// Dump the pg_query AST for SQL as JSON
    #[command(long_about = "Dump the pg_query AST for SQL as JSON.

Useful when writing custom Rhai checks — shows the exact AST structure that
your scripts receive. Provide either --sql for an inline string or --file for
a .sql file (not both).

EXAMPLES:
  diesel-guard dump-ast --sql \"ALTER TABLE users ADD COLUMN email TEXT\"
  diesel-guard dump-ast --file migrations/20240101/up.sql")]
    DumpAst {
        /// SQL string to parse
        #[arg(long, conflicts_with = "file", required_unless_present = "file")]
        sql: Option<String>,

        /// Path to a .sql file to parse
        #[arg(long, conflicts_with = "sql", required_unless_present = "sql")]
        file: Option<Utf8PathBuf>,
    },

    /// List all available checks
    ListChecks {
        /// Output format (default: text)
        #[arg(long, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Show full description of a specific check
    Explain {
        /// Check name (e.g. AddIndexCheck or require_concurrent)
        check_name: String,

        /// Output format (default: text)
        #[arg(long, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

fn run_check(
    path: &camino::Utf8Path,
    format_args: &[String],
    output_args: &[Utf8PathBuf],
) -> Result<()> {
    let formats = parse_formats(format_args.join(",")).map_err(|e| miette::miette!(e))?;
    if output_args.len() > formats.len() {
        return Err(miette::miette!(
            "got {} output path(s) for {} selected format(s)",
            output_args.len(),
            formats.len()
        ));
    }

    let config = Config::load().map_err(|e| miette::miette!(e))?;
    let checker = SafetyChecker::with_config(config).map_err(|e| miette::miette!(e))?;
    let results = checker.check_path(path)?;

    // Freeze one generation: the rendered reports and the process status below
    // must all describe the same violation set.
    let snapshot = ViolationSnapshot::new(results);
    let code = exit_code(&snapshot.results);

    if output_args.is_empty() && formats.len() == 1 {
        // A single format keeps the historical stdout behaviour exactly.
        let payload = render_stdout(&snapshot.results, &formats);
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(payload.as_bytes()).into_diagnostic()?;
        stdout.flush().into_diagnostic()?;
    } else {
        // Several selected formats publish one file per format, all in the
        // same transaction.  Without explicit paths the historical report
        // naming scheme is used.
        let paths: Vec<PathBuf> = output_args
            .iter()
            .map(|path| PathBuf::from(path.as_str()))
            .collect();
        let targets = if output_args.len() == 1 && formats.len() > 1 {
            plan_outputs_from_base(&formats, &paths[0])
        } else {
            plan_outputs(&formats, &paths).map_err(|e| miette::miette!(e))?
        };
        publish_snapshot(&snapshot, &targets)
            .map_err(|e| miette::miette!("failed to publish report(s): {e}"))?;
    }

    if code != 0 {
        let _ = std::io::stdout().flush();
        exit(code);
    }
    Ok(())
}

fn load_all_checks() -> Result<(Config, SafetyChecker)> {
    let config = Config::load().map_err(|e| miette::miette!(e))?;
    let checker = SafetyChecker::with_config(Config {
        disable_checks: vec![],
        enable_checks: vec![],
        ..config.clone()
    })
    .map_err(|e| miette::miette!(e))?;
    Ok((config, checker))
}

fn run_list_checks(format: OutputFormat) -> Result<()> {
    let (config, checker) = load_all_checks()?;
    let checks: Vec<_> = checker.registry().iter_checks().collect();
    print!("{}", format.formatter().format_checks(&checks, &config));
    Ok(())
}

fn run_explain(check_name: &str, format: OutputFormat) -> Result<()> {
    let (config, checker) = load_all_checks()?;
    let Some(check) = checker
        .registry()
        .iter_checks()
        .find(|c| c.name() == check_name)
    else {
        eprintln!("Error: No check named '{check_name}'.");
        eprintln!("Run list-checks to see available checks.");
        exit(1);
    };
    print!("{}", format.formatter().format_explain(check, &config));
    Ok(())
}

fn main() -> Result<()> {
    human_panic::setup_panic!(human_panic::metadata!()
        .support("Please open an issue at https://github.com/ayarotsky/diesel-guard/issues. Attach the crash report file mentioned above."));
    miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(true)
                .unicode(true)
                .context_lines(3)
                .build(),
        )
    }))?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            path,
            format,
            output,
        } => {
            let path = path.unwrap_or_else(|| Utf8PathBuf::from("migrations"));
            run_check(&path, &format, &output)?;
        }

        Commands::DumpAst { sql, file } => {
            let sql_input = match (sql, file) {
                (Some(s), _) => s,
                (None, Some(path)) => fs::read_to_string(&path)
                    .into_diagnostic()
                    .map_err(|e| miette::miette!("Failed to read file '{}': {}", path, e))?,
                (None, None) => unreachable!(),
            };

            let json = ast_dump::dump_ast(&sql_input)?;
            println!("{json}");
        }

        Commands::ListChecks { format } => run_list_checks(format)?,

        Commands::Explain { check_name, format } => run_explain(&check_name, format)?,

        Commands::Init { force } => {
            let config_path = Utf8PathBuf::from("diesel-guard.toml");

            let file_existed = config_path.exists();
            if file_existed && !force {
                eprintln!("Error: diesel-guard.toml already exists in current directory");
                eprintln!("Use --force to overwrite the existing file");
                exit(1);
            }

            fs::write(&config_path, CONFIG_TEMPLATE)
                .into_diagnostic()
                .map_err(|e| miette::miette!("Failed to write config file: {}", e))?;

            if file_existed {
                println!("✓ Overwrote diesel-guard.toml");
            } else {
                println!("✓ Created diesel-guard.toml");
            }
            println!();
            println!("Next steps:");
            println!(
                "1. Edit diesel-guard.toml and set the 'framework' field to \"diesel\" or \"sqlx\""
            );
            println!("2. Customize other configuration options as needed");
            println!("3. Run 'diesel-guard check' to check your migrations");
        }
    }

    Ok(())
}
