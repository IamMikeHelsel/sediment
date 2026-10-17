#[cfg(feature = "gui")]
mod gui;

#[cfg(not(feature = "gui"))]
use clap::CommandFactory;
use clap::{Parser, Subcommand, ValueEnum};
use sediment::archive::{self, OperationControl};
use serde_json::json;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

/// A local archive utility. ZIP creation; ZIP, TAR and TAR.GZ extraction.
#[derive(Parser)]
#[command(
    version,
    subcommand_precedence_over_arg = true,
    after_help = "Examples:
  sediment x photos.zip
  sediment c backup.zip Documents/
  sediment shell-init --alias sed

Extraction defaults to a new folder beside the archive. Existing paths are never replaced."
)]
struct Cli {
    /// Emit machine-readable results (errors go to stderr).
    #[arg(long, global = true)]
    json: bool,
    /// Emit structured operation diagnostics to stderr; excludes file paths.
    #[arg(long, global = true)]
    trace: bool,
    /// Open an archive in the desktop application.
    archive: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List archive entries without extracting them.
    #[command(visible_alias = "l")]
    List { archive: PathBuf },
    /// Verify archive data and checksums where the format provides them.
    #[command(visible_alias = "t")]
    Test { archive: PathBuf },
    /// Extract into a NEW directory; existing destinations are never replaced.
    #[command(visible_alias = "x")]
    Extract {
        archive: PathBuf,
        /// New folder (default: archive name without its suffix, beside the archive).
        destination: Option<PathBuf>,
    },
    /// Create a ZIP at a NEW path from files and folders.
    #[command(visible_alias = "c")]
    Create {
        output: PathBuf,
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
    },
    /// Print an opt-in Bash/Zsh shortcut; eval the output to enable it.
    ShellInit {
        /// sed shadows the system text utility; use `command sed` to reach it.
        #[arg(long, value_enum, default_value = "sdm")]
        alias: Shortcut,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Shortcut {
    Sdm,
    Sed,
}

fn default_destination(path: &Path) -> anyhow::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("Specify a destination for this archive name"))?;
    let lower = name.to_ascii_lowercase();
    let suffix = [".tar.gz", ".tgz", ".zip", ".tar"]
        .into_iter()
        .find(|suffix| lower.ends_with(suffix))
        .ok_or_else(|| {
            anyhow::anyhow!("Specify a destination for an archive without a recognized suffix")
        })?;
    let stem = &name[..name.len() - suffix.len()];
    anyhow::ensure!(
        !stem.is_empty() && stem != "." && stem != "..",
        "Specify a destination for this archive name"
    );
    Ok(path.with_file_name(stem))
}

fn diagnostics(enabled: bool) {
    if enabled {
        // Restrict diagnostics to our own metadata events: dependencies may log private paths.
        use tracing_subscriber::prelude::*;
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .json()
            .with_writer(io::stderr)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("sediment", tracing::Level::DEBUG),
            );
        let _ = tracing_subscriber::registry().with(layer).try_init();
    }
}

fn execute(cli: &Cli, control: &OperationControl) -> anyhow::Result<()> {
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let result = match cli.command.as_ref().expect("command was checked") {
        Command::List { archive: path } => {
            let info = archive::inspect_with_control(path, control)?;
            if cli.json {
                json!({"operation":"list", "format":info.format, "total_size":info.total_size,
                    "compressed_size":info.compressed_size, "entries":info.entries.iter().map(|e|
                        json!({"name":e.name,"size":e.size,"compressed_size":e.compressed_size,"is_dir":e.is_dir})).collect::<Vec<_>>()})
            } else {
                writeln!(
                    stdout,
                    "{} · {} entries · {} bytes",
                    info.format,
                    info.entries.len(),
                    info.total_size
                )?;
                for entry in info.entries {
                    // Escape control characters so malicious archive names cannot control the terminal.
                    let name = entry.name.escape_debug();
                    writeln!(
                        stdout,
                        "{:>12}  {}{}",
                        entry.size,
                        name,
                        if entry.is_dir && !entry.name.ends_with('/') {
                            "/"
                        } else {
                            ""
                        }
                    )?;
                }
                stdout.flush()?;
                return Ok(());
            }
        }
        Command::Test { archive: path } => {
            let count = archive::verify_with_control(path, control)?;
            if !cli.json {
                writeln!(stdout, "Verified {count} files")?;
            }
            json!({"operation":"test", "files":count})
        }
        Command::Extract {
            archive: path,
            destination,
        } => {
            let destination = match destination {
                Some(destination) => destination.clone(),
                None => default_destination(path)?,
            };
            let count = archive::extract_with_control(path, &destination, control)?;
            if !cli.json {
                writeln!(
                    stdout,
                    "Extracted {count} files to {}",
                    destination.display().to_string().escape_debug()
                )?;
            }
            json!({"operation":"extract", "files":count, "destination":destination})
        }
        Command::Create { output, inputs } => {
            let count = archive::create_zip_with_control(inputs, output, control)?;
            if !cli.json {
                writeln!(
                    stdout,
                    "Archived {count} files to {}",
                    output.display().to_string().escape_debug()
                )?;
            }
            json!({"operation":"create", "files":count, "output":output})
        }
        Command::ShellInit { alias } => {
            let name = match alias {
                Shortcut::Sdm => "sdm",
                Shortcut::Sed => "sed",
            };
            let executable = std::env::current_exe()?;
            let executable = executable.to_str().ok_or_else(|| {
                anyhow::anyhow!("Shell shortcut requires a Unicode executable path")
            })?;
            let quoted = executable.replace('\'', "'\"'\"'");
            let script = format!("{name}() {{ command '{quoted}' \"$@\"; }}");
            if !cli.json {
                writeln!(stdout, "{script}")?;
            }
            json!({"operation":"shell-init", "script":script})
        }
    };
    if cli.json {
        serde_json::to_writer(&mut stdout, &result)?;
        writeln!(stdout)?;
    }
    stdout.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    diagnostics(cli.trace || std::env::var_os("SEDIMENT_TRACE").is_some_and(|v| v == "1"));
    if cli.command.is_none() {
        if cli.json {
            eprintln!(
                "{{\"error\":\"--json requires an archive subcommand\",\"cancelled\":false}}"
            );
            return ExitCode::from(2);
        }
        #[cfg(feature = "gui")]
        {
            return match gui::run(cli.archive) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("Cannot start desktop interface: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(feature = "gui"))]
        {
            let _ = Cli::command().print_help();
            eprintln!("\nThis build has no GUI. Use list, test, extract or create.");
            return ExitCode::from(2);
        }
    }
    if cli.archive.is_some() {
        eprintln!("An archive positional argument cannot precede a subcommand.");
        return ExitCode::from(2);
    }
    let control = OperationControl::default();
    let signal_control = control.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_control.cancel()) {
        eprintln!("Cannot initialize interruption handler: {error}");
        return ExitCode::FAILURE;
    }
    let operation = match cli.command {
        Some(Command::List { .. }) => "list",
        Some(Command::Test { .. }) => "test",
        Some(Command::Extract { .. }) => "extract",
        Some(Command::Create { .. }) => "create",
        Some(Command::ShellInit { .. }) => "shell-init",
        None => unreachable!(),
    };
    let span = tracing::info_span!("archive_operation", operation);
    let _entered = span.enter();
    let started = Instant::now();
    tracing::info!(event = "started");
    match execute(&cli, &control) {
        Ok(()) => {
            tracing::info!(
                event = "completed",
                elapsed_ms = started.elapsed().as_millis() as u64
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            let cancelled = error.downcast_ref::<archive::Cancelled>().is_some();
            tracing::info!(
                event = "finished",
                outcome = if cancelled { "cancelled" } else { "failed" },
                elapsed_ms = started.elapsed().as_millis() as u64
            );
            if cli.json {
                eprintln!(
                    "{}",
                    json!({"error":format!("{error:#}"),"cancelled":cancelled})
                );
            } else {
                eprintln!("{}", format!("{error:#}").escape_debug());
            }
            ExitCode::from(if cancelled { 130 } else { 1 })
        }
    }
}
