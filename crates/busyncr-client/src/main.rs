//! BusyNCR client: runs on the host being backed up (Windows service in
//! production; Linux for dev/test). CLI surface grows slice by slice:
//! backup | restore | list | bench-chunking | export-key | import-key | enroll

mod bench_cmd;

use clap::{Parser, Subcommand};

/// Top-level CLI.
#[derive(Parser)]
#[command(name = "busyncr-client", version, about = "BusyNCR backup client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands (grows slice by slice).
#[derive(Subcommand)]
enum Command {
    /// Offline chunk-size benchmark: measure candidate CDC target sizes over
    /// a real directory tree before committing one to config (PRD §3.7).
    #[command(name = "bench-chunking", long_about = bench_cmd::LONG_ABOUT)]
    BenchChunking(bench_cmd::BenchArgs),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::BenchChunking(args) => bench_cmd::run(&args),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
