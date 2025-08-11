//use kes_summed_ed25519::cli::{get_args, run};

//fn main() {
//    if let Err(e) = get_args().and_then(run) {
//        eprintln!("{e}");
//        std::process::exit(1);
//    }
//}

//! CLI implementation using Sum6Kes implementation of KES

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generates 32 bytes secret seed
    GenerateSeed,

    /// Generates 612 bytes signing key of Sum6Kes
    GenerateSk,

    /// Derives 612 bytes signing key of Sum6Kes from 32 bytes seed
    DeriveSk(cmd::derive_sk::Args),

    /// Derives 32 bytes public key from 612 bytes signing key
    DerivePk(cmd::derive_pk::Args),

    /// Get period from 612 bytes signing key
    Period(cmd::period::Args),
}

#[derive(Debug, Parser)]
#[clap(name = "Cardano compliant Sum6 KES")]
#[clap(bin_name = "kes")]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let result = match args.command {
        Command::GenerateSeed => cmd::generate_seed::run(),
        Command::GenerateSk => cmd::generate_sk::run(),
        Command::DeriveSk(args) => cmd::derive_sk::run(args),
        Command::DerivePk(args) => cmd::derive_pk::run(args),
        Command::Period(args) => cmd::period::run(args),
    };
    result
}
