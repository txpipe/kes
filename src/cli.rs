//! CLI implementation using Sum6Kes implementation of KES

use crate::kes::Sum6Kes;
use crate::traits::KesSk;

use clap::{App, Arg};
use std::error::Error;

type GenericError = Box<dyn Error + Send + Sync + 'static>;
type CLIResult<T> = Result<T, GenericError>;

/// CLI commands available
#[derive(Debug)]
pub enum Cmd {
    /// Generates 32 bytes secret seed
    GenerateSeed,

    /// Generates 612 bytes signing key of Sum6Kes
    GenerateSk,
}

/// Config captured that determines what is invoked in CLI
#[derive(Debug)]
pub struct Config {
    cmd: Cmd,
}

/// Determines and invokes Sum6Kes functions based on the parsed config
pub fn run(config: Config) -> CLIResult<()> {
    match config.cmd {
        Cmd::GenerateSeed => {
            let mut seed_bytes = [0u8; 32];
            getrandom::fill(&mut seed_bytes)?;
            print!("{}", hex::encode(seed_bytes));
        }

        Cmd::GenerateSk => {
            let mut key_bytes = [0u8; Sum6Kes::SIZE + 4];
            let mut seed_bytes = [0u8; 32];
            getrandom::fill(&mut seed_bytes)?;
            let (sk, _pk) = Sum6Kes::keygen(&mut key_bytes, &mut seed_bytes);
            let mut sk_bytes = [0u8; Sum6Kes::SIZE + 4];
            sk_bytes.copy_from_slice(sk.as_bytes());
            print!("{}", hex::encode(sk_bytes));
        }
    }
    Ok(())
}

/// Parses line entered by user into config
pub fn get_args() -> CLIResult<Config> {
    let matches = App::new("kes-summed-ed25519")
        .version("0.1.0")
        .author("HAL Team <hal@cardanofoundation.org>")
        .about("Rust KES")
        .arg(
            Arg::with_name("generate_seed")
                .short("s")
                .long("generate_seed")
                .help("Generate a secret key")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("generate_sk")
                .short("k")
                .long("generate_sk")
                .help("Generate a signing key")
                .takes_value(false),
        )
        .get_matches();

    Ok(if matches.is_present("generate_seed") {
        Config {
            cmd: Cmd::GenerateSeed,
        }
    } else if matches.is_present("generate_sk") {
        Config {
            cmd: Cmd::GenerateSk,
        }
    } else {
        panic!("wrong cmd")
    })
}
