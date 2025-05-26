//! CLI implementation using Sum6Kes implementation of KES

use crate::kes::Sum6Kes;
use crate::traits::KesSk;

use std::error::Error;

type GenericError = Box<dyn Error + Send + Sync + 'static>;
type CLIResult<T> = Result<T, GenericError>;

/// CLI commands available
#[derive(Debug)]
pub enum Cmd {
    /// Generates 32 bytes secret key
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
