use clap::Parser;
use kes_summed_ed25519::common::open_any;
use kes_summed_ed25519::kes::Sum6Kes;
use kes_summed_ed25519::traits::KesSk;
use std::error::Error;
use std::io::Read;

#[derive(Debug, Parser)]
pub struct Args {
    ///Seed path used for derivation of a signing key
    #[arg(short, long, value_name = "FILE")]
    file: Option<String>,
}

/// Derives 612 bytes signing key of Sum6Kes from 32 bytes seed
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.file {
        None => {
            eprintln!("No stdin or file was provided to read a secret seed");
        }
        Some(seed_source) => match open_any(&seed_source) {
            Err(err) => {
                eprintln!("Failed to open {seed_source}: {err}");
            }
            Ok(seed_handle) => {
                let mut buffer = [0; 64];
                let mut handle = seed_handle.take(64);
                handle.read_exact(&mut buffer)?;
                match hex::decode(buffer) {
                    Ok(bs) => {
                        let mut seed_bytes = [0u8; 32];
                        seed_bytes.copy_from_slice(&bs);
                        let mut key_bytes = [0u8; Sum6Kes::SIZE + 4];
                        let (sk, _pk) = Sum6Kes::keygen(&mut key_bytes, &mut seed_bytes);
                        print!("{}", hex::encode(sk.as_bytes()));
                    }
                    Err(err) => {
                        eprintln!("Decode error of the secret seed: {err}");
                    }
                }
            }
        },
    }

    Ok(())
}
