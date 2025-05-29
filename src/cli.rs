//! CLI implementation using Sum6Kes implementation of KES

use crate::common::PublicKey;
use crate::kes::{Sum6Kes, Sum6KesSig};
use crate::traits::{KesSig, KesSk};

use clap::{App, Arg};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

type GenericError = Box<dyn Error + Send + Sync + 'static>;
type CLIResult<T> = Result<T, GenericError>;

/// CLI commands available
#[derive(Debug)]
pub enum Cmd {
    /// Generates 32 bytes secret seed
    GenerateSeed,

    /// Generates 612 bytes signing key of Sum6Kes
    GenerateSk,

    /// Derives 612 bytes signing key of Sum6Kes from 32 bytes seed
    DeriveSk,

    /// Derives 32 bytes public key from 612 bytes signing key
    DerivePk,

    /// Get period from 612 bytes signing key
    GetPeriod,

    /// Sign msg from stdin using 612 bytes signing key read from file
    SignMsg,

    /// Verify using public key (file) and proper period that the signature is indeed signed using the dual signing key
    VerifySignature {
        /// signature
        signature: Vec<u8>,
    },
}

/// Config captured that determines what is invoked in CLI
#[derive(Debug)]
pub struct Config {
    cmd: Cmd,
    file: Option<String>,
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
        Cmd::DeriveSk => {
            match config.file {
                None => {
                    eprintln!("No stdin or file was provided to read a secret seed");
                }
                Some(seed_source) => match open_any(&seed_source) {
                    Err(err) => {
                        eprintln!("Failed to open {}: {}", seed_source, err);
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
                                eprintln!("Decode error of the secret seed: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::DerivePk => {
            match config.file {
                None => {
                    eprintln!("No stdin or file was provided to read a signing key");
                }
                Some(sk_source) => match open_any(&sk_source) {
                    Err(err) => {
                        eprintln!("Failed to open {}: {}", sk_source, err);
                    }
                    Ok(sk_handle) => {
                        let mut buffer = [0; 1224];
                        let mut handle = sk_handle.take(1224);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut sk_bytes = [0u8; 612];
                                sk_bytes.copy_from_slice(&bs);
                                match Sum6Kes::from_bytes(&mut sk_bytes) {
                                    Ok(sk) => {
                                        let pk = sk.to_pk();
                                        print!("{}", hex::encode(pk.as_bytes()));
                                    }
                                    _ => {
                                        eprintln!("Signing key expects 612 bytes");
                                    }
                                };
                            }
                            Err(err) => {
                                eprintln!("Decode error of the signing key: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::GetPeriod => {
            match config.file {
                None => {
                    eprintln!("No stdin or file was provided to read a signing key");
                }
                Some(sk_source) => match open_any(&sk_source) {
                    Err(err) => {
                        eprintln!("Failed to open {}: {}", sk_source, err);
                    }
                    Ok(sk_handle) => {
                        let mut buffer = [0; 1224];
                        let mut handle = sk_handle.take(1224);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut sk_bytes = [0u8; 612];
                                sk_bytes.copy_from_slice(&bs);
                                match Sum6Kes::from_bytes(&mut sk_bytes) {
                                    Ok(sk) => {
                                        let period = sk.get_period();
                                        print!("{}", period);
                                    }
                                    _ => {
                                        eprintln!("Signing key expects 612 bytes");
                                    }
                                };
                            }
                            Err(err) => {
                                eprintln!("Decode error of the signing key: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::SignMsg => {
            match config.file {
                None => {
                    eprintln!("A secret key must be provided in a file");
                }
                Some(sk_source) => match open_both(&sk_source) {
                    Err(err) => {
                        eprintln!("{}: {}", sk_source, err);
                    }
                    Ok((mut msg_handle, sk_handle)) => {
                        let mut buffer = [0; 1224];
                        let mut handle = sk_handle.take(1224);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut sk_bytes = [0u8; 612];
                                sk_bytes.copy_from_slice(&bs);
                                match Sum6Kes::from_bytes(&mut sk_bytes) {
                                    Ok(sk) => {
                                        let msg = msg_handle.fill_buf()?;
                                        let signature = sk.sign(&msg);
                                        print!("{}", hex::encode(signature.to_bytes()));
                                    }
                                    _ => {
                                        eprintln!("Signing key expects 612 bytes");
                                    }
                                };
                            }
                            Err(err) => {
                                eprintln!("Decode error of the secret key: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::VerifySignature { signature } => {
            match config.file {
                None => {
                    eprintln!("A signature must be provided in a file");
                }
                Some(pk_source) => match open_both(&pk_source) {
                    Err(err) => {
                        eprintln!("{}: {}", pk_source, err);
                    }
                    Ok((mut msg_handle, pk_handle)) => {
                        let mut buffer = [0; 64];
                        let mut handle = pk_handle.take(64);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut pk_array = [0u8; 32];
                                pk_array.copy_from_slice(&bs);
                                let pk = PublicKey::from_bytes(&pk_array)?;
                                let msg = msg_handle.fill_buf()?;
                                let mut sig_array = [0u8; 448];
                                sig_array.copy_from_slice(&signature);
                                let sig = Sum6KesSig::from_bytes(&sig_array)?;
                                match sig.verify(0, &pk, msg) {
                                    Ok(()) => {
                                        println!("OK");
                                    }
                                    _ => {
                                        println!("Fail");
                                    }
                                }
                            }
                            Err(err) => {
                                eprintln!("Decode error of the secret key: {}", err);
                            }
                        }
                    }
                },
            };
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
                .long("generate_seed")
                .help("Generate a 32-byte secret key")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("generate_sk")
                .long("generate_sk")
                .help("Generate a 612-byte signing key")
                .conflicts_with("generate_seed")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("derive_sk")
                .long("derive_sk")
                .help("Derive a 612-byte signing key from a 32-byte secret seed (stdin/file)")
                .conflicts_with("generate_seed")
                .conflicts_with("generate_sk")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("derive_pk")
                .long("derive_pk")
                .help("Derive a 32-byte public key from a 612-byte signing key (stdin/file)")
                .conflicts_with("generate_seed")
                .conflicts_with("generate_sk")
                .conflicts_with("derive_sk")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("get_period")
                .long("get_period")
                .help("Get period from a 612-byte signing key (stdin/file)")
                .conflicts_with("generate_seed")
                .conflicts_with("generate_sk")
                .conflicts_with("derive_sk")
                .conflicts_with("derive_pk")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("sign_msg")
                .long("sign")
                .help("Sign message (stdin) using a 612-byte signing key (file)")
                .conflicts_with("generate_seed")
                .conflicts_with("generate_sk")
                .conflicts_with("derive_sk")
                .conflicts_with("derive_pk")
                .conflicts_with("get_period")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("verify_sig")
                .long("verify")
                .help("Verified 64-byte signature using a message (stdin) and public key (file) for a given period")
                .conflicts_with("generate_seed")
                .conflicts_with("generate_sk")
                .conflicts_with("derive_sk")
                .conflicts_with("derive_pk")
                .conflicts_with("get_period")
                .conflicts_with("sign_msg")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .value_name("FILE")
                .help("Input file")
                .multiple(false)
                .default_value("-"),
        )
        .get_matches();

    Ok(if matches.is_present("generate_seed") {
        Config {
            cmd: Cmd::GenerateSeed,
            file: None,
        }
    } else if matches.is_present("generate_sk") {
        Config {
            cmd: Cmd::GenerateSk,
            file: None,
        }
    } else if matches.is_present("derive_sk") {
        Config {
            cmd: Cmd::DeriveSk,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("derive_pk") {
        Config {
            cmd: Cmd::DerivePk,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("get_period") {
        Config {
            cmd: Cmd::GetPeriod,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("sign_msg") {
        Config {
            cmd: Cmd::SignMsg,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("verify_sig") {
        let signature_read = match hex::decode(
            matches
                .values_of_lossy("verify_sig")
                .map(|mut vec| vec.pop().unwrap())
                .unwrap(),
        ) {
            Ok(bs) if bs.len() == 448 => Ok(bs),
            _ => Err("not valid signature"),
        };
        Config {
            cmd: Cmd::VerifySignature {
                signature: signature_read?,
            },
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else {
        panic!("wrong cmd")
    })
}

fn open_any(filename: &str) -> CLIResult<Box<dyn BufRead>> {
    match filename {
        "-" => Ok(Box::new(BufReader::new(io::stdin()))),
        _ => Ok(Box::new(BufReader::new(File::open(filename)?))),
    }
}

fn open_both(filename: &str) -> CLIResult<(Box<dyn BufRead>, Box<dyn BufRead>)> {
    Ok((
        Box::new(BufReader::new(io::stdin())),
        Box::new(BufReader::new(File::open(filename)?)),
    ))
}
