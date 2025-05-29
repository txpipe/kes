use assert_cmd::Command;
use getrandom::fill;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

const PRG: &str = "kes-summed-ed25519";

#[test]
fn correct_output_help_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn correct_output_version_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let ver = "kes-summed-ed25519 0.1.0";
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(ver));
}

fn hex_length_check(option: &str, len: i32) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let regex = format!("^[0-9a-f]{{{}}}$", 2 * len);
    let is_len_byte_hex = predicate::str::is_match(regex).unwrap();
    cmd.arg(option).assert().success().stdout(is_len_byte_hex);
}

#[test]
fn correct_length_output_generate_seed() {
    hex_length_check("--generate_seed", 32)
}

#[test]
fn correct_length_output_generate_signing_key() {
    hex_length_check("--generate_sk", 612)
}

#[test]
fn deriving_sk_from_seed_is_deterministic() {
    let mut random_bytes = [0u8; 32];
    let _ = fill(&mut random_bytes[..]);
    let mut seed = NamedTempFile::new().unwrap();
    write!(seed, "{}", hex::encode(&random_bytes)).unwrap();
    let seed_file_name = (*seed.path()).display().to_string();

    let sk1 = Command::cargo_bin(PRG)
        .unwrap()
        .args(["--derive_sk", &seed_file_name])
        .assert()
        .get_output()
        .stdout
        .clone();
    let sk2 = Command::cargo_bin(PRG)
        .unwrap()
        .args(["--derive_sk", &seed_file_name])
        .assert()
        .get_output()
        .stdout
        .clone();
    let sk3 = Command::cargo_bin(PRG)
        .unwrap()
        .write_stdin(hex::encode(&random_bytes))
        .arg("--derive_sk")
        .assert()
        .get_output()
        .stdout
        .clone();
    // derivation is deterministic is file is used
    assert_eq!(sk1, sk2);
    // derivation is deterministic irrespective of file/stdin input
    assert_eq!(sk1, sk3);
    // output is 1224 character hex, meaning 612-byte payload
    assert_eq!(sk1.len(), 1224)
}

#[test]
fn deriving_pk_from_sk_is_deterministic() {
    let mut random_bytes = [0u8; 612];
    let _ = fill(&mut random_bytes[..]);
    let mut sk = NamedTempFile::new().unwrap();
    write!(sk, "{}", hex::encode(&random_bytes)).unwrap();
    let sk_file_name = (*sk.path()).display().to_string();

    let pk1 = Command::cargo_bin(PRG)
        .unwrap()
        .args(["--derive_pk", &sk_file_name])
        .assert()
        .get_output()
        .stdout
        .clone();
    let pk2 = Command::cargo_bin(PRG)
        .unwrap()
        .args(["--derive_pk", &sk_file_name])
        .assert()
        .get_output()
        .stdout
        .clone();
    let pk3 = Command::cargo_bin(PRG)
        .unwrap()
        .write_stdin(hex::encode(&random_bytes))
        .arg("--derive_pk")
        .assert()
        .get_output()
        .stdout
        .clone();
    // derivation is deterministic if file input is used
    assert_eq!(pk1, pk2);
    // derivation is deterministic irrespective of file/stdin input
    assert_eq!(pk1, pk3);
    // output is 64 character hex, meaning 32-byte payload
    assert_eq!(pk1.len(), 64)
}
