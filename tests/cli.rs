use assert_cmd::Command;
use predicates::prelude::*;

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
