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

#[test]
fn correct_length_hex_output_generate_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let is_32_byte_hex = predicate::str::is_match("^[0-9a-f]{64}$").unwrap();
    cmd.arg("--generate_seed")
        .assert()
        .success()
        .stdout(is_32_byte_hex);
}
