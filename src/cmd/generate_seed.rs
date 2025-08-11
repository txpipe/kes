use kes_summed_ed25519::common::generate_crypto_secure_seed;

/// Generates 32 bytes secret seed using cryptographic secure generator
pub fn run() {
    let mut seed_bytes = [0u8; 32];
    generate_crypto_secure_seed(&mut seed_bytes);
    print!("{}", hex::encode(seed_bytes));
}
