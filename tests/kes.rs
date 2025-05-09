#[cfg(test)]
mod test {

    use kes_summed_ed25519::common::PublicKey;
    use kes_summed_ed25519::kes::*;
    use kes_summed_ed25519::traits::KesSk;

    use proptest::prelude::*;

    fn secret_public_key_bytes() -> impl Strategy<Value = ([u8; Sum6Kes::SIZE + 4], PublicKey)> {
        proptest::string::bytes_regex("[[:ascii:]]{32}")
            .unwrap()
            .prop_map(|vec| {
                let mut key_bytes = [0u8; Sum6Kes::SIZE + 4];
                let mut seed_bytes = [0u8; 32];
                seed_bytes.copy_from_slice(&vec);
                let (sk, pk) = Sum6Kes::keygen(&mut key_bytes, &mut seed_bytes);
                let mut sk_bytes = [0u8; Sum6Kes::SIZE + 4];
                sk_bytes.copy_from_slice(sk.as_bytes());
                (sk_bytes, pk)
            })
    }

    fn payload() -> impl Strategy<Value = Vec<u8>> {
        proptest::string::bytes_regex("[[:ascii:]]{0,254}").unwrap()
    }

    proptest! {
        #[test]
        fn public_key_derivation_correct((mut sk_bytes,pk) in secret_public_key_bytes()) {
            let sk = Sum6Kes::from_bytes(&mut sk_bytes);
            prop_assert!(sk?.to_pk() == pk);
        }
    }
}
