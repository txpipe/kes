//! Structures common to all constructions of key evolving signatures
use crate::errors::Error;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_dalek as ed25519;
#[cfg(feature = "serde_enabled")]
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

/// ED25519 secret key size
pub const INDIVIDUAL_SECRET_SIZE: usize = 32;
/// ED25519 signature size
pub const SIGMA_SIZE: usize = 64;

/// KES public key size (which equals the size of the output of the Hash).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Seed of a KES scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed;

/// KES public key, which is represented as an array of bytes. A `PublicKey`is the output
/// of a Blake2b hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
pub struct PublicKey(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))] pub(crate) [u8; PUBLIC_KEY_SIZE],
);

impl PublicKey {
    pub(crate) fn from_ed25519_verifyingkey(public: &ed25519::VerifyingKey) -> Self {
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out.copy_from_slice(public.as_bytes());
        PublicKey(out)
    }

    pub(crate) fn as_ed25519(&self) -> Result<ed25519::VerifyingKey, Error> {
        ed25519::VerifyingKey::from_bytes(
            self.as_bytes()
                .try_into()
                .expect("Won't fail as slice has size 32."),
        )
        .or(Err(Error::Ed25519InvalidCompressedFormat))
    }

    /// Return `Self` as its byte representation.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Tries to convert a slice of `bytes` as `Self`.
    ///
    /// # Errors
    /// This function returns an error if the length of `bytes` is not equal to
    /// `PUBLIC_KEY_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == PUBLIC_KEY_SIZE {
            let mut v = [0u8; PUBLIC_KEY_SIZE];
            v.copy_from_slice(bytes);
            Ok(PublicKey(v))
        } else {
            Err(Error::InvalidPublicKeySize(bytes.len()))
        }
    }

    /// Hash two public keys using Blake2b
    pub(crate) fn hash_pair(&self, other: &PublicKey) -> PublicKey {
        let mut out = [0u8; 32];
        let mut h = Blake2bVar::new(32).expect("valid size");
        h.update(&self.0);
        h.update(&other.0);

        h.finalize_variable(&mut out).expect("valid size");
        PublicKey(out)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Seed {
    /// Byte representation size of a `Seed`.
    pub const SIZE: usize = 32;

    /// Function that takes as input a mutable slice, splits it into two, and overwrites the input
    /// slice with zeros.
    pub fn split_slice(bytes: &mut [u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(bytes.len(), Self::SIZE, "Size of the seed is incorrect.");
        let mut left_seed = [0u8; Self::SIZE];
        let mut right_seed = [0u8; Self::SIZE];

        let mut hasher = Blake2bVar::new(32).expect("valid size");
        hasher.update(&[1]);
        hasher.update(bytes);
        hasher
            .finalize_variable(&mut left_seed)
            .expect("valid size");
        let mut hasher = Blake2bVar::new(32).expect("valid size");
        hasher.update(&[2]);
        hasher.update(bytes);
        hasher
            .finalize_variable(&mut right_seed)
            .expect("valid size");

        bytes.copy_from_slice(&[0u8; Self::SIZE]);

        (left_seed, right_seed)
    }
}

/// Structure that represents the depth of the binary tree.
#[derive(Debug, Copy, Clone)]
pub struct Depth(pub u32);

impl Depth {
    /// Compute the total number of signatures one can generate with the given `Depth`
    pub fn total(self) -> u32 {
        u32::pow(2, self.0)
    }

    /// Compute half of the total number of signatures one can generate with the given `Depth`
    pub fn half(self) -> u32 {
        assert!(self.0 > 0);
        u32::pow(2, self.0 - 1)
    }

    /// Returns a new `Depth` value with one less depth as `self`.
    pub fn decr(self) -> Self {
        assert!(self.0 > 0);
        Depth(self.0 - 1)
    }

    /// Returns a new `Depth` value with one more depth as `self`.
    pub fn incr(self) -> Self {
        Depth(self.0 + 1)
    }
}

impl PartialEq for Depth {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for Depth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
