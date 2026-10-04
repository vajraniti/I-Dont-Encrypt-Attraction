//! IDEA block cipher in CBC mode, keyed from a passphrase.
//!
//! A sealed message is `salt || IV || ciphertext`: 16 random bytes of salt
//! for the key derivation, a random 8-byte IV, then the encrypted blocks.
//! The 128-bit IDEA key comes from the passphrase through
//! PBKDF2-HMAC-SHA-256, so the passphrase can be any length. The plaintext
//! must be a whole number of 8-byte blocks: there is no padding.
//!
//! CBC gives secrecy, not integrity: there is no authentication tag, so
//! opening with the wrong passphrase doesn't fail, it returns noise. Don't
//! rely on it where someone could tamper with the message.

mod cbc;
pub mod hex;
mod idea;
mod kdf;

use std::num::NonZeroU32;

use idea::{BLOCK_LEN, Block, Idea, KEY_LEN};
use kdf::{ROUNDS, SALT_LEN};

type Salt = [u8; SALT_LEN];

/// Salt and IV, in front of the ciphertext.
const HEADER_LEN: usize = SALT_LEN + BLOCK_LEN;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{len} bytes is not a whole number of {BLOCK_LEN}-byte blocks (there is no padding)")]
    Unaligned { len: usize },
    #[error("the message is {len} bytes, shorter than its {HEADER_LEN}-byte salt and IV")]
    TooShort { len: usize },
    #[error("invalid hex digit {ch:?} at character {position}")]
    InvalidHex { ch: char, position: usize },
    #[error("odd number of hex digits ({digits}): every byte takes two")]
    OddHex { digits: usize },
    #[error("the OS random number generator failed while making the salt and IV")]
    Rng(#[source] getrandom::Error),
}

/// Encrypts `plaintext` under a key derived from `passphrase` with a fresh
/// random salt, using a fresh random IV.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
    let mut salt = [0; SALT_LEN];
    let mut iv = [0; BLOCK_LEN];
    getrandom::fill(&mut salt).map_err(Error::Rng)?;
    getrandom::fill(&mut iv).map_err(Error::Rng)?;
    seal_with(passphrase, salt, iv, ROUNDS, plaintext)
}

fn seal_with(
    passphrase: &[u8],
    salt: Salt,
    iv: Block,
    rounds: NonZeroU32,
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    // Checked before the key derivation: no point spending 0.2 s on a
    // plaintext that can't be encrypted.
    let mut blocks = whole_blocks(plaintext)?.to_vec();
    cbc::encrypt(&cipher(passphrase, &salt, rounds), &iv, &mut blocks);
    Ok(Sealed { salt, iv, blocks })
}

fn cipher(passphrase: &[u8], salt: &Salt, rounds: NonZeroU32) -> Idea {
    let mut key = [0; KEY_LEN];
    kdf::pbkdf2(passphrase, salt, rounds, &mut key);
    Idea::new(&key)
}

fn whole_blocks(bytes: &[u8]) -> Result<&[Block], Error> {
    match bytes.as_chunks() {
        (blocks, []) => Ok(blocks),
        _ => Err(Error::Unaligned { len: bytes.len() }),
    }
}

/// An encrypted message, known to hold a salt, an IV and whole ciphertext
/// blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    salt: Salt,
    iv: Block,
    blocks: Vec<Block>,
}

impl Sealed {
    /// Parses `salt || IV || ciphertext` as produced by [`Sealed::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let too_short = || Error::TooShort { len: bytes.len() };
        let (salt, rest) = bytes.split_first_chunk().ok_or_else(too_short)?;
        let (iv, ciphertext) = rest.split_first_chunk().ok_or_else(too_short)?;
        // Salt and IV make three whole blocks, so the whole message is aligned
        // exactly when the ciphertext is. Report the length the caller passed.
        let blocks = whole_blocks(ciphertext)
            .map_err(|_| Error::Unaligned { len: bytes.len() })?
            .to_vec();
        Ok(Self {
            salt: *salt,
            iv: *iv,
            blocks,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + BLOCK_LEN * self.blocks.len());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.iv);
        bytes.extend_from_slice(self.blocks.as_flattened());
        bytes
    }

    /// Decrypts the message; deriving the key takes about 0.2 s. A wrong
    /// passphrase isn't an error: CBC can't tell it apart from the right
    /// one, so it returns noise.
    pub fn open(&self, passphrase: &[u8]) -> Vec<u8> {
        self.open_with(passphrase, ROUNDS)
    }

    fn open_with(&self, passphrase: &[u8], rounds: NonZeroU32) -> Vec<u8> {
        let mut blocks = self.blocks.clone();
        cbc::decrypt(
            &cipher(passphrase, &self.salt, rounds),
            &self.iv,
            &mut blocks,
        );
        blocks.into_flattened()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"Dance with me ;)";
    const TEXT: &[u8] = b"In Darkness Everything's Allowed";
    const SALT: Salt = *b"16 bytes of salt";
    const IV: Block = *b"\x00\x11\x22\x33\x44\x55\x66\x77";

    /// Few rounds, so the tests don't spend 0.2 s on every key derivation.
    fn fast() -> NonZeroU32 {
        NonZeroU32::new(1_000).expect("1000 is not zero")
    }

    #[test]
    fn the_demo_pair_round_trips_with_real_rounds() {
        assert_eq!(TEXT.len(), 4 * BLOCK_LEN);
        let sealed = seal(KEY, TEXT).expect("32 bytes are four blocks");
        let bytes = sealed.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + TEXT.len());

        let parsed = Sealed::from_bytes(&bytes).expect("own output parses");
        assert_eq!(parsed, sealed);
        assert_eq!(parsed.open(KEY), TEXT);
    }

    #[test]
    fn key_comes_from_pbkdf2_over_the_stored_salt() {
        // PBKDF2-HMAC-SHA-256("Dance with me ;)", SALT, 1000 rounds, 16 bytes),
        // computed with OpenSSL rather than with this crate.
        let key: [u8; KEY_LEN] = hex::decode("ba13e38e5528c1079d5f1d2b84e3b0f1")
            .expect("valid hex")
            .try_into()
            .expect("16 bytes");
        let bytes = seal_with(KEY, SALT, IV, fast(), TEXT)
            .expect("aligned")
            .to_bytes();
        assert_eq!(bytes[..SALT_LEN], SALT);
        assert_eq!(bytes[SALT_LEN..HEADER_LEN], IV);

        let mut blocks = whole_blocks(&bytes[HEADER_LEN..])
            .expect("aligned")
            .to_vec();
        cbc::decrypt(&Idea::new(&key), &IV, &mut blocks);
        assert_eq!(blocks.as_flattened(), TEXT);
    }

    #[test]
    fn fresh_salt_and_iv_every_time() {
        let a = seal(KEY, TEXT).expect("aligned");
        let b = seal(KEY, TEXT).expect("aligned");
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.iv, b.iv);
        assert_ne!(a.blocks, b.blocks);
    }

    #[test]
    fn salt_changes_the_key() {
        let a = seal_with(KEY, SALT, IV, fast(), TEXT).expect("aligned");
        let b = seal_with(KEY, *b"other salt bytes", IV, fast(), TEXT).expect("aligned");
        assert_ne!(a.blocks, b.blocks);
    }

    #[test]
    fn any_passphrase_length_works() {
        let long = [b'x'; 200];
        let passphrases: [&[u8]; 5] = [b"", b"k", "танцуй со мной!".as_bytes(), KEY, &long];
        for passphrase in passphrases {
            let sealed = seal_with(passphrase, SALT, IV, fast(), TEXT).expect("aligned");
            assert_eq!(sealed.open_with(passphrase, fast()), TEXT, "{passphrase:?}");
        }
    }

    #[test]
    fn wrong_passphrase_gives_noise_not_an_error() {
        let sealed = seal_with(KEY, SALT, IV, fast(), TEXT).expect("aligned");
        let noise = sealed.open_with(b"dance with me ;)", fast());
        assert_eq!(noise.len(), TEXT.len());
        assert_ne!(noise, TEXT);
    }

    #[test]
    fn empty_plaintext_is_just_salt_and_iv() {
        let sealed = seal_with(KEY, SALT, IV, fast(), b"").expect("zero blocks is a whole number");
        assert_eq!(sealed.to_bytes().len(), HEADER_LEN);
        assert_eq!(sealed.open_with(KEY, fast()), b"");
    }

    #[test]
    fn rejects_bad_lengths() {
        // The curly apostrophe is three bytes in UTF-8: 34 instead of 32.
        let curly = "In Darkness Everything’s Allowed";
        assert!(matches!(
            seal(KEY, curly.as_bytes()),
            Err(Error::Unaligned { len: 34 })
        ));
        for len in [0, 7, 16, HEADER_LEN - 1] {
            assert!(matches!(
                Sealed::from_bytes(&vec![0; len]),
                Err(Error::TooShort { len: l }) if l == len
            ));
        }
        assert!(matches!(
            Sealed::from_bytes(&[0; HEADER_LEN + 4]),
            Err(Error::Unaligned { len: 28 })
        ));
    }
}
