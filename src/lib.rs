//! IDEA block cipher in CBC mode, keyed from a passphrase.
//!
//! A sealed message is `salt || IV || ciphertext`: 16 random bytes of salt
//! for the key derivation, a random 8-byte IV, then the encrypted blocks.
//! The 128-bit IDEA key comes from the passphrase through
//! PBKDF2-HMAC-SHA-256, so the passphrase can be any length. The plaintext
//! can be any length too: PKCS#7 padding tops it up to whole blocks.
//!
//! CBC gives secrecy, not integrity: there is no authentication tag. A wrong
//! passphrase is caught only because the padding stops checking out, and
//! anyone who can feed altered messages to a decryptor and see whether the
//! padding failed can recover the plaintext (a padding oracle). Don't rely on
//! it where someone could tamper with messages.

mod cbc;
pub mod hex;
mod idea;
mod kdf;
mod pkcs7;

use std::num::NonZeroU32;

use idea::{BLOCK_LEN, Block, Idea, KEY_LEN};
use kdf::{ROUNDS, SALT_LEN};

type Salt = [u8; SALT_LEN];

/// Salt and IV, in front of the ciphertext.
const HEADER_LEN: usize = SALT_LEN + BLOCK_LEN;
/// Padding always adds bytes, so there is at least one ciphertext block.
const MIN_LEN: usize = HEADER_LEN + BLOCK_LEN;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the message is {len} bytes, not a whole number of {BLOCK_LEN}-byte blocks")]
    Unaligned { len: usize },
    #[error("the message is {len} bytes, shorter than the {MIN_LEN} of salt, IV and one block")]
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
    Ok(seal_with(passphrase, salt, iv, ROUNDS, plaintext))
}

fn seal_with(
    passphrase: &[u8],
    salt: Salt,
    iv: Block,
    rounds: NonZeroU32,
    plaintext: &[u8],
) -> Sealed {
    let mut blocks = pkcs7::pad(plaintext);
    cbc::encrypt(&cipher(passphrase, &salt, rounds), &iv, &mut blocks);
    Sealed { salt, iv, blocks }
}

fn cipher(passphrase: &[u8], salt: &Salt, rounds: NonZeroU32) -> Idea {
    let mut key = [0; KEY_LEN];
    kdf::pbkdf2(passphrase, salt, rounds, &mut key);
    Idea::new(&key)
}

/// [`Sealed::open`] found no valid padding at the end: the passphrase is
/// wrong, or the message was damaged.
#[derive(Debug, thiserror::Error)]
#[error("wrong passphrase or damaged message: the padding doesn't check out")]
pub struct BadPadding {
    /// The decrypted blocks as they came out: noise, for a wrong passphrase.
    pub noise: Vec<u8>,
}

/// An encrypted message, known to hold a salt, an IV and at least one whole
/// ciphertext block.
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
        if bytes.len() < MIN_LEN {
            return Err(too_short());
        }
        let (salt, rest) = bytes.split_first_chunk().ok_or_else(too_short)?;
        let (iv, ciphertext) = rest.split_first_chunk().ok_or_else(too_short)?;
        // Salt and IV make three whole blocks, so the whole message is aligned
        // exactly when the ciphertext is. Report the length the caller passed.
        let (blocks, []) = ciphertext.as_chunks() else {
            return Err(Error::Unaligned { len: bytes.len() });
        };
        Ok(Self {
            salt: *salt,
            iv: *iv,
            blocks: blocks.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + BLOCK_LEN * self.blocks.len());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.iv);
        bytes.extend_from_slice(self.blocks.as_flattened());
        bytes
    }

    /// Decrypts the message; deriving the key takes about 0.1 s. A wrong
    /// passphrase breaks the padding all but about once in 256 tries; the
    /// rest of the time it comes back as noise that only looks unpadded.
    pub fn open(&self, passphrase: &[u8]) -> Result<Vec<u8>, BadPadding> {
        self.open_with(passphrase, ROUNDS)
    }

    fn open_with(&self, passphrase: &[u8], rounds: NonZeroU32) -> Result<Vec<u8>, BadPadding> {
        let mut blocks = self.blocks.clone();
        cbc::decrypt(
            &cipher(passphrase, &self.salt, rounds),
            &self.iv,
            &mut blocks,
        );
        let mut plaintext = blocks.into_flattened();
        match pkcs7::unpad(&plaintext) {
            Some(body) => {
                plaintext.truncate(body.len());
                Ok(plaintext)
            }
            None => Err(BadPadding { noise: plaintext }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"Dance with me ;)";
    const TEXT: &[u8] = b"In Darkness Everything's Allowed";
    const SALT: Salt = *b"16 bytes of salt";
    const IV: Block = *b"\x00\x11\x22\x33\x44\x55\x66\x77";

    /// Few rounds, so the tests don't run 600 000 for every key derivation.
    fn fast() -> NonZeroU32 {
        NonZeroU32::new(1_000).expect("1000 is not zero")
    }

    #[test]
    fn the_demo_pair_round_trips_with_real_rounds() {
        let sealed = seal(KEY, TEXT).expect("the OS has randomness");
        let bytes = sealed.to_bytes();
        // 32 bytes already fill four blocks, so padding adds a fifth.
        assert_eq!(bytes.len(), HEADER_LEN + TEXT.len() + BLOCK_LEN);

        let parsed = Sealed::from_bytes(&bytes).expect("own output parses");
        assert_eq!(parsed, sealed);
        assert_eq!(parsed.open(KEY).expect("right passphrase"), TEXT);
    }

    #[test]
    fn key_comes_from_pbkdf2_over_the_stored_salt() {
        // PBKDF2-HMAC-SHA-256("Dance with me ;)", SALT, 1000 rounds, 16 bytes),
        // computed with OpenSSL rather than with this crate.
        let key: [u8; KEY_LEN] = hex::decode("ba13e38e5528c1079d5f1d2b84e3b0f1")
            .expect("valid hex")
            .try_into()
            .expect("16 bytes");
        let bytes = seal_with(KEY, SALT, IV, fast(), TEXT).to_bytes();
        assert_eq!(bytes[..SALT_LEN], SALT);
        assert_eq!(bytes[SALT_LEN..HEADER_LEN], IV);

        let (blocks, []) = bytes[HEADER_LEN..].as_chunks() else {
            panic!("ciphertext is whole blocks");
        };
        let mut blocks = blocks.to_vec();
        cbc::decrypt(&Idea::new(&key), &IV, &mut blocks);
        let (body, padding) = blocks.as_flattened().split_at(TEXT.len());
        assert_eq!(body, TEXT);
        assert_eq!(padding, [8; 8]);
    }

    #[test]
    fn fresh_salt_and_iv_every_time() {
        let a = seal(KEY, TEXT).expect("the OS has randomness");
        let b = seal(KEY, TEXT).expect("the OS has randomness");
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.iv, b.iv);
        assert_ne!(a.blocks, b.blocks);
    }

    #[test]
    fn salt_changes_the_key() {
        let a = seal_with(KEY, SALT, IV, fast(), TEXT);
        let b = seal_with(KEY, *b"other salt bytes", IV, fast(), TEXT);
        assert_ne!(a.blocks, b.blocks);
    }

    #[test]
    fn any_text_length_works() {
        let mut texts: Vec<Vec<u8>> = (0..=17).map(|len| TEXT[..len].to_vec()).collect();
        texts.push("In Darkness Everything’s Allowed".into());
        texts.push("в темноте можно всё".into());
        for text in texts {
            let sealed = seal_with(KEY, SALT, IV, fast(), &text);
            assert_eq!(sealed.blocks.len(), text.len() / BLOCK_LEN + 1, "{text:?}");
            assert_eq!(
                sealed.open_with(KEY, fast()).expect("right passphrase"),
                text
            );
        }
    }

    #[test]
    fn any_passphrase_length_works() {
        let long = [b'x'; 200];
        let passphrases: [&[u8]; 5] = [b"", b"k", "танцуй со мной!".as_bytes(), KEY, &long];
        for passphrase in passphrases {
            let sealed = seal_with(passphrase, SALT, IV, fast(), TEXT);
            assert_eq!(
                sealed
                    .open_with(passphrase, fast())
                    .expect("right passphrase"),
                TEXT,
                "{passphrase:?}"
            );
        }
    }

    #[test]
    fn wrong_passphrase_breaks_the_padding() {
        let sealed = seal_with(KEY, SALT, IV, fast(), TEXT);
        let err = sealed
            .open_with(b"dance with me ;)", fast())
            .expect_err("wrong passphrase");
        assert_eq!(err.noise.len(), TEXT.len() + BLOCK_LEN);
        assert_ne!(err.noise[..TEXT.len()], *TEXT);
    }

    #[test]
    fn rejects_bad_lengths() {
        for len in [0, 7, HEADER_LEN, MIN_LEN - 1] {
            assert!(matches!(
                Sealed::from_bytes(&vec![0; len]),
                Err(Error::TooShort { len: l }) if l == len
            ));
        }
        assert!(matches!(
            Sealed::from_bytes(&[0; MIN_LEN + 4]),
            Err(Error::Unaligned { len: 36 })
        ));
    }
}
