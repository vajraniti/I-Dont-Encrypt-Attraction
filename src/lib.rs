//! IDEA block cipher in CBC mode, without padding.
//!
//! A sealed message is `IV || ciphertext`: a fresh random 8-byte IV followed
//! by the encrypted blocks. The plaintext must be a whole number of 8-byte
//! blocks.
//!
//! CBC gives secrecy, not integrity: there is no authentication tag, so
//! opening with the wrong key doesn't fail, it returns noise. Don't rely on
//! it where someone could tamper with the message.

mod cbc;
pub mod hex;
mod idea;

pub use idea::KEY_LEN;

use idea::{BLOCK_LEN, Block, Idea};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{len} bytes is not a whole number of {BLOCK_LEN}-byte blocks (there is no padding)")]
    Unaligned { len: usize },
    #[error("the message is {len} bytes, shorter than its {BLOCK_LEN}-byte IV")]
    TooShort { len: usize },
    #[error("invalid hex digit {ch:?} at character {position}")]
    InvalidHex { ch: char, position: usize },
    #[error("odd number of hex digits ({digits}): every byte takes two")]
    OddHex { digits: usize },
    #[error("the OS random number generator failed while making the IV")]
    Rng(#[source] getrandom::Error),
}

/// Encrypts `plaintext` under a fresh random IV.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Sealed, Error> {
    let mut iv = [0; BLOCK_LEN];
    getrandom::fill(&mut iv).map_err(Error::Rng)?;
    seal_with_iv(key, iv, plaintext)
}

fn seal_with_iv(key: &[u8; KEY_LEN], iv: Block, plaintext: &[u8]) -> Result<Sealed, Error> {
    let mut blocks = whole_blocks(plaintext)?.to_vec();
    cbc::encrypt(&Idea::new(key), &iv, &mut blocks);
    Ok(Sealed { iv, blocks })
}

fn whole_blocks(bytes: &[u8]) -> Result<&[Block], Error> {
    match bytes.as_chunks() {
        (blocks, []) => Ok(blocks),
        _ => Err(Error::Unaligned { len: bytes.len() }),
    }
}

/// An encrypted message, known to hold an IV and whole ciphertext blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    iv: Block,
    blocks: Vec<Block>,
}

impl Sealed {
    /// Parses `IV || ciphertext` as produced by [`Sealed::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (iv, ciphertext) = bytes
            .split_first_chunk()
            .ok_or(Error::TooShort { len: bytes.len() })?;
        // The IV is one block, so the whole message is aligned exactly when the
        // ciphertext is. Report the length the caller actually passed.
        let blocks = whole_blocks(ciphertext)
            .map_err(|_| Error::Unaligned { len: bytes.len() })?
            .to_vec();
        Ok(Self { iv: *iv, blocks })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BLOCK_LEN * (1 + self.blocks.len()));
        bytes.extend_from_slice(&self.iv);
        bytes.extend_from_slice(self.blocks.as_flattened());
        bytes
    }

    /// Decrypts the message. A wrong key isn't an error: CBC can't tell it
    /// apart from the right one, so it returns noise.
    pub fn open(&self, key: &[u8; KEY_LEN]) -> Vec<u8> {
        let mut blocks = self.blocks.clone();
        cbc::decrypt(&Idea::new(key), &self.iv, &mut blocks);
        blocks.into_flattened()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; KEY_LEN] = b"Dance with me ;)";
    const TEXT: &[u8] = b"In Darkness Everything's Allowed";

    #[test]
    fn the_demo_pair_fits_without_padding() {
        assert_eq!(TEXT.len(), 4 * BLOCK_LEN);
        let sealed = seal(KEY, TEXT).expect("32 bytes are four blocks");
        let bytes = sealed.to_bytes();
        assert_eq!(bytes.len(), BLOCK_LEN + TEXT.len());
        assert_ne!(&bytes[BLOCK_LEN..], TEXT);

        let parsed = Sealed::from_bytes(&bytes).expect("own output parses");
        assert_eq!(parsed, sealed);
        assert_eq!(parsed.open(KEY), TEXT);
    }

    #[test]
    fn fresh_iv_every_time() {
        let a = seal(KEY, TEXT).expect("aligned");
        let b = seal(KEY, TEXT).expect("aligned");
        assert_ne!(a, b, "same text and key must not give the same message");
        assert_eq!(a.open(KEY), b.open(KEY));
    }

    #[test]
    fn iv_leads_the_message() {
        let iv = *b"\x00\x11\x22\x33\x44\x55\x66\x77";
        let sealed = seal_with_iv(KEY, iv, TEXT).expect("aligned");
        assert_eq!(sealed, seal_with_iv(KEY, iv, TEXT).expect("aligned"));
        assert_eq!(sealed.to_bytes()[..BLOCK_LEN], iv);
    }

    #[test]
    fn wrong_key_gives_noise_not_an_error() {
        let sealed = seal(KEY, TEXT).expect("aligned");
        let noise = sealed.open(b"dance with me ;)");
        assert_eq!(noise.len(), TEXT.len());
        assert_ne!(noise, TEXT);
    }

    #[test]
    fn empty_plaintext_is_just_an_iv() {
        let sealed = seal(KEY, b"").expect("zero blocks is a whole number");
        assert_eq!(sealed.to_bytes().len(), BLOCK_LEN);
        assert_eq!(sealed.open(KEY), b"");
    }

    #[test]
    fn rejects_partial_blocks() {
        // The curly apostrophe is three bytes in UTF-8: 34 instead of 32.
        let curly = "In Darkness Everything’s Allowed";
        assert!(matches!(
            seal(KEY, curly.as_bytes()),
            Err(Error::Unaligned { len: 34 })
        ));
        assert!(matches!(
            Sealed::from_bytes(&[0; 7]),
            Err(Error::TooShort { len: 7 })
        ));
        assert!(matches!(
            Sealed::from_bytes(&[0; 12]),
            Err(Error::Unaligned { len: 12 })
        ));
    }
}
