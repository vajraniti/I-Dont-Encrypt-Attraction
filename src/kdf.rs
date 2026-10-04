//! Turns a passphrase of any length into an IDEA key with PBKDF2-HMAC-SHA-256
//! (RFC 8018, section 5.2; HMAC from RFC 2104), written out on top of the
//! `sha2` hash.
//!
//! A plain hash of the passphrase would be fast to brute-force. PBKDF2 makes
//! every guess cost `ROUNDS` HMAC calls, and the per-message salt stops one
//! precomputed "passphrase → key" table from working on every message.

use std::num::NonZeroU32;

use sha2::{Digest, Sha256};

/// OWASP's recommended work factor for PBKDF2-HMAC-SHA-256: about 0.2 s per
/// derivation on a modern CPU in a release build.
pub(crate) const ROUNDS: NonZeroU32 = NonZeroU32::new(600_000).expect("600 000 is not zero");
pub(crate) const SALT_LEN: usize = 16;

/// SHA-256 works on 64-byte blocks and outputs 32 bytes.
const HASH_BLOCK_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// HMAC-SHA-256 with the key already absorbed into both hash states, so each
/// call clones them instead of rehashing the padded key. That halves the work
/// of PBKDF2, which makes `ROUNDS` calls per output block.
struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        // Keys longer than a block are hashed first; all keys are then
        // zero-padded to a full block.
        let mut block = [0; HASH_BLOCK_LEN];
        if key.len() > HASH_BLOCK_LEN {
            block[..HASH_LEN].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let keyed = |pad: u8| Sha256::new().chain_update(block.map(|b| b ^ pad));
        Self {
            inner: keyed(0x36),
            outer: keyed(0x5C),
        }
    }

    fn mac(&self, message: &[u8]) -> [u8; HASH_LEN] {
        let inner = self.inner.clone().chain_update(message).finalize();
        self.outer.clone().chain_update(inner).finalize().into()
    }
}

/// Fills `out` with PBKDF2-HMAC-SHA-256 of `password` and `salt`.
pub(crate) fn pbkdf2(password: &[u8], salt: &[u8], rounds: NonZeroU32, out: &mut [u8]) {
    let prf = HmacSha256::new(password);
    // Output block i is T_i = U_1 ^ U_2 ^ … ^ U_rounds, where
    // U_1 = HMAC(salt || i as 32-bit big-endian) and U_j = HMAC(U_(j-1)).
    // Counting from 1u32 can't overflow: that would take 128 GiB of output.
    for (chunk, i) in out.chunks_mut(HASH_LEN).zip(1u32..) {
        let mut first = Vec::with_capacity(salt.len() + 4);
        first.extend_from_slice(salt);
        first.extend_from_slice(&i.to_be_bytes());
        let mut u = prf.mac(&first);
        let mut t = u;
        for _ in 1..rounds.get() {
            u = prf.mac(&u);
            for (t, u) in t.iter_mut().zip(&u) {
                *t ^= u;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        crate::hex::decode(s).expect("test vector is valid hex")
    }

    fn rounds(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).expect("test rounds are positive")
    }

    /// RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (case 5 checks a truncated
    /// tag). Cases 6 and 7 use a 131-byte key, longer than a SHA-256 block.
    #[test]
    fn hmac_matches_rfc_4231() {
        let long_key = [0xAA; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &[0x0B; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xAA; 20],
                &[0xDD; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25,
                ],
                &[0xCD; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &long_key,
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (i, (key, message, tag)) in cases.into_iter().enumerate() {
            assert_eq!(
                HmacSha256::new(key).mac(message)[..],
                unhex(tag),
                "case {i}"
            );
        }
    }

    /// Password, salt, rounds, output. The `passwd` row is RFC 7914 section
    /// 11 and spans two output blocks; the rest are the widely used vectors
    /// that Go's crypto/pbkdf2 tests also carry. Every row was cross-checked
    /// against OpenSSL.
    #[test]
    fn pbkdf2_matches_known_answers() {
        let cases: [(&[u8], &[u8], u32, &str); 6] = [
            (
                b"password",
                b"salt",
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c9",
            ),
            (
                b"password",
                b"salt",
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8e",
            ),
            (
                b"password",
                b"salt",
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a0",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                "89b69d0516f829893c696226650a8687",
            ),
            (
                b"passwd",
                b"salt",
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ),
        ];
        for (password, salt, n, expected) in cases {
            let expected = unhex(expected);
            let mut out = vec![0; expected.len()];
            pbkdf2(password, salt, rounds(n), &mut out);
            assert_eq!(out, expected, "{n} rounds, {} bytes", expected.len());
        }
    }

    #[test]
    fn shorter_output_is_a_prefix() {
        let mut long = [0; 40];
        let mut short = [0; 16];
        pbkdf2(
            b"Dance with me ;)",
            b"any salt at all",
            rounds(10),
            &mut long,
        );
        pbkdf2(
            b"Dance with me ;)",
            b"any salt at all",
            rounds(10),
            &mut short,
        );
        assert_eq!(short, long[..16]);
    }
}
