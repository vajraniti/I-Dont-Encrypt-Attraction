//! IDEA block cipher (Lai & Massey, 1991): 64-bit blocks, 128-bit key, 8.5 rounds.
//!
//! Every round mixes three algebraic groups on 16-bit words — XOR, addition
//! modulo 2^16 and multiplication modulo 2^16 + 1. No two of them distribute
//! over each other, which is where the cipher gets its confusion from.

pub(crate) const BLOCK_LEN: usize = 8;
pub const KEY_LEN: usize = 16;

pub(crate) type Block = [u8; BLOCK_LEN];

const ROUNDS: usize = 8;
/// Six subkeys per round plus four for the output transformation.
const SUBKEYS: usize = 6 * ROUNDS + 4;

type Schedule = [u16; SUBKEYS];

/// An expanded key, ready to encrypt and decrypt single blocks.
///
/// Deliberately not `Debug`: the schedule is the key in disguise.
pub(crate) struct Idea {
    encrypt: Schedule,
    decrypt: Schedule,
}

impl Idea {
    pub(crate) fn new(key: &[u8; KEY_LEN]) -> Self {
        let encrypt = expand_key(key);
        let decrypt = invert_schedule(&encrypt);
        Self { encrypt, decrypt }
    }

    pub(crate) fn encrypt_block(&self, block: &Block) -> Block {
        crypt(block, &self.encrypt)
    }

    pub(crate) fn decrypt_block(&self, block: &Block) -> Block {
        crypt(block, &self.decrypt)
    }
}

/// Multiplication modulo 2^16 + 1, where the word 0 stands for 2^16.
///
/// Low-high trick: with p = a·b = hi·2^16 + lo and 2^16 ≡ −1 (mod 2^16 + 1),
/// p ≡ lo − hi. There are no branches on the operands, so timing doesn't
/// depend on key or data.
fn mul(a: u16, b: u16) -> u16 {
    let widen = |x: u16| u64::from(x) | (u64::from(x == 0) << 16);
    let p = widen(a) * widen(b);
    let lo = p & 0xFFFF;
    let hi = p >> 16;
    // lo − hi lies in (−2^16, 2^16). When negative, adding the modulus 2^16 + 1
    // is the same as adding 1 once we truncate to 16 bits, and the truncation
    // also turns a result of 2^16 back into its encoding 0. The result is never
    // 0 mod 2^16 + 1: the modulus is prime and both factors are non-zero.
    lo.wrapping_sub(hi).wrapping_add(u64::from(lo < hi)) as u16
}

/// Multiplicative inverse modulo the prime 2^16 + 1, via Fermat's little
/// theorem: x^-1 = x^(2^16 − 1). The exponent is fixed, so this is
/// constant-time too. 0 (that is, 2^16 ≡ −1) comes out as its own inverse.
fn mul_inv(x: u16) -> u16 {
    // Each step maps the exponent e to 2e + 1: 1 → 3 → 7 → … → 2^16 − 1.
    let mut r = x;
    for _ in 1..16 {
        r = mul(mul(r, r), x);
    }
    r
}

/// Encryption subkeys: 16-bit slices of the key, which is rotated left by
/// 25 bits after every eight of them.
fn expand_key(key: &[u8; KEY_LEN]) -> Schedule {
    let mut k = u128::from_be_bytes(*key);
    let mut schedule = [0; SUBKEYS];
    for (i, group) in schedule.chunks_mut(8).enumerate() {
        if i > 0 {
            k = k.rotate_left(25);
        }
        for (j, subkey) in group.iter_mut().enumerate() {
            *subkey = (k >> (112 - 16 * j)) as u16;
        }
    }
    schedule
}

/// Decryption subkeys. Decryption runs the same rounds as encryption, with
/// the encryption rounds undone in reverse order.
fn invert_schedule(enc: &Schedule) -> Schedule {
    let mut dec = [0; SUBKEYS];
    for r in 0..=ROUNDS {
        // The encryption round this decryption round undoes; round 8 is the
        // output transformation.
        let undone = ROUNDS - r;
        let mix = &enc[6 * undone..6 * undone + 4];
        // Inner rounds see the middle words swapped, so the additive keys trade
        // places. The output transformation undoes the swap itself, so the two
        // outermost rounds keep them in order.
        let (add1, add2) = if r == 0 || r == ROUNDS {
            (mix[1], mix[2])
        } else {
            (mix[2], mix[1])
        };
        let d = &mut dec[6 * r..];
        d[0] = mul_inv(mix[0]);
        d[1] = add1.wrapping_neg();
        d[2] = add2.wrapping_neg();
        d[3] = mul_inv(mix[3]);
        if r < ROUNDS {
            // The multiply-add half of a round is its own inverse under the same
            // keys, so the previous encryption round's keys are reused as is.
            d[4] = enc[6 * undone - 2];
            d[5] = enc[6 * undone - 1];
        }
    }
    dec
}

/// Eight rounds and the output transformation; the schedule picks the direction.
fn crypt(block: &Block, schedule: &Schedule) -> Block {
    let word = |i: usize| u16::from_be_bytes([block[2 * i], block[2 * i + 1]]);
    let (mut x1, mut x2, mut x3, mut x4) = (word(0), word(1), word(2), word(3));

    for k in schedule[..6 * ROUNDS].chunks_exact(6) {
        // Key mixing.
        let y1 = mul(x1, k[0]);
        let y2 = x2.wrapping_add(k[1]);
        let y3 = x3.wrapping_add(k[2]);
        let y4 = mul(x4, k[3]);
        // Multiply-add structure: every output bit depends on every input bit.
        let t1 = mul(y1 ^ y3, k[4]);
        let t2 = mul((y2 ^ y4).wrapping_add(t1), k[5]);
        let t3 = t1.wrapping_add(t2);
        // Middle words come out swapped.
        x1 = y1 ^ t2;
        x2 = y3 ^ t2;
        x3 = y2 ^ t3;
        x4 = y4 ^ t3;
    }

    // Output transformation; it also cancels the last round's swap.
    let k = &schedule[6 * ROUNDS..];
    let words = [
        mul(x1, k[0]),
        x3.wrapping_add(k[1]),
        x2.wrapping_add(k[2]),
        mul(x4, k[3]),
    ];
    let mut out = [0; BLOCK_LEN];
    for (bytes, w) in out.chunks_exact_mut(2).zip(words) {
        bytes.copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = crate::hex::decode(s).expect("test vector is valid hex");
        bytes.try_into().expect("test vector has the right length")
    }

    /// Key, plaintext, ciphertext. The first row is the example from Lai's
    /// original IDEA paper; all of them are Crypto++'s TestData/ideaval.dat
    /// and also appear in Botan's IDEA test vectors.
    #[rustfmt::skip]
    const VECTORS: [(&str, &str, &str); 11] = [
        ("00010002000300040005000600070008", "0000000100020003", "11FBED2B01986DE5"),
        ("00010002000300040005000600070008", "0102030405060708", "540E5FEA18C2F8B1"),
        ("00010002000300040005000600070008", "0019324B647D96AF", "9F0A0AB6E10CED78"),
        ("00010002000300040005000600070008", "F5202D5B9C671B08", "CF18FD7355E2C5C5"),
        ("00010002000300040005000600070008", "FAE6D2BEAA96826E", "85DF52005608193D"),
        ("00010002000300040005000600070008", "0A141E28323C4650", "2F7DE750212FB734"),
        ("00010002000300040005000600070008", "050A0F14191E2328", "7B7314925DE59C09"),
        ("0005000A000F00140019001E00230028", "0102030405060708", "3EC04780BEFF6E20"),
        ("3A984E2000195DB32EE501C8C47CEA60", "0102030405060708", "97BCD8200780DA86"),
        ("006400C8012C019001F4025802BC0320", "05320A6414C819FA", "65BE87E7A2538AED"),
        ("9D4075C103BC322AFB03E7BE6AB30006", "0808080808080808", "F5DB1AC45E5EF9F9"),
    ];

    #[test]
    fn known_answers() {
        for (key, plain, cipher) in VECTORS {
            let idea = Idea::new(&unhex(key));
            let (plain, cipher) = (unhex(plain), unhex(cipher));
            assert_eq!(idea.encrypt_block(&plain), cipher, "encrypt, key {key}");
            assert_eq!(idea.decrypt_block(&cipher), plain, "decrypt, key {key}");
        }
    }

    /// Straightforward reference: map 0 to 2^16, multiply, reduce, map back.
    fn mul_reference(a: u16, b: u16) -> u16 {
        let widen = |x: u16| if x == 0 { 1 << 16 } else { u64::from(x) };
        let p = widen(a) * widen(b) % 0x1_0001;
        if p == 1 << 16 { 0 } else { p as u16 }
    }

    #[test]
    fn mul_matches_reference() {
        let edges = [0, 1, 2, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF];
        for a in 0..=u16::MAX {
            for b in edges {
                assert_eq!(mul(a, b), mul_reference(a, b), "{a} * {b}");
            }
        }
        for a in (0..=u16::MAX).step_by(251) {
            for b in (0..=u16::MAX).step_by(257) {
                assert_eq!(mul(a, b), mul_reference(a, b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn mul_inv_inverts_every_word() {
        for x in 0..=u16::MAX {
            assert_eq!(mul(x, mul_inv(x)), 1, "x = {x}");
        }
    }

    #[test]
    fn decrypt_undoes_encrypt_for_varied_keys() {
        let mut key = [0u8; KEY_LEN];
        let mut block: Block = *b"\x00\xFF\x80\x7F\x01\xFE\x55\xAA";
        for round in 0u8..64 {
            for (i, b) in key.iter_mut().enumerate() {
                *b = b.wrapping_mul(31).wrapping_add(round ^ i as u8);
            }
            let idea = Idea::new(&key);
            let encrypted = idea.encrypt_block(&block);
            assert_ne!(encrypted, block);
            assert_eq!(idea.decrypt_block(&encrypted), block);
            block = encrypted;
        }
    }
}
