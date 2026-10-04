//! Cipher block chaining. Each plaintext block is XORed with the previous
//! ciphertext block (the IV for the first one) before encryption, so equal
//! blocks encrypt differently and each block depends on everything before it.

use crate::idea::{Block, Idea};

pub(crate) fn encrypt(cipher: &Idea, iv: &Block, blocks: &mut [Block]) {
    let mut prev = *iv;
    for block in blocks {
        xor(block, &prev);
        *block = cipher.encrypt_block(block);
        prev = *block;
    }
}

pub(crate) fn decrypt(cipher: &Idea, iv: &Block, blocks: &mut [Block]) {
    let mut prev = *iv;
    for block in blocks {
        let ciphertext = *block;
        *block = cipher.decrypt_block(block);
        xor(block, &prev);
        prev = ciphertext;
    }
}

fn xor(block: &mut Block, other: &Block) {
    for (b, o) in block.iter_mut().zip(other) {
        *b ^= o;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"0123456789abcdef";
    const IV: Block = *b"\x10\x32\x54\x76\x98\xBA\xDC\xFE";

    #[test]
    fn chains_blocks_through_the_cipher() {
        let cipher = Idea::new(&KEY);
        let plain = [*b"same old", *b"same old", *b"the end."];
        let mut blocks = plain;
        encrypt(&cipher, &IV, &mut blocks);

        // C1 = E(P1 ^ IV), C2 = E(P2 ^ C1), C3 = E(P3 ^ C2), built by hand.
        let mut prev = IV;
        for (i, (p, c)) in plain.iter().zip(&blocks).enumerate() {
            let mut expected = *p;
            xor(&mut expected, &prev);
            prev = cipher.encrypt_block(&expected);
            assert_eq!(*c, prev, "block {i}");
        }
        // "same old" twice: CBC must hide the repetition, unlike ECB.
        assert_ne!(blocks[0], blocks[1]);

        decrypt(&cipher, &IV, &mut blocks);
        assert_eq!(blocks, plain);
    }

    #[test]
    fn iv_changes_every_block() {
        let cipher = Idea::new(&KEY);
        let mut a = [*b"same old"; 3];
        let mut b = a;
        encrypt(&cipher, &IV, &mut a);
        encrypt(&cipher, &[0; 8], &mut b);
        for (x, y) in a.iter().zip(&b) {
            assert_ne!(x, y);
        }
    }
}
