//! PKCS#7 padding (RFC 5652, section 6.3): the data is topped up to whole
//! blocks with n bytes of value n, where n is 1 to 8. Data that already
//! fills its blocks gets a whole extra block of 8s, so the last byte always
//! says how much to cut off.

use crate::idea::{BLOCK_LEN, Block};

pub(crate) fn pad(data: &[u8]) -> Vec<Block> {
    let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
    // 1 to 8, so it fits in the byte that records it.
    let pad_len = BLOCK_LEN - rest.len();
    let mut last = [pad_len as u8; BLOCK_LEN];
    last[..rest.len()].copy_from_slice(rest);

    let mut padded = Vec::with_capacity(blocks.len() + 1);
    padded.extend_from_slice(blocks);
    padded.push(last);
    padded
}

/// The data without its padding, or `None` when the padding is malformed,
/// which is what a wrong key almost always produces.
pub(crate) fn unpad(data: &[u8]) -> Option<&[u8]> {
    let pad_len = usize::from(*data.last()?);
    if !(1..=BLOCK_LEN).contains(&pad_len) || pad_len > data.len() {
        return None;
    }
    let (body, padding) = data.split_at(data.len() - pad_len);
    padding
        .iter()
        .all(|&b| usize::from(b) == pad_len)
        .then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_every_length_to_the_next_whole_block() {
        let data: Vec<u8> = (100..120).collect();
        for len in 0..=data.len() {
            let padded = pad(&data[..len]);
            let pad_len = BLOCK_LEN - len % BLOCK_LEN;
            assert_eq!(padded.len(), len / BLOCK_LEN + 1, "{len} bytes");

            let flat = padded.as_flattened();
            assert_eq!(flat[..len], data[..len]);
            assert!(flat[len..].iter().all(|&b| usize::from(b) == pad_len));
            assert_eq!(unpad(flat), Some(&data[..len]), "{len} bytes");
        }
    }

    #[test]
    fn a_full_block_gets_a_whole_block_of_padding() {
        let padded = pad(b"12345678");
        assert_eq!(padded, [*b"12345678", [8; 8]]);
        assert_eq!(pad(b""), [[8; 8]]);
        assert_eq!(pad(b"1234567"), [*b"1234567\x01"]);
    }

    #[test]
    fn rejects_malformed_padding() {
        for bad in [
            &b""[..],
            b"1234567\x00",
            b"1234567\x09",
            b"\x05\x05",
            b"12345\x03\x02\x03",
            b"1234\x04\x04\x04\x05",
        ] {
            assert_eq!(unpad(bad), None, "{bad:?}");
        }
    }
}
