//! Hex encoding: a dozen lines, not worth a dependency.

use crate::Error;

/// Lowercase hex, two digits per byte.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    out
}

/// Parses hex in either case. ASCII whitespace is skipped, so a dump that was
/// grouped or wrapped when copied still parses.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let mut nibbles = Vec::with_capacity(s.len());
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let nibble = ch.to_digit(16).ok_or(Error::InvalidHex {
            ch,
            position: i + 1,
        })?;
        // to_digit(16) is below 16, so the cast is lossless.
        nibbles.push(nibble as u8);
    }
    if nibbles.len() % 2 != 0 {
        return Err(Error::OddHex {
            digits: nibbles.len(),
        });
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|p| (p[0] << 4) | p[1])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_byte() {
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        let hex = encode(&bytes);
        assert_eq!(&hex[..8], "00010203");
        assert_eq!(&hex[hex.len() - 4..], "feff");
        assert_eq!(decode(&hex).expect("own output parses"), bytes);
    }

    #[test]
    fn accepts_uppercase_and_whitespace() {
        assert_eq!(
            decode(" DE ad\nBE\tef ").expect("valid hex"),
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(decode("").expect("empty is valid"), []);
    }

    #[test]
    fn rejects_bad_digits_with_their_position() {
        assert!(matches!(
            decode("00g0"),
            Err(Error::InvalidHex {
                ch: 'g',
                position: 3
            })
        ));
        assert!(matches!(
            decode("ab’"),
            Err(Error::InvalidHex {
                ch: '’',
                position: 3
            })
        ));
    }

    #[test]
    fn rejects_odd_digit_count() {
        assert!(matches!(decode("abc"), Err(Error::OddHex { digits: 3 })));
        assert!(matches!(decode("a b c"), Err(Error::OddHex { digits: 3 })));
    }
}
