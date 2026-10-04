//! The reveal: a line of hex noise that locks into the real text one
//! character at a time, left to right.

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

const FRAME_TIME: Duration = Duration::from_millis(35);
/// Frames of pure noise before the first character locks in.
const WARMUP_FRAMES: usize = 12;
/// Frames between two characters locking in.
const FRAMES_PER_CHAR: usize = 2;
/// Longer lines may wrap, and `\r` can only redraw the line it's on.
const MAX_ANIMATED_CHARS: usize = 64;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Prints `text` with the reveal animation when `animate` is set and the
/// text can be redrawn in place; otherwise just prints it.
pub(crate) fn show(out: &mut impl Write, text: &str, animate: bool) -> io::Result<()> {
    let chars: Vec<char> = text.chars().collect();
    let redrawable = chars.len() <= MAX_ANIMATED_CHARS && chars.iter().all(|&c| is_plain(c));
    if !(animate && redrawable) {
        return writeln!(out, "{text}");
    }

    let mut noise = vec![0; chars.len()];
    for frame_no in 0..=WARMUP_FRAMES + chars.len() * FRAMES_PER_CHAR {
        let locked = frame_no.saturating_sub(WARMUP_FRAMES) / FRAMES_PER_CHAR;
        getrandom::fill(&mut noise)?;
        write!(out, "\r{}", frame(&chars, locked, &noise))?;
        out.flush()?;
        thread::sleep(FRAME_TIME);
    }
    writeln!(out)
}

/// Printable Latin-1: no control characters and no zero-width soft hyphen.
///
/// Redrawing with `\r` works only if each frame covers the one before it.
/// Frames swap one-column noise for real characters, so they never shrink
/// as long as no real character is zero-width.
pub(crate) fn is_plain(c: char) -> bool {
    matches!(c, ' '..='~' | '\u{A0}'..='\u{FF}') && c != '\u{AD}'
}

/// The first `locked` characters of the text, then one noise digit per
/// remaining character.
fn frame(chars: &[char], locked: usize, noise: &[u8]) -> String {
    chars
        .iter()
        .zip(noise)
        .enumerate()
        .map(|(i, (&c, &n))| {
            if i < locked {
                c
            } else {
                char::from(HEX_DIGITS[usize::from(n & 0x0F)])
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_locks_a_prefix_and_fills_the_rest_with_hex() {
        let chars: Vec<char> = "Dance".chars().collect();
        let noise = [0x00, 0x1F, 0xAB, 0xF3, 0x47];
        assert_eq!(frame(&chars, 0, &noise), "0fb37");
        assert_eq!(frame(&chars, 2, &noise), "Dab37");
        assert_eq!(frame(&chars, 5, &noise), "Dance");
        assert_eq!(frame(&chars, 9, &noise), "Dance");
    }

    #[test]
    fn plain_chars() {
        for c in [' ', 'A', '~', '\'', ';', ')', 'ÿ', '¤', '·', '\u{A0}'] {
            assert!(is_plain(c), "{c:?}");
        }
        for c in [
            '\n', '\t', '\u{7F}', '\u{85}', '\u{AD}', '\u{301}', '…', 'ж',
        ] {
            assert!(!is_plain(c), "{c:?}");
        }
    }

    #[test]
    fn falls_back_to_plain_output() {
        let mut out = Vec::new();
        show(&mut out, "In Darkness Everything's Allowed", false).expect("writes to a Vec");
        assert_eq!(out, b"In Darkness Everything's Allowed\n");

        // Two lines can't be redrawn with `\r`, so no animation even if asked.
        let mut out = Vec::new();
        show(&mut out, "two\nlines", true).expect("writes to a Vec");
        assert_eq!(out, b"two\nlines\n");
    }

    #[test]
    fn animation_ends_on_the_text() {
        let mut out = Vec::new();
        show(&mut out, "hi ;)", true).expect("writes to a Vec");
        let out = String::from_utf8(out).expect("frames are UTF-8");
        let frames: Vec<&str> = out.split('\r').skip(1).collect();
        assert_eq!(frames.len(), WARMUP_FRAMES + 5 * FRAMES_PER_CHAR + 1);
        assert!(
            frames
                .iter()
                .all(|f| f.trim_end_matches('\n').chars().count() == 5)
        );
        assert_eq!(*frames.last().expect("at least one frame"), "hi ;)\n");
    }
}
