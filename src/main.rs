//! `enc` seals a text under a passphrase and prints it as hex; `dec` takes
//! the hex back and reveals the text.

mod reveal;

use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use idea_cbc::{BadPadding, Sealed, hex};

const USAGE: &str = "\
Usage:
  idea-cbc enc [-k KEY] <TEXT>   encrypt TEXT, print salt + IV + ciphertext as hex
  idea-cbc dec [-k KEY] <HEX>    decrypt HEX and reveal the text

KEY is a passphrase of any length; without -k it is asked for on the terminal.
Put -- before a TEXT that starts with a dash.";

/// How many bytes of noise a wrong key gets to show.
const NOISE_PREVIEW: usize = 12;

#[derive(Debug, PartialEq)]
enum Cli {
    Help,
    Enc { key: Option<String>, text: String },
    Dec { key: Option<String>, hex: String },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|arg| anyhow!("argument {arg:?} is not valid UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    match parse(args)? {
        Cli::Help => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Cli::Enc { key, text } => {
            encrypt(key, &text)?;
            Ok(ExitCode::SUCCESS)
        }
        Cli::Dec { key, hex } => decrypt(key, &hex),
    }
}

fn parse(args: Vec<String>) -> Result<Cli> {
    type Build = fn(Option<String>, String) -> Cli;
    let mut args = args.into_iter();
    let command = args.next();
    let (what, build): (&str, Build) = match command.as_deref() {
        Some("enc") => ("TEXT", |key, text| Cli::Enc { key, text }),
        Some("dec") => ("HEX", |key, hex| Cli::Dec { key, hex }),
        Some("-h" | "--help") => return Ok(Cli::Help),
        Some(other) => bail!("unknown command {other:?}\n\n{USAGE}"),
        None => bail!("no command given\n\n{USAGE}"),
    };

    let mut key = None;
    let mut input = None;
    let mut options_done = false;
    while let Some(arg) = args.next() {
        let is_option = !options_done && arg.starts_with('-') && arg.len() > 1;
        if !is_option {
            if input.replace(arg).is_some() {
                bail!("more than one {what} given; quote it if it contains spaces");
            }
            continue;
        }
        match arg.as_str() {
            "--" => options_done = true,
            "-h" | "--help" => return Ok(Cli::Help),
            "-k" | "--key" => {
                let value = args
                    .next()
                    .with_context(|| format!("{arg} needs a value"))?;
                if key.replace(value).is_some() {
                    bail!("the key is given twice");
                }
            }
            _ => bail!("unknown option {arg:?}\n\n{USAGE}"),
        }
    }

    let input = input.with_context(|| format!("no {what} given\n\n{USAGE}"))?;
    Ok(build(key, input))
}

fn encrypt(key: Option<String>, text: &str) -> Result<()> {
    if text.is_empty() {
        bail!("nothing to encrypt: the text is empty");
    }
    // `dec` only prints what passes this check and calls anything else a
    // wrong key, so a text that fails it could never be read back.
    if readable_text(text.as_bytes()).is_none() {
        bail!("the text has control characters other than line breaks and tabs");
    }
    let key = match key {
        Some(key) => key,
        None => prompt_key()?,
    };
    let sealed =
        idea_cbc::seal(key_bytes(&key)?, text.as_bytes()).context("encrypting the text")?;
    println!("{}", hex::encode(&sealed.to_bytes()));
    Ok(())
}

fn decrypt(key: Option<String>, hex_input: &str) -> Result<ExitCode> {
    // The message is checked before the key is asked for: no point typing a
    // key for hex that was cut off when copied.
    let bytes = hex::decode(hex_input).context("reading the hex")?;
    let sealed = Sealed::from_bytes(&bytes).context("reading the message")?;
    let key = match key {
        Some(key) => key,
        None => {
            // The demo: the noise first, then the question.
            eprintln!("{}", hex::encode(&bytes));
            prompt_key()?
        }
    };
    let opened = sealed.open(key_bytes(&key)?);

    let mut out = io::stdout().lock();
    let animate = out.is_terminal();
    if let Ok(plaintext) = &opened
        && let Some(text) = readable_text(plaintext)
    {
        reveal::show(&mut out, text, animate).context("printing the text")?;
        return Ok(ExitCode::SUCCESS);
    }
    let noise = match opened {
        Ok(plaintext) => plaintext,
        Err(BadPadding { noise }) => noise,
    };
    reveal::show(&mut out, &noise_preview(&noise), animate).context("printing the noise")?;
    eprintln!(
        "✗ wrong key, or the hex got damaged (first {} of {} bytes above)",
        noise.len().min(NOISE_PREVIEW),
        noise.len()
    );
    Ok(ExitCode::FAILURE)
}

fn key_bytes(key: &str) -> Result<&[u8]> {
    if key.is_empty() {
        bail!("the key is empty");
    }
    Ok(key.as_bytes())
}

fn prompt_key() -> Result<String> {
    eprint!("key: ");
    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading the key")?;
    if read == 0 {
        // End the prompt line so the error doesn't land after "key: ".
        eprintln!();
        bail!("no key: input ended before one was typed");
    }
    Ok(trim_line_ending(&line).to_owned())
}

/// Drops one `\n` or `\r\n` from the end of a typed line. Nothing else is
/// trimmed: spaces are part of the key.
fn trim_line_ending(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// CBC has no integrity check, so a wrong key shows only as noise. Most of
/// the time the padding check in `Sealed::open` catches it; this catches the
/// rest by asking for text: valid UTF-8 with no control characters besides
/// line breaks and tabs. Noise gets past both about once in 67 000 tries for
/// a one-block message, and about once in 3·10^15 for the demo's five blocks.
fn readable_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let readable = text
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'));
    readable.then_some(text)
}

/// A short look at the noise: bytes read as Latin-1, which is how mojibake
/// looks, with anything unprintable shown as `·`.
fn noise_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(NOISE_PREVIEW)
        .map(|&b| {
            let c = char::from(b);
            if reveal::is_plain(c) { c } else { '·' }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|&a| a.to_owned()).collect()
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            parse(args(&["enc", "-k", "Dance with me ;)", "In Darkness"])).expect("valid"),
            Cli::Enc {
                key: Some("Dance with me ;)".into()),
                text: "In Darkness".into()
            }
        );
        assert_eq!(
            parse(args(&["dec", "00ff"])).expect("valid"),
            Cli::Dec {
                key: None,
                hex: "00ff".into()
            }
        );
        assert_eq!(
            parse(args(&["dec", "00ff", "--key", "k"])).expect("options go anywhere"),
            Cli::Dec {
                key: Some("k".into()),
                hex: "00ff".into()
            }
        );
        assert_eq!(
            parse(args(&["enc", "--", "-k"])).expect("-- ends options"),
            Cli::Enc {
                key: None,
                text: "-k".into()
            }
        );
        assert_eq!(parse(args(&["--help"])).expect("valid"), Cli::Help);
        assert_eq!(parse(args(&["dec", "-h"])).expect("valid"), Cli::Help);
    }

    #[test]
    fn rejects_bad_arguments() {
        for bad in [
            &[][..],
            &["encrypt", "x"],
            &["enc"],
            &["enc", "a", "b"],
            &["enc", "-k"],
            &["enc", "-k", "a", "-k", "b", "x"],
            &["dec", "-x", "00"],
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn key_can_be_any_length_but_not_empty() {
        assert_eq!(key_bytes("k").expect("one byte"), b"k");
        assert_eq!(key_bytes("Dance with me ;)").expect("16 bytes").len(), 16);
        assert_eq!(key_bytes("танцуй со мной!").expect("27 bytes").len(), 27);
        let err = key_bytes("").expect_err("empty");
        assert_eq!(err.to_string(), "the key is empty");
    }

    #[test]
    fn tells_text_from_noise() {
        assert_eq!(readable_text(b"In Darkness"), Some("In Darkness"));
        assert_eq!(
            readable_text("line\n\tтекст".as_bytes()),
            Some("line\n\tтекст")
        );
        assert_eq!(readable_text(b"windows\r\nlines"), Some("windows\r\nlines"));
        assert_eq!(readable_text(b"bell\x07"), None);
        assert_eq!(readable_text(b"\x1b[2Jescape"), None);
        assert_eq!(readable_text(b"\xFF\xFE"), None);
    }

    #[test]
    fn only_the_line_ending_is_trimmed_from_a_typed_key() {
        assert_eq!(trim_line_ending("Dance with me ;)\n"), "Dance with me ;)");
        assert_eq!(trim_line_ending("Dance with me ;)\r\n"), "Dance with me ;)");
        assert_eq!(trim_line_ending("no newline"), "no newline");
        assert_eq!(trim_line_ending("  spaced key  \n"), "  spaced key  ");
        assert_eq!(trim_line_ending("two\n\n"), "two\n");
    }

    #[test]
    fn noise_preview_is_short_and_printable() {
        let noise: Vec<u8> = (0..32).map(|i| i * 8 + 3).collect();
        let preview = noise_preview(&noise);
        assert_eq!(preview.chars().count(), NOISE_PREVIEW);
        assert!(preview.chars().all(reveal::is_plain));
        assert_eq!(preview, "····#+3;CKS[");
        assert_eq!(noise_preview(b"\xAD\x85"), "··");
    }
}
