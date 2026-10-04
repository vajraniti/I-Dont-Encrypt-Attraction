//! `enc` seals a text under a passphrase and prints it as hex; `dec` takes
//! the hex back and reveals the text. The text, the key and the hex can each
//! be typed on the command line or read from a file.

mod reveal;

use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use idea_cbc::{BadPadding, Sealed, hex};

const USAGE: &str = "\
Usage:
  idea-cbc enc [OPTIONS] <TEXT>   encrypt TEXT, print salt + IV + ciphertext as hex
  idea-cbc dec [OPTIONS] <HEX>    decrypt HEX and reveal the text

Options:
  -k, --key KEY         the passphrase, any length
  -K, --key-file FILE   read the passphrase from FILE
  -i, --in FILE         read TEXT or HEX from FILE instead of the command line
  -o, --out FILE        write the result to FILE instead of the screen
                        (an existing FILE is overwritten)
  -h, --help            show this help

Without -k or -K the key is asked for on the terminal. A key file loses its
last line break, which editors add on save; spaces stay part of the key.
Put -- before a TEXT that starts with a dash.";

/// How many bytes of noise a wrong key gets to show.
const NOISE_PREVIEW: usize = 12;

#[derive(Debug, PartialEq)]
enum Cli {
    Help,
    Enc(Job),
    Dec(Job),
}

/// Where the key and the input come from, and where the result goes.
#[derive(Debug, PartialEq)]
struct Job {
    key: Option<Source>,
    input: Source,
    out: Option<PathBuf>,
}

/// A value typed on the command line, or the file that holds it.
#[derive(Debug, PartialEq)]
enum Source {
    Arg(String),
    File(PathBuf),
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
        Cli::Enc(job) => {
            encrypt(job)?;
            Ok(ExitCode::SUCCESS)
        }
        Cli::Dec(job) => decrypt(job),
    }
}

fn parse(args: Vec<String>) -> Result<Cli> {
    let mut args = args.into_iter();
    let command = args.next();
    let (what, build): (&str, fn(Job) -> Cli) = match command.as_deref() {
        Some("enc") => ("TEXT", Cli::Enc),
        Some("dec") => ("HEX", Cli::Dec),
        Some("-h" | "--help") => return Ok(Cli::Help),
        Some(other) => bail!("unknown command {other:?}\n\n{USAGE}"),
        None => bail!("no command given\n\n{USAGE}"),
    };

    let mut key = None;
    let mut input = None;
    let mut out = None;
    let mut options_done = false;
    while let Some(arg) = args.next() {
        let is_option = !options_done && arg.starts_with('-') && arg.len() > 1;
        if !is_option {
            if input.replace(Source::Arg(arg)).is_some() {
                bail!("more than one {what} given; quote it if it contains spaces");
            }
            continue;
        }
        match arg.as_str() {
            "--" => options_done = true,
            "-h" | "--help" => return Ok(Cli::Help),
            "-k" | "--key" => {
                let key_arg = Source::Arg(value(&mut args, &arg)?);
                set_once(&mut key, key_arg, "the key")?;
            }
            "-K" | "--key-file" => {
                let key_file = Source::File(value(&mut args, &arg)?.into());
                set_once(&mut key, key_file, "the key")?;
            }
            "-i" | "--in" => {
                let input_file = Source::File(value(&mut args, &arg)?.into());
                set_once(&mut input, input_file, what)?;
            }
            "-o" | "--out" => {
                let out_file = PathBuf::from(value(&mut args, &arg)?);
                set_once(&mut out, out_file, "the output file")?;
            }
            _ => bail!("unknown option {arg:?}\n\n{USAGE}"),
        }
    }

    let input = input.with_context(|| format!("no {what} given\n\n{USAGE}"))?;
    Ok(build(Job { key, input, out }))
}

/// The value that follows an option such as `-k`.
fn value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{option} needs a value"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, what: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("{what} is given twice");
    }
    Ok(())
}

fn encrypt(job: Job) -> Result<()> {
    let text = read_input(job.input, "text")?;
    if text.is_empty() {
        bail!("nothing to encrypt: the text is empty");
    }
    // `dec` only prints what passes this check and calls anything else a
    // wrong key, so a text that fails it could never be read back.
    if readable_text(text.as_bytes()).is_none() {
        bail!("the text has control characters other than line breaks and tabs");
    }
    let key = read_key(job.key)?;
    let sealed =
        idea_cbc::seal(key_bytes(&key)?, text.as_bytes()).context("encrypting the text")?;
    let hex = hex::encode(&sealed.to_bytes());
    match job.out {
        Some(path) => save(&path, format!("{hex}\n").as_bytes()),
        None => {
            println!("{hex}");
            Ok(())
        }
    }
}

fn decrypt(job: Job) -> Result<ExitCode> {
    // The message is checked before the key is asked for: no point typing a
    // key for hex that was cut off when copied.
    let hex_input = read_input(job.input, "hex")?;
    let bytes = hex::decode(&hex_input).context("reading the hex")?;
    let sealed = Sealed::from_bytes(&bytes).context("reading the message")?;
    if job.key.is_none() {
        // The demo: the noise first, then the question.
        eprintln!("{}", hex::encode(&bytes));
    }
    let key = read_key(job.key)?;
    let opened = sealed.open(key_bytes(&key)?);

    let mut out = io::stdout().lock();
    let animate = out.is_terminal();
    if let Ok(plaintext) = &opened
        && let Some(text) = readable_text(plaintext)
    {
        match job.out {
            // Byte for byte, so a text read from a file comes back the same.
            Some(path) => save(&path, plaintext)?,
            // `show` ends the line itself; the text's own last line break,
            // which a text file usually has, would leave a blank line.
            None => reveal::show(&mut out, trim_line_ending(text), animate)
                .context("printing the text")?,
        }
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

/// The text or hex, as typed or read from its file.
fn read_input(source: Source, what: &str) -> Result<String> {
    match source {
        Source::Arg(input) => Ok(input),
        Source::File(path) => read_text(&path, what),
    }
}

/// Without a key on the command line, it is asked for on the terminal.
fn read_key(source: Option<Source>) -> Result<String> {
    match source {
        Some(Source::Arg(key)) => Ok(key),
        Some(Source::File(path)) => {
            // Editors end the last line on save; the key typed at the
            // prompt loses its Enter the same way, so both give one key.
            let mut key = read_text(&path, "key")?;
            key.truncate(trim_line_ending(&key).len());
            Ok(key)
        }
        None => prompt_key(),
    }
}

fn read_text(path: &Path, what: &str) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("reading the {what} from {}", path.display()))?;
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8 text", path.display()))
}

/// Writes the result and says so on stderr, so stdout stays empty.
fn save(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("✓ saved to {}", path.display());
    Ok(())
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

/// Drops one `\n` or `\r\n` from the end of a line. Nothing else is trimmed:
/// spaces are part of the key.
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

    fn typed(s: &str) -> Source {
        Source::Arg(s.into())
    }

    fn file(s: &str) -> Source {
        Source::File(s.into())
    }

    /// A directory of its own for one test's files, removed afterwards.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("idea-cbc-{}-{test}", std::process::id()));
            fs::create_dir_all(&dir).expect("temp dir can be made");
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Leftovers in the temp dir harm nothing, and panicking in drop
            // would hide the test's own result.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            parse(args(&["enc", "-k", "Dance with me ;)", "In Darkness"])).expect("valid"),
            Cli::Enc(Job {
                key: Some(typed("Dance with me ;)")),
                input: typed("In Darkness"),
                out: None
            })
        );
        assert_eq!(
            parse(args(&["dec", "00ff"])).expect("valid"),
            Cli::Dec(Job {
                key: None,
                input: typed("00ff"),
                out: None
            })
        );
        assert_eq!(
            parse(args(&["dec", "00ff", "--key", "k"])).expect("options go anywhere"),
            Cli::Dec(Job {
                key: Some(typed("k")),
                input: typed("00ff"),
                out: None
            })
        );
        assert_eq!(
            parse(args(&["enc", "--", "-k"])).expect("-- ends options"),
            Cli::Enc(Job {
                key: None,
                input: typed("-k"),
                out: None
            })
        );
        assert_eq!(parse(args(&["--help"])).expect("valid"), Cli::Help);
        assert_eq!(parse(args(&["dec", "-h"])).expect("valid"), Cli::Help);
    }

    #[test]
    fn parses_files_mixed_with_typed_values() {
        assert_eq!(
            parse(args(&["enc", "-K", "key.txt", "In Darkness"])).expect("valid"),
            Cli::Enc(Job {
                key: Some(file("key.txt")),
                input: typed("In Darkness"),
                out: None
            })
        );
        assert_eq!(
            parse(args(&["enc", "--in", "text.txt", "-k", "k", "-o", "c.hex"])).expect("valid"),
            Cli::Enc(Job {
                key: Some(typed("k")),
                input: file("text.txt"),
                out: Some("c.hex".into())
            })
        );
        assert_eq!(
            parse(args(&[
                "dec",
                "-i",
                "c.hex",
                "--key-file",
                "key.txt",
                "--out",
                "plain.txt"
            ]))
            .expect("valid"),
            Cli::Dec(Job {
                key: Some(file("key.txt")),
                input: file("c.hex"),
                out: Some("plain.txt".into())
            })
        );
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
            &["enc", "-k", "a", "-K", "key.txt", "x"],
            &["enc", "-i"],
            &["enc", "-i", "text.txt", "x"],
            &["enc", "x", "-i", "text.txt"],
            &["enc", "-o", "a.hex", "-o", "b.hex", "x"],
            &["enc", "-o", "c.hex"],
            &["dec", "-x", "00"],
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn key_file_loses_only_its_last_line_break() {
        let dir = TempDir::new("key-file");
        for (contents, key) in [
            ("Dance with me ;)\n", "Dance with me ;)"),
            ("Dance with me ;)\r\n", "Dance with me ;)"),
            ("no line break", "no line break"),
            ("  spaced key  \n", "  spaced key  "),
            ("two\n\n", "two\n"),
        ] {
            let path = dir.path("key.txt");
            fs::write(&path, contents).expect("temp file can be written");
            let read = read_key(Some(Source::File(path))).expect("key file reads");
            assert_eq!(read, key, "{contents:?}");
        }

        let missing = dir.path("missing.txt");
        let err = read_key(Some(Source::File(missing.clone()))).expect_err("no such file");
        assert!(
            err.to_string()
                .starts_with(&format!("reading the key from {}", missing.display())),
            "{err}"
        );

        let binary = dir.path("binary.key");
        fs::write(&binary, b"\xFF\xFE").expect("temp file can be written");
        let err = read_key(Some(Source::File(binary.clone()))).expect_err("not UTF-8");
        assert_eq!(
            err.to_string(),
            format!("{} is not UTF-8 text", binary.display())
        );
    }

    #[test]
    fn files_round_trip_byte_for_byte() {
        let dir = TempDir::new("round-trip");
        let (text, key, hex, plain) = (
            dir.path("text.txt"),
            dir.path("key.txt"),
            dir.path("c.hex"),
            dir.path("plain.txt"),
        );
        let contents = "В темноте можно всё\nIn Darkness Everything's Allowed\n";
        fs::write(&text, contents).expect("temp file can be written");
        fs::write(&key, "Dance with me ;)\n").expect("temp file can be written");

        encrypt(Job {
            key: Some(Source::File(key)),
            input: Source::File(text),
            out: Some(hex.clone()),
        })
        .expect("encrypts");
        // The key from the file and the same key typed are one key.
        let code = decrypt(Job {
            key: Some(typed("Dance with me ;)")),
            input: Source::File(hex),
            out: Some(plain.clone()),
        })
        .expect("decrypts");
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(fs::read_to_string(&plain).expect("written"), contents);
    }

    #[test]
    fn wrong_key_writes_no_file() {
        let dir = TempDir::new("wrong-key");
        let (key, hex, plain) = (
            dir.path("key.txt"),
            dir.path("c.hex"),
            dir.path("plain.txt"),
        );
        fs::write(&key, "Dance with me ;)").expect("temp file can be written");

        encrypt(Job {
            key: Some(Source::File(key)),
            input: typed("In Darkness"),
            out: Some(hex.clone()),
        })
        .expect("encrypts");
        let code = decrypt(Job {
            key: Some(typed("dance with me ;)")),
            input: Source::File(hex),
            out: Some(plain.clone()),
        })
        .expect("runs to the end");
        assert_eq!(code, ExitCode::FAILURE);
        assert!(!plain.exists());
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
