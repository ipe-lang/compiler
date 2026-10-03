//! The one decode point for a host binary's command line.
//!
//! Every workspace binary (`ipe` and the documentation generators) reads its
//! arguments through [`host_args`], never `std::env::args()`, which aborts the
//! process on an argument that is not valid UTF-8. A non-UTF-8 argument is
//! turned into a typed [`NonUtf8Argument`] naming its position; its bytes are
//! never echoed, so a hostile argument cannot reach a terminal or a log.

use std::ffi::OsString;
use std::fmt;

/// A command-line argument that is not valid UTF-8 text.
///
/// Carries only the argument's 1-based position after the program name, never
/// its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonUtf8Argument {
    position: usize,
}

impl NonUtf8Argument {
    /// The 1-based position of the refused argument after the program name.
    #[must_use]
    pub const fn position(self) -> usize {
        self.position
    }
}

impl fmt::Display for NonUtf8Argument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "command-line argument {} is not valid UTF-8; pass every argument as UTF-8 text (rename a path that is not)",
            self.position
        )
    }
}

impl std::error::Error for NonUtf8Argument {}

/// This process's arguments after the program name, each decoded as UTF-8.
///
/// # Errors
///
/// [`NonUtf8Argument`] for the first argument that is not valid UTF-8.
pub fn host_args() -> Result<Vec<String>, NonUtf8Argument> {
    decode(std::env::args_os())
}

/// Decode a full argument vector (program name first) into the UTF-8 arguments
/// after the program name.
///
/// The program name itself is skipped undecoded: it names the binary, not
/// input, so its encoding never refuses a run.
///
/// # Errors
///
/// [`NonUtf8Argument`] for the first argument after the program name that is
/// not valid UTF-8, naming its 1-based position.
pub fn decode(argv: impl IntoIterator<Item = OsString>) -> Result<Vec<String>, NonUtf8Argument> {
    argv.into_iter()
        .enumerate()
        .skip(1)
        .map(|(position, arg)| arg.into_string().map_err(|_| NonUtf8Argument { position }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{NonUtf8Argument, decode};
    use std::ffi::OsString;

    fn os(text: &str) -> OsString {
        OsString::from(text)
    }

    #[test]
    fn utf8_arguments_decode_after_the_program_name() {
        let args = decode([os("ipe"), os("build"), os("src/Main.ipe")]);
        assert_eq!(
            args,
            Ok(vec!["build".to_owned(), "src/Main.ipe".to_owned()])
        );
    }

    #[test]
    fn an_empty_argument_vector_decodes_to_no_arguments() {
        assert_eq!(decode([]), Ok(Vec::new()));
    }

    #[cfg(unix)]
    fn non_utf8() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'a', 0xff, 0x1b, b'['])
    }

    #[cfg(windows)]
    fn non_utf8() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        // An unpaired surrogate has no UTF-8 form.
        OsString::from_wide(&[0x61, 0xD800])
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn a_non_utf8_argument_is_refused_with_its_position() {
        let refused = decode([os("ipe"), os("check"), non_utf8(), os("--json")]);
        assert_eq!(refused, Err(NonUtf8Argument { position: 2 }));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn the_refusal_never_echoes_the_argument_bytes() {
        let decoded = decode([os("ipe"), non_utf8()]);
        assert!(decoded.is_err(), "a non-UTF-8 argument must be refused");
        let Err(refused) = decoded else { return };
        let text = refused.to_string();
        assert!(text.contains("argument 1"), "{text}");
        assert!(
            !text.contains('\u{1b}') && !text.contains('\u{fffd}'),
            "{text}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn a_non_utf8_program_name_does_not_refuse_the_run() {
        assert_eq!(decode([non_utf8(), os("fmt")]), Ok(vec!["fmt".to_owned()]));
    }
}
