//! Saved sessions: the cookies of a browser kept in a file, so that a later
//! browser starts signed in.
//!
//! The file holds credentials. Nothing here puts a cookie value into an error,
//! a log line or a `Debug` output.

/// The longest session name.
const MAX_NAME_LEN: usize = 64;

/// Whether `name` is a session name: one to 64 letters, digits, `.`, `_` or
/// `-`, starting with a letter or a digit. Such a name is one path component,
/// holds no separator and no NUL, and does not start with a dot.
pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= MAX_NAME_LEN
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
