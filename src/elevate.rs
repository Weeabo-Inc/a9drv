//! Elevation detection and the *single sentence* the user gets when it is missing.
//!
//! a9drv never attempts to self-elevate. It is run from a console, possibly by a
//! script, possibly by another tool; a UAC prompt appearing out of nowhere is how
//! an automation run hangs forever. The contract is: detect, say one actionable
//! sentence, exit 3, touch nothing.

use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Exactly one actionable sentence, and nothing else. No Win32 error code, no
/// dump, no numbered list of options.
pub const NOT_ELEVATED_ACTION: &str = "This needs an elevated console - open an Administrator \
PowerShell (Win+X, then 'Terminal (Admin)') and re-run the same command there.";

/// One sentence, and it says why it is not the same as the other one.
pub const ELEVATION_UNKNOWN_ACTION: &str = "Windows would not tell this process whether it is \
elevated, so open an Administrator PowerShell (Win+X, then 'Terminal (Admin)') and re-run the \
same command there.";

/// What we were able to learn about the current token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Token says elevated. Binding may proceed.
    Elevated,
    /// Token says not elevated. Binding must not be attempted.
    NotElevated,
    /// The token could not be read. Treated as "do not proceed", because the
    /// alternative is a partly-applied driver change.
    Unknown,
}

impl Elevation {
    pub fn is_elevated(&self) -> bool {
        matches!(self, Elevation::Elevated)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Elevation::Elevated => "elevated",
            Elevation::NotElevated => "not-elevated",
            Elevation::Unknown => "unknown",
        }
    }
}

/// The message to print, or `None` when the operation may proceed.
///
/// Pure, so the exact wording is unit-tested rather than eyeballed in a console.
pub fn gate(e: Elevation) -> Option<&'static str> {
    match e {
        Elevation::Elevated => None,
        Elevation::NotElevated => Some(NOT_ELEVATED_ACTION),
        Elevation::Unknown => Some(ELEVATION_UNKNOWN_ACTION),
    }
}

/// Read the current process token's elevation state without prompting.
///
/// SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be closed;
/// only the token from `OpenProcessToken` is closed, and only on the success
/// path where it was written.
pub fn detect() -> Elevation {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Elevation::Unknown;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        // CloseHandle's BOOL is deliberately ignored: a failure to close a token
        // does not change the answer, and there is nothing useful to do with it.
        CloseHandle(token);
        if ok == 0 {
            return Elevation::Unknown;
        }
        if elev.TokenIsElevated != 0 {
            Elevation::Elevated
        } else {
            Elevation::NotElevated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The requirement is "exactly one actionable sentence". A sentence with two
    /// full stops, or one that leaks a hex error code, is not that.
    fn assert_is_one_clean_sentence(msg: &str) {
        assert_eq!(
            msg.matches('.').count(),
            1,
            "expected exactly one full stop in: {msg}"
        );
        assert!(msg.ends_with('.'), "must be a sentence: {msg}");
        assert!(!msg.contains('\n'), "message must be one line: {msg}");
        assert!(!msg.contains("0x"), "no hex error codes: {msg}");
        assert!(!msg.to_lowercase().contains("win32"), "no Win32 dump: {msg}");
        assert!(
            !msg.to_lowercase().contains("error code"),
            "no error-code dump: {msg}"
        );
        // It must say what to do, not just what went wrong.
        assert!(msg.contains("re-run"), "must tell the user what to do: {msg}");
        assert!(
            msg.to_lowercase().contains("administrator"),
            "must name the fix: {msg}"
        );
    }

    #[test]
    fn elevated_process_passes_the_gate_with_no_message() {
        assert_eq!(gate(Elevation::Elevated), None);
    }

    #[test]
    fn not_elevated_selects_the_one_sentence() {
        let m = gate(Elevation::NotElevated).expect("must produce a message");
        assert_eq!(m, NOT_ELEVATED_ACTION);
        assert_is_one_clean_sentence(m);
    }

    #[test]
    fn unknown_elevation_also_refuses_and_says_so() {
        let m = gate(Elevation::Unknown).expect("must produce a message");
        assert_eq!(m, ELEVATION_UNKNOWN_ACTION);
        assert_is_one_clean_sentence(m);
        // It must not claim to know something it does not know.
        assert!(m.contains("would not tell"), "{m}");
    }

    #[test]
    fn the_two_messages_are_different() {
        assert_ne!(NOT_ELEVATED_ACTION, ELEVATION_UNKNOWN_ACTION);
    }

    #[test]
    fn elevation_names_are_stable_for_json() {
        assert_eq!(Elevation::Elevated.name(), "elevated");
        assert_eq!(Elevation::NotElevated.name(), "not-elevated");
        assert_eq!(Elevation::Unknown.name(), "unknown");
        assert!(Elevation::Elevated.is_elevated());
        assert!(!Elevation::NotElevated.is_elevated());
        assert!(!Elevation::Unknown.is_elevated());
    }
}
