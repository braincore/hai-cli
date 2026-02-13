use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global printer state using atomic booleans for lock-free thread safety
static STDOUT_ENABLED: AtomicBool = AtomicBool::new(true);
static STDERR_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enable all printing (stdout and stderr)
#[allow(dead_code)]
pub fn enable_printing() {
    STDOUT_ENABLED.store(true, Ordering::SeqCst);
    STDERR_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable all printing (stdout and stderr)
#[allow(dead_code)]
pub fn disable_printing() {
    STDOUT_ENABLED.store(false, Ordering::SeqCst);
    STDERR_ENABLED.store(false, Ordering::SeqCst);
}

/// Enable stdout printing only
#[allow(dead_code)]
pub fn enable_stdout() {
    STDOUT_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable stdout printing only
pub fn disable_stdout() {
    STDOUT_ENABLED.store(false, Ordering::SeqCst);
}

/// Enable stderr printing only
#[allow(dead_code)]
pub fn enable_stderr() {
    STDERR_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable stderr printing only
#[allow(dead_code)]
pub fn disable_stderr() {
    STDERR_ENABLED.store(false, Ordering::SeqCst);
}

/// Check if stdout printing is enabled
#[allow(dead_code)]
pub fn is_stdout_enabled() -> bool {
    STDOUT_ENABLED.load(Ordering::SeqCst)
}

/// Check if stderr printing is enabled
#[allow(dead_code)]
pub fn is_stderr_enabled() -> bool {
    STDERR_ENABLED.load(Ordering::SeqCst)
}

/// Check if all printing is enabled
pub fn is_printing_enabled() -> bool {
    STDOUT_ENABLED.load(Ordering::SeqCst) && STDERR_ENABLED.load(Ordering::SeqCst)
}

/// Set stdout state directly
#[allow(dead_code)]
pub fn set_stdout(enabled: bool) {
    STDOUT_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Set stderr state directly
#[allow(dead_code)]
pub fn set_stderr(enabled: bool) {
    STDERR_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Set both stdout and stderr state
#[allow(dead_code)]
pub fn set_printing(enabled: bool) {
    STDOUT_ENABLED.store(enabled, Ordering::SeqCst);
    STDERR_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Internal function for printing to stdout (used by macros)
#[doc(hidden)]
pub fn _print(args: std::fmt::Arguments) {
    if STDOUT_ENABLED.load(Ordering::SeqCst) {
        let _ = io::stdout().write_fmt(args);
    }
}

/// Internal function for printing to stderr (used by macros)
#[doc(hidden)]
pub fn _eprint(args: std::fmt::Arguments) {
    if STDERR_ENABLED.load(Ordering::SeqCst) {
        let _ = io::stderr().write_fmt(args);
    }
}

/// Internal function for flushing stdout
#[doc(hidden)]
pub fn _flush_stdout() {
    if STDOUT_ENABLED.load(Ordering::SeqCst) {
        let _ = io::stdout().flush();
    }
}

/// Internal function for flushing stderr
#[doc(hidden)]
pub fn _flush_stderr() {
    if STDERR_ENABLED.load(Ordering::SeqCst) {
        let _ = io::stderr().flush();
    }
}

/// Replacement for `print!()` - respects stdout printing state
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::printer::_print(format_args!($($arg)*));
    }};
}

/// Replacement for `println!()` - respects stdout printing state
#[macro_export]
macro_rules! println {
    () => {{
        $crate::printer::_print(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        $crate::printer::_print(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// Replacement for `eprint!()` - respects stderr printing state
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        $crate::printer::_eprint(format_args!($($arg)*));
    }};
}

/// Replacement for `eprintln!()` - respects stderr printing state
#[macro_export]
macro_rules! eprintln {
    () => {{
        $crate::printer::_eprint(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        $crate::printer::_eprint(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// Replace for `writeln!()`
/// A bit tricky because the destination can be stdout or stderr, but this
/// macro specifically respects the stdout printing state.
/// It's also not named writeln! to avoid accidentally using it in places that
/// are irrelevant to stdout/stderr.
#[macro_export]
macro_rules! writeln_if_enabled {
    ($dst:expr, $($arg:tt)*) => {{
        if $crate::printer::is_printing_enabled() {
            writeln!($dst, $($arg)*)
        } else {
            Ok(())
        }
    }};
}

/// Replace for `write!()`
/// A bit tricky because the destination can be stdout or stderr, but this
/// macro specifically respects the stdout printing state.
/// It's also not named write! to avoid accidentally using it in places that
/// are irrelevant to stdout/stderr.
#[macro_export]
macro_rules! write_if_enabled {
    ($dst:expr, $($arg:tt)*) => {{
        if $crate::printer::is_printing_enabled() {
            write!($dst, $($arg)*)
        } else {
            Ok(())
        }
    }};
}

/// Force print to stdout, bypassing the global state
#[macro_export]
macro_rules! force_print {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = std::io::stdout().write_fmt(format_args!($($arg)*));
    }};
}

/// Force println to stdout, bypassing the global state
#[macro_export]
macro_rules! force_println {
    () => {{
        use std::io::Write;
        let _ = std::io::stdout().write_fmt(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = std::io::stdout().write_fmt(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// Force eprint to stderr, bypassing the global state
#[macro_export]
macro_rules! force_eprint {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = std::io::stderr().write_fmt(format_args!($($arg)*));
    }};
}

/// Force eprintln to stderr, bypassing the global state
#[macro_export]
macro_rules! force_eprintln {
    () => {{
        use std::io::Write;
        let _ = std::io::stderr().write_fmt(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = std::io::stderr().write_fmt(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// Flush stdout if printing is enabled
#[macro_export]
macro_rules! flush {
    () => {{
        $crate::printer::_flush_stdout();
    }};
}

/// Flush stderr if printing is enabled
#[macro_export]
macro_rules! eflush {
    () => {{
        $crate::printer::_flush_stderr();
    }};
}

/// Force flush stdout, bypassing the global state
#[macro_export]
macro_rules! force_flush {
    () => {{
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }};
}

/// Force flush stderr, bypassing the global state
#[macro_export]
macro_rules! force_eflush {
    () => {{
        use std::io::Write;
        let _ = std::io::stderr().flush();
    }};
}
