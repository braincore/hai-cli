use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

/// Initialise file-based logging.
///
/// The returned guard flushes buffered logs when dropped — hold it for the
/// lifetime of the program, or you will lose output.
#[must_use = "logs are dropped when the guard is dropped"]
pub fn init(debug: bool) -> WorkerGuard {
    let log_dir = log_dir();
    std::fs::create_dir_all(&log_dir)
        .unwrap_or_else(|e| panic!("failed to create log dir {}: {e}", log_dir.display()));

    let file = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("debug")
        .filename_suffix("log")
        .max_log_files(10)
        .build(&log_dir)
        .expect("failed to build appender");

    let (writer, guard) = tracing_appender::non_blocking(file);

    let default_env_filter_str = if debug { "warn,hai=debug" } else { "warn" };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_env_filter_str));

    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_env_filter(filter)
        .init();

    tracing::info!(path = %log_dir.display(), "hai logging");

    guard
}

/// Use a separate folder for logs to support rotation.
fn log_dir() -> PathBuf {
    let mut path = crate::config::get_config_folder_path();
    path.push("log");
    path
}
