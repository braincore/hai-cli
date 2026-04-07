use chrono::{DateTime, Datelike, Timelike, Utc, Weekday as ChronoWeekday};
use chrono_tz::Tz;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use russh::*;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{File, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use termion::raw::IntoRawMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Notify, RwLock};
use zeroize::Zeroizing;

use crate::api::types::asset::AssetEntry;
use crate::{config, db};

// --

//
// haibot SSH client
//

pub struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Session {
    handle: client::Handle<Client>,
}

impl Session {
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        ssh_signing_key: Zeroizing<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect(config, (host, port), Client).await?;

        let ssh_private_key = PrivateKey::from_openssh(ssh_signing_key)?;

        let auth_res = session
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(
                    Arc::new(ssh_private_key),
                    session.best_supported_rsa_hash().await?.flatten(),
                ),
            )
            .await?;

        if !auth_res.success() {
            return Err("authentication failed".into());
        }

        Ok(Self { handle: session })
    }

    async fn sftp_session(&mut self) -> Result<SftpSession, Box<dyn std::error::Error>> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;
        Ok(sftp)
    }

    pub async fn call(
        &mut self,
        command: &str,
    ) -> Result<(u32, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = 0u32;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        // stderr
                        stderr.extend_from_slice(data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                }
                _ => {}
            }
        }

        Ok((exit_code, stdout, stderr))
    }

    #[allow(dead_code)]
    /// Stream output directly to terminal
    pub async fn call_streaming(
        &mut self,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let mut exit_code = 0u32;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.write_all(data).await?;
                    stdout.flush().await?;
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr.write_all(data).await?;
                        stderr.flush().await?;
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                }
                _ => {}
            }
        }

        Ok(exit_code)
    }

    /// Interactive PTY session with raw terminal mode
    pub async fn call_interactive(
        &mut self,
        command: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut channel = self.handle.channel_open_session().await?;

        let (w, h) = termion::terminal_size()?;

        channel
            .request_pty(
                false,
                &std::env::var("TERM").unwrap_or("xterm".into()),
                w as u32,
                h as u32,
                0,
                0,
                &[],
            )
            .await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdin = tokio_fd::AsyncFd::try_from(0)?;
        let mut stdout = tokio_fd::AsyncFd::try_from(1)?;
        let mut buf = vec![0; 1024];
        let mut stdin_closed = false;

        let _raw_term = std::io::stdout().into_raw_mode()?;

        loop {
            tokio::select! {
                r = stdin.read(&mut buf), if !stdin_closed => {
                    match r {
                        Ok(0) => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            if !stdin_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }

        Ok(code)
    }

    /// Upload a file via SFTP
    pub async fn upload(
        &mut self,
        local_path: impl AsRef<Path>,
        remote_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let contents = tokio::fs::read(local_path).await?;

        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;

        remote_file.write_all(&contents).await?;
        remote_file.flush().await?;
        remote_file.shutdown().await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Download a file via SFTP
    pub async fn download(
        &mut self,
        remote_path: &str,
        local_path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp.open_with_flags(remote_path, OpenFlags::READ).await?;

        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents).await?;

        tokio::fs::write(local_path, &contents).await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Upload bytes directly via SFTP
    pub async fn upload_bytes(
        &mut self,
        data: &[u8],
        remote_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;

        remote_file.write_all(data).await?;
        remote_file.flush().await?;
        remote_file.shutdown().await?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Download file as bytes via SFTP
    pub async fn download_bytes(
        &mut self,
        remote_path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let sftp = self.sftp_session().await?;

        let mut remote_file = sftp.open_with_flags(remote_path, OpenFlags::READ).await?;

        let mut contents = Vec::new();
        remote_file.read_to_end(&mut contents).await?;

        Ok(contents)
    }

    pub async fn close(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

// --

//
// haibot cron system
//

fn get_pid_file() -> PathBuf {
    config::get_bot_pid_path()
}

/// Start the bot.
///
/// If `launch_as_daemon` is true, the bot is started in a background process
/// and detached. Otherwise, the bot is started in this process.
pub async fn start_bot(
    cfg: config::Config,
    account: Option<db::Account>,
    force_ai_model: Option<config::AiModel>,
    launch_as_daemon: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let is_daemon_child = std::env::var("HAI_BOT_DAEMON").is_ok();

    // Only check for existing process if we're not the spawned daemon
    if !is_daemon_child {
        if let Some(pid) = read_pid() {
            if is_process_running(pid).await {
                eprintln!("Bot is already running (PID: {})", pid);
                return Ok(());
            }
        }
    }

    if launch_as_daemon && !is_daemon_child {
        spawn_background()?;
    } else {
        match run_bot_loop(cfg, account, force_ai_model).await {
            Ok(_) => println!("Bot exited normally"),
            Err(e) => eprintln!("Bot exited with error: {}", e),
        }
    }

    Ok(())
}

pub async fn stop_bot() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pid) = read_pid() {
        if is_process_running(pid).await {
            kill_process(pid, false).await?;
            println!("Stopped bot (PID: {})", pid);
        } else {
            println!("Bot was not running");
        }

        std::fs::remove_file(get_pid_file()).ok();
    } else {
        println!("No bot PID file found");
    }

    Ok(())
}

//
// Process management
//

async fn kill_process(pid: u32, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let signal = if force { "-9" } else { "-TERM" };
        let output = Command::new("kill")
            .args([signal, &pid.to_string()])
            .output()
            .await?;

        if !output.status.success() {
            return Err(format!(
                "Failed to kill process: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }

    #[cfg(windows)]
    {
        let mut args = vec!["/PID", &pid.to_string()];
        if force {
            args.push("/F");
        }

        let output = Command::new("taskkill").args(&args).output()?;

        // If graceful failed, try forceful on Windows
        if !output.status.success() && !force {
            return kill_process(pid, true);
        }

        if !output.status.success() {
            return Err(format!(
                "Failed to kill process: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }

    Ok(())
}

pub async fn bot_status() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pid) = read_pid() {
        if is_process_running(pid).await {
            println!("Bot is running (PID: {})", pid);
        } else {
            println!("Bot is not running (stale PID file)");
        }
    } else {
        println!("Bot is not running");
    }
    Ok(())
}

fn read_pid() -> Option<u32> {
    read_to_string(get_pid_file()).ok()?.trim().parse().ok()
}

async fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

fn spawn_background() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    let current_binary = std::env::current_exe()?;
    let log_file = File::create(config::get_bot_log_path())?;

    let mut cmd = Command::new(current_binary);
    cmd.arg("bot").arg("start");

    let child = cmd
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .env("HAI_BOT_DAEMON", "1")
        .spawn()?;

    let pid = child.id();

    let mut pid_file = File::create(get_pid_file())?;
    writeln!(pid_file, "{}", pid)?;

    println!("Bot started (PID: {})", pid);
    Ok(())
}

#[cfg(windows)]
fn spawn_background(config: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const DETACHED_PROCESS: u32 = 0x00000008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

    let exe = std::env::current_exe()?;
    let log_file = File::create(get_hai_dir().join("bot.log"))?;

    let mut cmd = Command::new(exe);
    cmd.arg("bot").arg("start");

    if let Some(cfg) = config {
        cmd.arg("-c").arg(cfg);
    }

    let child = cmd
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .env("HAI_BOT_DAEMON", "1")
        .spawn()?;

    let mut pid_file = File::create(get_pid_file())?;
    writeln!(pid_file, "{}", child.id())?;

    println!("Bot started (PID: {})", child.id());
    Ok(())
}

// --

/// Main bot loop.
///
/// Responsible for fetching list of jobs, setting up a listener to track
/// changes to jobs, and launching the scheduler to execute them.
pub async fn run_bot_loop(
    cfg: config::Config,
    account: Option<db::Account>,
    force_ai_model: Option<config::AiModel>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Bot running...");

    let start_msg = format!("Bot starting at {:?}\n", std::time::SystemTime::now());
    std::fs::write(config::get_bot_log_path(), &start_msg).ok();

    let repl_mode = crate::session::ReplMode::Normal;
    let incognito = false;
    let session = crate::session::SessionState::new_from_cfg(
        repl_mode,
        &cfg,
        account.clone(),
        incognito,
        force_ai_model,
    );

    let api_client = crate::session::mk_api_client(Some(&session));
    let prefix = "haibot/jobs/".to_string();

    // Initial fetch of job list
    let (initial_jobs, initial_cursor) = fetch_job_list(&api_client, &prefix).await?;

    if initial_jobs.is_empty() {
        println!("No jobs found. Add assets with prefix 'haibot/jobs/' to get started.");
    }

    // Shared state
    let job_groups = Arc::new(RwLock::new(initial_jobs));
    let job_groups_clone = Arc::clone(&job_groups);

    // Notify channel for waking up the scheduler when jobs change
    let schedule_notify = Arc::new(Notify::new());
    let schedule_notify_clone = Arc::clone(&schedule_notify);

    // Spawn the listener task for job config changes
    let api_client_for_listener = crate::session::mk_api_client(Some(&session));
    let prefix_clone = prefix.clone();
    let listen_url = format!(
        "{}/notify/listen",
        crate::session::get_api_base_url().replace("http", "ws")
    );

    let _listener_handle = tokio::spawn(async move {
        listen_for_changes(
            api_client_for_listener,
            prefix_clone,
            initial_cursor,
            job_groups_clone,
            listen_url,
            schedule_notify_clone, // Wake scheduler on changes
        )
        .await
    });

    // Run the scheduler (which will also spawn asset change listeners)
    let api_client_for_scheduler = crate::session::mk_api_client(Some(&session));
    run_scheduler(job_groups, schedule_notify, api_client_for_scheduler).await
}

/// Fetching the list of jobs is equivalent to listing all assets at a given
/// prefix.
///
/// If pool does not exist, will keep trying until it does so that a cursor can
/// be returned.
async fn fetch_job_list(
    api_client: &crate::api::client::HaiClient,
    prefix: &str,
) -> Result<
    (Vec<crate::api::types::asset::AssetEntry>, String),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use crate::api::types::asset::{AssetEntryIterArg, AssetEntryIterError, AssetEntryIterNextArg};

    loop {
        match api_client
            .asset_entry_iter(AssetEntryIterArg {
                prefix: Some(prefix.to_string()),
                limit: 200,
            })
            .await
        {
            Ok(mut iter_res) => {
                let mut entries = Vec::new();
                let cursor;
                loop {
                    entries.extend_from_slice(&iter_res.entries);
                    if !iter_res.has_more {
                        cursor = iter_res.cursor;
                        break;
                    }
                    iter_res = api_client
                        .asset_entry_iter_next(AssetEntryIterNextArg {
                            cursor: iter_res.cursor,
                            limit: 200,
                        })
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                }
                return Ok((entries, cursor));
            }
            Err(e) => match &e {
                crate::api::client::RequestError::Route(AssetEntryIterError::Empty) => {
                    eprintln!("No cursor available, will retry...");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
                _ => {
                    eprintln!("error fetching task list: {}", e);
                    return Err(Box::new(e));
                }
            },
        }
    }
}

async fn listen_for_changes(
    api_client: crate::api::client::HaiClient,
    prefix: String,
    initial_cursor: String,
    job_groups: Arc<RwLock<Vec<crate::api::types::asset::AssetEntry>>>,
    listen_url: String,
    notify: Arc<Notify>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    // Special handling of the initial cursor for cases where the pool is not
    // created. It's a bit of overkill.
    let mut current_cursor = initial_cursor;

    use crate::api::types::notify::{ListenAssetPool, NotifyListenArg};

    let mut attempt = 0;

    loop {
        let arg = NotifyListenArg::AssetPool(ListenAssetPool {
            cursor: current_cursor.clone(),
        });

        let (mut ws_stream, _) = match connect_async(&listen_url).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("error: failed to connect: {}", e);
                attempt += 1;
                let backoff_duration = std::time::Duration::from_secs(2_u64.pow(attempt).min(60));
                eprintln!("retrying in {} seconds...", backoff_duration.as_secs());
                tokio::time::sleep(backoff_duration).await;
                continue;
            }
        };

        if attempt > 0 {
            println!("listener connected");
            attempt = 0;
        }

        if let Err(e) = ws_stream
            .send(Message::Text(serde_json::to_string(&arg).unwrap().into()))
            .await
        {
            eprintln!("error sending listen arg: {}", e);
            continue;
        }

        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(_msg) => {
                    // Received a notification - use iter_next to get changes
                    println!("Received change notification, scanning for changes...");
                    use crate::api::types::asset::AssetEntryIterNextArg;

                    match api_client
                        .asset_entry_iter_next(AssetEntryIterNextArg {
                            cursor: current_cursor.clone(),
                            limit: 200,
                        })
                        .await
                    {
                        Ok(mut iter_res) => {
                            let mut changed_entries = Vec::new();
                            loop {
                                changed_entries.extend_from_slice(&iter_res.entries);
                                if !iter_res.has_more {
                                    current_cursor = iter_res.cursor;
                                    break;
                                }
                                match api_client
                                    .asset_entry_iter_next(AssetEntryIterNextArg {
                                        cursor: iter_res.cursor,
                                        limit: 200,
                                    })
                                    .await
                                {
                                    Ok(next_res) => iter_res = next_res,
                                    Err(e) => {
                                        eprintln!("error during iter_next pagination: {}", e);
                                        break;
                                    }
                                }
                            }

                            if !changed_entries.is_empty() {
                                println!(
                                    "Detected {} changed entries, updating job list...",
                                    changed_entries.len()
                                );

                                // Apply changes to the job groups
                                let mut job_groups_guard = job_groups.write().await;
                                for changed in &changed_entries {
                                    // Remove existing entry with same name (if any)
                                    job_groups_guard.retain(|e| e.name != changed.name);
                                    // Add updated entry (unless it was deleted - check if it has a URL)
                                    if changed.asset.url.is_some() {
                                        job_groups_guard.push(changed.clone());
                                    } else {
                                        println!("Entry removed: {}", changed.name);
                                    }
                                }
                                drop(job_groups_guard);

                                notify.notify_one();
                                println!("Job list updated");
                            }
                        }
                        Err(e) => {
                            eprintln!("error fetching changes via iter_next: {}", e);
                            // Fallback: full refresh
                            match fetch_job_list(&api_client, &prefix).await {
                                Ok((new_jobs, new_cursor)) => {
                                    let mut job_groups_guard = job_groups.write().await;
                                    *job_groups_guard = new_jobs;
                                    drop(job_groups_guard);
                                    current_cursor = new_cursor;
                                    notify.notify_one();
                                }
                                Err(e2) => {
                                    eprintln!("error during fallback refresh: {}", e2);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if !e
                        .to_string()
                        .contains("Connection reset without closing handshake")
                    {
                        eprintln!("error: websocket: {}", e);
                    }
                    break; // Reconnect
                }
            }
        }
    }
}

// --

//
// Job configuration
//

#[derive(Debug, Deserialize)]
pub struct JobGroupConfig {
    /// Default timezone for all jobs in this asset (IANA format)
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub job: Vec<JobConfig>,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

#[derive(Debug, Deserialize)]
pub struct JobConfig {
    /// Description of the job
    pub description: Option<String>,
    /// Task identifier: "username/task-name"
    pub task: Option<String>,
    /// REPL steps (if task specified, these are executed after the task)
    pub steps: Option<Vec<String>>,
    /// Human-friendly schedule OR "always"
    pub schedule: Option<HumanSchedule>,
    /// Cron expression (escape hatch)
    pub cron: Option<String>,
    /// Trigger on change to asset with given name
    pub asset_change: Option<String>,
    /// Override bot-level timezone
    pub timezone: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HumanSchedule {
    Always,
    Every {
        amount: u32,
        unit: TimeUnit,
    },
    Hourly {
        minute: Option<u32>,
    },
    Daily {
        time: TimeOfDay,
    },
    Weekly {
        day: Weekday,
        time: Option<TimeOfDay>,
    },
    Monthly {
        day: u8,
        time: Option<TimeOfDay>,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum TimeUnit {
    Minutes,
    Hours,
    Days,
}

#[derive(Debug, Clone, Copy)]
pub struct TimeOfDay {
    pub hour: u8,
    pub minute: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

// --- Custom Deserializer for HumanSchedule ---

impl<'de> Deserialize<'de> for HumanSchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_human_schedule(&s).map_err(serde::de::Error::custom)
    }
}

fn parse_human_schedule(s: &str) -> Result<HumanSchedule, String> {
    let s = s.trim().to_lowercase();

    // "always"
    if s == "always" {
        return Ok(HumanSchedule::Always);
    }

    // "every N <unit>"
    if let Some(rest) = s.strip_prefix("every ") {
        return parse_every(rest);
    }

    // "hourly" or "hourly at :MM"
    if s == "hourly" {
        return Ok(HumanSchedule::Hourly { minute: None });
    }
    if let Some(rest) = s.strip_prefix("hourly at :") {
        let minute = rest.parse().map_err(|_| "invalid minute")?;
        return Ok(HumanSchedule::Hourly {
            minute: Some(minute),
        });
    }

    // "daily at <time>"
    if let Some(rest) = s.strip_prefix("daily at ") {
        let time = parse_time_of_day(rest)?;
        return Ok(HumanSchedule::Daily { time });
    }

    // "weekly on <day>" or "weekly on <day> at <time>"
    if let Some(rest) = s.strip_prefix("weekly on ") {
        return parse_weekly(rest);
    }

    // "monthly on <N>" or "monthly on <N> at <time>"
    if let Some(rest) = s.strip_prefix("monthly on ") {
        return parse_monthly(rest);
    }

    Err(format!("unrecognized schedule format: {}", s))
}

fn parse_every(s: &str) -> Result<HumanSchedule, String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 2 {
        return Err("expected 'every N <unit>'".into());
    }
    let amount: u32 = parts[0].parse().map_err(|_| "invalid number")?;
    let unit = match parts[1].trim_end_matches('s') {
        "minute" => TimeUnit::Minutes,
        "hour" => TimeUnit::Hours,
        "day" => TimeUnit::Days,
        other => return Err(format!("unknown time unit: {}", other)),
    };
    Ok(HumanSchedule::Every { amount, unit })
}

fn parse_time_of_day(s: &str) -> Result<TimeOfDay, String> {
    let s = s.trim();

    // 12-hour format: "4pm", "4:30pm", "12:00am"
    let (time_part, is_pm) = if let Some(t) = s.strip_suffix("pm") {
        (t.trim(), true)
    } else if let Some(t) = s.strip_suffix("am") {
        (t.trim(), false)
    } else {
        // 24-hour format: "16:00", "09:30"
        let parts: Vec<&str> = s.split(':').collect();
        return match parts.as_slice() {
            [h, m] => Ok(TimeOfDay {
                hour: h.parse().map_err(|_| "invalid hour")?,
                minute: m.parse().map_err(|_| "invalid minute")?,
            }),
            [h] => Ok(TimeOfDay {
                hour: h.parse().map_err(|_| "invalid hour")?,
                minute: 0,
            }),
            _ => Err("invalid time format".into()),
        };
    };

    let (hour_12, minute) = if let Some((h, m)) = time_part.split_once(':') {
        (
            h.parse::<u8>().map_err(|_| "invalid hour")?,
            m.parse::<u8>().map_err(|_| "invalid minute")?,
        )
    } else {
        (time_part.parse::<u8>().map_err(|_| "invalid hour")?, 0)
    };

    let hour = match (hour_12, is_pm) {
        (12, false) => 0,    // 12am = midnight
        (12, true) => 12,    // 12pm = noon
        (h, false) => h,     // am
        (h, true) => h + 12, // pm
    };

    Ok(TimeOfDay { hour, minute })
}

fn parse_weekday(s: &str) -> Result<Weekday, String> {
    match s.trim() {
        "monday" | "mon" => Ok(Weekday::Monday),
        "tuesday" | "tue" => Ok(Weekday::Tuesday),
        "wednesday" | "wed" => Ok(Weekday::Wednesday),
        "thursday" | "thu" => Ok(Weekday::Thursday),
        "friday" | "fri" => Ok(Weekday::Friday),
        "saturday" | "sat" => Ok(Weekday::Saturday),
        "sunday" | "sun" => Ok(Weekday::Sunday),
        other => Err(format!("unknown weekday: {}", other)),
    }
}

fn parse_weekly(s: &str) -> Result<HumanSchedule, String> {
    if let Some((day_str, rest)) = s.split_once(" at ") {
        let day = parse_weekday(day_str)?;
        let time = parse_time_of_day(rest)?;
        Ok(HumanSchedule::Weekly {
            day,
            time: Some(time),
        })
    } else {
        let day = parse_weekday(s)?;
        Ok(HumanSchedule::Weekly { day, time: None })
    }
}

fn parse_monthly(s: &str) -> Result<HumanSchedule, String> {
    if let Some((day_str, rest)) = s.split_once(" at ") {
        let day: u8 = day_str.parse().map_err(|_| "invalid day of month")?;
        let time = parse_time_of_day(rest)?;
        Ok(HumanSchedule::Monthly {
            day,
            time: Some(time),
        })
    } else {
        let day: u8 = s.parse().map_err(|_| "invalid day of month")?;
        Ok(HumanSchedule::Monthly { day, time: None })
    }
}

// --

#[derive(Debug, Clone)]
struct ScheduledJob {
    /// Job index
    index_in_group: usize,
    /// From the asset entry
    asset_name: String,
    /// Job description
    description: Option<String>,
    /// "username/task-name"
    task: Option<String>,
    /// Additional REPL steps
    steps: Option<Vec<String>>,
    /// Resolved timezone
    timezone: Tz,
    /// The schedule type
    schedule: ResolvedSchedule,
}

#[derive(Debug, Clone)]
enum ResolvedSchedule {
    Always,
    Cron(cron::Schedule),
    Human(HumanSchedule),
    AssetChange(String),
}

#[derive(Debug)]
struct DaemonState {
    asset_name: String,
    index_in_group: usize,
    task: Option<String>,
    steps: Option<Vec<String>>,
    child: Child,
}

/// State for an asset change watcher
struct AssetWatcherState {
    #[allow(dead_code)]
    /// The job key this watcher is for
    job_key: String,
    /// Handle to the spawned watcher task
    handle: tokio::task::JoinHandle<()>,
}

//
// Scheduler
//

async fn run_scheduler(
    job_groups: Arc<RwLock<Vec<AssetEntry>>>,
    notify: Arc<Notify>,
    api_client: crate::api::client::HaiClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Track running daemons (always-on tasks)
    let mut daemons: HashMap<String, DaemonState> = HashMap::new();

    // Track next run time for scheduled jobs
    let mut next_runs: HashMap<String, DateTime<Utc>> = HashMap::new();

    // Track asset change watchers
    let mut asset_watchers: HashMap<String, AssetWatcherState> = HashMap::new();

    loop {
        // Parse current job configurations
        let scheduled_jobs = {
            let assets = job_groups.read().await;
            parse_all_job_groups(&assets).await
        };

        // Reconcile daemons (start new ones, stop removed ones)
        reconcile_daemons(&scheduled_jobs, &mut daemons).await;

        // Check and restart any crashed daemons
        check_daemon_health(&mut daemons).await;

        // Reconcile asset watchers
        reconcile_asset_watchers(&scheduled_jobs, &mut asset_watchers, &api_client).await;

        // Update next_runs for any new/changed jobs
        update_next_runs(&scheduled_jobs, &mut next_runs);

        // Find the next job to run
        let now = Utc::now();
        let next_job = find_next_job(&next_runs, now);

        match next_job {
            Some((job_key, next_time)) if next_time <= now => {
                // Time to run this job
                if let Some(job) = scheduled_jobs.iter().find(|j| job_key_for(j) == job_key) {
                    execute_job(
                        &job_key,
                        job.description.as_deref(),
                        job.task.as_deref(),
                        job.steps.as_deref(),
                        None, // No asset revision for scheduled jobs
                    )
                    .await;

                    // Calculate next run time
                    if let Some(next) = calculate_next_run(&job.schedule, &job.timezone, now) {
                        println!("Next run at: {:?}", next);
                        next_runs.insert(job_key, next);
                    }
                }
            }
            Some((_, next_time)) => {
                // Sleep until next job or until notified of changes
                let sleep_duration = (next_time - now)
                    .to_std()
                    .unwrap_or(std::time::Duration::from_secs(1));

                let sleep_duration = sleep_duration.min(std::time::Duration::from_secs(60));

                tokio::select! {
                    _ = tokio::time::sleep(sleep_duration) => {}
                    _ = notify.notified() => {
                        // Jobs changed, loop around to re-parse
                        log_scheduler("Job configuration changed, reloading...");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        log_scheduler("Received Ctrl+C, shutting down scheduler...");
                        shutdown_all_daemons(&mut daemons).await;
                        shutdown_all_watchers(&mut asset_watchers).await;
                        return Ok(());
                    }
                }
            }
            None => {
                // No scheduled jobs, just wait for changes or check daemons
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                    _ = notify.notified() => {
                        log_scheduler("Job configuration changed, reloading...");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        log_scheduler("Received Ctrl+C, shutting down scheduler...");
                        shutdown_all_daemons(&mut daemons).await;
                        shutdown_all_watchers(&mut asset_watchers).await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Helper function to gracefully shutdown all daemons
async fn shutdown_all_daemons(daemons: &mut HashMap<String, DaemonState>) {
    log_scheduler(&format!("Stopping {} daemon(s)...", daemons.len()));
    for (name, mut daemon) in daemons.drain() {
        log_scheduler(&format!("Stopping daemon: {}", name));
        let _ = daemon.child.kill().await;
    }
}

/// Helper function to shutdown all asset watchers
async fn shutdown_all_watchers(watchers: &mut HashMap<String, AssetWatcherState>) {
    log_scheduler(&format!("Stopping {} asset watcher(s)...", watchers.len()));
    for (name, watcher) in watchers.drain() {
        log_scheduler(&format!("Stopping asset watcher: {}", name));
        watcher.handle.abort();
    }
}

// --

//
// Asset change watcher management
//

async fn reconcile_asset_watchers(
    jobs: &[ScheduledJob],
    watchers: &mut HashMap<String, AssetWatcherState>,
    api_client: &crate::api::client::HaiClient,
) {
    // Find all asset change jobs
    let asset_change_jobs: HashMap<String, &ScheduledJob> = jobs
        .iter()
        .filter_map(|j| {
            if let ResolvedSchedule::AssetChange(_) = &j.schedule {
                Some((job_key_for(j), j))
            } else {
                None
            }
        })
        .collect();

    // Stop watchers that are no longer configured
    let to_remove: Vec<String> = watchers
        .keys()
        .filter(|job_key| !asset_change_jobs.contains_key(*job_key))
        .cloned()
        .collect();

    for job_key in to_remove {
        if let Some(watcher) = watchers.remove(&job_key) {
            log_scheduler(&format!("Stopping asset watcher: {}", job_key));
            watcher.handle.abort();
        }
    }

    // Start new watchers
    for (job_key, job) in asset_change_jobs {
        if !watchers.contains_key(&job_key) {
            if let ResolvedSchedule::AssetChange(asset_name) = &job.schedule {
                log_scheduler(&format!(
                    "Starting asset watcher for job {} on asset: {}",
                    job_key, asset_name
                ));

                match spawn_asset_watcher(
                    api_client.clone(),
                    job_key.clone(),
                    asset_name.clone(),
                    job.task.clone(),
                    job.steps.clone(),
                    job.description.clone(),
                )
                .await
                {
                    Ok(handle) => {
                        watchers.insert(job_key.clone(), AssetWatcherState { job_key, handle });
                    }
                    Err(e) => {
                        log_scheduler(&format!("Failed to start asset watcher: {}", e));
                    }
                }
            }
        }
    }
}

/// Spawn an asset watcher that listens for changes to a specific asset
async fn spawn_asset_watcher(
    api_client: crate::api::client::HaiClient,
    job_key: String,
    asset_name: String,
    task: Option<String>,
    steps: Option<Vec<String>>,
    description: Option<String>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    use crate::api::types::asset::{AssetRevisionIterArg, EntryRef, RevisionIterDirection};

    // Get initial cursor (latest revision) - we don't want to process existing versions
    let initial_cursor = match api_client
        .asset_revision_iter(AssetRevisionIterArg {
            entry_ref: EntryRef::Name(asset_name.clone()),
            limit: 1,
            direction: RevisionIterDirection::Newer,
        })
        .await
    {
        Ok(iter_res) => iter_res.next.map(|n| n.cursor),
        Err(e) => {
            log_scheduler(&format!(
                "Warning: Could not get initial cursor for asset '{}': {}. Will retry on connection.",
                asset_name, e
            ));
            None
        }
    };

    let handle = tokio::spawn(async move {
        asset_watcher_loop(
            api_client,
            job_key,
            asset_name,
            task,
            steps,
            description,
            initial_cursor,
        )
        .await;
    });

    Ok(handle)
}

/// The main loop for watching an asset for changes
async fn asset_watcher_loop(
    api_client: crate::api::client::HaiClient,
    job_key: String,
    asset_name: String,
    task: Option<String>,
    steps: Option<Vec<String>>,
    description: Option<String>,
    initial_cursor: Option<String>,
) {
    use crate::api::types::asset::{
        AssetRevisionIterArg, AssetRevisionIterNextArg, EntryRef, RevisionIterDirection,
    };
    use crate::api::types::notify::{ListenAsset, NotifyListenArg};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let listen_url = format!(
        "{}/notify/listen",
        crate::session::get_api_base_url().replace("http", "ws")
    );

    // If we don't have an initial cursor, we need to get one
    let mut current_cursor = match initial_cursor {
        Some(cursor) => cursor,
        None => {
            // Keep trying to get a cursor
            loop {
                match api_client
                    .asset_revision_iter(AssetRevisionIterArg {
                        entry_ref: EntryRef::Name(asset_name.clone()),
                        limit: 1,
                        direction: RevisionIterDirection::Newer,
                    })
                    .await
                {
                    Ok(iter_res) => {
                        if let Some(next) = iter_res.next {
                            break next.cursor;
                        }
                        log_scheduler(&format!(
                            "Asset '{}' has no revisions yet, waiting...",
                            asset_name
                        ));
                    }
                    Err(e) => {
                        log_scheduler(&format!(
                            "Error getting cursor for asset '{}': {}, retrying...",
                            asset_name, e
                        ));
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    };

    let mut attempt = 0;

    loop {
        let arg = NotifyListenArg::Asset(ListenAsset {
            cursor: current_cursor.clone(),
        });

        let (mut ws_stream, _) = match connect_async(&listen_url).await {
            Ok(res) => res,
            Err(e) => {
                log_scheduler(&format!(
                    "Asset watcher '{}': failed to connect: {}",
                    job_key, e
                ));
                attempt += 1;
                let backoff_duration = std::time::Duration::from_secs(2_u64.pow(attempt).min(60));
                log_scheduler(&format!(
                    "Asset watcher '{}': retrying in {} seconds...",
                    job_key,
                    backoff_duration.as_secs()
                ));
                tokio::time::sleep(backoff_duration).await;
                continue;
            }
        };

        if attempt > 0 {
            log_scheduler(&format!("Asset watcher '{}': connected", job_key));
            attempt = 0;
        }

        if let Err(e) = ws_stream
            .send(Message::Text(serde_json::to_string(&arg).unwrap().into()))
            .await
        {
            log_scheduler(&format!(
                "Asset watcher '{}': error sending listen arg: {}",
                job_key, e
            ));
            continue;
        }

        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(_msg) => {
                    // Received a notification - fetch new revisions
                    log_scheduler(&format!(
                        "Asset watcher '{}': change detected on '{}'",
                        job_key, asset_name
                    ));

                    match api_client
                        .asset_revision_iter_next(AssetRevisionIterNextArg {
                            cursor: current_cursor.clone(),
                            limit: 100, // Process up to 100 revisions at once
                        })
                        .await
                    {
                        Ok(iter_res) => {
                            for revision in iter_res.revisions {
                                let rev_id = &revision.asset.rev_id;
                                log_scheduler(&format!(
                                    "Asset watcher '{}': executing job for revision {}",
                                    job_key, rev_id
                                ));

                                // Execute the job with the asset revision
                                execute_job(
                                    &job_key,
                                    description.as_deref(),
                                    task.as_deref(),
                                    steps.as_deref(),
                                    Some((&asset_name, rev_id)),
                                )
                                .await;
                            }

                            // Update cursor
                            if let Some(next) = iter_res.next {
                                current_cursor = next.cursor;
                            }
                        }
                        Err(e) => {
                            log_scheduler(&format!(
                                "Asset watcher '{}': error fetching revisions: {}",
                                job_key, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    if !e
                        .to_string()
                        .contains("Connection reset without closing handshake")
                    {
                        log_scheduler(&format!(
                            "Asset watcher '{}': websocket error: {}",
                            job_key, e
                        ));
                    }
                    break; // Reconnect
                }
            }
        }
    }
}

// --

//
// Job config parsing
//

async fn parse_all_job_groups(asset_entries: &[AssetEntry]) -> Vec<ScheduledJob> {
    let mut jobs = Vec::new();

    for asset_entry in asset_entries {
        let data_url = if let Some(data_url) = asset_entry.asset.url.as_ref() {
            data_url.clone()
        } else {
            log_scheduler(&format!("Asset {} has no URL, skipping", asset_entry.name));
            continue;
        };
        match crate::asset_reader::get_asset_raw(&data_url).await {
            Some(toml_content) => {
                let toml_str = String::from_utf8_lossy(&toml_content);
                match toml::from_str::<JobGroupConfig>(&toml_str) {
                    Ok(group_config) => {
                        let default_tz: Tz = match group_config.timezone.parse() {
                            Ok(tz) => tz,
                            Err(e) => {
                                log_scheduler(&format!(
                                    "Job config in asset {} has an invalid timezone: {}",
                                    asset_entry.name, e
                                ));
                                continue;
                            }
                        };

                        for (index, job_config) in group_config.job.into_iter().enumerate() {
                            if job_config.task.is_none() && job_config.steps.is_none() {
                                log_scheduler(&format!(
                                    "Job {} in asset {} has no task or steps specified, skipping",
                                    index, asset_entry.name
                                ));
                                continue;
                            }
                            let tz = job_config
                                .timezone
                                .as_ref()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(default_tz);

                            let schedule = resolve_schedule(&job_config);

                            if let Some(schedule) = schedule {
                                jobs.push(ScheduledJob {
                                    index_in_group: index,
                                    asset_name: asset_entry.name.clone(),
                                    description: job_config.description,
                                    task: job_config.task,
                                    steps: job_config.steps,
                                    timezone: tz,
                                    schedule,
                                });
                            } else {
                                log_scheduler(&format!(
                                    "Job {} in asset {} has an invalid schedule, skipping",
                                    index, asset_entry.name
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        log_scheduler(&format!(
                            "Failed to parse job group {}: {}",
                            asset_entry.name, e
                        ));
                    }
                }
            }
            None => {
                log_scheduler(&format!("Failed to download asset: {}", asset_entry.name));
            }
        }
    }

    jobs
}

fn resolve_schedule(job: &JobConfig) -> Option<ResolvedSchedule> {
    if let Some(ref human) = job.schedule {
        return Some(match human {
            HumanSchedule::Always => ResolvedSchedule::Always,
            other => ResolvedSchedule::Human(other.clone()),
        });
    }

    if let Some(ref cron_str) = job.cron {
        match cron_str.parse::<cron::Schedule>() {
            Ok(schedule) => return Some(ResolvedSchedule::Cron(schedule)),
            Err(e) => {
                log_scheduler(&format!("Invalid cron expression '{}': {}", cron_str, e));
                return None;
            }
        }
    }

    if let Some(ref asset_name) = job.asset_change {
        if crate::asset_helper::is_likely_valid_asset_name(asset_name) {
            return Some(ResolvedSchedule::AssetChange(asset_name.clone()));
        } else {
            log_scheduler(&format!(
                "Job ({}) has invalid asset change name '{}'",
                job.description.as_deref().unwrap_or("<no description>"),
                asset_name
            ));
            return None;
        }
    }

    log_scheduler(&format!(
        "Job ({}) has no schedule or cron",
        job.description.as_deref().unwrap_or("<no description>")
    ));
    None
}

fn job_key_for(job: &ScheduledJob) -> String {
    format!("{}:{}", job.asset_name, job.index_in_group)
}

// --

//
// Daemon management
//

async fn reconcile_daemons(jobs: &[ScheduledJob], daemons: &mut HashMap<String, DaemonState>) {
    // Find all "always" jobs
    let always_tasks: HashMap<String, &ScheduledJob> = jobs
        .iter()
        .filter(|j| matches!(j.schedule, ResolvedSchedule::Always))
        .map(|j| (job_key_for(j), j))
        .collect();

    // Stop daemons that are no longer configured
    let to_remove: Vec<String> = daemons
        .keys()
        .filter(|job_key| !always_tasks.contains_key(*job_key))
        .cloned()
        .collect();

    for job_key in to_remove {
        if let Some(mut daemon) = daemons.remove(&job_key) {
            log_scheduler(&format!("Stopping daemon: {}", job_key));
            let _ = daemon.child.kill().await;
        }
    }

    // Start new daemons
    for (job_key, job) in always_tasks {
        if !daemons.contains_key(&job_key) {
            log_scheduler(&format!("Starting daemon: {}", job_key));
            match spawn_daemon(job.task.as_deref(), job.steps.as_deref()).await {
                Ok(child) => {
                    daemons.insert(
                        job_key,
                        DaemonState {
                            asset_name: job.asset_name.clone(),
                            index_in_group: job.index_in_group,
                            task: job.task.clone(),
                            steps: job.steps.clone(),
                            child,
                        },
                    );
                }
                Err(e) => {
                    log_scheduler(&format!("Failed to start daemon {}: {}", job_key, e));
                }
            }
        }
    }
}

async fn check_daemon_health(daemons: &mut HashMap<String, DaemonState>) {
    let mut to_restart = Vec::new();

    for (job_key, daemon) in daemons.iter_mut() {
        match daemon.child.try_wait() {
            Ok(Some(status)) => {
                // Process exited
                log_scheduler(&format!(
                    "Daemon {} exited with status {:?}, will restart",
                    job_key, status
                ));
                to_restart.push((
                    job_key.clone(),
                    daemon.asset_name.clone(),
                    daemon.index_in_group,
                    daemon.task.clone(),
                    daemon.steps.clone(),
                ));
            }
            Ok(None) => {
                // Still running, good
            }
            Err(e) => {
                log_scheduler(&format!(
                    "Error checking daemon {} status: {}, will restart",
                    job_key, e
                ));
                to_restart.push((
                    job_key.clone(),
                    daemon.asset_name.clone(),
                    daemon.index_in_group,
                    daemon.task.clone(),
                    daemon.steps.clone(),
                ));
            }
        }
    }

    for (job_key, asset_name, index_in_group, task, steps) in to_restart.iter() {
        daemons.remove(job_key);
        log_scheduler(&format!("Restarting daemon: {}", job_key));
        match spawn_daemon(task.as_deref(), steps.as_deref()).await {
            Ok(child) => {
                daemons.insert(
                    job_key.clone(),
                    DaemonState {
                        asset_name: asset_name.clone(),
                        index_in_group: *index_in_group,
                        task: task.clone(),
                        steps: steps.clone(),
                        child,
                    },
                );
            }
            Err(e) => {
                log_scheduler(&format!("Failed to restart daemon {}: {}", job_key, e));
            }
        }
    }
}

async fn spawn_daemon(
    task: Option<&str>,
    steps: Option<&[String]>,
) -> Result<Child, std::io::Error> {
    let mut args = vec!["bye".to_string()];
    if let Some(task) = task {
        args.push(format!("/task.trust {}", task));
    }
    if let Some(steps) = steps {
        args.extend(steps.iter().cloned());
    }

    Command::new("hai")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

// --

//
// Scheduled job execution
//

fn update_next_runs(jobs: &[ScheduledJob], next_runs: &mut HashMap<String, DateTime<Utc>>) {
    let now = Utc::now();

    // Remove entries for jobs that no longer exist
    let current_keys: std::collections::HashSet<String> = jobs
        .iter()
        .filter(|j| {
            !matches!(
                j.schedule,
                ResolvedSchedule::Always | ResolvedSchedule::AssetChange(_)
            )
        })
        .map(job_key_for)
        .collect();

    next_runs.retain(|k, _| current_keys.contains(k));

    // Add entries for new jobs
    for job in jobs {
        if matches!(
            job.schedule,
            ResolvedSchedule::Always | ResolvedSchedule::AssetChange(_)
        ) {
            continue; // Daemons and asset watchers handled separately
        }

        let key = job_key_for(job);
        if !next_runs.contains_key(&key) {
            if let Some(next) = calculate_next_run(&job.schedule, &job.timezone, now) {
                next_runs.insert(key, next);
            }
        }
    }
}

fn find_next_job(
    next_runs: &HashMap<String, DateTime<Utc>>,
    _now: DateTime<Utc>,
) -> Option<(String, DateTime<Utc>)> {
    next_runs
        .iter()
        .min_by_key(|(_, time)| *time)
        .map(|(k, t)| (k.clone(), *t))
}

fn calculate_next_run(
    schedule: &ResolvedSchedule,
    tz: &Tz,
    after: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match schedule {
        ResolvedSchedule::Always => None, // Handled by daemon system

        ResolvedSchedule::AssetChange(_) => None, // Handled by asset watcher system

        ResolvedSchedule::Cron(cron_schedule) => cron_schedule.after(&after).next(),

        ResolvedSchedule::Human(human) => calculate_next_human_schedule(human, tz, after),
    }
}

fn calculate_next_human_schedule(
    schedule: &HumanSchedule,
    tz: &Tz,
    after: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let after_local = after.with_timezone(tz);

    let next_local = match schedule {
        HumanSchedule::Always => return None,

        HumanSchedule::Every { amount, unit } => {
            let duration = match unit {
                TimeUnit::Minutes => chrono::Duration::minutes(*amount as i64),
                TimeUnit::Hours => chrono::Duration::hours(*amount as i64),
                TimeUnit::Days => chrono::Duration::days(*amount as i64),
            };
            after_local + duration
        }

        HumanSchedule::Hourly { minute } => {
            let target_minute = minute.unwrap_or(0);
            let mut next = after_local
                .with_minute(target_minute)
                .unwrap()
                .with_second(0)
                .unwrap();

            if next <= after_local {
                next = next + chrono::Duration::hours(1);
            }
            next
        }

        HumanSchedule::Daily { time } => {
            let mut next = after_local
                .with_hour(time.hour as u32)
                .unwrap()
                .with_minute(time.minute as u32)
                .unwrap()
                .with_second(0)
                .unwrap();

            if next <= after_local {
                next = next + chrono::Duration::days(1);
            }
            next
        }

        HumanSchedule::Weekly { day, time } => {
            let target_weekday = to_chrono_weekday(day);
            let target_time = time.as_ref().map(|t| (t.hour, t.minute)).unwrap_or((0, 0));

            let mut next = after_local
                .with_hour(target_time.0 as u32)
                .unwrap()
                .with_minute(target_time.1 as u32)
                .unwrap()
                .with_second(0)
                .unwrap();

            // Find next occurrence of target weekday
            let days_ahead = (target_weekday.num_days_from_monday() as i64
                - next.weekday().num_days_from_monday() as i64
                + 7)
                % 7;

            next = next + chrono::Duration::days(days_ahead);

            if next <= after_local {
                next = next + chrono::Duration::weeks(1);
            }
            next
        }

        HumanSchedule::Monthly { day, time } => {
            let target_time = time.as_ref().map(|t| (t.hour, t.minute)).unwrap_or((0, 0));

            let mut next = after_local
                .with_day(*day as u32)
                .unwrap_or_else(|| {
                    // Day doesn't exist in this month, use last day
                    let last_day = last_day_of_month(after_local.year(), after_local.month());
                    after_local.with_day(last_day).unwrap()
                })
                .with_hour(target_time.0 as u32)
                .unwrap()
                .with_minute(target_time.1 as u32)
                .unwrap()
                .with_second(0)
                .unwrap();

            if next <= after_local {
                // Move to next month
                let (year, month) = if after_local.month() == 12 {
                    (after_local.year() + 1, 1)
                } else {
                    (after_local.year(), after_local.month() + 1)
                };
                use chrono::{NaiveDate, TimeZone};
                let target_day = (*day as u32).min(last_day_of_month(year, month));
                let date = NaiveDate::from_ymd_opt(year, month, target_day)?;
                let time =
                    chrono::NaiveTime::from_hms_opt(target_time.0 as u32, target_time.1 as u32, 0)?;
                let naive_dt = date.and_time(time);
                next = tz.from_local_datetime(&naive_dt).single()?;
            }
            next
        }
    };

    Some(next_local.with_timezone(&Utc))
}

fn to_chrono_weekday(day: &Weekday) -> ChronoWeekday {
    match day {
        Weekday::Monday => ChronoWeekday::Mon,
        Weekday::Tuesday => ChronoWeekday::Tue,
        Weekday::Wednesday => ChronoWeekday::Wed,
        Weekday::Thursday => ChronoWeekday::Thu,
        Weekday::Friday => ChronoWeekday::Fri,
        Weekday::Saturday => ChronoWeekday::Sat,
        Weekday::Sunday => ChronoWeekday::Sun,
    }
}

fn last_day_of_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

// --

//
// Job execution
//

/// Returns the command and initial args needed to re-invoke this program.
fn self_invocation() -> (String, Vec<String>) {
    // Check if we're running under cargo
    // When run via `cargo run`, CARGO env var is set
    if let Ok(cargo) = std::env::var("CARGO") {
        // We're in a cargo run context
        // Reconstruct: cargo run --
        let mut args = vec!["run".to_string()];

        // Preserve the package name if in a workspace
        if let Ok(pkg) = std::env::var("CARGO_PKG_NAME") {
            args.push("-p".to_string());
            args.push(pkg);
        }

        args.push("--".to_string());

        return (cargo, args);
    }

    // Production: use the current executable path
    let exe = std::env::current_exe()
        .expect("Failed to determine current executable path")
        .to_string_lossy()
        .to_string();

    (exe, vec![])
}

async fn execute_job(
    job_key: &str,
    description: Option<&str>,
    task: Option<&str>,
    steps: Option<&[String]>,
    asset_revision: Option<(&str, &str)>,
) {
    log_scheduler(&format!("Executing job: {} ({:?})", job_key, description));

    let (program, mut args) = self_invocation();

    args.push("bye".to_string());

    if let Some((asset_name, rev_id)) = asset_revision {
        args.push(format!("/asset-revision-temp {} {}", asset_name, rev_id));
    }

    if let Some(task) = task {
        args.push(format!("/task.trust {}", task));
    }
    if let Some(steps) = steps {
        args.extend(steps.iter().cloned());
    }

    log_scheduler(&format!("Invoking: {} {}", program, args.join(" ")));

    let result = Command::new(&program)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await;

    match result {
        Ok(output) => {
            if output.status.success() {
                log_scheduler(&format!(
                    "Job {} completed successfully: {}",
                    job_key,
                    String::from_utf8_lossy(&output.stdout)
                ));
            } else {
                log_scheduler(&format!(
                    "Job {} failed with status {:?}: {}",
                    job_key,
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        Err(e) => {
            log_scheduler(&format!("Failed to execute job {}: {}", job_key, e));
        }
    }
}

// --

fn log_scheduler(msg: &str) {
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let log_line = format!("[{}] {}\n", timestamp, msg);

    // Append to log file
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config::get_bot_log_path())
    {
        let _ = file.write_all(log_line.as_bytes());
    }

    // Also print if stdout is available
    print!("{}", log_line);
}
