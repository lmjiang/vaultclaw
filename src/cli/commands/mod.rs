pub mod security;
pub mod agent;
pub mod sync_cmd;
pub mod daemon_cmd;
pub mod vault_cmd;
pub mod browser_cmd;
pub mod inject_cmd;
pub mod lease_cmd;
pub mod redact_cmd;
pub mod run_cmd;
pub mod scan_cmd;
pub mod yubikey_cmd;
pub mod passkey_cmd;
pub mod backup_cmd;
pub mod completions_cmd;
pub mod config_cmd;
#[cfg(target_os = "macos")]
pub mod touchid_cmd;

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use crate::config::{self, AppConfig};
use crate::crypto::kdf::KdfParams;
use crate::crypto::keys::password_secret;
use crate::daemon::client::DaemonClient;
use crate::daemon::protocol::{Request, ResponseData};
use crate::import::onepassword;
use crate::totp;
use crate::vault::entry::*;
use crate::vault::format::VaultFile;
use crate::vault::search::fuzzy_search;

#[derive(Parser)]
#[command(name = "vaultclaw", about = "Local-first credential manager")]
pub struct Cli {
    /// Path to vault file (overrides config default)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Suppress non-essential output
    #[arg(long, global = true)]
    quiet: bool,

    /// Skip daemon, always use direct vault access
    #[arg(long, global = true)]
    no_daemon: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new vault
    Init,

    /// Get a credential by name (fuzzy match)
    Get {
        /// Search query
        query: String,
        /// Copy password to clipboard
        #[arg(short, long)]
        clip: bool,
    },

    /// Add a new credential
    Add {
        /// Entry title
        #[arg(short, long)]
        title: String,
        /// Credential type
        #[arg(short = 'T', long, default_value = "login")]
        r#type: String,
        /// URL
        #[arg(short, long)]
        url: Option<String>,
        /// Username
        #[arg(short = 'U', long)]
        username: Option<String>,
        /// Password (prompted if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Category
        #[arg(short, long)]
        category: Option<String>,
        /// Tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,
        /// Notes
        #[arg(short, long)]
        notes: Option<String>,
        /// TOTP secret
        #[arg(long)]
        totp: Option<String>,
        /// Mark as favorite
        #[arg(short, long)]
        favorite: bool,
        /// Mark as sensitive (requires manual approval for agent access)
        #[arg(long)]
        sensitive: bool,
    },

    /// Edit an existing credential
    Edit {
        /// Entry ID or title to search
        query: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(short, long)]
        url: Option<String>,
        #[arg(short = 'U', long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        category: Option<String>,
        #[arg(long)]
        tags: Option<String>,
        #[arg(short, long)]
        notes: Option<String>,
        #[arg(long)]
        totp: Option<String>,
        #[arg(short, long)]
        favorite: Option<bool>,
        /// Set sensitive flag
        #[arg(long)]
        sensitive: Option<bool>,
    },

    /// Delete a credential
    Rm {
        /// Entry ID or title to search
        query: String,
    },

    /// List credentials
    Ls {
        /// Filter by tag
        #[arg(long)]
        tag: Option<String>,
        /// Filter by category
        #[arg(long, alias = "cat")]
        category: Option<String>,
        /// Show favorites only
        #[arg(long)]
        favorites: bool,
    },

    /// Search credentials
    Search {
        /// Search query
        query: String,
    },

    /// Show TOTP code for an entry
    Totp {
        /// Entry title or ID
        query: String,
        /// Copy code to clipboard
        #[arg(short, long)]
        clip: bool,
    },

    /// Generate a random password
    Gen {
        /// Password length
        #[arg(short, long, default_value = "24")]
        length: usize,
        /// Copy to clipboard
        #[arg(short, long)]
        clip: bool,
    },

    /// Export vault
    Export {
        /// Output format (json or csv)
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import credentials
    Import {
        /// Source format
        #[arg(long)]
        from: String,
        /// Input file
        file: PathBuf,
        /// Dry run (show what would be imported)
        #[arg(long)]
        dry_run: bool,
    },

    /// Show vault status
    Status,

    /// Check vault password health
    Health,

    /// Check passwords against breach databases
    Breach {
        /// Check all entries (not just weak ones)
        #[arg(long)]
        all: bool,
        /// Check a specific entry by title
        #[arg(long)]
        entry: Option<String>,
    },

    /// Generate a full security report (Watchtower-style dashboard)
    Watch,

    /// Generate an AI-enhanced security report
    Report,

    /// Manage password rotation
    Rotate {
        #[command(subcommand)]
        command: security::RotateCommands,
    },

    /// Agent gateway management
    Agent {
        #[command(subcommand)]
        command: agent::AgentCommands,
    },

    /// Sync vault to/from remote
    Sync {
        #[command(subcommand)]
        command: sync_cmd::SyncCommands,
    },

    /// Manage vault backups
    Backup {
        #[command(subcommand)]
        command: backup_cmd::BackupCommands,
    },

    /// Manage the background daemon
    Daemon {
        #[command(subcommand)]
        command: daemon_cmd::DaemonCommands,
    },

    /// Manage multiple vaults
    Vault {
        #[command(subcommand)]
        command: vault_cmd::VaultCommands,
    },

    /// Manage browser extension native messaging host
    BrowserHost {
        #[command(subcommand)]
        command: browser_cmd::BrowserHostCommands,
    },

    /// Manage credential leases
    Lease {
        #[command(subcommand)]
        command: lease_cmd::LeaseCommands,
    },

    /// Manage per-agent rate limits
    RateLimit {
        #[command(subcommand)]
        command: RateLimitCommands,
    },

    /// Run a command with vclaw:// credential references resolved
    Run {
        /// .env file to resolve vclaw:// references in
        #[arg(long)]
        env: Option<PathBuf>,
        /// Config file to resolve vclaw:// references in (written to secure temp file)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Environment variable name for the resolved config file path
        #[arg(long, default_value = "VAULTCLAW_CONFIG")]
        config_var: String,
        /// Redact injected secrets from child process stdout/stderr
        #[arg(long)]
        redact_output: bool,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Resolve vclaw:// and vault:// references in a config file, output to stdout
    Inject {
        /// Config file to resolve (JSON, YAML, TOML, .env — any text format)
        file: PathBuf,
    },

    /// Scan text for credential patterns and redact them
    Redact {
        /// File to redact (reads stdin if not specified)
        file: Option<PathBuf>,
        /// Scan only: report matches without redacting
        #[arg(long)]
        scan: bool,
        /// Add custom regex detection pattern(s)
        #[arg(long = "pattern")]
        patterns: Vec<String>,
        /// Output redaction summary report to stderr
        #[arg(long)]
        report: bool,
        /// Disable entropy-based detection
        #[arg(long)]
        no_entropy: bool,
        /// Enable PII anonymization (username/path scrubbing)
        #[arg(long)]
        anonymize: bool,
        /// Additional usernames to anonymize (comma-separated)
        #[arg(long)]
        extra_usernames: Option<String>,
        /// Display active allowlist rules
        #[arg(long)]
        show_allowlist: bool,
    },

    /// Scan files for plaintext secrets and optionally migrate to vclaw:// references
    Scan {
        /// Path to scan (file or directory)
        path: PathBuf,
        /// Import secrets to vault and replace with vclaw:// references
        #[arg(long)]
        fix: bool,
        /// Show what --fix would do without changing anything
        #[arg(long)]
        dry_run: bool,
        /// Add custom regex detection pattern(s)
        #[arg(long = "pattern")]
        patterns: Vec<String>,
    },

    /// Unlock the vault in the running daemon
    Unlock {
        /// Unlock using a recovery key instead of master password
        #[arg(long)]
        recovery: bool,
        /// Unlock using Touch ID (macOS only)
        #[arg(long)]
        touchid: bool,
    },

    /// Manage stored passkeys (WebAuthn discoverable credentials)
    Passkey {
        #[command(subcommand)]
        command: passkey_cmd::PasskeyCommands,
    },

    /// Manage YubiKey enrollment and recovery keys
    Yubikey {
        #[command(subcommand)]
        command: yubikey_cmd::YubiKeyCommands,
    },

    /// Manage Touch ID enrollment for biometric vault unlock (macOS only)
    #[cfg(target_os = "macos")]
    Touchid {
        #[command(subcommand)]
        command: touchid_cmd::TouchIdCommands,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: ShellArg,
    },

    /// Manage application configuration
    Config {
        #[command(subcommand)]
        command: config_cmd::ConfigCommands,
    },

    /// Generate man page to stdout
    Manpage,
}

/// Shell argument for completion generation.
#[derive(Copy, Clone, ValueEnum)]
pub enum ShellArg {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
}

#[derive(Subcommand)]
pub enum RateLimitCommands {
    /// Set rate limit for an agent
    Set {
        /// Agent ID
        agent_id: String,
        /// Max requests per minute (0 = unlimited)
        #[arg(long)]
        rpm: u32,
        /// Max requests per hour (0 = unlimited)
        #[arg(long)]
        rph: u32,
        /// Auto-revoke tokens on anomaly detection
        #[arg(long)]
        auto_revoke: bool,
    },
    /// Remove rate limit for an agent
    Remove {
        /// Agent ID
        agent_id: String,
    },
    /// List all configured rate limits
    List,
}

#[rustfmt::skip]
/// Read password from terminal without echoing.
pub fn read_password(prompt: &str) -> String { eprint!("{}", prompt); io::stderr().flush().unwrap(); rpassword::read_password().unwrap_or_default() }

#[rustfmt::skip]
/// Execute the CLI command.
pub fn execute(cli: Cli) -> anyhow::Result<()> { execute_impl(cli, read_password) }

fn execute_impl(cli: Cli, get_pw: impl Fn(&str) -> String) -> anyhow::Result<()> {
    let config = AppConfig::load();
    let vault_path = cli.vault.unwrap_or(config.vault_path.clone());
    let json_output = cli.json;

    // Auto-detect daemon unless --no-daemon or command doesn't need it
    let daemon = if cli.no_daemon {
        None
    } else {
        DaemonClient::try_connect(&config.socket_path)
    };

    match cli.command {
        // Never use daemon
        Commands::Init => {
            if vault_path.exists() {
                anyhow::bail!("Vault already exists at {}", vault_path.display());
            }
            if let Some(parent) = vault_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let pw1 = get_pw("New master password: ");
            let pw2 = get_pw("Confirm master password: ");
            if pw1 != pw2 {
                anyhow::bail!("Passwords do not match");
            }
            let password = password_secret(pw1);
            VaultFile::create(&vault_path, &password, KdfParams::default())?;
            println!("Vault created at {}", vault_path.display());
        }
        Commands::Gen { length, clip } => cmd_gen(length, clip, json_output, &config)?,

        // Daemon management
        Commands::Daemon { command } => {
            daemon_cmd::handle_daemon_command(command, &config, json_output)?
        }
        Commands::Unlock { recovery, touchid } => {
            if recovery {
                daemon_cmd::cmd_unlock_recovery(&config, get_pw, json_output)?
            } else if touchid {
                #[cfg(target_os = "macos")]
                {
                    daemon_cmd::cmd_unlock_touchid(&config, &vault_path, json_output)?
                }
                #[cfg(not(target_os = "macos"))]
                {
                    anyhow::bail!("Touch ID is only available on macOS");
                }
            } else {
                daemon_cmd::cmd_unlock(&config, get_pw, json_output)?
            }
        }

        // Auto-detect: use daemon when available, fallback to direct
        Commands::Get { query, clip } => {
            if let Some(mut client) = daemon {
                cmd_get_via_daemon(&mut client, &query, clip, json_output, &config)?
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_get_with_vault(&vault, &query, clip, json_output, &config)?
            }
        }
        Commands::Ls { tag, category, favorites } => {
            if let Some(mut client) = daemon {
                cmd_ls_via_daemon(&mut client, tag, category, favorites, json_output)?
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_ls_with_vault(&vault, tag, category, favorites, json_output)?
            }
        }
        Commands::Search { query } => {
            if let Some(mut client) = daemon {
                cmd_search_via_daemon(&mut client, &query, json_output)?
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_search_with_vault(&vault, &query, json_output)?
            }
        }
        Commands::Totp { query, clip } => {
            if let Some(mut client) = daemon {
                cmd_totp_via_daemon(&mut client, &query, clip, json_output, &config)?
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_totp_with_vault(&vault, &query, clip, json_output, &config)?
            }
        }
        Commands::Status => {
            if let Some(mut client) = daemon {
                cmd_status_via_daemon(&mut client, json_output)?
            } else if !vault_path.exists() {
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "exists": false,
                        "path": vault_path.display().to_string(),
                    }))?);
                } else {
                    println!("No vault found at {}", vault_path.display());
                    println!("Run 'vaultclaw init' to create one.");
                }
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_status_with_vault(&vault, &vault_path, json_output)?
            }
        }
        Commands::Add {
            title, r#type, url, username, password,
            category, tags, notes, totp, favorite, sensitive,
        } => {
            if let Some(mut client) = daemon {
                cmd_add_via_daemon(&mut client, title, r#type, url, username, password, category, tags, notes, totp, favorite, sensitive)?
            } else {
                let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_add_with_vault(&mut vault, title, r#type, url, username, password, category, tags, notes, totp, favorite, sensitive)?
            }
        }
        Commands::Edit {
            query, title, url, username, password,
            category, tags, notes, totp, favorite, sensitive,
        } => {
            if let Some(mut client) = daemon {
                cmd_edit_via_daemon(&mut client, query, title, url, username, password, category, tags, notes, totp, favorite, sensitive)?
            } else {
                let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_edit_with_vault(&mut vault, query, title, url, username, password, category, tags, notes, totp, favorite, sensitive)?
            }
        }
        Commands::Rm { query } => {
            if let Some(mut client) = daemon {
                cmd_rm_via_daemon(&mut client, &query)?
            } else {
                let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_rm_with_vault(&mut vault, &query)?
            }
        }
        Commands::Export { format, output } => {
            if let Some(mut client) = daemon {
                cmd_export_via_daemon(&mut client, &format, output)?
            } else {
                let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                cmd_export_with_vault(&vault, &format, output)?
            }
        }

        // Agent: daemon preferred for state persistence
        Commands::Agent { command } => {
            if let Some(mut client) = daemon {
                agent::handle_agent_command_via_daemon(&mut client, command, json_output)?
            } else {
                agent::handle_agent_command(command, json_output)?
            }
        }

        // Direct-mode only
        Commands::Import { from, file, dry_run } => {
            let result = match from.as_str() {
                "1password" | "1password-csv" => onepassword::import_csv(&file)?,
                "1password-1pif" | "1pif" => onepassword::import_1pif(&file)?,
                _ => anyhow::bail!("Unsupported import format: {}. Use '1password' or '1pif'.", from),
            };
            println!("Processed: {} entries", result.total_processed);
            println!("Importable: {} entries", result.imported.len());
            if !result.skipped.is_empty() {
                println!("Skipped: {} entries", result.skipped.len());
                for (title, reason) in &result.skipped {
                    println!("  - {} ({})", title, reason);
                }
            }
            if dry_run {
                println!("\nDry run — no changes made.");
                for entry in &result.imported {
                    print_entry_summary(entry);
                }
            } else {
                let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
                for entry in result.imported {
                    vault.store_mut().add(entry);
                }
                vault.save()?;
                println!("Import complete.");
            }
        }
        Commands::Sync { command } => {
            sync_cmd::handle_sync_command(command, &vault_path, json_output)?
        }
        Commands::Backup { command } => {
            backup_cmd::handle_backup_command(command, &vault_path, json_output)?
        }
        Commands::Health => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            security::cmd_health_with_vault(&vault, json_output)?
        }
        Commands::Breach { all, entry } => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            security::cmd_breach_with_vault(&vault, all, entry.as_deref(), json_output)?
        }
        Commands::Watch => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            security::cmd_watch_with_vault(&vault, json_output)?
        }
        Commands::Report => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            security::cmd_report_with_vault(&vault, json_output)?
        }
        Commands::Rotate { command } => {
            let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            security::handle_rotate_command(command, &mut vault, json_output)?
        }
        Commands::Vault { command } => {
            vault_cmd::handle_vault_command(command, json_output)?
        }
        Commands::BrowserHost { command } => {
            browser_cmd::handle_browser_host_command(command, json_output)?
        }

        // Run: wraps a command with resolved vclaw:// refs
        Commands::Run { env, config, config_var, redact_output, command } => {
            let exit_code = run_cmd::handle_run_command(
                daemon, &vault_path, get_pw, env, config, config_var, redact_output, command,
            )?;
            std::process::exit(exit_code);
        }

        // Inject: resolve vclaw:// and vault:// references in a config file
        Commands::Inject { file } => {
            inject_cmd::handle_inject_command(daemon, &vault_path, get_pw, &file)?
        }

        // Redact: scan and redact credential patterns
        Commands::Redact { file, scan, patterns, report, no_entropy, anonymize, extra_usernames, show_allowlist } => {
            redact_cmd::handle_redact_command(
                file.as_deref(), scan, &patterns, json_output,
                report, no_entropy, anonymize,
                extra_usernames.as_deref(), show_allowlist,
            )?
        }

        // Scan: find plaintext secrets
        Commands::Scan { path, fix, dry_run, patterns } => {
            scan_cmd::handle_scan_command(
                path, json_output, dry_run, fix, patterns, &vault_path, get_pw,
            )?
        }

        // Lease: requires daemon
        Commands::Lease { command } => {
            let mut client = daemon.ok_or_else(|| {
                anyhow::anyhow!("Lease commands require a running daemon. Start it with 'vaultclaw daemon start'.")
            })?;
            lease_cmd::handle_lease_command(&mut client, command, json_output)?
        }

        // Rate limit management: requires daemon (HTTP API)
        Commands::RateLimit { command } => {
            cmd_rate_limit(command, &config, json_output)?
        }

        // Passkey management: direct vault access
        Commands::Passkey { command } => {
            let mut vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            passkey_cmd::handle_passkey_command(command, &mut vault, json_output)?
        }

        // YubiKey management: direct vault access
        Commands::Yubikey { command } => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            yubikey_cmd::handle_yubikey_command(command, &vault, json_output)?
        }

        // Touch ID management: direct vault access (macOS only)
        #[cfg(target_os = "macos")]
        Commands::Touchid { command } => {
            let vault = open_vault_with_password(&vault_path, get_pw("Master password: "))?;
            touchid_cmd::handle_touchid_command(command, &vault, json_output)?
        }

        // Shell completions
        Commands::Completions { shell } => {
            let shell = match shell {
                ShellArg::Bash => clap_complete::Shell::Bash,
                ShellArg::Zsh => clap_complete::Shell::Zsh,
                ShellArg::Fish => clap_complete::Shell::Fish,
                ShellArg::PowerShell => clap_complete::Shell::PowerShell,
                ShellArg::Elvish => clap_complete::Shell::Elvish,
            };
            completions_cmd::generate_completions(shell);
        }

        // Config management
        Commands::Config { command } => {
            config_cmd::handle_config_command(command, json_output)?
        }

        // Man page generation
        Commands::Manpage => {
            completions_cmd::generate_manpage()?
        }
    }
    Ok(())
}

fn open_vault_with_password(vault_path: &PathBuf, password_str: String) -> anyhow::Result<VaultFile> {
    let password = password_secret(password_str);
    let vault = VaultFile::open(vault_path, &password)?;
    Ok(vault)
}

fn cmd_get_with_vault(
    vault: &VaultFile,
    query: &str,
    clip: bool,
    json_output: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let entries = vault.store().list();
    let results = fuzzy_search(&entries, query);

    if results.is_empty() {
        anyhow::bail!("No matching entries found for '{}'", query);
    }

    let entry = results[0].0;

    if json_output {
        println!("{}", serde_json::to_string_pretty(entry)?);
    } else {
        print_entry(entry);
    }

    if clip {
        if let Credential::Login(login) = &entry.credential {
            crate::cli::clipboard::copy_to_clipboard(
                &login.password,
                config.clipboard_clear_seconds,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("Password copied to clipboard (clears in {}s)", config.clipboard_clear_seconds);
        }
    }

    Ok(())
}

// ---- Daemon-routed command helpers ----

fn send_daemon_request(client: &mut DaemonClient, req: &Request) -> anyhow::Result<Box<ResponseData>> {
    client.request(req).map_err(|e| anyhow::anyhow!("{}", e))
}

fn cmd_get_via_daemon(
    client: &mut DaemonClient,
    query: &str,
    clip: bool,
    json_output: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::FuzzyGet { query: query.to_string() })?;
    match *data {
        ResponseData::Entry(entry) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                print_entry(&entry);
            }
            if clip {
                if let Credential::Login(login) = &entry.credential {
                    crate::cli::clipboard::copy_to_clipboard(
                        &login.password,
                        config.clipboard_clear_seconds,
                    ).map_err(|e| anyhow::anyhow!(e))?;
                    eprintln!("Password copied to clipboard (clears in {}s)", config.clipboard_clear_seconds);
                }
            }
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

fn cmd_ls_via_daemon(
    client: &mut DaemonClient,
    tag: Option<String>,
    category: Option<String>,
    favorites: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::List {
        tag,
        category,
        favorites_only: favorites,
    })?;
    match *data {
        ResponseData::Entries(entries) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("No entries found.");
            } else {
                for entry in &entries {
                    print_entry_summary(entry);
                }
                println!("\n{} entries", entries.len());
            }
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

fn cmd_search_via_daemon(
    client: &mut DaemonClient,
    query: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::Search { query: query.to_string() })?;
    match *data {
        ResponseData::Entries(entries) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("No results for '{}'", query);
            } else {
                for entry in &entries {
                    print_entry_summary(entry);
                }
                println!("\n{} results", entries.len());
            }
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

fn cmd_totp_via_daemon(
    client: &mut DaemonClient,
    query: &str,
    clip: bool,
    json_output: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    // First fuzzy-get the entry to find its ID
    let entry_data = send_daemon_request(client, &Request::FuzzyGet { query: query.to_string() })?;
    let entry_id = match *entry_data {
        ResponseData::Entry(ref e) => e.id,
        _ => anyhow::bail!("Unexpected response from daemon"),
    };

    let data = send_daemon_request(client, &Request::Totp { id: entry_id })?;
    match *data {
        ResponseData::Totp(ref totp_resp) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "code": totp_resp.code,
                    "seconds_remaining": totp_resp.seconds_remaining,
                }))?);
            } else {
                println!("{} ({}s remaining)", totp_resp.code, totp_resp.seconds_remaining);
            }
            if clip {
                crate::cli::clipboard::copy_to_clipboard(&totp_resp.code, config.clipboard_clear_seconds)
                    .map_err(|e| anyhow::anyhow!(e))?;
                eprintln!("Code copied to clipboard");
            }
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

fn cmd_status_via_daemon(
    client: &mut DaemonClient,
    json_output: bool,
) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::Status)?;
    match *data {
        ResponseData::Status(ref status) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "exists": true,
                    "daemon": true,
                    "locked": status.locked,
                    "path": status.vault_path,
                    "entry_count": status.entry_count,
                }))?);
            } else {
                println!("Vault: {} (via daemon)", status.vault_path);
                println!("Status: {}", if status.locked { "locked" } else { "unlocked" });
                if !status.locked {
                    println!("Entries: {}", status.entry_count);
                }
            }
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_add_via_daemon(
    client: &mut DaemonClient,
    title: String,
    entry_type: String,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: bool,
    sensitive: bool,
) -> anyhow::Result<()> {
    let (credential, _needs_prompt) = build_credential(&entry_type, url, username, password)?;
    let credential = if let Credential::SecureNote(_) = &credential {
        Credential::SecureNote(SecureNoteCredential {
            content: notes.clone().unwrap_or_default(),
        })
    } else {
        credential
    };
    let entry = build_entry_with_metadata(title, credential, category, tags, notes, totp_secret, favorite)
        .with_sensitive(sensitive);
    let data = send_daemon_request(client, &Request::Add { entry })?;
    match *data {
        ResponseData::Id(id) => {
            println!("Added entry: {}", id);
            Ok(())
        }
        _ => anyhow::bail!("Unexpected response from daemon"),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_edit_via_daemon(
    client: &mut DaemonClient,
    query: String,
    title: Option<String>,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: Option<bool>,
    sensitive: Option<bool>,
) -> anyhow::Result<()> {
    // Fuzzy-get the entry first
    let data = send_daemon_request(client, &Request::FuzzyGet { query: query.clone() })?;
    let mut entry = match *data {
        ResponseData::Entry(e) => e,
        _ => anyhow::bail!("Unexpected response from daemon"),
    };

    apply_entry_edits(&mut entry, title, url, username, password, category, tags, notes, totp_secret, favorite, sensitive);

    send_daemon_request(client, &Request::Update { entry: entry.clone() })?;
    println!("Updated entry: {}", entry.id);
    Ok(())
}

fn cmd_rm_via_daemon(client: &mut DaemonClient, query: &str) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::FuzzyGet { query: query.to_string() })?;
    let entry = match *data {
        ResponseData::Entry(e) => e,
        _ => anyhow::bail!("Unexpected response from daemon"),
    };

    let id = entry.id;
    let title = entry.title.clone();
    send_daemon_request(client, &Request::Delete { id })?;
    println!("Deleted: {} ({})", title, id);
    Ok(())
}

fn cmd_export_via_daemon(
    client: &mut DaemonClient,
    format: &str,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let data = send_daemon_request(client, &Request::List {
        tag: None,
        category: None,
        favorites_only: false,
    })?;
    let entries = match *data {
        ResponseData::Entries(e) => e,
        _ => anyhow::bail!("Unexpected response from daemon"),
    };

    let content = export_entries_to_string(&entries, format)?;
    match output {
        Some(path) => {
            std::fs::write(&path, &content)?;
            println!("Exported {} entries to {}", entries.len(), path.display());
        }
        None => print!("{}", content),
    }
    Ok(())
}

/// Build a credential from CLI arguments. Returns None for the password field
/// if it needs to be prompted interactively.
fn build_credential(
    entry_type: &str,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<(Credential, bool)> {
    let needs_prompt = password.is_none();
    let credential = match entry_type {
        "login" => {
            Credential::Login(LoginCredential {
                url: url.unwrap_or_default(),
                username: username.unwrap_or_default(),
                password: password.unwrap_or_default(),
            })
        }
        "api_key" | "apikey" => Credential::ApiKey(ApiKeyCredential {
            service: url.unwrap_or_default(),
            key: username.unwrap_or_default(),
            secret: password.unwrap_or_default(),
        }),
        "note" | "secure_note" => Credential::SecureNote(SecureNoteCredential {
            content: String::new(),
        }),
        "ssh" | "ssh_key" => Credential::SshKey(SshKeyCredential {
            private_key: password.unwrap_or_default(),
            public_key: username.unwrap_or_default(),
            passphrase: url.unwrap_or_default(),
        }),
        "passkey" => Credential::Passkey(PasskeyCredential {
            credential_id: String::new(),
            rp_id: url.unwrap_or_default(),
            rp_name: username.unwrap_or_default(),
            user_handle: String::new(),
            user_name: password.unwrap_or_default(),
            private_key: String::new(),
            algorithm: PasskeyAlgorithm::Es256,
            sign_count: 0,
            discoverable: true,
            backup_eligible: false,
            backup_state: false,
            last_used_at: None,
        }),
        _ => anyhow::bail!("Unknown credential type: {}", entry_type),
    };
    Ok((credential, needs_prompt))
}

/// Build an entry with optional metadata from CLI arguments.
fn build_entry_with_metadata(
    title: String,
    credential: Credential,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: bool,
) -> Entry {
    let mut entry = Entry::new(title, credential).with_favorite(favorite);

    if let Some(cat) = category {
        entry = entry.with_category(cat);
    }
    if let Some(t) = tags {
        let tag_list: Vec<String> = t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        entry = entry.with_tags(tag_list);
    }
    if let Some(n) = notes {
        entry = entry.with_notes(n);
    }
    if let Some(otp) = totp_secret {
        entry = entry.with_totp(otp);
    }

    entry
}

#[allow(clippy::too_many_arguments)]
fn cmd_add_with_vault(
    vault: &mut VaultFile,
    title: String,
    entry_type: String,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: bool,
    sensitive: bool,
) -> anyhow::Result<()> {
    let (credential, _needs_prompt) = build_credential(&entry_type, url, username, password)?;

    // For secure notes, use the notes field as content
    let credential = if let Credential::SecureNote(_) = &credential {
        Credential::SecureNote(SecureNoteCredential {
            content: notes.clone().unwrap_or_default(),
        })
    } else {
        credential
    };

    let entry = build_entry_with_metadata(title, credential, category, tags, notes, totp_secret, favorite)
        .with_sensitive(sensitive);

    let id = vault.store_mut().add(entry);
    vault.save()?;
    println!("Added entry: {}", id);
    Ok(())
}

/// Apply edit operations to an entry. Pure function, no I/O.
#[allow(clippy::too_many_arguments)]
fn apply_entry_edits(
    entry: &mut Entry,
    title: Option<String>,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: Option<bool>,
    sensitive: Option<bool>,
) {
    entry.updated_at = chrono::Utc::now();

    if let Some(t) = title {
        entry.title = t;
    }
    if let Some(f) = favorite {
        entry.favorite = f;
    }
    if let Some(s) = sensitive {
        entry.sensitive = s;
    }
    if let Some(cat) = category {
        entry.category = Some(cat);
    }
    if let Some(t) = tags {
        entry.tags = t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    if let Some(n) = notes {
        entry.notes = n;
    }
    if let Some(otp) = totp_secret {
        entry.totp_secret = Some(otp);
    }

    // Update credential-specific fields
    match &mut entry.credential {
        Credential::Login(login) => {
            if let Some(u) = url {
                login.url = u;
            }
            if let Some(u) = username {
                login.username = u;
            }
            if let Some(p) = password {
                login.password = p;
            }
        }
        Credential::ApiKey(api) => {
            if let Some(s) = url {
                api.service = s;
            }
            if let Some(k) = username {
                api.key = k;
            }
            if let Some(s) = password {
                api.secret = s;
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_edit_with_vault(
    vault: &mut VaultFile,
    query: String,
    title: Option<String>,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: Option<bool>,
    sensitive: Option<bool>,
) -> anyhow::Result<()> {
    let entries = vault.store().list();
    let results = fuzzy_search(&entries, &query);

    if results.is_empty() {
        anyhow::bail!("No matching entries found for '{}'", query);
    }

    let id = results[0].0.id;
    let entry = vault.store_mut().get_mut(&id).unwrap();

    apply_entry_edits(entry, title, url, username, password, category, tags, notes, totp_secret, favorite, sensitive);

    vault.save()?;
    println!("Updated entry: {}", id);
    Ok(())
}

fn cmd_rm_with_vault(vault: &mut VaultFile, query: &str) -> anyhow::Result<()> {
    let entries = vault.store().list();
    let results = fuzzy_search(&entries, query);

    if results.is_empty() {
        anyhow::bail!("No matching entries found for '{}'", query);
    }

    let entry = results[0].0;
    let id = entry.id;
    let title = entry.title.clone();

    vault.store_mut().remove(&id);
    vault.save()?;
    println!("Deleted: {} ({})", title, id);
    Ok(())
}

fn cmd_ls_with_vault(
    vault: &VaultFile,
    tag: Option<String>,
    category: Option<String>,
    favorites: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    let entries: Vec<&Entry> = if favorites {
        vault.store().list_favorites()
    } else if let Some(t) = &tag {
        vault.store().list_by_tag(t)
    } else if let Some(c) = &category {
        vault.store().list_by_category(c)
    } else {
        vault.store().list()
    };

    if json_output {
        let cloned: Vec<Entry> = entries.iter().map(|e| (*e).clone()).collect();
        println!("{}", serde_json::to_string_pretty(&cloned)?);
    } else if entries.is_empty() {
        println!("No entries found.");
    } else {
        for entry in &entries {
            print_entry_summary(entry);
        }
        println!("\n{} entries", entries.len());
    }

    Ok(())
}

fn cmd_search_with_vault(
    vault: &VaultFile,
    query: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let entries = vault.store().search(query);

    if json_output {
        let cloned: Vec<Entry> = entries.iter().map(|e| (*e).clone()).collect();
        println!("{}", serde_json::to_string_pretty(&cloned)?);
    } else if entries.is_empty() {
        println!("No results for '{}'", query);
    } else {
        for entry in &entries {
            print_entry_summary(entry);
        }
        println!("\n{} results", entries.len());
    }

    Ok(())
}

fn cmd_totp_with_vault(
    vault: &VaultFile,
    query: &str,
    clip: bool,
    json_output: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let entries = vault.store().list();
    let results = fuzzy_search(&entries, query);

    if results.is_empty() {
        anyhow::bail!("No matching entries found for '{}'", query);
    }

    let entry = results[0].0;
    let secret = entry
        .totp_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No TOTP secret for '{}'", entry.title))?;

    let code = totp::generate_totp(secret)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "code": code.code,
                "seconds_remaining": code.seconds_remaining,
                "period": code.period,
            }))?
        );
    } else {
        println!("{} ({}s remaining)", code.code, code.seconds_remaining);
    }

    if clip {
        crate::cli::clipboard::copy_to_clipboard(&code.code, config.clipboard_clear_seconds)
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("Code copied to clipboard");
    }

    Ok(())
}

fn cmd_gen(length: usize, clip: bool, json_output: bool, config: &AppConfig) -> anyhow::Result<()> {
    let password = config::generate_password(length);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "password": password,
                "length": length,
            }))?
        );
    } else {
        println!("{}", password);
    }

    if clip {
        crate::cli::clipboard::copy_to_clipboard(&password, config.clipboard_clear_seconds)
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("Password copied to clipboard (clears in {}s)", config.clipboard_clear_seconds);
    }

    Ok(())
}

/// Export entries to a string in the given format. Pure function, no I/O.
fn export_entries_to_string(entries: &[Entry], format: &str) -> anyhow::Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(entries)?),
        "csv" => {
            let mut wtr = csv::Writer::from_writer(vec![]);
            wtr.write_record(["Title", "Type", "URL", "Username", "Password", "Notes", "Tags", "Category", "TOTP"])?;
            for entry in entries {
                let (url, username, password) = match &entry.credential {
                    Credential::Login(l) => (l.url.as_str(), l.username.as_str(), l.password.as_str()),
                    Credential::ApiKey(a) => (a.service.as_str(), a.key.as_str(), a.secret.as_str()),
                    Credential::SecureNote(_) => ("", "", ""),
                    Credential::SshKey(s) => ("", s.public_key.as_str(), s.private_key.as_str()),
                    Credential::Passkey(pk) => (pk.rp_id.as_str(), pk.user_name.as_str(), ""),
                };
                wtr.write_record([
                    &entry.title,
                    entry.credential_type(),
                    url,
                    username,
                    password,
                    &entry.notes,
                    &entry.tags.join(","),
                    entry.category.as_deref().unwrap_or(""),
                    entry.totp_secret.as_deref().unwrap_or(""),
                ])?;
            }
            Ok(String::from_utf8(wtr.into_inner()?)?)
        }
        _ => anyhow::bail!("Unsupported export format: {}. Use 'json' or 'csv'.", format),
    }
}

fn cmd_export_with_vault(
    vault: &VaultFile,
    format: &str,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let entries = vault.store().entries();

    let content = export_entries_to_string(&entries, format)?;

    match output {
        Some(path) => {
            std::fs::write(&path, &content)?;
            println!("Exported {} entries to {}", entries.len(), path.display());
        }
        None => print!("{}", content),
    }

    Ok(())
}

fn cmd_status_with_vault(
    vault: &VaultFile,
    vault_path: &std::path::Path,
    json_output: bool,
) -> anyhow::Result<()> {
    let count = vault.store().len();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "exists": true,
                "path": vault_path.display().to_string(),
                "entry_count": count,
                "version": vault.header.version,
            }))?
        );
    } else {
        println!("Vault: {}", vault_path.display());
        println!("Version: {}", vault.header.version);
        println!("Entries: {}", count);
    }

    Ok(())
}

fn print_entry(entry: &Entry) {
    println!("Title: {}", entry.title);
    println!("ID: {}", entry.id);
    println!("Type: {}", entry.credential_type());

    match &entry.credential {
        Credential::Login(login) => {
            println!("URL: {}", login.url);
            println!("Username: {}", login.username);
            println!("Password: {}", mask_password(&login.password));
        }
        Credential::ApiKey(api) => {
            println!("Service: {}", api.service);
            println!("Key: {}", api.key);
            println!("Secret: {}", mask_password(&api.secret));
        }
        Credential::SecureNote(note) => {
            println!("Content: {}", note.content);
        }
        Credential::SshKey(ssh) => {
            println!("Public key: {}", ssh.public_key);
            println!("Private key: [hidden]");
        }
        Credential::Passkey(pk) => {
            println!("RP: {} ({})", pk.rp_name, pk.rp_id);
            println!("User: {}", pk.user_name);
            println!("Algorithm: {:?}", pk.algorithm);
            println!("Sign count: {}", pk.sign_count);
            if let Some(lu) = pk.last_used_at {
                println!("Last used: {}", lu.format("%Y-%m-%d %H:%M"));
            }
        }
    }

    if let Some(cat) = &entry.category {
        println!("Category: {}", cat);
    }
    if !entry.tags.is_empty() {
        println!("Tags: {}", entry.tags.join(", "));
    }
    if entry.favorite {
        println!("Favorite: yes");
    }
    if !entry.notes.is_empty() {
        println!("Notes: {}", entry.notes);
    }
    if entry.totp_secret.is_some() {
        println!("TOTP: configured");
    }
    println!("Created: {}", entry.created_at.format("%Y-%m-%d %H:%M"));
    println!("Updated: {}", entry.updated_at.format("%Y-%m-%d %H:%M"));
}

fn print_entry_summary(entry: &Entry) {
    let type_icon = match &entry.credential {
        Credential::Login(_) => "L",
        Credential::ApiKey(_) => "A",
        Credential::SecureNote(_) => "N",
        Credential::SshKey(_) => "S",
        Credential::Passkey(_) => "P",
    };
    let fav = if entry.favorite { "*" } else { " " };
    let detail = match &entry.credential {
        Credential::Login(l) => format!("{} @ {}", l.username, l.url),
        Credential::ApiKey(a) => a.service.clone(),
        Credential::SecureNote(_) => "secure note".to_string(),
        Credential::SshKey(_) => "SSH key".to_string(),
        Credential::Passkey(pk) => format!("{} @ {}", pk.user_name, pk.rp_id),
    };
    println!("{} [{}] {} — {}", fav, type_icon, entry.title, detail);
}

fn mask_password(password: &str) -> String {
    if password.is_empty() {
        return String::new();
    }
    format!("{}****", &password[..1.min(password.len())])
}

fn cmd_rate_limit(command: RateLimitCommands, config: &AppConfig, json_output: bool) -> anyhow::Result<()> {
    let base_url = format!("http://127.0.0.1:{}", config.http_port);
    let client = reqwest::blocking::Client::new();

    // Get admin token
    let pw = read_password("Master password (for admin auth): ");
    let auth_resp: serde_json::Value = client
        .post(format!("{}/v1/auth/token", base_url))
        .json(&serde_json::json!({ "password": pw }))
        .send()?
        .json()?;
    let token = auth_resp["token"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Authentication failed"))?;

    match command {
        RateLimitCommands::Set { agent_id, rpm, rph, auto_revoke } => {
            let resp: serde_json::Value = client
                .put(format!("{}/v1/rate-limits/{}", base_url, agent_id))
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "rpm": rpm,
                    "rph": rph,
                    "auto_revoke_on_anomaly": auto_revoke
                }))
                .send()?
                .json()?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                println!("Rate limit set for agent '{}': {} RPM, {} RPH{}", agent_id, rpm, rph,
                    if auto_revoke { " (auto-revoke on anomaly)" } else { "" });
            }
        }
        RateLimitCommands::Remove { agent_id } => {
            let resp = client
                .delete(format!("{}/v1/rate-limits/{}", base_url, agent_id))
                .bearer_auth(token)
                .send()?;
            if resp.status().is_success() {
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "status": "ok" }))?);
                } else {
                    println!("Rate limit removed for agent '{}'", agent_id);
                }
            } else {
                anyhow::bail!("No rate limit found for agent '{}'", agent_id);
            }
        }
        RateLimitCommands::List => {
            let resp: serde_json::Value = client
                .get(format!("{}/v1/rate-limits", base_url))
                .bearer_auth(token)
                .send()?
                .json()?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let empty = vec![];
                let limits = resp["rate_limits"].as_array().unwrap_or(&empty);
                if limits.is_empty() {
                    println!("No rate limits configured.");
                } else {
                    println!("{:<25} {:>6} {:>6} {:>10} {:>10} {:>12}", "Agent", "RPM", "RPH", "Cur RPM", "Cur RPH", "Auto-revoke");
                    println!("{}", "-".repeat(75));
                    for l in limits {
                        println!("{:<25} {:>6} {:>6} {:>10} {:>10} {:>12}",
                            l["agent_id"].as_str().unwrap_or("-"),
                            l["rpm"].as_u64().unwrap_or(0),
                            l["rph"].as_u64().unwrap_or(0),
                            l["current_rpm"].as_u64().unwrap_or(0),
                            l["current_rph"].as_u64().unwrap_or(0),
                            if l["auto_revoke_on_anomaly"].as_bool().unwrap_or(false) { "yes" } else { "no" },
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Credential extraction helpers ----
    fn unwrap_login(cred: Credential) -> LoginCredential {
        match cred { Credential::Login(l) => l, _ => panic!("Expected Login credential") }
    }

    fn unwrap_api_key(cred: Credential) -> ApiKeyCredential {
        match cred { Credential::ApiKey(a) => a, _ => panic!("Expected ApiKey credential") }
    }

    fn unwrap_secure_note(cred: Credential) -> SecureNoteCredential {
        match cred { Credential::SecureNote(n) => n, _ => panic!("Expected SecureNote credential") }
    }

    fn unwrap_login_ref(cred: &Credential) -> &LoginCredential {
        match cred { Credential::Login(l) => l, _ => panic!("Expected Login credential") }
    }

    fn unwrap_api_key_ref(cred: &Credential) -> &ApiKeyCredential {
        match cred { Credential::ApiKey(a) => a, _ => panic!("Expected ApiKey credential") }
    }

    fn unwrap_secure_note_ref(cred: &Credential) -> &SecureNoteCredential {
        match cred { Credential::SecureNote(n) => n, _ => panic!("Expected SecureNote credential") }
    }

    fn unwrap_ssh_key_ref(cred: &Credential) -> &SshKeyCredential {
        match cred { Credential::SshKey(s) => s, _ => panic!("Expected SshKey credential") }
    }

    // ---- should_panic tests for credential helpers ----
    #[test]
    #[should_panic(expected = "Expected Login")]
    fn test_unwrap_login_wrong() {
        unwrap_login(Credential::SecureNote(SecureNoteCredential { content: "".into() }));
    }

    #[test]
    #[should_panic(expected = "Expected ApiKey")]
    fn test_unwrap_api_key_wrong() {
        unwrap_api_key(Credential::Login(LoginCredential { url: "".into(), username: "".into(), password: "".into() }));
    }

    #[test]
    #[should_panic(expected = "Expected SecureNote")]
    fn test_unwrap_secure_note_wrong() {
        unwrap_secure_note(Credential::Login(LoginCredential { url: "".into(), username: "".into(), password: "".into() }));
    }

    #[test]
    fn test_unwrap_secure_note_success() {
        let note = unwrap_secure_note(Credential::SecureNote(SecureNoteCredential { content: "hello".into() }));
        assert_eq!(note.content, "hello");
    }

    #[test]
    #[should_panic(expected = "Expected Login")]
    fn test_unwrap_login_ref_wrong() {
        let cred = Credential::SecureNote(SecureNoteCredential { content: "".into() });
        unwrap_login_ref(&cred);
    }

    #[test]
    #[should_panic(expected = "Expected ApiKey")]
    fn test_unwrap_api_key_ref_wrong() {
        let cred = Credential::Login(LoginCredential { url: "".into(), username: "".into(), password: "".into() });
        unwrap_api_key_ref(&cred);
    }

    #[test]
    #[should_panic(expected = "Expected SecureNote")]
    fn test_unwrap_secure_note_ref_wrong() {
        let cred = Credential::Login(LoginCredential { url: "".into(), username: "".into(), password: "".into() });
        unwrap_secure_note_ref(&cred);
    }

    #[test]
    #[should_panic(expected = "Expected SshKey")]
    fn test_unwrap_ssh_key_ref_wrong() {
        let cred = Credential::Login(LoginCredential { url: "".into(), username: "".into(), password: "".into() });
        unwrap_ssh_key_ref(&cred);
    }

    // ---- mask_password ----
    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password("secret123"), "s****");
        assert_eq!(mask_password("a"), "a****");
        assert_eq!(mask_password(""), "");
    }

    // ---- CLI parsing tests ----
    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["vaultclaw", "gen", "--length", "32"]);
        let (length, _clip) = match cli.command { Commands::Gen { length, clip } => (length, clip), _ => panic!("Expected Gen") };
        assert_eq!(length, 32);
    }

    #[test]
    fn test_cli_parsing_status() {
        let cli = Cli::parse_from(["vaultclaw", "status"]);
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn test_cli_parsing_search() {
        let cli = Cli::parse_from(["vaultclaw", "search", "github"]);
        let query = match cli.command { Commands::Search { query } => query, _ => panic!("Expected Search") };
        assert_eq!(query, "github");
    }

    #[test]
    fn test_cli_parsing_ls() {
        let cli = Cli::parse_from(["vaultclaw", "ls", "--tag", "work"]);
        let tag = match cli.command { Commands::Ls { tag, .. } => tag, _ => panic!("Expected Ls") };
        assert_eq!(tag, Some("work".to_string()));
    }

    #[test]
    fn test_cli_parsing_add() {
        let cli = Cli::parse_from([
            "vaultclaw", "add",
            "--title", "GitHub",
            "--url", "https://github.com",
            "--username", "user",
            "--password", "pass",
            "--favorite",
        ]);
        let (title, url, username, password, favorite) = match cli.command { Commands::Add { title, url, username, password, favorite, .. } => (title, url, username, password, favorite), _ => panic!("Expected Add") };
        assert_eq!(title, "GitHub");
        assert_eq!(url, Some("https://github.com".to_string()));
        assert_eq!(username, Some("user".to_string()));
        assert_eq!(password, Some("pass".to_string()));
        assert!(favorite);
    }

    #[test]
    fn test_cli_parsing_json_flag() {
        let cli = Cli::parse_from(["vaultclaw", "--json", "status"]);
        assert!(cli.json);
    }

    #[test]
    fn test_cli_parsing_vault_path() {
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/my.vclaw", "status"]);
        assert_eq!(cli.vault, Some(PathBuf::from("/tmp/my.vclaw")));
    }

    #[test]
    fn test_cli_parsing_import() {
        let cli = Cli::parse_from([
            "vaultclaw", "import", "--from", "1password", "--dry-run", "export.csv",
        ]);
        let (from, file, dry_run) = match cli.command { Commands::Import { from, file, dry_run } => (from, file, dry_run), _ => panic!("Expected Import") };
        assert_eq!(from, "1password");
        assert_eq!(file, PathBuf::from("export.csv"));
        assert!(dry_run);
    }

    #[test]
    fn test_cli_parsing_export() {
        let cli = Cli::parse_from([
            "vaultclaw", "export", "--format", "csv", "--output", "out.csv",
        ]);
        let (format, output) = match cli.command { Commands::Export { format, output } => (format, output), _ => panic!("Expected Export") };
        assert_eq!(format, "csv");
        assert_eq!(output, Some(PathBuf::from("out.csv")));
    }

    #[test]
    fn test_cli_parsing_get_with_clip() {
        let cli = Cli::parse_from(["vaultclaw", "get", "github", "--clip"]);
        let (query, clip) = match cli.command { Commands::Get { query, clip } => (query, clip), _ => panic!("Expected Get") };
        assert_eq!(query, "github");
        assert!(clip);
    }

    #[test]
    fn test_cli_parsing_totp() {
        let cli = Cli::parse_from(["vaultclaw", "totp", "github", "-c"]);
        let (query, clip) = match cli.command { Commands::Totp { query, clip } => (query, clip), _ => panic!("Expected Totp") };
        assert_eq!(query, "github");
        assert!(clip);
    }

    #[test]
    fn test_cli_parsing_edit() {
        let cli = Cli::parse_from([
            "vaultclaw", "edit", "github",
            "--title", "GitHub Updated",
            "--password", "newpass",
        ]);
        let (query, title, password) = match cli.command { Commands::Edit { query, title, password, .. } => (query, title, password), _ => panic!("Expected Edit") };
        assert_eq!(query, "github");
        assert_eq!(title, Some("GitHub Updated".to_string()));
        assert_eq!(password, Some("newpass".to_string()));
    }

    #[test]
    fn test_cli_parsing_init() {
        let cli = Cli::parse_from(["vaultclaw", "init"]);
        assert!(matches!(cli.command, Commands::Init));
    }

    #[test]
    fn test_cli_parsing_rm() {
        let cli = Cli::parse_from(["vaultclaw", "rm", "github"]);
        let query = match cli.command { Commands::Rm { query } => query, _ => panic!("Expected Rm") };
        assert_eq!(query, "github");
    }

    #[test]
    fn test_cli_parsing_ls_category() {
        let cli = Cli::parse_from(["vaultclaw", "ls", "--cat", "development"]);
        let category = match cli.command { Commands::Ls { category, .. } => category, _ => panic!("Expected Ls") };
        assert_eq!(category, Some("development".to_string()));
    }

    #[test]
    fn test_cli_parsing_ls_favorites() {
        let cli = Cli::parse_from(["vaultclaw", "ls", "--favorites"]);
        let favorites = match cli.command { Commands::Ls { favorites, .. } => favorites, _ => panic!("Expected Ls") };
        assert!(favorites);
    }

    #[test]
    fn test_cli_parsing_gen_default_length() {
        let cli = Cli::parse_from(["vaultclaw", "gen"]);
        let (length, clip) = match cli.command { Commands::Gen { length, clip } => (length, clip), _ => panic!("Expected Gen") };
        assert_eq!(length, 24);
        assert!(!clip);
    }

    #[test]
    fn test_cli_parsing_export_default_format() {
        let cli = Cli::parse_from(["vaultclaw", "export"]);
        let (format, output) = match cli.command { Commands::Export { format, output } => (format, output), _ => panic!("Expected Export") };
        assert_eq!(format, "json");
        assert!(output.is_none());
    }

    #[test]
    fn test_cli_parsing_add_type_variants() {
        for t in &["login", "api_key", "note", "ssh"] {
            let cli = Cli::parse_from(["vaultclaw", "add", "--title", "Test", "-T", t, "--password", "x"]);
            let r#type = match cli.command { Commands::Add { r#type, .. } => r#type, _ => panic!("Expected Add") };
            assert_eq!(r#type, *t);
        }
    }

    // ---- print_entry tests ----
    #[test]
    fn test_print_entry_login() {
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "secret123".to_string(),
            }),
        );
        // Should not panic
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "aws".to_string(),
                key: "AKID123".to_string(),
                secret: "secret".to_string(),
            }),
        );
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_secure_note() {
        let entry = Entry::new(
            "WiFi Password".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "MyWiFiPass123".to_string(),
            }),
        );
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_ssh_key() {
        let entry = Entry::new(
            "Server Key".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "-----BEGIN PRIVATE KEY-----".to_string(),
                public_key: "ssh-rsa AAAA...".to_string(),
                passphrase: "pass".to_string(),
            }),
        );
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_with_metadata() {
        let entry = Entry::new(
            "Full Entry".to_string(),
            Credential::Login(LoginCredential {
                url: "https://example.com".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        )
        .with_category("work")
        .with_tags(vec!["dev".to_string(), "prod".to_string()])
        .with_favorite(true)
        .with_notes("Important account".to_string())
        .with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_no_metadata() {
        // Entry with no category, no tags, not favorite, no notes, no totp
        let entry = Entry::new(
            "Bare".to_string(),
            Credential::Login(LoginCredential {
                url: "".to_string(),
                username: "".to_string(),
                password: "".to_string(),
            }),
        );
        print_entry(&entry);
    }

    // ---- print_entry_summary tests ----
    #[test]
    fn test_print_entry_summary_login() {
        let entry = Entry::new(
            "GitHub".to_string(),
            Credential::Login(LoginCredential {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "pass".to_string(),
            }),
        );
        print_entry_summary(&entry);
    }

    #[test]
    fn test_print_entry_summary_api_key() {
        let entry = Entry::new(
            "AWS".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "aws-prod".to_string(),
                key: "AKID".to_string(),
                secret: "secret".to_string(),
            }),
        );
        print_entry_summary(&entry);
    }

    #[test]
    fn test_print_entry_summary_note() {
        let entry = Entry::new(
            "WiFi".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "password123".to_string(),
            }),
        );
        print_entry_summary(&entry);
    }

    #[test]
    fn test_print_entry_summary_ssh() {
        let entry = Entry::new(
            "Server".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "key".to_string(),
                public_key: "pub".to_string(),
                passphrase: "".to_string(),
            }),
        );
        print_entry_summary(&entry);
    }

    #[test]
    fn test_print_entry_summary_favorite() {
        let entry = Entry::new(
            "Fav".to_string(),
            Credential::Login(LoginCredential {
                url: "u".to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
            }),
        ).with_favorite(true);
        print_entry_summary(&entry);
    }

    // ---- cmd_gen tests (no vault needed) ----
    #[test]
    fn test_cmd_gen_plain() {
        let config = AppConfig::default();
        cmd_gen(24, false, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_gen_json() {
        let config = AppConfig::default();
        cmd_gen(16, false, true, &config).unwrap();
    }

    #[test]
    fn test_cmd_gen_short() {
        let config = AppConfig::default();
        cmd_gen(1, false, false, &config).unwrap();
    }

    // ---- cmd_status with non-existent vault (no stdin needed) ----
    #[test]
    fn test_cmd_status_no_vault_plain() {
        let path = "/tmp/nonexistent_vault_test_12345.vclaw";
        let cli = Cli::parse_from(["vaultclaw", "--vault", path, "status"]);
        execute_impl(cli, |_| "test".to_string()).unwrap();
    }

    #[test]
    fn test_cmd_status_no_vault_json() {
        let path = "/tmp/nonexistent_vault_test_12345.vclaw";
        let cli = Cli::parse_from(["vaultclaw", "--vault", path, "--json", "status"]);
        execute_impl(cli, |_| "test".to_string()).unwrap();
    }

    // ---- cmd_init with existing vault path ----
    #[test]
    fn test_cmd_init_vault_already_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("existing.vclaw");
        std::fs::write(&path, b"dummy").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "init"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    // ---- Helper to create test entries ----
    fn create_test_entries() -> Vec<Entry> {
        vec![
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "octocat".to_string(),
                    password: "ghp_secret".to_string(),
                }),
            )
            .with_category("development")
            .with_tags(vec!["work".to_string()])
            .with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),

            Entry::new(
                "AWS Keys".to_string(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "aws".to_string(),
                    key: "AKID123".to_string(),
                    secret: "aws_secret".to_string(),
                }),
            ),

            Entry::new(
                "Wi-Fi Pass".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "MyWiFi123".to_string(),
                }),
            ),

            Entry::new(
                "Server Key".to_string(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "-----BEGIN-----".to_string(),
                    public_key: "ssh-rsa AAAA".to_string(),
                    passphrase: "".to_string(),
                }),
            ),
        ]
    }

    // ---- export_entries_to_string tests ----
    #[test]
    fn test_export_entries_json() {
        let entries = create_test_entries();
        let result = export_entries_to_string(&entries, "json").unwrap();
        assert!(result.contains("GitHub"));
        assert!(result.contains("AWS Keys"));
        assert!(result.contains("Wi-Fi Pass"));
        assert!(result.contains("Server Key"));
    }

    #[test]
    fn test_export_entries_csv() {
        let entries = create_test_entries();
        let result = export_entries_to_string(&entries, "csv").unwrap();
        assert!(result.contains("Title,Type,URL"));
        assert!(result.contains("GitHub"));
        assert!(result.contains("octocat"));
        assert!(result.contains("aws"));
        assert!(result.contains("AKID123"));
    }

    #[test]
    fn test_export_entries_csv_all_types() {
        let entries = create_test_entries();
        let csv = export_entries_to_string(&entries, "csv").unwrap();
        // Login type
        assert!(csv.contains("https://github.com"));
        assert!(csv.contains("ghp_secret"));
        // ApiKey type
        assert!(csv.contains("aws_secret"));
        // SecureNote type is empty strings for url/username/password
        // SshKey type
        assert!(csv.contains("ssh-rsa AAAA"));
        assert!(csv.contains("-----BEGIN-----"));
    }

    #[test]
    fn test_export_entries_unsupported_format() {
        let entries = create_test_entries();
        let result = export_entries_to_string(&entries, "xml");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported export format"));
    }

    #[test]
    fn test_export_entries_empty() {
        let entries: Vec<Entry> = vec![];
        let json = export_entries_to_string(&entries, "json").unwrap();
        assert_eq!(json.trim(), "[]");
        let csv = export_entries_to_string(&entries, "csv").unwrap();
        assert!(csv.contains("Title,Type,URL"));
    }

    #[test]
    fn test_export_entries_with_metadata() {
        let entries = vec![
            Entry::new(
                "Test".to_string(),
                Credential::Login(LoginCredential {
                    url: "u".into(),
                    username: "u".into(),
                    password: "p".into(),
                }),
            )
            .with_category("cat1")
            .with_tags(vec!["t1".into(), "t2".into()])
            .with_notes("my notes".to_string())
            .with_totp("SECRET"),
        ];
        let csv = export_entries_to_string(&entries, "csv").unwrap();
        assert!(csv.contains("cat1"));
        assert!(csv.contains("t1,t2"));
        assert!(csv.contains("SECRET"));
    }

    // ---- build_credential tests ----
    #[test]
    fn test_build_credential_login() {
        let (cred, needs_prompt) = build_credential(
            "login",
            Some("https://example.com".into()),
            Some("user".into()),
            Some("pass".into()),
        ).unwrap();
        assert!(!needs_prompt);
        let l = unwrap_login(cred);
        assert_eq!(l.url, "https://example.com");
        assert_eq!(l.username, "user");
        assert_eq!(l.password, "pass");
    }

    #[test]
    fn test_build_credential_login_no_password() {
        let (cred, needs_prompt) = build_credential(
            "login",
            Some("https://example.com".into()),
            Some("user".into()),
            None,
        ).unwrap();
        assert!(needs_prompt);
        let l = unwrap_login(cred);
        assert_eq!(l.password, ""); // default when no password provided
    }

    #[test]
    fn test_build_credential_apikey() {
        let (cred, _) = build_credential(
            "api_key",
            Some("aws".into()),
            Some("AKID".into()),
            Some("secret".into()),
        ).unwrap();
        let a = unwrap_api_key(cred);
        assert_eq!(a.service, "aws");
        assert_eq!(a.key, "AKID");
        assert_eq!(a.secret, "secret");
    }

    #[test]
    fn test_build_credential_apikey_alias() {
        let (cred, _) = build_credential("apikey", None, None, Some("s".into())).unwrap();
        assert!(matches!(cred, Credential::ApiKey(_)));
    }

    #[test]
    fn test_build_credential_note() {
        let (cred, _) = build_credential("note", None, None, None).unwrap();
        assert!(matches!(cred, Credential::SecureNote(_)));
    }

    #[test]
    fn test_build_credential_secure_note_alias() {
        let (cred, _) = build_credential("secure_note", None, None, None).unwrap();
        assert!(matches!(cred, Credential::SecureNote(_)));
    }

    #[test]
    fn test_build_credential_ssh() {
        let (cred, _) = build_credential(
            "ssh",
            Some("passphrase".into()),
            Some("pubkey".into()),
            Some("privkey".into()),
        ).unwrap();
        let s = match cred { Credential::SshKey(s) => s, _ => panic!("Expected SshKey") };
        assert_eq!(s.private_key, "privkey");
        assert_eq!(s.public_key, "pubkey");
        assert_eq!(s.passphrase, "passphrase");
    }

    #[test]
    fn test_build_credential_ssh_key_alias() {
        let (cred, _) = build_credential("ssh_key", None, None, None).unwrap();
        assert!(matches!(cred, Credential::SshKey(_)));
    }

    #[test]
    fn test_build_credential_unknown_type() {
        let result = build_credential("bitwarden", None, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown credential type"));
    }

    #[test]
    fn test_build_credential_defaults() {
        let (cred, _) = build_credential("login", None, None, Some("p".into())).unwrap();
        let l = unwrap_login(cred);
        assert_eq!(l.url, "");
        assert_eq!(l.username, "");
    }

    // ---- build_entry_with_metadata tests ----
    #[test]
    fn test_build_entry_all_metadata() {
        let cred = Credential::Login(LoginCredential {
            url: "u".into(), username: "u".into(), password: "p".into(),
        });
        let entry = build_entry_with_metadata(
            "Test".into(),
            cred,
            Some("dev".into()),
            Some("a, b, c".into()),
            Some("my notes".into()),
            Some("TOTP_SECRET".into()),
            true,
        );
        assert_eq!(entry.title, "Test");
        assert!(entry.favorite);
        assert_eq!(entry.category, Some("dev".into()));
        assert_eq!(entry.tags, vec!["a", "b", "c"]);
        assert_eq!(entry.notes, "my notes");
        assert_eq!(entry.totp_secret, Some("TOTP_SECRET".into()));
    }

    #[test]
    fn test_build_entry_no_metadata() {
        let cred = Credential::Login(LoginCredential {
            url: "u".into(), username: "u".into(), password: "p".into(),
        });
        let entry = build_entry_with_metadata(
            "Bare".into(), cred, None, None, None, None, false,
        );
        assert_eq!(entry.title, "Bare");
        assert!(!entry.favorite);
        assert!(entry.category.is_none());
        assert!(entry.tags.is_empty());
        assert!(entry.notes.is_empty());
        assert!(entry.totp_secret.is_none());
    }

    #[test]
    fn test_build_entry_tags_with_empty_items() {
        let cred = Credential::Login(LoginCredential {
            url: "u".into(), username: "u".into(), password: "p".into(),
        });
        let entry = build_entry_with_metadata(
            "T".into(), cred, None, Some("a,,b, ,c".into()), None, None, false,
        );
        assert_eq!(entry.tags, vec!["a", "b", "c"]);
    }

    // ---- apply_entry_edits tests ----
    #[test]
    fn test_apply_edits_login_all_fields() {
        let mut entry = Entry::new(
            "Old".to_string(),
            Credential::Login(LoginCredential {
                url: "old-url".to_string(),
                username: "old-user".to_string(),
                password: "old-pass".to_string(),
            }),
        );

        apply_entry_edits(
            &mut entry,
            Some("New".into()),
            Some("new-url".into()),
            Some("new-user".into()),
            Some("new-pass".into()),
            Some("cat".into()),
            Some("t1,t2".into()),
            Some("new notes".into()),
            Some("TOTP".into()),
            Some(true),
            None,
        );

        assert_eq!(entry.title, "New");
        assert!(entry.favorite);
        assert_eq!(entry.category, Some("cat".into()));
        assert_eq!(entry.tags, vec!["t1", "t2"]);
        assert_eq!(entry.notes, "new notes");
        assert_eq!(entry.totp_secret, Some("TOTP".into()));
        let l = unwrap_login_ref(&entry.credential);
        assert_eq!(l.url, "new-url");
        assert_eq!(l.username, "new-user");
        assert_eq!(l.password, "new-pass");
    }

    #[test]
    fn test_apply_edits_no_changes() {
        let mut entry = Entry::new(
            "Original".to_string(),
            Credential::Login(LoginCredential {
                url: "u".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        );
        let original_title = entry.title.clone();

        apply_entry_edits(
            &mut entry, None, None, None, None, None, None, None, None, None, None,
        );

        assert_eq!(entry.title, original_title);
        let l = unwrap_login_ref(&entry.credential);
        assert_eq!(l.username, "user");
    }

    #[test]
    fn test_apply_edits_apikey() {
        let mut entry = Entry::new(
            "API".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "old".to_string(),
                key: "old-key".to_string(),
                secret: "old-secret".to_string(),
            }),
        );

        apply_entry_edits(
            &mut entry,
            None,
            Some("new-service".into()),
            Some("new-key".into()),
            Some("new-secret".into()),
            None, None, None, None, None, None,
        );

        let a = unwrap_api_key_ref(&entry.credential);
        assert_eq!(a.service, "new-service");
        assert_eq!(a.key, "new-key");
        assert_eq!(a.secret, "new-secret");
    }

    #[test]
    fn test_apply_edits_secure_note_no_credential_changes() {
        let mut entry = Entry::new(
            "Note".to_string(),
            Credential::SecureNote(SecureNoteCredential {
                content: "content".to_string(),
            }),
        );

        apply_entry_edits(
            &mut entry,
            Some("Updated Note".into()),
            Some("ignored-url".into()),
            Some("ignored-user".into()),
            Some("ignored-pass".into()),
            None, None, None, None, None, None,
        );

        assert_eq!(entry.title, "Updated Note");
        // SecureNote doesn't have url/username/password fields to update
        let n = unwrap_secure_note_ref(&entry.credential);
        assert_eq!(n.content, "content"); // unchanged
    }

    #[test]
    fn test_apply_edits_ssh_key_no_credential_changes() {
        let mut entry = Entry::new(
            "SSH".to_string(),
            Credential::SshKey(SshKeyCredential {
                private_key: "key".to_string(),
                public_key: "pub".to_string(),
                passphrase: "pass".to_string(),
            }),
        );

        apply_entry_edits(
            &mut entry, None, None, None, None, None, None, None, None, Some(true), None,
        );

        assert!(entry.favorite);
        let s = unwrap_ssh_key_ref(&entry.credential);
        assert_eq!(s.private_key, "key"); // unchanged
    }

    #[test]
    fn test_apply_edits_updates_timestamp() {
        let mut entry = Entry::new(
            "T".to_string(),
            Credential::Login(LoginCredential {
                url: "u".into(), username: "u".into(), password: "p".into(),
            }),
        );
        let before = entry.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        apply_entry_edits(&mut entry, Some("New".into()), None, None, None, None, None, None, None, None, None);
        assert!(entry.updated_at >= before);
    }

    // ---- import error handling ----
    #[test]
    fn test_import_unsupported_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let dummy = dir.path().join("dummy.txt");
        std::fs::write(&dummy, "data").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/test.vclaw", "import", "--from", "bitwarden", dummy.to_str().unwrap()]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported import format"));
    }

    // ---- import dry run (no vault open needed) ----
    #[test]
    fn test_import_dry_run_csv() {
        let dir = tempfile::TempDir::new().unwrap();
        let csv_file = dir.path().join("export.csv");
        std::fs::write(&csv_file, "Title,Username,Password,URL,OTP,Notes,Type\nGitHub,user,pass,https://github.com,,notes,Login\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/nonexistent.vclaw", "import", "--from", "1password", "--dry-run", csv_file.to_str().unwrap()]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_dry_run_1pif() {
        let dir = tempfile::TempDir::new().unwrap();
        let pif_file = dir.path().join("export.1pif");
        // 1PIF format: one JSON object per line, with ***...*** separators
        std::fs::write(&pif_file, "{\"typeName\":\"webforms.WebForm\",\"title\":\"Test\",\"secureContents\":{\"fields\":[{\"designation\":\"username\",\"value\":\"user\"},{\"designation\":\"password\",\"value\":\"pass\"}]},\"location\":\"https://test.com\"}\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/nonexistent.vclaw", "import", "--from", "1pif", "--dry-run", pif_file.to_str().unwrap()]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_nonexistent_file() {
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/test.vclaw", "import", "--from", "1password", "/nonexistent/file.csv"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_err());
    }

    // ---- Vault-backed command tests ----

    /// Create a test vault with sample entries for command testing.
    fn create_test_vault() -> (tempfile::TempDir, PathBuf, VaultFile) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.vclaw");
        let password = password_secret("testpass".to_string());
        let mut vault = VaultFile::create(&path, &password, KdfParams::fast_for_testing()).unwrap();

        vault.store_mut().add(
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "octocat".to_string(),
                    password: "ghp_secret123".to_string(),
                }),
            )
            .with_category("development")
            .with_tags(vec!["work".to_string(), "code".to_string()])
            .with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .with_favorite(true),
        );

        vault.store_mut().add(
            Entry::new(
                "AWS Keys".to_string(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "aws".to_string(),
                    key: "AKID123".to_string(),
                    secret: "aws_secret".to_string(),
                }),
            )
            .with_category("cloud"),
        );

        vault.store_mut().add(
            Entry::new(
                "Wi-Fi Pass".to_string(),
                Credential::SecureNote(SecureNoteCredential {
                    content: "MyWiFi123".to_string(),
                }),
            ),
        );

        vault.store_mut().add(
            Entry::new(
                "Server SSH".to_string(),
                Credential::SshKey(SshKeyCredential {
                    private_key: "-----BEGIN-----".to_string(),
                    public_key: "ssh-rsa AAAA".to_string(),
                    passphrase: "".to_string(),
                }),
            ),
        );

        vault.save().unwrap();
        (dir, path, vault)
    }

    // ---- cmd_get_with_vault tests ----

    #[test]
    fn test_cmd_get_with_vault_plain() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "github", false, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_json() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "github", false, true, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_not_found() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        let result = cmd_get_with_vault(&vault, "nonexistent_entry_xyz", false, false, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching entries"));
    }

    #[test]
    fn test_cmd_get_with_vault_api_key() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "AWS", false, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_secure_note() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "Wi-Fi", false, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_ssh_key() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "Server SSH", false, false, &config).unwrap();
    }

    // ---- cmd_add_with_vault tests ----

    #[test]
    fn test_cmd_add_with_vault_login() {
        let (_dir, _path, mut vault) = create_test_vault();
        let before_count = vault.store().len();
        cmd_add_with_vault(
            &mut vault,
            "New Login".to_string(),
            "login".to_string(),
            Some("https://example.com".to_string()),
            Some("user".to_string()),
            Some("pass".to_string()),
            Some("personal".to_string()),
            Some("tag1,tag2".to_string()),
            Some("my notes".to_string()),
            Some("TOTP_SECRET".to_string()),
            true,
            false,
        ).unwrap();
        assert_eq!(vault.store().len(), before_count + 1);
    }

    #[test]
    fn test_cmd_add_with_vault_secure_note() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_add_with_vault(
            &mut vault,
            "My Note".to_string(),
            "note".to_string(),
            None, None, None, None, None,
            Some("This is the note content".to_string()),
            None, false, false,
        ).unwrap();
        // Verify the secure note content was set
        let entries = vault.store().list();
        let note_entry = entries.iter().find(|e| e.title == "My Note").unwrap();
        let n = unwrap_secure_note_ref(&note_entry.credential);
        assert_eq!(n.content, "This is the note content");
    }

    #[test]
    fn test_cmd_add_with_vault_api_key() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_add_with_vault(
            &mut vault,
            "Stripe".to_string(),
            "api_key".to_string(),
            Some("stripe".to_string()),
            Some("pk_live_123".to_string()),
            Some("sk_live_456".to_string()),
            None, None, None, None, false, false,
        ).unwrap();
    }

    #[test]
    fn test_cmd_add_with_vault_ssh() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_add_with_vault(
            &mut vault,
            "Deploy Key".to_string(),
            "ssh_key".to_string(),
            Some("passphrase".to_string()),
            Some("ssh-rsa AAAA".to_string()),
            Some("-----BEGIN-----".to_string()),
            None, None, None, None, false, false,
        ).unwrap();
    }

    #[test]
    fn test_cmd_add_with_vault_unknown_type() {
        let (_dir, _path, mut vault) = create_test_vault();
        let result = cmd_add_with_vault(
            &mut vault,
            "Bad".to_string(),
            "unknown_type".to_string(),
            None, None, None, None, None, None, None, false, false,
        );
        assert!(result.is_err());
    }

    // ---- cmd_edit_with_vault tests ----

    #[test]
    fn test_cmd_edit_with_vault_update_title() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_edit_with_vault(
            &mut vault,
            "GitHub".to_string(),
            Some("GitHub Updated".to_string()),
            None, None, None, None, None, None, None, None, None,
        ).unwrap();
        let entries = vault.store().list();
        assert!(entries.iter().any(|e| e.title == "GitHub Updated"));
    }

    #[test]
    fn test_cmd_edit_with_vault_update_all_login_fields() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_edit_with_vault(
            &mut vault,
            "GitHub".to_string(),
            Some("GH".to_string()),
            Some("https://gh.com".to_string()),
            Some("newuser".to_string()),
            Some("newpass".to_string()),
            Some("newcat".to_string()),
            Some("newtag".to_string()),
            Some("newnotes".to_string()),
            Some("NEWSECRET".to_string()),
            Some(false),
            None,
        ).unwrap();

        let entries = vault.store().list();
        let entry = entries.iter().find(|e| e.title == "GH").unwrap();
        assert_eq!(entry.category, Some("newcat".to_string()));
        assert_eq!(entry.tags, vec!["newtag"]);
        assert_eq!(entry.notes, "newnotes");
        assert_eq!(entry.totp_secret, Some("NEWSECRET".to_string()));
        assert!(!entry.favorite);
        let l = unwrap_login_ref(&entry.credential);
        assert_eq!(l.url, "https://gh.com");
        assert_eq!(l.username, "newuser");
        assert_eq!(l.password, "newpass");
    }

    #[test]
    fn test_cmd_edit_with_vault_not_found() {
        let (_dir, _path, mut vault) = create_test_vault();
        let result = cmd_edit_with_vault(
            &mut vault,
            "nonexistent_xyz".to_string(),
            Some("X".to_string()),
            None, None, None, None, None, None, None, None, None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching entries"));
    }

    // ---- cmd_rm_with_vault tests ----

    #[test]
    fn test_cmd_rm_with_vault() {
        let (_dir, _path, mut vault) = create_test_vault();
        let before_count = vault.store().len();
        cmd_rm_with_vault(&mut vault, "GitHub").unwrap();
        assert_eq!(vault.store().len(), before_count - 1);
    }

    #[test]
    fn test_cmd_rm_with_vault_not_found() {
        let (_dir, _path, mut vault) = create_test_vault();
        let result = cmd_rm_with_vault(&mut vault, "nonexistent_xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching entries"));
    }

    // ---- cmd_ls_with_vault tests ----

    #[test]
    fn test_cmd_ls_with_vault_all() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, None, false, false).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, None, false, true).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_favorites() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, None, true, false).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_by_tag() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, Some("work".to_string()), None, false, false).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_by_category() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, Some("development".to_string()), false, false).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_empty_result() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, Some("nonexistent_tag".to_string()), None, false, false).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_favorites_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, None, true, true).unwrap();
    }

    // ---- cmd_search_with_vault tests ----

    #[test]
    fn test_cmd_search_with_vault_found() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_search_with_vault(&vault, "github", false).unwrap();
    }

    #[test]
    fn test_cmd_search_with_vault_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_search_with_vault(&vault, "github", true).unwrap();
    }

    #[test]
    fn test_cmd_search_with_vault_no_results() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_search_with_vault(&vault, "zzz_nonexistent_zzz", false).unwrap();
    }

    #[test]
    fn test_cmd_search_with_vault_no_results_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_search_with_vault(&vault, "zzz_nonexistent_zzz", true).unwrap();
    }

    // ---- cmd_totp_with_vault tests ----

    #[test]
    fn test_cmd_totp_with_vault_plain() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_totp_with_vault(&vault, "GitHub", false, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_totp_with_vault_json() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_totp_with_vault(&vault, "GitHub", false, true, &config).unwrap();
    }

    #[test]
    fn test_cmd_totp_with_vault_not_found() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        let result = cmd_totp_with_vault(&vault, "nonexistent_xyz", false, false, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching entries"));
    }

    #[test]
    fn test_cmd_totp_with_vault_no_totp_secret() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        // AWS Keys has no TOTP
        let result = cmd_totp_with_vault(&vault, "AWS", false, false, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No TOTP secret"));
    }

    // ---- cmd_export_with_vault tests ----

    #[test]
    fn test_cmd_export_with_vault_json_stdout() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_export_with_vault(&vault, "json", None).unwrap();
    }

    #[test]
    fn test_cmd_export_with_vault_csv_stdout() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_export_with_vault(&vault, "csv", None).unwrap();
    }

    #[test]
    fn test_cmd_export_with_vault_json_file() {
        let (_dir, _path, vault) = create_test_vault();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out_path = out_dir.path().join("export.json");
        cmd_export_with_vault(&vault, "json", Some(out_path.clone())).unwrap();
        assert!(out_path.exists());
        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("GitHub"));
    }

    #[test]
    fn test_cmd_export_with_vault_csv_file() {
        let (_dir, _path, vault) = create_test_vault();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out_path = out_dir.path().join("export.csv");
        cmd_export_with_vault(&vault, "csv", Some(out_path.clone())).unwrap();
        assert!(out_path.exists());
        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("Title,Type,URL"));
    }

    #[test]
    fn test_cmd_export_with_vault_unsupported() {
        let (_dir, _path, vault) = create_test_vault();
        let result = cmd_export_with_vault(&vault, "xml", None);
        assert!(result.is_err());
    }

    // ---- cmd_status_with_vault tests ----

    #[test]
    fn test_cmd_status_with_vault_plain() {
        let (_dir, path, vault) = create_test_vault();
        cmd_status_with_vault(&vault, &path, false).unwrap();
    }

    #[test]
    fn test_cmd_status_with_vault_json() {
        let (_dir, path, vault) = create_test_vault();
        cmd_status_with_vault(&vault, &path, true).unwrap();
    }

    // ---- open_vault_with_password tests ----

    #[test]
    fn test_open_vault_with_password_success() {
        let (_dir, path, _vault) = create_test_vault();
        let vault = open_vault_with_password(&path, "testpass".to_string()).unwrap();
        assert!(!vault.store().is_empty());
    }

    #[test]
    fn test_open_vault_with_password_wrong() {
        let (_dir, path, _vault) = create_test_vault();
        let result = open_vault_with_password(&path, "wrongpassword".to_string());
        assert!(result.is_err());
    }

    // ---- cmd_import tests ----

    #[test]
    fn test_cmd_import_csv_into_vault_dry_run() {
        let (_dir, path, _vault) = create_test_vault();
        let import_dir = tempfile::TempDir::new().unwrap();
        let csv_file = import_dir.path().join("export.csv");
        std::fs::write(&csv_file, "Title,Username,Password,URL,OTP,Notes,Type\nImported,user,pass,https://imported.com,,notes,Login\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "import", "--from", "1password", "--dry-run", csv_file.to_str().unwrap()]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_import_csv_with_skipped_entries() {
        let import_dir = tempfile::TempDir::new().unwrap();
        let csv_file = import_dir.path().join("export.csv");
        // Include an entry with empty title which should be skipped
        std::fs::write(&csv_file, "Title,Username,Password,URL,OTP,Notes,Type\nGitHub,user,pass,https://github.com,,notes,Login\n,,,,,empty,Login\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/nonexistent.vclaw", "import", "--from", "1password", "--dry-run", csv_file.to_str().unwrap()]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    // ---- clipboard tests ----

    #[test]
    fn test_cmd_gen_with_clip() {
        let config = AppConfig::default();
        // On macOS this should succeed (pbcopy available)
        let _ = cmd_gen(16, true, false, &config);
    }

    #[test]
    fn test_cmd_gen_with_clip_json() {
        let config = AppConfig::default();
        let _ = cmd_gen(16, true, true, &config);
    }

    #[test]
    fn test_cmd_get_with_vault_clip() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        // Test clip path - on macOS pbcopy should work
        let _ = cmd_get_with_vault(&vault, "GitHub", true, false, &config);
    }

    #[test]
    fn test_cmd_totp_with_vault_clip() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        let _ = cmd_totp_with_vault(&vault, "GitHub", true, false, &config);
    }

    // ---- cmd_get_with_vault for non-login types (no clip action) ----

    #[test]
    fn test_cmd_get_with_vault_clip_non_login() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        // Secure note - clip=true but no password to copy
        cmd_get_with_vault(&vault, "Wi-Fi", true, false, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_json_api_key() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "AWS", false, true, &config).unwrap();
    }

    #[test]
    fn test_cmd_get_with_vault_json_ssh() {
        let (_dir, _path, vault) = create_test_vault();
        let config = AppConfig::default();
        cmd_get_with_vault(&vault, "Server SSH", false, true, &config).unwrap();
    }

    // ---- cmd_ls with tag/category json outputs ----

    #[test]
    fn test_cmd_ls_with_vault_by_tag_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, Some("work".to_string()), None, false, true).unwrap();
    }

    #[test]
    fn test_cmd_ls_with_vault_by_category_json() {
        let (_dir, _path, vault) = create_test_vault();
        cmd_ls_with_vault(&vault, None, Some("development".to_string()), false, true).unwrap();
    }

    // ---- cmd_search_with_vault additional ----

    #[test]
    fn test_cmd_search_with_vault_multiple_results() {
        let (_dir, _path, vault) = create_test_vault();
        // "e" should match multiple entries
        cmd_search_with_vault(&vault, "e", false).unwrap();
    }

    // ---- cmd_edit_with_vault for api key ----

    #[test]
    fn test_cmd_edit_with_vault_api_key() {
        let (_dir, _path, mut vault) = create_test_vault();
        cmd_edit_with_vault(
            &mut vault,
            "AWS".to_string(),
            None,
            Some("new-service".to_string()),
            Some("new-key".to_string()),
            Some("new-secret".to_string()),
            None, None, None, None, None, None,
        ).unwrap();

        let entries = vault.store().list();
        let entry = entries.iter().find(|e| e.title == "AWS Keys").unwrap();
        let a = unwrap_api_key_ref(&entry.credential);
        assert_eq!(a.service, "new-service");
        assert_eq!(a.key, "new-key");
        assert_eq!(a.secret, "new-secret");
    }

    // ---- execute_impl tests ----

    #[test]
    fn test_execute_impl_init() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("new.vclaw");
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "init"]);
        execute_impl(cli, |_| "testpassword".to_string()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_execute_impl_init_passwords_mismatch() {
        use std::cell::Cell;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("new.vclaw");
        let call_count = Cell::new(0u32);
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "init"]);
        let result = execute_impl(cli, |_| {
            let n = call_count.get();
            call_count.set(n + 1);
            if n == 0 { "pass1".to_string() } else { "pass2".to_string() }
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Passwords do not match"));
    }

    #[test]
    fn test_execute_impl_get() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "get", "GitHub"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_add() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "add", "--title", "New", "--password", "p"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_edit() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "edit", "GitHub", "--title", "GH"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_rm() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "rm", "GitHub"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_ls() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "ls"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_search() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "search", "git"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_totp() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "totp", "GitHub"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_gen() {
        let cli = Cli::parse_from(["vaultclaw", "gen"]);
        execute_impl(cli, |_| "test".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_export_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "export"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_status_with_vault() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "status"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_status_json_with_vault() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "status"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_import_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let csv_file = dir.path().join("export.csv");
        std::fs::write(&csv_file, "Title,Username,Password,URL,OTP,Notes,Type\nGitHub,user,pass,https://github.com,,notes,Login\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", "/tmp/nonexistent.vclaw", "import", "--from", "1password", "--dry-run", csv_file.to_str().unwrap()]);
        execute_impl(cli, |_| "test".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_import_into_vault() {
        let (_dir, path, _vault) = create_test_vault();
        let import_dir = tempfile::TempDir::new().unwrap();
        let csv_file = import_dir.path().join("export.csv");
        std::fs::write(&csv_file, "Title,Username,Password,URL,OTP,Notes,Type\nImported,user,pass,https://imported.com,,notes,Login\n").unwrap();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "import", "--from", "1password", csv_file.to_str().unwrap()]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_apply_edits_apikey_no_changes() {
        let mut entry = Entry::new(
            "API".to_string(),
            Credential::ApiKey(ApiKeyCredential {
                service: "svc".to_string(),
                key: "k".to_string(),
                secret: "s".to_string(),
            }),
        );
        apply_entry_edits(&mut entry, None, None, None, None, None, None, None, None, None, None);
        let a = unwrap_api_key_ref(&entry.credential);
        assert_eq!(a.service, "svc");
        assert_eq!(a.key, "k");
        assert_eq!(a.secret, "s");
    }

    #[test]
    fn test_execute_impl_export_csv() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "export", "--format", "csv"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_export_to_file() {
        let (_dir, path, _vault) = create_test_vault();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out_file = out_dir.path().join("out.json");
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "export", "--output", out_file.to_str().unwrap()]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
        assert!(out_file.exists());
    }

    #[test]
    fn test_execute_impl_ls_with_tag() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "ls", "--tag", "work"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_ls_with_category() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "ls", "--cat", "development"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_ls_favorites() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "ls", "--favorites"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_get_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "get", "GitHub"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_search_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "search", "git"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_totp_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "totp", "GitHub"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_gen_json() {
        let cli = Cli::parse_from(["vaultclaw", "--json", "gen"]);
        execute_impl(cli, |_| "test".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_ls_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "ls"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_health() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "health"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_health_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "health"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_watch() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "watch"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_watch_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "watch"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_agent_tokens() {
        let cli = Cli::parse_from(["vaultclaw", "agent", "tokens"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_agent_pending() {
        let cli = Cli::parse_from(["vaultclaw", "agent", "pending"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_agent_audit() {
        let cli = Cli::parse_from(["vaultclaw", "agent", "audit"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_sync_status() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.vclaw");
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "sync", "status"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_execute_impl_sync_status_with_vault() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "sync", "status"]);
        execute_impl(cli, |_| "testpass".to_string()).unwrap();
    }

    #[test]
    fn test_cmd_export_csv_format() {
        let (_dir, _path, vault) = create_test_vault();
        let result = export_entries_to_string(&vault.store().entries(), "csv");
        assert!(result.is_ok());
        let csv = result.unwrap();
        assert!(csv.contains("Title"));
        assert!(csv.contains("GitHub"));
    }

    #[test]
    fn test_cmd_export_unsupported_format() {
        let result = export_entries_to_string(&[], "xml");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported export format"));
    }

    // ---- Daemon CLI parsing tests ----

    #[test]
    fn test_cli_parsing_daemon_status() {
        let cli = Cli::parse_from(["vaultclaw", "daemon", "status"]);
        assert!(matches!(cli.command, Commands::Daemon { .. }));
    }

    #[test]
    fn test_cli_parsing_daemon_start() {
        let cli = Cli::parse_from(["vaultclaw", "daemon", "start"]);
        assert!(matches!(cli.command, Commands::Daemon { .. }));
    }

    #[test]
    fn test_cli_parsing_daemon_stop() {
        let cli = Cli::parse_from(["vaultclaw", "daemon", "stop"]);
        assert!(matches!(cli.command, Commands::Daemon { .. }));
    }

    #[test]
    fn test_cli_parsing_unlock() {
        let cli = Cli::parse_from(["vaultclaw", "unlock"]);
        assert!(matches!(cli.command, Commands::Unlock { recovery: false, .. }));
    }

    #[test]
    fn test_cli_parsing_no_daemon_flag() {
        let cli = Cli::parse_from(["vaultclaw", "--no-daemon", "status"]);
        assert!(cli.no_daemon);
    }

    #[test]
    fn test_cli_parsing_no_daemon_false_by_default() {
        let cli = Cli::parse_from(["vaultclaw", "status"]);
        assert!(!cli.no_daemon);
    }

    // ---- execute_impl with daemon-related commands ----

    #[test]
    fn test_execute_impl_daemon_status() {
        let cli = Cli::parse_from(["vaultclaw", "daemon", "status"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_daemon_stop_not_running() {
        let cli = Cli::parse_from(["vaultclaw", "daemon", "stop"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok()); // prints "not running" but doesn't error
    }

    #[test]
    fn test_execute_impl_unlock_no_daemon() {
        let cli = Cli::parse_from(["vaultclaw", "unlock"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    #[test]
    fn test_execute_impl_no_daemon_flag() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--no-daemon", "status"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_daemon_status_json() {
        let cli = Cli::parse_from(["vaultclaw", "--json", "daemon", "status"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    // ---- send_daemon_request error path ----
    #[test]
    fn test_send_daemon_request_not_connected() {
        let result = DaemonClient::connect(
            &PathBuf::from("/tmp/nonexistent_vaultclaw_send_test.sock")
        );
        assert!(result.is_err());
    }

    // ---- Daemon-routed helper integration tests ----

    /// Helper to start a test daemon, unlock it, and return a connected client.
    fn start_unlocked_daemon() -> (tempfile::TempDir, DaemonClient, tokio::runtime::Runtime) {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("test.vclaw");
        let socket_path = dir.path().join("route_test.sock");
        let password = crate::crypto::keys::password_secret("testpass".to_string());
        let params = crate::crypto::kdf::KdfParams::fast_for_testing();
        let mut vault = VaultFile::create(&vault_path, &password, params).unwrap();
        vault.store_mut().add(
            Entry::new(
                "GitHub".to_string(),
                Credential::Login(LoginCredential {
                    url: "https://github.com".to_string(),
                    username: "octocat".to_string(),
                    password: "ghp_secret".to_string(),
                }),
            ).with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .with_category("development")
            .with_tags(vec!["work".to_string()])
            .with_favorite(true),
        );
        vault.store_mut().add(
            Entry::new(
                "AWS Keys".to_string(),
                Credential::ApiKey(ApiKeyCredential {
                    service: "aws".to_string(),
                    key: "AKID123".to_string(),
                    secret: "aws_secret".to_string(),
                }),
            ),
        );
        vault.save().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut state = crate::daemon::server::DaemonState::new(vault_path, 300);
        state.unlock(&password).unwrap();
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(state));
        let socket_clone = socket_path.clone();
        let state_clone = state.clone();
        rt.spawn(async move {
            let _ = crate::daemon::server::run_server(&socket_clone, state_clone).await;
        });

        std::thread::sleep(std::time::Duration::from_millis(150));
        let client = DaemonClient::connect(&socket_path).unwrap();
        (dir, client, rt)
    }

    #[test]
    fn test_cmd_get_via_daemon_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_get_via_daemon(&mut client, "github", false, false, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_get_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_get_via_daemon(&mut client, "github", false, true, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_get_via_daemon_not_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_get_via_daemon(&mut client, "zzz_nonexistent_zzz", false, false, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_get_via_daemon_clip() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let _ = cmd_get_via_daemon(&mut client, "github", true, false, &config);
    }

    #[test]
    fn test_cmd_ls_via_daemon_all() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, None, None, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_ls_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, None, None, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_ls_via_daemon_favorites() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, None, None, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_ls_via_daemon_by_tag() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, Some("work".to_string()), None, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_ls_via_daemon_by_category() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, None, Some("development".to_string()), false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_ls_via_daemon_empty() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_ls_via_daemon(&mut client, Some("nonexistent_tag".to_string()), None, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_search_via_daemon_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_search_via_daemon(&mut client, "github", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_search_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_search_via_daemon(&mut client, "github", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_search_via_daemon_empty() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_search_via_daemon(&mut client, "zzz_nonexistent_zzz", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_search_via_daemon_empty_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_search_via_daemon(&mut client, "zzz_nonexistent_zzz", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_totp_via_daemon_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_totp_via_daemon(&mut client, "github", false, false, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_totp_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_totp_via_daemon(&mut client, "github", false, true, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_totp_via_daemon_not_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        let result = cmd_totp_via_daemon(&mut client, "zzz_nonexistent", false, false, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_status_via_daemon() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_status_via_daemon(&mut client, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_status_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_status_via_daemon(&mut client, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_add_via_daemon() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_add_via_daemon(
            &mut client,
            "New Entry".to_string(),
            "login".to_string(),
            Some("https://new.com".to_string()),
            Some("user".to_string()),
            Some("pass".to_string()),
            Some("cat".to_string()),
            Some("tag1,tag2".to_string()),
            Some("notes".to_string()),
            None,
            false,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_edit_via_daemon() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_edit_via_daemon(
            &mut client,
            "GitHub".to_string(),
            Some("GitHub Updated".to_string()),
            None, None, None, None, None, None, None, None, None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_edit_via_daemon_not_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_edit_via_daemon(
            &mut client,
            "zzz_nonexistent".to_string(),
            Some("New".to_string()),
            None, None, None, None, None, None, None, None, None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_rm_via_daemon() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_rm_via_daemon(&mut client, "AWS");
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_rm_via_daemon_not_found() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_rm_via_daemon(&mut client, "zzz_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_export_via_daemon_json() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_export_via_daemon(&mut client, "json", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_export_via_daemon_csv() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_export_via_daemon(&mut client, "csv", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_export_via_daemon_to_file() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out_path = out_dir.path().join("export.json");
        let result = cmd_export_via_daemon(&mut client, "json", Some(out_path.clone()));
        assert!(result.is_ok());
        assert!(out_path.exists());
    }

    #[test]
    fn test_cmd_export_via_daemon_unsupported() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_export_via_daemon(&mut client, "xml", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_get_via_daemon_clip_non_login() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        // AWS is an API key, clip should work but no password copy
        let result = cmd_get_via_daemon(&mut client, "AWS", true, false, &config);
        assert!(result.is_ok());
    }

    // ---- Lease CLI parsing tests ----

    #[test]
    fn test_cli_parsing_lease_list() {
        let cli = Cli::parse_from(["vaultclaw", "lease", "list"]);
        assert!(matches!(cli.command, Commands::Lease { .. }));
    }

    #[test]
    fn test_cli_parsing_lease_revoke_all() {
        let cli = Cli::parse_from(["vaultclaw", "lease", "revoke-all"]);
        assert!(matches!(cli.command, Commands::Lease { .. }));
    }

    #[test]
    fn test_cli_parsing_lease_revoke() {
        let id = uuid::Uuid::new_v4();
        let cli = Cli::parse_from(["vaultclaw", "lease", "revoke", &id.to_string()]);
        assert!(matches!(cli.command, Commands::Lease { .. }));
    }

    #[test]
    fn test_cli_parsing_lease_sensitivity() {
        let id = uuid::Uuid::new_v4();
        let cli = Cli::parse_from(["vaultclaw", "lease", "sensitivity", &id.to_string(), "high"]);
        assert!(matches!(cli.command, Commands::Lease { .. }));
    }

    // ---- Completions & Config & Manpage CLI parsing ----

    #[test]
    fn test_cli_parsing_completions_bash() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "bash"]);
        assert!(matches!(cli.command, Commands::Completions { shell: ShellArg::Bash }));
    }

    #[test]
    fn test_cli_parsing_completions_zsh() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "zsh"]);
        assert!(matches!(cli.command, Commands::Completions { shell: ShellArg::Zsh }));
    }

    #[test]
    fn test_cli_parsing_completions_fish() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "fish"]);
        assert!(matches!(cli.command, Commands::Completions { shell: ShellArg::Fish }));
    }

    #[test]
    fn test_cli_parsing_completions_powershell() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "power-shell"]);
        assert!(matches!(cli.command, Commands::Completions { shell: ShellArg::PowerShell }));
    }

    #[test]
    fn test_cli_parsing_completions_elvish() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "elvish"]);
        assert!(matches!(cli.command, Commands::Completions { shell: ShellArg::Elvish }));
    }

    #[test]
    fn test_cli_parsing_config_show() {
        let cli = Cli::parse_from(["vaultclaw", "config", "show"]);
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    #[test]
    fn test_cli_parsing_config_get() {
        let cli = Cli::parse_from(["vaultclaw", "config", "get", "vault_path"]);
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    #[test]
    fn test_cli_parsing_config_set() {
        let cli = Cli::parse_from(["vaultclaw", "config", "set", "http_port", "8080"]);
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    #[test]
    fn test_cli_parsing_config_path() {
        let cli = Cli::parse_from(["vaultclaw", "config", "path"]);
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    #[test]
    fn test_cli_parsing_config_reset() {
        let cli = Cli::parse_from(["vaultclaw", "config", "reset"]);
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    #[test]
    fn test_cli_parsing_manpage() {
        let cli = Cli::parse_from(["vaultclaw", "manpage"]);
        assert!(matches!(cli.command, Commands::Manpage));
    }

    #[test]
    fn test_cli_parsing_quiet_flag() {
        let cli = Cli::parse_from(["vaultclaw", "--quiet", "status"]);
        assert!(cli.quiet);
    }

    // ---- Passkey credential tests ----

    #[test]
    fn test_build_credential_passkey() {
        let (cred, needs_prompt) = build_credential(
            "passkey",
            Some("https://example.com".into()),
            Some("Example Site".into()),
            Some("testuser".into()),
        ).unwrap();
        assert!(!needs_prompt);
        match cred {
            Credential::Passkey(pk) => {
                assert_eq!(pk.rp_id, "https://example.com");
                assert_eq!(pk.rp_name, "Example Site");
                assert_eq!(pk.user_name, "testuser");
                assert_eq!(pk.sign_count, 0);
                assert!(pk.discoverable);
            }
            _ => panic!("Expected Passkey credential"),
        }
    }

    #[test]
    fn test_build_credential_passkey_defaults() {
        let (cred, _) = build_credential("passkey", None, None, None).unwrap();
        match cred {
            Credential::Passkey(pk) => {
                assert_eq!(pk.rp_id, "");
                assert_eq!(pk.rp_name, "");
                assert_eq!(pk.user_name, "");
            }
            _ => panic!("Expected Passkey credential"),
        }
    }

    #[test]
    fn test_print_entry_passkey() {
        let entry = Entry::new(
            "Example Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred123".into(),
                rp_id: "example.com".into(),
                rp_name: "Example".into(),
                user_handle: "dXNlcg".into(),
                user_name: "alice".into(),
                private_key: "privkey".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 5,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: Some(chrono::Utc::now()),
            }),
        );
        // Just verify it doesn't panic
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_passkey_no_last_used() {
        let entry = Entry::new(
            "Passkey No Last Used".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred".into(),
                rp_id: "site.com".into(),
                rp_name: "Site".into(),
                user_handle: "".into(),
                user_name: "bob".into(),
                private_key: "".into(),
                algorithm: PasskeyAlgorithm::EdDsa,
                sign_count: 0,
                discoverable: false,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        print_entry(&entry);
    }

    #[test]
    fn test_print_entry_summary_passkey() {
        let entry = Entry::new(
            "My Passkey".to_string(),
            Credential::Passkey(PasskeyCredential {
                credential_id: "cred".into(),
                rp_id: "example.com".into(),
                rp_name: "Example".into(),
                user_handle: "".into(),
                user_name: "user1".into(),
                private_key: "".into(),
                algorithm: PasskeyAlgorithm::Es256,
                sign_count: 0,
                discoverable: true,
                backup_eligible: false,
                backup_state: false,
                last_used_at: None,
            }),
        );
        // Verify it doesn't panic and exercises the Passkey branch
        print_entry_summary(&entry);
    }

    // ---- export_entries_to_string with Passkey (covers CSV Passkey branch) ----

    #[test]
    fn test_export_entries_csv_with_passkey() {
        let entries = vec![
            Entry::new(
                "My Passkey".to_string(),
                Credential::Passkey(PasskeyCredential {
                    credential_id: "cred123".into(),
                    rp_id: "example.com".into(),
                    rp_name: "Example".into(),
                    user_handle: "dXNlcg".into(),
                    user_name: "alice".into(),
                    private_key: "privkey".into(),
                    algorithm: PasskeyAlgorithm::Es256,
                    sign_count: 0,
                    discoverable: true,
                    backup_eligible: false,
                    backup_state: false,
                    last_used_at: None,
                }),
            ),
        ];
        let csv = export_entries_to_string(&entries, "csv").unwrap();
        assert!(csv.contains("My Passkey"));
        assert!(csv.contains("example.com"));
        assert!(csv.contains("alice"));
    }

    // ---- apply_entry_edits with sensitive field (covers line 1171) ----

    #[test]
    fn test_apply_edits_with_sensitive() {
        let mut entry = Entry::new(
            "Test".to_string(),
            Credential::Login(LoginCredential {
                url: "u".into(), username: "u".into(), password: "p".into(),
            }),
        );
        assert!(!entry.sensitive);
        apply_entry_edits(
            &mut entry, None, None, None, None, None, None, None, None, None, Some(true),
        );
        assert!(entry.sensitive);

        apply_entry_edits(
            &mut entry, None, None, None, None, None, None, None, None, None, Some(false),
        );
        assert!(!entry.sensitive);
    }

    // ---- execute_impl tests for dispatch arms not yet covered ----

    #[test]
    fn test_execute_impl_backup_list() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "backup", "list"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_backup_create() {
        let (_dir, path, _vault) = create_test_vault();
        let backup_dir = tempfile::TempDir::new().unwrap();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", path.to_str().unwrap(),
            "backup", "create", "--path", backup_dir.path().to_str().unwrap(),
        ]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_breach() {
        let (_dir, path, _vault) = create_test_vault();
        // --entry with a specific entry avoids network calls
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", path.to_str().unwrap(),
            "breach", "--entry", "GitHub",
        ]);
        // This may fail due to network, but it exercises the dispatch arm
        let _ = execute_impl(cli, |_| "testpass".to_string());
    }

    #[test]
    fn test_execute_impl_report() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "report"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_report_json() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "--json", "report"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_rotate_scan() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "rotate", "scan"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_rotate_list() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "rotate", "list"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_rotate_status() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from(["vaultclaw", "--vault", path.to_str().unwrap(), "rotate", "status"]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_vault_list() {
        let cli = Cli::parse_from(["vaultclaw", "vault", "list"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_browser_host_show_manifest() {
        let cli = Cli::parse_from([
            "vaultclaw", "browser-host", "show-manifest", "chrome", "test-extension-id",
        ]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_browser_host_uninstall() {
        let cli = Cli::parse_from(["vaultclaw", "browser-host", "uninstall"]);
        let result = execute_impl(cli, |_| "test".to_string());
        // May succeed or fail depending on whether manifests exist
        let _ = result;
    }

    #[test]
    fn test_execute_impl_redact_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "Hello world, no secrets here").unwrap();
        let cli = Cli::parse_from([
            "vaultclaw", "redact", "--scan", file.to_str().unwrap(),
        ]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_redact_with_report() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE").unwrap();
        let cli = Cli::parse_from([
            "vaultclaw", "redact", "--report", file.to_str().unwrap(),
        ]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_scan_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.env");
        std::fs::write(&file, "DATABASE_URL=postgres://user:pass@localhost/db").unwrap();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", "/tmp/nonexistent.vclaw",
            "scan", "--dry-run", dir.path().to_str().unwrap(),
        ]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_passkey_list() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", path.to_str().unwrap(), "passkey", "list",
        ]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_yubikey_list() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", path.to_str().unwrap(), "yubikey", "list",
        ]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_yubikey_recovery() {
        let (_dir, path, _vault) = create_test_vault();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", path.to_str().unwrap(), "yubikey", "recovery",
        ]);
        let result = execute_impl(cli, |_| "testpass".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_completions_bash() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "bash"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_completions_zsh() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "zsh"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_completions_fish() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "fish"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_completions_powershell() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "power-shell"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_completions_elvish() {
        let cli = Cli::parse_from(["vaultclaw", "completions", "elvish"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_config_show() {
        let cli = Cli::parse_from(["vaultclaw", "config", "show"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_config_path() {
        let cli = Cli::parse_from(["vaultclaw", "config", "path"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_config_get() {
        let cli = Cli::parse_from(["vaultclaw", "config", "get", "http_port"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_manpage() {
        let cli = Cli::parse_from(["vaultclaw", "manpage"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_lease_no_daemon() {
        let cli = Cli::parse_from(["vaultclaw", "--no-daemon", "lease", "list"]);
        let result = execute_impl(cli, |_| "test".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("require a running daemon"));
    }

    #[test]
    fn test_execute_impl_inject() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("config.json");
        std::fs::write(&file, r#"{"key": "plain_value"}"#).unwrap();
        let cli = Cli::parse_from([
            "vaultclaw", "--vault", "/tmp/nonexistent.vclaw", "--no-daemon",
            "inject", file.to_str().unwrap(),
        ]);
        let result = execute_impl(cli, |_| "test".to_string());
        // inject with no vclaw:// refs should succeed (pass through)
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_impl_init_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested_path = dir.path().join("a").join("b").join("c").join("vault.vclaw");
        let cli = Cli::parse_from(["vaultclaw", "--vault", nested_path.to_str().unwrap(), "init"]);
        execute_impl(cli, |_| "testpassword".to_string()).unwrap();
        assert!(nested_path.exists());
    }

    // ---- Daemon-routed tests for additional coverage ----

    #[test]
    fn test_cmd_add_via_daemon_secure_note() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_add_via_daemon(
            &mut client,
            "My Note".to_string(),
            "note".to_string(),
            None, None, None, None, None,
            Some("Note content here".to_string()),
            None, false, false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_add_via_daemon_with_sensitive() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_add_via_daemon(
            &mut client,
            "Sensitive Entry".to_string(),
            "login".to_string(),
            Some("https://secret.com".to_string()),
            Some("admin".to_string()),
            Some("supersecret".to_string()),
            None, None, None, None, false, true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_totp_via_daemon_clip() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let config = AppConfig::default();
        // Clip path for totp via daemon - on macOS pbcopy should work
        let _ = cmd_totp_via_daemon(&mut client, "github", true, false, &config);
    }

    #[test]
    fn test_cmd_edit_via_daemon_all_fields() {
        let (_dir, mut client, _rt) = start_unlocked_daemon();
        let result = cmd_edit_via_daemon(
            &mut client,
            "GitHub".to_string(),
            Some("GitHub Enterprise".to_string()),
            Some("https://github.example.com".to_string()),
            Some("newuser".to_string()),
            Some("newpass".to_string()),
            Some("enterprise".to_string()),
            Some("corp,git".to_string()),
            Some("Updated notes".to_string()),
            Some("NEWSECRET".to_string()),
            Some(false),
            Some(true),
        );
        assert!(result.is_ok());
    }
}
