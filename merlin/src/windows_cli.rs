//! The Windows command line. Without a subcommand it is the collector the
//! installer schedules: `merlin --config <path>` checks in now and then on
//! the server's interval; `--once` checks in once; `--check-config`
//! validates the configuration without checking in or printing secrets.
//! `discover` and `posture` print what it would report.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use crate::windows_checkin::{self, CheckIn, Config, Inventory, SchannelTransport};
use crate::windows_discovery::{self, ContainedFs, DiscoveryRoots, HandleFs, valid_workspace_root};
use crate::{windows_host, windows_posture, windows_wsl};

#[derive(Parser)]
#[command(
    name = "merlin",
    version,
    about = "Deixic Endpoint: inventory, AI tool discovery and posture for Windows"
)]
struct Cli {
    /// Restricted per-device configuration (sync_url, device_id,
    /// device_token, optional workspace_roots).
    #[arg(long, default_value_os_t = default_config_path())]
    config: PathBuf,
    /// Check in once and exit.
    #[arg(long)]
    once: bool,
    /// Validate the configuration and exit without checking in.
    #[arg(long)]
    check_config: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the AI tools, MCP servers, agent files and agent processes found
    /// on this computer as JSON: names and fixed source labels only.
    Discover {
        /// A local absolute directory to scan for project AI files, with up
        /// to 32 directories below it (repeatable, at most 8).
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<String>,
    },
    /// Print this computer's security settings (posture schema version 2)
    /// as JSON: pass, finding or unavailable per check, with evidence hashes.
    Posture,
}

fn default_config_path() -> PathBuf {
    let program_data = std::env::var_os("ProgramData").unwrap_or_default();
    Path::new(&program_data)
        .join("Deixic")
        .join("Endpoint")
        .join("config.json")
}

/// Read the configuration with the same handle-verified read discovery uses:
/// no reparse point, at most 16 KiB.
fn load_config(path: &Path) -> Result<Config> {
    let parent = path
        .parent()
        .context("read configuration: no parent directory")?;
    let body = HandleFs
        .read_within(parent, path, windows_checkin::MAX_CONFIG_BYTES)
        .context("read configuration: missing, linked, oversized or unreadable")?;
    windows_checkin::parse_config(&body)
}

/// Where the WSL plugin leaves its results.
fn wsl_dir() -> PathBuf {
    let program_data = std::env::var_os("ProgramData").unwrap_or_default();
    Path::new(&program_data)
        .join("Deixic")
        .join("Endpoint")
        .join("wsl")
}

fn discover(workspaces: Vec<PathBuf>) -> windows_discovery::WindowsDiscovery {
    let mut found = windows_discovery::collect(&HandleFs, &DiscoveryRoots::system(workspaces));
    found.processes = windows_host::agent_processes();
    found
}

pub(crate) fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Discover { workspace_roots }) => {
            ensure!(workspace_roots.len() <= 8, "at most 8 workspace roots");
            ensure!(
                workspace_roots
                    .iter()
                    .all(|root| valid_workspace_root(root)),
                "workspace roots must be local absolute paths without traversal"
            );
            let found = discover(workspace_roots.into_iter().map(PathBuf::from).collect());
            println!("{}", serde_json::to_string_pretty(&found)?);
            Ok(())
        }
        Some(Cmd::Posture) => {
            let posture = windows_posture::collect(&windows_host::WindowsHost, SystemTime::now());
            println!("{}", serde_json::to_string_pretty(&posture)?);
            Ok(())
        }
        None => {
            let config = match load_config(&cli.config) {
                Ok(config) => config,
                Err(error) => {
                    // The installer reads a non-zero exit as a rejected
                    // configuration; the message carries no file values.
                    eprintln!("{error:#}");
                    std::process::exit(2);
                }
            };
            if cli.check_config {
                return Ok(());
            }
            run(&config, cli.once)
        }
    }
}

fn run(config: &Config, once: bool) -> Result<()> {
    let host = windows_host::hostname()?;
    let host = windows_checkin::valid_host(&host)?.to_string();
    let transport = SchannelTransport::new();
    loop {
        let mut discovery = discover(config.workspace_roots.clone());
        let wsl = windows_wsl::collect(
            &HandleFs,
            &wsl_dir(),
            &windows_host::registered_wsl_distros(),
        );
        windows_discovery::merge_off_host(&mut discovery, wsl.mcp_servers, wsl.agent_assets);
        let mut inventory = Inventory::new(discovery, SystemTime::now());
        // WSL distributions first, then this computer's unread files.
        let host_coverage = std::mem::replace(&mut inventory.ai_location_coverage, wsl.coverage);
        for entry in host_coverage {
            crate::ai_discovery::add_coverage(&mut inventory.ai_location_coverage, entry);
        }
        let posture = windows_posture::collect(&windows_host::WindowsHost, SystemTime::now());
        let check_in = CheckIn::new(&host, inventory, posture);
        let result = windows_checkin::post_check_in(&transport, config, &check_in);
        if once {
            return result.map(|_| ());
        }
        std::thread::sleep(windows_checkin::next_wait(result));
    }
}
