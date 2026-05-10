use crate::app;
use crate::client_api;
use crate::paths::AppPaths;
use crate::state::AppState;
use crate::state::invite;
#[path = "doctor.rs"]
mod doctor;
#[path = "install.rs"]
mod install;
use home_node::agent::prepare_agent_from_path;
use medium_session::{ConnectOptions, TransportMode};
use overlay_protocol::{DeviceRecord, PublishedService, ServiceKind, SessionOpenGrant};
use sqlx::Row;
use std::io as std_io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::mpsc;
use std::time::Duration;

const HELP: &str = r#"Medium CLI

Usage:
  medium <command> [options]

Bootstrap:
  medium init-control [--reconfigure]
      Initialize a control-plane host.
  medium init-node <node-invite> [--reconfigure]
      Initialize a node that publishes services.
  medium join <invite>
      Join this client to a Medium network.

Client:
  medium devices
      List devices and SSH endpoints visible to this joined client.
  medium services
      List published services visible to this joined client.
  medium ssh [-v|--verbose] [--relay] <device>
      Open SSH to a device through Medium with an ephemeral certified key.
      Use --relay to skip direct TCP candidates and force relay transport.

Control-plane diagnostics:
  medium control devices
      Read the control-plane registry and show registered nodes and services.
      Run this on a control-plane host, usually with sudo.
  medium control restart
      Restart the local systemd relay and control-plane services.
  medium doctor
      Inspect local config, state, binaries, and service status.

Node runtime:
  medium run [--config <path>]
      Run node-agent using ~/.medium/node.toml by default.
  medium node restart
      Restart the local systemd node-agent service.

SSH and proxy:
  medium proxy ssh --device <name> [--verbose] [--relay]
      Internal SSH TCP proxy used by `medium ssh`.

Maintenance:
  medium info
      Print product information.
  medium normalize-label <value>
      Normalize a node or device label.

Run `medium help <command>` is not supported yet.
"#;

enum Command {
    InitControl {
        reconfigure: bool,
    },
    InitNode {
        invite: String,
        reconfigure: bool,
    },
    Run {
        config_path: PathBuf,
    },
    Join {
        invite: String,
    },
    Pair {
        server_url: String,
        device_name: String,
    },
    Devices,
    Services,
    Ssh {
        device_name: String,
        verbose: bool,
        force_relay: bool,
    },
    ControlDevices,
    ControlRestart,
    NodeRestart,
    Help,
    ProxySsh {
        device_name: String,
        verbose: bool,
        force_relay: bool,
    },
    ProxyService {
        node_name: String,
        service_id: String,
        verbose: bool,
        force_relay: bool,
    },
    Doctor,
    Info,
    NormalizeLabel {
        value: String,
    },
}

pub fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    match parse(args)? {
        Command::Run { config_path } => {
            if !config_path.is_file() {
                return Err(format!(
                    "node config not found at {}",
                    config_path.display()
                ));
            }
            let agent = prepare_agent_from_path(config_path).map_err(|error| error.to_string())?;
            Ok(agent.startup_summary())
        }
        Command::Info => Ok(app::summary().to_string()),
        Command::Help => Ok(HELP.to_string()),
        Command::NormalizeLabel { value } => Ok(app::normalize_device_label(&value)),
        Command::InitControl { .. }
        | Command::InitNode { .. }
        | Command::Join { .. }
        | Command::Pair { .. }
        | Command::Devices
        | Command::Services
        | Command::Ssh { .. }
        | Command::ControlDevices
        | Command::ControlRestart
        | Command::NodeRestart
        | Command::ProxySsh { .. }
        | Command::ProxyService { .. }
        | Command::Doctor => Err("command requires runtime context; use run_main".into()),
    }
}

pub async fn run_main<I>(args: I) -> Result<Option<String>, String>
where
    I: IntoIterator<Item = String>,
{
    match parse(args)? {
        Command::InitControl { reconfigure } => {
            let report =
                install::init_control(reconfigure).map_err(|error| format!("{error:#}"))?;
            Ok(Some(format!(
                "initialized Medium control at {} and generated invite {}\ngenerated node invite {}",
                report.control_config_path.display(),
                report.invite,
                report.node_invite
            )))
        }
        Command::InitNode {
            invite,
            reconfigure,
        } => {
            let report = install::init_node(&invite, reconfigure)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(Some(format!(
                "initialized Medium node at {}",
                report.node_config_path.display()
            )))
        }
        Command::Run { config_path } => {
            if !config_path.is_file() {
                return Err(format!(
                    "node config not found at {}",
                    config_path.display()
                ));
            }
            let agent = prepare_agent_from_path(config_path).map_err(|error| error.to_string())?;
            agent
                .run_until_shutdown()
                .await
                .map_err(|error| format!("node-agent failed: {error:#}"))?;
            Ok(None)
        }
        Command::Join { invite } => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let invite = invite::parse_invite(&invite).map_err(|error| error.to_string())?;
            let state = client_api::join(&invite)
                .await
                .map_err(|error| error.to_string())?;
            state.save(&paths).map_err(|error| error.to_string())?;
            Ok(Some(format!(
                "joined {} via {} using invite v{}",
                state.device_name, state.server_url, state.invite_version
            )))
        }
        Command::Pair {
            server_url,
            device_name,
        } => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let state = client_api::pair(&server_url, &device_name)
                .await
                .map_err(|error| error.to_string())?;
            state.save(&paths).map_err(|error| error.to_string())?;
            Ok(Some(format!(
                "paired {} with {} using bootstrap code {}",
                state.device_name, state.server_url, state.bootstrap_code
            )))
        }
        Command::Devices => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let state = AppState::load(&paths).map_err(|error| {
                format!(
                    "{}; `medium devices` is a client command, run `medium join <invite>` first or use `medium control devices` on a control-plane host",
                    error
                )
            })?;
            let devices = client_api::fetch_devices(&state)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Some(render_devices(&devices.devices)))
        }
        Command::Services => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let state = AppState::load(&paths).map_err(|error| {
                format!(
                    "{}; `medium services` is a client command, run `medium join <invite>` first",
                    error
                )
            })?;
            let devices = client_api::fetch_devices(&state)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Some(render_services(&devices.devices)))
        }
        Command::ControlDevices => {
            let report = render_control_devices()
                .await
                .map_err(|error| error.to_string())?;
            Ok(Some(report))
        }
        Command::ControlRestart => {
            let services =
                install::restart_control_services().map_err(|error| format!("{error:#}"))?;
            Ok(Some(format!("restarted {}", services.join(", "))))
        }
        Command::NodeRestart => {
            let service = install::restart_node_service().map_err(|error| format!("{error:#}"))?;
            Ok(Some(format!("restarted {service}")))
        }
        Command::Ssh {
            device_name,
            verbose,
            force_relay,
        } => run_ssh_command(&device_name, verbose, force_relay)
            .await
            .map(|()| None),
        Command::ProxySsh {
            device_name,
            verbose,
            force_relay,
        } => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let state = AppState::load(&paths).map_err(|error| error.to_string())?;
            let devices = client_api::fetch_devices(&state)
                .await
                .map_err(|error| error.to_string())?;
            run_proxy_ssh(&state, &devices.devices, &device_name, verbose, force_relay)
                .await
                .map_err(|error| error.to_string())?;
            Ok(None)
        }
        Command::ProxyService {
            node_name,
            service_id,
            verbose,
            force_relay,
        } => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let state = AppState::load(&paths).map_err(|error| error.to_string())?;
            let devices = client_api::fetch_devices(&state)
                .await
                .map_err(|error| error.to_string())?;
            run_proxy_service(
                &state,
                &devices.devices,
                &node_name,
                &service_id,
                verbose,
                force_relay,
            )
            .await
            .map_err(|error| error.to_string())?;
            Ok(None)
        }
        Command::Doctor => {
            let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
            let report = doctor::inspect(&paths).map_err(|error| error.to_string())?;
            Ok(Some(report.render()))
        }
        Command::Info => Ok(Some(app::summary().to_string())),
        Command::Help => Ok(Some(HELP.to_string())),
        Command::NormalizeLabel { value } => Ok(Some(app::normalize_device_label(&value))),
    }
}

fn parse<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();

    match args.as_slice() {
        [_binary] => Ok(Command::Help),
        [_binary, command] if command == "help" || command == "--help" || command == "-h" => {
            Ok(Command::Help)
        }
        [_binary, command] if command == "init-control" => {
            Ok(Command::InitControl { reconfigure: false })
        }
        [_binary, command, flag] if command == "init-control" && flag == "--reconfigure" => {
            Ok(Command::InitControl { reconfigure: true })
        }
        [_binary, command, invite] if command == "init-node" => Ok(Command::InitNode {
            invite: invite.clone(),
            reconfigure: false,
        }),
        [_binary, command, invite, flag] if command == "init-node" && flag == "--reconfigure" => {
            Ok(Command::InitNode {
                invite: invite.clone(),
                reconfigure: true,
            })
        }
        [_binary, command, invite] if command == "join" => Ok(Command::Join {
            invite: invite.clone(),
        }),
        [_binary, command, flag, server_url, device_flag, device_name]
            if command == "pair" && flag == "--server" && device_flag == "--device" =>
        {
            Ok(Command::Pair {
                server_url: server_url.clone(),
                device_name: device_name.clone(),
            })
        }
        [_binary, command] if command == "devices" => Ok(Command::Devices),
        [_binary, command] if command == "services" => Ok(Command::Services),
        [_binary, first, second] if first == "control" && second == "devices" => {
            Ok(Command::ControlDevices)
        }
        [_binary, first, second] if first == "control" && second == "restart" => {
            Ok(Command::ControlRestart)
        }
        [_binary, first, second] if first == "node" && second == "restart" => {
            Ok(Command::NodeRestart)
        }
        [_binary, first, second] if first == "ssh" && second == "sync" => {
            Err("medium ssh sync was removed; use `medium ssh <device>`".to_string())
        }
        [_binary, first, rest @ ..] if first == "ssh" => {
            let options = parse_ssh_options(rest)?;
            Ok(Command::Ssh {
                device_name: options.device_name,
                verbose: options.verbose,
                force_relay: options.force_relay,
            })
        }
        [_binary, first, second, rest @ ..] if first == "proxy" && second == "ssh" => {
            let options = parse_proxy_ssh_options(rest)?;
            Ok(Command::ProxySsh {
                device_name: options.device_name,
                verbose: options.verbose,
                force_relay: options.force_relay,
            })
        }
        [_binary, first, second, rest @ ..] if first == "proxy" && second == "service" => {
            let options = parse_proxy_service_options(rest)?;
            Ok(Command::ProxyService {
                node_name: options.node_name,
                service_id: options.service_id,
                verbose: options.verbose,
                force_relay: options.force_relay,
            })
        }
        [_binary, command] if command == "doctor" => Ok(Command::Doctor),
        [_binary, command, flag, path] if command == "run" && flag == "--config" => {
            Ok(Command::Run {
                config_path: PathBuf::from(path),
            })
        }
        [_binary, command] if command == "run" => Ok(Command::Run {
            config_path: install::default_node_config_path(&install::install_root()),
        }),
        [_binary, command] if command == "info" => Ok(Command::Info),
        [_binary, command, value] if command == "normalize-label" => Ok(Command::NormalizeLabel {
            value: value.clone(),
        }),
        [_binary, command, ..] => Err(format!("unknown command: {command}\n\nRun: medium help")),
        [] => Err("missing argv[0]\n\nRun: medium help".to_string()),
    }
}

struct SshOptions {
    device_name: String,
    verbose: bool,
    force_relay: bool,
}

struct ProxyServiceOptions {
    node_name: String,
    service_id: String,
    verbose: bool,
    force_relay: bool,
}

fn parse_ssh_options(args: &[String]) -> Result<SshOptions, String> {
    let mut device_name = None;
    let mut verbose = false;
    let mut force_relay = false;

    for arg in args {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--relay" => force_relay = true,
            "sync" if device_name.is_none() => {
                return Err("medium ssh sync was removed; use `medium ssh <device>`".to_string());
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown medium ssh option: {value}"));
            }
            value => {
                if device_name.replace(value.to_string()).is_some() {
                    return Err("medium ssh accepts exactly one device".to_string());
                }
            }
        }
    }

    let device_name = device_name.ok_or_else(|| "medium ssh requires a device".to_string())?;
    Ok(SshOptions {
        device_name,
        verbose,
        force_relay,
    })
}

fn parse_proxy_ssh_options(args: &[String]) -> Result<SshOptions, String> {
    let mut device_name = None;
    let mut verbose = false;
    let mut force_relay = false;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--device" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "medium proxy ssh --device requires a value".to_string())?;
                if device_name.replace(value.clone()).is_some() {
                    return Err("medium proxy ssh accepts one --device value".to_string());
                }
            }
            "--verbose" => verbose = true,
            "--relay" => force_relay = true,
            value => return Err(format!("unknown medium proxy ssh option: {value}")),
        }
        index += 1;
    }

    let device_name =
        device_name.ok_or_else(|| "medium proxy ssh requires --device <name>".to_string())?;
    Ok(SshOptions {
        device_name,
        verbose,
        force_relay,
    })
}

fn parse_proxy_service_options(args: &[String]) -> Result<ProxyServiceOptions, String> {
    let mut node_name = None;
    let mut service_id = None;
    let mut verbose = false;
    let mut force_relay = false;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--node" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "medium proxy service --node requires a value".to_string())?;
                if node_name.replace(value.clone()).is_some() {
                    return Err("medium proxy service accepts one --node value".to_string());
                }
            }
            "--service" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "medium proxy service --service requires a value".to_string())?;
                if service_id.replace(value.clone()).is_some() {
                    return Err("medium proxy service accepts one --service value".to_string());
                }
            }
            "-v" | "--verbose" => verbose = true,
            "--relay" => force_relay = true,
            value => return Err(format!("unknown medium proxy service option: {value}")),
        }
        index += 1;
    }

    let node_name =
        node_name.ok_or_else(|| "medium proxy service requires --node <name>".to_string())?;
    let service_id =
        service_id.ok_or_else(|| "medium proxy service requires --service <id>".to_string())?;
    Ok(ProxyServiceOptions {
        node_name,
        service_id,
        verbose,
        force_relay,
    })
}

fn render_devices(devices: &[DeviceRecord]) -> String {
    devices
        .iter()
        .map(|device| match &device.ssh {
            Some(ssh) => format!("{} ssh {}@{}:{}", device.name, ssh.user, ssh.host, ssh.port),
            None => format!("{} no-ssh", device.name),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_services(devices: &[DeviceRecord]) -> String {
    let mut output = Vec::new();
    let mut services_seen = 0usize;

    for device in devices {
        if device.services.is_empty() {
            continue;
        }

        output.push(format!("{} ({})", device.name, device.id));
        for service in &device.services {
            services_seen += 1;
            output.push(format!("  {}", render_published_service(device, service)));
        }
    }

    if services_seen == 0 {
        return "no published services".to_string();
    }

    output.join("\n")
}

fn render_published_service(device: &DeviceRecord, service: &PublishedService) -> String {
    let label = service
        .label
        .as_deref()
        .filter(|label| *label != service.id)
        .map(|label| format!(" \"{label}\""))
        .unwrap_or_default();
    let endpoint = service_endpoint(device, service);

    format!(
        "{} {}{} {} -> {}",
        service.id,
        service.kind.as_str(),
        label,
        endpoint,
        service.target
    )
}

fn service_endpoint(device: &DeviceRecord, service: &PublishedService) -> String {
    match service.kind {
        ServiceKind::Http | ServiceKind::Https => format!("https://{}.medium/", service.id),
        ServiceKind::Ssh => {
            let user = service.user_name.as_deref().unwrap_or("overlay");
            format!("ssh://{user}@{}", device.name)
        }
    }
}

async fn run_ssh_command(
    device_name: &str,
    verbose: bool,
    force_relay: bool,
) -> Result<(), String> {
    let paths = AppPaths::from_env().map_err(|error| error.to_string())?;
    let state = AppState::load(&paths).map_err(|error| error.to_string())?;
    let devices = client_api::fetch_devices(&state)
        .await
        .map_err(|error| error.to_string())?;
    let device = devices
        .devices
        .iter()
        .find(|device| device.name == device_name)
        .ok_or_else(|| format!("unknown device {device_name}"))?;
    let ssh = device
        .ssh
        .as_ref()
        .ok_or_else(|| format!("device {device_name} has no SSH endpoint"))?;

    let key = generate_ephemeral_ssh_key(device_name).map_err(|error| error.to_string())?;
    let public_key = std::fs::read_to_string(&key.public_key_path).map_err(|error| {
        format!(
            "read ephemeral SSH public key {}: {error}",
            key.public_key_path.display()
        )
    })?;
    let certificate =
        client_api::issue_ssh_certificate(&state, &device.id, &ssh.service_id, &public_key)
            .await
            .map_err(|error| error.to_string())?;
    std::fs::write(&key.certificate_path, certificate.certificate).map_err(|error| {
        format!(
            "write ephemeral SSH certificate {}: {error}",
            key.certificate_path.display()
        )
    })?;

    let status = ProcessCommand::new("ssh")
        .args(ssh_command_args(
            device_name,
            &certificate.user_name,
            &key.private_key_path,
            &key.certificate_path,
            &current_medium_exe(),
            verbose,
            force_relay,
        ))
        .status()
        .map_err(|error| format!("run ssh: {error}"))?;
    key.cleanup();
    if status.success() {
        return Ok(());
    }
    Err(format!("ssh exited with {status}"))
}

struct EphemeralSshKey {
    dir: PathBuf,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    certificate_path: PathBuf,
}

impl EphemeralSshKey {
    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn generate_ephemeral_ssh_key(device_name: &str) -> anyhow::Result<EphemeralSshKey> {
    let dir = std::env::temp_dir().join(format!(
        "medium-ssh-{}-{}",
        app::normalize_device_label(device_name).replace('/', "_"),
        timestamp_suffix()
    ));
    std::fs::create_dir_all(&dir)?;
    let private_key_path = dir.join("id_ed25519");
    let public_key_path = dir.join("id_ed25519.pub");
    let certificate_path = dir.join("id_ed25519-cert.pub");
    let output = ProcessCommand::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "medium-ephemeral",
            "-f",
            &private_key_path.display().to_string(),
        ])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!("ssh-keygen failed to generate ephemeral SSH key: {stderr}");
    }
    Ok(EphemeralSshKey {
        dir,
        private_key_path,
        public_key_path,
        certificate_path,
    })
}

fn ssh_command_args(
    device_name: &str,
    user_name: &str,
    private_key_path: &Path,
    certificate_path: &Path,
    medium_exe_path: &Path,
    verbose: bool,
    force_relay: bool,
) -> Vec<String> {
    let verbose_flag = if verbose { " --verbose" } else { "" };
    let relay_flag = if force_relay { " --relay" } else { "" };
    vec![
        "-l".into(),
        user_name.into(),
        "-i".into(),
        private_key_path.display().to_string(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("CertificateFile={}", certificate_path.display()),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=0".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=45".into(),
        "-o".into(),
        "ConnectionAttempts=1".into(),
        "-o".into(),
        format!(
            "ProxyCommand={} proxy ssh --device {}{}{}",
            shell_quote(&medium_exe_path.display().to_string()),
            shell_quote(device_name),
            verbose_flag,
            relay_flag
        ),
        device_name.into(),
    ]
}

fn current_medium_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("medium"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn timestamp_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos()
}

async fn render_control_devices() -> anyhow::Result<String> {
    let root = install::install_root();
    let control_config_path = install::control_config_path(&root);
    let raw = std::fs::read_to_string(&control_config_path).map_err(|error| {
        anyhow::anyhow!(
            "control config not found at {}: {}",
            control_config_path.display(),
            error
        )
    })?;
    let database_url = parse_simple_toml_string(&raw, "database_url")
        .ok_or_else(|| anyhow::anyhow!("control config is missing database_url"))?;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;

    let rows = match sqlx::query(
        r#"
        select
          n.id as node_id,
          n.label as node_label,
          n.last_seen_at as last_seen_at,
          ns.id as service_id,
          ns.kind as service_kind,
          ns.target as service_target,
          ns.label as service_label
        from nodes n
        left join node_services ns on ns.node_id = n.id
        order by n.id, ns.id
        "#,
    )
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) if error.to_string().contains("no such table") => {
            return Ok(
                "control registry is not initialized; start medium-control-plane first".to_string(),
            );
        }
        Err(error) => return Err(error.into()),
    };

    if rows.is_empty() {
        return Ok("no registered nodes".into());
    }

    let mut output = Vec::new();
    let mut current_node = String::new();
    let mut service_count = 0usize;
    for row in rows {
        let node_id: String = row.try_get("node_id")?;
        if node_id != current_node {
            if !current_node.is_empty() && service_count == 0 {
                output.push("  no published services".to_string());
            }
            current_node = node_id.clone();
            service_count = 0;
            let node_label: String = row.try_get("node_label")?;
            let last_seen_at: String = row.try_get("last_seen_at")?;
            output.push(format!("{node_label} ({node_id}) last_seen={last_seen_at}"));
        }

        let service_id: Option<String> = row.try_get("service_id")?;
        if let Some(service_id) = service_id {
            service_count += 1;
            let kind: String = row.try_get("service_kind")?;
            let target: String = row.try_get("service_target")?;
            let label: Option<String> = row.try_get("service_label")?;
            match label.filter(|label| label != &service_id) {
                Some(label) => {
                    output.push(format!("  {service_id} {kind} \"{label}\" -> {target}"))
                }
                None => output.push(format!("  {service_id} {kind} -> {target}")),
            }
        }
    }
    if service_count == 0 {
        output.push("  no published services".to_string());
    }

    Ok(output.join("\n"))
}

fn parse_simple_toml_string(raw: &str, wanted_key: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let line = line
            .split_once('#')
            .map_or(line, |(before, _)| before)
            .trim();
        let (key, value) = line.split_once('=')?;
        if key.trim() != wanted_key {
            return None;
        }
        let value = value.trim();
        if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
            return None;
        }
        Some(value[1..value.len() - 1].to_string())
    })
}

async fn run_proxy_ssh(
    state: &AppState,
    devices: &[DeviceRecord],
    device_name: &str,
    verbose: bool,
    force_relay: bool,
) -> anyhow::Result<()> {
    let device = find_device(devices, device_name)?;
    let ssh = device
        .ssh
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("device {} has no SSH endpoint", device_name))?;
    run_proxy_device_service(
        state,
        device,
        &ssh.service_id,
        "medium ssh",
        "SSH proxy",
        verbose,
        force_relay,
    )
    .await
}

async fn run_proxy_service(
    state: &AppState,
    devices: &[DeviceRecord],
    node_name: &str,
    service_id: &str,
    verbose: bool,
    force_relay: bool,
) -> anyhow::Result<()> {
    let device = find_device(devices, node_name)?;
    run_proxy_device_service(
        state,
        device,
        service_id,
        "medium proxy",
        "service proxy",
        verbose,
        force_relay,
    )
    .await
}

fn find_device<'a>(
    devices: &'a [DeviceRecord],
    name_or_id: &str,
) -> anyhow::Result<&'a DeviceRecord> {
    devices
        .iter()
        .find(|device| device.name == name_or_id || device.id == name_or_id)
        .ok_or_else(|| anyhow::anyhow!("unknown node {}", name_or_id))
}

async fn run_proxy_device_service(
    state: &AppState,
    device: &DeviceRecord,
    service_id: &str,
    log_prefix: &'static str,
    task_name: &'static str,
    verbose: bool,
    force_relay: bool,
) -> anyhow::Result<()> {
    let service = device
        .services
        .iter()
        .find(|service| service.id == service_id)
        .ok_or_else(|| anyhow::anyhow!("node {} has no service {}", device.name, service_id))?;
    let service_hostname = service_medium_hostname(Some(service), service_id);
    let service_ca = client_api::fetch_medium_ca(state).await?;
    let grant = client_api::open_session_for_node(state, Some(&device.id), service_id).await?;
    let control_pin = (state.security == "pinned-tls").then(|| state.control_pin.clone());
    let grant_node_id = grant.node_id.clone();
    tokio::task::spawn_blocking(move || {
        proxy_via_medium_session(
            grant,
            service_ca,
            service_hostname,
            control_pin,
            log_prefix,
            verbose,
            force_relay,
        )
    })
    .await
    .map_err(|error| anyhow::anyhow!("{task_name} task failed: {error}"))??;
    if verbose {
        eprintln!("{log_prefix}: proxy finished for {grant_node_id}");
    }
    Ok(())
}

fn proxy_via_medium_session(
    grant: SessionOpenGrant,
    service_ca: String,
    service_hostname: String,
    control_pin: Option<String>,
    log_prefix: &'static str,
    verbose: bool,
    force_relay: bool,
) -> anyhow::Result<()> {
    let mode = if force_relay {
        TransportMode::RelayOnly
    } else {
        TransportMode::Auto
    };
    if verbose && force_relay {
        eprintln!(
            "{log_prefix}: forcing relay transport for {}",
            grant.node_id
        );
    }
    let attempts = if force_relay { 2 } else { 1 };
    if verbose && attempts > 1 {
        eprintln!(
            "{log_prefix}: relay TCP is only the VPS hop; waiting for end-to-end Medium TLS with up to {attempts} attempts per relay candidate"
        );
    }
    let connected = medium_session::connect_session_service_tls(
        &grant,
        ConnectOptions {
            mode,
            control_pin: control_pin.as_deref(),
            preferred_ice: None,
        },
        &service_hostname,
        &service_ca,
        attempts,
        Duration::from_millis(250),
    )?;
    if verbose {
        eprintln!(
            "{log_prefix}: connected via {} {}",
            connected.path.kind, connected.path.addr
        );
        eprintln!("{log_prefix}: Medium TLS connected as {service_hostname}");
    }
    pipe_stdio_blocking(connected.stream)
}

fn service_medium_hostname(service: Option<&PublishedService>, service_id: &str) -> String {
    let label = service
        .and_then(|service| service.label.as_deref())
        .unwrap_or(service_id);
    format!("{}.medium", normalize_hostname_label(label))
}

fn normalize_hostname_label(value: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
            last_was_dash = false;
        } else if !last_was_dash && !output.is_empty() {
            output.push('-');
            last_was_dash = true;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        "service".to_string()
    } else {
        output
    }
}

fn pipe_stdio_blocking<S>(mut stream: S) -> anyhow::Result<()>
where
    S: Read + Write,
{
    let (stdin_tx, stdin_rx) = mpsc::channel::<std_io::Result<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut stdin = std_io::stdin().lock();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => {
                    let _ = stdin_tx.send(Ok(Vec::new()));
                    return;
                }
                Ok(size) => {
                    if stdin_tx.send(Ok(buffer[..size].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = stdin_tx.send(Err(error));
                    return;
                }
            }
        }
    });

    let mut stdout = std_io::stdout().lock();
    let mut network_buffer = [0_u8; 64 * 1024];
    loop {
        while let Ok(input) = stdin_rx.try_recv() {
            let input = input?;
            if !input.is_empty() {
                stream.write_all(&input)?;
                stream.flush()?;
            }
        }

        match stream.read(&mut network_buffer) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                stdout.write_all(&network_buffer[..size])?;
                stdout.flush()?;
            }
            Err(error) if is_stdio_proxy_timeout(&error) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn is_stdio_proxy_timeout(error: &std_io::Error) -> bool {
    error.kind() == std_io::ErrorKind::WouldBlock
        || error.kind() == std_io::ErrorKind::TimedOut
        || error.kind() == std_io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_command_args_are_non_interactive_and_bounded() {
        let args = ssh_command_args(
            "studio-smiley",
            "overlay",
            Path::new("/tmp/medium-key"),
            Path::new("/tmp/medium-key-cert.pub"),
            Path::new("/tmp/current-medium"),
            false,
            false,
        );

        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"NumberOfPasswordPrompts=0".to_string()));
        assert!(args.contains(&"ConnectTimeout=45".to_string()));
    }

    #[test]
    fn ssh_command_disables_openssh_host_key_prompt_because_medium_tls_authenticates_service() {
        let args = ssh_command_args(
            "studio-smiley",
            "overlay",
            Path::new("/tmp/medium-key"),
            Path::new("/tmp/medium-key-cert.pub"),
            Path::new("/tmp/current-medium"),
            false,
            false,
        );

        assert!(args.contains(&"StrictHostKeyChecking=no".to_string()));
        assert!(args.contains(&"UserKnownHostsFile=/dev/null".to_string()));
        assert!(args.contains(&"GlobalKnownHostsFile=/dev/null".to_string()));
    }

    #[test]
    fn verbose_ssh_command_passes_verbose_flag_to_proxy_command() {
        let args = ssh_command_args(
            "studio-smiley",
            "overlay",
            Path::new("/tmp/medium-key"),
            Path::new("/tmp/medium-key-cert.pub"),
            Path::new("/tmp/current-medium"),
            true,
            false,
        );

        let proxy_command = args
            .iter()
            .find(|arg| arg.starts_with("ProxyCommand="))
            .expect("ssh command should include ProxyCommand");
        assert!(proxy_command.contains("--verbose"));
    }

    #[test]
    fn relay_ssh_command_passes_relay_flag_to_proxy_command() {
        let args = ssh_command_args(
            "studio-smiley",
            "overlay",
            Path::new("/tmp/medium-key"),
            Path::new("/tmp/medium-key-cert.pub"),
            Path::new("/tmp/current-medium"),
            false,
            true,
        );

        let proxy_command = args
            .iter()
            .find(|arg| arg.starts_with("ProxyCommand="))
            .expect("ssh command should include ProxyCommand");
        assert!(proxy_command.contains("--relay"));
    }

    #[test]
    fn ssh_command_uses_current_binary_for_proxy_command() {
        let args = ssh_command_args(
            "studio-smiley",
            "overlay",
            Path::new("/tmp/medium-key"),
            Path::new("/tmp/medium-key-cert.pub"),
            Path::new("/tmp/current-medium"),
            false,
            false,
        );

        let proxy_command = args
            .iter()
            .find(|arg| arg.starts_with("ProxyCommand="))
            .expect("ssh command should include ProxyCommand");
        assert!(proxy_command.contains("'/tmp/current-medium' proxy ssh"));
    }
}
