use crate::client_api;
use anyhow::{Context, bail};
use std::fs;
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CONTROL_BIND_ADDR: &str = "0.0.0.0:7777";
const DEFAULT_NODE_ID: &str = "node-1";
const DEFAULT_RELAY_BIND_ADDR: &str = "0.0.0.0:7001";
const DEFAULT_SSH_SERVICE_ID: &str = "svc_ssh";
const DEFAULT_SSH_TARGET: &str = "127.0.0.1:22";
const DEFAULT_SSH_USER: &str = "overlay";
const CONTROL_PLANE_UNIT_TEMPLATE: &str =
    include_str!("../../../packaging/systemd/medium-control-plane.service");
const NODE_AGENT_UNIT_TEMPLATE: &str =
    include_str!("../../../packaging/systemd/medium-node-agent.service");
const RELAY_UNIT_TEMPLATE: &str = include_str!("../../../packaging/systemd/medium-relay.service");
const RELAY_SERVICE: &str = "medium-relay.service";
const CONTROL_SERVICE: &str = "medium-control-plane.service";
const NODE_SERVICE: &str = "medium-node-agent.service";

#[allow(dead_code)]
pub struct InitControlReport {
    pub control_config_path: PathBuf,
    pub database_path: PathBuf,
    pub invite: String,
    pub node_invite: String,
}

#[allow(dead_code)]
pub struct InitNodeReport {
    pub node_config_path: PathBuf,
}

struct InstallLayout {
    config_dir: PathBuf,
    state_dir: PathBuf,
    systemd_unit_dir: PathBuf,
    control_config_path: PathBuf,
    control_cert_path: PathBuf,
    control_key_path: PathBuf,
    service_ca_cert_path: PathBuf,
    service_ca_key_path: PathBuf,
    ssh_ca_key_path: PathBuf,
    ssh_ca_public_key_path: PathBuf,
    node_config_path: PathBuf,
    node_services_path: PathBuf,
    node_ssh_ca_public_key_path: PathBuf,
    sshd_config_path: PathBuf,
    database_path: PathBuf,
    control_unit_path: PathBuf,
    node_unit_path: PathBuf,
    relay_unit_path: PathBuf,
}

impl InstallLayout {
    fn new(root: &Path) -> Self {
        let (config_dir, state_dir, systemd_unit_dir) = install_dirs(root);
        let node_config_dir = node_config_dir(root);

        Self {
            control_config_path: config_dir.join("control.toml"),
            control_cert_path: config_dir.join("control.crt"),
            control_key_path: config_dir.join("control.key"),
            service_ca_cert_path: config_dir.join("service-ca.crt"),
            service_ca_key_path: config_dir.join("service-ca.key"),
            ssh_ca_key_path: config_dir.join("ssh-ca"),
            ssh_ca_public_key_path: config_dir.join("ssh-ca.pub"),
            node_config_path: node_config_dir.join("node.toml"),
            node_services_path: node_config_dir.join("services.toml"),
            node_ssh_ca_public_key_path: config_dir.join("ssh-ca.pub"),
            sshd_config_path: root
                .join("etc")
                .join("ssh")
                .join("sshd_config.d")
                .join("99-medium.conf"),
            database_path: state_dir.join("control-plane.db"),
            control_unit_path: systemd_unit_dir.join("medium-control-plane.service"),
            node_unit_path: systemd_unit_dir.join("medium-node-agent.service"),
            relay_unit_path: systemd_unit_dir.join("medium-relay.service"),
            config_dir,
            state_dir,
            systemd_unit_dir,
        }
    }

    fn is_bootstrapped(&self) -> bool {
        self.control_config_path.exists()
            || self.database_path.exists()
            || self.config_dir.exists()
            || self.state_dir.exists()
    }

    fn is_node_bootstrapped(&self) -> bool {
        self.node_config_path.exists()
            || self.legacy_node_config_path().exists()
            || self.node_unit_path.exists()
    }

    fn legacy_node_config_path(&self) -> PathBuf {
        self.config_dir.join("node.toml")
    }
}

fn install_dirs(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    if root == Path::new("/") && cfg!(target_os = "macos") {
        let home = std::env::var_os("OVERLAY_HOME")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let app_root = home
            .join("Library")
            .join("Application Support")
            .join("Medium");
        let config_dir = app_root.join("config");
        let state_dir = app_root.join("state");
        let unit_dir = app_root.join("launchd");
        return (config_dir, state_dir, unit_dir);
    }

    (
        root.join("etc").join("medium"),
        root.join("var").join("lib").join("medium"),
        root.join("etc").join("systemd").join("system"),
    )
}

fn node_config_dir(root: &Path) -> PathBuf {
    if let Some(home) = std::env::var_os("MEDIUM_HOME").or_else(|| std::env::var_os("OVERLAY_HOME"))
    {
        return PathBuf::from(home).join(".medium");
    }

    if root != Path::new("/") {
        return root.join("home").join(".medium");
    }

    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".medium")
}

pub fn init_control(reconfigure: bool) -> anyhow::Result<InitControlReport> {
    let root = install_root();
    let bind_addr = control_bind_addr();
    let relay_bind_addr = relay_bind_addr();
    let configured_wss_relay_url = env_string("MEDIUM_WSS_RELAY_URL");
    let mut config_errors = Vec::new();
    let control_url = match control_public_url(&bind_addr) {
        Ok(value) => value,
        Err(error) => {
            config_errors.push(error.to_string());
            String::new()
        }
    };
    let relay_addr = match relay_public_addr(&relay_bind_addr) {
        Ok(value) => value,
        Err(error) => {
            config_errors.push(error.to_string());
            String::new()
        }
    };
    if !config_errors.is_empty() {
        bail!(config_errors.join("; "));
    }
    let wss_relay_is_external = configured_wss_relay_url.is_some();
    let wss_relay_url = match configured_wss_relay_url {
        Some(value) => {
            validate_wss_relay_url(&value)?;
            value
        }
        None => embedded_wss_relay_url(&control_url)?,
    };
    init_control_at(
        &root,
        &bind_addr,
        &control_url,
        &relay_bind_addr,
        &relay_addr,
        &wss_relay_url,
        wss_relay_is_external,
        reconfigure,
    )
}

fn init_control_at(
    root: &Path,
    bind_addr: &str,
    control_url: &str,
    relay_bind_addr: &str,
    relay_addr: &str,
    wss_relay_url: &str,
    wss_relay_is_external: bool,
    reconfigure: bool,
) -> anyhow::Result<InitControlReport> {
    let layout = InstallLayout::new(root);
    if layout.is_bootstrapped() && !reconfigure {
        bail!(
            "Medium control is already initialized; rerun with --reconfigure to rewrite bootstrap files"
        );
    }

    fs::create_dir_all(&layout.config_dir)
        .with_context(|| format!("create {}", layout.config_dir.display()))?;
    fs::create_dir_all(&layout.state_dir)
        .with_context(|| format!("create {}", layout.state_dir.display()))?;

    let tls_identity =
        overlay_crypto::issue_control_tls_identity(&control_tls_names(bind_addr, control_url)?)?;
    let service_ca = overlay_crypto::issue_medium_service_ca()?;
    write_text_file(&layout.control_cert_path, &tls_identity.cert_pem)?;
    write_private_file(&layout.control_key_path, &tls_identity.key_pem)?;
    write_text_file(&layout.service_ca_cert_path, &service_ca.cert_pem)?;
    write_private_file(&layout.service_ca_key_path, &service_ca.key_pem)?;
    ensure_ssh_ca_identity(&layout.ssh_ca_key_path)?;

    let shared_secret = make_token("medium-shared-secret");
    let client_secret = make_token("medium-client-secret");
    let control_pin = tls_identity.control_pin;
    let invite = format_join_invite(control_url, &control_pin, &client_secret)?;
    let node_invite = format_node_invite(
        control_url,
        &control_pin,
        &shared_secret,
        relay_addr,
        wss_relay_url,
    )?;

    write_control_config(
        &layout.control_config_path,
        bind_addr,
        control_url,
        &layout.database_path,
        &layout.control_cert_path,
        &layout.control_key_path,
        &layout.service_ca_cert_path,
        &layout.service_ca_key_path,
        &layout.ssh_ca_key_path,
        &layout.ssh_ca_public_key_path,
        &shared_secret,
        &client_secret,
        &control_pin,
        relay_addr,
        wss_relay_url,
    )?;
    touch_file(&layout.database_path)?;
    if writes_systemd_units(root) {
        write_control_systemd_unit(
            &layout,
            root,
            bind_addr,
            &shared_secret,
            &client_secret,
            &control_pin,
            relay_addr,
            wss_relay_url,
        )?;
        write_relay_systemd_unit(
            &layout,
            root,
            relay_bind_addr,
            &shared_secret,
            wss_relay_is_external,
        )?;
    }
    maybe_enable_systemd_services(
        root,
        &["medium-relay.service", "medium-control-plane.service"],
        reconfigure,
    )
    .context("systemd setup failed")?;

    Ok(InitControlReport {
        control_config_path: layout.control_config_path,
        database_path: layout.database_path,
        invite,
        node_invite,
    })
}

pub async fn init_node(invite: &str, reconfigure: bool) -> anyhow::Result<InitNodeReport> {
    let root = install_root();
    let profile = parse_node_invite(invite)?;
    let node_addrs = node_addrs()?;
    init_node_at(&root, &profile, &node_addrs, reconfigure).await
}

async fn init_node_at(
    root: &Path,
    profile: &NodeInvite,
    node_addrs: &NodeAddrs,
    reconfigure: bool,
) -> anyhow::Result<InitNodeReport> {
    let layout = InstallLayout::new(root);
    if layout.is_node_bootstrapped() && !reconfigure {
        bail!("Medium node is already initialized; rerun with --reconfigure to rewrite node files");
    }

    if let Some(parent) = layout.node_config_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if writes_systemd_units(root) {
        fs::create_dir_all(&layout.systemd_unit_dir)
            .with_context(|| format!("create {}", layout.systemd_unit_dir.display()))?;
    }

    write_home_node_config(
        &layout.node_config_path,
        &node_id(),
        &node_addrs.listen_addr,
        &node_addrs.public_addr,
        &profile.control_url,
        &profile.shared_secret,
        &profile.control_pin,
        profile.relay_addr.as_deref().unwrap_or(""),
        profile.wss_relay_url.as_deref().unwrap_or(""),
        profile.service_ca_cert_pem.as_deref(),
        profile.service_ca_key_pem.as_deref(),
    )?;
    write_default_services_config(&layout.node_services_path)?;
    if writes_systemd_units(root) {
        let ssh_ca_public_key = resolve_node_ssh_ca_public_key(profile).await?;
        write_node_ssh_ca_config(
            &layout.node_ssh_ca_public_key_path,
            &layout.sshd_config_path,
            &ssh_ca_public_key,
        )?;
        maybe_reload_sshd(root)?;
    }
    if writes_systemd_units(root) {
        write_node_systemd_unit(
            &layout,
            root,
            &profile.control_url,
            &profile.shared_secret,
            &profile.control_pin,
            profile.relay_addr.as_deref().unwrap_or(""),
            profile.wss_relay_url.as_deref().unwrap_or(""),
        )?;
    }
    maybe_enable_systemd_services(root, &["medium-node-agent.service"], reconfigure)
        .context("systemd setup failed")?;

    Ok(InitNodeReport {
        node_config_path: layout.node_config_path,
    })
}

async fn resolve_node_ssh_ca_public_key(profile: &NodeInvite) -> anyhow::Result<String> {
    if let Some(ssh_ca_public_key) = profile
        .ssh_ca_public_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(ssh_ca_public_key.to_string());
    }
    client_api::fetch_ssh_ca_public_key(&profile.control_url, &profile.control_pin)
        .await
        .with_context(|| {
            format!(
                "fetch Medium SSH CA public key from {}/api/ssh/ca.pub",
                profile.control_url.trim_end_matches('/')
            )
        })
}

pub(crate) fn install_root() -> PathBuf {
    std::env::var_os("MEDIUM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn control_bind_addr() -> String {
    std::env::var("MEDIUM_CONTROL_BIND_ADDR").unwrap_or_else(|_| DEFAULT_CONTROL_BIND_ADDR.into())
}

fn relay_bind_addr() -> String {
    std::env::var("MEDIUM_RELAY_BIND_ADDR").unwrap_or_else(|_| DEFAULT_RELAY_BIND_ADDR.into())
}

fn control_public_url(bind_addr: &str) -> anyhow::Result<String> {
    if let Some(url) =
        env_string("OVERLAY_CONTROL_URL").or_else(|| env_string("MEDIUM_CONTROL_PUBLIC_URL"))
    {
        return client_api::format_join_invite(&url, "control-key-placeholder")
            .map(|_| url)
            .map_err(|error| anyhow::anyhow!("invalid public control URL: {error}"));
    }

    let host = split_host_port(bind_addr)
        .map(|(host, _port)| host)
        .ok_or_else(|| anyhow::anyhow!("MEDIUM_CONTROL_BIND_ADDR must include host:port"))?;
    let port = split_host_port(bind_addr)
        .map(|(_host, port)| port)
        .ok_or_else(|| anyhow::anyhow!("MEDIUM_CONTROL_BIND_ADDR must include host:port"))?;
    if is_unsuitable_public_host(host) {
        return Ok(format!("https://{}:{port}", default_public_host()?));
    }

    Ok(format!("https://{bind_addr}"))
}

fn relay_public_addr(bind_addr: &str) -> anyhow::Result<String> {
    if let Some(addr) =
        env_string("MEDIUM_RELAY_ADDR").or_else(|| env_string("MEDIUM_RELAY_PUBLIC_ADDR"))
    {
        return Ok(addr);
    }
    let (host, port) = split_host_port(bind_addr)
        .ok_or_else(|| anyhow::anyhow!("MEDIUM_RELAY_BIND_ADDR must include host:port"))?;
    if is_unsuitable_public_host(host) {
        return Ok(format!("{}:{port}", default_public_host()?));
    }
    Ok(bind_addr.to_string())
}

fn embedded_wss_relay_url(control_url: &str) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(control_url)
        .with_context(|| format!("invalid public control URL: {control_url}"))?;
    if url.scheme() != "https" {
        bail!("embedded WSS relay requires https control URL");
    }
    url.set_scheme("wss")
        .map_err(|_| anyhow::anyhow!("failed to derive WSS relay URL from {control_url}"))?;
    url.set_path("/medium/v1/relay");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

struct NodeAddrs {
    listen_addr: String,
    public_addr: String,
}

fn node_addrs() -> anyhow::Result<NodeAddrs> {
    if let Some(legacy_addr) = env_string("MEDIUM_HOME_NODE_BIND_ADDR")
        .or_else(|| env_string("OVERLAY_HOME_NODE_BIND_ADDR"))
    {
        return Ok(NodeAddrs {
            listen_addr: legacy_addr.clone(),
            public_addr: legacy_addr,
        });
    }

    let listen_addr =
        env_string("MEDIUM_NODE_LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:17001".to_string());
    let public_addr = if let Some(public_addr) = env_string("MEDIUM_NODE_PUBLIC_ADDR") {
        public_addr
    } else {
        let host = split_host_port(&listen_addr)
            .map(|(host, _port)| host)
            .ok_or_else(|| anyhow::anyhow!("MEDIUM_NODE_LISTEN_ADDR must include host:port"))?;
        let port = split_host_port(&listen_addr)
            .map(|(_host, port)| port)
            .ok_or_else(|| anyhow::anyhow!("MEDIUM_NODE_LISTEN_ADDR must include host:port"))?;
        if is_unsuitable_public_host(host) {
            format!("{}:{port}", default_public_host()?)
        } else {
            listen_addr.clone()
        }
    };

    Ok(NodeAddrs {
        listen_addr,
        public_addr,
    })
}

fn write_control_config(
    path: &Path,
    bind_addr: &str,
    control_url: &str,
    database_path: &Path,
    tls_cert_path: &Path,
    tls_key_path: &Path,
    service_ca_cert_path: &Path,
    service_ca_key_path: &Path,
    ssh_ca_key_path: &Path,
    ssh_ca_public_key_path: &Path,
    shared_secret: &str,
    client_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> anyhow::Result<()> {
    let wss_relay_line = if wss_relay_url.trim().is_empty() {
        String::new()
    } else {
        format!("wss_relay_url = \"{wss_relay_url}\"\n")
    };
    let contents = format!(
        "# Generated by medium init-control\nbind_addr = \"{bind_addr}\"\ndatabase_url = \"sqlite://{}\"\ncontrol_url = \"{control_url}\"\ntls_cert_path = \"{}\"\ntls_key_path = \"{}\"\nservice_ca_cert_path = \"{}\"\nservice_ca_key_path = \"{}\"\nssh_ca_key_path = \"{}\"\nssh_ca_public_key_path = \"{}\"\nshared_secret = \"{shared_secret}\"\nclient_secret = \"{client_secret}\"\ncontrol_pin = \"{control_pin}\"\nrelay_addr = \"{relay_addr}\"\n{wss_relay_line}",
        database_path.display(),
        tls_cert_path.display(),
        tls_key_path.display(),
        service_ca_cert_path.display(),
        service_ca_key_path.display(),
        ssh_ca_key_path.display(),
        ssh_ca_public_key_path.display()
    );
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn write_home_node_config(
    path: &Path,
    node_id: &str,
    bind_addr: &str,
    public_addr: &str,
    control_url: &str,
    shared_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
    service_ca_cert_pem: Option<&str>,
    service_ca_key_pem: Option<&str>,
) -> anyhow::Result<()> {
    let relay_line = if relay_addr.trim().is_empty() {
        String::new()
    } else {
        format!("relay_addr = \"{relay_addr}\"\n")
    };
    let wss_relay_line = if wss_relay_url.trim().is_empty() {
        String::new()
    } else {
        format!("wss_relay_url = \"{wss_relay_url}\"\n")
    };
    let service_ca_cert = service_ca_cert_pem
        .map(|pem| format!("service_ca_cert_pem = \"\"\"\n{pem}\"\"\"\n"))
        .unwrap_or_default();
    let service_ca_key = service_ca_key_pem
        .map(|pem| format!("service_ca_key_pem = \"\"\"\n{pem}\"\"\"\n"))
        .unwrap_or_default();
    let contents = format!(
        "node_id = \"{node_id}\"\nnode_label = \"{node_id}\"\nbind_addr = \"{bind_addr}\"\npublic_addr = \"{public_addr}\"\ncontrol_url = \"{control_url}\"\nshared_secret = \"{shared_secret}\"\ncontrol_pin = \"{control_pin}\"\n{relay_line}{wss_relay_line}{service_ca_cert}{service_ca_key}"
    );
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn write_default_services_config(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }

    let contents = format!(
        "[[services]]\nid = \"{DEFAULT_SSH_SERVICE_ID}\"\nkind = \"ssh\"\ntarget = \"{DEFAULT_SSH_TARGET}\"\nuser_name = \"{DEFAULT_SSH_USER}\"\nenabled = true\n"
    );
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn write_node_ssh_ca_config(
    ca_public_key_path: &Path,
    sshd_config_path: &Path,
    ca_public_key: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = ca_public_key_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    write_text_file(ca_public_key_path, ca_public_key)?;
    if let Some(parent) = sshd_config_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    write_text_file(
        sshd_config_path,
        &format!(
            "# Generated by medium init-node\nTrustedUserCAKeys {}\n",
            ca_public_key_path.display()
        ),
    )
}

fn write_control_systemd_unit(
    layout: &InstallLayout,
    root: &Path,
    bind_addr: &str,
    shared_secret: &str,
    client_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> anyhow::Result<()> {
    fs::create_dir_all(&layout.systemd_unit_dir)
        .with_context(|| format!("create {}", layout.systemd_unit_dir.display()))?;
    fs::write(
        &layout.control_unit_path,
        render_control_plane_unit(
            root,
            layout,
            bind_addr,
            shared_secret,
            client_secret,
            control_pin,
            relay_addr,
            wss_relay_url,
        ),
    )
    .with_context(|| format!("write {}", layout.control_unit_path.display()))?;
    Ok(())
}

fn write_node_systemd_unit(
    layout: &InstallLayout,
    root: &Path,
    control_url: &str,
    shared_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> anyhow::Result<()> {
    fs::create_dir_all(&layout.systemd_unit_dir)
        .with_context(|| format!("create {}", layout.systemd_unit_dir.display()))?;
    fs::write(
        &layout.node_unit_path,
        render_node_agent_unit(
            root,
            layout,
            control_url,
            shared_secret,
            control_pin,
            relay_addr,
            wss_relay_url,
        ),
    )
    .with_context(|| format!("write {}", layout.node_unit_path.display()))?;
    Ok(())
}

fn render_control_plane_unit(
    root: &Path,
    layout: &InstallLayout,
    bind_addr: &str,
    shared_secret: &str,
    client_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> String {
    let wss_relay_env = if wss_relay_url.trim().is_empty() {
        String::new()
    } else {
        format!("Environment=MEDIUM_WSS_RELAY_URL={wss_relay_url}")
    };
    render_unit(
        CONTROL_PLANE_UNIT_TEMPLATE,
        &[
            (
                "{{CONTROL_PLANE_BIN}}",
                &control_plane_binary_path(root).display().to_string(),
            ),
            ("{{CONTROL_BIND_ADDR}}", bind_addr),
            (
                "{{DATABASE_URL}}",
                &format!("sqlite://{}", layout.database_path.display()),
            ),
            ("{{SHARED_SECRET}}", shared_secret),
            ("{{CLIENT_SECRET}}", client_secret),
            ("{{CONTROL_PIN}}", control_pin),
            (
                "{{SERVICE_CA_CERT_PATH}}",
                &layout.service_ca_cert_path.display().to_string(),
            ),
            (
                "{{SERVICE_CA_KEY_PATH}}",
                &layout.service_ca_key_path.display().to_string(),
            ),
            (
                "{{SSH_CA_KEY_PATH}}",
                &layout.ssh_ca_key_path.display().to_string(),
            ),
            ("{{RELAY_ADDR}}", relay_addr),
            ("{{WSS_RELAY_ENV}}", &wss_relay_env),
            (
                "{{TLS_CERT_PATH}}",
                &layout.control_cert_path.display().to_string(),
            ),
            (
                "{{TLS_KEY_PATH}}",
                &layout.control_key_path.display().to_string(),
            ),
            ("{{STATE_DIR}}", &layout.state_dir.display().to_string()),
        ],
    )
}

fn render_node_agent_unit(
    root: &Path,
    layout: &InstallLayout,
    control_url: &str,
    shared_secret: &str,
    control_pin: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> String {
    let wss_relay_env = if wss_relay_url.trim().is_empty() {
        String::new()
    } else {
        format!("Environment=MEDIUM_WSS_RELAY_URL={wss_relay_url}")
    };
    render_unit(
        NODE_AGENT_UNIT_TEMPLATE,
        &[
            (
                "{{NODE_AGENT_BIN}}",
                &node_agent_binary_path(root).display().to_string(),
            ),
            (
                "{{NODE_CONFIG_PATH}}",
                &layout.node_config_path.display().to_string(),
            ),
            ("{{CONTROL_URL}}", control_url),
            ("{{SHARED_SECRET}}", shared_secret),
            ("{{CONTROL_PIN}}", control_pin),
            ("{{RELAY_ADDR}}", relay_addr),
            ("{{WSS_RELAY_ENV}}", &wss_relay_env),
        ],
    )
}

fn write_relay_systemd_unit(
    layout: &InstallLayout,
    root: &Path,
    relay_bind_addr: &str,
    shared_secret: &str,
    wss_mode: bool,
) -> anyhow::Result<()> {
    fs::create_dir_all(&layout.systemd_unit_dir)
        .with_context(|| format!("create {}", layout.systemd_unit_dir.display()))?;
    fs::write(
        &layout.relay_unit_path,
        render_relay_unit(root, relay_bind_addr, shared_secret, wss_mode),
    )
    .with_context(|| format!("write {}", layout.relay_unit_path.display()))?;
    Ok(())
}

fn render_relay_unit(
    root: &Path,
    relay_bind_addr: &str,
    shared_secret: &str,
    wss_mode: bool,
) -> String {
    let relay_mode_env = if wss_mode {
        "Environment=MEDIUM_RELAY_MODE=wss"
    } else {
        ""
    };
    render_unit(
        RELAY_UNIT_TEMPLATE,
        &[
            (
                "{{RELAY_BIN}}",
                &relay_binary_path(root).display().to_string(),
            ),
            ("{{RELAY_BIND_ADDR}}", relay_bind_addr),
            ("{{SHARED_SECRET}}", shared_secret),
            ("{{RELAY_MODE_ENV}}", relay_mode_env),
        ],
    )
}

fn render_unit(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (needle, replacement) in replacements {
        rendered = rendered.replace(needle, replacement);
    }
    rendered
}

pub(crate) fn control_plane_binary_path(root: &Path) -> PathBuf {
    if root == Path::new("/") {
        if cfg!(target_os = "macos") {
            return PathBuf::from("/usr/local/bin/control-plane");
        }
        PathBuf::from("/usr/bin/control-plane")
    } else {
        root.join("usr").join("bin").join("control-plane")
    }
}

pub(crate) fn node_agent_binary_path(root: &Path) -> PathBuf {
    if root == Path::new("/") {
        if cfg!(target_os = "macos") {
            return PathBuf::from("/usr/local/bin/node-agent");
        }
        PathBuf::from("/usr/bin/node-agent")
    } else {
        root.join("usr").join("bin").join("node-agent")
    }
}

pub(crate) fn relay_binary_path(root: &Path) -> PathBuf {
    if root == Path::new("/") {
        if cfg!(target_os = "macos") {
            return PathBuf::from("/usr/local/bin/relay");
        }
        PathBuf::from("/usr/bin/relay")
    } else {
        root.join("usr").join("bin").join("relay")
    }
}

fn maybe_enable_systemd_services(
    root: &Path,
    services: &[&str],
    restart: bool,
) -> anyhow::Result<()> {
    if !uses_systemd(root) {
        return Ok(());
    }

    let systemctl = systemctl_bin();
    run_command(&systemctl, &["daemon-reload"]).context("systemd daemon-reload failed")?;
    for service in services {
        run_command(&systemctl, &["enable", "--now", service])
            .with_context(|| format!("systemd enable/start failed for {service}"))?;
        if restart {
            run_command(&systemctl, &["restart", service])
                .with_context(|| format!("systemd restart failed for {service}"))?;
        }
    }
    Ok(())
}

fn maybe_reload_sshd(root: &Path) -> anyhow::Result<()> {
    if !uses_systemd(root) {
        return Ok(());
    }

    let systemctl = systemctl_bin();
    let ssh = Command::new(&systemctl)
        .args(["reload", "ssh.service"])
        .output()
        .with_context(|| "run systemctl reload ssh.service")?;
    if ssh.status.success() {
        return Ok(());
    }

    let sshd = Command::new(&systemctl)
        .args(["reload", "sshd.service"])
        .output()
        .with_context(|| "run systemctl reload sshd.service")?;
    if sshd.status.success() {
        return Ok(());
    }

    bail!(
        "failed to reload SSH daemon after installing Medium SSH CA; tried ssh.service ({}) and sshd.service ({})",
        String::from_utf8_lossy(&ssh.stderr).trim(),
        String::from_utf8_lossy(&sshd.stderr).trim()
    );
}

fn uses_systemd(root: &Path) -> bool {
    if env_string("MEDIUM_SYSTEMCTL_BIN").is_some() {
        return true;
    }
    root == Path::new("/") && !cfg!(target_os = "macos")
}

fn writes_systemd_units(root: &Path) -> bool {
    root != Path::new("/") || !cfg!(target_os = "macos")
}

pub(crate) fn control_config_path(root: &Path) -> PathBuf {
    InstallLayout::new(root).control_config_path
}

pub(crate) fn default_node_config_path(root: &Path) -> PathBuf {
    let layout = InstallLayout::new(root);
    if layout.node_config_path.is_file() {
        return layout.node_config_path;
    }

    let legacy_path = layout.legacy_node_config_path();
    if legacy_path.is_file() {
        return legacy_path;
    }

    layout.node_config_path
}

pub(crate) fn node_services_path(root: &Path) -> PathBuf {
    InstallLayout::new(root).node_services_path
}

pub(crate) fn database_path(root: &Path) -> PathBuf {
    InstallLayout::new(root).database_path
}

pub fn restart_control_services() -> anyhow::Result<Vec<&'static str>> {
    let root = install_root();
    if !uses_systemd(&root) {
        bail!("control restart requires systemd");
    }

    let systemctl = systemctl_bin();
    let services = vec![RELAY_SERVICE, CONTROL_SERVICE];
    for service in &services {
        run_command(&systemctl, &["restart", service])
            .with_context(|| format!("systemd restart failed for {service}"))?;
    }
    Ok(services)
}

pub fn restart_node_service() -> anyhow::Result<&'static str> {
    let root = install_root();
    if !uses_systemd(&root) {
        bail!("node restart requires systemd");
    }

    let systemctl = systemctl_bin();
    run_command(&systemctl, &["restart", NODE_SERVICE])
        .with_context(|| format!("systemd restart failed for {NODE_SERVICE}"))?;
    Ok(NODE_SERVICE)
}

pub(crate) fn systemctl_bin() -> String {
    env_string("MEDIUM_SYSTEMCTL_BIN").unwrap_or_else(|| "systemctl".into())
}

fn run_command(command: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("run {} {}", command, args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut message = format!(
        "command failed: {} {} (status {})",
        command,
        args.join(" "),
        output.status
    );
    if !stderr.is_empty() {
        message.push_str(&format!("\nstderr:\n{stderr}"));
    }
    if !stdout.is_empty() {
        message.push_str(&format!("\nstdout:\n{stdout}"));
    }
    bail!(message);
}

fn touch_file(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }

    fs::write(path, []).with_context(|| format!("write {}", path.display()))
}

fn make_token(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{now:x}")
}

fn node_id() -> String {
    env_string("MEDIUM_NODE_ID").unwrap_or_else(|| DEFAULT_NODE_ID.to_string())
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn validate_wss_relay_url(value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        return Ok(());
    }
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("invalid MEDIUM_WSS_RELAY_URL: {value}"))?;
    if url.scheme() != "wss" {
        bail!("MEDIUM_WSS_RELAY_URL must use wss://");
    }
    Ok(())
}

fn control_tls_names(bind_addr: &str, control_url: &str) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    let url = reqwest::Url::parse(control_url)
        .with_context(|| format!("invalid public control URL: {control_url}"))?;
    if url.scheme() != "https" {
        bail!("public control URL must use https for pinned-tls bootstrap");
    }
    if let Some(host) = url.host_str() {
        push_cert_name(&mut names, host);
    }
    if let Some((host, _)) = split_host_port(bind_addr) {
        push_cert_name(&mut names, host);
    }
    if names.is_empty() {
        bail!("control TLS certificate needs at least one subject name");
    }
    Ok(names)
}

fn push_cert_name(names: &mut Vec<String>, host: &str) {
    if is_unsuitable_certificate_host(host) {
        return;
    }
    let host = host.trim_matches(['[', ']']);
    if !names.iter().any(|existing| existing == host) {
        names.push(host.to_string());
    }
}

fn is_unsuitable_certificate_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::")
}

fn format_join_invite(
    control_url: &str,
    control_pin: &str,
    client_secret: &str,
) -> anyhow::Result<String> {
    let base = client_api::format_join_invite(control_url, control_pin)?;
    if client_secret.is_empty() {
        bail!("client secret cannot be empty");
    }
    Ok(format!(
        "{base}&client_secret={}",
        url_query_value(client_secret)
    ))
}

#[derive(Debug, Clone)]
struct NodeInvite {
    control_url: String,
    control_pin: String,
    shared_secret: String,
    relay_addr: Option<String>,
    wss_relay_url: Option<String>,
    service_ca_cert_pem: Option<String>,
    service_ca_key_pem: Option<String>,
    ssh_ca_public_key: Option<String>,
}

fn format_node_invite(
    control_url: &str,
    control_pin: &str,
    shared_secret: &str,
    relay_addr: &str,
    wss_relay_url: &str,
) -> anyhow::Result<String> {
    let _ = client_api::format_join_invite(control_url, control_pin)?;
    if shared_secret.is_empty() {
        bail!("shared secret cannot be empty");
    }
    let relay_part = if relay_addr.is_empty() {
        String::new()
    } else {
        format!("&relay={relay_addr}")
    };
    let wss_relay_part = if wss_relay_url.is_empty() {
        String::new()
    } else {
        format!("&wss_relay={}", url_query_value(wss_relay_url))
    };
    Ok(format!(
        "medium://node?v=1&control={control_url}&security=pinned-tls&control_pin={control_pin}&shared_secret={shared_secret}"
    ) + &relay_part
        + &wss_relay_part)
}

fn parse_node_invite(raw: &str) -> anyhow::Result<NodeInvite> {
    let (scheme, remainder) = raw
        .split_once("://")
        .context("node invite must include a scheme")?;
    if scheme != "medium" {
        bail!("unsupported node invite scheme {scheme}");
    }
    let (path, query) = remainder
        .split_once('?')
        .context("node invite must include query parameters")?;
    if path == "join" {
        bail!(
            "medium init-node requires a node invite (medium://node...), but got a client join invite (medium://join...). On the control-plane host, run `sudo medium init-control --reconfigure` and copy the line that starts with `generated node invite `."
        );
    }
    if path != "node" {
        bail!("unsupported node invite path {path}");
    }

    let mut version = None;
    let mut control_url = None;
    let mut security = None;
    let mut control_pin = None;
    let mut shared_secret = None;
    let mut relay_addr = None;
    let mut wss_relay_url = None;
    let mut service_ca_cert_pem = None;
    let mut service_ca_key_pem = None;
    let mut ssh_ca_public_key = None;

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "v" => version = Some(value.parse::<u32>()?),
            "control" => control_url = Some(value.to_string()),
            "security" => security = Some(value.to_string()),
            "control_pin" => control_pin = Some(value.to_string()),
            "shared_secret" => shared_secret = Some(value.to_string()),
            "relay" => relay_addr = Some(value.to_string()),
            "wss_relay" => wss_relay_url = Some(value.to_string()),
            "service_ca_cert" => service_ca_cert_pem = Some(value.to_string()),
            "service_ca_key" => service_ca_key_pem = Some(value.to_string()),
            "ssh_ca_public_key" => ssh_ca_public_key = Some(value.to_string()),
            _ => {}
        }
    }

    let version = version.context("node invite is missing version")?;
    if version != 1 {
        bail!("unsupported node invite version {version}");
    }
    let security = security.context("node invite is missing security")?;
    if security != "pinned-tls" {
        bail!("unsupported node invite security {security}");
    }
    let control_url = control_url.context("node invite is missing control URL")?;
    let control_pin = control_pin.context("node invite is missing control pin")?;
    let shared_secret = shared_secret.context("node invite is missing shared secret")?;
    if shared_secret.is_empty() {
        bail!("node invite shared secret cannot be empty");
    }
    if let Some(wss_relay_url) = &wss_relay_url {
        validate_wss_relay_url(wss_relay_url)?;
    }
    let _ = client_api::format_join_invite(&control_url, &control_pin)?;

    Ok(NodeInvite {
        control_url,
        control_pin,
        shared_secret,
        relay_addr,
        wss_relay_url,
        service_ca_cert_pem,
        service_ca_key_pem,
        ssh_ca_public_key,
    })
}

fn url_query_value(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
}

fn write_text_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn write_private_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

fn ensure_ssh_ca_identity(key_path: &Path) -> anyhow::Result<()> {
    let public_key_path = key_path.with_extension("pub");
    if key_path.is_file() && public_key_path.is_file() {
        return Ok(());
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let output = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "medium-ssh-ca",
            "-f",
            &key_path.display().to_string(),
        ])
        .output()
        .with_context(|| "run ssh-keygen to generate Medium SSH CA")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("ssh-keygen failed to generate Medium SSH CA: {stderr}");
    }
    Ok(())
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }

    value.rsplit_once(':')
}

fn is_unsuitable_public_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "localhost")
}

fn default_public_host() -> anyhow::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("detect default public host")?;
    socket
        .connect("8.8.8.8:80")
        .context("detect default public host route")?;
    let ip = socket.local_addr()?.ip();
    if is_unsuitable_ip(ip) {
        bail!(
            "could not derive a usable public host; set MEDIUM_CONTROL_PUBLIC_URL or MEDIUM_NODE_PUBLIC_ADDR explicitly"
        );
    }
    Ok(ip.to_string())
}

fn is_unsuitable_ip(ip: IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}
