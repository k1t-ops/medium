use medium_cli::run_main;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const LEGACY_SSH_CA_PARAM: &str =
    "&ssh_ca_public_key=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAITestMediumSshCa%20medium-ssh-ca";

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set_path(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }

    fn set_str(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve")
}

fn write_mock_systemctl(path: &Path) -> anyhow::Result<()> {
    fs::write(
        path,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$MEDIUM_SYSTEMCTL_LOG\"\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn write_failing_systemctl(path: &Path) -> anyhow::Result<()> {
    fs::write(
        path,
        "#!/bin/sh\nset -eu\nif [ \"$*\" = 'reload ssh.service' ]; then exit 0; fi\nprintf 'stdout: %s\\n' \"$*\"\nprintf 'stderr: %s\\n' \"$*\" >&2\nexit 7\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[tokio::test]
async fn init_control_renders_units_and_enables_services() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let systemctl_path = temp.path().join("mock-systemctl.sh");
    let systemctl_log = temp.path().join("systemctl.log");
    write_mock_systemctl(&systemctl_path)?;

    let _root = EnvGuard::set_path("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let _control_bind = EnvGuard::set_str("MEDIUM_CONTROL_BIND_ADDR", "0.0.0.0:7777");
    let _node_public = EnvGuard::set_str("MEDIUM_NODE_PUBLIC_ADDR", "198.51.100.24:17001");
    let _wss_relay = EnvGuard::set_str(
        "MEDIUM_WSS_RELAY_URL",
        "wss://relay.example.com/medium/v1/relay",
    );
    let _systemctl_bin = EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &systemctl_path);
    let _systemctl_log = EnvGuard::set_path("MEDIUM_SYSTEMCTL_LOG", &systemctl_log);

    let control_output = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");
    let node_invite = control_output
        .lines()
        .find_map(|line| line.strip_prefix("generated node invite "))
        .expect("init-control should print node invite")
        .to_string();
    assert!(!node_invite.contains("ssh_ca_public_key="));
    let node_invite = format!("{node_invite}{LEGACY_SSH_CA_PARAM}");

    let control_unit_path = temp
        .path()
        .join("etc/systemd/system/medium-control-plane.service");
    let node_unit_path = temp
        .path()
        .join("etc/systemd/system/medium-node-agent.service");
    let relay_unit_path = temp.path().join("etc/systemd/system/medium-relay.service");

    assert!(control_unit_path.is_file());
    assert!(relay_unit_path.is_file());
    assert!(!node_unit_path.exists());

    let control_unit = fs::read_to_string(&control_unit_path)?;
    assert!(control_unit.contains(&format!(
        "ExecStart={}",
        temp.path().join("usr/bin/control-plane").display()
    )));
    assert!(control_unit.contains(&format!(
        "Environment=OVERLAY_CONTROL_BIND_ADDR={}",
        "0.0.0.0:7777"
    )));
    assert!(control_unit.contains(&format!(
        "Environment=OVERLAY_CONTROL_DATABASE_URL=sqlite://{}",
        temp.path().join("var/lib/medium/control-plane.db").display()
    )));
    let control_config = fs::read_to_string(temp.path().join("etc/medium/control.toml"))?;
    let shared_secret_line = control_config
        .lines()
        .find(|line| line.starts_with("shared_secret = "))
        .expect("shared_secret should be present in control config");
    let shared_secret = shared_secret_line
        .trim_start_matches("shared_secret = \"")
        .trim_end_matches('"');
    let control_pin_line = control_config
        .lines()
        .find(|line| line.starts_with("control_pin = "))
        .expect("control_pin should be present in control config");
    let control_pin = control_pin_line
        .trim_start_matches("control_pin = \"")
        .trim_end_matches('"');
    assert!(control_unit.contains(&format!(
        "Environment=OVERLAY_SHARED_SECRET={shared_secret}"
    )));
    assert!(control_unit.contains(&format!("Environment=MEDIUM_CONTROL_PIN={control_pin}")));
    assert!(control_unit.contains("Environment=MEDIUM_RELAY_ADDR="));
    assert!(control_unit.contains("Environment=MEDIUM_ICE_RELAY_ADDR="));
    assert!(
        control_unit
            .contains("Environment=MEDIUM_WSS_RELAY_URL=wss://relay.example.com/medium/v1/relay")
    );
    assert!(control_unit.contains(&format!(
        "Environment=MEDIUM_CONTROL_TLS_CERT_PATH={}",
        temp.path().join("etc/medium/control.crt").display()
    )));
    assert!(control_unit.contains(&format!(
        "Environment=MEDIUM_CONTROL_TLS_KEY_PATH={}",
        temp.path().join("etc/medium/control.key").display()
    )));
    assert!(control_unit.contains(&format!(
        "Environment=MEDIUM_SERVICE_CA_CERT_PATH={}",
        temp.path().join("etc/medium/service-ca.crt").display()
    )));
    assert!(control_unit.contains(&format!(
        "Environment=MEDIUM_SERVICE_CA_KEY_PATH={}",
        temp.path().join("etc/medium/service-ca.key").display()
    )));
    assert!(control_unit.contains(&format!(
        "WorkingDirectory={}",
        temp.path().join("var/lib/medium").display()
    )));
    assert!(!control_unit.contains("medium serve"));
    assert!(!control_unit.contains("MEDIUM_CONTROL_DATABASE_URL"));
    let relay_unit = fs::read_to_string(&relay_unit_path)?;
    assert!(relay_unit.contains(&format!(
        "ExecStart={}",
        temp.path().join("usr/bin/relay").display()
    )));
    assert!(relay_unit.contains("Environment=MEDIUM_RELAY_BIND_ADDR=0.0.0.0:7001"));
    assert!(relay_unit.contains(&format!(
        "Environment=MEDIUM_RELAY_SHARED_SECRET={shared_secret}"
    )));
    assert!(relay_unit.contains("Environment=MEDIUM_RELAY_MODE=wss"));

    let node_output = run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        node_invite,
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("init-node should return a summary");

    assert!(node_unit_path.is_file());
    let node_unit = fs::read_to_string(&node_unit_path)?;
    assert!(node_unit.contains(&format!(
        "ExecStart={} --config {}",
        temp.path().join("usr/bin/node-agent").display(),
        temp.path().join("home/.medium/node.toml").display()
    )));
    assert!(node_unit.contains("Environment=OVERLAY_CONTROL_URL=https://control.example.test"));
    assert!(node_unit.contains(&format!(
        "Environment=OVERLAY_SHARED_SECRET={shared_secret}"
    )));
    assert!(node_unit.contains(&format!("Environment=MEDIUM_CONTROL_PIN={control_pin}")));
    assert!(node_unit.contains("Environment=MEDIUM_RELAY_ADDR="));
    assert!(
        node_unit
            .contains("Environment=MEDIUM_WSS_RELAY_URL=wss://relay.example.com/medium/v1/relay")
    );
    assert!(!node_unit.contains("medium serve"));
    assert!(!node_unit.contains("http://127.0.0.1:7777"));

    let template_root = repo_root().join("packaging/systemd");
    assert!(template_root.join("medium-control-plane.service").is_file());
    assert!(template_root.join("medium-node-agent.service").is_file());
    assert!(template_root.join("medium-relay.service").is_file());

    let commands = fs::read_to_string(&systemctl_log)?;
    assert_eq!(
        commands.lines().collect::<Vec<_>>(),
        vec![
            "daemon-reload",
            "enable --now medium-relay.service",
            "enable --now medium-control-plane.service",
            "reload ssh.service",
            "daemon-reload",
            "enable --now medium-node-agent.service",
        ]
    );

    assert!(control_output.contains("initialized Medium control"));
    assert!(node_output.contains("initialized Medium node"));
    Ok(())
}

#[tokio::test]
async fn reconfigure_restarts_systemd_services() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let systemctl_path = temp.path().join("mock-systemctl.sh");
    let systemctl_log = temp.path().join("systemctl.log");
    write_mock_systemctl(&systemctl_path)?;

    let _root = EnvGuard::set_path("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let _systemctl_bin = EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &systemctl_path);
    let _systemctl_log = EnvGuard::set_path("MEDIUM_SYSTEMCTL_LOG", &systemctl_log);

    run_main(vec![
        "medium".to_string(),
        "init-control".to_string(),
        "--reconfigure".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("init-control should return a summary");

    let commands = fs::read_to_string(&systemctl_log)?;
    assert_eq!(
        commands.lines().collect::<Vec<_>>(),
        vec![
            "daemon-reload",
            "enable --now medium-relay.service",
            "restart medium-relay.service",
            "enable --now medium-control-plane.service",
            "restart medium-control-plane.service",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn control_restart_restarts_relay_and_control_plane_services() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let systemctl_path = temp.path().join("mock-systemctl.sh");
    let systemctl_log = temp.path().join("systemctl.log");
    write_mock_systemctl(&systemctl_path)?;

    let _root = EnvGuard::set_path("MEDIUM_ROOT", temp.path());
    let _systemctl_bin = EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &systemctl_path);
    let _systemctl_log = EnvGuard::set_path("MEDIUM_SYSTEMCTL_LOG", &systemctl_log);

    let output = run_main(vec![
        "medium".to_string(),
        "control".to_string(),
        "restart".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("control restart should return a summary");

    let commands = fs::read_to_string(&systemctl_log)?;
    assert_eq!(
        commands.lines().collect::<Vec<_>>(),
        vec![
            "restart medium-relay.service",
            "restart medium-control-plane.service"
        ]
    );
    assert_eq!(
        output,
        "restarted medium-relay.service, medium-control-plane.service"
    );
    Ok(())
}

#[tokio::test]
async fn node_restart_restarts_node_agent_service() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let systemctl_path = temp.path().join("mock-systemctl.sh");
    let systemctl_log = temp.path().join("systemctl.log");
    write_mock_systemctl(&systemctl_path)?;

    let _root = EnvGuard::set_path("MEDIUM_ROOT", temp.path());
    let _systemctl_bin = EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &systemctl_path);
    let _systemctl_log = EnvGuard::set_path("MEDIUM_SYSTEMCTL_LOG", &systemctl_log);

    let output = run_main(vec![
        "medium".to_string(),
        "node".to_string(),
        "restart".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("node restart should return a summary");

    let commands = fs::read_to_string(&systemctl_log)?;
    assert_eq!(
        commands.lines().collect::<Vec<_>>(),
        vec!["restart medium-node-agent.service"]
    );
    assert_eq!(output, "restarted medium-node-agent.service");
    Ok(())
}

#[tokio::test]
async fn init_node_reports_failing_systemd_command_with_output() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let systemctl_path = temp.path().join("mock-systemctl.sh");
    let failing_systemctl_path = temp.path().join("failing-systemctl.sh");
    let systemctl_log = temp.path().join("systemctl.log");
    write_mock_systemctl(&systemctl_path)?;
    write_failing_systemctl(&failing_systemctl_path)?;

    let _root = EnvGuard::set_path("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let systemctl_bin = EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &systemctl_path);
    let _systemctl_log = EnvGuard::set_path("MEDIUM_SYSTEMCTL_LOG", &systemctl_log);

    drop(systemctl_bin);
    let _failing_systemctl_bin =
        EnvGuard::set_path("MEDIUM_SYSTEMCTL_BIN", &failing_systemctl_path);
    let node_invite = format!(
        "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test{LEGACY_SSH_CA_PARAM}"
    );

    let error = run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        node_invite,
    ])
    .await
    .expect_err("init-node should fail when systemctl fails");

    assert!(error.contains("systemd setup failed"));
    assert!(error.contains("command failed:"));
    assert!(error.contains("daemon-reload"));
    assert!(error.contains("exit status: 7"));
    assert!(error.contains("stderr: daemon-reload"));
    assert!(error.contains("stdout: daemon-reload"));
    Ok(())
}
