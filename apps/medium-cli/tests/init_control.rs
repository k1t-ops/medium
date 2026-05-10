use home_node::config::load_from_path;
use home_node::control::build_registration;
use medium_cli::run_main;
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    fn set(key: &'static str, value: &Path) -> Self {
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

#[tokio::test]
async fn init_control_creates_expected_paths_and_files() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let _control_bind = EnvGuard::set_str("MEDIUM_CONTROL_BIND_ADDR", "0.0.0.0:7777");

    let output = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");

    let control_config_path = temp.path().join("etc/medium/control.toml");
    let control_cert_path = temp.path().join("etc/medium/control.crt");
    let control_key_path = temp.path().join("etc/medium/control.key");
    let service_ca_cert_path = temp.path().join("etc/medium/service-ca.crt");
    let service_ca_key_path = temp.path().join("etc/medium/service-ca.key");
    let database_path = temp.path().join("var/lib/medium/control-plane.db");

    assert!(control_config_path.is_file());
    assert!(control_cert_path.is_file());
    assert!(control_key_path.is_file());
    assert!(service_ca_cert_path.is_file());
    assert!(service_ca_key_path.is_file());
    assert!(!temp.path().join("home/.medium/node.toml").exists());
    assert!(
        !temp
            .path()
            .join("etc/systemd/system/medium-node-agent.service")
            .exists()
    );
    assert!(database_path.is_file());

    let control_config = fs::read_to_string(&control_config_path)?;
    assert!(control_config.contains("bind_addr = \"0.0.0.0:7777\""));
    assert!(control_config.contains("control_url = \"https://control.example.test\""));
    assert!(control_config.contains("database_url = \"sqlite://"));
    assert!(control_config.contains("shared_secret = \""));
    assert!(control_config.contains("control_pin = \"sha256:"));
    assert!(control_config.contains(&format!(
        "tls_cert_path = \"{}\"",
        control_cert_path.display()
    )));
    assert!(control_config.contains(&format!(
        "tls_key_path = \"{}\"",
        control_key_path.display()
    )));
    assert!(control_config.contains(&format!(
        "service_ca_cert_path = \"{}\"",
        service_ca_cert_path.display()
    )));
    assert!(control_config.contains(&format!(
        "service_ca_key_path = \"{}\"",
        service_ca_key_path.display()
    )));
    assert!(control_config.contains(&format!(
        "database_url = \"sqlite://{}\"",
        database_path.display()
    )));

    assert!(output.contains("initialized Medium control"));
    assert!(output.contains(
        "medium://join?v=1&control=https://control.example.test&security=pinned-tls&control_pin="
    ));
    assert!(output.contains(
        "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin="
    ));
    assert!(output.contains("&shared_secret="));
    assert!(!output.contains("&service_ca_cert="));
    assert!(!output.contains("&service_ca_key="));
    assert!(!output.contains("&ssh_ca_public_key="));
    assert!(output.contains("&wss_relay=wss%3A%2F%2Fcontrol.example.test%2Fmedium%2Fv1%2Frelay"));
    assert!(!output.contains("&token="));
    Ok(())
}

#[tokio::test]
async fn init_control_writes_configured_or_embedded_wss_relay_url() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let _wss_relay = EnvGuard::set_str(
        "MEDIUM_WSS_RELAY_URL",
        "wss://relay.example.com/medium/v1/relay",
    );

    run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");

    let control_config = fs::read_to_string(temp.path().join("etc/medium/control.toml"))?;
    assert!(control_config.contains("wss_relay_url = \"wss://relay.example.com/medium/v1/relay\""));

    let empty_temp = tempfile::tempdir()?;
    let _empty_root = EnvGuard::set("MEDIUM_ROOT", empty_temp.path());
    let _empty_wss_relay = EnvGuard::set_str("MEDIUM_WSS_RELAY_URL", "");

    run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");

    let empty_control_config =
        fs::read_to_string(empty_temp.path().join("etc/medium/control.toml"))?;
    assert!(
        empty_control_config
            .contains("wss_relay_url = \"wss://control.example.test/medium/v1/relay\"")
    );
    Ok(())
}

#[tokio::test]
async fn control_devices_reads_control_registry_without_client_state() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let config_dir = temp.path().join("etc/medium");
    let state_dir = temp.path().join("var/lib/medium");
    let database_path = state_dir.join("control-plane.db");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&state_dir)?;
    fs::write(&database_path, [])?;
    fs::write(
        config_dir.join("control.toml"),
        format!(
            "bind_addr = \"127.0.0.1:7777\"\ndatabase_url = \"sqlite://{}\"\n",
            database_path.display()
        ),
    )?;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", database_path.display())).await?;
    sqlx::query(
        "create table nodes (
            id text primary key,
            label text not null,
            created_at text not null default current_timestamp,
            updated_at text not null default current_timestamp,
            last_seen_at text not null default current_timestamp
        )",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "create table node_services (
            id text primary key,
            node_id text not null references nodes(id) on delete cascade,
            kind text not null,
            schema_version integer not null,
            target text not null,
            user_name text,
            label text,
            created_at text not null default current_timestamp
        )",
    )
    .execute(&pool)
    .await?;
    sqlx::query("insert into nodes (id, label, last_seen_at) values ('node-1', 'office', '2026-04-28T10:00:00Z')")
        .execute(&pool)
        .await?;
    sqlx::query("insert into node_services (id, node_id, kind, schema_version, target, label) values ('svc-web', 'node-1', 'http', 1, '127.0.0.1:8080', 'stub')")
        .execute(&pool)
        .await?;

    let output = run_main(vec![
        "medium".to_string(),
        "control".to_string(),
        "devices".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("control devices should return a registry report");

    assert!(output.contains("office (node-1) last_seen=2026-04-28T10:00:00Z"));
    assert!(output.contains("svc-web http \"stub\" -> 127.0.0.1:8080"));
    Ok(())
}

#[tokio::test]
async fn control_devices_omits_redundant_service_label() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let config_dir = temp.path().join("etc/medium");
    let state_dir = temp.path().join("var/lib/medium");
    let database_path = state_dir.join("control-plane.db");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&state_dir)?;
    fs::write(&database_path, [])?;
    fs::write(
        config_dir.join("control.toml"),
        format!("database_url = \"sqlite://{}\"\n", database_path.display()),
    )?;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", database_path.display())).await?;
    sqlx::query("create table nodes (id text primary key, label text not null, last_seen_at text not null default current_timestamp)")
        .execute(&pool)
        .await?;
    sqlx::query("create table node_services (id text primary key, node_id text not null, kind text not null, schema_version integer not null, target text not null, label text)")
        .execute(&pool)
        .await?;
    sqlx::query("insert into nodes (id, label, last_seen_at) values ('node-1', 'node-1', '2026-04-28T10:00:00Z')")
        .execute(&pool)
        .await?;
    sqlx::query("insert into node_services (id, node_id, kind, schema_version, target, label) values ('hello', 'node-1', 'https', 1, '127.0.0.1:8082', 'hello')")
        .execute(&pool)
        .await?;

    let output = run_main(vec![
        "medium".to_string(),
        "control".to_string(),
        "devices".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("control devices should return a registry report");

    assert!(output.contains("hello https -> 127.0.0.1:8082"));
    assert!(!output.contains("hello https hello ->"));
    Ok(())
}

#[tokio::test]
async fn init_control_rejects_non_tls_wss_relay_url() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");
    let _wss_relay = EnvGuard::set_str(
        "MEDIUM_WSS_RELAY_URL",
        "ws://relay.example.com/medium/v1/relay",
    );

    let error = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .unwrap_err();

    assert!(error.contains("MEDIUM_WSS_RELAY_URL must use wss://"));
    Ok(())
}

#[tokio::test]
async fn init_node_preserves_encoded_wss_relay_url_from_invite() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let invite = format!(
        "medium://node?v=1&control=https%3A%2F%2Fcontrol.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test&wss_relay=wss%3A%2F%2Frelay.example.com%2Fmedium%2Fv1%2Frelay%3Ftoken%3Da%2525%26mode%3Db{LEGACY_SSH_CA_PARAM}"
    );

    run_main(vec!["medium".to_string(), "init-node".to_string(), invite])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-node should return a summary");

    let node_unit = fs::read_to_string(
        temp.path()
            .join("etc/systemd/system/medium-node-agent.service"),
    )?;
    assert!(node_unit.contains(
        "Environment=MEDIUM_WSS_RELAY_URL=wss://relay.example.com/medium/v1/relay?token=a%25&mode=b"
    ));
    Ok(())
}

#[tokio::test]
async fn init_node_rejects_non_tls_wss_relay_url_from_invite() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let invite = "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test&wss_relay=ws://relay.example.com/medium/v1/relay";

    let error = run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        invite.to_string(),
    ])
    .await
    .unwrap_err();

    assert!(error.contains("MEDIUM_WSS_RELAY_URL must use wss://"));
    Ok(())
}

#[tokio::test]
async fn init_node_explains_join_invite_mismatch() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let invite = "medium://join?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let error = run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        invite.to_string(),
    ])
    .await
    .expect_err("init-node should reject join invite");

    assert!(error.contains("requires a node invite"));
    assert!(error.contains("generated node invite"));
    Ok(())
}

#[tokio::test]
async fn init_control_allows_domainless_control_url_from_concrete_bind_addr() -> anyhow::Result<()>
{
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _clear_public = EnvGuard::set_str("MEDIUM_CONTROL_PUBLIC_URL", "");
    let _clear_legacy_public = EnvGuard::set_str("OVERLAY_CONTROL_URL", "");
    let _control_bind = EnvGuard::set_str("MEDIUM_CONTROL_BIND_ADDR", "198.51.100.24:7777");

    let output = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");

    assert!(output.contains(
        "medium://join?v=1&control=https://198.51.100.24:7777&security=pinned-tls&control_pin="
    ));
    assert!(!output.contains("&token="));
    Ok(())
}

#[tokio::test]
async fn init_control_derives_public_url_for_default_wildcard_bind() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _control_bind = EnvGuard::set_str("MEDIUM_CONTROL_BIND_ADDR", "0.0.0.0:7777");
    let _clear_public = EnvGuard::set_str("MEDIUM_CONTROL_PUBLIC_URL", "");
    let _clear_legacy_public = EnvGuard::set_str("OVERLAY_CONTROL_URL", "");

    let output = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-control should return a summary");

    assert!(output.contains("medium://join?v=1&control=https://"));
    assert!(output.contains(":7777&security=pinned-tls"));
    assert!(!output.contains("control=https://0.0.0.0:7777"));
    Ok(())
}

#[tokio::test]
async fn init_node_creates_node_config_and_agent_unit_from_node_invite() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _node_id = EnvGuard::set_str("MEDIUM_NODE_ID", "office-server");
    let _node_listen = EnvGuard::set_str("MEDIUM_NODE_LISTEN_ADDR", "0.0.0.0:17001");
    let _node_public = EnvGuard::set_str("MEDIUM_NODE_PUBLIC_ADDR", "203.0.113.10:17001");
    let invite = format!(
        "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test&service_ca_cert=-----BEGIN%20CERTIFICATE-----%0Atest-cert%0A-----END%20CERTIFICATE-----%0A&service_ca_key=-----BEGIN%20PRIVATE%20KEY-----%0Atest-key%0A-----END%20PRIVATE%20KEY-----%0A{LEGACY_SSH_CA_PARAM}"
    );

    let output = run_main(vec!["medium".to_string(), "init-node".to_string(), invite])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-node should return a summary");

    let node_config_path = temp.path().join("home/.medium/node.toml");
    let services_config_path = temp.path().join("home/.medium/services.toml");
    let node_config = load_from_path(&node_config_path)?;
    assert_eq!(node_config.node_id, "office-server");
    assert_eq!(node_config.bind_addr, "0.0.0.0:17001");
    assert_eq!(
        node_config.public_addr.as_deref(),
        Some("203.0.113.10:17001")
    );
    assert!(!fs::read_to_string(&node_config_path)?.contains("[[services]]"));
    assert!(services_config_path.is_file());
    assert_eq!(node_config.services[0].id, "svc_ssh");
    assert_eq!(node_config.services[0].kind, "ssh");
    assert_eq!(
        node_config.control_url.as_deref(),
        Some("https://control.example.test")
    );
    assert_eq!(
        node_config.control_pin.as_deref(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        node_config.shared_secret.as_deref(),
        Some("medium-shared-secret-test")
    );
    assert!(
        node_config
            .service_ca_cert_pem
            .as_deref()
            .unwrap()
            .contains("test-cert")
    );
    assert!(
        node_config
            .service_ca_key_pem
            .as_deref()
            .unwrap()
            .contains("test-key")
    );

    let registration = build_registration(&node_config);
    assert_eq!(registration.node_id, "office-server");
    assert_eq!(registration.endpoints[0].addr, "203.0.113.10:17001");

    let node_unit = fs::read_to_string(
        temp.path()
            .join("etc/systemd/system/medium-node-agent.service"),
    )?;
    assert!(node_unit.contains("Environment=OVERLAY_CONTROL_URL=https://control.example.test"));
    assert!(node_unit.contains("Environment=OVERLAY_SHARED_SECRET=medium-shared-secret-test"));
    assert!(node_unit.contains("Environment=MEDIUM_CONTROL_PIN=sha256:aaaaaaaa"));
    assert!(output.contains("initialized Medium node at"));
    Ok(())
}

#[tokio::test]
async fn init_node_fetches_ssh_ca_public_key_from_control_plane() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _node_id = EnvGuard::set_str("MEDIUM_NODE_ID", "office-server");
    let _node_listen = EnvGuard::set_str("MEDIUM_NODE_LISTEN_ADDR", "0.0.0.0:17001");
    let _node_public = EnvGuard::set_str("MEDIUM_NODE_PUBLIC_ADDR", "203.0.113.10:17001");
    let server = TestTlsControlServer::start(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMediumSshCaFromControl medium-ssh-ca\n",
    )
    .await;
    let invite = format!(
        "medium://node?v=1&control={}&security=pinned-tls&control_pin={}&shared_secret=medium-shared-secret-test",
        server.url, server.control_pin
    );

    run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        invite.to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("init-node should return a summary");

    let ca_public_key_path = temp.path().join("etc/medium/ssh-ca.pub");
    let sshd_config_path = temp.path().join("etc/ssh/sshd_config.d/99-medium.conf");
    assert_eq!(
        fs::read_to_string(&ca_public_key_path)?,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMediumSshCaFromControl medium-ssh-ca\n"
    );
    assert!(fs::read_to_string(&sshd_config_path)?.contains(&format!(
        "TrustedUserCAKeys {}",
        ca_public_key_path.display()
    )));
    Ok(())
}

#[tokio::test]
async fn init_node_reconfigure_preserves_existing_services_config() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _node_id = EnvGuard::set_str("MEDIUM_NODE_ID", "office-server");
    let first_invite = format!(
        "medium://node?v=1&control=https://control-one.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-one{LEGACY_SSH_CA_PARAM}"
    );
    let second_invite = format!(
        "medium://node?v=1&control=https://control-two.example.test&security=pinned-tls&control_pin=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&shared_secret=medium-shared-secret-two{LEGACY_SSH_CA_PARAM}"
    );

    run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        first_invite,
    ])
    .await
    .map_err(anyhow::Error::msg)?;

    let services_config_path = temp.path().join("home/.medium/services.toml");
    let custom_services = "[[services]]\nid = \"hello\"\nkind = \"http\"\ntarget = \"127.0.0.1:8082\"\nlabel = \"Hello\"\nenabled = true\n";
    fs::write(&services_config_path, custom_services)?;

    run_main(vec![
        "medium".to_string(),
        "init-node".to_string(),
        second_invite,
        "--reconfigure".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?;

    let node_config = load_from_path(temp.path().join("home/.medium/node.toml"))?;
    assert_eq!(
        node_config.control_url.as_deref(),
        Some("https://control-two.example.test")
    );
    assert_eq!(fs::read_to_string(&services_config_path)?, custom_services);
    assert_eq!(node_config.services.len(), 1);
    assert_eq!(node_config.services[0].id, "hello");
    Ok(())
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn init_node_uses_macos_application_support_without_systemd() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir)?;
    let _home = EnvGuard::set("HOME", &home_dir);
    let _clear_root = EnvGuard::set_str("MEDIUM_ROOT", "");
    unsafe {
        std::env::remove_var("MEDIUM_ROOT");
        std::env::remove_var("MEDIUM_SYSTEMCTL_BIN");
    }
    let _node_id = EnvGuard::set_str("MEDIUM_NODE_ID", "mac-node");
    let _node_listen = EnvGuard::set_str("MEDIUM_NODE_LISTEN_ADDR", "127.0.0.1:17001");
    let _node_public = EnvGuard::set_str("MEDIUM_NODE_PUBLIC_ADDR", "127.0.0.1:17001");
    let invite = format!(
        "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test{LEGACY_SSH_CA_PARAM}"
    );

    let output = run_main(vec!["medium".to_string(), "init-node".to_string(), invite])
        .await
        .map_err(anyhow::Error::msg)?
        .expect("init-node should return a summary");

    let node_config_path = home_dir.join(".medium/node.toml");
    let services_config_path = home_dir.join(".medium/services.toml");
    assert!(output.contains(&node_config_path.display().to_string()));
    assert!(node_config_path.is_file());
    assert!(services_config_path.is_file());
    let node_config = load_from_path(&node_config_path)?;
    assert_eq!(
        node_config.control_url.as_deref(),
        Some("https://control.example.test")
    );
    assert_eq!(
        node_config.control_pin.as_deref(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        node_config.shared_secret.as_deref(),
        Some("medium-shared-secret-test")
    );
    assert!(
        !home_dir
            .join("Library/Application Support/Medium/launchd/medium-node-agent.service")
            .exists()
    );
    Ok(())
}

#[tokio::test]
async fn init_control_refuses_existing_install_without_reconfigure() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _public_url = EnvGuard::set_str("OVERLAY_CONTROL_URL", "https://control.example.test");

    run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .map_err(anyhow::Error::msg)?;

    let error = run_main(vec!["medium".to_string(), "init-control".to_string()])
        .await
        .unwrap_err();
    assert!(error.contains("--reconfigure"));

    let output = run_main(vec![
        "medium".to_string(),
        "init-control".to_string(),
        "--reconfigure".to_string(),
    ])
    .await
    .map_err(anyhow::Error::msg)?
    .expect("reconfigure should return a summary");
    assert!(output.contains("initialized Medium control"));
    Ok(())
}

#[tokio::test]
async fn init_node_derives_public_node_addr_for_default_wildcard_bind() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let temp = tempfile::tempdir()?;
    let _root = EnvGuard::set("MEDIUM_ROOT", temp.path());
    let _node_listen = EnvGuard::set_str("MEDIUM_NODE_LISTEN_ADDR", "0.0.0.0:17001");
    let _clear_node = EnvGuard::set_str("MEDIUM_NODE_PUBLIC_ADDR", "");
    let _clear_legacy_node = EnvGuard::set_str("MEDIUM_HOME_NODE_BIND_ADDR", "");
    let invite = format!(
        "medium://node?v=1&control=https://control.example.test&security=pinned-tls&control_pin=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&shared_secret=medium-shared-secret-test{LEGACY_SSH_CA_PARAM}"
    );

    run_main(vec!["medium".to_string(), "init-node".to_string(), invite])
        .await
        .map_err(anyhow::Error::msg)?;

    let node_config = load_from_path(&temp.path().join("home/.medium/node.toml"))?;
    let public_addr = node_config
        .public_addr
        .as_deref()
        .expect("public address should be derived");

    assert!(public_addr.ends_with(":17001"));
    assert!(!public_addr.starts_with("0.0.0.0:"));
    Ok(())
}

struct TestTlsControlServer {
    url: String,
    control_pin: String,
}

impl TestTlsControlServer {
    async fn start(ssh_ca_public_key: &'static str) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let key_pair = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let control_pin = sha256_pin(cert.der().as_ref());
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = [0_u8; 1024];
                    let Ok(n) = stream.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..n]);
                    let (status, body) = if request.starts_with("GET /api/ssh/ca.pub ") {
                        ("200 OK", ssh_ca_public_key)
                    } else {
                        ("404 Not Found", "")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        Self {
            url: format!("https://{addr}"),
            control_pin,
        }
    }
}

fn sha256_pin(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
