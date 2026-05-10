use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use overlay_protocol::{
    EndpointKind, NodeEndpoint, PublishedService, RegisterNodeRequest, ServiceKind,
    SshCertificateRequest, SshCertificateResponse,
};
use std::process::Command;
use tower::ServiceExt;

#[tokio::test]
async fn ssh_ca_route_returns_public_key_from_control_plane() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ca_key = temp.path().join("ssh-ca");
    run_ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "test-ca",
        "-f",
        &ca_key.display().to_string(),
    ])?;
    let expected_public_key = std::fs::read_to_string(ca_key.with_extension("pub"))?;

    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry: control_plane::registry::RegistryStore::in_memory().await?,
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: String::new(),
        service_ca_cert_pem: None,
        service_ca_key_pem: None,
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: Some(ca_key.display().to_string()),
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/ssh/ca.pub")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), 200);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, expected_public_key);
    Ok(())
}

#[tokio::test]
async fn ssh_certificate_route_signs_ephemeral_public_key_for_service_user() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ca_key = temp.path().join("ssh-ca");
    let user_key = temp.path().join("id_ed25519");
    run_ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "test-ca",
        "-f",
        &ca_key.display().to_string(),
    ])?;
    run_ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "test-user",
        "-f",
        &user_key.display().to_string(),
    ])?;

    let registry = control_plane::registry::RegistryStore::in_memory().await?;
    registry
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "studio-smiley".into(),
            endpoints: vec![NodeEndpoint {
                kind: EndpointKind::TcpProxy,
                schema_version: 1,
                addr: "127.0.0.1:17001".into(),
                priority: 10,
            }],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: None,
                target: "127.0.0.1:3322".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await?;

    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry,
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: String::new(),
        service_ca_cert_pem: None,
        service_ca_key_pem: None,
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: Some(ca_key.display().to_string()),
    });

    let request = SshCertificateRequest {
        service_id: "svc_ssh".into(),
        node_id: None,
        requester_device_id: "macbook".into(),
        public_key: std::fs::read_to_string(user_key.with_extension("pub"))?,
        client_secret: "client-secret".into(),
    };
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/ssh/certificate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;

    assert_eq!(response.status(), 200);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let payload: SshCertificateResponse = serde_json::from_slice(&body)?;
    assert_eq!(payload.user_name, "overlay");
    assert_eq!(payload.valid_seconds, 300);
    assert!(
        payload
            .certificate
            .starts_with("ssh-ed25519-cert-v01@openssh.com ")
    );

    let cert_path = temp.path().join("id_ed25519-cert.pub");
    std::fs::write(&cert_path, payload.certificate)?;
    let output = Command::new("ssh-keygen")
        .args(["-Lf", &cert_path.display().to_string()])
        .output()?;
    assert!(output.status.success());
    let cert_info = String::from_utf8_lossy(&output.stdout);
    assert!(cert_info.contains("Principals:"));
    assert!(cert_info.contains("overlay"));
    Ok(())
}

#[tokio::test]
async fn ssh_certificate_route_uses_node_scoped_service_id() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ca_key = temp.path().join("ssh-ca");
    let user_key = temp.path().join("id_ed25519");
    run_ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "test-ca",
        "-f",
        &ca_key.display().to_string(),
    ])?;
    run_ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "test-user",
        "-f",
        &user_key.display().to_string(),
    ])?;

    let registry = control_plane::registry::RegistryStore::in_memory().await?;
    for (node_id, user_name) in [("node-1", "overlay"), ("studio-smiley", "smiley")] {
        registry
            .register_node(&RegisterNodeRequest {
                node_id: node_id.into(),
                node_label: node_id.into(),
                endpoints: vec![NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: "127.0.0.1:17001".into(),
                    priority: 10,
                }],
                services: vec![PublishedService {
                    id: "svc_ssh".into(),
                    kind: ServiceKind::Ssh,
                    schema_version: 1,
                    label: None,
                    target: "127.0.0.1:22".into(),
                    user_name: Some(user_name.into()),
                }],
            })
            .await?;
    }

    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry,
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: String::new(),
        service_ca_cert_pem: None,
        service_ca_key_pem: None,
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: Some(ca_key.display().to_string()),
    });

    let request = SshCertificateRequest {
        service_id: "svc_ssh".into(),
        node_id: Some("studio-smiley".into()),
        requester_device_id: "macbook".into(),
        public_key: std::fs::read_to_string(user_key.with_extension("pub"))?,
        client_secret: "client-secret".into(),
    };
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/ssh/certificate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;

    assert_eq!(response.status(), 200);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let payload: SshCertificateResponse = serde_json::from_slice(&body)?;
    assert_eq!(payload.user_name, "smiley");
    Ok(())
}

fn run_ssh_keygen(args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("ssh-keygen").args(args).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
