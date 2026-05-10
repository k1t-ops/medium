use medium_cli::client_api;
use medium_cli::state::AppState;
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn fetch_devices_enforces_control_certificate_pin() {
    let server = TestTlsControlServer::start().await;
    let state = AppState {
        server_url: server.url.clone(),
        device_name: "client".to_string(),
        bootstrap_code: String::new(),
        invite_version: 1,
        security: "pinned-tls".to_string(),
        control_pin: server.control_pin.clone(),
        client_secret: "client-secret".to_string(),
    };

    let catalog = client_api::fetch_devices(&state).await.unwrap();

    assert_eq!(catalog.devices.len(), 1);
    assert_eq!(catalog.devices[0].id, "node-1");

    let grant = client_api::open_session(&state, "svc_ssh").await.unwrap();
    assert_eq!(grant.service_id, "svc_ssh");
    assert_eq!(grant.node_id, "node-1");

    let scoped_grant = client_api::open_session_for_node(&state, Some("studio-smiley"), "svc_ssh")
        .await
        .unwrap();
    assert_eq!(scoped_grant.service_id, "svc_ssh");
    assert_eq!(scoped_grant.node_id, "studio-smiley");

    let wrong_pin_state = AppState {
        control_pin: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        ..state
    };
    let error = client_api::fetch_devices(&wrong_pin_state)
        .await
        .unwrap_err();
    let error = error.to_string();

    assert!(error.contains("control TLS pin mismatch"));
    assert!(error.contains(&wrong_pin_state.control_pin));
    assert!(error.contains(&server.control_pin));
}

struct TestTlsControlServer {
    url: String,
    control_pin: String,
}

impl TestTlsControlServer {
    async fn start() -> Self {
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
                    let body = if request.starts_with("GET /api/devices ") {
                        r#"{"devices":[{"id":"node-1","name":"node-one","ssh":null}]}"#
                    } else if request.starts_with(
                        "GET /api/sessions/open?service_id=svc_ssh&requester_device_id=client ",
                    ) {
                        r#"{"session_id":"session-1","service_id":"svc_ssh","node_id":"node-1","relay_hint":null,"authorization":{"token":"token-1","expires_at":"2099-01-01T00:00:00Z","candidates":[{"addr":"127.0.0.1:17001"}]}}"#
                    } else if request.starts_with(
                        "GET /api/sessions/open?service_id=svc_ssh&requester_device_id=client&node_id=studio-smiley ",
                    ) {
                        r#"{"session_id":"session-2","service_id":"svc_ssh","node_id":"studio-smiley","relay_hint":null,"authorization":{"token":"token-2","expires_at":"2099-01-01T00:00:00Z","candidates":[{"addr":"192.168.1.126:17001"}]}}"#
                    } else {
                        return;
                    };

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
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
