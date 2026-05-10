use home_node::config::NodeConfig;
use home_node::proxy::run_tcp_proxy_with_shutdown;
use overlay_crypto::{issue_medium_service_ca, issue_session_token};
use overlay_transport::session::{SessionHello, write_session_hello};
use overlay_transport::udp_session::UdpSessionStream;
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn proxy_forwards_plain_tcp_stream_to_matching_non_wrapped_service() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        stream.write_all(b"SSH-2.0-OverlayTest\r\n").await.unwrap();
    });

    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"

[[services]]
id = "svc_raw"
kind = "https"
target = "{target_addr}"
"#
    ))
    .unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();

    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, Some(bound_addr_tx))
            .await
            .unwrap();
    });

    let bound_addr = bound_addr_rx.await.unwrap();
    let mut client = TcpStream::connect(bound_addr).await.unwrap();
    let hello = SessionHello {
        token: issue_session_token("local-secret", "sess-1", "svc_raw", "node-1").unwrap(),
        service_id: "svc_raw".into(),
        transport: None,
    };
    write_session_hello(&mut client, &hello).await.unwrap();

    let mut banner = Vec::new();
    let mut reader = BufReader::new(client);
    reader.read_until(b'\n', &mut banner).await.unwrap();
    assert_eq!(banner, b"SSH-2.0-OverlayTest\r\n");

    let _ = shutdown_tx.send(());
    proxy_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn udp_session_listener_forwards_to_matching_service_via_tcp_proxy() -> anyhow::Result<()> {
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request = Vec::new();
        reader.read_until(b'\n', &mut request).await.unwrap();
        assert_eq!(request, b"ping\n");
        reader.get_mut().write_all(b"pong\n").await.unwrap();
    });

    let tcp_addr = reserve_tcp_addr()?;
    let udp_addr = reserve_udp_addr()?;
    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "{tcp_addr}"
ice_bind_addr = "{udp_addr}"

[[services]]
id = "svc_web"
kind = "https"
target = "{target_addr}"
"#
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, None)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut client = UdpSessionStream::connect(
            client_socket,
            udp_addr,
            SessionHello {
                token: issue_session_token("local-secret", "sess-udp", "svc_web", "node-1")?,
                service_id: "svc_web".into(),
                transport: None,
            },
        )?;
        std::io::Write::write_all(&mut client, b"ping\n")?;
        let mut response = [0_u8; 5];
        std::io::Read::read_exact(&mut client, &mut response)?;
        assert_eq!(&response, b"pong\n");
        Ok(())
    })
    .await??;

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn proxy_terminates_tls_for_http_service_and_forwards_plain_http() -> anyhow::Result<()> {
    let ca = issue_medium_service_ca()?;
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;

    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        assert_eq!(request_line, "GET / HTTP/1.1\r\n");
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
            .await
            .unwrap();
    });

    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"
service_ca_cert_pem = """
{cert}
"""
service_ca_key_pem = """
{key}
"""

[[services]]
id = "hello"
kind = "http"
target = "{target_addr}"
"#,
        cert = ca.cert_pem,
        key = ca.key_pem,
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();

    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, Some(bound_addr_tx))
            .await
            .unwrap();
    });

    let bound_addr = bound_addr_rx.await?;
    let mut stream = TcpStream::connect(bound_addr).await?;
    let hello = SessionHello {
        token: issue_session_token("local-secret", "sess-1", "hello", "node-1")?,
        service_id: "hello".into(),
        transport: None,
    };
    write_session_hello(&mut stream, &hello).await?;

    let connector = TlsConnector::from(Arc::new(client_tls_config(&ca.cert_pem)?));
    let server_name = ServerName::try_from("hello.medium")?;
    let mut tls = connector.connect(server_name, stream).await?;
    tls.write_all(b"GET / HTTP/1.1\r\nhost: hello.medium\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    assert!(String::from_utf8_lossy(&response).contains("hello"));

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn proxy_terminates_tls_for_ssh_service_and_forwards_raw_ssh() -> anyhow::Result<()> {
    let ca = issue_medium_service_ca()?;
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;

    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut client_banner = String::new();
        reader.read_line(&mut client_banner).await.unwrap();
        assert_eq!(client_banner, "SSH-2.0-MediumClient\r\n");
        reader
            .get_mut()
            .write_all(b"SSH-2.0-MediumTarget\r\n")
            .await
            .unwrap();
    });

    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"
service_ca_cert_pem = """
{cert}
"""
service_ca_key_pem = """
{key}
"""

[[services]]
id = "svc_ssh"
kind = "ssh"
target = "{target_addr}"
"#,
        cert = ca.cert_pem,
        key = ca.key_pem,
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();

    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, Some(bound_addr_tx))
            .await
            .unwrap();
    });

    let bound_addr = bound_addr_rx.await?;
    let mut stream = TcpStream::connect(bound_addr).await?;
    let hello = SessionHello {
        token: issue_session_token("local-secret", "sess-ssh", "svc_ssh", "node-1")?,
        service_id: "svc_ssh".into(),
        transport: None,
    };
    write_session_hello(&mut stream, &hello).await?;

    let connector = TlsConnector::from(Arc::new(client_tls_config(&ca.cert_pem)?));
    let server_name = ServerName::try_from("svc-ssh.medium")?;
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        connector.connect(server_name, stream),
    )
    .await??;
    tls.write_all(b"SSH-2.0-MediumClient\r\n").await?;
    let mut banner = Vec::new();
    let mut reader = BufReader::new(tls);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reader.read_until(b'\n', &mut banner),
    )
    .await??;
    assert_eq!(banner, b"SSH-2.0-MediumTarget\r\n");

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn proxy_accepts_tls_and_returns_502_when_http_target_is_down() -> anyhow::Result<()> {
    let ca = issue_medium_service_ca()?;
    let unavailable_target = reserve_tcp_addr()?;

    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"
service_ca_cert_pem = """
{cert}
"""
service_ca_key_pem = """
{key}
"""

[[services]]
id = "hello"
kind = "http"
target = "{unavailable_target}"
"#,
        cert = ca.cert_pem,
        key = ca.key_pem,
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();

    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, Some(bound_addr_tx))
            .await
            .unwrap();
    });

    let bound_addr = bound_addr_rx.await?;
    let mut stream = TcpStream::connect(bound_addr).await?;
    let hello = SessionHello {
        token: issue_session_token("local-secret", "sess-down", "hello", "node-1")?,
        service_id: "hello".into(),
        transport: None,
    };
    write_session_hello(&mut stream, &hello).await?;

    let connector = TlsConnector::from(Arc::new(client_tls_config(&ca.cert_pem)?));
    let server_name = ServerName::try_from("hello.medium")?;
    let mut tls = connector.connect(server_name, stream).await?;
    tls.write_all(b"GET / HTTP/1.1\r\nhost: hello.medium\r\n\r\n")
        .await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("Medium service target unavailable"));

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    Ok(())
}

#[tokio::test]
async fn proxy_returns_502_when_http_target_closes_without_response() -> anyhow::Result<()> {
    let ca = issue_medium_service_ca()?;
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;

    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        drop(stream);
    });

    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"
service_ca_cert_pem = """
{cert}
"""
service_ca_key_pem = """
{key}
"""

[[services]]
id = "hello"
kind = "http"
target = "{target_addr}"
"#,
        cert = ca.cert_pem,
        key = ca.key_pem,
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();

    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, Some(bound_addr_tx))
            .await
            .unwrap();
    });

    let bound_addr = bound_addr_rx.await?;
    let mut stream = TcpStream::connect(bound_addr).await?;
    let hello = SessionHello {
        token: issue_session_token("local-secret", "sess-closed", "hello", "node-1")?,
        service_id: "hello".into(),
        transport: None,
    };
    write_session_hello(&mut stream, &hello).await?;

    let connector = TlsConnector::from(Arc::new(client_tls_config(&ca.cert_pem)?));
    let server_name = ServerName::try_from("hello.medium")?;
    let mut tls = connector.connect(server_name, stream).await?;
    tls.write_all(b"GET / HTTP/1.1\r\nhost: hello.medium\r\n\r\n")
        .await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    assert!(response.contains("502 Bad Gateway"));
    assert!(response.contains("closed before returning a response"));

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn udp_session_proxy_terminates_tls_for_http_service() -> anyhow::Result<()> {
    let ca = issue_medium_service_ca()?;
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;

    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        assert_eq!(request_line, "GET / HTTP/1.1\r\n");
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
            .await
            .unwrap();
    });

    let tcp_addr = reserve_tcp_addr()?;
    let udp_addr = reserve_udp_addr()?;
    let cfg: NodeConfig = toml::from_str(&format!(
        r#"
node_id = "node-1"
bind_addr = "{tcp_addr}"
ice_bind_addr = "{udp_addr}"
service_ca_cert_pem = """
{cert}
"""
service_ca_key_pem = """
{key}
"""

[[services]]
id = "hello"
kind = "http"
target = "{target_addr}"
"#,
        cert = ca.cert_pem,
        key = ca.key_pem,
    ))?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        run_tcp_proxy_with_shutdown(cfg, "local-secret", shutdown_rx, None)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let client = UdpSessionStream::connect(
            client_socket,
            udp_addr,
            SessionHello {
                token: issue_session_token("local-secret", "sess-udp-http", "hello", "node-1")?,
                service_id: "hello".into(),
                transport: None,
            },
        )?;
        let connection = rustls::ClientConnection::new(
            Arc::new(client_tls_config(&ca.cert_pem)?),
            ServerName::try_from("hello.medium")?,
        )?;
        let mut tls = rustls::StreamOwned::new(connection, client);
        std::io::Write::write_all(&mut tls, b"GET / HTTP/1.1\r\nhost: hello.medium\r\n\r\n")?;
        let mut response = String::new();
        std::io::Read::read_to_string(&mut tls, &mut response)?;
        assert!(response.contains("hello"));
        Ok(())
    })
    .await??;

    let _ = shutdown_tx.send(());
    proxy_task.await?;
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn node_agent_connects_to_wss_relay_when_configured() -> anyhow::Result<()> {
    let cfg = load_test_config_with_service("node-1", "svc_web", "127.0.0.1:3000")?;
    let relay = TestWssRelay::start("relay-secret").await?;

    let relay_url = format!("ws://{}/medium/v1/relay", relay.addr());
    let connector = tokio::spawn(async move {
        home_node::proxy::connect_wss_relay_once(&cfg, "relay-secret", &relay_url).await
    });

    assert_eq!(relay.first_node_id().await?, "node-1");
    connector.abort();
    Ok(())
}

fn client_tls_config(ca_cert_pem: &str) -> anyhow::Result<rustls::ClientConfig> {
    let mut reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(CertificateDer::from(cert))?;
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Ok(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[test]
fn derives_embedded_wss_relay_url_from_control_url() -> anyhow::Result<()> {
    let cfg: NodeConfig = toml::from_str(
        r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"
control_url = "https://control.example.test:7777"

[[services]]
id = "svc_web"
kind = "web"
target = "127.0.0.1:3000"
"#,
    )?;

    assert_eq!(
        home_node::proxy::effective_wss_relay_url(&cfg).as_deref(),
        Some("wss://control.example.test:7777/medium/v1/relay")
    );
    Ok(())
}

#[tokio::test]
async fn wss_relay_binary_session_forwards_to_matching_service() -> anyhow::Result<()> {
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request = Vec::new();
        reader.read_until(b'\n', &mut request).await.unwrap();
        assert_eq!(request, b"ping\n");
        reader.get_mut().write_all(b"pong\n").await.unwrap();
    });

    let cfg = load_test_config_with_service("node-1", "svc_web", &target_addr.to_string())?;
    let relay = TestWssRelay::start("relay-secret").await?;
    let relay_url = format!("ws://{}/medium/v1/relay", relay.addr());
    let connector = tokio::spawn(async move {
        home_node::proxy::connect_wss_relay_once(&cfg, "relay-secret", &relay_url).await
    });

    assert_eq!(relay.first_node_id().await?, "node-1");
    let hello = SessionHello {
        token: issue_session_token("relay-secret", "sess-1", "svc_web", "node-1")?,
        service_id: "svc_web".into(),
        transport: None,
    };
    let mut payload = serde_json::to_vec(&hello)?;
    payload.push(b'\n');
    payload.extend_from_slice(b"ping\n");
    relay.send_binary(payload).await?;
    assert_eq!(relay.recv_binary().await?, b"pong\n");

    connector.abort();
    target_task.await?;
    Ok(())
}

#[tokio::test]
async fn wss_relay_binary_session_rejects_unknown_service() -> anyhow::Result<()> {
    let cfg = load_test_config_with_service("node-1", "svc_web", "127.0.0.1:3000")?;
    let relay = TestWssRelay::start("relay-secret").await?;
    let relay_url = format!("ws://{}/medium/v1/relay", relay.addr());
    let connector = tokio::spawn(async move {
        home_node::proxy::connect_wss_relay_once(&cfg, "relay-secret", &relay_url).await
    });

    assert_eq!(relay.first_node_id().await?, "node-1");
    let hello = SessionHello {
        token: issue_session_token("relay-secret", "sess-1", "missing", "node-1")?,
        service_id: "missing".into(),
        transport: None,
    };
    let mut payload = serde_json::to_vec(&hello)?;
    payload.push(b'\n');
    relay.send_binary(payload).await?;

    let result = connector.await?;
    assert!(result.unwrap_err().to_string().contains("unknown service"));
    Ok(())
}

fn load_test_config_with_service(
    node_id: &str,
    service_id: &str,
    target: &str,
) -> anyhow::Result<NodeConfig> {
    Ok(toml::from_str(&format!(
        r#"
node_id = "{node_id}"
bind_addr = "127.0.0.1:0"

[[services]]
id = "{service_id}"
kind = "web"
target = "{target}"
"#
    ))?)
}

fn reserve_tcp_addr() -> anyhow::Result<std::net::SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn reserve_udp_addr() -> anyhow::Result<std::net::SocketAddr> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let addr = socket.local_addr()?;
    drop(socket);
    Ok(addr)
}

struct TestWssRelay {
    addr: std::net::SocketAddr,
    first_node_id: Arc<Mutex<Option<String>>>,
    node_ws: Arc<Mutex<Option<WebSocketStream<TcpStream>>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestWssRelay {
    async fn start(shared_secret: &str) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let first_node_id = Arc::new(Mutex::new(None));
        let node_ws = Arc::new(Mutex::new(None));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let shared_secret = shared_secret.to_string();
        let first_node_id_for_task = first_node_id.clone();
        let node_ws_for_task = node_ws.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            continue;
                        };
                        let first_node_id = first_node_id_for_task.clone();
                        let node_ws = node_ws_for_task.clone();
                        let shared_secret = shared_secret.clone();
                        tokio::spawn(async move {
                            let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                                return;
                            };
                            let Some(Ok(Message::Text(payload))) = futures_util::StreamExt::next(&mut ws).await else {
                                return;
                            };
                            let Ok(hello) = serde_json::from_str::<serde_json::Value>(&payload) else {
                                return;
                            };
                            if hello["role"] == "node" && hello["shared_secret"] == shared_secret {
                                if let Some(node_id) = hello["node_id"].as_str() {
                                    *first_node_id.lock().await = Some(node_id.to_string());
                                }
                            }
                            *node_ws.lock().await = Some(ws);
                        });
                    }
                }
            }
        });

        Ok(Self {
            addr,
            first_node_id,
            node_ws,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    async fn first_node_id(&self) -> anyhow::Result<String> {
        for _ in 0..50 {
            if let Some(node_id) = self.first_node_id.lock().await.clone() {
                return Ok(node_id);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        anyhow::bail!("node did not connect to wss relay")
    }

    async fn send_binary(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        for _ in 0..50 {
            if let Some(ws) = self.node_ws.lock().await.as_mut() {
                futures_util::SinkExt::send(ws, Message::Binary(payload.into())).await?;
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        anyhow::bail!("node websocket is not connected")
    }

    async fn recv_binary(&self) -> anyhow::Result<Vec<u8>> {
        for _ in 0..50 {
            if let Some(ws) = self.node_ws.lock().await.as_mut() {
                while let Some(message) = futures_util::StreamExt::next(ws).await {
                    if let Message::Binary(payload) = message? {
                        return Ok(payload.to_vec());
                    }
                }
                anyhow::bail!("node websocket closed before binary frame")
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        anyhow::bail!("node websocket is not connected")
    }
}

impl Drop for TestWssRelay {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}
