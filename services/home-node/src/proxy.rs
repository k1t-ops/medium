use crate::config::NodeConfig;
use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use overlay_crypto::verify_session_token;
use overlay_protocol::{ServiceCertificateRequest, ServiceCertificateResponse};
use overlay_transport::p2p_diag;
use overlay_transport::pinned_http::pinned_tls_client_config;
use overlay_transport::session::{RelayHello, SessionHello, read_session_hello, write_relay_hello};
use overlay_transport::udp_rendezvous::send_node_register;
use overlay_transport::udp_session::UdpSessionListener;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{TcpStream as StdTcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    Connector, WebSocketStream, connect_async_tls_with_config, tungstenite::Message,
};

const RELAY_RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
const RELAY_NODE_IDLE_LEASE: std::time::Duration = std::time::Duration::from_secs(60);
type ProxyServices = Arc<HashMap<String, ProxyService>>;

pub async fn run_tcp_proxy(cfg: NodeConfig, shared_secret: &str) -> anyhow::Result<()> {
    spawn_configured_connectors(&cfg, shared_secret);
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();
    run_tcp_proxy_with_shutdown(cfg, shared_secret, shutdown_rx, None).await
}

pub fn spawn_configured_connectors(cfg: &NodeConfig, shared_secret: &str) {
    if let Some(relay_addr) = cfg.relay_addr.clone().or_else(|| {
        std::env::var("MEDIUM_RELAY_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }) {
        spawn_relay_connectors(&cfg, shared_secret, &relay_addr);
    }
    if let Some(wss_relay_url) = effective_wss_relay_url(cfg) {
        tracing::info!(%wss_relay_url, "starting WSS relay connectors");
        spawn_wss_relay_connectors(&cfg, shared_secret, &wss_relay_url);
    }
}

pub fn effective_wss_relay_url(cfg: &NodeConfig) -> Option<String> {
    cfg.wss_relay_url
        .clone()
        .or_else(|| {
            std::env::var("MEDIUM_WSS_RELAY_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            cfg.control_url
                .as_deref()
                .and_then(derive_embedded_wss_relay_url)
        })
}

fn derive_embedded_wss_relay_url(control_url: &str) -> Option<String> {
    let mut url = url::Url::parse(control_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    url.set_scheme("wss").ok()?;
    url.set_path("/medium/v1/relay");
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

fn spawn_relay_connectors(cfg: &NodeConfig, shared_secret: &str, relay_addr: &str) {
    for _ in 0..4 {
        let cfg = cfg.clone();
        let shared_secret = shared_secret.to_string();
        let relay_addr = relay_addr.to_string();
        tokio::spawn(async move {
            let services = loop {
                match proxy_services_from_config(&cfg, &shared_secret).await {
                    Ok(services) => break services,
                    Err(error) => {
                        tracing::warn!(%error, "relay connector service preparation failed");
                        tokio::time::sleep(RELAY_RECONNECT_DELAY).await;
                    }
                }
            };
            loop {
                match connect_relay_once(&cfg, &shared_secret, &relay_addr, services.clone()).await
                {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(%error, "relay connector failed");
                        tokio::time::sleep(RELAY_RECONNECT_DELAY).await;
                    }
                }
            }
        });
    }
}

fn spawn_wss_relay_connectors(cfg: &NodeConfig, shared_secret: &str, relay_url: &str) {
    for _ in 0..4 {
        let cfg = cfg.clone();
        let shared_secret = shared_secret.to_string();
        let relay_url = relay_url.to_string();
        tokio::spawn(async move {
            let services = loop {
                match proxy_services_from_config(&cfg, &shared_secret).await {
                    Ok(services) => break services,
                    Err(error) => {
                        tracing::warn!(%error, "wss relay connector service preparation failed");
                        tokio::time::sleep(RELAY_RECONNECT_DELAY).await;
                    }
                }
            };
            loop {
                match connect_wss_relay_once_with_services(
                    &cfg,
                    &shared_secret,
                    &relay_url,
                    services.clone(),
                )
                .await
                {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(%error, "wss relay connector failed");
                        tokio::time::sleep(RELAY_RECONNECT_DELAY).await;
                    }
                }
            }
        });
    }
}

async fn connect_relay_once(
    cfg: &NodeConfig,
    shared_secret: &str,
    relay_addr: &str,
    services: ProxyServices,
) -> anyhow::Result<()> {
    connect_relay_once_with_idle_timeout(
        cfg,
        shared_secret,
        relay_addr,
        services,
        RELAY_NODE_IDLE_LEASE,
    )
    .await
}

async fn connect_relay_once_with_idle_timeout(
    cfg: &NodeConfig,
    shared_secret: &str,
    relay_addr: &str,
    services: ProxyServices,
    idle_timeout: std::time::Duration,
) -> anyhow::Result<()> {
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_addr,
        "connecting TCP relay node socket"
    );
    let mut stream = TcpStream::connect(relay_addr).await?;
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_addr,
        "connected TCP relay node socket"
    );
    write_relay_hello(
        &mut stream,
        &RelayHello::Node {
            node_id: cfg.node_id.clone(),
            shared_secret: shared_secret.to_string(),
        },
    )
    .await?;
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_addr,
        "sent TCP relay node hello"
    );

    handle_relay_connection(stream, services, &cfg.node_id, shared_secret, idle_timeout).await
}

pub async fn connect_wss_relay_once(
    cfg: &NodeConfig,
    shared_secret: &str,
    relay_url: &str,
) -> anyhow::Result<()> {
    let services = proxy_services_from_config(cfg, shared_secret).await?;
    connect_wss_relay_once_with_services(cfg, shared_secret, relay_url, services).await
}

async fn connect_wss_relay_once_with_services(
    cfg: &NodeConfig,
    shared_secret: &str,
    relay_url: &str,
    services: ProxyServices,
) -> anyhow::Result<()> {
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_url,
        "connecting WSS relay node socket"
    );
    let connector = cfg
        .control_pin
        .as_deref()
        .map(|control_pin| {
            tracing::info!(
                node_id = %cfg.node_id,
                %relay_url,
                "using pinned TLS for WSS relay"
            );
            pinned_tls_client_config(control_pin).map(|config| Connector::Rustls(Arc::new(config)))
        })
        .transpose()?;
    let (mut ws, _) = connect_async_tls_with_config(relay_url, None, false, connector).await?;
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_url,
        "connected WSS relay node socket"
    );
    let hello = RelayHello::Node {
        node_id: cfg.node_id.clone(),
        shared_secret: shared_secret.to_string(),
    };
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await?;
    tracing::info!(
        node_id = %cfg.node_id,
        %relay_url,
        "sent WSS relay node hello"
    );
    handle_wss_connection(ws, services, &cfg.node_id, shared_secret).await
}

pub async fn run_tcp_proxy_with_shutdown(
    cfg: NodeConfig,
    shared_secret: &str,
    mut shutdown: oneshot::Receiver<()>,
    bound_addr_tx: Option<oneshot::Sender<std::net::SocketAddr>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(listener.local_addr()?);
    }

    let services = proxy_services_from_config(&cfg, shared_secret).await?;
    let udp_running = Arc::new(AtomicBool::new(true));
    spawn_udp_session_listener(&cfg, &shared_secret, udp_running.clone());
    let node_id = cfg.node_id;
    let shared_secret = shared_secret.to_string();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                udp_running.store(false, Ordering::Relaxed);
                break;
            },
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let services = services.clone();
                let node_id = node_id.clone();
                let shared_secret = shared_secret.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, services, &node_id, &shared_secret).await {
                        tracing::warn!(%error, "proxy connection failed");
                    }
                });
            }
        }
    }

    Ok(())
}

fn spawn_udp_session_listener(cfg: &NodeConfig, shared_secret: &str, running: Arc<AtomicBool>) {
    let udp_bind_addr = cfg.ice_bind_addr.clone();
    let tcp_proxy_addr = loopback_tcp_proxy_addr(&cfg.bind_addr);
    let node_id = cfg.node_id.clone();
    let shared_secret = shared_secret.to_string();
    let rendezvous_addr = effective_udp_rendezvous_addr(cfg);
    tokio::task::spawn_blocking(move || {
        if let Err(error) = run_udp_session_listener(
            &udp_bind_addr,
            &tcp_proxy_addr,
            &node_id,
            &shared_secret,
            rendezvous_addr.as_deref(),
            running,
        ) {
            tracing::warn!(%error, %udp_bind_addr, "UDP session listener stopped");
        }
    });
}

fn run_udp_session_listener(
    udp_bind_addr: &str,
    tcp_proxy_addr: &str,
    node_id: &str,
    shared_secret: &str,
    rendezvous_addr: Option<&str>,
    running: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(udp_bind_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
    if let Some(rendezvous_addr) = rendezvous_addr {
        let socket = socket.try_clone()?;
        let node_id = node_id.to_string();
        let shared_secret = shared_secret.to_string();
        let rendezvous_addr = rendezvous_addr.parse::<std::net::SocketAddr>()?;
        let running = running.clone();
        tracing::info!(
            %node_id,
            %rendezvous_addr,
            %udp_bind_addr,
            "starting UDP rendezvous registration"
        );
        tracing::info!(
            "{}",
            p2p_diag::line(
                "node_register_loop",
                "start",
                [
                    ("node_id", node_id.as_str()),
                    ("rendezvous_addr", rendezvous_addr.to_string().as_str()),
                    ("udp_bind_addr", udp_bind_addr),
                ],
            )
        );
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Err(error) =
                    send_node_register(&socket, rendezvous_addr, &node_id, &shared_secret)
                {
                    tracing::warn!(%error, "UDP rendezvous registration failed");
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }
    tracing::info!(%udp_bind_addr, %tcp_proxy_addr, "UDP session listener started");
    let listener = UdpSessionListener::new(socket);
    while running.load(Ordering::Relaxed) {
        let accepted = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if is_timeout(&error) => continue,
            Err(error) => return Err(error),
        };
        tracing::info!(
            "{}",
            p2p_diag::line(
                "session_hello_received",
                "ok",
                [
                    ("node_id", node_id),
                    ("service_id", accepted.hello.service_id.as_str()),
                    ("peer_addr", accepted.peer_addr.to_string().as_str()),
                ],
            )
        );
        let tcp_proxy_addr = tcp_proxy_addr.to_string();
        std::thread::spawn(move || {
            if let Err(error) =
                bridge_udp_session_to_tcp_proxy(accepted.stream, &tcp_proxy_addr, &accepted.hello)
            {
                tracing::warn!(%error, peer = %accepted.peer_addr, "UDP session failed");
            }
        });
    }
    tracing::info!(%udp_bind_addr, "UDP session listener stopped");
    Ok(())
}

fn is_timeout(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .is_some_and(|error| {
            error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut
        })
}

fn bridge_udp_session_to_tcp_proxy(
    udp_stream: overlay_transport::udp_session::UdpSessionStream,
    tcp_proxy_addr: &str,
    hello: &SessionHello,
) -> anyhow::Result<()> {
    tracing::info!(
        service_id = %hello.service_id,
        %tcp_proxy_addr,
        "UDP session bridge connecting to local TCP proxy"
    );
    let mut tcp_stream = StdTcpStream::connect(tcp_proxy_addr)?;
    write_session_hello_sync(&mut tcp_stream, hello)?;
    tracing::info!(
        service_id = %hello.service_id,
        %tcp_proxy_addr,
        "UDP session bridge wrote session hello to local TCP proxy"
    );
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_millis(20)))?;
    tcp_stream.set_write_timeout(Some(std::time::Duration::from_secs(3)))?;
    udp_stream.set_poll_timeout(std::time::Duration::from_millis(20))?;
    let mut tcp_writer = tcp_stream.try_clone()?;
    let mut udp_writer = udp_stream;
    let mut tcp_reader = tcp_stream;
    let mut udp_reader = udp_writer.try_clone()?;

    let service_id = hello.service_id.clone();
    let tcp_to_udp_service_id = service_id.clone();
    let tcp_to_udp = std::thread::spawn(move || {
        copy_blocking(
            &mut tcp_reader,
            &mut udp_writer,
            "tcp_proxy_to_udp",
            &tcp_to_udp_service_id,
        )
    });
    let udp_to_tcp = copy_blocking(
        &mut udp_reader,
        &mut tcp_writer,
        "udp_to_tcp_proxy",
        &service_id,
    );
    match tcp_to_udp.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "UDP session bridge tcp->udp ended with error"),
        Err(_) => tracing::warn!("UDP session bridge tcp->udp thread panicked"),
    }
    udp_to_tcp
}

fn write_session_hello_sync(stream: &mut StdTcpStream, hello: &SessionHello) -> anyhow::Result<()> {
    let mut payload = serde_json::to_vec(hello)?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    Ok(())
}

fn copy_blocking<R, W>(
    reader: &mut R,
    writer: &mut W,
    direction: &'static str,
    service_id: &str,
) -> anyhow::Result<()>
where
    R: Read,
    W: Write,
{
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                tracing::info!(%direction, %service_id, "blocking copy reached EOF");
                return Ok(());
            }
            Ok(size) => {
                tracing::info!(%direction, %service_id, bytes = size, "blocking copy transferring bytes");
                writer.write_all(&buffer[..size])?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn loopback_tcp_proxy_addr(bind_addr: &str) -> String {
    if let Some(port) = bind_addr.rsplit_once(':').map(|(_, port)| port) {
        if bind_addr.starts_with("0.0.0.0:") || bind_addr.starts_with("[::]:") {
            return format!("127.0.0.1:{port}");
        }
    }
    bind_addr.to_string()
}

fn effective_udp_rendezvous_addr(cfg: &NodeConfig) -> Option<String> {
    cfg.ice_relay_addr
        .clone()
        .or_else(|| {
            std::env::var("MEDIUM_ICE_RENDEZVOUS_ADDR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| cfg.relay_addr.clone())
}

async fn handle_connection(
    mut inbound: TcpStream,
    services: ProxyServices,
    expected_node_id: &str,
    shared_secret: &str,
) -> anyhow::Result<()> {
    let hello = read_session_hello(&mut inbound).await?;
    handle_connection_with_hello(inbound, hello, services, expected_node_id, shared_secret).await
}

async fn handle_relay_connection(
    mut inbound: TcpStream,
    services: ProxyServices,
    expected_node_id: &str,
    shared_secret: &str,
    idle_timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let hello = match tokio::time::timeout(idle_timeout, read_session_hello(&mut inbound)).await {
        Ok(result) => result?,
        Err(_) => anyhow::bail!("relay node socket idle lease expired after {idle_timeout:?}"),
    };
    handle_connection_with_hello(inbound, hello, services, expected_node_id, shared_secret).await
}

async fn handle_connection_with_hello(
    inbound: TcpStream,
    hello: SessionHello,
    services: ProxyServices,
    expected_node_id: &str,
    shared_secret: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        service_id = %hello.service_id,
        expected_node_id,
        "received TCP session"
    );
    let claims = verify_session_token(shared_secret, &hello.token)?;
    if claims.service_id != hello.service_id {
        anyhow::bail!("session service mismatch");
    }
    if claims.node_id != expected_node_id {
        anyhow::bail!("session node mismatch");
    }

    let service = services
        .get(&hello.service_id)
        .ok_or_else(|| anyhow::anyhow!("unknown service {}", hello.service_id))?;
    tracing::info!(
        service_id = %hello.service_id,
        target = %service.target,
        kind = %service.kind,
        "connecting TCP session to local target"
    );
    proxy_stream_to_service(inbound, service).await
}

async fn handle_wss_connection<S>(
    ws: WebSocketStream<S>,
    services: ProxyServices,
    expected_node_id: &str,
    shared_secret: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (hello, initial_payload) =
        match tokio::time::timeout(RELAY_NODE_IDLE_LEASE, read_wss_session_hello(&mut ws_rx)).await
        {
            Ok(result) => result?,
            Err(_) => anyhow::bail!(
                "wss relay node socket idle lease expired after {RELAY_NODE_IDLE_LEASE:?}"
            ),
        };
    tracing::info!(
        service_id = %hello.service_id,
        expected_node_id,
        initial_payload_bytes = initial_payload.len(),
        "received WSS relay session"
    );
    let claims = verify_session_token(shared_secret, &hello.token)?;
    if claims.service_id != hello.service_id {
        anyhow::bail!("session service mismatch");
    }
    if claims.node_id != expected_node_id {
        anyhow::bail!("session node mismatch");
    }

    let service = services
        .get(&hello.service_id)
        .ok_or_else(|| anyhow::anyhow!("unknown service {}", hello.service_id))?;
    tracing::info!(
        service_id = %hello.service_id,
        target = %service.target,
        kind = %service.kind,
        "connecting WSS relay session to local target"
    );
    let (proxy_side, bridge_side) = duplex(64 * 1024);
    let (mut bridge_rx, mut bridge_tx) = tokio::io::split(bridge_side);

    let ws_to_tcp = async {
        if !initial_payload.is_empty() {
            bridge_tx.write_all(&initial_payload).await?;
        }
        while let Some(message) = ws_rx.next().await {
            match message? {
                Message::Binary(payload) => bridge_tx.write_all(&payload).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        bridge_tx.shutdown().await?;
        anyhow::Ok(())
    };

    let tcp_to_ws = async {
        let mut buffer = [0_u8; 8192];
        loop {
            let read = bridge_rx.read(&mut buffer).await?;
            if read == 0 {
                let _ = ws_tx.send(Message::Close(None)).await;
                break;
            }
            ws_tx
                .send(Message::Binary(buffer[..read].to_vec().into()))
                .await?;
        }
        anyhow::Ok(())
    };

    let proxy = proxy_stream_to_service(proxy_side, service);

    tokio::select! {
        result = proxy => result?,
        result = ws_to_tcp => result?,
        result = tcp_to_ws => result?,
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct ProxyService {
    id: String,
    kind: String,
    target: String,
    tls_config: Option<Arc<ServerConfig>>,
    tls_mode: ServiceTlsMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceTlsMode {
    None,
    Http,
    Raw,
}

async fn proxy_services_from_config(
    cfg: &NodeConfig,
    shared_secret: &str,
) -> anyhow::Result<ProxyServices> {
    let mut services = HashMap::new();
    for service in &cfg.services {
        if !service.enabled {
            continue;
        }
        let kind = service.kind.to_ascii_lowercase();
        let hostname = service_hostname(service);
        let tls_mode = match kind.as_str() {
            "http" => ServiceTlsMode::Http,
            "ssh" => ServiceTlsMode::Raw,
            _ => ServiceTlsMode::None,
        };
        let tls_config = if tls_mode != ServiceTlsMode::None {
            Some(Arc::new(
                http_service_tls_config(cfg, shared_secret, &service.id, &hostname).await?,
            ))
        } else {
            None
        };
        services.insert(
            service.id.clone(),
            ProxyService {
                id: service.id.clone(),
                kind,
                target: service.target.clone(),
                tls_config,
                tls_mode,
            },
        );
    }
    Ok(Arc::new(services))
}

async fn http_service_tls_config(
    cfg: &NodeConfig,
    shared_secret: &str,
    service_id: &str,
    hostname: &str,
) -> anyhow::Result<ServerConfig> {
    let identity = if let (Some(ca_cert), Some(ca_key)) = (
        cfg.service_ca_cert_pem.as_deref(),
        cfg.service_ca_key_pem.as_deref(),
    ) {
        overlay_crypto::issue_service_tls_identity(ca_cert, ca_key, &[hostname.to_string()])?
    } else {
        request_service_tls_identity(cfg, shared_secret, service_id, hostname)
            .await
            .with_context(|| {
                format!(
                    "issue Medium service TLS certificate for http service {service_id} ({hostname}); ensure the control-plane is updated and reconfigured with `sudo medium init-control --reconfigure`, then restarted with `sudo medium control restart`"
                )
            })?
    };
    server_tls_config_from_pem(&identity.cert_pem, &identity.key_pem)
}

async fn request_service_tls_identity(
    cfg: &NodeConfig,
    shared_secret: &str,
    service_id: &str,
    hostname: &str,
) -> anyhow::Result<overlay_crypto::ServiceTlsIdentity> {
    let control_url = cfg
        .control_url
        .clone()
        .or_else(|| std::env::var("OVERLAY_CONTROL_URL").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("http service {service_id} requires service CA config or control_url")
        })?;
    let control_pin = cfg
        .control_pin
        .clone()
        .or_else(|| std::env::var("MEDIUM_CONTROL_PIN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("http service {service_id} requires service CA config or control_pin")
        })?;
    let request = ServiceCertificateRequest {
        node_id: cfg.node_id.clone(),
        hostnames: vec![hostname.to_string()],
        shared_secret: shared_secret.to_string(),
    };
    let response: ServiceCertificateResponse = overlay_transport::pinned_http::post_json(
        &format!(
            "{}/api/nodes/service-certificate",
            control_url.trim_end_matches('/')
        ),
        &control_pin,
        &request,
    )
    .await?;
    Ok(overlay_crypto::ServiceTlsIdentity {
        cert_pem: response.cert_pem,
        key_pem: response.key_pem,
    })
}

async fn proxy_stream_to_service<S>(mut inbound: S, service: &ProxyService) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(config) = &service.tls_config {
        tracing::info!(service_id = %service.id, "accepting Medium TLS for service");
        let acceptor = TlsAcceptor::from(config.clone());
        let mut inbound = acceptor
            .accept(inbound)
            .await
            .with_context(|| format!("accept TLS for service {}", service.id))?;
        tracing::info!(service_id = %service.id, "accepted Medium TLS for service");

        if service.tls_mode == ServiceTlsMode::Raw {
            let mut outbound = TcpStream::connect(&service.target).await.with_context(|| {
                format!("connect service {} target {}", service.id, service.target)
            })?;
            tracing::info!(
                service_id = %service.id,
                target = %service.target,
                "connected raw TLS-wrapped service target"
            );
            let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
            tracing::info!(service_id = %service.id, "finished raw TLS-wrapped service proxy");
            return Ok(());
        }

        let request = read_http_request_for_proxy(&mut inbound, service).await?;
        let mut outbound = match TcpStream::connect(&service.target).await {
            Ok(outbound) => outbound,
            Err(error) => {
                tracing::warn!(
                    service_id = %service.id,
                    target = %service.target,
                    %error,
                    "service target unavailable after Medium TLS accept"
                );
                write_service_unavailable_response(&mut inbound, service, &error).await?;
                return Ok(());
            }
        };
        tracing::info!(service_id = %service.id, target = %service.target, "connected HTTP service target");
        if let Err(error) = outbound.write_all(&request).await {
            tracing::warn!(
                service_id = %service.id,
                target = %service.target,
                %error,
                "failed to write HTTP request to service target"
            );
            write_service_closed_response(&mut inbound, service, &error.to_string()).await?;
            return Ok(());
        }
        outbound.flush().await?;
        if !forward_first_http_response_chunk(&mut outbound, &mut inbound, service).await? {
            return Ok(());
        }
        let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
        tracing::info!(service_id = %service.id, "finished TLS-terminated service proxy");
        return Ok(());
    }

    let mut outbound = TcpStream::connect(&service.target)
        .await
        .with_context(|| format!("connect service {} target {}", service.id, service.target))?;
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn read_http_request_for_proxy<R>(
    reader: &mut R,
    service: &ProxyService,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let size = reader.read(&mut chunk).await?;
            if size == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..size]);
            if complete_http_request(&buffer) {
                break;
            }
            if buffer.len() > 64 * 1024 {
                break;
            }
        }
        anyhow::Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            tracing::info!(
                service_id = %service.id,
                bytes = buffer.len(),
                "read HTTP request before proxying to service target"
            );
            Ok(buffer)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => {
            anyhow::bail!(
                "timed out waiting for HTTP request for service {}",
                service.id
            )
        }
    }
}

async fn forward_first_http_response_chunk<R, W>(
    reader: &mut R,
    writer: &mut W,
    service: &ProxyService,
) -> anyhow::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let size =
        match tokio::time::timeout(std::time::Duration::from_secs(12), reader.read(&mut buffer))
            .await
        {
            Ok(Ok(size)) => size,
            Ok(Err(error)) => {
                tracing::warn!(
                    service_id = %service.id,
                    target = %service.target,
                    %error,
                    "failed to read first HTTP response chunk from service target"
                );
                write_service_closed_response(writer, service, &error.to_string()).await?;
                return Ok(false);
            }
            Err(_) => {
                tracing::warn!(
                    service_id = %service.id,
                    target = %service.target,
                    "timed out waiting for first HTTP response chunk from service target"
                );
                write_service_timeout_response(writer, service).await?;
                return Ok(false);
            }
        };

    if size == 0 {
        tracing::warn!(
            service_id = %service.id,
            target = %service.target,
            "service target closed before returning a response"
        );
        write_service_closed_response(
            writer,
            service,
            "service target closed before returning a response",
        )
        .await?;
        return Ok(false);
    }

    writer.write_all(&buffer[..size]).await?;
    writer.flush().await?;
    tracing::info!(
        service_id = %service.id,
        target = %service.target,
        bytes = size,
        "forwarded first HTTP response chunk from service target"
    );
    Ok(true)
}

fn complete_http_request(data: &[u8]) -> bool {
    let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = &data[..header_end];
    let body_start = header_end + 4;
    let Ok(headers) = std::str::from_utf8(headers) else {
        return true;
    };
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    match content_length {
        Some(length) => data.len().saturating_sub(body_start) >= length,
        None => true,
    }
}

async fn write_service_unavailable_response<W>(
    writer: &mut W,
    service: &ProxyService,
    error: &std::io::Error,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_http_error_response(
        writer,
        service,
        "502 Bad Gateway",
        format!(
            "Medium service target unavailable\n\nservice: {}\ntarget: {}\nerror: {}\n",
            service.id, service.target, error
        ),
        "sent Medium service unavailable response",
    )
    .await
}

async fn write_service_closed_response<W>(
    writer: &mut W,
    service: &ProxyService,
    error: &str,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_http_error_response(
        writer,
        service,
        "502 Bad Gateway",
        format!(
            "Medium service target closed before returning a response\n\nservice: {}\ntarget: {}\nerror: {}\n",
            service.id, service.target, error
        ),
        "sent Medium service closed response",
    )
    .await
}

async fn write_service_timeout_response<W>(
    writer: &mut W,
    service: &ProxyService,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_http_error_response(
        writer,
        service,
        "504 Gateway Timeout",
        format!(
            "Medium service target did not return a response in time\n\nservice: {}\ntarget: {}\n",
            service.id, service.target
        ),
        "sent Medium service timeout response",
    )
    .await
}

async fn write_http_error_response<W>(
    writer: &mut W,
    service: &ProxyService,
    status: &str,
    body: String,
    log_message: &'static str,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;
    tracing::info!(
        service_id = %service.id,
        target = %service.target,
        bytes = response.len(),
        log_message
    );
    writer.shutdown().await?;
    Ok(())
}

fn server_tls_config_from_pem(cert_pem: &str, key_pem: &str) -> anyhow::Result<ServerConfig> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("missing service TLS private key"))?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Ok(ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            certs.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::from(key),
        )?)
}

fn service_hostname(service: &crate::config::ServiceConfig) -> String {
    let label = service.label.as_deref().unwrap_or(&service.id);
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

async fn read_wss_session_hello<S>(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
) -> anyhow::Result<(SessionHello, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    while let Some(message) = ws_rx.next().await {
        match message? {
            Message::Binary(frame) => {
                payload.extend_from_slice(&frame);
                if let Some(newline_index) = payload.iter().position(|byte| *byte == b'\n') {
                    let remaining = payload.split_off(newline_index + 1);
                    payload.pop();
                    if payload.is_empty() {
                        anyhow::bail!("missing session hello");
                    }
                    let hello = serde_json::from_slice(&payload)?;
                    return Ok((hello, remaining));
                }
                if payload.len() > 16 * 1024 {
                    anyhow::bail!("session hello too large");
                }
            }
            Message::Close(_) => anyhow::bail!("websocket closed before session hello"),
            _ => {}
        }
    }

    anyhow::bail!("missing session hello")
}

#[cfg(test)]
mod tests {
    use super::*;
    use overlay_crypto::{issue_medium_service_ca, issue_session_token};
    use overlay_transport::session::read_relay_hello;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn tcp_relay_connector_does_not_advertise_before_services_are_ready() {
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let cfg: NodeConfig = toml::from_str(&format!(
            r#"
node_id = "node-1"
bind_addr = "127.0.0.1:0"

[[services]]
id = "svc_ssh"
kind = "ssh"
target = "127.0.0.1:22"
"#
        ))
        .unwrap();

        spawn_relay_connectors(&cfg, "relay-secret", &relay_addr.to_string());

        let advertised =
            tokio::time::timeout(std::time::Duration::from_millis(300), relay.accept()).await;
        assert!(
            advertised.is_err(),
            "node advertised a relay socket before service TLS config was ready"
        );
    }

    #[tokio::test]
    async fn tcp_relay_path_completes_medium_tls_for_ssh_service() -> anyhow::Result<()> {
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

        let (relay_shutdown_tx, relay_shutdown_rx) = oneshot::channel();
        let (relay_addr_tx, relay_addr_rx) = oneshot::channel();
        let relay_task = tokio::spawn(async move {
            relay::run_tcp_relay_with_shutdown(
                "127.0.0.1:0",
                Some("relay-secret".into()),
                relay_shutdown_rx,
                Some(relay_addr_tx),
            )
            .await
            .unwrap();
        });
        let relay_addr = relay_addr_rx.await?;

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
        let services = proxy_services_from_config(&cfg, "relay-secret").await?;
        let connector_cfg = cfg.clone();
        let relay_addr = relay_addr.to_string();
        let connector_relay_addr = relay_addr.clone();
        let connector = tokio::spawn(async move {
            connect_relay_once(
                &connector_cfg,
                "relay-secret",
                &connector_relay_addr,
                services,
            )
            .await
        });

        let mut client = TcpStream::connect(&relay_addr).await?;
        write_relay_hello(
            &mut client,
            &RelayHello::Client {
                node_id: "node-1".into(),
            },
        )
        .await?;
        overlay_transport::session::write_session_hello(
            &mut client,
            &SessionHello {
                token: issue_session_token("relay-secret", "sess-relay-ssh", "svc_ssh", "node-1")?,
                service_id: "svc_ssh".into(),
                transport: None,
            },
        )
        .await?;

        let connector_tls = TlsConnector::from(Arc::new(client_tls_config(&ca.cert_pem)?));
        let server_name = ServerName::try_from("svc-ssh.medium")?;
        let mut tls = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connector_tls.connect(server_name, client),
        )
        .await??;
        tls.write_all(b"SSH-2.0-MediumClient\r\n").await?;
        let mut reader = BufReader::new(tls);
        let mut target_banner = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut target_banner),
        )
        .await??;
        assert_eq!(target_banner, "SSH-2.0-MediumTarget\r\n");
        drop(reader);

        let _ = relay_shutdown_tx.send(());
        target_task.await?;
        connector.abort();
        let _ = connector.await;
        relay_task.await?;
        Ok(())
    }

    #[tokio::test]
    async fn tcp_relay_connector_closes_idle_socket_after_lease() -> anyhow::Result<()> {
        let ca = issue_medium_service_ca()?;
        let relay = TcpListener::bind("127.0.0.1:0").await?;
        let relay_addr = relay.local_addr()?;
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
target = "127.0.0.1:22"
"#,
            cert = ca.cert_pem,
            key = ca.key_pem,
        ))?;
        let services = proxy_services_from_config(&cfg, "relay-secret").await?;
        let connector = tokio::spawn(async move {
            connect_relay_once_with_idle_timeout(
                &cfg,
                "relay-secret",
                &relay_addr.to_string(),
                services,
                std::time::Duration::from_millis(50),
            )
            .await
        });

        let (mut node_socket, _) = relay.accept().await?;
        assert_eq!(
            read_relay_hello(&mut node_socket).await?,
            RelayHello::Node {
                node_id: "node-1".into(),
                shared_secret: "relay-secret".into(),
            }
        );
        let mut buffer = [0_u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            node_socket.read(&mut buffer),
        )
        .await??;
        assert_eq!(read, 0, "idle relay node socket stayed open past lease");

        let result = connector.await?;
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("idle lease expired"),
            "unexpected connector error: {error:#}"
        );
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
}
