use anyhow::Context;
use overlay_protocol::{
    CandidateKind, IceCandidate, IceCandidateKind, PeerCandidate, SessionOpenGrant,
};
use overlay_transport::pinned_http::pinned_tls_client_config;
use overlay_transport::session::{RelayHello, SessionHello};
use overlay_transport::udp_rendezvous::resolve_peer;
use overlay_transport::udp_session::UdpSessionStream;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Message, WebSocket};
use url::Url;

const CANDIDATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const UDP_CONNECTED_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_TLS_CANDIDATE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const SERVICE_TLS_DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Auto,
    RelayOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedPath {
    pub kind: String,
    pub addr: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectOptions<'a> {
    pub mode: TransportMode,
    pub control_pin: Option<&'a str>,
    pub preferred_ice: Option<&'a IceCandidate>,
}

impl Default for ConnectOptions<'_> {
    fn default() -> Self {
        Self {
            mode: TransportMode::Auto,
            control_pin: None,
            preferred_ice: None,
        }
    }
}

pub struct ConnectedSession {
    pub stream: MediumSessionStream,
    pub path: SelectedPath,
}

pub struct ConnectedTlsSession {
    pub stream: StreamOwned<ClientConnection, MediumSessionStream>,
    pub path: SelectedPath,
}

pub enum MediumSessionStream {
    Tcp(TcpStream),
    Udp(Box<UdpSessionStream>),
    Wss(Box<WssByteStream>),
}

impl MediumSessionStream {
    pub fn set_io_timeout(&mut self, timeout: Option<Duration>) -> anyhow::Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)?;
            }
            Self::Udp(stream) => {
                stream.set_poll_timeout(timeout.unwrap_or(UDP_CONNECTED_POLL_TIMEOUT))?;
            }
            Self::Wss(stream) => stream.set_io_timeout(timeout)?,
        }
        Ok(())
    }
}

pub struct WssByteStream {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    pending_read: Vec<u8>,
}

impl WssByteStream {
    pub fn set_io_timeout(&mut self, timeout: Option<Duration>) -> anyhow::Result<()> {
        match self.socket.get_mut() {
            MaybeTlsStream::Plain(stream) => {
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)?;
            }
            MaybeTlsStream::Rustls(stream) => {
                stream.get_mut().set_read_timeout(timeout)?;
                stream.get_mut().set_write_timeout(timeout)?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Read for MediumSessionStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Udp(stream) => stream.read(buffer),
            Self::Wss(stream) => stream.read(buffer),
        }
    }
}

impl Write for MediumSessionStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            Self::Udp(stream) => stream.write(bytes),
            Self::Wss(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Udp(stream) => stream.flush(),
            Self::Wss(stream) => stream.flush(),
        }
    }
}

impl Read for WssByteStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.pending_read.is_empty() {
            let size = buffer.len().min(self.pending_read.len());
            buffer[..size].copy_from_slice(&self.pending_read[..size]);
            self.pending_read.drain(..size);
            return Ok(size);
        }

        loop {
            match self.socket.read().map_err(std::io::Error::other)? {
                Message::Binary(bytes) => {
                    let size = buffer.len().min(bytes.len());
                    buffer[..size].copy_from_slice(&bytes[..size]);
                    if size < bytes.len() {
                        self.pending_read.extend_from_slice(&bytes[size..]);
                    }
                    return Ok(size);
                }
                Message::Text(text) => {
                    let bytes = text.as_bytes();
                    let size = buffer.len().min(bytes.len());
                    buffer[..size].copy_from_slice(&bytes[..size]);
                    if size < bytes.len() {
                        self.pending_read.extend_from_slice(&bytes[size..]);
                    }
                    return Ok(size);
                }
                Message::Close(_) => return Ok(0),
                Message::Ping(payload) => {
                    self.socket
                        .send(Message::Pong(payload))
                        .map_err(std::io::Error::other)?;
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }
}

impl Write for WssByteStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket
            .send(Message::Binary(bytes.to_vec().into()))
            .map_err(std::io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush().map_err(std::io::Error::other)
    }
}

pub fn connect_session(
    grant: &SessionOpenGrant,
    options: ConnectOptions<'_>,
) -> anyhow::Result<ConnectedSession> {
    if options.mode == TransportMode::Auto {
        if let Some(connected) = try_connect_ice_udp(grant, options.preferred_ice)? {
            return Ok(connected);
        }
    }

    connect_legacy_candidate(grant, &options)
}

pub fn connect_service_tls(
    connected: ConnectedSession,
    server_name: &str,
    service_ca_pem: &str,
) -> anyhow::Result<ConnectedTlsSession> {
    connect_service_tls_with_timeout(
        connected,
        server_name,
        service_ca_pem,
        SERVICE_TLS_DEFAULT_HANDSHAKE_TIMEOUT,
    )
}

fn connect_service_tls_with_timeout(
    mut connected: ConnectedSession,
    server_name: &str,
    service_ca_pem: &str,
    handshake_timeout: Duration,
) -> anyhow::Result<ConnectedTlsSession> {
    let path = connected.path.clone();
    let server_name_text = server_name.to_string();
    connected
        .stream
        .set_io_timeout(Some(Duration::from_millis(100)))?;
    let config = service_tls_client_config(service_ca_pem)?;
    let server_name = ServerName::try_from(server_name.to_string())
        .with_context(|| format!("invalid Medium service TLS server name {server_name}"))?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .context("create Medium service TLS client")?;
    let mut stream = StreamOwned::new(connection, connected.stream);
    let deadline = std::time::Instant::now() + handshake_timeout;
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if is_timeout(&error) && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if is_timeout(&error) => {
                anyhow::bail!(
                    "Medium service TLS handshake timed out after {:?} for {} via {} {}: {}",
                    handshake_timeout,
                    server_name_text,
                    path.kind,
                    path.addr,
                    error
                );
            }
            Err(error) => {
                anyhow::bail!(
                    "Medium service TLS handshake failed for {} via {} {}: {}",
                    server_name_text,
                    path.kind,
                    path.addr,
                    error
                );
            }
        }
    }

    Ok(ConnectedTlsSession { stream, path })
}

pub fn connect_session_service_tls(
    grant: &SessionOpenGrant,
    options: ConnectOptions<'_>,
    server_name: &str,
    service_ca_pem: &str,
    attempts: usize,
    retry_delay: Duration,
) -> anyhow::Result<ConnectedTlsSession> {
    let attempts = attempts.max(1);
    let mut failures = Vec::new();
    if options.mode == TransportMode::Auto {
        for candidate in ice_checklist(grant, options.preferred_ice) {
            let addr = ice_candidate_addr(&candidate);
            if is_unusable_backend_candidate_addr(&addr) {
                continue;
            }
            match connect_ice_udp_session_candidate(grant, &candidate).and_then(|connected| {
                connect_service_tls_with_timeout(
                    connected,
                    server_name,
                    service_ca_pem,
                    SERVICE_TLS_CANDIDATE_HANDSHAKE_TIMEOUT,
                )
            }) {
                Ok(connected) => return Ok(connected),
                Err(error) => record_candidate_failure(
                    &mut failures,
                    format!("ice_udp/{} {}", candidate.kind.as_str(), addr),
                    1,
                    &error,
                ),
            }
        }
    }

    let candidates = ordered_legacy_candidates_for_mode(grant, options.mode);
    for candidate in candidates {
        let label = format!("{} {}", candidate.kind.as_str(), candidate.addr);
        for attempt in 1..=attempts {
            match connect_legacy_session_candidate(grant, options.control_pin, &candidate).and_then(
                |connected| {
                    connect_service_tls_with_timeout(
                        connected,
                        server_name,
                        service_ca_pem,
                        SERVICE_TLS_CANDIDATE_HANDSHAKE_TIMEOUT,
                    )
                },
            ) {
                Ok(connected) => return Ok(connected),
                Err(error) => {
                    record_candidate_failure(&mut failures, label.clone(), attempt, &error);
                    if attempt < attempts {
                        std::thread::sleep(retry_delay);
                    }
                }
            }
        }
    }

    let error = if failures.is_empty() {
        if options.mode == TransportMode::RelayOnly {
            "session grant has no relay candidates".to_string()
        } else {
            "session grant has no usable candidates".to_string()
        }
    } else {
        failures.join("; ")
    };
    anyhow::bail!(
        "Medium end-to-end service connection failed after up to {} attempt(s) per candidate for {} on node {}: {}",
        attempts,
        server_name,
        grant.node_id,
        error
    )
}

pub fn ordered_legacy_candidates_for_mode(
    grant: &SessionOpenGrant,
    mode: TransportMode,
) -> Vec<PeerCandidate> {
    let mut candidates = grant.authorization.candidates.clone();
    if mode == TransportMode::RelayOnly {
        candidates.retain(|candidate| {
            matches!(
                candidate.kind,
                CandidateKind::RelayTcp | CandidateKind::WssRelay
            )
        });
    }
    candidates.sort_by(|left, right| right.priority.cmp(&left.priority));
    candidates
}

pub fn ice_checklist(
    grant: &SessionOpenGrant,
    preferred: Option<&IceCandidate>,
) -> Vec<IceCandidate> {
    let Some(ice) = &grant.authorization.ice else {
        return Vec::new();
    };
    let mut candidates = ice
        .candidates
        .iter()
        .filter(|candidate| candidate.transport.eq_ignore_ascii_case("udp"))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        candidate_preference_rank(left, preferred)
            .cmp(&candidate_preference_rank(right, preferred))
            .then_with(|| {
                ice_kind_rank(left.kind)
                    .cmp(&ice_kind_rank(right.kind))
                    .then_with(|| right.priority.cmp(&left.priority))
                    .then_with(|| left.foundation.cmp(&right.foundation))
            })
    });
    candidates
}

fn try_connect_ice_udp(
    grant: &SessionOpenGrant,
    preferred_ice: Option<&IceCandidate>,
) -> anyhow::Result<Option<ConnectedSession>> {
    let mut last_error = None;
    for candidate in ice_checklist(grant, preferred_ice) {
        let addr = ice_candidate_addr(&candidate);
        if is_unusable_backend_candidate_addr(&addr) {
            continue;
        }
        match connect_ice_udp_session_candidate(grant, &candidate) {
            Ok(connected) => return Ok(Some(connected)),
            Err(error) => last_error = Some(error),
        }
    }

    if let Some(error) = last_error {
        tracing::warn!(%error, "all ICE UDP candidates failed; falling back to legacy candidates");
    }
    Ok(None)
}

fn record_candidate_failure(
    failures: &mut Vec<String>,
    candidate: String,
    attempt: usize,
    error: &anyhow::Error,
) {
    tracing::warn!(
        %candidate,
        attempt,
        %error,
        "Medium service candidate failed"
    );
    failures.push(format!("{candidate} attempt {attempt}: {error}"));
}

fn connect_ice_udp_session_candidate(
    grant: &SessionOpenGrant,
    candidate: &IceCandidate,
) -> anyhow::Result<ConnectedSession> {
    let addr = ice_candidate_addr(candidate);
    let stream = match candidate.kind {
        IceCandidateKind::Relay => connect_ice_udp_via_rendezvous(grant, &addr),
        IceCandidateKind::Host | IceCandidateKind::Srflx => connect_ice_udp_candidate(grant, &addr),
    }?;
    stream.set_poll_timeout(UDP_CONNECTED_POLL_TIMEOUT)?;
    Ok(ConnectedSession {
        stream: MediumSessionStream::Udp(Box::new(stream)),
        path: SelectedPath {
            kind: format!("ice_udp/{}", candidate.kind.as_str()),
            addr,
        },
    })
}

fn connect_legacy_candidate(
    grant: &SessionOpenGrant,
    options: &ConnectOptions<'_>,
) -> anyhow::Result<ConnectedSession> {
    let mut last_error = None;
    for candidate in ordered_legacy_candidates_for_mode(grant, options.mode) {
        if is_unusable_backend_candidate_addr(&candidate.addr) {
            continue;
        }
        match connect_legacy_session_candidate(grant, options.control_pin, &candidate) {
            Ok(connected) => return Ok(connected),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        if options.mode == TransportMode::RelayOnly {
            anyhow::anyhow!("session grant has no relay candidates")
        } else {
            anyhow::anyhow!("session grant has no candidates")
        }
    }))
}

fn connect_legacy_session_candidate(
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
    candidate: &PeerCandidate,
) -> anyhow::Result<ConnectedSession> {
    let stream = connect_session_candidate(grant, control_pin, candidate)?;
    Ok(ConnectedSession {
        stream,
        path: SelectedPath {
            kind: candidate.kind.as_str().to_string(),
            addr: candidate.addr.clone(),
        },
    })
}

fn connect_session_candidate(
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
    candidate: &PeerCandidate,
) -> anyhow::Result<MediumSessionStream> {
    match candidate.kind {
        CandidateKind::DirectTcp => {
            let mut stream = connect_tcp(&candidate.addr)?;
            write_session_hello(&mut stream, grant)?;
            Ok(MediumSessionStream::Tcp(stream))
        }
        CandidateKind::RelayTcp => {
            let mut stream = connect_tcp(&candidate.addr)?;
            write_json_line(
                &mut stream,
                &RelayHello::Client {
                    node_id: grant.node_id.clone(),
                },
            )?;
            write_session_hello(&mut stream, grant)?;
            Ok(MediumSessionStream::Tcp(stream))
        }
        CandidateKind::WssRelay => {
            let socket = connect_wss_relay(&candidate.addr, grant, control_pin)?;
            Ok(MediumSessionStream::Wss(Box::new(WssByteStream {
                socket,
                pending_read: Vec::new(),
            })))
        }
    }
}

fn connect_ice_udp_via_rendezvous(
    grant: &SessionOpenGrant,
    relay_addr: &str,
) -> anyhow::Result<UdpSessionStream> {
    let mut last_error = None;
    for socket_addr in relay_addr.to_socket_addrs()? {
        match create_udp_socket(socket_addr) {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_millis(500)))?;
                socket.set_write_timeout(Some(Duration::from_millis(500)))?;
                let peer_addr = resolve_peer(
                    &socket,
                    socket_addr,
                    &grant.node_id,
                    &grant.authorization.token,
                )?;
                return UdpSessionStream::connect(
                    socket,
                    peer_addr,
                    SessionHello {
                        token: grant.authorization.token.clone(),
                        service_id: grant.service_id.clone(),
                        transport: None,
                    },
                );
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no socket addresses for {relay_addr}")))
}

fn connect_ice_udp_candidate(
    grant: &SessionOpenGrant,
    addr: &str,
) -> anyhow::Result<UdpSessionStream> {
    let mut last_error = None;
    for socket_addr in addr.to_socket_addrs()? {
        match create_udp_socket(socket_addr) {
            Ok(socket) => {
                return UdpSessionStream::connect(
                    socket,
                    socket_addr,
                    SessionHello {
                        token: grant.authorization.token.clone(),
                        service_id: grant.service_id.clone(),
                        transport: None,
                    },
                );
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no socket addresses for {addr}")))
}

fn create_udp_socket(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let bind_addr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>()?,
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>()?,
    };
    Ok(UdpSocket::bind(bind_addr)?)
}

fn connect_tcp(addr: &str) -> anyhow::Result<TcpStream> {
    let mut last_error = None;
    for socket_addr in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket_addr, CANDIDATE_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no socket addresses for {addr}")))
}

fn connect_wss_relay(
    relay_url: &str,
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
) -> anyhow::Result<WebSocket<MaybeTlsStream<TcpStream>>> {
    let addr = websocket_tcp_addr(relay_url)?;
    let stream = connect_tcp(&addr)?;
    let connector = match control_pin {
        Some(control_pin) => Some(Connector::Rustls(Arc::new(pinned_tls_client_config(
            control_pin,
        )?))),
        None => None,
    };
    let (mut socket, _) = tungstenite::client_tls_with_config(relay_url, stream, None, connector)?;
    socket.send(Message::Text(
        serde_json::to_string(&RelayHello::Client {
            node_id: grant.node_id.clone(),
        })?
        .into(),
    ))?;
    socket.send(Message::Binary(session_hello_frame(grant)?.into()))?;
    Ok(socket)
}

fn websocket_tcp_addr(relay_url: &str) -> anyhow::Result<String> {
    let url = Url::parse(relay_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("wss relay URL is missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("wss relay URL is missing port"))?;
    Ok(format!("{host}:{port}"))
}

fn write_session_hello(stream: &mut TcpStream, grant: &SessionOpenGrant) -> anyhow::Result<()> {
    write_json_line(
        stream,
        &SessionHello {
            token: grant.authorization.token.clone(),
            service_id: grant.service_id.clone(),
            transport: None,
        },
    )
}

fn session_hello_frame(grant: &SessionOpenGrant) -> anyhow::Result<Vec<u8>> {
    let mut payload = serde_json::to_vec(&SessionHello {
        token: grant.authorization.token.clone(),
        service_id: grant.service_id.clone(),
        transport: None,
    })?;
    payload.push(b'\n');
    Ok(payload)
}

fn write_json_line<T: serde::Serialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<()> {
    let mut payload = serde_json::to_vec(value)?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn service_tls_client_config(service_ca_pem: &str) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(service_ca_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("Medium service CA PEM does not contain a certificate");
    }
    for cert in certs {
        roots.add(cert)?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn ice_candidate_addr(candidate: &IceCandidate) -> String {
    match candidate.addr.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", candidate.addr, candidate.port),
        _ => format!("{}:{}", candidate.addr, candidate.port),
    }
}

fn candidate_preference_rank(candidate: &IceCandidate, preferred: Option<&IceCandidate>) -> u8 {
    if preferred.is_some_and(|preferred| same_ice_candidate(candidate, preferred)) {
        0
    } else {
        1
    }
}

fn same_ice_candidate(left: &IceCandidate, right: &IceCandidate) -> bool {
    left.transport.eq_ignore_ascii_case(&right.transport)
        && left.kind == right.kind
        && left.addr == right.addr
        && left.port == right.port
}

fn ice_kind_rank(kind: IceCandidateKind) -> u8 {
    match kind {
        IceCandidateKind::Host => 0,
        IceCandidateKind::Srflx => 1,
        IceCandidateKind::Relay => 2,
    }
}

fn is_unusable_backend_candidate_addr(addr: &str) -> bool {
    let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    match socket_addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_unspecified()
                || ip.is_loopback()
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback(),
    }
}

fn is_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use super::*;
    use overlay_protocol::{CandidateKind, IceCandidateKind};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn relay_only_legacy_candidates_exclude_direct_tcp() {
        let grant: SessionOpenGrant = serde_json::from_str(
            r#"{"session_id":"session-1","service_id":"svc_ssh","node_id":"node-1","relay_hint":"127.0.0.1:7001","authorization":{"token":"token","expires_at":"2099-01-01T00:00:00Z","candidates":[{"kind":"direct_tcp","addr":"192.168.1.10:17001","priority":100},{"kind":"relay_tcp","addr":"203.0.113.10:7001","priority":10},{"kind":"wss_relay","addr":"wss://relay.example.com/medium/v1/relay","priority":5}]}}"#,
        )
        .unwrap();

        let kinds = ordered_legacy_candidates_for_mode(&grant, TransportMode::RelayOnly)
            .into_iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![CandidateKind::RelayTcp, CandidateKind::WssRelay]
        );
    }

    #[test]
    fn ice_checklist_orders_host_then_srflx_then_relay() {
        let grant: SessionOpenGrant = serde_json::from_str(
            r#"{"session_id":"session-1","service_id":"svc_ssh","node_id":"node-1","relay_hint":"127.0.0.1:7001","authorization":{"token":"token","expires_at":"2099-01-01T00:00:00Z","candidates":[],"ice":{"credentials":{"ufrag":"u","pwd":"p","expires_at":"2099-01-01T00:00:00Z"},"candidates":[{"foundation":"relay-1","component":1,"transport":"udp","priority":300,"addr":"203.0.113.10","port":3478,"kind":"relay","related_addr":null,"related_port":null},{"foundation":"srflx-1","component":1,"transport":"udp","priority":200,"addr":"198.51.100.20","port":17002,"kind":"srflx","related_addr":null,"related_port":null},{"foundation":"host-1","component":1,"transport":"udp","priority":100,"addr":"192.168.1.10","port":17002,"kind":"host","related_addr":null,"related_port":null}]}}}"#,
        )
        .unwrap();

        let kinds = ice_checklist(&grant, None)
            .into_iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![
                IceCandidateKind::Host,
                IceCandidateKind::Srflx,
                IceCandidateKind::Relay
            ]
        );
    }

    #[test]
    fn ice_checklist_uses_preferred_candidate_first() {
        let grant: SessionOpenGrant = serde_json::from_str(
            r#"{"session_id":"session-1","service_id":"svc_ssh","node_id":"node-1","relay_hint":"127.0.0.1:7001","authorization":{"token":"token","expires_at":"2099-01-01T00:00:00Z","candidates":[],"ice":{"credentials":{"ufrag":"u","pwd":"p","expires_at":"2099-01-01T00:00:00Z"},"candidates":[{"foundation":"relay-1","component":1,"transport":"udp","priority":300,"addr":"203.0.113.10","port":3478,"kind":"relay","related_addr":null,"related_port":null},{"foundation":"host-1","component":1,"transport":"udp","priority":100,"addr":"192.168.1.10","port":17002,"kind":"host","related_addr":null,"related_port":null}]}}}"#,
        )
        .unwrap();
        let preferred = grant.authorization.ice.as_ref().unwrap().candidates[0].clone();

        let candidates = ice_checklist(&grant, Some(&preferred));

        assert_eq!(candidates[0].kind, IceCandidateKind::Relay);
        assert_eq!(candidates[0].addr, "203.0.113.10");
    }

    #[test]
    fn relay_tls_retry_reconnects_after_first_relay_socket_closes() -> anyhow::Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = overlay_crypto::issue_medium_service_ca()?;
        let identity = overlay_crypto::issue_service_tls_identity(
            &ca.cert_pem,
            &ca.key_pem,
            &["svc-ssh.medium".to_string()],
        )?;
        let server_config = Arc::new(server_tls_config(&identity.cert_pem, &identity.key_pem)?);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let relay_addr = format!("localhost:{}", listener.local_addr()?.port());
        let server = thread::spawn(move || -> anyhow::Result<()> {
            let (mut first, _) = listener.accept()?;
            read_json_line(&mut first)?;
            read_json_line(&mut first)?;
            drop(first);

            let (mut second, _) = listener.accept()?;
            read_json_line(&mut second)?;
            read_json_line(&mut second)?;
            let connection = ServerConnection::new(server_config)?;
            let mut tls = StreamOwned::new(connection, second);
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock)?;
            }
            tls.write_all(b"ok")?;
            tls.flush()?;
            Ok(())
        });
        let grant: SessionOpenGrant = serde_json::from_str(&format!(
            r#"{{
              "session_id":"session-1",
              "service_id":"svc_ssh",
              "node_id":"node-1",
              "relay_hint":"{relay_addr}",
              "authorization":{{
                "token":"token",
                "expires_at":"2099-01-01T00:00:00Z",
                "candidates":[{{"kind":"relay_tcp","addr":"{relay_addr}","priority":10}}]
              }}
            }}"#,
        ))?;

        let mut connected = connect_session_service_tls(
            &grant,
            ConnectOptions {
                mode: TransportMode::RelayOnly,
                control_pin: None,
                preferred_ice: None,
            },
            "svc-ssh.medium",
            &ca.cert_pem,
            2,
            Duration::from_millis(1),
        )?;
        let mut buffer = [0_u8; 2];
        connected.stream.read_exact(&mut buffer)?;

        assert_eq!(&buffer, b"ok");
        server.join().expect("relay server thread panicked")?;
        Ok(())
    }

    #[test]
    fn relay_tls_falls_back_to_wss_relay_after_tcp_relay_tls_failure() -> anyhow::Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = overlay_crypto::issue_medium_service_ca()?;
        let identity = overlay_crypto::issue_service_tls_identity(
            &ca.cert_pem,
            &ca.key_pem,
            &["svc-ssh.medium".to_string()],
        )?;
        let server_config = Arc::new(server_tls_config(&identity.cert_pem, &identity.key_pem)?);
        let tcp_listener = TcpListener::bind("127.0.0.1:0")?;
        let tcp_relay_addr = format!("localhost:{}", tcp_listener.local_addr()?.port());
        let ws_listener = TcpListener::bind("127.0.0.1:0")?;
        let ws_relay_url = format!(
            "ws://localhost:{}/medium/v1/relay",
            ws_listener.local_addr()?.port()
        );
        let tcp_server = thread::spawn(move || -> anyhow::Result<()> {
            let (mut stream, _) = tcp_listener.accept()?;
            read_json_line(&mut stream)?;
            read_json_line(&mut stream)?;
            Ok(())
        });
        let wss_server = thread::spawn(move || -> anyhow::Result<()> {
            let (stream, _) = ws_listener.accept()?;
            let mut ws = tungstenite::accept(stream)?;
            match ws.read()? {
                Message::Text(_) => {}
                other => anyhow::bail!("expected relay hello text frame, got {other:?}"),
            }
            match ws.read()? {
                Message::Binary(frame) => {
                    if !frame.ends_with(b"\n") {
                        anyhow::bail!("session hello frame is missing newline");
                    }
                }
                other => anyhow::bail!("expected session hello binary frame, got {other:?}"),
            }
            let connection = ServerConnection::new(server_config)?;
            let mut tls = StreamOwned::new(connection, ServerWssByteStream::new(ws));
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock)?;
            }
            tls.write_all(b"ok")?;
            tls.flush()?;
            Ok(())
        });
        let grant: SessionOpenGrant = serde_json::from_str(&format!(
            r#"{{
              "session_id":"session-1",
              "service_id":"svc_ssh",
              "node_id":"node-1",
              "relay_hint":"{tcp_relay_addr}",
              "authorization":{{
                "token":"token",
                "expires_at":"2099-01-01T00:00:00Z",
                "candidates":[
                  {{"kind":"relay_tcp","addr":"{tcp_relay_addr}","priority":20}},
                  {{"kind":"wss_relay","addr":"{ws_relay_url}","priority":10}}
                ]
              }}
            }}"#,
        ))?;

        let mut connected = connect_session_service_tls(
            &grant,
            ConnectOptions {
                mode: TransportMode::RelayOnly,
                control_pin: None,
                preferred_ice: None,
            },
            "svc-ssh.medium",
            &ca.cert_pem,
            1,
            Duration::from_millis(1),
        )?;
        let mut buffer = [0_u8; 2];
        connected.stream.read_exact(&mut buffer)?;

        assert_eq!(&buffer, b"ok");
        assert_eq!(connected.path.kind, "wss_relay");
        tcp_server.join().expect("tcp relay thread panicked")?;
        wss_server.join().expect("wss relay thread panicked")?;
        Ok(())
    }

    fn read_json_line(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        Ok(line)
    }

    fn server_tls_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<ServerConfig> {
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

    struct ServerWssByteStream {
        socket: WebSocket<TcpStream>,
        pending_read: Vec<u8>,
    }

    impl ServerWssByteStream {
        fn new(socket: WebSocket<TcpStream>) -> Self {
            Self {
                socket,
                pending_read: Vec::new(),
            }
        }
    }

    impl Read for ServerWssByteStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.pending_read.is_empty() {
                let size = buffer.len().min(self.pending_read.len());
                buffer[..size].copy_from_slice(&self.pending_read[..size]);
                self.pending_read.drain(..size);
                return Ok(size);
            }

            loop {
                match self.socket.read().map_err(std::io::Error::other)? {
                    Message::Binary(bytes) => {
                        let size = buffer.len().min(bytes.len());
                        buffer[..size].copy_from_slice(&bytes[..size]);
                        if size < bytes.len() {
                            self.pending_read.extend_from_slice(&bytes[size..]);
                        }
                        return Ok(size);
                    }
                    Message::Close(_) => return Ok(0),
                    Message::Ping(payload) => {
                        self.socket
                            .send(Message::Pong(payload))
                            .map_err(std::io::Error::other)?;
                    }
                    Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        }
    }

    impl Write for ServerWssByteStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.socket
                .send(Message::Binary(bytes.to_vec().into()))
                .map_err(std::io::Error::other)?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.socket.flush().map_err(std::io::Error::other)
        }
    }
}
