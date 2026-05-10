use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong};
use log::{LevelFilter, debug, error, info};
use medium_netstack::{PublishedService, VirtualNetwork, stack::MediumStack, tcp::TcpPumpEvent};
use overlay_protocol::{
    CandidateKind, IceCandidate, IceCandidateKind, PeerCandidate, SessionOpenGrant,
};
use overlay_transport::p2p_diag;
use overlay_transport::session::SessionHello;
use overlay_transport::udp_rendezvous::resolve_peer;
use overlay_transport::udp_session::UdpSessionStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Message, WebSocket};
use url::Url;

static LOGGER: Once = Once::new();
const CANDIDATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IDLE_BACKENDS_PER_SERVICE: usize = 1;

#[derive(Debug)]
struct Runner {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Runner {
    fn start(
        fd: RawFd,
        catalog: ServiceCatalog,
        protector: Option<SocketProtector>,
    ) -> anyhow::Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        let network = VirtualNetwork::new(&catalog.services)?;
        let thread = thread::Builder::new()
            .name("medium-netstack".to_string())
            .spawn(move || {
                if let Err(error) =
                    run_tun_loop(fd, network, catalog.routes, protector, thread_running)
                {
                    error!("medium netstack loop exited: {error:#}");
                }
            })?;

        Ok(Self {
            running,
            thread: Some(thread),
        })
    }

    fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                error!("medium netstack thread panicked");
            }
        }
    }
}

struct SocketProtector {
    vm: JavaVM,
    service: Option<GlobalRef>,
}

impl SocketProtector {
    fn new(vm: JavaVM, service: GlobalRef) -> Self {
        Self {
            vm,
            service: Some(service),
        }
    }

    fn protect(&self, fd: RawFd) -> anyhow::Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let service = self.service.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Android routing service reference was already dropped")
        })?;
        let protected = env
            .call_method(service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])?
            .z()?;
        if !protected {
            anyhow::bail!("Android routing service failed to protect socket fd {fd}");
        }
        Ok(())
    }
}

impl Drop for SocketProtector {
    fn drop(&mut self) {
        let _guard = self.vm.attach_current_thread().ok();
        let _ = self.service.take();
    }
}

#[derive(Debug, Deserialize)]
struct AndroidService {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default = "default_service_kind")]
    kind: String,
    target: String,
    #[serde(default)]
    grant: Option<SessionOpenGrant>,
    #[serde(default)]
    control_pin: Option<String>,
}

#[derive(Debug)]
struct ServiceCatalog {
    services: Vec<PublishedService>,
    routes: HashMap<String, BackendRoute>,
}

#[derive(Debug, Clone)]
enum BackendRoute {
    DirectTarget(String),
    SessionGrant {
        grant: SessionOpenGrant,
        control_pin: Option<String>,
    },
}

fn default_service_kind() -> String {
    "https".to_string()
}

fn init_logger() {
    LOGGER.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("MediumNetstack")
                .with_max_level(LevelFilter::Debug),
        );
    });
}

fn parse_services(json: &str) -> anyhow::Result<ServiceCatalog> {
    let android_services = serde_json::from_str::<Vec<AndroidService>>(json)?;
    let mut routes = HashMap::new();
    let mut services = Vec::with_capacity(android_services.len());
    for service in android_services {
        let route = match service.grant {
            Some(grant) => BackendRoute::SessionGrant {
                grant,
                control_pin: service.control_pin,
            },
            None => BackendRoute::DirectTarget(service.target),
        };
        routes.insert(service.id.clone(), route);
        services.push(PublishedService {
            id: service.id,
            label: service.label,
            kind: service.kind,
        });
    }
    Ok(ServiceCatalog { services, routes })
}

fn run_tun_loop(
    fd: RawFd,
    network: VirtualNetwork,
    routes: HashMap<String, BackendRoute>,
    protector: Option<SocketProtector>,
    running: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut tun = unsafe { File::from_raw_fd(fd) };
    set_nonblocking(tun.as_raw_fd())?;
    let mut stack = MediumStack::new(network)?;
    let mut backends = StreamBackends::new(routes, protector);
    backends.warm_up();
    let mut packet = vec![0_u8; 2048];
    let mut now_millis = 0_i64;

    info!("medium netstack started");
    while running.load(Ordering::Relaxed) {
        if wait_readable(tun.as_raw_fd(), 250)? {
            match tun.read(&mut packet) {
                Ok(0) => break,
                Ok(size) => stack.push_tun_packet(packet[..size].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        for event in stack.poll(now_millis)? {
            debug!("tcp pump event: {event:?}");
            backends.handle_event(&mut stack, event)?;
        }
        backends.pump_writes(&mut stack)?;
        backends.pump_reads(&mut stack)?;
        backends.pump_writes(&mut stack)?;
        while let Some(outbound) = stack.pop_tun_packet() {
            tun.write_all(&outbound)?;
        }
        now_millis += 250;
    }
    info!("medium netstack stopped");
    Ok(())
}

struct StreamBackends {
    routes: HashMap<String, BackendRoute>,
    streams: HashMap<String, ActiveBackend>,
    stream_services: HashMap<String, String>,
    idle_backends: IdlePool<ActiveBackend>,
    pending_writes: HashMap<String, VecDeque<u8>>,
    selected_ice_paths: HashMap<String, IceCandidate>,
    protector: Option<SocketProtector>,
}

impl StreamBackends {
    fn new(routes: HashMap<String, BackendRoute>, protector: Option<SocketProtector>) -> Self {
        Self {
            routes,
            streams: HashMap::new(),
            stream_services: HashMap::new(),
            idle_backends: IdlePool::new(IDLE_BACKENDS_PER_SERVICE),
            pending_writes: HashMap::new(),
            selected_ice_paths: HashMap::new(),
            protector,
        }
    }

    fn warm_up(&mut self) {
        let service_ids = self
            .routes
            .iter()
            .filter_map(|(service_id, route)| match route {
                BackendRoute::SessionGrant { .. } => Some(service_id.clone()),
                BackendRoute::DirectTarget(_) => None,
            })
            .collect::<Vec<_>>();

        for service_id in service_ids {
            self.ensure_idle_backend(&service_id);
        }
    }

    fn handle_event(
        &mut self,
        stack: &mut MediumStack<'_>,
        event: TcpPumpEvent,
    ) -> anyhow::Result<()> {
        match event {
            TcpPumpEvent::Connected {
                stream_id,
                service_id,
            } => self.open_backend(stack, &stream_id, &service_id),
            TcpPumpEvent::Received {
                stream_id, bytes, ..
            } => {
                if let Err(error) = self.queue_backend_write(&stream_id, &bytes) {
                    error!("backend write failed for stream {stream_id}: {error:#}");
                    self.remove_stream(&stream_id);
                    let _ = stack.close_tcp(&stream_id);
                }
                Ok(())
            }
            TcpPumpEvent::Closed { stream_id, .. } => {
                self.remove_stream(&stream_id);
                Ok(())
            }
        }
    }

    fn open_backend(
        &mut self,
        stack: &mut MediumStack<'_>,
        stream_id: &str,
        service_id: &str,
    ) -> anyhow::Result<()> {
        let Some(route) = self.routes.get(service_id).cloned() else {
            stack.close_tcp(stream_id)?;
            return Ok(());
        };

        match self.take_or_connect_backend(service_id, &route) {
            Ok(stream) => {
                self.streams.insert(stream_id.to_string(), stream);
                self.stream_services
                    .insert(stream_id.to_string(), service_id.to_string());
            }
            Err(error) => {
                error!("failed to connect backend service {service_id}: {error:#}");
                let _ = stack.send_tcp(
                    stream_id,
                    diagnostic_http_response(
                        502,
                        "Medium backend unavailable",
                        &format!(
                            "Medium resolved the service and accepted the browser TCP connection, \
                             but no backend candidate could be reached for service `{service_id}`.\n\n\
                             Last error:\n{error:#}\n\n\
                             Check that the node-agent is running and that either direct TCP is reachable \
                             or relay/WSS relay is configured and reachable from this phone."
                        ),
                    )
                    .as_bytes(),
                );
                stack.close_tcp(stream_id)?;
            }
        }
        Ok(())
    }

    fn take_or_connect_backend(
        &mut self,
        service_id: &str,
        route: &BackendRoute,
    ) -> anyhow::Result<ActiveBackend> {
        if let Some(stream) = self.idle_backends.pop(service_id) {
            debug!("using warmed backend for service {service_id}");
            return Ok(stream);
        }

        let mut outcome = connect_backend(
            route,
            self.protector.as_ref(),
            self.selected_ice_paths.get(service_id),
        )?;
        outcome.backend.configure_nonblocking()?;
        if let Some(candidate) = outcome.selected_ice_path {
            self.selected_ice_paths
                .insert(service_id.to_string(), candidate);
        }
        Ok(outcome.backend)
    }

    fn ensure_idle_backend(&mut self, service_id: &str) {
        if self.idle_backends.len(service_id) >= IDLE_BACKENDS_PER_SERVICE {
            return;
        }
        let Some(route) = self.routes.get(service_id).cloned() else {
            return;
        };
        let BackendRoute::SessionGrant { .. } = &route else {
            return;
        };

        match connect_backend(
            &route,
            self.protector.as_ref(),
            self.selected_ice_paths.get(service_id),
        ) {
            Ok(mut outcome) => {
                if let Err(error) = outcome.backend.configure_nonblocking() {
                    error!("failed to configure warmed backend service {service_id}: {error:#}");
                    return;
                }
                if let Some(candidate) = outcome.selected_ice_path {
                    self.selected_ice_paths
                        .insert(service_id.to_string(), candidate);
                }
                if self.idle_backends.push(service_id, outcome.backend).is_ok() {
                    info!("warmed backend for service {service_id}");
                }
            }
            Err(error) => {
                error!("failed to warm backend for service {service_id}: {error:#}");
            }
        }
    }

    fn queue_backend_write(&mut self, stream_id: &str, bytes: &[u8]) -> anyhow::Result<()> {
        if !self.streams.contains_key(stream_id) {
            return Ok(());
        }
        self.pending_writes
            .entry(stream_id.to_string())
            .or_default()
            .extend(bytes.iter().copied());
        self.flush_pending_backend(stream_id)?;
        Ok(())
    }

    fn flush_pending_backend(&mut self, stream_id: &str) -> anyhow::Result<()> {
        let Some(stream) = self.streams.get_mut(stream_id) else {
            self.pending_writes.remove(stream_id);
            return Ok(());
        };
        let Some(pending) = self.pending_writes.get_mut(stream_id) else {
            return Ok(());
        };
        flush_pending_to_writer(stream_id, stream, pending)?;
        if pending.is_empty() {
            self.pending_writes.remove(stream_id);
        }
        Ok(())
    }

    fn pump_writes(&mut self, stack: &mut MediumStack<'_>) -> anyhow::Result<()> {
        let stream_ids = self.pending_writes.keys().cloned().collect::<Vec<_>>();
        let mut closed = Vec::new();

        for stream_id in stream_ids {
            if let Err(error) = self.flush_pending_backend(&stream_id) {
                error!("backend write failed for stream {stream_id}: {error:#}");
                closed.push(stream_id);
            }
        }

        for stream_id in closed {
            self.remove_stream(&stream_id);
            let _ = stack.close_tcp(&stream_id);
        }

        Ok(())
    }

    fn pump_reads(&mut self, stack: &mut MediumStack<'_>) -> anyhow::Result<()> {
        let mut buffer = [0_u8; 8192];
        let mut closed = Vec::new();

        for (stream_id, stream) in self.streams.iter_mut() {
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        closed.push(stream_id.clone());
                        break;
                    }
                    Ok(size) => {
                        debug!("backend read stream={stream_id} bytes={size}");
                        stack.send_tcp(stream_id, &buffer[..size])?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        error!("backend read failed for stream {stream_id}: {error}");
                        closed.push(stream_id.clone());
                        break;
                    }
                }
            }
        }

        for stream_id in closed {
            self.remove_stream(&stream_id);
            let _ = stack.close_tcp(&stream_id);
        }

        Ok(())
    }

    fn remove_stream(&mut self, stream_id: &str) {
        self.streams.remove(stream_id);
        self.pending_writes.remove(stream_id);
        if let Some(service_id) = self.stream_services.remove(stream_id) {
            self.ensure_idle_backend(&service_id);
        }
    }
}

struct IdlePool<T> {
    max_per_service: usize,
    backends: HashMap<String, VecDeque<T>>,
}

impl<T> IdlePool<T> {
    fn new(max_per_service: usize) -> Self {
        Self {
            max_per_service,
            backends: HashMap::new(),
        }
    }

    fn push(&mut self, service_id: &str, backend: T) -> Result<(), T> {
        let entries = self.backends.entry(service_id.to_string()).or_default();
        if entries.len() >= self.max_per_service {
            return Err(backend);
        }
        entries.push_back(backend);
        Ok(())
    }

    fn pop(&mut self, service_id: &str) -> Option<T> {
        let entries = self.backends.get_mut(service_id)?;
        let backend = entries.pop_front();
        if entries.is_empty() {
            self.backends.remove(service_id);
        }
        backend
    }

    fn len(&self, service_id: &str) -> usize {
        self.backends
            .get(service_id)
            .map(VecDeque::len)
            .unwrap_or_default()
    }
}

fn flush_pending_to_writer<W: Write>(
    stream_id: &str,
    stream: &mut W,
    pending: &mut VecDeque<u8>,
) -> anyhow::Result<()> {
    let mut scratch = [0_u8; 8192];
    while !pending.is_empty() {
        let size = pending.len().min(scratch.len());
        for (index, byte) in pending.iter().take(size).copied().enumerate() {
            scratch[index] = byte;
        }

        match stream.write(&scratch[..size]) {
            Ok(0) => return Ok(()),
            Ok(written) => {
                for _ in 0..written {
                    pending.pop_front();
                }
                debug!(
                    "backend write stream={stream_id} bytes={written} pending={}",
                    pending.len()
                );
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

fn diagnostic_http_response(status: u16, title: &str, body: &str) -> String {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head>\
         <body style=\"font-family: sans-serif; padding: 24px; line-height: 1.45\">\
         <h1>{}</h1><pre style=\"white-space: pre-wrap\">{}</pre></body></html>",
        html_escape(title),
        html_escape(title),
        html_escape(body),
    );
    format!(
        "HTTP/1.1 {status} {title}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

enum ActiveBackend {
    Tcp(TcpStream),
    WebSocket(Box<WebSocket<MaybeTlsStream<TcpStream>>>),
    Udp(Box<UdpSessionStream>),
}

impl ActiveBackend {
    fn configure_nonblocking(&mut self) -> anyhow::Result<()> {
        match self {
            ActiveBackend::Tcp(stream) => stream.set_nonblocking(true)?,
            ActiveBackend::WebSocket(socket) => {
                set_websocket_timeouts(socket, Some(Duration::from_millis(10)))?;
            }
            ActiveBackend::Udp(stream) => {
                stream.set_poll_timeout(Duration::from_millis(10))?;
            }
        }
        Ok(())
    }
}

impl Read for ActiveBackend {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ActiveBackend::Tcp(stream) => stream.read(buffer),
            ActiveBackend::Udp(stream) => stream.read(buffer),
            ActiveBackend::WebSocket(socket) => loop {
                match socket.read() {
                    Ok(Message::Binary(payload)) => {
                        let size = payload.len().min(buffer.len());
                        buffer[..size].copy_from_slice(&payload[..size]);
                        return Ok(size);
                    }
                    Ok(Message::Close(_)) => return Ok(0),
                    Ok(Message::Ping(payload)) => {
                        let _ = socket.send(Message::Pong(payload));
                    }
                    Ok(_) => {}
                    Err(tungstenite::Error::Io(error))
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Err(error);
                    }
                    Err(error) => return Err(std::io::Error::other(error)),
                }
            },
        }
    }
}

impl Write for ActiveBackend {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            ActiveBackend::Tcp(stream) => stream.write(bytes),
            ActiveBackend::Udp(stream) => stream.write(bytes),
            ActiveBackend::WebSocket(socket) => {
                socket
                    .send(Message::Binary(bytes.to_vec().into()))
                    .map_err(std::io::Error::other)?;
                Ok(bytes.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ActiveBackend::Tcp(stream) => stream.flush(),
            ActiveBackend::Udp(stream) => stream.flush(),
            ActiveBackend::WebSocket(socket) => socket.flush().map_err(std::io::Error::other),
        }
    }
}

struct BackendConnectOutcome {
    backend: ActiveBackend,
    selected_ice_path: Option<IceCandidate>,
}

fn connect_backend(
    route: &BackendRoute,
    protector: Option<&SocketProtector>,
    preferred_ice_path: Option<&IceCandidate>,
) -> anyhow::Result<BackendConnectOutcome> {
    match route {
        BackendRoute::DirectTarget(target) => Ok(BackendConnectOutcome {
            backend: ActiveBackend::Tcp(connect_protected_tcp(target, protector)?),
            selected_ice_path: None,
        }),
        BackendRoute::SessionGrant { grant, control_pin } => {
            connect_session_grant(grant, control_pin.as_deref(), protector, preferred_ice_path)
        }
    }
}

fn connect_session_grant(
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
    protector: Option<&SocketProtector>,
    preferred_ice_path: Option<&IceCandidate>,
) -> anyhow::Result<BackendConnectOutcome> {
    if let Some((stream, selected_ice_path)) =
        try_connect_ice_udp(grant, protector, preferred_ice_path)?
    {
        return Ok(BackendConnectOutcome {
            backend: ActiveBackend::Udp(Box::new(stream)),
            selected_ice_path: Some(selected_ice_path),
        });
    }

    let mut candidates = grant.authorization.candidates.clone();
    candidates.sort_by(|left, right| right.priority.cmp(&left.priority));
    let mut last_error = None;

    for candidate in candidates {
        if is_unusable_backend_candidate_addr(&candidate.addr) {
            info!(
                "skipping unusable session candidate service={} kind={} addr={} priority={}",
                grant.service_id,
                candidate.kind.as_str(),
                candidate.addr,
                candidate.priority
            );
            continue;
        }
        info!(
            "trying session candidate service={} kind={} addr={} priority={}",
            grant.service_id,
            candidate.kind.as_str(),
            candidate.addr,
            candidate.priority
        );
        match connect_session_candidate(grant, control_pin, &candidate, protector) {
            Ok(stream) => {
                info!(
                    "connected session candidate service={} kind={} addr={}",
                    grant.service_id,
                    candidate.kind.as_str(),
                    candidate.addr
                );
                return Ok(BackendConnectOutcome {
                    backend: stream,
                    selected_ice_path: None,
                });
            }
            Err(error) => {
                error!(
                    "session candidate failed service={} kind={} addr={}: {error:#}",
                    grant.service_id,
                    candidate.kind.as_str(),
                    candidate.addr
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("session grant has no candidates")))
}

fn try_connect_ice_udp(
    grant: &SessionOpenGrant,
    protector: Option<&SocketProtector>,
    preferred_ice_path: Option<&IceCandidate>,
) -> anyhow::Result<Option<(UdpSessionStream, IceCandidate)>> {
    let Some(ice) = &grant.authorization.ice else {
        info!(
            "{}",
            p2p_diag::line(
                "grant",
                "missing_ice",
                [
                    ("session_id", grant.session_id.as_str()),
                    ("service_id", grant.service_id.as_str()),
                    ("node_id", grant.node_id.as_str()),
                ],
            )
        );
        return Ok(None);
    };
    let candidate_summary = ice
        .candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}:{}:{}",
                candidate.kind.as_str(),
                candidate.addr,
                candidate.port
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    info!(
        "{}",
        p2p_diag::line(
            "grant",
            "received",
            [
                ("session_id", grant.session_id.as_str()),
                ("service_id", grant.service_id.as_str()),
                ("node_id", grant.node_id.as_str()),
                ("ice_candidates", candidate_summary.as_str()),
            ],
        )
    );
    let mut last_error = None;

    for candidate in ice_checklist_with_preference(grant, preferred_ice_path) {
        let addr = ice_candidate_addr(&candidate);
        if is_unusable_backend_candidate_addr(&addr) {
            info!(
                "{}",
                p2p_diag::line(
                    "ice_pair_check",
                    "skipped",
                    [
                        ("session_id", grant.session_id.as_str()),
                        ("service_id", grant.service_id.as_str()),
                        ("node_id", grant.node_id.as_str()),
                        ("kind", candidate.kind.as_str()),
                        ("addr", addr.as_str()),
                        ("reason", "unusable_backend_addr"),
                    ],
                )
            );
            continue;
        }
        info!(
            "{}",
            p2p_diag::line(
                "ice_pair_check",
                "start",
                [
                    ("session_id", grant.session_id.as_str()),
                    ("service_id", grant.service_id.as_str()),
                    ("node_id", grant.node_id.as_str()),
                    ("kind", candidate.kind.as_str()),
                    ("addr", addr.as_str()),
                    ("priority", candidate.priority.to_string().as_str()),
                ],
            )
        );
        let connection = match candidate.kind {
            IceCandidateKind::Relay => connect_ice_udp_via_rendezvous(grant, &addr, protector),
            IceCandidateKind::Host | IceCandidateKind::Srflx => {
                connect_ice_udp_candidate(grant, &addr, protector)
            }
        };
        match connection {
            Ok(stream) => {
                info!(
                    "{}",
                    p2p_diag::line(
                        "ice_selected_pair",
                        "ok",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("node_id", grant.node_id.as_str()),
                            ("kind", candidate.kind.as_str()),
                            ("addr", addr.as_str()),
                        ],
                    )
                );
                return Ok(Some((stream, candidate)));
            }
            Err(error) => {
                let reason = error.to_string();
                error!(
                    "{}",
                    p2p_diag::line(
                        "ice_pair_check",
                        "failed",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("node_id", grant.node_id.as_str()),
                            ("kind", candidate.kind.as_str()),
                            ("addr", addr.as_str()),
                            ("reason", reason.as_str()),
                        ],
                    )
                );
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        let reason = error.to_string();
        info!(
            "{}",
            p2p_diag::line(
                "verdict",
                "fallback_relay",
                [
                    ("session_id", grant.session_id.as_str()),
                    ("service_id", grant.service_id.as_str()),
                    ("node_id", grant.node_id.as_str()),
                    ("reason", reason.as_str()),
                ],
            )
        );
        error!(
            "all ICE UDP candidates failed for service={}, falling back to legacy candidates: {error:#}",
            grant.service_id
        );
    }
    Ok(None)
}

fn ice_checklist_with_preference(
    grant: &SessionOpenGrant,
    preferred: Option<&IceCandidate>,
) -> Vec<IceCandidate> {
    medium_session::ice_checklist(grant, preferred)
}

fn ice_candidate_addr(candidate: &IceCandidate) -> String {
    match candidate.addr.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", candidate.addr, candidate.port),
        _ => format!("{}:{}", candidate.addr, candidate.port),
    }
}

fn connect_ice_udp_via_rendezvous(
    grant: &SessionOpenGrant,
    relay_addr: &str,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<UdpSessionStream> {
    let mut last_error = None;
    for socket_addr in relay_addr.to_socket_addrs()? {
        match create_protected_udp_socket(socket_addr, protector) {
            Ok(socket) => {
                let local_addr = socket.local_addr()?.to_string();
                let relay = socket_addr.to_string();
                info!(
                    "{}",
                    p2p_diag::line(
                        "udp_socket",
                        "bound",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("local_addr", local_addr.as_str()),
                            ("relay_addr", relay.as_str()),
                        ],
                    )
                );
                socket.set_read_timeout(Some(Duration::from_millis(500)))?;
                socket.set_write_timeout(Some(Duration::from_millis(500)))?;
                info!(
                    "{}",
                    p2p_diag::line(
                        "rendezvous_request",
                        "sent",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("node_id", grant.node_id.as_str()),
                            ("relay_addr", relay.as_str()),
                        ],
                    )
                );
                let peer_addr = match resolve_peer(
                    &socket,
                    socket_addr,
                    &grant.node_id,
                    &grant.authorization.token,
                ) {
                    Ok(peer_addr) => peer_addr,
                    Err(error) => {
                        let reason = error.to_string();
                        info!(
                            "{}",
                            p2p_diag::line(
                                "verdict",
                                "rendezvous_unavailable",
                                [
                                    ("session_id", grant.session_id.as_str()),
                                    ("service_id", grant.service_id.as_str()),
                                    ("node_id", grant.node_id.as_str()),
                                    ("relay_addr", relay.as_str()),
                                    ("reason", reason.as_str()),
                                ],
                            )
                        );
                        return Err(error);
                    }
                };
                let peer = peer_addr.to_string();
                info!(
                    "{}",
                    p2p_diag::line(
                        "peer_received",
                        "ok",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("node_id", grant.node_id.as_str()),
                            ("peer_addr", peer.as_str()),
                        ],
                    )
                );
                info!(
                    "{}",
                    p2p_diag::line(
                        "session_hello_sent",
                        "start",
                        [
                            ("session_id", grant.session_id.as_str()),
                            ("service_id", grant.service_id.as_str()),
                            ("node_id", grant.node_id.as_str()),
                            ("peer_addr", peer.as_str()),
                        ],
                    )
                );
                let stream = UdpSessionStream::connect(
                    socket,
                    peer_addr,
                    SessionHello {
                        token: grant.authorization.token.clone(),
                        service_id: grant.service_id.clone(),
                        transport: None,
                    },
                );
                match stream {
                    Ok(stream) => {
                        info!(
                            "{}",
                            p2p_diag::line(
                                "session_ack_received",
                                "ok",
                                [
                                    ("session_id", grant.session_id.as_str()),
                                    ("service_id", grant.service_id.as_str()),
                                    ("node_id", grant.node_id.as_str()),
                                    ("peer_addr", peer.as_str()),
                                ],
                            )
                        );
                        info!(
                            "{}",
                            p2p_diag::line(
                                "verdict",
                                "p2p_possible",
                                [
                                    ("session_id", grant.session_id.as_str()),
                                    ("service_id", grant.service_id.as_str()),
                                    ("node_id", grant.node_id.as_str()),
                                    ("peer_addr", peer.as_str()),
                                ],
                            )
                        );
                        return Ok(stream);
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        info!(
                            "{}",
                            p2p_diag::line(
                                "session_hello_received",
                                "timeout",
                                [
                                    ("session_id", grant.session_id.as_str()),
                                    ("service_id", grant.service_id.as_str()),
                                    ("node_id", grant.node_id.as_str()),
                                    ("peer_addr", peer.as_str()),
                                    ("reason", reason.as_str()),
                                ],
                            )
                        );
                        info!(
                            "{}",
                            p2p_diag::line(
                                "verdict",
                                "peer_udp_unreachable",
                                [
                                    ("session_id", grant.session_id.as_str()),
                                    ("service_id", grant.service_id.as_str()),
                                    ("node_id", grant.node_id.as_str()),
                                    ("peer_addr", peer.as_str()),
                                    ("reason", reason.as_str()),
                                ],
                            )
                        );
                        return Err(error);
                    }
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no socket addresses for {relay_addr}")))
}

fn connect_ice_udp_candidate(
    grant: &SessionOpenGrant,
    addr: &str,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<UdpSessionStream> {
    let mut last_error = None;
    for socket_addr in addr.to_socket_addrs()? {
        match create_protected_udp_socket(socket_addr, protector) {
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

fn connect_session_candidate(
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
    candidate: &PeerCandidate,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<ActiveBackend> {
    match candidate.kind {
        CandidateKind::DirectTcp => {
            let mut stream = connect_protected_tcp(&candidate.addr, protector)?;
            write_session_hello(&mut stream, grant)?;
            Ok(ActiveBackend::Tcp(stream))
        }
        CandidateKind::RelayTcp => {
            let mut stream = connect_protected_tcp(&candidate.addr, protector)?;
            write_json_line(
                &mut stream,
                &serde_json::json!({
                    "role": "client",
                    "node_id": grant.node_id,
                }),
            )?;
            write_session_hello(&mut stream, grant)?;
            Ok(ActiveBackend::Tcp(stream))
        }
        CandidateKind::WssRelay => {
            let mut socket = connect_wss_relay(&candidate.addr, grant, control_pin, protector)?;
            set_websocket_timeouts(&mut socket, Some(Duration::from_millis(10)))?;
            Ok(ActiveBackend::WebSocket(Box::new(socket)))
        }
    }
}

fn connect_wss_relay(
    relay_url: &str,
    grant: &SessionOpenGrant,
    control_pin: Option<&str>,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<WebSocket<MaybeTlsStream<TcpStream>>> {
    let addr = websocket_tcp_addr(relay_url)?;
    let stream = connect_protected_tcp(&addr, protector)?;
    let connector = match control_pin {
        Some(control_pin) => Some(Connector::Rustls(Arc::new(pinned_tls_client_config(
            control_pin,
        )?))),
        None => None,
    };
    let (mut socket, _) = tungstenite::client_tls_with_config(relay_url, stream, None, connector)?;
    socket.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "role": "client",
            "node_id": grant.node_id,
        }))?
        .into(),
    ))?;
    socket.send(Message::Binary(session_hello_frame(grant)?.into()))?;
    Ok(socket)
}

fn pinned_tls_client_config(control_pin: &str) -> anyhow::Result<ClientConfig> {
    let expected_pin = parse_sha256_pin(control_pin)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let supported = provider.signature_verification_algorithms;
    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            expected_pin,
            supported,
        }))
        .with_no_client_auth())
}

fn parse_sha256_pin(pin: &str) -> anyhow::Result<[u8; 32]> {
    let hex = pin
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("control pin must start with sha256:"))?;
    if hex.len() != 64 {
        anyhow::bail!("control pin sha256 digest must be 64 hex characters");
    }

    let mut digest = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|error| anyhow::anyhow!("invalid control pin hex byte {pair}: {error}"))?;
    }
    Ok(digest)
}

#[derive(Clone)]
struct PinnedCertVerifier {
    expected_pin: [u8; 32],
    supported: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertVerifier")
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = Sha256::digest(end_entity.as_ref());
        if actual.as_slice() != self.expected_pin {
            return Err(TlsError::General("control TLS pin mismatch".to_string()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
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

fn session_hello_frame(grant: &SessionOpenGrant) -> anyhow::Result<Vec<u8>> {
    let mut payload = serde_json::to_vec(&serde_json::json!({
        "token": grant.authorization.token,
        "service_id": grant.service_id,
    }))?;
    payload.push(b'\n');
    Ok(payload)
}

fn set_websocket_timeouts(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    timeout: Option<Duration>,
) -> anyhow::Result<()> {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => {
            stream.set_read_timeout(timeout)?;
            stream.set_write_timeout(timeout)?;
        }
        MaybeTlsStream::Rustls(stream) => {
            stream.get_mut().set_read_timeout(timeout)?;
            stream.get_mut().set_write_timeout(timeout)?;
        }
        #[allow(unreachable_patterns)]
        _ => {}
    }
    Ok(())
}

fn connect_protected_tcp(
    addr: &str,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<TcpStream> {
    if let Some(protector) = protector {
        let mut last_error = None;
        for socket_addr in addr.to_socket_addrs()? {
            match connect_protected_socket(socket_addr, protector) {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no socket addresses for {addr}")));
    }

    Ok(TcpStream::connect(addr)?)
}

fn connect_protected_socket(
    addr: SocketAddr,
    protector: &SocketProtector,
) -> anyhow::Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, None)?;
    protector.protect(socket.as_raw_fd())?;
    socket.connect_timeout(&SockAddr::from(addr), CANDIDATE_CONNECT_TIMEOUT)?;
    Ok(socket.into())
}

fn create_protected_udp_socket(
    addr: SocketAddr,
    protector: Option<&SocketProtector>,
) -> anyhow::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    if let Some(protector) = protector {
        protector.protect(socket.as_raw_fd())?;
    }
    let bind_addr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>()?,
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>()?,
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    Ok(socket.into())
}

fn write_session_hello(stream: &mut TcpStream, grant: &SessionOpenGrant) -> anyhow::Result<()> {
    write_json_line(
        stream,
        &serde_json::json!({
            "token": grant.authorization.token,
            "service_id": grant.service_id,
        }),
    )
}

fn write_json_line<T: serde::Serialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<()> {
    let mut payload = serde_json::to_vec(value)?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> anyhow::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn wait_readable(fd: RawFd, timeout_millis: i32) -> anyhow::Result<bool> {
    let mut fds = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut fds, 1, timeout_millis) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(result > 0 && (fds.revents & libc::POLLIN) != 0)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_burniq_medium_android_MediumNativeBridge_nativeStartTun(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    service: JObject<'_>,
    fd: jint,
    services_json: JString<'_>,
) -> jlong {
    init_logger();

    let result = (|| -> anyhow::Result<Runner> {
        let services_json: String = env.get_string(&services_json)?.into();
        let catalog = parse_services(&services_json)?;
        let protector = SocketProtector::new(env.get_java_vm()?, env.new_global_ref(service)?);
        Runner::start(fd, catalog, Some(protector))
    })();

    match result {
        Ok(runner) => Box::into_raw(Box::new(runner)) as jlong,
        Err(error) => {
            error!("failed to start medium netstack: {error:#}");
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_burniq_medium_android_MediumNativeBridge_nativeStopTun(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    init_logger();
    if handle == 0 {
        return;
    }
    let runner = unsafe { Box::from_raw(handle as *mut Runner) };
    runner.stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_android_services_for_virtual_network() {
        let catalog = parse_services(
            r#"[{"id":"hello","label":null,"kind":"https","target":"127.0.0.1:8082"},{"id":"svc_docs","label":"Docs","target":"127.0.0.1:8080"}]"#,
        )
        .unwrap();

        assert_eq!(catalog.services[0].id, "hello");
        assert_eq!(catalog.services[0].label, None);
        assert_eq!(catalog.services[1].label.as_deref(), Some("Docs"));
        assert_eq!(catalog.services[1].kind, "https");
        assert_eq!(
            matches!(catalog.routes.get("hello"), Some(BackendRoute::DirectTarget(target)) if target == "127.0.0.1:8082"),
            true
        );
    }

    #[test]
    fn treats_198_18_candidates_as_unusable_backend_addresses() {
        assert!(is_unusable_backend_candidate_addr("198.18.0.1:17002"));
        assert!(is_unusable_backend_candidate_addr("198.19.255.254:17002"));
        assert!(!is_unusable_backend_candidate_addr("198.20.0.1:17002"));
        assert!(!is_unusable_backend_candidate_addr("85.174.195.173:8919"));
    }

    #[test]
    fn ice_checklist_orders_direct_host_candidates_before_relay_rendezvous() {
        let grant: SessionOpenGrant = serde_json::from_str(
            r#"
            {
              "session_id": "sess_1",
              "service_id": "hello",
              "node_id": "node-1",
              "relay_hint": "127.0.0.1:7001",
              "authorization": {
                "token": "token",
                "expires_at": "2099-01-01T00:00:00Z",
                "candidates": [],
                "ice": {
                  "credentials": {
                    "ufrag": "ufrag",
                    "pwd": "pwd",
                    "expires_at": "2099-01-01T00:00:00Z"
                  },
                  "candidates": [
                    {
                      "foundation": "relay-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 10,
                      "addr": "127.0.0.1",
                      "port": 7001,
                      "kind": "relay",
                      "related_addr": null,
                      "related_port": null
                    },
                    {
                      "foundation": "host-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 300,
                      "addr": "192.168.1.44",
                      "port": 17002,
                      "kind": "host",
                      "related_addr": null,
                      "related_port": null
                    },
                    {
                      "foundation": "srflx-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 100,
                      "addr": "198.51.100.20",
                      "port": 17002,
                      "kind": "srflx",
                      "related_addr": null,
                      "related_port": null
                    }
                  ]
                }
              }
            }
            "#,
        )
        .unwrap();

        let checklist = ice_checklist_with_preference(&grant, None);
        let kinds = checklist
            .iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![
                IceCandidateKind::Host,
                IceCandidateKind::Srflx,
                IceCandidateKind::Relay,
            ]
        );
    }

    #[test]
    fn backend_write_flush_preserves_pending_after_partial_write() {
        struct ChunkedWouldBlockWriter {
            bytes: Vec<u8>,
            limit: usize,
            writes: usize,
        }

        impl ChunkedWouldBlockWriter {
            fn new(limit: usize) -> Self {
                Self {
                    bytes: Vec::new(),
                    limit,
                    writes: 0,
                }
            }

            fn allow_next_write(&mut self, limit: usize) {
                self.limit = limit;
                self.writes = 0;
            }
        }

        impl Write for ChunkedWouldBlockWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.writes > 0 {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                self.writes += 1;
                let size = bytes.len().min(self.limit);
                self.bytes.extend_from_slice(&bytes[..size]);
                Ok(size)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = ChunkedWouldBlockWriter::new(3);
        let mut pending = std::collections::VecDeque::from(b"abcdef".to_vec());

        flush_pending_to_writer("tcp-1", &mut writer, &mut pending).unwrap();

        assert_eq!(writer.bytes, b"abc");
        assert_eq!(pending.iter().copied().collect::<Vec<_>>(), b"def");

        writer.allow_next_write(10);
        flush_pending_to_writer("tcp-1", &mut writer, &mut pending).unwrap();

        assert_eq!(writer.bytes, b"abcdef");
        assert!(pending.is_empty());
    }

    #[test]
    fn idle_pool_keeps_only_configured_spares_per_service() {
        let mut pool = IdlePool::new(1);

        assert!(pool.push("hello", 1).is_ok());
        assert!(pool.push("hello", 2).is_err());
        assert_eq!(pool.pop("hello"), Some(1));
        assert_eq!(pool.pop("hello"), None);
    }

    #[test]
    fn ice_checklist_tries_preferred_successful_pair_first() {
        let grant = session_grant_with_ice_candidates();
        let preferred = IceCandidate {
            foundation: "srflx-udp-1".into(),
            component: 1,
            transport: "udp".into(),
            priority: 100,
            addr: "198.51.100.20".into(),
            port: 17002,
            kind: IceCandidateKind::Srflx,
            related_addr: None,
            related_port: None,
        };

        let checklist = ice_checklist_with_preference(&grant, Some(&preferred));
        let addrs = checklist.iter().map(ice_candidate_addr).collect::<Vec<_>>();

        assert_eq!(addrs[0], "198.51.100.20:17002");
    }

    fn session_grant_with_ice_candidates() -> SessionOpenGrant {
        serde_json::from_str(
            r#"
            {
              "session_id": "sess_1",
              "service_id": "hello",
              "node_id": "node-1",
              "relay_hint": "127.0.0.1:7001",
              "authorization": {
                "token": "token",
                "expires_at": "2099-01-01T00:00:00Z",
                "candidates": [],
                "ice": {
                  "credentials": {
                    "ufrag": "ufrag",
                    "pwd": "pwd",
                    "expires_at": "2099-01-01T00:00:00Z"
                  },
                  "candidates": [
                    {
                      "foundation": "relay-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 10,
                      "addr": "127.0.0.1",
                      "port": 7001,
                      "kind": "relay",
                      "related_addr": null,
                      "related_port": null
                    },
                    {
                      "foundation": "host-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 300,
                      "addr": "192.168.1.44",
                      "port": 17002,
                      "kind": "host",
                      "related_addr": null,
                      "related_port": null
                    },
                    {
                      "foundation": "srflx-udp-1",
                      "component": 1,
                      "transport": "udp",
                      "priority": 100,
                      "addr": "198.51.100.20",
                      "port": 17002,
                      "kind": "srflx",
                      "related_addr": null,
                      "related_port": null
                    }
                  ]
                }
              }
            }
            "#,
        )
        .unwrap()
    }
}
