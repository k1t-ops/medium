pub mod config;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use overlay_transport::p2p_diag;
use overlay_transport::session::{RelayHello, read_relay_hello};
use overlay_transport::udp_rendezvous::{UdpRendezvousMessage, parse_message};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, oneshot};
use tokio::time::Instant;

const RELAY_NODE_SOCKET_TTL: std::time::Duration = std::time::Duration::from_secs(60);

struct WaitingTcpNode {
    connected_at: Instant,
    stream: TcpStream,
}

struct WaitingWebSocketNode {
    connected_at: Instant,
    socket: WebSocket,
}

type WaitingNodes = Arc<Mutex<HashMap<String, Vec<WaitingTcpNode>>>>;
type WaitingWebSocketNodes = Arc<Mutex<HashMap<String, Vec<WaitingWebSocketNode>>>>;
type RendezvousNodes = Arc<Mutex<HashMap<String, SocketAddr>>>;

#[derive(Clone)]
struct RelayState {
    shared_secret: Option<String>,
    waiting_nodes: WaitingWebSocketNodes,
}

impl RelayState {
    fn new(shared_secret: Option<String>) -> Self {
        Self {
            shared_secret,
            waiting_nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub fn wss_router(shared_secret: Option<String>) -> Router {
    Router::new()
        .route("/medium/v1/relay", get(handle_wss_upgrade))
        .with_state(RelayState::new(shared_secret))
}

pub async fn run_tcp_relay(bind_addr: &str, shared_secret: Option<String>) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();
    run_tcp_relay_with_shutdown(bind_addr, shared_secret, shutdown_rx, None).await
}

pub async fn run_wss_relay(bind_addr: &str, shared_secret: Option<String>) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();
    run_wss_relay_with_shutdown(bind_addr, shared_secret, shutdown_rx).await
}

pub async fn run_wss_relay_with_shutdown(
    bind_addr: &str,
    shared_secret: Option<String>,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let udp_shared_secret = shared_secret.clone();
    let app = wss_router(shared_secret);
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let (udp_shutdown_tx, udp_shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Err(error) = run_udp_rendezvous_with_shutdown(
            &local_addr.to_string(),
            udp_shared_secret,
            udp_shutdown_rx,
            None,
        )
        .await
        {
            tracing::warn!(%error, bind_addr = %local_addr, "UDP rendezvous failed");
        }
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
            let _ = udp_shutdown_tx.send(());
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_relay_wait_discards_expired_node_sockets_and_waits_for_fresh_one()
    -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let stale_client = TcpStream::connect(addr).await?;
        let (stale_relay, _) = listener.accept().await?;
        let fresh_client = TcpStream::connect(addr).await?;
        let (fresh_relay, _) = listener.accept().await?;

        let waiting_nodes: WaitingNodes = Arc::new(Mutex::new(HashMap::new()));
        waiting_nodes
            .lock()
            .await
            .entry("node-1".into())
            .or_default()
            .push(WaitingTcpNode {
                connected_at: tokio::time::Instant::now() - std::time::Duration::from_secs(10),
                stream: stale_relay,
            });

        let delayed_waiting_nodes = waiting_nodes.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            delayed_waiting_nodes
                .lock()
                .await
                .entry("node-1".into())
                .or_default()
                .push(WaitingTcpNode {
                    connected_at: tokio::time::Instant::now(),
                    stream: fresh_relay,
                });
        });

        let mut selected = wait_for_node_stream_with_ttl(
            waiting_nodes,
            "node-1",
            std::time::Duration::from_millis(100),
        )
        .await?;

        selected.write_all(b"fresh").await?;
        let mut stale_client = stale_client;
        let mut fresh_client = fresh_client;
        let mut buffer = [0_u8; 5];
        let fresh_read = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            fresh_client.read_exact(&mut buffer),
        )
        .await??;
        assert_eq!(fresh_read, 5);
        assert_eq!(&buffer, b"fresh");

        let stale_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stale_client.read(&mut buffer),
        )
        .await??;
        assert_eq!(stale_result, 0, "expired stale relay socket was not closed");
        Ok(())
    }
}

pub async fn run_tcp_relay_with_shutdown(
    bind_addr: &str,
    shared_secret: Option<String>,
    mut shutdown: oneshot::Receiver<()>,
    bound_addr_tx: Option<oneshot::Sender<std::net::SocketAddr>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }
    let (udp_shutdown_tx, udp_shutdown_rx) = oneshot::channel();
    let udp_shared_secret = shared_secret.clone();
    tokio::spawn(async move {
        if let Err(error) = run_udp_rendezvous_with_shutdown(
            &local_addr.to_string(),
            udp_shared_secret,
            udp_shutdown_rx,
            None,
        )
        .await
        {
            tracing::warn!(%error, bind_addr = %local_addr, "UDP rendezvous failed");
        }
    });
    let waiting_nodes: WaitingNodes = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                let _ = udp_shutdown_tx.send(());
                break;
            },
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let waiting_nodes = waiting_nodes.clone();
                let shared_secret = shared_secret.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, waiting_nodes, shared_secret).await {
                        tracing::warn!(%error, "relay connection failed");
                    }
                });
            }
        }
    }

    Ok(())
}

pub async fn run_udp_rendezvous_with_shutdown(
    bind_addr: &str,
    shared_secret: Option<String>,
    mut shutdown: oneshot::Receiver<()>,
    bound_addr_tx: Option<oneshot::Sender<std::net::SocketAddr>>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let local_addr = socket.local_addr()?;
    let local = local_addr.to_string();
    tracing::info!(
        "{}",
        p2p_diag::line("relay_start", "ok", [("bind_addr", local.as_str())])
    );
    tracing::info!(bind_addr = %local_addr, "UDP rendezvous started");
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }
    let nodes: RendezvousNodes = Arc::new(Mutex::new(HashMap::new()));
    let mut buffer = [0_u8; 1500];

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            received = socket.recv_from(&mut buffer) => {
                let (size, peer_addr) = received?;
                if let Err(error) = handle_udp_rendezvous_message(
                    &socket,
                    &buffer[..size],
                    peer_addr,
                    nodes.clone(),
                    shared_secret.as_deref(),
                ).await {
                    tracing::warn!(%error, %peer_addr, "UDP rendezvous message rejected");
                }
            }
        }
    }

    tracing::info!(
        "{}",
        p2p_diag::line("relay_stop", "ok", [("bind_addr", local.as_str())])
    );
    tracing::info!(bind_addr = %local_addr, "UDP rendezvous stopped");
    Ok(())
}

async fn handle_udp_rendezvous_message(
    socket: &UdpSocket,
    payload: &[u8],
    peer_addr: SocketAddr,
    nodes: RendezvousNodes,
    shared_secret: Option<&str>,
) -> anyhow::Result<()> {
    match parse_message(payload)? {
        UdpRendezvousMessage::Node {
            node_id,
            shared_secret: provided_secret,
        } => {
            let expected_secret = shared_secret
                .ok_or_else(|| anyhow::anyhow!("rendezvous shared secret is not configured"))?;
            if expected_secret != provided_secret {
                tracing::info!(
                    "{}",
                    p2p_diag::line(
                        "node_registered",
                        "auth_failed",
                        [
                            ("node_id", node_id.as_str()),
                            ("peer_addr", peer_addr.to_string().as_str()),
                        ],
                    )
                );
                anyhow::bail!("rendezvous node authentication failed for {node_id}");
            }
            let previous_addr = {
                let mut nodes = nodes.lock().await;
                nodes.insert(node_id.clone(), peer_addr)
            };
            send_udp_message(
                socket,
                peer_addr,
                &UdpRendezvousMessage::Registered {
                    addr: peer_addr.to_string(),
                },
            )
            .await?;
            if previous_addr != Some(peer_addr) {
                tracing::info!(
                    "{}",
                    p2p_diag::line(
                        "node_registered",
                        "ok",
                        [
                            ("node_id", node_id.as_str()),
                            ("peer_addr", peer_addr.to_string().as_str()),
                        ],
                    )
                );
                tracing::info!(%node_id, %peer_addr, "UDP rendezvous node registered");
            } else {
                tracing::debug!(%node_id, %peer_addr, "UDP rendezvous node registration refreshed");
            }
        }
        UdpRendezvousMessage::Client { node_id, token } => {
            tracing::info!(
                "{}",
                p2p_diag::line(
                    "rendezvous_request",
                    "received",
                    [
                        ("node_id", node_id.as_str()),
                        ("client_addr", peer_addr.to_string().as_str()),
                    ],
                )
            );
            tracing::info!(%node_id, client_addr = %peer_addr, "UDP rendezvous client requested peer");
            let expected_secret = shared_secret
                .ok_or_else(|| anyhow::anyhow!("rendezvous shared secret is not configured"))?;
            let claims = overlay_crypto::verify_session_token(expected_secret, &token)?;
            if claims.node_id != node_id {
                tracing::info!(
                    "{}",
                    p2p_diag::line(
                        "rendezvous_request",
                        "token_node_mismatch",
                        [
                            ("node_id", node_id.as_str()),
                            ("token_node_id", claims.node_id.as_str()),
                            ("client_addr", peer_addr.to_string().as_str()),
                        ],
                    )
                );
                anyhow::bail!("rendezvous token node mismatch");
            }
            let node_addr = match nodes.lock().await.get(&node_id).copied() {
                Some(node_addr) => node_addr,
                None => {
                    tracing::info!(
                        "{}",
                        p2p_diag::line(
                            "verdict",
                            "node_not_registered",
                            [
                                ("node_id", node_id.as_str()),
                                ("client_addr", peer_addr.to_string().as_str()),
                            ],
                        )
                    );
                    anyhow::bail!("node {node_id} is not registered for UDP rendezvous");
                }
            };
            send_udp_message(
                socket,
                peer_addr,
                &UdpRendezvousMessage::Peer {
                    addr: node_addr.to_string(),
                },
            )
            .await?;
            send_udp_message(
                socket,
                node_addr,
                &UdpRendezvousMessage::Peer {
                    addr: peer_addr.to_string(),
                },
            )
            .await?;
            tracing::info!(
                "{}",
                p2p_diag::line(
                    "rendezvous_pair",
                    "ok",
                    [
                        ("node_id", node_id.as_str()),
                        ("client_addr", peer_addr.to_string().as_str()),
                        ("node_addr", node_addr.to_string().as_str()),
                    ],
                )
            );
            tracing::info!(%node_id, client_addr = %peer_addr, %node_addr, "UDP rendezvous paired peers");
        }
        UdpRendezvousMessage::Registered { .. }
        | UdpRendezvousMessage::Peer { .. }
        | UdpRendezvousMessage::Punch => {}
    }
    Ok(())
}

async fn send_udp_message(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    message: &UdpRendezvousMessage,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(message)?;
    socket.send_to(&payload, peer_addr).await?;
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    waiting_nodes: WaitingNodes,
    shared_secret: Option<String>,
) -> anyhow::Result<()> {
    match read_relay_hello(&mut stream).await? {
        RelayHello::Node {
            node_id,
            shared_secret: provided_secret,
        } => {
            tracing::info!(%node_id, "TCP relay node connected");
            let expected_secret = shared_secret
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("relay shared secret is not configured"))?;
            if expected_secret != provided_secret {
                anyhow::bail!("relay node authentication failed for {node_id}");
            }
            tracing::info!(%node_id, "TCP relay node authenticated");
            waiting_nodes
                .lock()
                .await
                .entry(node_id)
                .or_default()
                .push(WaitingTcpNode {
                    connected_at: Instant::now(),
                    stream,
                });
        }
        RelayHello::Client { node_id } => {
            tracing::info!(%node_id, "TCP relay client connected");
            let mut node_stream = wait_for_node_stream(waiting_nodes, &node_id).await?;
            tracing::info!(%node_id, "TCP relay paired client with node");
            let (client_to_node_bytes, node_to_client_bytes) =
                copy_bidirectional(&mut stream, &mut node_stream).await?;
            tracing::info!(
                %node_id,
                client_to_node_bytes,
                node_to_client_bytes,
                "TCP relay session finished"
            );
        }
    }
    Ok(())
}

async fn wait_for_node_stream(
    waiting_nodes: WaitingNodes,
    node_id: &str,
) -> anyhow::Result<TcpStream> {
    wait_for_node_stream_with_ttl(waiting_nodes, node_id, RELAY_NODE_SOCKET_TTL).await
}

async fn wait_for_node_stream_with_ttl(
    waiting_nodes: WaitingNodes,
    node_id: &str,
    ttl: std::time::Duration,
) -> anyhow::Result<TcpStream> {
    for _ in 0..50 {
        if let Some(stream) = {
            let mut waiting = waiting_nodes.lock().await;
            let mut selected = None;
            if let Some(nodes) = waiting.get_mut(node_id) {
                while let Some(node) = nodes.pop() {
                    let age = node.connected_at.elapsed();
                    if age <= ttl {
                        selected = Some(node.stream);
                        break;
                    }
                    tracing::info!(
                        %node_id,
                        age_ms = age.as_millis(),
                        ttl_ms = ttl.as_millis(),
                        "discarding expired TCP relay node socket"
                    );
                }
                if nodes.is_empty() {
                    waiting.remove(node_id);
                }
            }
            selected
        } {
            return Ok(stream);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    anyhow::bail!("no relay node connection available for {node_id}");
}

async fn handle_wss_upgrade(
    State(state): State<RelayState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if let Err(error) = handle_wss_connection(socket, state).await {
            tracing::warn!(%error, "wss relay connection failed");
        }
    })
}

async fn handle_wss_connection(mut socket: WebSocket, state: RelayState) -> anyhow::Result<()> {
    match read_wss_relay_hello(&mut socket).await? {
        RelayHello::Node {
            node_id,
            shared_secret: provided_secret,
        } => {
            tracing::info!(%node_id, "WSS relay node connected");
            let expected_secret = state
                .shared_secret
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("relay shared secret is not configured"))?;
            if expected_secret != provided_secret {
                anyhow::bail!("relay node authentication failed for {node_id}");
            }
            tracing::info!(%node_id, "WSS relay node authenticated");
            state
                .waiting_nodes
                .lock()
                .await
                .entry(node_id)
                .or_default()
                .push(WaitingWebSocketNode {
                    connected_at: Instant::now(),
                    socket,
                });
        }
        RelayHello::Client { node_id } => {
            tracing::info!(%node_id, "WSS relay client connected");
            let node_socket = wait_for_node_websocket(state.waiting_nodes, &node_id).await?;
            tracing::info!(%node_id, "WSS relay paired client with node");
            forward_wss_bidirectional(socket, node_socket).await?;
        }
    }
    Ok(())
}

async fn read_wss_relay_hello(socket: &mut WebSocket) -> anyhow::Result<RelayHello> {
    while let Some(message) = socket.recv().await {
        match message? {
            Message::Text(payload) => {
                return Ok(serde_json::from_str(payload.as_str())?);
            }
            Message::Close(_) => anyhow::bail!("websocket closed before relay hello"),
            _ => {}
        }
    }

    anyhow::bail!("missing relay hello")
}

async fn wait_for_node_websocket(
    waiting_nodes: WaitingWebSocketNodes,
    node_id: &str,
) -> anyhow::Result<WebSocket> {
    for _ in 0..50 {
        if let Some(socket) = {
            let mut waiting = waiting_nodes.lock().await;
            let mut selected = None;
            if let Some(nodes) = waiting.get_mut(node_id) {
                while let Some(node) = nodes.pop() {
                    let age = node.connected_at.elapsed();
                    if age <= RELAY_NODE_SOCKET_TTL {
                        selected = Some(node.socket);
                        break;
                    }
                    tracing::info!(
                        %node_id,
                        age_ms = age.as_millis(),
                        ttl_ms = RELAY_NODE_SOCKET_TTL.as_millis(),
                        "discarding expired WSS relay node socket"
                    );
                }
                if nodes.is_empty() {
                    waiting.remove(node_id);
                }
            }
            selected
        } {
            return Ok(socket);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    anyhow::bail!("no relay node websocket available for {node_id}");
}

async fn forward_wss_bidirectional(
    client_socket: WebSocket,
    node_socket: WebSocket,
) -> anyhow::Result<()> {
    let (mut client_tx, mut client_rx) = client_socket.split();
    let (mut node_tx, mut node_rx) = node_socket.split();

    let client_to_node = async {
        while let Some(message) = client_rx.next().await {
            match message? {
                Message::Binary(payload) => node_tx.send(Message::Binary(payload)).await?,
                Message::Close(frame) => {
                    let _ = node_tx.send(Message::Close(frame)).await;
                    break;
                }
                _ => {}
            }
        }
        anyhow::Ok(())
    };

    let node_to_client = async {
        while let Some(message) = node_rx.next().await {
            match message? {
                Message::Binary(payload) => client_tx.send(Message::Binary(payload)).await?,
                Message::Close(frame) => {
                    let _ = client_tx.send(Message::Close(frame)).await;
                    break;
                }
                _ => {}
            }
        }
        anyhow::Ok(())
    };

    tokio::select! {
        result = client_to_node => result?,
        result = node_to_client => result?,
    }

    Ok(())
}
