use crate::state::ControlState;
use axum::{Json, extract::Query, http::StatusCode};
use chrono::{Duration, Utc};
use overlay_crypto::{SESSION_TOKEN_TTL_MINUTES, issue_session_token};
use overlay_protocol::{
    CandidateKind, IceCandidate, IceCandidateKind, IceCredentials, IceSessionGrant, PeerCandidate,
    SessionAuthorization, SessionOpenGrant, SessionOpenRequest,
};
use std::net::{IpAddr, SocketAddr};

pub async fn open_session(
    axum::extract::State(state): axum::extract::State<ControlState>,
    Query(request): Query<SessionOpenRequest>,
) -> Result<Json<SessionOpenGrant>, StatusCode> {
    let grant = issue_session_grant(
        &request,
        &SessionSettings {
            registry: state.registry.clone(),
            shared_secret: state.shared_secret.clone(),
            relay_addr: state.relay_addr.clone(),
            wss_relay_url: state.wss_relay_url.clone(),
            ice_relay_addr: state.ice_relay_addr.clone(),
        },
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(grant))
}

#[derive(Debug, Clone)]
pub struct SessionSettings {
    pub registry: crate::registry::RegistryStore,
    pub shared_secret: String,
    pub relay_addr: Option<String>,
    pub wss_relay_url: Option<String>,
    pub ice_relay_addr: Option<String>,
}

pub async fn issue_session_grant(
    request: &SessionOpenRequest,
    settings: &SessionSettings,
) -> anyhow::Result<SessionOpenGrant> {
    let route = match request.node_id.as_deref() {
        Some(node_id) => {
            settings
                .registry
                .resolve_node_service_route(node_id, &request.service_id)
                .await?
        }
        None => {
            settings
                .registry
                .resolve_service_route(&request.service_id)
                .await?
        }
    };
    let session_id = format!("sess_{}", uuid::Uuid::new_v4().simple());
    let token = issue_session_token(
        &settings.shared_secret,
        &session_id,
        &request.service_id,
        &route.node_id,
    )?;

    let mut candidates = vec![PeerCandidate {
        kind: CandidateKind::DirectTcp,
        addr: route.tcp_addr,
        priority: 100,
    }];
    if let Some(relay_addr) = &settings.relay_addr {
        candidates.push(PeerCandidate {
            kind: CandidateKind::RelayTcp,
            addr: relay_addr.clone(),
            priority: 10,
        });
    }
    if let Some(wss_relay_url) = &settings.wss_relay_url {
        candidates.push(PeerCandidate {
            kind: CandidateKind::WssRelay,
            addr: wss_relay_url.clone(),
            priority: 10,
        });
    }
    let ice_relay_addr = settings
        .ice_relay_addr
        .as_deref()
        .or(settings.relay_addr.as_deref());
    let ice = build_ice_grant(&route.ice_udp_endpoints, ice_relay_addr)?;

    Ok(SessionOpenGrant {
        session_id,
        service_id: request.service_id.clone(),
        node_id: route.node_id,
        relay_hint: settings.relay_addr.clone(),
        authorization: SessionAuthorization {
            token,
            expires_at: Utc::now() + Duration::minutes(SESSION_TOKEN_TTL_MINUTES),
            candidates,
            ice,
        },
    })
}

fn build_ice_grant(
    node_udp_endpoints: &[crate::registry::ServiceEndpoint],
    relay_candidate_addr: Option<&str>,
) -> anyhow::Result<Option<IceSessionGrant>> {
    let mut candidates = Vec::new();
    for (index, endpoint) in node_udp_endpoints.iter().enumerate() {
        let (addr, port) = parse_host_port(&endpoint.addr)?;
        let kind = classify_node_udp_candidate(&addr);
        candidates.push(IceCandidate {
            foundation: format!("{}-udp-{}", kind.as_str(), index + 1),
            component: 1,
            transport: "udp".into(),
            priority: endpoint.priority.max(0) as u32,
            addr,
            port,
            kind,
            related_addr: None,
            related_port: None,
        });
    }
    if let Some(relay_candidate_addr) = relay_candidate_addr {
        let (addr, port) = parse_host_port(relay_candidate_addr)?;
        candidates.push(IceCandidate {
            foundation: "relay-udp-1".into(),
            component: 1,
            transport: "udp".into(),
            priority: 10,
            addr,
            port,
            kind: IceCandidateKind::Relay,
            related_addr: None,
            related_port: None,
        });
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    Ok(IceSessionGrant {
        credentials: IceCredentials {
            ufrag: format!("m{}", uuid::Uuid::new_v4().simple()),
            pwd: format!("m{}", uuid::Uuid::new_v4().simple()),
            expires_at: Utc::now() + Duration::minutes(SESSION_TOKEN_TTL_MINUTES),
        },
        candidates,
    }
    .into())
}

fn parse_host_port(value: &str) -> anyhow::Result<(String, u16)> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("ICE relay address must be host:port"))?;
    if host.trim().is_empty() {
        anyhow::bail!("ICE relay host must not be empty");
    }
    let port = port.parse::<u16>()?;
    Ok((host.trim_matches(['[', ']']).to_string(), port))
}

fn classify_node_udp_candidate(addr: &str) -> IceCandidateKind {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip))
            if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() =>
        {
            IceCandidateKind::Host
        }
        Ok(IpAddr::V6(ip))
            if ip.is_loopback()
                || ip.is_unicast_link_local()
                || is_ipv6_unique_local(&ip)
                || ip.is_unspecified() =>
        {
            IceCandidateKind::Host
        }
        Ok(_) => IceCandidateKind::Srflx,
        Err(_) => IceCandidateKind::Srflx,
    }
}

fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}
