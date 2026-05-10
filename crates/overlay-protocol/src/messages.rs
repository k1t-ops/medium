use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Http,
    Https,
    Ssh,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ssh => "ssh",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    TcpProxy,
    IceUdp,
}

impl EndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpProxy => "tcp_proxy",
            Self::IceUdp => "ice_udp",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    DirectTcp,
    RelayTcp,
    WssRelay,
}

impl CandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectTcp => "direct_tcp",
            Self::RelayTcp => "relay_tcp",
            Self::WssRelay => "wss_relay",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpenRequest {
    pub service_id: String,
    pub requester_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpenGrant {
    pub session_id: String,
    pub service_id: String,
    pub node_id: String,
    pub relay_hint: Option<String>,
    pub authorization: SessionAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedService {
    pub id: String,
    pub kind: ServiceKind,
    pub schema_version: u32,
    pub label: Option<String>,
    pub target: String,
    pub user_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub kind: EndpointKind,
    pub schema_version: u32,
    pub addr: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    pub node_id: String,
    pub node_label: String,
    pub endpoints: Vec<NodeEndpoint>,
    pub services: Vec<PublishedService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCertificateRequest {
    pub node_id: String,
    pub hostnames: Vec<String>,
    pub shared_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCertificateResponse {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCertificateRequest {
    pub service_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub requester_device_id: String,
    pub public_key: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCertificateResponse {
    pub certificate: String,
    pub user_name: String,
    pub valid_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCatalogResponse {
    pub devices: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapInviteResponse {
    pub code: String,
    pub invite: String,
    pub bootstrap_token: String,
    pub security: String,
    pub control_pin: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub ssh: Option<SshEndpoint>,
    #[serde(default)]
    pub services: Vec<PublishedService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshEndpoint {
    pub service_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCandidate {
    #[serde(default = "default_candidate_kind")]
    pub kind: CandidateKind,
    pub addr: String,
    #[serde(default)]
    pub priority: i32,
}

fn default_candidate_kind() -> CandidateKind {
    CandidateKind::DirectTcp
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IceCandidateKind {
    Host,
    Srflx,
    Relay,
}

impl IceCandidateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Srflx => "srflx",
            Self::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub foundation: String,
    pub component: u16,
    pub transport: String,
    pub priority: u32,
    pub addr: String,
    pub port: u16,
    pub kind: IceCandidateKind,
    pub related_addr: Option<String>,
    pub related_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCredentials {
    pub ufrag: String,
    pub pwd: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceSessionGrant {
    pub credentials: IceCredentials,
    pub candidates: Vec<IceCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthorization {
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub candidates: Vec<PeerCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice: Option<IceSessionGrant>,
}
