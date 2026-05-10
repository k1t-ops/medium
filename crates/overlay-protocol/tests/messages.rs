use overlay_protocol::{
    CandidateKind, DeviceCatalogResponse, DeviceRecord, EndpointKind, IceCandidate,
    IceCandidateKind, IceCredentials, IceSessionGrant, NodeEndpoint, PeerCandidate,
    PublishedService, RegisterNodeRequest, ServiceKind, SessionAuthorization, SessionOpenGrant,
    SessionOpenRequest, SshEndpoint,
};

#[test]
fn session_open_request_round_trips_as_json() {
    let req = SessionOpenRequest {
        service_id: "svc_openclaw".into(),
        requester_device_id: "dev_phone".into(),
        node_id: Some("node-1".into()),
    };

    let json = serde_json::to_string(&req).unwrap();
    let parsed: SessionOpenRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.service_id, "svc_openclaw");
    assert_eq!(parsed.requester_device_id, "dev_phone");
    assert_eq!(parsed.node_id.as_deref(), Some("node-1"));
    assert_eq!(ServiceKind::Http.as_str(), "http");
    assert_eq!(ServiceKind::Https.as_str(), "https");
    assert_eq!(EndpointKind::IceUdp.as_str(), "ice_udp");
}

#[test]
fn session_grant_round_trips_candidate_kinds() {
    let grant = SessionOpenGrant {
        session_id: "sess_1".into(),
        service_id: "svc_ssh".into(),
        node_id: "node-1".into(),
        relay_hint: Some("127.0.0.1:7001".into()),
        authorization: SessionAuthorization {
            token: "token".into(),
            expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .unwrap()
                .into(),
            candidates: vec![
                PeerCandidate {
                    kind: CandidateKind::DirectTcp,
                    addr: "198.51.100.10:17001".into(),
                    priority: 100,
                },
                PeerCandidate {
                    kind: CandidateKind::RelayTcp,
                    addr: "203.0.113.20:7001".into(),
                    priority: 10,
                },
            ],
            ice: None,
        },
    };

    let json = serde_json::to_string(&grant).unwrap();
    let parsed: SessionOpenGrant = serde_json::from_str(&json).unwrap();

    assert_eq!(
        parsed.authorization.candidates[0].kind.as_str(),
        "direct_tcp"
    );
    assert_eq!(
        parsed.authorization.candidates[1].kind.as_str(),
        "relay_tcp"
    );
    assert_eq!(parsed.authorization.candidates[0].priority, 100);
}

#[test]
fn session_grant_round_trips_wss_relay_candidate() {
    let grant = SessionOpenGrant {
        session_id: "session-wss".into(),
        service_id: "svc_web".into(),
        node_id: "node-1".into(),
        relay_hint: Some("wss://relay.example.com/medium/v1/relay".into()),
        authorization: SessionAuthorization {
            token: "token-wss".into(),
            expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .unwrap()
                .into(),
            candidates: vec![PeerCandidate {
                kind: CandidateKind::WssRelay,
                addr: "wss://relay.example.com/medium/v1/relay".into(),
                priority: 10,
            }],
            ice: None,
        },
    };

    let json = serde_json::to_string(&grant).unwrap();
    assert!(json.contains(r#""kind":"wss_relay""#));

    let parsed: SessionOpenGrant = serde_json::from_str(&json).unwrap();

    assert_eq!(
        parsed.authorization.candidates[0].kind,
        CandidateKind::WssRelay
    );
    assert_eq!(
        parsed.authorization.candidates[0].addr,
        "wss://relay.example.com/medium/v1/relay"
    );
}

#[test]
fn session_grant_round_trips_optional_ice_section() {
    let grant = SessionOpenGrant {
        session_id: "session-ice".into(),
        service_id: "svc_web".into(),
        node_id: "node-1".into(),
        relay_hint: Some("wss://relay.example.com/medium/v1/relay".into()),
        authorization: SessionAuthorization {
            token: "token-ice".into(),
            expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .unwrap()
                .into(),
            candidates: vec![PeerCandidate {
                kind: CandidateKind::WssRelay,
                addr: "wss://relay.example.com/medium/v1/relay".into(),
                priority: 10,
            }],
            ice: Some(IceSessionGrant {
                credentials: IceCredentials {
                    ufrag: "ufrag123".into(),
                    pwd: "pwd456".into(),
                    expires_at: chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                        .unwrap()
                        .into(),
                },
                candidates: vec![IceCandidate {
                    foundation: "relay-1".into(),
                    component: 1,
                    transport: "udp".into(),
                    priority: 10,
                    addr: "203.0.113.10".into(),
                    port: 3478,
                    kind: IceCandidateKind::Relay,
                    related_addr: None,
                    related_port: None,
                }],
            }),
        },
    };

    let json = serde_json::to_string(&grant).unwrap();
    assert!(json.contains(r#""ice""#));
    assert!(json.contains(r#""kind":"relay""#));

    let parsed: SessionOpenGrant = serde_json::from_str(&json).unwrap();
    let ice = parsed.authorization.ice.unwrap();

    assert_eq!(ice.credentials.ufrag, "ufrag123");
    assert_eq!(ice.candidates[0].kind, IceCandidateKind::Relay);
    assert_eq!(ice.candidates[0].port, 3478);
}

#[test]
fn device_catalog_round_trips_as_json() {
    let catalog = DeviceCatalogResponse {
        devices: vec![DeviceRecord {
            id: "node-1".into(),
            name: "node-1".into(),
            ssh: Some(SshEndpoint {
                service_id: "svc_ssh".into(),
                host: "127.0.0.1".into(),
                port: 2222,
                user: "overlay".into(),
            }),
            services: vec![],
        }],
    };

    let json = serde_json::to_string(&catalog).unwrap();
    let parsed: DeviceCatalogResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.devices.len(), 1);
    assert_eq!(parsed.devices[0].name, "node-1");
    assert_eq!(
        parsed.devices[0].ssh.as_ref().unwrap().service_id,
        "svc_ssh"
    );
    assert_eq!(parsed.devices[0].ssh.as_ref().unwrap().port, 2222);
}

#[test]
fn register_node_request_round_trips_versioned_components() {
    let request = RegisterNodeRequest {
        node_id: "node-1".into(),
        node_label: "Node".into(),
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
            label: Some("Node SSH".into()),
            target: "127.0.0.1:2222".into(),
            user_name: Some("overlay".into()),
        }],
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: RegisterNodeRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.node_label, "Node");
    assert_eq!(parsed.endpoints[0].kind.as_str(), "tcp_proxy");
    assert_eq!(parsed.services[0].schema_version, 1);
    assert_eq!(parsed.services[0].user_name.as_deref(), Some("overlay"));
}
