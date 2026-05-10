use overlay_crypto::verify_session_token;
use overlay_protocol::{
    CandidateKind, EndpointKind, IceCandidateKind, NodeEndpoint, PublishedService,
    RegisterNodeRequest, ServiceKind, SessionOpenRequest,
};

#[tokio::test]
async fn session_grant_contains_signed_token_and_candidate() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![
                NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: "127.0.0.1:17001".into(),
                    priority: 10,
                },
                NodeEndpoint {
                    kind: EndpointKind::IceUdp,
                    schema_version: 1,
                    addr: "198.51.100.20:17002".into(),
                    priority: 100,
                },
            ],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: Some("Node SSH".into()),
                target: "127.0.0.1:2222".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_ssh".into(),
            requester_device_id: "macbook".into(),
            node_id: None,
        },
        &settings,
    )
    .await
    .unwrap();

    assert_eq!(grant.authorization.candidates[0].addr, "127.0.0.1:17001");
    assert!(grant.relay_hint.is_none());
    let claims = verify_session_token("local-secret", &grant.authorization.token).unwrap();
    assert_eq!(claims.service_id, "svc_ssh");
    assert_eq!(claims.node_id, grant.node_id);
}

#[tokio::test]
async fn session_grant_includes_relay_candidate_when_configured() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![
                NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: "127.0.0.1:17001".into(),
                    priority: 10,
                },
                NodeEndpoint {
                    kind: EndpointKind::IceUdp,
                    schema_version: 1,
                    addr: "198.51.100.20:17002".into(),
                    priority: 100,
                },
            ],
            services: vec![PublishedService {
                id: "svc_ssh".into(),
                kind: ServiceKind::Ssh,
                schema_version: 1,
                label: Some("Node SSH".into()),
                target: "127.0.0.1:2222".into(),
                user_name: Some("overlay".into()),
            }],
        })
        .await
        .unwrap();

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: Some("127.0.0.1:7001".into()),
        wss_relay_url: None,
        ice_relay_addr: None,
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_ssh".into(),
            requester_device_id: "macbook".into(),
            node_id: None,
        },
        &settings,
    )
    .await
    .unwrap();

    assert_eq!(grant.authorization.candidates.len(), 2);
    assert_eq!(
        grant.authorization.candidates[0].kind,
        CandidateKind::DirectTcp
    );
    assert_eq!(
        grant.authorization.candidates[1].kind,
        CandidateKind::RelayTcp
    );
    assert_eq!(grant.authorization.candidates[1].addr, "127.0.0.1:7001");
    assert_eq!(grant.relay_hint.as_deref(), Some("127.0.0.1:7001"));

    let ice = grant
        .authorization
        .ice
        .expect("ICE should inherit relay_addr as rendezvous by default");
    assert_eq!(ice.candidates.len(), 2);
    assert_eq!(ice.candidates[0].kind, IceCandidateKind::Srflx);
    assert_eq!(ice.candidates[1].kind, IceCandidateKind::Relay);
    assert_eq!(ice.candidates[1].addr, "127.0.0.1");
    assert_eq!(ice.candidates[1].port, 7001);
}

#[tokio::test]
async fn session_grant_includes_wss_relay_candidate_when_configured() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
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
        })
        .await
        .unwrap();

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: Some("127.0.0.1:7001".into()),
        wss_relay_url: Some("wss://relay.example.com/medium/v1/relay".into()),
        ice_relay_addr: None,
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_ssh".into(),
            requester_device_id: "macbook".into(),
            node_id: None,
        },
        &settings,
    )
    .await
    .unwrap();

    assert_eq!(
        grant
            .authorization
            .candidates
            .iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>(),
        vec![
            CandidateKind::DirectTcp,
            CandidateKind::RelayTcp,
            CandidateKind::WssRelay,
        ]
    );
    assert_eq!(
        grant.authorization.candidates[2].addr,
        "wss://relay.example.com/medium/v1/relay"
    );
}

#[tokio::test]
async fn session_grant_includes_optional_ice_relay_section_when_configured() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![
                NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: "127.0.0.1:17001".into(),
                    priority: 10,
                },
                NodeEndpoint {
                    kind: EndpointKind::IceUdp,
                    schema_version: 1,
                    addr: "198.51.100.20:17002".into(),
                    priority: 100,
                },
            ],
            services: vec![PublishedService {
                id: "svc_web".into(),
                kind: ServiceKind::Http,
                schema_version: 1,
                label: Some("Web".into()),
                target: "127.0.0.1:8080".into(),
                user_name: None,
            }],
        })
        .await
        .unwrap();

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: Some("127.0.0.1:7001".into()),
        wss_relay_url: Some("wss://relay.example.com/medium/v1/relay".into()),
        ice_relay_addr: Some("203.0.113.10:3478".into()),
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_web".into(),
            requester_device_id: "android".into(),
            node_id: None,
        },
        &settings,
    )
    .await
    .unwrap();

    let ice = grant.authorization.ice.expect("ice should be configured");
    assert!(!ice.credentials.ufrag.is_empty());
    assert!(!ice.credentials.pwd.is_empty());
    assert_eq!(ice.candidates.len(), 2);
    assert_eq!(ice.candidates[0].kind.as_str(), "srflx");
    assert_eq!(ice.candidates[0].addr, "198.51.100.20");
    assert_eq!(ice.candidates[0].port, 17002);
    assert_eq!(ice.candidates[1].kind.as_str(), "relay");
    assert_eq!(ice.candidates[1].addr, "203.0.113.10");
    assert_eq!(ice.candidates[1].port, 3478);
    assert_eq!(ice.candidates[0].transport, "udp");
    assert_eq!(ice.candidates[0].component, 1);
}

#[tokio::test]
async fn session_grant_preserves_all_registered_ice_udp_endpoints() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    store
        .register_node(&RegisterNodeRequest {
            node_id: "node-1".into(),
            node_label: "Node".into(),
            endpoints: vec![
                NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: "127.0.0.1:17001".into(),
                    priority: 10,
                },
                NodeEndpoint {
                    kind: EndpointKind::IceUdp,
                    schema_version: 1,
                    addr: "192.168.1.44:17002".into(),
                    priority: 300,
                },
                NodeEndpoint {
                    kind: EndpointKind::IceUdp,
                    schema_version: 1,
                    addr: "198.51.100.20:17002".into(),
                    priority: 100,
                },
            ],
            services: vec![PublishedService {
                id: "svc_web".into(),
                kind: ServiceKind::Http,
                schema_version: 1,
                label: Some("Web".into()),
                target: "127.0.0.1:8080".into(),
                user_name: None,
            }],
        })
        .await
        .unwrap();

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: Some("127.0.0.1:7001".into()),
        wss_relay_url: None,
        ice_relay_addr: None,
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_web".into(),
            requester_device_id: "android".into(),
            node_id: None,
        },
        &settings,
    )
    .await
    .unwrap();

    let ice = grant.authorization.ice.expect("ice should be configured");
    let candidates = ice
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.kind,
                candidate.addr.as_str(),
                candidate.port,
                candidate.priority,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        candidates,
        vec![
            (IceCandidateKind::Host, "192.168.1.44", 17002, 300),
            (IceCandidateKind::Srflx, "198.51.100.20", 17002, 100),
            (IceCandidateKind::Relay, "127.0.0.1", 7001, 10),
        ]
    );
}

#[tokio::test]
async fn session_grant_can_target_node_scoped_service_id() {
    let store = control_plane::registry::RegistryStore::in_memory()
        .await
        .unwrap();
    for (node_id, addr) in [
        ("node-1", "127.0.0.1:17001"),
        ("studio-smiley", "192.168.1.126:17001"),
    ] {
        store
            .register_node(&RegisterNodeRequest {
                node_id: node_id.into(),
                node_label: node_id.into(),
                endpoints: vec![NodeEndpoint {
                    kind: EndpointKind::TcpProxy,
                    schema_version: 1,
                    addr: addr.into(),
                    priority: 10,
                }],
                services: vec![PublishedService {
                    id: "svc_ssh".into(),
                    kind: ServiceKind::Ssh,
                    schema_version: 1,
                    label: None,
                    target: "127.0.0.1:22".into(),
                    user_name: Some("overlay".into()),
                }],
            })
            .await
            .unwrap();
    }

    let settings = control_plane::routes::sessions::SessionSettings {
        registry: store,
        shared_secret: "local-secret".into(),
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
    };
    let grant = control_plane::routes::sessions::issue_session_grant(
        &SessionOpenRequest {
            service_id: "svc_ssh".into(),
            requester_device_id: "macbook".into(),
            node_id: Some("studio-smiley".into()),
        },
        &settings,
    )
    .await
    .unwrap();

    assert_eq!(grant.node_id, "studio-smiley");
    assert_eq!(
        grant.authorization.candidates[0].addr,
        "192.168.1.126:17001"
    );
}
