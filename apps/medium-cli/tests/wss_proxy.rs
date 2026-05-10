use overlay_protocol::{
    CandidateKind, IceCandidate, IceCandidateKind, IceCredentials, IceSessionGrant, PeerCandidate,
    SessionAuthorization, SessionOpenGrant,
};

#[test]
fn candidate_order_prefers_direct_then_wss_relay() {
    let grant = SessionOpenGrant {
        session_id: "session-1".into(),
        service_id: "svc_web".into(),
        node_id: "node-1".into(),
        relay_hint: Some("wss://relay.example.com/medium/v1/relay".into()),
        authorization: SessionAuthorization {
            token: "token".into(),
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            candidates: vec![
                PeerCandidate {
                    kind: CandidateKind::WssRelay,
                    addr: "wss://relay.example.com/medium/v1/relay".into(),
                    priority: 10,
                },
                PeerCandidate {
                    kind: CandidateKind::DirectTcp,
                    addr: "127.0.0.1:17001".into(),
                    priority: 100,
                },
            ],
            ice: None,
        },
    };

    let ordered = medium_session::ordered_legacy_candidates_for_mode(
        &grant,
        medium_session::TransportMode::Auto,
    )
    .into_iter()
    .map(|candidate| candidate.kind)
    .collect::<Vec<_>>();

    assert_eq!(
        ordered,
        vec![CandidateKind::DirectTcp, CandidateKind::WssRelay]
    );
}

#[test]
fn candidate_order_ignores_optional_ice_section_for_legacy_connectors() {
    let grant = SessionOpenGrant {
        session_id: "session-ice".into(),
        service_id: "svc_web".into(),
        node_id: "node-1".into(),
        relay_hint: Some("wss://relay.example.com/medium/v1/relay".into()),
        authorization: SessionAuthorization {
            token: "token".into(),
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            candidates: vec![
                PeerCandidate {
                    kind: CandidateKind::WssRelay,
                    addr: "wss://relay.example.com/medium/v1/relay".into(),
                    priority: 10,
                },
                PeerCandidate {
                    kind: CandidateKind::DirectTcp,
                    addr: "127.0.0.1:17001".into(),
                    priority: 100,
                },
            ],
            ice: Some(IceSessionGrant {
                credentials: IceCredentials {
                    ufrag: "ufrag".into(),
                    pwd: "pwd".into(),
                    expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
                },
                candidates: vec![IceCandidate {
                    foundation: "relay-udp-1".into(),
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

    let ordered = medium_session::ordered_legacy_candidates_for_mode(
        &grant,
        medium_session::TransportMode::Auto,
    )
    .into_iter()
    .map(|candidate| candidate.kind)
    .collect::<Vec<_>>();

    assert_eq!(
        ordered,
        vec![CandidateKind::DirectTcp, CandidateKind::WssRelay]
    );
}
