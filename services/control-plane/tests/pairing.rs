use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use overlay_crypto::issue_bootstrap_code;
use overlay_protocol::{
    BootstrapInviteResponse, ServiceCertificateRequest, ServiceCertificateResponse,
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
struct LegacyBootstrapCodeResponse {
    code: String,
}

#[test]
fn bootstrap_code_has_expected_prefix() {
    let code = issue_bootstrap_code();
    assert!(code.starts_with("ovr-"));
    assert!(code.len() > 12);
}

#[tokio::test]
async fn bootstrap_route_returns_medium_join_invite() {
    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry: control_plane::registry::RegistryStore::in_memory()
            .await
            .unwrap(),
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        service_ca_cert_pem: None,
        service_ca_key_pem: None,
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: None,
    });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/bootstrap-code")
                .header(header::HOST, "control.example.test")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: BootstrapInviteResponse = serde_json::from_slice(&body).unwrap();
    let legacy_payload: LegacyBootstrapCodeResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(payload.expires_at, None);
    assert!(payload.bootstrap_token.starts_with("ovr-"));
    assert_eq!(payload.security, "pinned-tls");
    assert_eq!(
        payload.control_pin,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(legacy_payload.code, payload.bootstrap_token);
    assert_eq!(
        payload.invite,
        format!(
            "medium://join?v=1&control=https://control.example.test&security=pinned-tls&control_pin={}&client_secret=client-secret",
            payload.control_pin
        )
    );
    assert!(!payload.invite.contains("token="));
}

#[tokio::test]
async fn bootstrap_route_ignores_invalid_forwarded_headers() {
    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry: control_plane::registry::RegistryStore::in_memory()
            .await
            .unwrap(),
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .into(),
        service_ca_cert_pem: None,
        service_ca_key_pem: None,
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: None,
    });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/bootstrap-code")
                .header(header::HOST, "control.example.test/poison")
                .header("x-forwarded-proto", "javascript")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: BootstrapInviteResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        payload.invite,
        format!(
            "medium://join?v=1&control=http://127.0.0.1:8080&security=pinned-tls&control_pin={}&client_secret=client-secret",
            payload.control_pin
        )
    );
}

#[tokio::test]
async fn service_certificate_route_issues_leaf_from_medium_ca() {
    let ca = overlay_crypto::issue_medium_service_ca().unwrap();
    let app = control_plane::app::build_router(control_plane::state::ControlState {
        registry: control_plane::registry::RegistryStore::in_memory()
            .await
            .unwrap(),
        shared_secret: "local-test-secret".into(),
        client_secret: "client-secret".into(),
        control_pin: String::new(),
        service_ca_cert_pem: Some(ca.cert_pem),
        service_ca_key_pem: Some(ca.key_pem),
        relay_addr: None,
        wss_relay_url: None,
        ice_relay_addr: None,
        ssh_ca_key_path: None,
    });
    let body = serde_json::to_vec(&ServiceCertificateRequest {
        node_id: "node-1".into(),
        hostnames: vec!["hello.medium".into()],
        shared_secret: "local-test-secret".into(),
    })
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/nodes/service-certificate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: ServiceCertificateResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(payload.key_pem.contains("BEGIN PRIVATE KEY"));
}
