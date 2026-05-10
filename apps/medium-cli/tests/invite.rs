use medium_cli::client_api;
use medium_cli::state::invite::{Invite, parse_invite};

#[test]
fn parses_versioned_join_invite() {
    let invite =
        parse_invite("medium://join?v=1&control=http://127.0.0.1:7777&security=pinned-tls&control_pin=sha256:abc123")
            .unwrap();

    assert_eq!(invite.version, 1);
    assert_eq!(invite.control_url, "http://127.0.0.1:7777");
    assert_eq!(invite.security, "pinned-tls");
    assert_eq!(invite.control_pin, "sha256:abc123");
    assert_eq!(invite.client_secret, None);
}

#[test]
fn rejects_invite_with_unknown_scheme() {
    assert!(parse_invite("overlay://join?v=1").is_err());
}

#[test]
fn rejects_invite_with_unsupported_version() {
    assert!(
        parse_invite("medium://join?v=2&control=http://127.0.0.1:7777&security=pinned-tls&control_pin=sha256:abc123")
            .is_err()
    );
}

#[test]
fn rejects_invite_without_control_pin() {
    let error = parse_invite("medium://join?v=1&control=http://127.0.0.1:7777&security=pinned-tls")
        .unwrap_err();

    assert!(error.to_string().contains("control pin"));
}

#[test]
fn rejects_invite_with_empty_control_pin() {
    let error = parse_invite(
        "medium://join?v=1&control=http://127.0.0.1:7777&security=pinned-tls&control_pin=",
    )
    .unwrap_err();

    assert!(error.to_string().contains("control pin"));
}

#[test]
fn rejects_invite_with_unsupported_security() {
    let error = parse_invite(
        "medium://join?v=1&control=http://127.0.0.1:7777&security=none&control_pin=sha256:abc123",
    )
    .unwrap_err();

    assert!(error.to_string().contains("unsupported invite security"));
}

#[tokio::test]
async fn join_rejects_malformed_control_url() {
    let invite = Invite {
        version: 1,
        control_url: "not-a-url".to_string(),
        security: "pinned-tls".to_string(),
        control_pin: "sha256:abc123".to_string(),
        client_secret: None,
    };

    assert!(client_api::join(&invite).await.is_err());
}
