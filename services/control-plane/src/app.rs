use axum::{
    Router,
    routing::{get, post},
};

use crate::routes::{
    ca::{issue_service_certificate, medium_ca},
    devices::list_devices,
    health::health,
    nodes::register_node,
    pairing::create_bootstrap_code,
    sessions::open_session,
    ssh::{issue_ssh_certificate, ssh_ca_public_key},
};
use crate::state::ControlState;

pub fn build_router(state: ControlState) -> Router {
    let wss_relay = relay::wss_router(Some(state.shared_secret.clone()));

    Router::new()
        .route("/health", get(health))
        .route("/api/bootstrap-code", get(create_bootstrap_code))
        .route("/api/devices", get(list_devices))
        .route("/api/medium-ca.pem", get(medium_ca))
        .route(
            "/api/nodes/service-certificate",
            post(issue_service_certificate),
        )
        .route("/api/nodes/register", post(register_node))
        .route("/api/sessions/open", get(open_session))
        .route("/api/ssh/ca.pub", get(ssh_ca_public_key))
        .route("/api/ssh/certificate", post(issue_ssh_certificate))
        .with_state(state)
        .merge(wss_relay)
}
