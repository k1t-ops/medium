use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header, uri::Authority},
};
use overlay_protocol::BootstrapInviteResponse;
use std::str::FromStr;

use crate::state::ControlState;

const DEFAULT_CONTROL_AUTHORITY: &str = "127.0.0.1:8080";

pub async fn create_bootstrap_code(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Json<BootstrapInviteResponse> {
    let control_url = control_url(&headers);
    Json(issue_bootstrap_invite(
        &control_url,
        &state.control_pin,
        &state.client_secret,
    ))
}

fn issue_bootstrap_invite(
    control_url: &str,
    configured_control_pin: &str,
    client_secret: &str,
) -> BootstrapInviteResponse {
    let bootstrap_token = overlay_crypto::issue_bootstrap_code();
    let control_pin = if configured_control_pin.is_empty() {
        overlay_crypto::issue_bootstrap_code().replacen("ovr-", "sha256:", 1)
    } else {
        configured_control_pin.to_string()
    };
    let invite = format!(
        "medium://join?v=1&control={control_url}&security=pinned-tls&control_pin={control_pin}&client_secret={client_secret}"
    );

    BootstrapInviteResponse {
        code: bootstrap_token.clone(),
        invite,
        bootstrap_token,
        security: "pinned-tls".to_string(),
        control_pin,
        expires_at: None,
    }
}

fn control_url(headers: &HeaderMap) -> String {
    let scheme = forwarded_scheme(headers);
    let authority =
        forwarded_authority(headers).unwrap_or_else(|| DEFAULT_CONTROL_AUTHORITY.to_string());

    format!("{scheme}://{authority}")
}

fn forwarded_scheme(headers: &HeaderMap) -> &'static str {
    match headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
    {
        Some(value) if value.eq_ignore_ascii_case("https") => "https",
        Some(value) if value.eq_ignore_ascii_case("http") => "http",
        _ => "http",
    }
}

fn forwarded_authority(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::HOST)?.to_str().ok()?;
    let authority = raw.split(',').next()?.trim();
    let authority = Authority::from_str(authority).ok()?;

    Some(authority.as_str().to_string())
}
