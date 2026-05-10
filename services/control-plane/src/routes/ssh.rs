use crate::state::ControlState;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use overlay_protocol::{SshCertificateRequest, SshCertificateResponse};
use std::path::{Path, PathBuf};
use std::process::Command;

const SSH_CERT_VALID_SECONDS: u64 = 300;

pub async fn ssh_ca_public_key(State(state): State<ControlState>) -> impl IntoResponse {
    let Some(ca_key_path) = state.ssh_ca_key_path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let ca_public_key_path = PathBuf::from(ca_key_path).with_extension("pub");
    match std::fs::read_to_string(ca_public_key_path) {
        Ok(public_key) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            public_key,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn issue_ssh_certificate(
    State(state): State<ControlState>,
    Json(request): Json<SshCertificateRequest>,
) -> Result<Json<SshCertificateResponse>, StatusCode> {
    if request.client_secret != state.client_secret {
        return Err(StatusCode::FORBIDDEN);
    }
    let route = match request.node_id.as_deref() {
        Some(node_id) => {
            state
                .registry
                .resolve_node_service_route(node_id, &request.service_id)
                .await
        }
        None => {
            state
                .registry
                .resolve_service_route(&request.service_id)
                .await
        }
    }
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let user_name = route.user_name.ok_or(StatusCode::BAD_REQUEST)?;
    let ca_key_path = state.ssh_ca_key_path.ok_or(StatusCode::NOT_FOUND)?;

    let certificate = sign_ssh_public_key(&ca_key_path, &user_name, &request.public_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SshCertificateResponse {
        certificate,
        user_name,
        valid_seconds: SSH_CERT_VALID_SECONDS,
    }))
}

fn sign_ssh_public_key(
    ca_key_path: impl AsRef<Path>,
    principal: &str,
    public_key: &str,
) -> anyhow::Result<String> {
    let public_key_path = temp_public_key_path();
    let cert_path = cert_path_for_public_key(&public_key_path);
    std::fs::write(&public_key_path, public_key)?;

    let key_id = format!("medium-{}", uuid::Uuid::new_v4().simple());
    let output = Command::new("ssh-keygen")
        .args([
            "-q",
            "-s",
            &ca_key_path.as_ref().display().to_string(),
            "-I",
            &key_id,
            "-n",
            principal,
            "-V",
            "+5m",
            &public_key_path.display().to_string(),
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ssh-keygen failed to sign SSH certificate: {stderr}");
    }

    let certificate = std::fs::read_to_string(&cert_path)?;
    let _ = std::fs::remove_file(public_key_path);
    let _ = std::fs::remove_file(cert_path);
    Ok(certificate)
}

fn temp_public_key_path() -> PathBuf {
    std::env::temp_dir().join(format!("medium-ssh-{}.pub", uuid::Uuid::new_v4().simple()))
}

fn cert_path_for_public_key(public_key_path: &Path) -> PathBuf {
    let stem = public_key_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("medium-ssh");
    public_key_path.with_file_name(format!("{stem}-cert.pub"))
}
