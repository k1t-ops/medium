use crate::app;
use crate::state::AppState;
use crate::state::invite::Invite;
use anyhow::{Context, bail};
use overlay_protocol::{
    DeviceCatalogResponse, SessionOpenGrant, SessionOpenRequest, SshCertificateRequest,
    SshCertificateResponse,
};
use overlay_transport::pinned_http;
use serde::Deserialize;

#[derive(Deserialize)]
struct BootstrapCodeResponse {
    #[serde(default)]
    invite: String,
    #[serde(default)]
    bootstrap_token: String,
    #[serde(default)]
    code: String,
}

pub async fn pair(server_url: &str, device_name: &str) -> anyhow::Result<AppState> {
    let server_url = server_url.trim_end_matches('/');
    let url = format!("{server_url}/api/bootstrap-code");
    let response = reqwest::get(url).await?.error_for_status()?;
    let payload: BootstrapCodeResponse = response.json().await?;
    let bootstrap_code = if !payload.bootstrap_token.is_empty() {
        payload.bootstrap_token
    } else if !payload.code.is_empty() {
        payload.code
    } else if !payload.invite.is_empty() {
        String::new()
    } else {
        bail!("bootstrap response is missing a token");
    };

    Ok(AppState {
        server_url: server_url.to_string(),
        device_name: device_name.to_string(),
        bootstrap_code,
        invite_version: 0,
        security: String::new(),
        control_pin: String::new(),
        client_secret: String::new(),
    })
}

pub async fn join(invite: &Invite) -> anyhow::Result<AppState> {
    let server_url = normalize_control_url(&invite.control_url)?;

    Ok(AppState {
        server_url,
        device_name: local_device_name(),
        bootstrap_code: String::new(),
        invite_version: invite.version,
        security: invite.security.clone(),
        control_pin: invite.control_pin.clone(),
        client_secret: invite.client_secret.clone().unwrap_or_default(),
    })
}

pub async fn fetch_devices(state: &AppState) -> anyhow::Result<DeviceCatalogResponse> {
    let url = format!("{}/api/devices", state.server_url.trim_end_matches('/'));
    if state.security == "pinned-tls" {
        return pinned_http::get_json(&url, &state.control_pin).await;
    }

    let response = reqwest::get(url).await?.error_for_status()?;
    Ok(response.json().await?)
}

pub async fn fetch_medium_ca(state: &AppState) -> anyhow::Result<String> {
    let url = format!(
        "{}/api/medium-ca.pem",
        state.server_url.trim_end_matches('/')
    );
    let bytes = if state.security == "pinned-tls" {
        pinned_http::get_bytes(&url, &state.control_pin).await?
    } else {
        reqwest::get(url)
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec()
    };
    let pem = String::from_utf8(bytes).context("Medium service CA response is not UTF-8")?;
    if !pem.contains("BEGIN CERTIFICATE") {
        bail!("Medium service CA response is not a PEM certificate");
    }
    Ok(pem)
}

pub async fn fetch_ssh_ca_public_key(
    control_url: &str,
    control_pin: &str,
) -> anyhow::Result<String> {
    let server_url = normalize_control_url(control_url)?;
    let url = format!("{}/api/ssh/ca.pub", server_url.trim_end_matches('/'));
    let bytes = pinned_http::get_bytes(&url, control_pin).await?;
    let public_key = String::from_utf8(bytes).context("Medium SSH CA response is not UTF-8")?;
    if !public_key.trim_start().starts_with("ssh-") {
        bail!("Medium SSH CA response is not an OpenSSH public key");
    }
    Ok(public_key)
}

fn local_device_name() -> String {
    std::env::var("MEDIUM_DEVICE_NAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .map(|value| app::normalize_device_label(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "medium-client".to_string())
}

fn normalize_control_url(raw: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("invalid control URL {raw}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => bail!("unsupported control URL scheme {scheme}"),
    }
    if url.host_str().is_none() {
        bail!("control URL must include a host");
    }

    Ok(url.as_str().trim_end_matches('/').to_string())
}

pub async fn open_session(state: &AppState, service_id: &str) -> anyhow::Result<SessionOpenGrant> {
    open_session_for_node(state, None, service_id).await
}

pub async fn open_session_for_node(
    state: &AppState,
    node_id: Option<&str>,
    service_id: &str,
) -> anyhow::Result<SessionOpenGrant> {
    let url = format!(
        "{}/api/sessions/open",
        state.server_url.trim_end_matches('/')
    );
    if state.security == "pinned-tls" {
        let mut url = format!(
            "{url}?service_id={}&requester_device_id={}",
            percent_encode(service_id),
            percent_encode(&state.device_name)
        );
        if let Some(node_id) = node_id {
            url.push_str("&node_id=");
            url.push_str(&percent_encode(node_id));
        }
        return pinned_http::get_json(&url, &state.control_pin).await;
    }

    let response = reqwest::Client::new()
        .get(url)
        .query(&SessionOpenRequest {
            service_id: service_id.to_string(),
            requester_device_id: state.device_name.clone(),
            node_id: node_id.map(str::to_string),
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json().await?)
}

pub async fn issue_ssh_certificate(
    state: &AppState,
    node_id: &str,
    service_id: &str,
    public_key: &str,
) -> anyhow::Result<SshCertificateResponse> {
    if state.client_secret.trim().is_empty() {
        bail!(
            "client state is missing client_secret; re-run `medium join <invite>` with a fresh invite from `medium init-control --reconfigure`"
        );
    }
    let url = format!(
        "{}/api/ssh/certificate",
        state.server_url.trim_end_matches('/')
    );
    let request = SshCertificateRequest {
        service_id: service_id.to_string(),
        node_id: Some(node_id.to_string()),
        requester_device_id: state.device_name.clone(),
        public_key: public_key.to_string(),
        client_secret: state.client_secret.clone(),
    };
    if state.security == "pinned-tls" {
        return pinned_http::post_json(&url, &state.control_pin, &request).await;
    }

    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json().await?)
}

pub fn format_join_invite(control_url: &str, control_pin: &str) -> anyhow::Result<String> {
    let control_url = normalize_control_url(control_url)?;
    if control_pin.is_empty() {
        bail!("control pin cannot be empty");
    }

    Ok(format!(
        "medium://join?v=1&control={control_url}&security=pinned-tls&control_pin={control_pin}"
    ))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
