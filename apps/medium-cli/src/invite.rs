use anyhow::{Context, bail};

const SUPPORTED_INVITE_VERSION: u32 = 1;
const SUPPORTED_INVITE_SECURITY: &str = "pinned-tls";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub version: u32,
    pub control_url: String,
    pub security: String,
    pub control_pin: String,
    pub client_secret: Option<String>,
}

pub fn parse_invite(raw: &str) -> anyhow::Result<Invite> {
    let (scheme, remainder) = raw
        .split_once("://")
        .context("invite must include a scheme")?;
    if scheme != "medium" {
        bail!("unsupported invite scheme {scheme}");
    }

    let (path, query) = remainder
        .split_once('?')
        .context("invite must include query parameters")?;
    if path != "join" {
        bail!("unsupported invite path {path}");
    }

    let mut version = None;
    let mut control_url = None;
    let mut security = None;
    let mut control_pin = None;
    let mut client_secret = None;

    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("invalid invite parameter {pair}"))?;

        match key {
            "v" => {
                version = Some(
                    value
                        .parse()
                        .with_context(|| format!("invalid invite version {value}"))?,
                );
            }
            "control" => {
                if value.is_empty() {
                    bail!("invite control URL cannot be empty");
                }
                control_url = Some(value.to_string());
            }
            "security" => {
                if value.is_empty() {
                    bail!("invite security cannot be empty");
                }
                security = Some(value.to_string());
            }
            "control_pin" => {
                if value.is_empty() {
                    bail!("invite control pin cannot be empty");
                }
                control_pin = Some(value.to_string());
            }
            "client_secret" => {
                if value.is_empty() {
                    bail!("invite client secret cannot be empty");
                }
                client_secret = Some(value.to_string());
            }
            _ => {}
        }
    }

    let version = version.context("invite is missing version")?;
    if version != SUPPORTED_INVITE_VERSION {
        bail!("unsupported invite version {version}");
    }
    let security = security.context("invite is missing security")?;
    if security != SUPPORTED_INVITE_SECURITY {
        bail!("unsupported invite security {security}");
    }

    Ok(Invite {
        version,
        control_url: control_url.context("invite is missing control URL")?,
        security,
        control_pin: control_pin.context("invite is missing control pin")?,
        client_secret,
    })
}
