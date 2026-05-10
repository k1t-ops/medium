use anyhow::{Context, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

pub async fn get_json<T>(url: &str, control_pin: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let response = request(Method::Get, url, control_pin, None).await?;
    Ok(serde_json::from_slice(&response)?)
}

pub async fn get_bytes(url: &str, control_pin: &str) -> anyhow::Result<Vec<u8>> {
    request(Method::Get, url, control_pin, None).await
}

pub async fn post_json<T, B>(url: &str, control_pin: &str, body: &B) -> anyhow::Result<T>
where
    T: DeserializeOwned,
    B: Serialize,
{
    let body = serde_json::to_vec(body)?;
    let response = request(Method::Post, url, control_pin, Some(body)).await?;
    Ok(serde_json::from_slice(&response)?)
}

pub async fn post_json_no_content<B>(url: &str, control_pin: &str, body: &B) -> anyhow::Result<()>
where
    B: Serialize,
{
    let body = serde_json::to_vec(body)?;
    request(Method::Post, url, control_pin, Some(body)).await?;
    Ok(())
}

pub fn sha256_pin(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

pub fn pinned_tls_client_config(control_pin: &str) -> anyhow::Result<ClientConfig> {
    let expected_pin = parse_sha256_pin(control_pin)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let supported = provider.signature_verification_algorithms;
    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            expected_pin,
            supported,
        }))
        .with_no_client_auth())
}

enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

async fn request(
    method: Method,
    url: &str,
    control_pin: &str,
    body: Option<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let url = Url::parse(url).with_context(|| format!("invalid control URL {url}"))?;
    if url.scheme() != "https" {
        bail!("pinned-tls control URL must use https");
    }
    let host = url.host_str().context("control URL must include a host")?;
    let port = url
        .port_or_known_default()
        .context("control URL must include a port")?;
    let addr = format!("{host}:{port}");
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name {host}"))?;

    let config = pinned_tls_client_config(control_pin)?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("failed to connect to control endpoint {addr}"))?;
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| anyhow::anyhow!("control TLS handshake failed for {url}: {error}"))?;

    let path = match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    };
    let body = body.unwrap_or_default();
    let content_headers = if body.is_empty() {
        String::new()
    } else {
        format!(
            "content-type: application/json\r\ncontent-length: {}\r\n",
            body.len()
        )
    };
    let request = format!(
        "{} {path} HTTP/1.1\r\nhost: {}\r\naccept: application/json\r\n{content_headers}connection: close\r\n\r\n",
        method.as_str(),
        host_header(&url)?
    );
    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(&body).await?;
    }
    stream.flush().await?;

    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
    }
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("control response is missing HTTP headers")?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .context("control response headers are not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .context("control response is missing HTTP status")?;
    if !is_success_status(status) {
        bail!("control request failed: {status}");
    }

    Ok(raw[header_end + 4..].to_vec())
}

fn is_success_status(status: &str) -> bool {
    let Some(code) = status.split_whitespace().nth(1) else {
        return false;
    };
    code.starts_with('2')
}

fn host_header(url: &Url) -> anyhow::Result<String> {
    let host = url.host_str().context("control URL must include a host")?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn parse_sha256_pin(pin: &str) -> anyhow::Result<[u8; 32]> {
    let hex = pin
        .strip_prefix("sha256:")
        .context("control pin must start with sha256:")?;
    if hex.len() != 64 {
        bail!("control pin sha256 digest must be 64 hex characters");
    }

    let mut digest = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)?;
        digest[index] = u8::from_str_radix(pair, 16)
            .with_context(|| format!("invalid control pin hex byte {pair}"))?;
    }
    Ok(digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone)]
struct PinnedCertVerifier {
    expected_pin: [u8; 32],
    supported: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertVerifier")
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = Sha256::digest(end_entity.as_ref());
        let actual_pin: &[u8] = actual.as_ref();
        if actual_pin != self.expected_pin.as_slice() {
            return Err(TlsError::General(format!(
                "control TLS pin mismatch: expected sha256:{} actual sha256:{}",
                hex_lower(&self.expected_pin),
                hex_lower(actual_pin)
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
