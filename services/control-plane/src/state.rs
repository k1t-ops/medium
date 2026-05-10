use crate::registry::RegistryStore;

#[derive(Debug, Clone)]
pub struct ControlState {
    pub registry: RegistryStore,
    pub shared_secret: String,
    pub client_secret: String,
    pub control_pin: String,
    pub service_ca_cert_pem: Option<String>,
    pub service_ca_key_pem: Option<String>,
    pub relay_addr: Option<String>,
    pub wss_relay_url: Option<String>,
    pub ice_relay_addr: Option<String>,
    pub ssh_ca_key_path: Option<String>,
}

impl ControlState {
    pub async fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("OVERLAY_CONTROL_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://control-plane.db".into());
        Ok(Self {
            registry: RegistryStore::connect(&database_url).await?,
            shared_secret: std::env::var("OVERLAY_SHARED_SECRET")
                .unwrap_or_else(|_| "local-dev-secret".into()),
            client_secret: std::env::var("MEDIUM_CLIENT_SECRET")
                .unwrap_or_else(|_| "local-dev-client-secret".into()),
            control_pin: std::env::var("MEDIUM_CONTROL_PIN").unwrap_or_default(),
            service_ca_cert_pem: std::env::var("MEDIUM_SERVICE_CA_CERT_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(std::fs::read_to_string)
                .transpose()?,
            service_ca_key_pem: std::env::var("MEDIUM_SERVICE_CA_KEY_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(std::fs::read_to_string)
                .transpose()?,
            relay_addr: std::env::var("MEDIUM_RELAY_ADDR")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            wss_relay_url: std::env::var("MEDIUM_WSS_RELAY_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            ice_relay_addr: std::env::var("MEDIUM_ICE_RELAY_ADDR")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            ssh_ca_key_path: std::env::var("MEDIUM_SSH_CA_KEY_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        })
    }
}
