use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[path = "invite.rs"]
pub mod invite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub server_url: String,
    #[serde(alias = "node_name")]
    pub device_name: String,
    pub bootstrap_code: String,
    #[serde(default)]
    pub invite_version: u32,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub control_pin: String,
    #[serde(default)]
    pub client_secret: String,
}

impl AppState {
    pub fn load(paths: &AppPaths) -> anyhow::Result<Self> {
        match std::fs::read_to_string(&paths.state_path) {
            Ok(raw) => Ok(serde_json::from_str(&raw)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let legacy_state_path = legacy_state_path(paths);
                let raw = std::fs::read_to_string(&legacy_state_path)?;
                std::fs::create_dir_all(&paths.state_dir)?;
                std::fs::write(&paths.state_path, raw.as_bytes())?;
                Ok(serde_json::from_str(&raw)?)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn save(&self, paths: &AppPaths) -> anyhow::Result<()> {
        std::fs::create_dir_all(&paths.state_dir)?;
        std::fs::write(&paths.state_path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

fn legacy_state_path(paths: &AppPaths) -> PathBuf {
    paths
        .home_dir
        .join(".config")
        .join("overlay")
        .join("state.json")
}
