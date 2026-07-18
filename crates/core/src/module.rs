use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use crate::common::types::{SecurityEvent, ModuleHealth};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub enabled: bool,
    pub priority: u8,
    pub settings: serde_json::Value,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self { enabled: true, priority: 50, settings: serde_json::Value::Object(Default::default()) }
    }
}

#[async_trait]
pub trait SecurityModule: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;

    async fn initialize(&mut self, config: ModuleConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn health(&self) -> ModuleHealth;

    async fn handle_event(&self, event: &SecurityEvent) -> Option<SecurityEvent>;

    fn config_schema(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}

pub struct ModuleEntry {
    pub module: Box<dyn SecurityModule>,
    pub config: ModuleConfig,
    pub health: ModuleHealth,
}
