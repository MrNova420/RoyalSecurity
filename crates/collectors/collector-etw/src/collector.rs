use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_common::types::{SecurityEvent, SecurityEventEnvelope, ModuleHealth, ModuleStatus};
use royalsecurity_core::bus::EventBus;
use std::time::Instant;
use tracing::info;

#[allow(dead_code)]
pub struct EtwCollector {
    bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    providers: Vec<EtwProviderConfig>,
}

#[derive(Debug, Clone)]
pub struct EtwProviderConfig {
    pub name: String,
    pub guid: String,
    pub enabled: bool,
    pub level: TraceLevel,
}

#[derive(Debug, Clone)]
pub enum TraceLevel {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
}

impl TraceLevel {
    pub fn to_value(&self) -> u8 {
        match self {
            Self::Critical => 1,
            Self::Error => 2,
            Self::Warning => 3,
            Self::Information => 4,
            Self::Verbose => 5,
        }
    }
}

impl EtwCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            providers: Self::default_providers(),
        }
    }

    fn default_providers() -> Vec<EtwProviderConfig> {
        vec![
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Process".into(),
                guid: "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-FileIO".into(),
                guid: "bed7cf1b-0c93-4be4-b4a7-5b0b0c84e6a8".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Network".into(),
                guid: "7dd42a49-5329-4832-8dfd-1e22f7e3b6ae".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Registry".into(),
                guid: "76577757-7206-4fa2-8069-80ecbc02c22f".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Security-Auditing".into(),
                guid: "54849625-5478-4994-a5ba-3e3b0328c30d".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-PowerShell".into(),
                guid: "a0c1853b-5c40-4b15-8766-3cf1c58f985a".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-WMI-Activity".into(),
                guid: "1418ef04-b0b4-4623-84f0-0f3be4d0de86".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Antimalware-Scan-Interface".into(),
                guid: "2e5e8c86-85dc-47dc-84cf-9a567241aeb5".into(),
                enabled: true,
                level: TraceLevel::Verbose,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Threat-Intelligence".into(),
                guid: "0ea14858-018a-4401-b4be-f3d0bfb90303".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-DNS-Client".into(),
                guid: "1c95122e-7180-4591-9bb3-f44be68d2e25".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
        ]
    }

    pub fn enabled_providers(&self) -> Vec<&EtwProviderConfig> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }

    pub fn add_provider(&mut self, provider: EtwProviderConfig) {
        info!(provider = %provider.name, "Adding ETW provider");
        self.providers.push(provider);
    }

    pub fn remove_provider(&mut self, name: &str) {
        self.providers.retain(|p| p.name != name);
    }

    pub fn process_raw_event(&mut self, raw_data: &[u8]) -> Option<SecurityEventEnvelope> {
        self.events_processed += 1;

        match crate::parser::parse_etw_event(raw_data) {
            Ok(Some(event)) => Some(event),
            Ok(None) => None,
            Err(e) => {
                self.errors += 1;
                tracing::warn!(error = %e, "Failed to parse ETW event");
                None
            }
        }
    }

    pub fn events_per_second(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.events_processed as f64 / elapsed;
            }
        }
        0.0
    }

    pub fn stats(&self) -> EtwStats {
        EtwStats {
            events_processed: self.events_processed,
            errors: self.errors,
            providers_active: self.providers.iter().filter(|p| p.enabled).count(),
            eps: self.events_per_second(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EtwStats {
    pub events_processed: u64,
    pub errors: u64,
    pub providers_active: usize,
    pub eps: f64,
}

#[async_trait]
impl SecurityModule for EtwCollector {
    fn name(&self) -> &str { "ETW Collector" }
    fn version(&self) -> &str { "0.1.0" }
    fn description(&self) -> &str { "Event Tracing for Windows telemetry collector" }

    async fn initialize(&mut self, config: ModuleConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("ETW Collector initialized with {} providers", self.providers.len());
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("ETW Collector started");

        for provider in self.enabled_providers() {
            info!(provider = %provider.name, guid = %provider.guid, "ETW provider registered");
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.status = ModuleStatus::Stopped;
        info!("ETW Collector stopped. Processed {} events", self.events_processed);
        Ok(())
    }

    async fn health(&self) -> ModuleHealth {
        ModuleHealth {
            status: self.status.clone(),
            last_heartbeat: chrono::Utc::now(),
            error_count: self.errors,
            events_processed: self.events_processed,
            events_per_second: self.events_per_second(),
            memory_usage_bytes: 0,
        }
    }

    async fn handle_event(&self, _event: &SecurityEvent) -> Option<SecurityEvent> {
        None
    }
}
