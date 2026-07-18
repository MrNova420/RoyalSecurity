use figment::{Figment, providers::{Format, Toml}};
use serde::{Serialize, Deserialize};
use crate::common::types::ConfigValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub agent: AgentConfig,
    pub defense: DefenseConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub logging: LoggingConfig,
    pub threat_intel: ThreatIntelConfig,
    pub compliance: ComplianceConfig,
    pub forensics: ForensicsConfig,
    pub automation: AutomationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub app_name: String,
    pub version: String,
    pub license_key: String,
    pub telemetry_enabled: bool,
    pub auto_update: bool,
    #[serde(default = "default_first_run")]
    pub first_run: bool,
}

fn default_first_run() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub run_as_service: bool,
    pub heartbeat_interval_secs: u64,
    pub max_memory_mb: u64,
    pub max_cpu_percent: f64,
    pub watchdog_enabled: bool,
    pub self_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseConfig {
    pub av_enabled: bool,
    pub edr_enabled: bool,
    pub xdr_enabled: bool,
    pub behavior_enabled: bool,
    pub asr_enabled: bool,
    pub ransomware_enabled: bool,
    pub memory_protection: bool,
    pub exploit_protection: bool,
    pub credential_protection: bool,
    pub device_control: bool,
    pub deception_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub firewall_enabled: bool,
    pub dns_proxy_enabled: bool,
    pub dns_over_https: bool,
    pub vpn_enabled: bool,
    pub tor_enabled: bool,
    pub leak_protection: bool,
    pub tls_inspection: bool,
    pub web_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    pub anti_fingerprint: bool,
    pub tracker_blocking: bool,
    pub metadata_minimization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_output: bool,
    pub console_output: bool,
    pub max_file_size_mb: u64,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub update_interval_minutes: u64,
    pub feeds: Vec<String>,
    pub local_cache_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub enabled: bool,
    pub frameworks: Vec<String>,
    pub auto_remediate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsConfig {
    pub enabled: bool,
    pub max_artifacts: usize,
    pub auto_collection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationConfig {
    pub enabled: bool,
    pub max_playbooks: usize,
    pub http_actions_enabled: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                app_name: "RoyalSecurity".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                license_key: "".into(),
                telemetry_enabled: true,
                auto_update: true,
                first_run: true,
            },
            agent: AgentConfig {
                run_as_service: true,
                heartbeat_interval_secs: 5,
                max_memory_mb: 256,
                max_cpu_percent: 5.0,
                watchdog_enabled: true,
                self_protection: true,
            },
            defense: DefenseConfig {
                av_enabled: true,
                edr_enabled: true,
                xdr_enabled: true,
                behavior_enabled: true,
                asr_enabled: true,
                ransomware_enabled: true,
                memory_protection: true,
                exploit_protection: true,
                credential_protection: true,
                device_control: true,
                deception_enabled: true,
            },
            network: NetworkConfig {
                firewall_enabled: true,
                dns_proxy_enabled: true,
                dns_over_https: true,
                vpn_enabled: true,
                tor_enabled: false,
                leak_protection: true,
                tls_inspection: false,
                web_protection: true,
            },
            privacy: PrivacyConfig {
                anti_fingerprint: true,
                tracker_blocking: true,
                metadata_minimization: true,
            },
            logging: LoggingConfig {
                level: "info".into(),
                format: "json".into(),
                file_output: true,
                console_output: true,
                max_file_size_mb: 100,
                retention_days: 90,
            },
            threat_intel: ThreatIntelConfig {
                enabled: true,
                update_interval_minutes: 15,
                feeds: vec![],
                local_cache_enabled: true,
            },
            compliance: ComplianceConfig {
                enabled: true,
                frameworks: vec!["CIS".into(), "STIG".into()],
                auto_remediate: false,
            },
            forensics: ForensicsConfig {
                enabled: true,
                max_artifacts: 10000,
                auto_collection: true,
            },
            automation: AutomationConfig {
                enabled: true,
                max_playbooks: 100,
                http_actions_enabled: true,
            },
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, figment::Error> {
        Figment::new()
            .merge(Toml::file("config/default.toml"))
            .extract()
    }

    pub fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn get_value(&self, key: &str) -> Option<ConfigValue> {
        match key {
            "general.app_name" => Some(ConfigValue::String(self.general.app_name.clone())),
            "general.telemetry_enabled" => Some(ConfigValue::Bool(self.general.telemetry_enabled)),
            "general.first_run" => Some(ConfigValue::Bool(self.general.first_run)),
            "agent.heartbeat_interval_secs" => Some(ConfigValue::Integer(self.agent.heartbeat_interval_secs as i64)),
            "agent.max_memory_mb" => Some(ConfigValue::Integer(self.agent.max_memory_mb as i64)),
            _ => None,
        }
    }
}
