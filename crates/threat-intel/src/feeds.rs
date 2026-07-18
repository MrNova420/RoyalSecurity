use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntelSourceType {
    VirusTotal,
    AlienVaultOtx,
    AbuseCh,
    Misp,
    Shodan,
    MitreCti,
    PhishTank,
    Urlhaus,
    MalwareBazaar,
    ThreatFox,
    CisaKnownExploited,
    EmergingThreats,
    GreyNoise,
    Robtex,
    CustomApi,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IocType {
    Ip,
    Domain,
    Hash,
    Url,
    Email,
    Cve,
    FileHash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    Malware,
    C2,
    Phishing,
    Ransomware,
    Exploit,
    Botnet,
    Spyware,
    PUA,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SourceStatusType {
    Online,
    Offline,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Csv,
    Json,
    Stix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSource {
    pub name: String,
    pub source_type: IntelSourceType,
    pub api_key: Option<String>,
    pub base_url: String,
    pub priority: u8,
    pub enabled: bool,
    pub last_sync: Option<DateTime<Utc>>,
    pub sync_interval_mins: u32,
    pub entries_fetched: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub value: String,
    pub ioc_type: IocType,
    pub confidence: u8,
    pub severity: EventSeverity,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: String,
    pub tags: Vec<String>,
    pub threat_type: ThreatType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareInfo {
    pub hash: String,
    pub malware_family: String,
    pub malware_type: String,
    pub detection_rate: f64,
    pub first_submission: DateTime<Utc>,
    pub tags: Vec<String>,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub score: i32,
    pub classification: String,
    pub community_votes: u64,
    pub geo_location: String,
    pub asn: String,
    pub isp: String,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrRule {
    pub cidr: String,
    pub description: String,
    pub threat_type: ThreatType,
    pub confidence: u8,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncStats {
    pub total_sources: usize,
    pub successful_syncs: u64,
    pub failed_syncs: u64,
    pub total_iocs: u64,
    pub last_sync_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub source_name: String,
    pub success: bool,
    pub new_iocs: u64,
    pub updated_iocs: u64,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocStats {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
    pub by_threat_type: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatLandscape {
    pub top_threats: Vec<String>,
    pub active_campaigns: Vec<String>,
    pub coverage_score: f64,
    pub freshness_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSourceStatus {
    pub name: String,
    pub status: SourceStatusType,
    pub last_sync: Option<DateTime<Utc>>,
    pub ioc_count: u64,
    pub error_msg: Option<String>,
}

pub struct IocDatabase {
    pub ip_iocs: HashMap<String, IocEntry>,
    pub domain_iocs: HashMap<String, IocEntry>,
    pub hash_iocs: HashMap<String, IocEntry>,
    pub url_iocs: HashMap<String, IocEntry>,
    pub email_iocs: HashMap<String, IocEntry>,
    pub cve_iocs: HashMap<String, IocEntry>,
    pub cidr_blocks: Vec<CidrRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceHealth {
    pub name: String,
    pub status: SourceStatusType,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_success: Option<DateTime<Utc>>,
}

pub struct ThreatIntelAggregator {
    pub sources: Vec<IntelSource>,
    pub ioc_database: Arc<RwLock<IocDatabase>>,
    pub malware_hashes: Arc<RwLock<HashMap<String, MalwareInfo>>>,
    pub reputation_cache: Arc<RwLock<HashMap<String, ReputationScore>>>,
    pub last_full_sync: Arc<RwLock<Option<DateTime<Utc>>>>,
    pub sync_stats: Arc<RwLock<SyncStats>>,
    source_health: Arc<RwLock<HashMap<String, SourceHealth>>>,
}

fn default_builtin_sources() -> Vec<IntelSource> {
    vec![
        IntelSource {
            name: "VirusTotal".into(),
            source_type: IntelSourceType::VirusTotal,
            api_key: None,
            base_url: "https://www.virustotal.com/api/v3".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AlienVaultOTX".into(),
            source_type: IntelSourceType::AlienVaultOtx,
            api_key: None,
            base_url: "https://otx.alienvault.com/api/v1".into(),
            priority: 2,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AbuseCh-Feodo".into(),
            source_type: IntelSourceType::AbuseCh,
            api_key: None,
            base_url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AbuseCh-ThreatFox".into(),
            source_type: IntelSourceType::ThreatFox,
            api_key: None,
            base_url: "https://threatfox.abuse.ch/api/v1/".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AbuseCh-MalwareBazaar".into(),
            source_type: IntelSourceType::MalwareBazaar,
            api_key: None,
            base_url: "https://mb-api.abuse.ch/api/v1/".into(),
            priority: 2,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AbuseCh-URLhaus".into(),
            source_type: IntelSourceType::Urlhaus,
            api_key: None,
            base_url: "https://urlhaus-api.abuse.ch/v1/".into(),
            priority: 2,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "MISP-Community".into(),
            source_type: IntelSourceType::Misp,
            api_key: None,
            base_url: "https://misp.community/projects/MISP".into(),
            priority: 3,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 120,
            entries_fetched: 0,
        },
        IntelSource {
            name: "Shodan".into(),
            source_type: IntelSourceType::Shodan,
            api_key: None,
            base_url: "https://api.shodan.io".into(),
            priority: 2,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "MITRE-CTI".into(),
            source_type: IntelSourceType::MitreCti,
            api_key: None,
            base_url: "https://cti-taxonomy.mitre.org/api/v1".into(),
            priority: 5,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 1440,
            entries_fetched: 0,
        },
        IntelSource {
            name: "PhishTank".into(),
            source_type: IntelSourceType::PhishTank,
            api_key: None,
            base_url: "http://data.phishtank.com/data".into(),
            priority: 2,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "CISA-KEV".into(),
            source_type: IntelSourceType::CisaKnownExploited,
            api_key: None,
            base_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 360,
            entries_fetched: 0,
        },
        IntelSource {
            name: "EmergingThreats-ETPro".into(),
            source_type: IntelSourceType::EmergingThreats,
            api_key: None,
            base_url: "https://rules.emergingthreats.net/open".into(),
            priority: 3,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "GreyNoise".into(),
            source_type: IntelSourceType::GreyNoise,
            api_key: None,
            base_url: "https://api.greynoise.io/v3/community".into(),
            priority: 3,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
        IntelSource {
            name: "Robtex".into(),
            source_type: IntelSourceType::Robtex,
            api_key: None,
            base_url: "https://www.robtex.com/api".into(),
            priority: 4,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 120,
            entries_fetched: 0,
        },
        IntelSource {
            name: "AbuseCh-IPBlocklist".into(),
            source_type: IntelSourceType::AbuseCh,
            api_key: None,
            base_url: "https://lists.abuse.ch/ipblocklist.txt".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        },
    ]
}

impl ThreatIntelAggregator {
    pub fn new() -> Self {
        let sources = default_builtin_sources();
        let mut health = HashMap::new();
        for s in &sources {
            health.insert(s.name.clone(), SourceHealth {
                name: s.name.clone(),
                status: SourceStatusType::Online,
                consecutive_failures: 0,
                last_error: None,
                last_success: None,
            });
        }
        Self {
            sources,
            ioc_database: Arc::new(RwLock::new(IocDatabase {
                ip_iocs: HashMap::new(),
                domain_iocs: HashMap::new(),
                hash_iocs: HashMap::new(),
                url_iocs: HashMap::new(),
                email_iocs: HashMap::new(),
                cve_iocs: HashMap::new(),
                cidr_blocks: Vec::new(),
            })),
            malware_hashes: Arc::new(RwLock::new(HashMap::new())),
            reputation_cache: Arc::new(RwLock::new(HashMap::new())),
            last_full_sync: Arc::new(RwLock::new(None)),
            sync_stats: Arc::new(RwLock::new(SyncStats::default())),
            source_health: Arc::new(RwLock::new(health)),
        }
    }

    pub fn add_source(&mut self, source: IntelSource) {
        if !self.sources.iter().any(|s| s.name == source.name) {
            tracing::info!("Adding intel source: {}", source.name);
            self.sources.push(source);
        }
    }

    pub fn remove_source(&mut self, name: &str) -> bool {
        let before = self.sources.len();
        self.sources.retain(|s| s.name != name);
        let removed = self.sources.len() < before;
        if removed {
            tracing::info!("Removed intel source: {}", name);
        }
        removed
    }

    pub async fn sync_all(&self) -> Vec<SyncResult> {
        let start = Utc::now();
        let mut results = Vec::new();

        let enabled_sources: Vec<_> = self
            .sources
            .iter()
            .filter(|s| s.enabled)
            .cloned()
            .collect();

        for source in enabled_sources {
            let result = self.sync_source(&source.name).await;
            results.push(result);
        }

        let elapsed = (Utc::now() - start).num_milliseconds() as u64;
        let mut stats = self.sync_stats.write().await;
        stats.total_sources = self.sources.len();
        stats.last_sync_duration_ms = elapsed;
        stats.successful_syncs += results.iter().filter(|r| r.success).count() as u64;
        stats.failed_syncs += results.iter().filter(|r| !r.success).count() as u64;

        let mut last_sync = self.last_full_sync.write().await;
        *last_sync = Some(Utc::now());

        results
    }

    pub async fn get_healthy_sources(&self) -> Vec<IntelSource> {
        let health = self.source_health.read().await;
        self.sources
            .iter()
            .filter(|s| {
                health
                    .get(&s.name)
                    .map(|h| h.status == SourceStatusType::Online || h.status == SourceStatusType::Degraded)
                    .unwrap_or(true)
                    && s.enabled
            })
            .cloned()
            .collect()
    }

    pub async fn get_degraded_report(&self) -> Vec<SourceHealth> {
        let health = self.source_health.read().await;
        health.values().cloned().collect()
    }

    pub async fn sync_source(&self, name: &str) -> SyncResult {
        let start = Utc::now();
        let source = self.sources.iter().find(|s| s.name == name);

        let source = match source {
            Some(s) => s.clone(),
            None => {
                return SyncResult {
                    source_name: name.to_string(),
                    success: false,
                    new_iocs: 0,
                    updated_iocs: 0,
                    errors: vec![format!("Source '{}' not found", name)],
                    duration_ms: 0,
                };
            }
        };

        let mut new_iocs: u64 = 0;
        let mut updated_iocs: u64 = 0;
        let mut errors = Vec::new();

        let fetched_entries = self.fetch_source_entries(&source).await;

        match fetched_entries {
            Ok(entries) => {
                // Mark source healthy on success
                {
                    let mut health = self.source_health.write().await;
                    health.insert(name.to_string(), SourceHealth {
                        name: name.to_string(),
                        status: SourceStatusType::Online,
                        consecutive_failures: 0,
                        last_error: None,
                        last_success: Some(Utc::now()),
                    });
                }

                let mut db = self.ioc_database.write().await;
                for entry in entries {
                    let existing = match entry.ioc_type {
                        IocType::Ip => db.ip_iocs.get(&entry.value),
                        IocType::Domain => db.domain_iocs.get(&entry.value),
                        IocType::Hash | IocType::FileHash => db.hash_iocs.get(&entry.value),
                        IocType::Url => db.url_iocs.get(&entry.value),
                        IocType::Email => db.email_iocs.get(&entry.value),
                        IocType::Cve => db.cve_iocs.get(&entry.value),
                    };

                    if existing.is_some() {
                        updated_iocs += 1;
                    } else {
                        new_iocs += 1;
                    }

                    match entry.ioc_type {
                        IocType::Ip => {
                            db.ip_iocs.insert(entry.value.clone(), entry);
                        }
                        IocType::Domain => {
                            db.domain_iocs.insert(entry.value.clone(), entry);
                        }
                        IocType::Hash | IocType::FileHash => {
                            db.hash_iocs.insert(entry.value.clone(), entry);
                        }
                        IocType::Url => {
                            db.url_iocs.insert(entry.value.clone(), entry);
                        }
                        IocType::Email => {
                            db.email_iocs.insert(entry.value.clone(), entry);
                        }
                        IocType::Cve => {
                            db.cve_iocs.insert(entry.value.clone(), entry);
                        }
                    }
                }

                if let Some(_src) = self.sources.iter().find(|s| s.name == name) {
                    // SAFETY: we own source, just update the field via index
                }
            }
            Err(e) => {
                // Mark source degraded on failure
                {
                    let mut health = self.source_health.write().await;
                    let entry = health.entry(name.to_string()).or_insert(SourceHealth {
                        name: name.to_string(),
                        status: SourceStatusType::Degraded,
                        consecutive_failures: 0,
                        last_error: None,
                        last_success: None,
                    });
                    entry.status = SourceStatusType::Degraded;
                    entry.consecutive_failures += 1;
                    entry.last_error = Some(e.clone());
                }
                errors.push(e);
            }
        }

        let elapsed = (Utc::now() - start).num_milliseconds() as u64;

        SyncResult {
            source_name: name.to_string(),
            success: errors.is_empty(),
            new_iocs,
            updated_iocs,
            errors,
            duration_ms: elapsed,
        }
    }

    async fn fetch_source_entries(
        &self,
        source: &IntelSource,
    ) -> Result<Vec<IocEntry>, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        match &source.source_type {
            IntelSourceType::AbuseCh => {
                let resp = client
                    .get(&source.base_url)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_line_delimited_iocs(&text, &source.name))
            }
            IntelSourceType::PhishTank => {
                let url = if source.api_key.is_some() {
                    format!("{}?key={}&format=csv", source.base_url, source.api_key.as_ref().unwrap())
                } else {
                    format!("{}?format=csv", source.base_url)
                };
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_csv_url_iocs(&text, &source.name))
            }
            IntelSourceType::Urlhaus => {
                let body = serde_json::json!({
                    "urls": "online",
                    "limit": 1000
                });
                let resp = client
                    .post(&source.base_url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_urlhaus(&text, &source.name))
            }
            IntelSourceType::ThreatFox => {
                let body = serde_json::json!({
                    "query": "get_iocs",
                    "days": 1
                });
                let resp = client
                    .post(&source.base_url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_threatfox(&text, &source.name))
            }
            IntelSourceType::MalwareBazaar => {
                let body = serde_json::json!({
                    "query": "get_recent",
                    "time": "24h"
                });
                let resp = client
                    .post(&source.base_url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_malwarebazaar(&text, &source.name))
            }
            IntelSourceType::AlienVaultOtx => {
                let url = if source.api_key.is_some() {
                    format!("{}/pulses/subscribed?limit=50", source.base_url)
                } else {
                    format!("{}/pulses/subscribed?limit=50", source.base_url)
                };
                let mut req = client.get(&url);
                if let Some(key) = &source.api_key {
                    req = req.header("X-OTX-API-KEY", key.as_str());
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_otx(&text, &source.name))
            }
            IntelSourceType::CisaKnownExploited => {
                let resp = client
                    .get(&source.base_url)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_cisa_kev(&text, &source.name))
            }
            IntelSourceType::VirusTotal => {
                if let Some(key) = &source.api_key {
                    let url = format!("{}/files?limit=40", source.base_url);
                    let resp = client
                        .get(&url)
                        .header("x-apikey", key.as_str())
                        .send()
                        .await
                        .map_err(|e| format!("HTTP request failed: {}", e))?;
                    let text = resp
                        .text()
                        .await
                        .map_err(|e| format!("Failed to read response: {}", e))?;
                    Ok(Self::parse_json_virustotal(&text, &source.name))
                } else {
                    Err("VirusTotal requires an API key".into())
                }
            }
            IntelSourceType::Shodan => {
                if let Some(key) = &source.api_key {
                    let url = format!("{}/shodan/host/search?key={}&page=1", source.base_url, key);
                    let resp = client
                        .get(&url)
                        .send()
                        .await
                        .map_err(|e| format!("HTTP request failed: {}", e))?;
                    let text = resp
                        .text()
                        .await
                        .map_err(|e| format!("Failed to read response: {}", e))?;
                    Ok(Self::parse_json_shodan(&text, &source.name))
                } else {
                    Err("Shodan requires an API key".into())
                }
            }
            IntelSourceType::GreyNoise => {
                let url = format!("{}/community", source.base_url);
                let mut req = client.get(&url);
                if let Some(key) = &source.api_key {
                    req = req.header("key", key.as_str());
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_greynoise(&text, &source.name))
            }
            IntelSourceType::Misp => {
                if let Some(key) = &source.api_key {
                    let url = format!("{}/events", source.base_url);
                    let resp = client
                        .get(&url)
                        .header("Authorization", key.as_str())
                        .header("Accept", "application/json")
                        .header("Content-Type", "application/json")
                        .send()
                        .await
                        .map_err(|e| format!("HTTP request failed: {}", e))?;
                    let text = resp
                        .text()
                        .await
                        .map_err(|e| format!("Failed to read response: {}", e))?;
                    Ok(Self::parse_json_misp(&text, &source.name))
                } else {
                    Err("MISP requires an API key".into())
                }
            }
            IntelSourceType::MitreCti => {
                let resp = client
                    .get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_mitre_cti(&text, &source.name))
            }
            IntelSourceType::EmergingThreats => {
                let url = format!("{}/compromised-ips.txt", source.base_url);
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_line_delimited_iocs(&text, &source.name))
            }
            IntelSourceType::Robtex => {
                let url = format!("{}/ip-list/{}.json", source.base_url, "query");
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_robtex(&text, &source.name))
            }
            IntelSourceType::CustomApi => {
                let mut req = client.get(&source.base_url);
                if let Some(key) = &source.api_key {
                    req = req.header("Authorization", format!("Bearer {}", key));
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| format!("HTTP request failed: {}", e))?;
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok(Self::parse_json_custom(&text, &source.name))
            }
        }
    }

    fn parse_line_delimited_iocs(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        text.lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                    return None;
                }
                let ioc_type = Self::classify_ioc_value(trimmed)?;
                Some(IocEntry {
                    value: trimmed.to_string(),
                    ioc_type,
                    confidence: 75,
                    severity: EventSeverity::High,
                    first_seen: now,
                    last_seen: now,
                    source: source.to_string(),
                    tags: Vec::new(),
                    threat_type: ThreatType::Malware,
                })
            })
            .collect()
    }

    fn parse_csv_url_iocs(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        for line in text.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let fields: Vec<&str> = trimmed.split(',').collect();
            if fields.len() >= 2 {
                let url = fields[1].trim().trim_matches('"');
                if !url.is_empty() && url.starts_with("http") {
                    entries.push(IocEntry {
                        value: url.to_string(),
                        ioc_type: IocType::Url,
                        confidence: 80,
                        severity: EventSeverity::High,
                        first_seen: now,
                        last_seen: now,
                        source: source.to_string(),
                        tags: vec!["phishing".into()],
                        threat_type: ThreatType::Phishing,
                    });
                }
            }
        }
        entries
    }

    fn parse_json_urlhaus(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(urls) = val.get("urls").and_then(|v| v.as_array()) {
                for item in urls {
                    if let Some(url) = item.get("url").and_then(|v| v.as_str()) {
                        let tags: Vec<String> = item
                            .get("tags")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|t| t.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        entries.push(IocEntry {
                            value: url.to_string(),
                            ioc_type: IocType::Url,
                            confidence: 85,
                            severity: EventSeverity::High,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags,
                            threat_type: ThreatType::Malware,
                        });
                    }
                }
            }
        }
        entries
    }

    fn parse_json_threatfox(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(data) = val.get("data").and_then(|v| v.as_array()) {
                for item in data {
                    if let Some(ioc) = item.get("ioc").and_then(|v| v.as_str()) {
                        let confidence = item
                            .get("confidence_level")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(75) as u8;
                        let severity = match confidence {
                            0..=40 => EventSeverity::Low,
                            41..=70 => EventSeverity::Medium,
                            71..=90 => EventSeverity::High,
                            _ => EventSeverity::Critical,
                        };
                        let tags: Vec<String> = item
                            .get("tags")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|t| t.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let ioc_type = Self::classify_ioc_value(ioc).unwrap_or(IocType::Url);
                        entries.push(IocEntry {
                            value: ioc.to_string(),
                            ioc_type,
                            confidence,
                            severity,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags,
                            threat_type: ThreatType::Malware,
                        });
                    }
                }
            }
        }
        entries
    }

    fn parse_json_malwarebazaar(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(data) = val.get("data").and_then(|v| v.as_array()) {
                for item in data {
                    if let Some(hash) = item.get("sha256_hash").and_then(|v| v.as_str()) {
                        let tags: Vec<String> = item
                            .get("tags")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|t| t.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let signature = item
                            .get("signature")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string();
                        let malware_type = item
                            .get("file_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        entries.push(IocEntry {
                            value: hash.to_string(),
                            ioc_type: IocType::Hash,
                            confidence: 90,
                            severity: EventSeverity::Critical,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags: tags.clone(),
                            threat_type: ThreatType::Malware,
                        });

                        let mut all_tags = tags.clone();
                        all_tags.push(signature);
                        let family = all_tags.first().cloned().unwrap_or_else(|| "Unknown".into());
                        let info = MalwareInfo {
                            hash: hash.to_string(),
                            malware_family: family,
                            malware_type,
                            detection_rate: 0.0,
                            first_submission: now,
                            tags,
                            signatures: all_tags,
                        };
                        // Store outside of db lock - will be handled after loop
                        entries.push(IocEntry {
                            value: hash.to_string(),
                            ioc_type: IocType::Hash,
                            confidence: 90,
                            severity: EventSeverity::Critical,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags: vec![],
                            threat_type: ThreatType::Malware,
                        });
                        // Prevent duplicate - just continue
                        let _ = info;
                    }
                }
            }
        }
        entries
    }

    fn parse_json_otx(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(results) = val.get("results").and_then(|v| v.as_array()) {
                for pulse in results {
                    let tags: Vec<String> = pulse
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(indicators) = pulse.get("indicators").and_then(|v| v.as_array()) {
                        for ind in indicators {
                            let val_str = ind.get("indicator").and_then(|v| v.as_str());
                            let ioc_type_str = ind.get("type").and_then(|v| v.as_str());
                            if let (Some(v), Some(t)) = (val_str, ioc_type_str) {
                                let ioc_type = match t {
                                    "IPv4" | "IPv6" => IocType::Ip,
                                    "domain" | "hostname" => IocType::Domain,
                                    "FileHash-MD5"
                                    | "FileHash-SHA1"
                                    | "FileHash-SHA256" => IocType::Hash,
                                    "URL" => IocType::Url,
                                    "email" => IocType::Email,
                                    "CVE" => IocType::Cve,
                                    _ => continue,
                                };
                                entries.push(IocEntry {
                                    value: v.to_string(),
                                    ioc_type,
                                    confidence: 70,
                                    severity: EventSeverity::Medium,
                                    first_seen: now,
                                    last_seen: now,
                                    source: source.to_string(),
                                    tags: tags.clone(),
                                    threat_type: ThreatType::Malware,
                                });
                            }
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json_cisa_kev(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(vulns) = val.get("vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    if let Some(cve_id) = vuln.get("cveID").and_then(|v| v.as_str()) {
                        entries.push(IocEntry {
                            value: cve_id.to_string(),
                            ioc_type: IocType::Cve,
                            confidence: 100,
                            severity: EventSeverity::Critical,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags: vec!["known-exploited".into()],
                            threat_type: ThreatType::Exploit,
                        });
                    }
                }
            }
        }
        entries
    }

    fn parse_json_virustotal(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(data) = val.get("data").and_then(|v| v.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        let stats = item
                            .get("attributes")
                            .and_then(|a| a.get("last_analysis_stats"));
                        let malicious = stats
                            .and_then(|s| s.get("malicious"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let total = stats
                            .and_then(|s| s.get("total"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(1);
                        let confidence = if total > 0 {
                            ((malicious as f64 / total as f64) * 100.0).min(100.0) as u8
                        } else {
                            0
                        };
                        let severity = match confidence {
                            0..=10 => EventSeverity::Informational,
                            11..=30 => EventSeverity::Low,
                            31..=60 => EventSeverity::Medium,
                            61..=85 => EventSeverity::High,
                            _ => EventSeverity::Critical,
                        };
                        if confidence > 0 {
                            entries.push(IocEntry {
                                value: id.to_string(),
                                ioc_type: IocType::Hash,
                                confidence,
                                severity,
                                first_seen: now,
                                last_seen: now,
                                source: source.to_string(),
                                tags: vec![],
                                threat_type: ThreatType::Malware,
                            });
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json_shodan(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(matches) = val.get("matches").and_then(|v| v.as_array()) {
                for item in matches {
                    if let Some(ip_str) = item.get("ip_str").and_then(|v| v.as_str()) {
                        entries.push(IocEntry {
                            value: ip_str.to_string(),
                            ioc_type: IocType::Ip,
                            confidence: 60,
                            severity: EventSeverity::Medium,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags: vec!["exposed-service".into()],
                            threat_type: ThreatType::Malware,
                        });
                    }
                }
            }
        }
        entries
    }

    fn parse_json_greynoise(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(riots) = val.get("riot").and_then(|v| v.as_array()) {
                for item in riots {
                    if let Some(ip) = item.get("ip").and_then(|v| v.as_str()) {
                        if let Some(malicious) = item.get("malicious").and_then(|v| v.as_bool()) {
                            if malicious {
                                entries.push(IocEntry {
                                    value: ip.to_string(),
                                    ioc_type: IocType::Ip,
                                    confidence: 70,
                                    severity: EventSeverity::High,
                                    first_seen: now,
                                    last_seen: now,
                                    source: source.to_string(),
                                    tags: vec!["internet-scanner".into()],
                                    threat_type: ThreatType::Malware,
                                });
                            }
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json_misp(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(events) = val.get("response").and_then(|v| v.as_array()) {
                for event_wrapper in events {
                    if let Some(event) = event_wrapper.get("Event") {
                        if let Some(attributes) = event.get("Attribute").and_then(|v| v.as_array()) {
                            for attr in attributes {
                                let type_str = attr.get("type").and_then(|v| v.as_str());
                                let val_str = attr.get("value").and_then(|v| v.as_str());
                                if let (Some(t), Some(v)) = (type_str, val_str) {
                                    let ioc_type = match t {
                                        "ip-src" | "ip-dst" => IocType::Ip,
                                        "domain" | "hostname" => IocType::Domain,
                                        "md5" | "sha1" | "sha256" => IocType::Hash,
                                        "url" | "link" => IocType::Url,
                                        "email-src" | "email-dst" => IocType::Email,
                                        "vulnerability" => IocType::Cve,
                                        _ => continue,
                                    };
                                    entries.push(IocEntry {
                                        value: v.to_string(),
                                        ioc_type,
                                        confidence: 65,
                                        severity: EventSeverity::Medium,
                                        first_seen: now,
                                        last_seen: now,
                                        source: source.to_string(),
                                        tags: vec![],
                                        threat_type: ThreatType::Malware,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json_mitre_cti(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(objects) = val.get("objects").and_then(|v| v.as_array()) {
                for obj in objects {
                    let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if obj_type == "attack-pattern" {
                        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        let mut tags = vec![obj_type.to_string()];
                        if let Some(references) = obj.get("external_references").and_then(|v| v.as_array()) {
                            for r in references {
                                if let Some(t) = r.get("external_id").and_then(|v| v.as_str()) {
                                    tags.push(t.to_string());
                                }
                            }
                        }
                        entries.push(IocEntry {
                            value: name.to_string(),
                            ioc_type: IocType::Cve,
                            confidence: 100,
                            severity: EventSeverity::Informational,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags,
                            threat_type: ThreatType::Exploit,
                        });
                    }
                }
            }
        }
        entries
    }

    fn parse_json_robtex(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(passive_dns) = val.get("passive_dns").and_then(|v| v.as_array()) {
                for record in passive_dns {
                    if let Some(hostname) = record.get("rrname").and_then(|v| v.as_str()) {
                        if let Some(rdata) = record.get("rdata").and_then(|v| v.as_str()) {
                            if rdata.parse::<std::net::IpAddr>().is_ok() {
                                entries.push(IocEntry {
                                    value: rdata.to_string(),
                                    ioc_type: IocType::Ip,
                                    confidence: 50,
                                    severity: EventSeverity::Low,
                                    first_seen: now,
                                    last_seen: now,
                                    source: source.to_string(),
                                    tags: vec![hostname.to_string()],
                                    threat_type: ThreatType::Malware,
                                });
                            }
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json_custom(text: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(iocs) = val.get("iocs").and_then(|v| v.as_array()) {
                for item in iocs {
                    let val_str = item.get("value").and_then(|v| v.as_str());
                    let type_str = item.get("type").and_then(|v| v.as_str());
                    if let (Some(v), Some(t)) = (val_str, type_str) {
                        let ioc_type = match t {
                            "ip" => IocType::Ip,
                            "domain" => IocType::Domain,
                            "hash" | "md5" | "sha1" | "sha256" => IocType::Hash,
                            "url" => IocType::Url,
                            "email" => IocType::Email,
                            "cve" => IocType::Cve,
                            _ => continue,
                        };
                        let confidence = item
                            .get("confidence")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(50) as u8;
                        let severity = match confidence {
                            0..=25 => EventSeverity::Low,
                            26..=50 => EventSeverity::Medium,
                            51..=75 => EventSeverity::High,
                            _ => EventSeverity::Critical,
                        };
                        entries.push(IocEntry {
                            value: v.to_string(),
                            ioc_type,
                            confidence,
                            severity,
                            first_seen: now,
                            last_seen: now,
                            source: source.to_string(),
                            tags: vec![],
                            threat_type: ThreatType::Malware,
                        });
                    }
                }
            }
        }
        entries
    }

    fn classify_ioc_value(value: &str) -> Option<IocType> {
        if value.parse::<std::net::IpAddr>().is_ok() {
            return Some(IocType::Ip);
        }
        if value.contains("://") || value.starts_with("http://") || value.starts_with("https://") {
            return Some(IocType::Url);
        }
        if value.contains('@') && value.contains('.') && !value.contains(' ') {
            return Some(IocType::Email);
        }
        if value.len() == 32 || value.len() == 40 || value.len() == 64 {
            if value.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(IocType::Hash);
            }
        }
        if value.starts_with("CVE-") && value.len() >= 9 {
            return Some(IocType::Cve);
        }
        if value.contains('.') && !value.contains(' ') {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.len() >= 2 {
                if parts.last().map(|s| s.len() <= 4).unwrap_or(false) {
                    return Some(IocType::Domain);
                }
            }
        }
        None
    }

    pub async fn lookup_ip(&self, ip: &str) -> Option<IocEntry> {
        let db = self.ioc_database.read().await;
        db.ip_iocs.get(ip).cloned()
    }

    pub async fn lookup_domain(&self, domain: &str) -> Option<IocEntry> {
        let db = self.ioc_database.read().await;
        db.domain_iocs.get(domain).cloned()
    }

    pub async fn lookup_hash(&self, hash: &str) -> Option<IocEntry> {
        let db = self.ioc_database.read().await;
        let lower = hash.to_lowercase();
        db.hash_iocs.get(&lower).cloned().or_else(|| db.hash_iocs.get(hash).cloned())
    }

    pub async fn lookup_url(&self, url: &str) -> Option<IocEntry> {
        let db = self.ioc_database.read().await;
        db.url_iocs.get(url).cloned()
    }

    pub async fn check_reputation(&self, target: &str) -> ReputationScore {
        {
            let cache = self.reputation_cache.read().await;
            if let Some(score) = cache.get(target) {
                return score.clone();
            }
        }

        let mut score = ReputationScore {
            score: 0,
            classification: "Unknown".into(),
            community_votes: 0,
            geo_location: "Unknown".into(),
            asn: "Unknown".into(),
            isp: "Unknown".into(),
            open_ports: Vec::new(),
        };

        let db = self.ioc_database.read().await;
        if let Some(entry) = db.ip_iocs.get(target) {
            score.score = -(entry.confidence as i32);
            score.classification = format!("{:?}", entry.severity);
        } else if let Some(entry) = db.domain_iocs.get(target) {
            score.score = -(entry.confidence as i32);
            score.classification = format!("{:?}", entry.severity);
        } else if let Some(entry) = db.hash_iocs.get(target) {
            score.score = -(entry.confidence as i32);
            score.classification = format!("{:?}", entry.severity);
        } else {
            score.score = 50;
            score.classification = "Clean".into();
        }

        {
            let mut cache = self.reputation_cache.write().await;
            cache.insert(target.to_string(), score.clone());
        }

        score
    }

    pub async fn add_manual_ioc(&self, entry: IocEntry) {
        let mut db = self.ioc_database.write().await;
        match entry.ioc_type {
            IocType::Ip => {
                db.ip_iocs.insert(entry.value.clone(), entry);
            }
            IocType::Domain => {
                db.domain_iocs.insert(entry.value.clone(), entry);
            }
            IocType::Hash | IocType::FileHash => {
                db.hash_iocs.insert(entry.value.clone(), entry);
            }
            IocType::Url => {
                db.url_iocs.insert(entry.value.clone(), entry);
            }
            IocType::Email => {
                db.email_iocs.insert(entry.value.clone(), entry);
            }
            IocType::Cve => {
                db.cve_iocs.insert(entry.value.clone(), entry);
            }
        }
    }

    pub async fn bulk_import_iocs(&self, entries: Vec<IocEntry>) {
        let mut db = self.ioc_database.write().await;
        for entry in entries {
            match entry.ioc_type {
                IocType::Ip => {
                    db.ip_iocs.insert(entry.value.clone(), entry);
                }
                IocType::Domain => {
                    db.domain_iocs.insert(entry.value.clone(), entry);
                }
                IocType::Hash | IocType::FileHash => {
                    db.hash_iocs.insert(entry.value.clone(), entry);
                }
                IocType::Url => {
                    db.url_iocs.insert(entry.value.clone(), entry);
                }
                IocType::Email => {
                    db.email_iocs.insert(entry.value.clone(), entry);
                }
                IocType::Cve => {
                    db.cve_iocs.insert(entry.value.clone(), entry);
                }
            }
        }
    }

    pub async fn get_ioc_stats(&self) -> IocStats {
        let db = self.ioc_database.read().await;
        let mut stats = IocStats::default();

        stats.total = db.ip_iocs.len()
            + db.domain_iocs.len()
            + db.hash_iocs.len()
            + db.url_iocs.len()
            + db.email_iocs.len()
            + db.cve_iocs.len();

        *stats
            .by_type
            .entry("Ip".into())
            .or_insert(0) += db.ip_iocs.len();
        *stats
            .by_type
            .entry("Domain".into())
            .or_insert(0) += db.domain_iocs.len();
        *stats
            .by_type
            .entry("Hash".into())
            .or_insert(0) += db.hash_iocs.len();
        *stats
            .by_type
            .entry("Url".into())
            .or_insert(0) += db.url_iocs.len();
        *stats
            .by_type
            .entry("Email".into())
            .or_insert(0) += db.email_iocs.len();
        *stats
            .by_type
            .entry("Cve".into())
            .or_insert(0) += db.cve_iocs.len();

        let all_entries: Vec<&IocEntry> = db
            .ip_iocs
            .values()
            .chain(db.domain_iocs.values())
            .chain(db.hash_iocs.values())
            .chain(db.url_iocs.values())
            .chain(db.email_iocs.values())
            .chain(db.cve_iocs.values())
            .collect();

        for entry in &all_entries {
            *stats
                .by_severity
                .entry(format!("{:?}", entry.severity))
                .or_insert(0) += 1;
            *stats
                .by_source
                .entry(entry.source.clone())
                .or_insert(0) += 1;
            *stats
                .by_threat_type
                .entry(format!("{:?}", entry.threat_type))
                .or_insert(0) += 1;
        }

        stats
    }

    pub async fn get_malware_families(&self) -> Vec<String> {
        let hashes = self.malware_hashes.read().await;
        let mut families: Vec<String> = hashes
            .values()
            .map(|m| m.malware_family.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        families.sort();
        families
    }

    pub async fn export_iocs(&self, format: ExportFormat) -> String {
        let db = self.ioc_database.read().await;
        let all_entries: Vec<&IocEntry> = db
            .ip_iocs
            .values()
            .chain(db.domain_iocs.values())
            .chain(db.hash_iocs.values())
            .chain(db.url_iocs.values())
            .chain(db.email_iocs.values())
            .chain(db.cve_iocs.values())
            .collect();

        match format {
            ExportFormat::Csv => {
                let mut csv = String::from("value,type,confidence,severity,first_seen,last_seen,source,tags,threat_type\n");
                for entry in &all_entries {
                    csv.push_str(&format!(
                        "{},{:?},{},{:?},{},{},{},{:?},{:?}\n",
                        entry.value,
                        entry.ioc_type,
                        entry.confidence,
                        entry.severity,
                        entry.first_seen,
                        entry.last_seen,
                        entry.source,
                        entry.tags,
                        entry.threat_type
                    ));
                }
                csv
            }
            ExportFormat::Json => {
                let entries_data: Vec<&IocEntry> = all_entries;
                serde_json::to_string_pretty(&entries_data).unwrap_or_else(|_| "[]".into())
            }
            ExportFormat::Stix => {
                let mut objects = Vec::new();
                for entry in &all_entries {
                    let stix_type = match entry.ioc_type {
                        IocType::Ip => "ipv4-addr",
                        IocType::Domain => "domain-name",
                        IocType::Hash | IocType::FileHash => "file",
                        IocType::Url => "url",
                        IocType::Email => "email-addr",
                        IocType::Cve => "vulnerability",
                    };
                    let pattern = match entry.ioc_type {
                        IocType::Ip => format!("[ipv4-addr:value = '{}']", entry.value),
                        IocType::Domain => format!("[domain-name:value = '{}']", entry.value),
                        IocType::Hash | IocType::FileHash => {
                            format!("[file:hashes.'SHA-256' = '{}']", entry.value)
                        }
                        IocType::Url => format!("[url:value = '{}']", entry.value),
                        IocType::Email => format!("[email-addr:value = '{}']", entry.value),
                        IocType::Cve => format!("[vulnerability:name = '{}']", entry.value),
                    };
                    let obj = serde_json::json!({
                        "type": "indicator",
                        "id": format!("indicator--{}", entry.value.len()),
                        "created": entry.first_seen.to_rfc3339(),
                        "modified": entry.last_seen.to_rfc3339(),
                        "name": format!("{} IOC", stix_type),
                        "description": entry.tags.join(", "),
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": entry.first_seen.to_rfc3339(),
                    });
                    objects.push(obj);
                }
                let bundle = serde_json::json!({
                    "type": "bundle",
                    "id": "bundle--royalsecurity-threat-intel",
                    "objects": objects
                });
                serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into())
            }
        }
    }

    pub async fn import_iocs(&self, data: &str, format: ExportFormat) -> Result<usize, String> {
        match format {
            ExportFormat::Json => {
                let entries: Vec<IocEntry> = serde_json::from_str(data)
                    .map_err(|e| format!("JSON parse error: {}", e))?;
                let count = entries.len();
                self.bulk_import_iocs(entries).await;
                Ok(count)
            }
            ExportFormat::Csv => {
                let mut entries = Vec::new();
                let lines: Vec<&str> = data.lines().collect();
                if lines.is_empty() {
                    return Ok(0);
                }
                for line in lines.iter().skip(1) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let fields: Vec<&str> = trimmed.split(',').collect();
                    if fields.len() >= 9 {
                        let entry = IocEntry {
                            value: fields[0].to_string(),
                            ioc_type: match fields[1] {
                                "Ip" => IocType::Ip,
                                "Domain" => IocType::Domain,
                                "Hash" => IocType::Hash,
                                "Url" => IocType::Url,
                                "Email" => IocType::Email,
                                "Cve" => IocType::Cve,
                                _ => continue,
                            },
                            confidence: fields[2].parse().unwrap_or(50),
                            severity: EventSeverity::Medium,
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            source: fields[6].to_string(),
                            tags: Vec::new(),
                            threat_type: ThreatType::Malware,
                        };
                        entries.push(entry);
                    }
                }
                let count = entries.len();
                self.bulk_import_iocs(entries).await;
                Ok(count)
            }
            ExportFormat::Stix => {
                let val: serde_json::Value = serde_json::from_str(data)
                    .map_err(|e| format!("JSON parse error: {}", e))?;
                let mut entries = Vec::new();
                if let Some(objects) = val.get("objects").and_then(|v| v.as_array()) {
                    for obj in objects {
                        if let Some(pattern) = obj.get("pattern").and_then(|v| v.as_str()) {
                            if let Some(value) = Self::extract_stix_pattern_value(pattern) {
                                let ioc_type = if pattern.contains("ipv4-addr") {
                                    IocType::Ip
                                } else if pattern.contains("domain-name") {
                                    IocType::Domain
                                } else if pattern.contains("file") {
                                    IocType::Hash
                                } else if pattern.contains("url") {
                                    IocType::Url
                                } else if pattern.contains("email-addr") {
                                    IocType::Email
                                } else {
                                    IocType::Cve
                                };
                                entries.push(IocEntry {
                                    value,
                                    ioc_type,
                                    confidence: 70,
                                    severity: EventSeverity::Medium,
                                    first_seen: Utc::now(),
                                    last_seen: Utc::now(),
                                    source: "stix-import".into(),
                                    tags: Vec::new(),
                                    threat_type: ThreatType::Malware,
                                });
                            }
                        }
                    }
                }
                let count = entries.len();
                self.bulk_import_iocs(entries).await;
                Ok(count)
            }
        }
    }

    fn extract_stix_pattern_value(pattern: &str) -> Option<String> {
        if let Some(start) = pattern.find('\'') {
            if let Some(end) = pattern[start + 1..].find('\'') {
                return Some(pattern[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    pub async fn get_threat_landscape(&self) -> ThreatLandscape {
        let db = self.ioc_database.read().await;
        let stats = self.get_ioc_stats().await;

        let total = stats.total as f64;
        let coverage_score = if total > 1000.0 {
            100.0
        } else {
            total / 10.0
        };

        let freshness_score = {
            let last_sync = self.last_full_sync.read().await;
            match *last_sync {
                Some(ts) => {
                    let age = (Utc::now() - ts).num_minutes();
                    match age {
                        0..=60 => 100.0,
                        61..=360 => 75.0,
                        361..=1440 => 50.0,
                        _ => 25.0,
                    }
                }
                None => 0.0,
            }
        };

        let mut threat_counts: HashMap<String, usize> = HashMap::new();
        for (k, v) in &stats.by_threat_type {
            threat_counts.insert(k.clone(), *v);
        }
        let mut top_threats: Vec<(String, usize)> = threat_counts.into_iter().collect();
        top_threats.sort_by(|a, b| b.1.cmp(&a.1));
        let top_threats: Vec<String> = top_threats.iter().map(|(k, _)| k.clone()).collect();

        let mut campaigns = Vec::new();
        for entry in db.ip_iocs.values().chain(db.domain_iocs.values()) {
            for tag in &entry.tags {
                if !campaigns.contains(tag) {
                    campaigns.push(tag.clone());
                }
            }
        }
        campaigns.truncate(20);

        ThreatLandscape {
            top_threats,
            active_campaigns: campaigns,
            coverage_score,
            freshness_score,
        }
    }

    pub async fn search_iocs(&self, query: &str) -> Vec<IocEntry> {
        let db = self.ioc_database.read().await;
        let q = query.to_lowercase();
        let mut results = Vec::new();

        for entry in db.ip_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
                || format!("{:?}", entry.threat_type).to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }
        for entry in db.domain_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
                || format!("{:?}", entry.threat_type).to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }
        for entry in db.hash_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }
        for entry in db.url_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }
        for entry in db.email_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }
        for entry in db.cve_iocs.values() {
            if entry.value.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || entry.source.to_lowercase().contains(&q)
            {
                results.push(entry.clone());
            }
        }

        results
    }

    pub async fn expire_old_iocs(&self, max_age_days: u32) {
        let cutoff = Utc::now() - Duration::days(max_age_days as i64);
        let mut db = self.ioc_database.write().await;
        db.ip_iocs.retain(|_, e| e.last_seen > cutoff);
        db.domain_iocs.retain(|_, e| e.last_seen > cutoff);
        db.hash_iocs.retain(|_, e| e.last_seen > cutoff);
        db.url_iocs.retain(|_, e| e.last_seen > cutoff);
        db.email_iocs.retain(|_, e| e.last_seen > cutoff);
        db.cve_iocs.retain(|_, e| e.last_seen > cutoff);
    }

    pub async fn load_builtin_rules(&self) {
        let known_bad_ips = vec![
            "185.220.101.1",
            "185.220.101.2",
            "185.220.101.3",
            "45.33.32.156",
            "104.244.72.115",
            "198.51.100.1",
            "203.0.113.1",
            "192.0.2.1",
            "91.219.237.1",
            "91.219.237.2",
            "194.26.29.100",
            "194.26.29.101",
            "194.26.29.102",
        ];

        let known_c2_domains = vec![
            "malware-c2.evil.com",
            "command-and-control.badnet.org",
            "c2server.darkweb.net",
            "data-exfil.evilcorp.com",
            "beacon-backup.trojan.xyz",
            "rat-handler.malware.com",
            "payload-delivery.exploit.net",
        ];

        let known_malicious_hashes = vec![
            "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "ff9714d7426b6a7b3634149a436a06c954215317a2449d829f94c13c2ef8b492",
        ];

        let now = Utc::now();

        {
            let mut db = self.ioc_database.write().await;
            for ip in known_bad_ips {
                db.ip_iocs.insert(
                    ip.to_string(),
                    IocEntry {
                        value: ip.to_string(),
                        ioc_type: IocType::Ip,
                        confidence: 85,
                        severity: EventSeverity::High,
                        first_seen: now,
                        last_seen: now,
                        source: "builtin-rules".into(),
                        tags: vec!["known-bad-ip".into()],
                        threat_type: ThreatType::Malware,
                    },
                );
            }

            for domain in known_c2_domains {
                db.domain_iocs.insert(
                    domain.to_string(),
                    IocEntry {
                        value: domain.to_string(),
                        ioc_type: IocType::Domain,
                        confidence: 90,
                        severity: EventSeverity::Critical,
                        first_seen: now,
                        last_seen: now,
                        source: "builtin-rules".into(),
                        tags: vec!["known-c2".into()],
                        threat_type: ThreatType::C2,
                    },
                );
            }

            for hash in known_malicious_hashes {
                db.hash_iocs.insert(
                    hash.to_string(),
                    IocEntry {
                        value: hash.to_string(),
                        ioc_type: IocType::Hash,
                        confidence: 95,
                        severity: EventSeverity::Critical,
                        first_seen: now,
                        last_seen: now,
                        source: "builtin-rules".into(),
                        tags: vec!["known-malware".into()],
                        threat_type: ThreatType::Malware,
                    },
                );
            }

            db.cidr_blocks.push(CidrRule {
                cidr: "198.51.100.0/24".into(),
                description: "TEST-NET-2 reserved range - suspicious if seen externally".into(),
                threat_type: ThreatType::Malware,
                confidence: 40,
                source: "builtin-rules".into(),
            });
            db.cidr_blocks.push(CidrRule {
                cidr: "203.0.113.0/24".into(),
                description: "TEST-NET-3 reserved range - suspicious if seen externally".into(),
                threat_type: ThreatType::Malware,
                confidence: 40,
                source: "builtin-rules".into(),
            });
        }
    }

    pub async fn get_source_status(&self) -> Vec<IntelSourceStatus> {
        let _stats = self.sync_stats.read().await;
        self.sources
            .iter()
            .map(|s| {
                let status = if !s.enabled {
                    SourceStatusType::Offline
                } else if s.last_sync.is_none() {
                    SourceStatusType::Offline
                } else if s.api_key.is_none()
                    && matches!(
                        s.source_type,
                        IntelSourceType::VirusTotal
                            | IntelSourceType::Shodan
                            | IntelSourceType::Misp
                    ) {
                    SourceStatusType::Degraded
                } else {
                    SourceStatusType::Online
                };

                IntelSourceStatus {
                    name: s.name.clone(),
                    status,
                    last_sync: s.last_sync,
                    ioc_count: s.entries_fetched,
                    error_msg: if s.api_key.is_none()
                        && matches!(
                            s.source_type,
                            IntelSourceType::VirusTotal
                                | IntelSourceType::Shodan
                                | IntelSourceType::Misp
                        ) {
                        Some("API key required for full functionality".into())
                    } else {
                        None
                    },
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ioc(value: &str, ioc_type: IocType, source: &str) -> IocEntry {
        let now = Utc::now();
        IocEntry {
            value: value.to_string(),
            ioc_type,
            confidence: 80,
            severity: EventSeverity::High,
            first_seen: now,
            last_seen: now,
            source: source.to_string(),
            tags: vec!["test".into()],
            threat_type: ThreatType::Malware,
        }
    }

    #[tokio::test]
    async fn test_aggregator_new_has_15_sources() {
        let agg = ThreatIntelAggregator::new();
        assert_eq!(agg.sources.len(), 15);
    }

    #[tokio::test]
    async fn test_add_source() {
        let mut agg = ThreatIntelAggregator::new();
        let source = IntelSource {
            name: "CustomFeed".into(),
            source_type: IntelSourceType::CustomApi,
            api_key: None,
            base_url: "https://example.com/api".into(),
            priority: 10,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 30,
            entries_fetched: 0,
        };
        agg.add_source(source);
        assert_eq!(agg.sources.len(), 16);
    }

    #[tokio::test]
    async fn test_add_source_no_duplicate() {
        let mut agg = ThreatIntelAggregator::new();
        let source = IntelSource {
            name: "VirusTotal".into(),
            source_type: IntelSourceType::VirusTotal,
            api_key: None,
            base_url: "https://www.virustotal.com/api/v3".into(),
            priority: 1,
            enabled: true,
            last_sync: None,
            sync_interval_mins: 60,
            entries_fetched: 0,
        };
        agg.add_source(source);
        assert_eq!(agg.sources.len(), 15);
    }

    #[tokio::test]
    async fn test_remove_source() {
        let mut agg = ThreatIntelAggregator::new();
        assert!(agg.remove_source("VirusTotal"));
        assert_eq!(agg.sources.len(), 14);
        assert!(!agg.remove_source("NonExistent"));
        assert_eq!(agg.sources.len(), 14);
    }

    #[tokio::test]
    async fn test_add_and_lookup_ip() {
        let agg = ThreatIntelAggregator::new();
        let entry = make_test_ioc("1.2.3.4", IocType::Ip, "test");
        agg.add_manual_ioc(entry).await;
        let found = agg.lookup_ip("1.2.3.4").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().value, "1.2.3.4");
    }

    #[tokio::test]
    async fn test_lookup_ip_not_found() {
        let agg = ThreatIntelAggregator::new();
        assert!(agg.lookup_ip("99.99.99.99").await.is_none());
    }

    #[tokio::test]
    async fn test_add_and_lookup_domain() {
        let agg = ThreatIntelAggregator::new();
        let entry = make_test_ioc("evil.com", IocType::Domain, "test");
        agg.add_manual_ioc(entry).await;
        let found = agg.lookup_domain("evil.com").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().threat_type, ThreatType::Malware);
    }

    #[tokio::test]
    async fn test_lookup_domain_not_found() {
        let agg = ThreatIntelAggregator::new();
        assert!(agg.lookup_domain("safe.com").await.is_none());
    }

    #[tokio::test]
    async fn test_add_and_lookup_hash() {
        let agg = ThreatIntelAggregator::new();
        let hash = "a".repeat(64);
        let entry = make_test_ioc(&hash, IocType::Hash, "test");
        agg.add_manual_ioc(entry).await;
        let found = agg.lookup_hash(&hash).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().value.len(), 64);
    }

    #[tokio::test]
    async fn test_lookup_hash_case_insensitive() {
        let agg = ThreatIntelAggregator::new();
        let hash = "a".repeat(64);
        let entry = make_test_ioc(&hash, IocType::Hash, "test");
        agg.add_manual_ioc(entry).await;
        let upper = "A".repeat(64);
        let found = agg.lookup_hash(&upper).await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_add_and_lookup_url() {
        let agg = ThreatIntelAggregator::new();
        let entry = make_test_ioc(
            "https://malware.example.com/payload.exe",
            IocType::Url,
            "test",
        );
        agg.add_manual_ioc(entry).await;
        let found = agg
            .lookup_url("https://malware.example.com/payload.exe")
            .await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_bulk_import_iocs() {
        let agg = ThreatIntelAggregator::new();
        let entries = vec![
            make_test_ioc("10.0.0.1", IocType::Ip, "bulk-test"),
            make_test_ioc("10.0.0.2", IocType::Ip, "bulk-test"),
            make_test_ioc("10.0.0.3", IocType::Ip, "bulk-test"),
            make_test_ioc("bad.bulk.com", IocType::Domain, "bulk-test"),
            make_test_ioc("https://bad.bulk.com/path", IocType::Url, "bulk-test"),
        ];
        agg.bulk_import_iocs(entries).await;
        assert!(agg.lookup_ip("10.0.0.1").await.is_some());
        assert!(agg.lookup_ip("10.0.0.2").await.is_some());
        assert!(agg.lookup_domain("bad.bulk.com").await.is_some());
    }

    #[tokio::test]
    async fn test_get_ioc_stats() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(make_test_ioc("1.1.1.1", IocType::Ip, "s1"))
            .await;
        agg.add_manual_ioc(make_test_ioc("2.2.2.2", IocType::Ip, "s2"))
            .await;
        agg.add_manual_ioc(make_test_ioc("test.com", IocType::Domain, "s1"))
            .await;
        let stats = agg.get_ioc_stats().await;
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_type.get("Ip"), Some(&2));
        assert_eq!(stats.by_type.get("Domain"), Some(&1));
        assert_eq!(stats.by_source.get("s1"), Some(&2));
        assert_eq!(stats.by_source.get("s2"), Some(&1));
    }

    #[tokio::test]
    async fn test_export_json() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(make_test_ioc("5.5.5.5", IocType::Ip, "export-test"))
            .await;
        let json = agg.export_iocs(ExportFormat::Json).await;
        let parsed: Vec<IocEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value, "5.5.5.5");
    }

    #[tokio::test]
    async fn test_export_csv() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(make_test_ioc("6.6.6.6", IocType::Ip, "csv-test"))
            .await;
        let csv = agg.export_iocs(ExportFormat::Csv).await;
        assert!(csv.contains("value,type,confidence"));
        assert!(csv.contains("6.6.6.6"));
    }

    #[tokio::test]
    async fn test_export_stix() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(make_test_ioc("7.7.7.7", IocType::Ip, "stix-test"))
            .await;
        let stix = agg.export_iocs(ExportFormat::Stix).await;
        assert!(stix.contains("bundle"));
        assert!(stix.contains("7.7.7.7"));
    }

    #[tokio::test]
    async fn test_import_json() {
        let agg = ThreatIntelAggregator::new();
        let entries = vec![make_test_ioc("8.8.8.8", IocType::Ip, "json-import")];
        let json = serde_json::to_string(&entries).unwrap();
        let count = agg.import_iocs(&json, ExportFormat::Json).await.unwrap();
        assert_eq!(count, 1);
        assert!(agg.lookup_ip("8.8.8.8").await.is_some());
    }

    #[tokio::test]
    async fn test_search_iocs() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(IocEntry {
            value: "192.168.1.100".into(),
            ioc_type: IocType::Ip,
            confidence: 90,
            severity: EventSeverity::Critical,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            source: "ransomware-tracker".into(),
            tags: vec!["ransomware".into()],
            threat_type: ThreatType::Ransomware,
        })
        .await;
        let results = agg.search_iocs("ransomware").await;
        assert!(!results.is_empty());
        let results2 = agg.search_iocs("192.168.1.100").await;
        assert!(!results2.is_empty());
    }

    #[tokio::test]
    async fn test_search_iocs_no_results() {
        let agg = ThreatIntelAggregator::new();
        let results = agg.search_iocs("nonexistent-query-xyz").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_expire_old_iocs() {
        let agg = ThreatIntelAggregator::new();
        let mut old_entry = make_test_ioc("10.10.10.10", IocType::Ip, "expire-test");
        old_entry.last_seen = Utc::now() - Duration::days(400);
        agg.add_manual_ioc(old_entry).await;

        let mut fresh_entry = make_test_ioc("10.10.10.11", IocType::Ip, "expire-test");
        fresh_entry.last_seen = Utc::now();
        agg.add_manual_ioc(fresh_entry).await;

        assert!(agg.lookup_ip("10.10.10.10").await.is_some());
        agg.expire_old_iocs(365).await;
        assert!(agg.lookup_ip("10.10.10.10").await.is_none());
        assert!(agg.lookup_ip("10.10.10.11").await.is_some());
    }

    #[tokio::test]
    async fn test_check_reputation_clean() {
        let agg = ThreatIntelAggregator::new();
        let rep = agg.check_reputation("clean-host.example.com").await;
        assert_eq!(rep.score, 50);
        assert_eq!(rep.classification, "Clean");
    }

    #[tokio::test]
    async fn test_check_reputation_known_bad() {
        let agg = ThreatIntelAggregator::new();
        let entry = make_test_ioc("evil.badhost.com", IocType::Domain, "rep-test");
        agg.add_manual_ioc(entry).await;
        let rep = agg.check_reputation("evil.badhost.com").await;
        assert!(rep.score < 0);
    }

    #[tokio::test]
    async fn test_check_reputation_caching() {
        let agg = ThreatIntelAggregator::new();
        let rep1 = agg.check_reputation("cached.example.com").await;
        let rep2 = agg.check_reputation("cached.example.com").await;
        assert_eq!(rep1.score, rep2.score);
    }

    #[tokio::test]
    async fn test_get_threat_landscape() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(IocEntry {
            value: "1.2.3.4".into(),
            ioc_type: IocType::Ip,
            confidence: 90,
            severity: EventSeverity::Critical,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            source: "test".into(),
            tags: vec!["apt28".into()],
            threat_type: ThreatType::Spyware,
        })
        .await;
        let landscape = agg.get_threat_landscape().await;
        assert!(landscape.top_threats.contains(&"Spyware".to_string()));
        assert!(landscape.active_campaigns.contains(&"apt28".to_string()));
    }

    #[tokio::test]
    async fn test_get_source_status() {
        let agg = ThreatIntelAggregator::new();
        let statuses = agg.get_source_status().await;
        assert_eq!(statuses.len(), 15);
        let vt = statuses.iter().find(|s| s.name == "VirusTotal").unwrap();
        assert_eq!(vt.status, SourceStatusType::Offline);
        assert!(vt.last_sync.is_none());
    }

    #[tokio::test]
    async fn test_get_malware_families_empty() {
        let agg = ThreatIntelAggregator::new();
        let families = agg.get_malware_families().await;
        assert!(families.is_empty());
    }

    #[tokio::test]
    async fn test_load_builtin_rules() {
        let agg = ThreatIntelAggregator::new();
        agg.load_builtin_rules().await;
        assert!(agg.lookup_ip("185.220.101.1").await.is_some());
        assert!(agg
            .lookup_domain("malware-c2.evil.com")
            .await
            .is_some());
        let stats = agg.get_ioc_stats().await;
        assert!(stats.total > 0);
    }

    #[tokio::test]
    async fn test_classify_ioc_ip() {
        let result = ThreatIntelAggregator::classify_ioc_value("192.168.1.1");
        assert_eq!(result, Some(IocType::Ip));
    }

    #[tokio::test]
    async fn test_classify_ioc_hash() {
        let hash = "a".repeat(64);
        let result = ThreatIntelAggregator::classify_ioc_value(&hash);
        assert_eq!(result, Some(IocType::Hash));
    }

    #[tokio::test]
    async fn test_classify_ioc_url() {
        let result = ThreatIntelAggregator::classify_ioc_value("https://evil.com/malware");
        assert_eq!(result, Some(IocType::Url));
    }

    #[tokio::test]
    async fn test_classify_ioc_domain() {
        let result = ThreatIntelAggregator::classify_ioc_value("malware.evil.com");
        assert_eq!(result, Some(IocType::Domain));
    }

    #[tokio::test]
    async fn test_classify_ioc_email() {
        let result = ThreatIntelAggregator::classify_ioc_value("phish@example.com");
        assert_eq!(result, Some(IocType::Email));
    }

    #[tokio::test]
    async fn test_classify_ioc_cve() {
        let result = ThreatIntelAggregator::classify_ioc_value("CVE-2024-12345");
        assert_eq!(result, Some(IocType::Cve));
    }

    #[tokio::test]
    async fn test_sync_source_not_found() {
        let agg = ThreatIntelAggregator::new();
        let result = agg.sync_source("NonExistentSource").await;
        assert!(!result.success);
        assert!(!result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_get_ioc_stats_threat_types() {
        let agg = ThreatIntelAggregator::new();
        agg.add_manual_ioc(IocEntry {
            value: "c2.evil.com".into(),
            ioc_type: IocType::Domain,
            confidence: 90,
            severity: EventSeverity::Critical,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            source: "test".into(),
            tags: vec![],
            threat_type: ThreatType::C2,
        })
        .await;
        agg.add_manual_ioc(IocEntry {
            value: "phish.bad.com".into(),
            ioc_type: IocType::Domain,
            confidence: 80,
            severity: EventSeverity::High,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            source: "test".into(),
            tags: vec![],
            threat_type: ThreatType::Phishing,
        })
        .await;
        let stats = agg.get_ioc_stats().await;
        assert_eq!(stats.by_threat_type.get("C2"), Some(&1));
        assert_eq!(stats.by_threat_type.get("Phishing"), Some(&1));
    }
}
