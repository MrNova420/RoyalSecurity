use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub enabled: bool,
    pub update_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    Stix,
    Taxii,
    Csv,
    LineDelimited,
    Json,
    OpenThreatExchange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub value: String,
    pub ioc_type: IocType,
    pub confidence: f64,
    pub severity: String,
    pub source: String,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    Mutex,
    RegistryKey,
    FilePath,
    EmailAddress,
    CertificateThumbprint,
    Cidr,
    YaraRule,
}

impl IocType {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ip" | "ip-address" | "ipaddr" => Self::IpAddress,
            "domain" | "hostname" => Self::Domain,
            "url" | "uri" => Self::Url,
            "md5" => Self::FileHashMd5,
            "sha1" => Self::FileHashSha1,
            "sha256" => Self::FileHashSha256,
            "mutex" => Self::Mutex,
            "registry" | "regkey" => Self::RegistryKey,
            "filepath" | "path" => Self::FilePath,
            "email" => Self::EmailAddress,
            "cert" | "thumbprint" => Self::CertificateThumbprint,
            "cidr" | "subnet" => Self::Cidr,
            "yara" => Self::YaraRule,
            _ => Self::Domain,
        }
    }
}

pub struct FeedManager {
    feeds: Vec<ThreatFeed>,
    client: reqwest::Client,
}

impl FeedManager {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("RoyalSecurity/0.1")
            .build()
            .unwrap_or_default();
        Self {
            feeds: Vec::new(),
            client,
        }
    }

    pub fn add_feed(&mut self, feed: ThreatFeed) {
        info!(name = %feed.name, url = %feed.url, "Added threat feed");
        self.feeds.push(feed);
    }

    pub async fn fetch_feed(
        &self,
        feed: &ThreatFeed,
    ) -> Result<Vec<IocEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let response = self.client.get(&feed.url).send().await?;
        let text = response.text().await?;

        match feed.feed_type {
            FeedType::LineDelimited => Ok(Self::parse_line_delimited(&text, &feed.name)),
            FeedType::Csv => Ok(Self::parse_csv(&text, &feed.name)),
            FeedType::Json => Ok(Self::parse_json(&text, &feed.name)),
            _ => {
                warn!(feed = %feed.name, "Unsupported feed type");
                Ok(Vec::new())
            }
        }
    }

    pub(crate) fn parse_line_delimited(text: &str, source: &str) -> Vec<IocEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(ioc) = Self::classify_ioc(line, source) {
                entries.push(ioc);
            }
        }
        entries
    }

    fn parse_csv(text: &str, source: &str) -> Vec<IocEntry> {
        let mut entries = Vec::new();
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() {
            return entries;
        }
        for line in &lines[1..] {
            let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if fields.len() >= 2 {
                if let Some(ioc) = Self::classify_ioc(fields[0], source) {
                    entries.push(ioc);
                }
            }
        }
        entries
    }

    fn parse_json(text: &str, source: &str) -> Vec<IocEntry> {
        if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
            items
                .into_iter()
                .filter_map(|item| {
                    let value = item.get("value")?.as_str()?;
                    let ioc_type = item
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("domain");
                    Some(IocEntry {
                        value: value.to_string(),
                        ioc_type: IocType::from_string(ioc_type),
                        confidence: item
                            .get("confidence")
                            .and_then(|c| c.as_f64())
                            .unwrap_or(0.7),
                        severity: item
                            .get("severity")
                            .and_then(|s| s.as_str())
                            .unwrap_or("medium")
                            .into(),
                        source: source.to_string(),
                        tags: Vec::new(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        expiry: None,
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub(crate) fn classify_ioc(value: &str, source: &str) -> Option<IocEntry> {
        let re_ip = regex::Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").ok()?;
        let re_md5 = regex::Regex::new(r"^[a-fA-F0-9]{32}$").ok()?;
        let re_sha1 = regex::Regex::new(r"^[a-fA-F0-9]{40}$").ok()?;
        let re_sha256 = regex::Regex::new(r"^[a-fA-F0-9]{64}$").ok()?;

        let ioc_type = if re_ip.is_match(value) {
            IocType::IpAddress
        } else if re_md5.is_match(value) {
            IocType::FileHashMd5
        } else if re_sha1.is_match(value) {
            IocType::FileHashSha1
        } else if re_sha256.is_match(value) {
            IocType::FileHashSha256
        } else if value.contains('/') || value.starts_with("http") {
            IocType::Url
        } else if value.contains('.') && !value.contains(' ') {
            IocType::Domain
        } else {
            return None;
        };

        Some(IocEntry {
            value: value.to_string(),
            ioc_type,
            confidence: 0.7,
            severity: "medium".into(),
            source: source.to_string(),
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expiry: None,
        })
    }

    pub fn feeds(&self) -> &[ThreatFeed] {
        &self.feeds
    }
}
