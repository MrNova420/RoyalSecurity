pub mod prelude;

use chrono::{DateTime, Utc};
use regex::Regex;
use royalsecurity_common::types::EventSeverity;
use royalsecurity_common::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LogCategory {
    Process,
    Network,
    File,
    Registry,
    Authentication,
    Policy,
    System,
    Application,
    Security,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CorrOperator {
    Equals,
    Contains,
    GreaterThan,
    LessThan,
    Regex,
    NotEquals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub max_buffer_size: usize,
    pub correlation_window_secs: u64,
    pub min_events_for_correlation: u32,
    pub enable_auto_alert: bool,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 50_000,
            correlation_window_secs: 300,
            min_events_for_correlation: 3,
            enable_auto_alert: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: LogCategory,
    pub message: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCondition {
    pub field: String,
    pub operator: CorrOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<CorrelationCondition>,
    pub window_secs: u64,
    pub threshold: u32,
    pub severity: EventSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemAlert {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: EventSeverity,
    pub matched_events: Vec<Uuid>,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiemStats {
    pub total_ingested: u64,
    pub total_alerts: u64,
    pub buffer_size: usize,
    pub category_counts: HashMap<String, u64>,
    pub source_counts: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQuery {
    pub category: Option<LogCategory>,
    pub source: Option<String>,
    pub severity_min: Option<EventSeverity>,
    pub search_text: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: usize,
}

impl Default for LogQuery {
    fn default() -> Self {
        Self {
            category: None,
            source: None,
            severity_min: None,
            search_text: None,
            start_time: None,
            end_time: None,
            limit: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemExport {
    pub alerts: Vec<SiemAlert>,
    pub exported_at: DateTime<Utc>,
    pub total_count: usize,
}

pub struct LocalSiem {
    log_buffer: Vec<NormalizedLog>,
    correlation_rules: Vec<CorrelationRule>,
    alerts: Vec<SiemAlert>,
    config: SiemConfig,
    stats: SiemStats,
}

impl LocalSiem {
    pub fn new() -> Self {
        Self::with_config(SiemConfig::default())
    }

    pub fn with_config(config: SiemConfig) -> Self {
        info!(
            max_buffer = config.max_buffer_size,
            correlation_window = config.correlation_window_secs,
            "Initialized SIEM module"
        );
        Self {
            log_buffer: Vec::with_capacity(config.max_buffer_size.min(1024)),
            correlation_rules: Vec::new(),
            alerts: Vec::new(),
            stats: SiemStats::default(),
            config,
        }
    }

    pub fn ingest(&mut self, log: NormalizedLog) {
        if self.log_buffer.len() >= self.config.max_buffer_size {
            self.log_buffer.remove(0);
        }
        self.log_buffer.push(log.clone());

        self.stats.total_ingested += 1;
        self.stats.buffer_size = self.log_buffer.len();
        *self
            .stats
            .category_counts
            .entry(format!("{:?}", log.category))
            .or_insert(0) += 1;
        *self
            .stats
            .source_counts
            .entry(log.source.clone())
            .or_insert(0) += 1;

        if self.config.enable_auto_alert {
            let new_alerts = self.check_correlation();
            for alert in &new_alerts {
                warn!(
                    alert_id = %alert.id,
                    rule = %alert.rule_name,
                    severity = ?alert.severity,
                    "Correlation alert triggered"
                );
            }
        }

        debug!(
            buffer_size = self.log_buffer.len(),
            total = self.stats.total_ingested,
            "Log ingested"
        );
    }

    pub fn ingest_raw(
        &mut self,
        source: &str,
        category: LogCategory,
        message: &str,
        severity: EventSeverity,
    ) -> Uuid {
        let log = NormalizedLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: source.to_string(),
            category,
            message: message.to_string(),
            fields: HashMap::new(),
            severity,
        };
        let id = log.id;
        self.ingest(log);
        id
    }

    pub fn query(&self, filter: &LogQuery) -> Vec<&NormalizedLog> {
        self.log_buffer
            .iter()
            .filter(|log| {
                if let Some(ref cat) = filter.category {
                    if log.category != *cat {
                        return false;
                    }
                }
                if let Some(ref src) = filter.source {
                    if log.source != *src {
                        return false;
                    }
                }
                if let Some(min_sev) = filter.severity_min {
                    if log.severity < min_sev {
                        return false;
                    }
                }
                if let Some(ref text) = filter.search_text {
                    let t = text.to_lowercase();
                    if !log.message.to_lowercase().contains(&t)
                        && !log.source.to_lowercase().contains(&t)
                    {
                        return false;
                    }
                }
                if let Some(start) = filter.start_time {
                    if log.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = filter.end_time {
                    if log.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .take(filter.limit)
            .collect()
    }

    pub fn check_correlation(&mut self) -> Vec<SiemAlert> {
        let mut new_alerts = Vec::new();
        let now = Utc::now();

        for rule in &self.correlation_rules {
            if !rule.enabled {
                continue;
            }

            let window_start =
                now - chrono::Duration::seconds(rule.window_secs as i64);

            let matching: Vec<&NormalizedLog> = self
                .log_buffer
                .iter()
                .filter(|log| log.timestamp >= window_start)
                .filter(|log| self.matches_conditions(log, &rule.conditions))
                .collect();

            if matching.len() as u32 >= rule.threshold {
                let already_fired = self.alerts.iter().any(|a| {
                    a.rule_id == rule.id
                        && (now - a.timestamp)
                            < chrono::Duration::seconds(rule.window_secs as i64)
                });

                if !already_fired {
                    let matched_ids = matching.iter().map(|l| l.id).collect();
                    let alert = SiemAlert {
                        id: Uuid::new_v4(),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        matched_events: matched_ids,
                        description: format!(
                            "Rule '{}' matched {} events (threshold: {})",
                            rule.name,
                            matching.len(),
                            rule.threshold
                        ),
                        timestamp: now,
                        acknowledged: false,
                    };
                    new_alerts.push(alert);
                }
            }
        }

        for alert in &new_alerts {
            self.alerts.push(alert.clone());
            self.stats.total_alerts += 1;
        }

        new_alerts
    }

    fn matches_conditions(
        &self,
        log: &NormalizedLog,
        conditions: &[CorrelationCondition],
    ) -> bool {
        conditions.iter().all(|cond| {
            let field_value: Option<String> = if cond.field == "message" {
                Some(log.message.clone())
            } else if cond.field == "source" {
                Some(log.source.clone())
            } else if cond.field == "category" {
                Some(format!("{:?}", log.category))
            } else if cond.field == "severity" {
                Some(format!("{:?}", log.severity))
            } else {
                log.fields
                    .get(&cond.field)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };

            match field_value.as_deref() {
                Some(val) => match cond.operator {
                    CorrOperator::Equals => val == cond.value,
                    CorrOperator::NotEquals => val != cond.value,
                    CorrOperator::Contains => val.contains(&cond.value),
                    CorrOperator::GreaterThan => {
                        val.parse::<f64>().ok().and_then(|v| {
                            cond.value.parse::<f64>().ok().map(|t| v > t)
                        }).unwrap_or(false)
                    }
                    CorrOperator::LessThan => {
                        val.parse::<f64>().ok().and_then(|v| {
                            cond.value.parse::<f64>().ok().map(|t| v < t)
                        }).unwrap_or(false)
                    }
                    CorrOperator::Regex => {
                        Regex::new(&cond.value)
                            .ok()
                            .map(|re| re.is_match(val))
                            .unwrap_or(false)
                    }
                },
                None => false,
            }
        })
    }

    pub fn add_correlation_rule(&mut self, rule: CorrelationRule) {
        info!(rule_id = %rule.id, rule_name = %rule.name, "Added correlation rule");
        self.correlation_rules.push(rule);
    }

    pub fn remove_correlation_rule(&mut self, rule_id: &str) -> bool {
        let before = self.correlation_rules.len();
        self.correlation_rules.retain(|r| r.id != rule_id);
        let removed = self.correlation_rules.len() < before;
        if removed {
            info!(rule_id = %rule_id, "Removed correlation rule");
        }
        removed
    }

    pub fn acknowledge_alert(&mut self, alert_id: Uuid) -> bool {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            info!(alert_id = %alert_id, "Alert acknowledged");
            true
        } else {
            false
        }
    }

    pub fn get_alerts(&self, only_unack: bool) -> Vec<&SiemAlert> {
        self.alerts
            .iter()
            .filter(|a| !only_unack || !a.acknowledged)
            .collect()
    }

    pub fn stats(&self) -> &SiemStats {
        &self.stats
    }

    pub fn purge_old(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        let before = self.log_buffer.len();
        self.log_buffer.retain(|log| log.timestamp >= cutoff);
        let purged = before - self.log_buffer.len();
        self.stats.buffer_size = self.log_buffer.len();
        if purged > 0 {
            info!(purged = purged, remaining = self.log_buffer.len(), "Purged old logs");
        }
    }

    pub fn export_alerts_json(&self) -> Result<String> {
        let export = SiemExport {
            alerts: self.alerts.clone(),
            exported_at: Utc::now(),
            total_count: self.alerts.len(),
        };
        Ok(serde_json::to_string_pretty(&export)?)
    }
}

impl Default for LocalSiem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(source: &str, category: LogCategory, message: &str, severity: EventSeverity) -> NormalizedLog {
        NormalizedLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: source.to_string(),
            category,
            message: message.to_string(),
            fields: HashMap::new(),
            severity,
        }
    }

    #[test]
    fn test_new_siem() {
        let siem = LocalSiem::new();
        assert_eq!(siem.stats.total_ingested, 0);
        assert_eq!(siem.stats.buffer_size, 0);
        assert!(siem.alerts.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = SiemConfig::default();
        assert_eq!(config.max_buffer_size, 50_000);
        assert_eq!(config.correlation_window_secs, 300);
        assert_eq!(config.min_events_for_correlation, 3);
        assert!(config.enable_auto_alert);
    }

    #[test]
    fn test_ingest_single_log() {
        let mut siem = LocalSiem::new();
        let log = make_log("sysmon", LogCategory::Process, "Process created", EventSeverity::Low);
        siem.ingest(log);
        assert_eq!(siem.stats.total_ingested, 1);
        assert_eq!(siem.stats.buffer_size, 1);
        assert_eq!(siem.log_buffer.len(), 1);
    }

    #[test]
    fn test_ingest_raw() {
        let mut siem = LocalSiem::new();
        let id = siem.ingest_raw(
            "firewall",
            LogCategory::Network,
            "Blocked connection to 10.0.0.1",
            EventSeverity::Medium,
        );
        assert_eq!(siem.stats.total_ingested, 1);
        assert_eq!(siem.log_buffer[0].id, id);
        assert_eq!(siem.log_buffer[0].source, "firewall");
    }

    #[test]
    fn test_ring_buffer_eviction() {
        let mut config = SiemConfig::default();
        config.max_buffer_size = 5;
        let mut siem = LocalSiem::with_config(config);

        for i in 0..10 {
            siem.ingest_raw("src", LogCategory::System, &format!("msg {}", i), EventSeverity::Low);
        }
        assert_eq!(siem.log_buffer.len(), 5);
        assert_eq!(siem.stats.total_ingested, 10);
        assert_eq!(siem.log_buffer[0].message, "msg 5");
    }

    #[test]
    fn test_query_by_category() {
        let mut siem = LocalSiem::new();
        siem.ingest(make_log("s", LogCategory::Network, "net msg", EventSeverity::Low));
        siem.ingest(make_log("s", LogCategory::File, "file msg", EventSeverity::Low));
        siem.ingest(make_log("s", LogCategory::Network, "net msg 2", EventSeverity::High));

        let filter = LogQuery {
            category: Some(LogCategory::Network),
            ..Default::default()
        };
        let results = siem.query(&filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_source() {
        let mut siem = LocalSiem::new();
        siem.ingest(make_log("sysmon", LogCategory::Process, "msg1", EventSeverity::Low));
        siem.ingest(make_log("firewall", LogCategory::Network, "msg2", EventSeverity::Low));

        let filter = LogQuery {
            source: Some("sysmon".to_string()),
            ..Default::default()
        };
        let results = siem.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source, "sysmon");
    }

    #[test]
    fn test_query_by_severity() {
        let mut siem = LocalSiem::new();
        siem.ingest(make_log("s", LogCategory::System, "info", EventSeverity::Informational));
        siem.ingest(make_log("s", LogCategory::System, "high", EventSeverity::High));
        siem.ingest(make_log("s", LogCategory::System, "crit", EventSeverity::Critical));

        let filter = LogQuery {
            severity_min: Some(EventSeverity::High),
            ..Default::default()
        };
        let results = siem.query(&filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_search_text() {
        let mut siem = LocalSiem::new();
        siem.ingest(make_log("s", LogCategory::Application, "Login failed", EventSeverity::Medium));
        siem.ingest(make_log("s", LogCategory::Application, "File saved", EventSeverity::Low));

        let filter = LogQuery {
            search_text: Some("login".to_string()),
            ..Default::default()
        };
        let results = siem.query(&filter);
        assert_eq!(results.len(), 1);
        assert!(results[0].message.contains("Login"));
    }

    #[test]
    fn test_query_limit() {
        let mut siem = LocalSiem::new();
        for i in 0..20 {
            siem.ingest(make_log("s", LogCategory::System, &format!("msg {}", i), EventSeverity::Low));
        }

        let filter = LogQuery {
            limit: 5,
            ..Default::default()
        };
        let results = siem.query(&filter);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_correlation_rule_match() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = false;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "rule-1".to_string(),
            name: "Brute Force".to_string(),
            description: "Multiple auth failures".to_string(),
            conditions: vec![CorrelationCondition {
                field: "category".to_string(),
                operator: CorrOperator::Equals,
                value: "Authentication".to_string(),
            }],
            window_secs: 300,
            threshold: 3,
            severity: EventSeverity::High,
            enabled: true,
        });

        for _ in 0..3 {
            siem.ingest(make_log(
                "auth",
                LogCategory::Authentication,
                "Login failed",
                EventSeverity::Medium,
            ));
        }

        let alerts = siem.check_correlation();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "Brute Force");
        assert_eq!(alerts[0].matched_events.len(), 3);
    }

    #[test]
    fn test_correlation_below_threshold() {
        let mut siem = LocalSiem::new();

        siem.add_correlation_rule(CorrelationRule {
            id: "rule-2".to_string(),
            name: "Threshold Rule".to_string(),
            description: "Needs 5 events".to_string(),
            conditions: vec![CorrelationCondition {
                field: "category".to_string(),
                operator: CorrOperator::Equals,
                value: "Network".to_string(),
            }],
            window_secs: 300,
            threshold: 5,
            severity: EventSeverity::High,
            enabled: true,
        });

        for _ in 0..3 {
            siem.ingest(make_log(
                "fw",
                LogCategory::Network,
                "Connection",
                EventSeverity::Low,
            ));
        }

        let alerts = siem.check_correlation();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_auto_alert_on_ingest() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = true;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "auto-rule".to_string(),
            name: "Auto Alert".to_string(),
            description: "Test".to_string(),
            conditions: vec![CorrelationCondition {
                field: "source".to_string(),
                operator: CorrOperator::Equals,
                value: "malicious".to_string(),
            }],
            window_secs: 300,
            threshold: 2,
            severity: EventSeverity::Critical,
            enabled: true,
        });

        siem.ingest_raw("malicious", LogCategory::Security, "IOC hit", EventSeverity::High);
        assert!(siem.alerts.is_empty());

        siem.ingest_raw("malicious", LogCategory::Security, "IOC hit 2", EventSeverity::High);
        assert_eq!(siem.alerts.len(), 1);
        assert_eq!(siem.alerts[0].severity, EventSeverity::Critical);
    }

    #[test]
    fn test_acknowledge_alert() {
        let mut siem = LocalSiem::new();
        let log = make_log("s", LogCategory::Security, "test", EventSeverity::High);
        let alert_id = Uuid::new_v4();
        siem.alerts.push(SiemAlert {
            id: alert_id,
            rule_id: "r1".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: EventSeverity::High,
            matched_events: vec![log.id],
            description: "Test alert".to_string(),
            timestamp: Utc::now(),
            acknowledged: false,
        });

        assert!(siem.acknowledge_alert(alert_id));
        assert!(siem.alerts[0].acknowledged);
        assert!(!siem.acknowledge_alert(Uuid::new_v4()));
    }

    #[test]
    fn test_get_alerts_filter() {
        let mut siem = LocalSiem::new();
        siem.alerts.push(SiemAlert {
            id: Uuid::new_v4(),
            rule_id: "r1".to_string(),
            rule_name: "A".to_string(),
            severity: EventSeverity::High,
            matched_events: vec![],
            description: "".to_string(),
            timestamp: Utc::now(),
            acknowledged: true,
        });
        siem.alerts.push(SiemAlert {
            id: Uuid::new_v4(),
            rule_id: "r2".to_string(),
            rule_name: "B".to_string(),
            severity: EventSeverity::Critical,
            matched_events: vec![],
            description: "".to_string(),
            timestamp: Utc::now(),
            acknowledged: false,
        });

        let all = siem.get_alerts(false);
        assert_eq!(all.len(), 2);

        let unack = siem.get_alerts(true);
        assert_eq!(unack.len(), 1);
        assert_eq!(unack[0].rule_name, "B");
    }

    #[test]
    fn test_add_remove_correlation_rule() {
        let mut siem = LocalSiem::new();
        siem.add_correlation_rule(CorrelationRule {
            id: "r1".to_string(),
            name: "Rule 1".to_string(),
            description: "".to_string(),
            conditions: vec![],
            window_secs: 60,
            threshold: 1,
            severity: EventSeverity::Low,
            enabled: true,
        });
        assert_eq!(siem.correlation_rules.len(), 1);

        assert!(siem.remove_correlation_rule("r1"));
        assert!(siem.correlation_rules.is_empty());
        assert!(!siem.remove_correlation_rule("nonexistent"));
    }

    #[test]
    fn test_purge_old_logs() {
        let mut siem = LocalSiem::new();
        let old = NormalizedLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now() - chrono::Duration::seconds(600),
            source: "old".to_string(),
            category: LogCategory::System,
            message: "old log".to_string(),
            fields: HashMap::new(),
            severity: EventSeverity::Low,
        };
        siem.ingest(old);
        siem.ingest(make_log("new", LogCategory::System, "new log", EventSeverity::Low));

        assert_eq!(siem.log_buffer.len(), 2);
        siem.purge_old(300);
        assert_eq!(siem.log_buffer.len(), 1);
        assert_eq!(siem.log_buffer[0].message, "new log");
    }

    #[test]
    fn test_export_alerts_json() {
        let mut siem = LocalSiem::new();
        siem.alerts.push(SiemAlert {
            id: Uuid::new_v4(),
            rule_id: "r1".to_string(),
            rule_name: "Test".to_string(),
            severity: EventSeverity::Medium,
            matched_events: vec![],
            description: "desc".to_string(),
            timestamp: Utc::now(),
            acknowledged: false,
        });

        let json = siem.export_alerts_json().unwrap();
        let parsed: SiemExport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_count, 1);
        assert_eq!(parsed.alerts[0].rule_name, "Test");
    }

    #[test]
    fn test_stats_tracking() {
        let mut siem = LocalSiem::new();
        siem.ingest_raw("sysmon", LogCategory::Process, "p1", EventSeverity::Low);
        siem.ingest_raw("sysmon", LogCategory::Process, "p2", EventSeverity::Low);
        siem.ingest_raw("fw", LogCategory::Network, "n1", EventSeverity::High);

        let stats = siem.stats();
        assert_eq!(stats.total_ingested, 3);
        assert_eq!(stats.buffer_size, 3);
        assert_eq!(stats.category_counts.get("Process").unwrap(), &2);
        assert_eq!(stats.category_counts.get("Network").unwrap(), &1);
        assert_eq!(stats.source_counts.get("sysmon").unwrap(), &2);
        assert_eq!(stats.source_counts.get("fw").unwrap(), &1);
    }

    #[test]
    fn test_regex_correlation_operator() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = false;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "regex-rule".to_string(),
            name: "Regex Match".to_string(),
            description: "Matches pattern".to_string(),
            conditions: vec![CorrelationCondition {
                field: "message".to_string(),
                operator: CorrOperator::Regex,
                value: r"(?i)failed.*password".to_string(),
            }],
            window_secs: 300,
            threshold: 1,
            severity: EventSeverity::High,
            enabled: true,
        });

        siem.ingest(make_log(
            "auth",
            LogCategory::Authentication,
            "Failed password for admin",
            EventSeverity::Medium,
        ));

        let alerts = siem.check_correlation();
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = false;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "disabled".to_string(),
            name: "Off".to_string(),
            description: "".to_string(),
            conditions: vec![CorrelationCondition {
                field: "source".to_string(),
                operator: CorrOperator::Equals,
                value: "test".to_string(),
            }],
            window_secs: 300,
            threshold: 1,
            severity: EventSeverity::Low,
            enabled: false,
        });

        siem.ingest_raw("test", LogCategory::System, "msg", EventSeverity::Low);
        let alerts = siem.check_correlation();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_correlation_no_duplicate_firing() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = false;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "dedup".to_string(),
            name: "Dedup".to_string(),
            description: "".to_string(),
            conditions: vec![CorrelationCondition {
                field: "category".to_string(),
                operator: CorrOperator::Equals,
                value: "Security".to_string(),
            }],
            window_secs: 300,
            threshold: 2,
            severity: EventSeverity::High,
            enabled: true,
        });

        for _ in 0..5 {
            siem.ingest(make_log(
                "s",
                LogCategory::Security,
                "event",
                EventSeverity::Low,
            ));
        }

        let alerts = siem.check_correlation();
        assert_eq!(alerts.len(), 1);

        let alerts2 = siem.check_correlation();
        assert!(alerts2.is_empty());
    }

    #[test]
    fn test_correlation_contains_operator() {
        let mut config = SiemConfig::default();
        config.enable_auto_alert = false;
        let mut siem = LocalSiem::with_config(config);

        siem.add_correlation_rule(CorrelationRule {
            id: "contains-rule".to_string(),
            name: "Contains".to_string(),
            description: "".to_string(),
            conditions: vec![CorrelationCondition {
                field: "message".to_string(),
                operator: CorrOperator::Contains,
                value: "malware".to_string(),
            }],
            window_secs: 300,
            threshold: 2,
            severity: EventSeverity::Critical,
            enabled: true,
        });

        siem.ingest(make_log("s", LogCategory::Security, "detected malware sample", EventSeverity::Low));
        siem.ingest(make_log("s", LogCategory::Security, "malware quarantine success", EventSeverity::Low));
        siem.ingest(make_log("s", LogCategory::Security, "clean scan result", EventSeverity::Low));

        let alerts = siem.check_correlation();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].matched_events.len(), 2);
    }

    #[test]
    fn test_export_empty_alerts() {
        let siem = LocalSiem::new();
        let json = siem.export_alerts_json().unwrap();
        let parsed: SiemExport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_count, 0);
        assert!(parsed.alerts.is_empty());
    }
}
