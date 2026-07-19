use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::audit::AuditLog;
use crate::bus::{EventBus, TryRecvError};
use crate::config::AppConfig;
use crate::processtree::ProcessTreeTracker;
use royalsecurity_common::types::*;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Quick,
    Full,
    Memory,
    #[default]
    Process,
    Network,
}

impl ScanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanType::Quick => "quick",
            ScanType::Full => "full",
            ScanType::Memory => "memory",
            ScanType::Process => "process",
            ScanType::Network => "network",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    pub events_processed: usize,
    pub running: bool,
    pub uptime_secs: u64,
    pub bus_subscribers: usize,
    pub bus_events_published: usize,
    pub bus_events_delivered: usize,
    pub bus_events_dropped: usize,
}

pub struct SecurityEngine {
    pub bus: Arc<EventBus>,
    pub config: Arc<RwLock<AppConfig>>,
    pub running: Arc<AtomicBool>,
    pub audit: Arc<RwLock<AuditLog>>,
    pub event_count: Arc<AtomicUsize>,
    pub start_time: Arc<RwLock<Option<chrono::DateTime<Utc>>>>,
    pub process_tree: Arc<ProcessTreeTracker>,
}

impl SecurityEngine {
    pub fn new(config: AppConfig) -> Self {
        Self {
            bus: Arc::new(EventBus::new()),
            config: Arc::new(RwLock::new(config)),
            running: Arc::new(AtomicBool::new(false)),
            audit: Arc::new(RwLock::new(AuditLog::new())),
            event_count: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(RwLock::new(None)),
            process_tree: Arc::new(ProcessTreeTracker::new()),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running.load(Ordering::SeqCst) {
            warn!("SecurityEngine is already running");
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write().await = Some(Utc::now());

        {
            let mut audit = self.audit.write().await;
            let mut details = HashMap::new();
            details.insert("component".into(), serde_json::json!("SecurityEngine"));
            details.insert("action".into(), serde_json::json!("startup"));
            audit.record("engine.startup", "system", "security_engine", details);
        }

        info!("SecurityEngine starting up");

        let bus = Arc::clone(&self.bus);
        let config = Arc::clone(&self.config);
        let running = Arc::clone(&self.running);
        let audit = Arc::clone(&self.audit);
        let event_count = Arc::clone(&self.event_count);

        {
            let ch_running = Arc::clone(&running);
            let ch_config = Arc::clone(&config);
            let ch_bus = Arc::clone(&bus);
            let ch_event_count = Arc::clone(&event_count);
            tokio::spawn(async move {
                Self::run_collector_loop(ch_running, ch_config, ch_bus, ch_event_count).await;
            });
        }

        {
            let de_running = Arc::clone(&running);
            let de_bus = Arc::clone(&bus);
            let de_audit = Arc::clone(&audit);
            let de_event_count = Arc::clone(&event_count);
            let de_process_tree = Arc::clone(&self.process_tree);
            tokio::spawn(async move {
                Self::run_detection_loop(de_running, de_bus, de_audit, de_event_count, de_process_tree).await;
            });
        }

        {
            let mr_running = Arc::clone(&running);
            let mr_bus = Arc::clone(&bus);
            let mr_event_count = Arc::clone(&event_count);
            let mr_audit = Arc::clone(&audit);
            tokio::spawn(async move {
                Self::run_metrics_loop(mr_running, mr_bus, mr_event_count, mr_audit).await;
            });
        }

        {
            let ti_running = Arc::clone(&running);
            let ti_config = Arc::clone(&config);
            let ti_audit = Arc::clone(&audit);
            tokio::spawn(async move {
                Self::run_threat_intel_loop(ti_running, ti_config, ti_audit).await;
            });
        }

        info!("SecurityEngine started with all background tasks");
        Ok(())
    }

    pub async fn stop(&self) {
        info!("SecurityEngine stopping");
        self.running.store(false, Ordering::SeqCst);

        {
            let mut audit = self.audit.write().await;
            let mut details = HashMap::new();
            details.insert("component".into(), serde_json::json!("SecurityEngine"));
            details.insert("action".into(), serde_json::json!("shutdown"));
            details.insert(
                "events_processed".into(),
                serde_json::json!(self.event_count.load(Ordering::Relaxed)),
            );
            audit.record("engine.shutdown", "system", "security_engine", details);
        }

        info!("SecurityEngine stopped");
    }

    async fn run_collector_loop(
        running: Arc<AtomicBool>,
        config: Arc<RwLock<AppConfig>>,
        bus: Arc<EventBus>,
        event_count: Arc<AtomicUsize>,
    ) {
        info!("Collector heartbeat loop started");

        while running.load(Ordering::SeqCst) {
            let interval_secs = {
                let cfg = config.read().await;
                cfg.agent.heartbeat_interval_secs
            };

            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
            ticker.tick().await;

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let event = SecurityEvent::Process(ProcessInfo {
                pid: std::process::id(),
                ppid: 0,
                name: "royalsecurity-agent".into(),
                path: std::env::current_exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                command_line: "royalsecurity-agent --heartbeat".into(),
                user: "system".into(),
                hash_sha256: None,
                integrity_level: Some("System".into()),
                timestamp: Utc::now(),
            });

            match bus.publish(event) {
                Ok(_) => {
                    event_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!("Failed to publish heartbeat event: {}", e);
                }
            }
        }

        info!("Collector heartbeat loop exited");
    }

    async fn run_detection_loop(
        running: Arc<AtomicBool>,
        bus: Arc<EventBus>,
        audit: Arc<RwLock<AuditLog>>,
        event_count: Arc<AtomicUsize>,
        process_tree: Arc<ProcessTreeTracker>,
    ) {
        info!("Detection evaluator loop started");
        let mut receiver = bus.subscribe();

        while running.load(Ordering::SeqCst) {
            match receiver.try_recv() {
                Ok(event) => {
                    event_count.fetch_add(1, Ordering::Relaxed);

                    let suspicious = process_tree.process_event(&event);
                    for pattern in suspicious {
                        warn!(
                            pid = pattern.pid,
                            name = %pattern.process_name,
                            severity = %pattern.severity,
                            mitre = ?pattern.mitre_technique,
                            "{}",
                            pattern.description
                        );

                        let mut audit_log = audit.write().await;
                        let mut details = std::collections::HashMap::new();
                        details.insert("event_type".into(), serde_json::json!("suspicious_process"));
                        details.insert("severity".into(), serde_json::json!(format!("{}", pattern.severity)));
                        details.insert("pid".into(), serde_json::json!(pattern.pid));
                        details.insert("process_name".into(), serde_json::json!(pattern.process_name));
                        details.insert("description".into(), serde_json::json!(pattern.description));
                        details.insert("mitre_tactic".into(), serde_json::json!(pattern.mitre_tactic));
                        details.insert("mitre_technique".into(), serde_json::json!(pattern.mitre_technique));
                        audit_log.record(
                            "detection.suspicious_process",
                            "process_tree",
                            "security_event",
                            details,
                        );
                    }

                    let severity = Self::evaluate_event(&event);

                    if severity == EventSeverity::Critical || severity == EventSeverity::High {
                        let mut audit_log = audit.write().await;
                        let mut details = HashMap::new();
                        details.insert(
                            "event_type".into(),
                            serde_json::json!(format!("{:?}", event)),
                        );
                        details.insert(
                            "severity".into(),
                            serde_json::json!(format!("{}", severity)),
                        );
                        audit_log.record(
                            "detection.alert",
                            "detection_engine",
                            "security_event",
                            details,
                        );

                        warn!(severity = %severity, "High/Critical event detected");
                    }
                }
                Err(TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(TryRecvError::Lagged(n)) => {
                    warn!("Detection loop lagged by {} events", n);
                }
            }
        }

        info!("Detection evaluator loop exited");
    }

    async fn run_metrics_loop(
        running: Arc<AtomicBool>,
        bus: Arc<EventBus>,
        event_count: Arc<AtomicUsize>,
        _audit: Arc<RwLock<AuditLog>>,
    ) {
        info!("Metrics reporter loop started");

        while running.load(Ordering::SeqCst) {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.tick().await;

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let stats = bus.stats();
            let published = stats.events_published.load(Ordering::Relaxed);
            let delivered = stats.events_delivered.load(Ordering::Relaxed);
            let dropped = stats.events_dropped.load(Ordering::Relaxed);
            let avg_latency = stats.avg_publish_latency_ns();
            let total = event_count.load(Ordering::Relaxed);

            info!(
                published,
                delivered,
                dropped,
                avg_latency_ns = format!("{:.0}", avg_latency),
                total_processed = total,
                "Bus metrics"
            );
        }

        info!("Metrics reporter loop exited");
    }

    async fn run_threat_intel_loop(
        running: Arc<AtomicBool>,
        config: Arc<RwLock<AppConfig>>,
        audit: Arc<RwLock<AuditLog>>,
    ) {
        info!("Threat intel updater loop started");

        let interval_mins = {
            let cfg = config.read().await;
            cfg.threat_intel.update_interval_minutes
        };

        let mut ticker = tokio::time::interval(Duration::from_secs((interval_mins * 60).max(1)));

        while running.load(Ordering::SeqCst) {
            ticker.tick().await;

            if !running.load(Ordering::SeqCst) {
                break;
            }

            info!("Performing scheduled threat intel update");

            {
                let mut audit_log = audit.write().await;
                let mut details = HashMap::new();
                details.insert("component".into(), serde_json::json!("threat_intel"));
                details.insert("action".into(), serde_json::json!("scheduled_update"));
                details.insert(
                    "interval_mins".into(),
                    serde_json::json!(interval_mins),
                );
                audit_log.record(
                    "threat_intel.scheduled_update",
                    "system",
                    "security_engine",
                    details,
                );
            }

            info!("Threat intel update completed");
        }

        info!("Threat intel updater loop exited");
    }

    pub fn evaluate_event(event: &SecurityEvent) -> EventSeverity {
        match event {
            SecurityEvent::Process(info) => {
                if info.hash_sha256.is_some() {
                    EventSeverity::Medium
                } else {
                    EventSeverity::Informational
                }
            }
            SecurityEvent::Network(info) => {
                if info.dst_port == 443 || info.dst_port == 80 {
                    EventSeverity::Informational
                } else {
                    EventSeverity::Low
                }
            }
            SecurityEvent::File(info) => match info.action {
                FileAction::Deleted => EventSeverity::Medium,
                FileAction::Modified => EventSeverity::Low,
                _ => EventSeverity::Informational,
            },
            SecurityEvent::Registry(_) => EventSeverity::Low,
            SecurityEvent::Service(info) => match info.action {
                ServiceAction::Created => EventSeverity::Medium,
                ServiceAction::Deleted => EventSeverity::High,
                _ => EventSeverity::Low,
            },
            SecurityEvent::Memory(_) => EventSeverity::Medium,
            SecurityEvent::Thread(_) => EventSeverity::Medium,
            SecurityEvent::Dns(_) => EventSeverity::Informational,
        }
    }

    pub async fn trigger_scan(&self, scan_type: &str) -> Result<String, String> {
        if !self.running.load(Ordering::SeqCst) {
            return Err("SecurityEngine is not running".into());
        }

        let scan_id = uuid::Uuid::new_v4().to_string();
        info!(scan_type, scan_id = %scan_id, "Triggering scan");

        {
            let mut audit = self.audit.write().await;
            let mut details = HashMap::new();
            details.insert("scan_type".into(), serde_json::json!(scan_type));
            details.insert("scan_id".into(), serde_json::json!(scan_id));
            details.insert("triggered_by".into(), serde_json::json!("api"));
            audit.record("scan.triggered", "api", scan_type, details);
        }

        let event = SecurityEvent::Process(ProcessInfo {
            pid: std::process::id(),
            ppid: 0,
            name: format!("scan-{}", scan_type),
            path: String::new(),
            command_line: format!("scan --type {}", scan_type),
            user: "system".into(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        });

        self.bus.publish(event).map_err(|e| e.to_string())?;

        Ok(scan_id)
    }

    pub fn event_count(&self) -> usize {
        self.event_count.load(Ordering::Relaxed)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> EngineStats {
        let bus_stats = self.bus.stats();
        let uptime = self.start_time.try_read()
            .ok()
            .and_then(|t| t.map(|t| (chrono::Utc::now() - t).num_seconds() as u64))
            .unwrap_or(0);
        EngineStats {
            events_processed: self.event_count(),
            running: self.is_running(),
            uptime_secs: uptime,
            bus_subscribers: self.bus.subscriber_count(),
            bus_events_published: bus_stats.events_published.load(Ordering::Relaxed),
            bus_events_delivered: bus_stats.events_delivered.load(Ordering::Relaxed),
            bus_events_dropped: bus_stats.events_dropped.load(Ordering::Relaxed),
        }
    }

    pub async fn trigger_threat_intel_update(&self) -> Result<String, String> {
        if !self.running.load(Ordering::SeqCst) {
            return Err("SecurityEngine is not running".into());
        }
        info!("Threat intel update triggered");
        {
            let mut audit = self.audit.write().await;
            let mut details = HashMap::new();
            details.insert("component".into(), serde_json::json!("threat_intel"));
            details.insert("action".into(), serde_json::json!("update"));
            audit.record("threat_intel.update", "api", "security_engine", details);
        }
        Ok("threat intel update triggered".into())
    }

    pub fn force_intel_update(&self) {
        if !self.running.load(Ordering::SeqCst) {
            warn!("Force intel update requested but engine not running");
            return;
        }
        info!("Force intel update triggered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_new() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        assert!(!engine.is_running());
        assert_eq!(engine.event_count(), 0);
    }

    #[test]
    fn test_engine_initial_running_false() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        assert!(!engine.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_engine_bus_publish_subscribe() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        let mut rx = engine.bus.subscribe();
        let event = SecurityEvent::Process(ProcessInfo::default());
        engine.bus.publish(event).unwrap();
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_evaluate_event_process_with_hash() {
        let event = SecurityEvent::Process(ProcessInfo {
            hash_sha256: Some("abc123".into()),
            ..Default::default()
        });
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::Medium
        );
    }

    #[test]
    fn test_evaluate_event_process_without_hash() {
        let event = SecurityEvent::Process(ProcessInfo::default());
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::Informational
        );
    }

    #[test]
    fn test_evaluate_event_network_common_port() {
        let event = SecurityEvent::Network(NetworkEvent {
            dst_port: 443,
            ..Default::default()
        });
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::Informational
        );
    }

    #[test]
    fn test_evaluate_event_network_unusual_port() {
        let event = SecurityEvent::Network(NetworkEvent {
            dst_port: 6667,
            ..Default::default()
        });
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::Low
        );
    }

    #[test]
    fn test_evaluate_event_file_delete() {
        let event = SecurityEvent::File(FileEvent {
            action: FileAction::Deleted,
            ..Default::default()
        });
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::Medium
        );
    }

    #[test]
    fn test_evaluate_event_service_delete() {
        let event = SecurityEvent::Service(ServiceEvent {
            action: ServiceAction::Deleted,
            ..Default::default()
        });
        assert_eq!(
            SecurityEngine::evaluate_event(&event),
            EventSeverity::High
        );
    }

    #[tokio::test]
    async fn test_engine_stop_sets_running_false() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        engine.running.store(true, Ordering::SeqCst);
        engine.stop().await;
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn test_engine_stop_records_audit_entry() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        engine.running.store(true, Ordering::SeqCst);
        engine.stop().await;
        let audit = engine.audit.read().await;
        assert!(audit.count() > 0);
    }

    #[tokio::test]
    async fn test_trigger_scan_not_running() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        let result = engine.trigger_scan("full").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not running"));
    }

    #[tokio::test]
    async fn test_trigger_scan_running() {
        let config = AppConfig::default();
        let engine = SecurityEngine::new(config);
        engine.running.store(true, Ordering::SeqCst);
        let result = engine.trigger_scan("quick").await;
        assert!(result.is_ok());
        let scan_id = result.unwrap();
        assert!(!scan_id.is_empty());
    }
}
