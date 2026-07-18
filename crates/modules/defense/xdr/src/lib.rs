pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalType {
    ProcessAlert,
    NetworkAlert,
    FileAlert,
    IdentityAlert,
    CloudAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrSignal {
    pub signal_type: SignalType,
    pub source: String,
    pub data: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrCorrelation {
    pub id: String,
    pub signals: Vec<XdrSignal>,
    pub threat_name: String,
    pub confidence: f32,
    pub severity: EventSeverity,
}

pub struct XdrEngine {
    signals: Vec<XdrSignal>,
    correlations: Vec<XdrCorrelation>,
    correlation_counter: u64,
}

impl XdrEngine {
    pub fn new() -> Self {
        info!("Initializing XDR Engine");
        Self {
            signals: Vec::new(),
            correlations: Vec::new(),
            correlation_counter: 0,
        }
    }

    pub fn ingest_signal(&mut self, signal: XdrSignal) {
        info!(
            signal_type = ?signal.signal_type,
            source = %signal.source,
            severity = ?signal.severity,
            "Ingesting XDR signal"
        );
        self.signals.push(signal);
    }

    pub fn correlate(&mut self, time_window_secs: u64) -> Vec<XdrCorrelation> {
        let now = Utc::now();
        let window = chrono::Duration::seconds(time_window_secs as i64);

        let recent: Vec<&XdrSignal> = self
            .signals
            .iter()
            .filter(|s| now - s.timestamp <= window)
            .collect();

        if recent.len() < 2 {
            return Vec::new();
        }

        let mut type_counts: HashMap<SignalType, Vec<&XdrSignal>> = HashMap::new();
        for signal in &recent {
            type_counts
                .entry(signal.signal_type)
                .or_insert_with(Vec::new)
                .push(signal);
        }

        let mut new_correlations = Vec::new();

        if type_counts.len() >= 2 {
            let has_critical = recent
                .iter()
                .any(|s| s.severity == EventSeverity::Critical);
            let has_high = recent.iter().any(|s| s.severity == EventSeverity::High);

            let severity = if has_critical {
                EventSeverity::Critical
            } else if has_high {
                EventSeverity::High
            } else {
                EventSeverity::Medium
            };

            let signal_count = recent.len() as f32;
            let type_count = type_counts.len() as f32;
            let confidence = (0.5 + (type_count * 0.15) + (signal_count * 0.05)).min(1.0);

            let threat_name = if type_counts.contains_key(&SignalType::ProcessAlert)
                && type_counts.contains_key(&SignalType::NetworkAlert)
            {
                "Multi-stage Attack: Process + Network".to_string()
            } else if type_counts.contains_key(&SignalType::FileAlert)
                && type_counts.contains_key(&SignalType::ProcessAlert)
            {
                "Malware Execution: File + Process".to_string()
            } else if type_counts.contains_key(&SignalType::IdentityAlert)
                && type_counts.contains_key(&SignalType::NetworkAlert)
            {
                "Lateral Movement: Identity + Network".to_string()
            } else if type_counts.contains_key(&SignalType::CloudAlert)
                && type_counts.contains_key(&SignalType::IdentityAlert)
            {
                "Cloud Account Compromise".to_string()
            } else {
                "Cross-domain Correlated Threat".to_string()
            };

            self.correlation_counter += 1;
            let correlation = XdrCorrelation {
                id: format!("XDR-{:06}", self.correlation_counter),
                signals: recent.into_iter().cloned().collect(),
                threat_name,
                confidence,
                severity,
            };

            warn!(
                id = %correlation.id,
                threat = %correlation.threat_name,
                confidence = correlation.confidence,
                "XDR correlation detected"
            );

            new_correlations.push(correlation);
        }

        self.correlations.extend(new_correlations.clone());
        new_correlations
    }

    pub fn get_correlations(&self) -> &[XdrCorrelation] {
        &self.correlations
    }

    pub fn get_signals(&self, time_window_secs: u64) -> Vec<&XdrSignal> {
        let now = Utc::now();
        let window = chrono::Duration::seconds(time_window_secs as i64);
        self.signals
            .iter()
            .filter(|s| now - s.timestamp <= window)
            .collect()
    }

    pub fn threat_count(&self) -> usize {
        self.correlations.len()
    }
}

impl Default for XdrEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(signal_type: SignalType, severity: EventSeverity, source: &str) -> XdrSignal {
        XdrSignal {
            signal_type,
            source: source.to_string(),
            data: format!("test data from {}", source),
            severity,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_xdr_engine_new() {
        let engine = XdrEngine::new();
        assert_eq!(engine.threat_count(), 0);
        assert!(engine.get_correlations().is_empty());
    }

    #[test]
    fn test_ingest_signal() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::High,
            "edr",
        ));
        engine.ingest_signal(make_signal(
            SignalType::NetworkAlert,
            EventSeverity::High,
            "firewall",
        ));
        assert_eq!(engine.get_signals(60).len(), 2);
    }

    #[test]
    fn test_correlate_multi_domain() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::High,
            "edr",
        ));
        engine.ingest_signal(make_signal(
            SignalType::NetworkAlert,
            EventSeverity::Critical,
            "firewall",
        ));

        let correlations = engine.correlate(60);
        assert_eq!(correlations.len(), 1);
        assert!(correlations[0].confidence > 0.5);
        assert_eq!(engine.threat_count(), 1);
    }

    #[test]
    fn test_correlate_single_domain_no_correlation() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::High,
            "edr",
        ));

        let correlations = engine.correlate(60);
        assert!(correlations.is_empty());
        assert_eq!(engine.threat_count(), 0);
    }

    #[test]
    fn test_correlate_outside_window() {
        let mut engine = XdrEngine::new();
        let old_signal = XdrSignal {
            signal_type: SignalType::ProcessAlert,
            source: "edr".to_string(),
            data: "old".to_string(),
            severity: EventSeverity::High,
            timestamp: Utc::now() - chrono::Duration::seconds(120),
        };
        engine.ingest_signal(old_signal);
        engine.ingest_signal(make_signal(
            SignalType::NetworkAlert,
            EventSeverity::High,
            "firewall",
        ));

        let correlations = engine.correlate(60);
        assert!(correlations.is_empty());
    }

    #[test]
    fn test_get_signals_time_filter() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::Medium,
            "edr",
        ));

        let old = XdrSignal {
            signal_type: SignalType::FileAlert,
            source: "av".to_string(),
            data: "old".to_string(),
            severity: EventSeverity::Low,
            timestamp: Utc::now() - chrono::Duration::seconds(300),
        };
        engine.ingest_signal(old);

        let recent = engine.get_signals(60);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_threat_name_process_network() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::High,
            "edr",
        ));
        engine.ingest_signal(make_signal(
            SignalType::NetworkAlert,
            EventSeverity::High,
            "firewall",
        ));

        let correlations = engine.correlate(60);
        assert_eq!(correlations[0].threat_name, "Multi-stage Attack: Process + Network");
    }

    #[test]
    fn test_correlation_severity_uses_highest() {
        let mut engine = XdrEngine::new();
        engine.ingest_signal(make_signal(
            SignalType::ProcessAlert,
            EventSeverity::Low,
            "edr",
        ));
        engine.ingest_signal(make_signal(
            SignalType::NetworkAlert,
            EventSeverity::Critical,
            "firewall",
        ));

        let correlations = engine.correlate(60);
        assert_eq!(correlations[0].severity, EventSeverity::Critical);
    }
}
