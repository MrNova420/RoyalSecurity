pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BootError {
    #[error("PCR verification failed: {0}")]
    PcrVerificationFailed(String),
    #[error("Bootkit detected: {0}")]
    BootkitDetected(String),
    #[error("Secure Boot is disabled")]
    SecureBootDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum PcrAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurement {
    pub index: u32,
    pub algorithm: PcrAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootStatus {
    pub secure_boot_enabled: bool,
    pub uefi_lock: bool,
    pub pcr_measurements: Vec<PcrMeasurement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootAlertType {
    SecureBootDisabled,
    PcrMismatch,
    BootkitDetected,
    UefiModification,
    MeasuredBootFailure,
    FirmwareIntegrityViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootAlert {
    pub alert_type: BootAlertType,
    pub description: String,
    pub severity: EventSeverity,
    pub pcr_index: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiVariable {
    pub name: String,
    pub guid: String,
    pub value_hash: String,
    pub is_secure: bool,
}

pub struct SecureBootMonitor {
    status: BootStatus,
    baseline_measurements: Vec<PcrMeasurement>,
    alerts: Vec<BootAlert>,
    uefi_variables: HashMap<String, UefiVariable>,
    verification_history: Vec<(u32, bool, DateTime<Utc>)>,
    bootkit_signatures: Vec<String>,
}

impl SecureBootMonitor {
    pub fn new() -> Self {
        info!("Initializing Secure Boot monitor");
        Self {
            status: BootStatus {
                secure_boot_enabled: true,
                uefi_lock: false,
                pcr_measurements: Vec::new(),
            },
            baseline_measurements: Vec::new(),
            alerts: Vec::new(),
            uefi_variables: HashMap::new(),
            verification_history: Vec::new(),
            bootkit_signatures: vec![
                "riot".to_string(),
                "cosmicstranger".to_string(),
                "blacklotus".to_string(),
                "bootkit_rootkit".to_string(),
            ],
        }
    }

    pub fn check_status(&self) -> BootStatus {
        self.status.clone()
    }

    pub fn set_secure_boot_enabled(&mut self, enabled: bool) {
        self.status.secure_boot_enabled = enabled;
        if !enabled {
            let alert = BootAlert {
                alert_type: BootAlertType::SecureBootDisabled,
                description: "Secure Boot has been disabled".to_string(),
                severity: EventSeverity::Critical,
                pcr_index: None,
                timestamp: Utc::now(),
            };
            warn!("Secure Boot disabled");
            self.alerts.push(alert);
        }
    }

    pub fn set_uefi_lock(&mut self, locked: bool) {
        self.status.uefi_lock = locked;
    }

    pub fn set_baseline(&mut self, measurements: Vec<PcrMeasurement>) {
        info!(count = measurements.len(), "Setting PCR baseline measurements");
        self.baseline_measurements = measurements;
    }

    pub fn update_measurements(&mut self, measurements: Vec<PcrMeasurement>) {
        self.status.pcr_measurements = measurements;
    }

    pub fn verify_pcr(&mut self, index: u32, expected_value: &str) -> bool {
        let actual = self.status.pcr_measurements
            .iter()
            .find(|m| m.index == index);

        let result = match actual {
            Some(m) => m.value == expected_value,
            None => false,
        };

        self.verification_history.push((index, result, Utc::now()));

        if !result {
            let description = match actual {
                Some(m) => format!(
                    "PCR[{}] mismatch: expected {}, got {}",
                    index, expected_value, m.value
                ),
                None => format!("PCR[{}] not found, expected {}", index, expected_value),
            };

            let alert = BootAlert {
                alert_type: BootAlertType::PcrMismatch,
                description,
                severity: EventSeverity::Critical,
                pcr_index: Some(index),
                timestamp: Utc::now(),
            };

            warn!(index = index, "PCR verification failed");
            self.alerts.push(alert);
        }

        result
    }

    pub fn detect_bootkit(&mut self, measurements: &[PcrMeasurement]) -> Vec<BootAlert> {
        let mut alerts = Vec::new();

        for measurement in measurements {
            if self.bootkit_signatures.iter().any(|sig| measurement.value.contains(sig)) {
                let alert = BootAlert {
                    alert_type: BootAlertType::BootkitDetected,
                    description: format!(
                        "Bootkit signature detected in PCR[{}]: {} matches known bootkit",
                        measurement.index, measurement.value
                    ),
                    severity: EventSeverity::Critical,
                    pcr_index: Some(measurement.index),
                    timestamp: Utc::now(),
                };
                warn!(index = measurement.index, "Bootkit detected in PCR measurement");
                alerts.push(alert.clone());
                self.alerts.push(alert);
            }
        }

        let zero_count = measurements.iter()
            .filter(|m| m.value.chars().all(|c| c == '0'))
            .count();

        if zero_count > measurements.len() / 2 && !measurements.is_empty() {
            let alert = BootAlert {
                alert_type: BootAlertType::MeasuredBootFailure,
                description: format!(
                    "Abnormal number of zero PCR values ({}/{}) - measured boot may be compromised",
                    zero_count, measurements.len()
                ),
                severity: EventSeverity::High,
                pcr_index: None,
                timestamp: Utc::now(),
            };
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        alerts
    }

    pub fn verify_uefi_variable(&mut self, name: &str, current_hash: &str) -> bool {
        if let Some(var) = self.uefi_variables.get(name) {
            if var.value_hash != current_hash {
                let alert = BootAlert {
                    alert_type: BootAlertType::UefiModification,
                    description: format!("UEFI variable '{}' modified: expected {}, got {}", name, var.value_hash, current_hash),
                    severity: EventSeverity::Critical,
                    pcr_index: None,
                    timestamp: Utc::now(),
                };
                warn!(name = %name, "UEFI variable modification detected");
                self.alerts.push(alert);
                return false;
            }
            true
        } else {
            self.uefi_variables.insert(name.to_string(), UefiVariable {
                name: name.to_string(),
                guid: "00000000-0000-0000-0000-000000000000".to_string(),
                value_hash: current_hash.to_string(),
                is_secure: true,
            });
            true
        }
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn get_alerts(&self) -> &[BootAlert] {
        &self.alerts
    }

    pub fn get_verification_history(&self) -> &[(u32, bool, DateTime<Utc>)] {
        &self.verification_history
    }
}

impl Default for SecureBootMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_measurement(index: u32, value: &str) -> PcrMeasurement {
        PcrMeasurement {
            index,
            algorithm: PcrAlgorithm::Sha256,
            value: value.to_string(),
        }
    }

    #[test]
    fn test_secure_boot_monitor_new() {
        let monitor = SecureBootMonitor::new();
        let status = monitor.check_status();
        assert!(status.secure_boot_enabled);
        assert!(!status.uefi_lock);
        assert!(monitor.alert_count() == 0);
    }

    #[test]
    fn test_check_status() {
        let mut monitor = SecureBootMonitor::new();
        monitor.set_secure_boot_enabled(true);
        monitor.set_uefi_lock(true);
        let status = monitor.check_status();
        assert!(status.secure_boot_enabled);
        assert!(status.uefi_lock);
    }

    #[test]
    fn test_verify_pcr_match() {
        let mut monitor = SecureBootMonitor::new();
        monitor.update_measurements(vec![make_measurement(0, "abc123")]);
        assert!(monitor.verify_pcr(0, "abc123"));
        assert!(monitor.alert_count() == 0);
    }

    #[test]
    fn test_verify_pcr_mismatch() {
        let mut monitor = SecureBootMonitor::new();
        monitor.update_measurements(vec![make_measurement(0, "abc123")]);
        assert!(!monitor.verify_pcr(0, "wrong_hash"));
        assert!(monitor.alert_count() == 1);
        assert_eq!(monitor.get_alerts()[0].alert_type, BootAlertType::PcrMismatch);
    }

    #[test]
    fn test_verify_pcr_missing() {
        let mut monitor = SecureBootMonitor::new();
        assert!(!monitor.verify_pcr(5, "expected"));
        assert!(monitor.alert_count() == 1);
    }

    #[test]
    fn test_detect_bootkit_signature() {
        let mut monitor = SecureBootMonitor::new();
        let measurements = vec![
            make_measurement(0, "normal_value"),
            make_measurement(7, "blacklotus_detected_hash"),
        ];
        let alerts = monitor.detect_bootkit(&measurements);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].alert_type, BootAlertType::BootkitDetected);
    }

    #[test]
    fn test_detect_bootkit_zero_pcr() {
        let mut monitor = SecureBootMonitor::new();
        let measurements = vec![
            make_measurement(0, "000000000000"),
            make_measurement(1, "000000000000"),
            make_measurement(2, "000000000000"),
            make_measurement(7, "normal"),
        ];
        let alerts = monitor.detect_bootkit(&measurements);
        assert!(alerts.iter().any(|a| a.alert_type == BootAlertType::MeasuredBootFailure));
    }

    #[test]
    fn test_secure_boot_disabled_alert() {
        let mut monitor = SecureBootMonitor::new();
        monitor.set_secure_boot_enabled(false);
        assert!(!monitor.check_status().secure_boot_enabled);
        assert_eq!(monitor.alert_count(), 1);
        assert_eq!(monitor.get_alerts()[0].alert_type, BootAlertType::SecureBootDisabled);
    }

    #[test]
    fn test_uefi_variable_verification() {
        let mut monitor = SecureBootMonitor::new();
        assert!(monitor.verify_uefi_variable("dbx", "hash123"));
        assert!(monitor.verify_uefi_variable("dbx", "hash123"));
        assert!(!monitor.verify_uefi_variable("dbx", "modified"));
        assert_eq!(monitor.alert_count(), 1);
    }

    #[test]
    fn test_set_baseline() {
        let mut monitor = SecureBootMonitor::new();
        let baseline = vec![
            make_measurement(0, "baseline0"),
            make_measurement(1, "baseline1"),
        ];
        monitor.set_baseline(baseline);
        monitor.update_measurements(vec![
            make_measurement(0, "baseline0"),
            make_measurement(1, "baseline1"),
        ]);
        assert!(monitor.verify_pcr(0, "baseline0"));
        assert!(monitor.verify_pcr(1, "baseline1"));
    }
}
