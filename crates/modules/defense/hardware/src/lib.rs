pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareEventType {
    DmaAttack,
    ThunderboltHotplug,
    PciConfigChange,
    FirmwareUpdate,
    HardwareTamper,
}

impl std::fmt::Display for HardwareEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardwareEventType::DmaAttack => write!(f, "DMA Attack"),
            HardwareEventType::ThunderboltHotplug => write!(f, "Thunderbolt Hotplug"),
            HardwareEventType::PciConfigChange => write!(f, "PCI Config Change"),
            HardwareEventType::FirmwareUpdate => write!(f, "Firmware Update"),
            HardwareEventType::HardwareTamper => write!(f, "Hardware Tamper"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvent {
    pub device_type: String,
    pub event_type: HardwareEventType,
    pub details: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAlert {
    pub id: Uuid,
    pub event: HardwareEvent,
    pub mitigation: String,
    pub timestamp: DateTime<Utc>,
}

pub struct HardwareMonitor {
    dma_protection_enabled: bool,
    thunderbolt_connected: bool,
    pci_baseline: HashMap<String, String>,
    alerts: Vec<HardwareAlert>,
    event_count: u64,
}

impl HardwareMonitor {
    pub fn new() -> Self {
        info!("Initializing hardware integrity monitor");
        Self {
            dma_protection_enabled: true,
            thunderbolt_connected: false,
            pci_baseline: HashMap::new(),
            alerts: Vec::new(),
            event_count: 0,
        }
    }

    pub fn check_dma_protection(&self) -> bool {
        self.dma_protection_enabled
    }

    pub fn analyze_hardware_event(&mut self, event: &HardwareEvent) -> Vec<HardwareAlert> {
        self.event_count += 1;
        let mut alerts = Vec::new();

        match event.event_type {
            HardwareEventType::DmaAttack => {
                if self.dma_protection_enabled {
                    warn!(
                        device = %event.device_type,
                        "DMA attack attempt detected and blocked by IOMMU/VBS protection"
                    );
                    alerts.push(HardwareAlert {
                        id: Uuid::new_v4(),
                        event: event.clone(),
                        mitigation: "IOMMU/VBS DMA protection blocked the attack".to_string(),
                        timestamp: Utc::now(),
                    });
                } else {
                    warn!(
                        device = %event.device_type,
                        "DMA attack detected with no protection active!"
                    );
                    alerts.push(HardwareAlert {
                        id: Uuid::new_v4(),
                        event: event.clone(),
                        mitigation: "CRITICAL: No DMA protection! Enable IOMMU immediately".to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
            HardwareEventType::ThunderboltHotplug => {
                self.thunderbolt_connected = true;
                warn!(
                    device = %event.device_type,
                    "Thunderbolt device hotplugged - potential DMA vector"
                );
                alerts.push(HardwareAlert {
                    id: Uuid::new_v4(),
                    event: event.clone(),
                    mitigation: "Thunderbolt DMA mitigation: verify device authorization".to_string(),
                    timestamp: Utc::now(),
                });
            }
            HardwareEventType::PciConfigChange => {
                let device_id = event.device_type.clone();
                if let Some(baseline_details) = self.pci_baseline.get(&device_id) {
                    if baseline_details != &event.details {
                        warn!(
                            device = %event.device_type,
                            "PCI configuration changed from baseline"
                        );
                        alerts.push(HardwareAlert {
                            id: Uuid::new_v4(),
                            event: event.clone(),
                            mitigation: "PCI config deviation detected - investigate for evil maid attack"
                                .to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                } else {
                    self.pci_baseline
                        .insert(device_id, event.details.clone());
                }
            }
            HardwareEventType::FirmwareUpdate => {
                info!(
                    device = %event.device_type,
                    "Firmware update detected: {}", event.details
                );
            }
            HardwareEventType::HardwareTamper => {
                warn!(
                    device = %event.device_type,
                    "Hardware tamper event detected"
                );
                alerts.push(HardwareAlert {
                    id: Uuid::new_v4(),
                    event: event.clone(),
                    mitigation: "Hardware tamper detected - inspect physical device".to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        for alert in &alerts {
            self.alerts.push(alert.clone());
        }

        alerts
    }

    pub fn detect_thunderbolt_risk(&self) -> HardwareRiskLevel {
        if !self.thunderbolt_connected {
            return HardwareRiskLevel::None;
        }
        if !self.dma_protection_enabled {
            return HardwareRiskLevel::Critical;
        }
        HardwareRiskLevel::Low
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    pub fn set_dma_protection(&mut self, enabled: bool) {
        self.dma_protection_enabled = enabled;
        info!(enabled = enabled, "DMA protection updated");
    }

    pub fn alerts(&self) -> &[HardwareAlert] {
        &self.alerts
    }
}

impl Default for HardwareMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dma_attack_event() -> HardwareEvent {
        HardwareEvent {
            device_type: "PCIe Device".to_string(),
            event_type: HardwareEventType::DmaAttack,
            details: "Unauthorized DMA read from external device".to_string(),
            severity: EventSeverity::Critical,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_hardware_monitor_new() {
        let monitor = HardwareMonitor::new();
        assert!(monitor.dma_protection_enabled);
        assert!(!monitor.thunderbolt_connected);
        assert_eq!(monitor.alert_count(), 0);
    }

    #[test]
    fn test_check_dma_protection_default() {
        let monitor = HardwareMonitor::new();
        assert!(monitor.check_dma_protection());
    }

    #[test]
    fn test_analyze_dma_attack_with_protection() {
        let mut monitor = HardwareMonitor::new();
        let event = dma_attack_event();
        let alerts = monitor.analyze_hardware_event(&event);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].mitigation.contains("IOMMU"));
        assert_eq!(monitor.alert_count(), 1);
    }

    #[test]
    fn test_analyze_dma_attack_without_protection() {
        let mut monitor = HardwareMonitor::new();
        monitor.set_dma_protection(false);
        let event = dma_attack_event();
        let alerts = monitor.analyze_hardware_event(&event);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].mitigation.contains("CRITICAL"));
    }

    #[test]
    fn test_thunderbolt_hotplug_creates_alert() {
        let mut monitor = HardwareMonitor::new();
        let event = HardwareEvent {
            device_type: "Thunderbolt Dock".to_string(),
            event_type: HardwareEventType::ThunderboltHotplug,
            details: "New Thunderbolt device connected".to_string(),
            severity: EventSeverity::High,
            timestamp: Utc::now(),
        };
        let alerts = monitor.analyze_hardware_event(&event);
        assert_eq!(alerts.len(), 1);
        assert!(monitor.thunderbolt_connected);
    }

    #[test]
    fn test_detect_thunderbolt_risk_no_device() {
        let monitor = HardwareMonitor::new();
        assert_eq!(monitor.detect_thunderbolt_risk(), HardwareRiskLevel::None);
    }

    #[test]
    fn test_detect_thunderbolt_risk_with_protection() {
        let mut monitor = HardwareMonitor::new();
        let event = HardwareEvent {
            device_type: "Thunderbolt".to_string(),
            event_type: HardwareEventType::ThunderboltHotplug,
            details: "Connected".to_string(),
            severity: EventSeverity::Medium,
            timestamp: Utc::now(),
        };
        monitor.analyze_hardware_event(&event);
        assert_eq!(monitor.detect_thunderbolt_risk(), HardwareRiskLevel::Low);
    }

    #[test]
    fn test_detect_thunderbolt_risk_without_protection() {
        let mut monitor = HardwareMonitor::new();
        monitor.set_dma_protection(false);
        let event = HardwareEvent {
            device_type: "Thunderbolt".to_string(),
            event_type: HardwareEventType::ThunderboltHotplug,
            details: "Connected".to_string(),
            severity: EventSeverity::Medium,
            timestamp: Utc::now(),
        };
        monitor.analyze_hardware_event(&event);
        assert_eq!(
            monitor.detect_thunderbolt_risk(),
            HardwareRiskLevel::Critical
        );
    }

    #[test]
    fn test_pci_config_change_baseline() {
        let mut monitor = HardwareMonitor::new();
        let event = HardwareEvent {
            device_type: "GPU".to_string(),
            event_type: HardwareEventType::PciConfigChange,
            details: "PCI_DEV_001".to_string(),
            severity: EventSeverity::Medium,
            timestamp: Utc::now(),
        };
        let alerts = monitor.analyze_hardware_event(&event);
        assert!(alerts.is_empty(), "First PCI event should establish baseline");

        let event2 = HardwareEvent {
            device_type: "GPU".to_string(),
            event_type: HardwareEventType::PciConfigChange,
            details: "PCI_DEV_001_CHANGED".to_string(),
            severity: EventSeverity::High,
            timestamp: Utc::now(),
        };
        let alerts2 = monitor.analyze_hardware_event(&event2);
        assert_eq!(alerts2.len(), 1);
    }

    #[test]
    fn test_hardware_tamper() {
        let mut monitor = HardwareMonitor::new();
        let event = HardwareEvent {
            device_type: "TPM".to_string(),
            event_type: HardwareEventType::HardwareTamper,
            details: "TPM physical presence detected".to_string(),
            severity: EventSeverity::Critical,
            timestamp: Utc::now(),
        };
        let alerts = monitor.analyze_hardware_event(&event);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].mitigation.contains("physical"));
    }

    #[test]
    fn test_event_count() {
        let mut monitor = HardwareMonitor::new();
        assert_eq!(monitor.event_count(), 0);
        let event = dma_attack_event();
        monitor.analyze_hardware_event(&event);
        assert_eq!(monitor.event_count(), 1);
    }
}
