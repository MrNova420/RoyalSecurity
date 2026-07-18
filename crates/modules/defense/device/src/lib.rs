pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("Device not found: {0}")]
    NotFound(String),
    #[error("Device policy violation: {0}")]
    PolicyViolation(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DeviceType {
    Usb,
    Bluetooth,
    Wifi,
    Thunderbolt,
    Pci,
    ExternalStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DevicePolicy {
    Allowed,
    Blocked,
    Audit,
    Quarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub device_type: DeviceType,
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device: DeviceInfo,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub policy: DevicePolicy,
    pub interaction_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicyEntry {
    pub vendor: String,
    pub product: String,
    pub policy: DevicePolicy,
    pub added_at: DateTime<Utc>,
}

pub struct DeviceController {
    devices: HashMap<String, DeviceRecord>,
    policy_rules: Vec<DevicePolicyEntry>,
    alerts: Vec<DeviceAlert>,
    device_history: Vec<(String, DevicePolicy, DateTime<Utc>)>,
    blocked_vendors: Vec<String>,
    allowed_vendors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAlert {
    pub device_id: String,
    pub device_name: String,
    pub policy: DevicePolicy,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

impl DeviceController {
    pub fn new() -> Self {
        info!("Initializing Device Control module");
        Self {
            devices: HashMap::new(),
            policy_rules: Vec::new(),
            alerts: Vec::new(),
            device_history: Vec::new(),
            blocked_vendors: Vec::new(),
            allowed_vendors: Vec::new(),
        }
    }

    pub fn check_device(&mut self, device: &DeviceInfo) -> DevicePolicy {
        let policy = self.evaluate_policy(device);

        let record = self.devices.entry(device.id.clone()).or_insert_with(|| DeviceRecord {
            device: device.clone(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            policy,
            interaction_count: 0,
        });

        record.last_seen = Utc::now();
        record.interaction_count += 1;
        record.policy = policy;

        self.device_history.push((device.id.clone(), policy, Utc::now()));

        if policy == DevicePolicy::Blocked {
            let alert = DeviceAlert {
                device_id: device.id.clone(),
                device_name: format!("{} {}", device.vendor, device.product),
                policy,
                message: format!(
                    "Blocked device connected: {} {} (serial: {})",
                    device.vendor, device.product, device.serial
                ),
                severity: EventSeverity::High,
                timestamp: Utc::now(),
            };
            warn!(
                device_id = %device.id,
                vendor = %device.vendor,
                product = %device.product,
                "Blocked device detected"
            );
            self.alerts.push(alert);
        }

        policy
    }

    fn evaluate_policy(&self, device: &DeviceInfo) -> DevicePolicy {
        for rule in &self.policy_rules {
            if rule.vendor == device.vendor && rule.product == device.product {
                return rule.policy;
            }
        }

        if self.blocked_vendors.contains(&device.vendor) {
            return DevicePolicy::Blocked;
        }

        if !self.allowed_vendors.is_empty() && !self.allowed_vendors.contains(&device.vendor) {
            return DevicePolicy::Audit;
        }

        if device.allowed {
            DevicePolicy::Allowed
        } else {
            DevicePolicy::Audit
        }
    }

    pub fn add_allowed_device(&mut self, vendor: &str, product: &str) {
        info!(vendor = %vendor, product = %product, "Adding allowed device");
        self.policy_rules.push(DevicePolicyEntry {
            vendor: vendor.to_string(),
            product: product.to_string(),
            policy: DevicePolicy::Allowed,
            added_at: Utc::now(),
        });
    }

    pub fn block_device(&mut self, vendor: &str, product: &str) {
        warn!(vendor = %vendor, product = %product, "Blocking device");
        self.policy_rules.push(DevicePolicyEntry {
            vendor: vendor.to_string(),
            product: product.to_string(),
            policy: DevicePolicy::Blocked,
            added_at: Utc::now(),
        });
    }

    pub fn block_vendor(&mut self, vendor: &str) {
        warn!(vendor = %vendor, "Blocking all devices from vendor");
        if !self.blocked_vendors.contains(&vendor.to_string()) {
            self.blocked_vendors.push(vendor.to_string());
        }
    }

    pub fn allow_vendor(&mut self, vendor: &str) {
        info!(vendor = %vendor, "Allowing vendor");
        if !self.allowed_vendors.contains(&vendor.to_string()) {
            self.allowed_vendors.push(vendor.to_string());
        }
    }

    pub fn device_history(&self) -> &[(String, DevicePolicy, DateTime<Utc>)] {
        &self.device_history
    }

    pub fn is_allowed(&self, vendor: &str, product: &str) -> bool {
        for rule in &self.policy_rules {
            if rule.vendor == vendor && rule.product == product {
                return rule.policy == DevicePolicy::Allowed;
            }
        }

        if self.blocked_vendors.contains(&vendor.to_string()) {
            return false;
        }

        if !self.allowed_vendors.is_empty() {
            return self.allowed_vendors.contains(&vendor.to_string());
        }

        true
    }

    pub fn get_device(&self, id: &str) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }

    pub fn get_all_devices(&self) -> Vec<&DeviceRecord> {
        self.devices.values().collect()
    }

    pub fn get_alerts(&self) -> &[DeviceAlert] {
        &self.alerts
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }
}

impl Default for DeviceController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(id: &str, vendor: &str, product: &str, allowed: bool) -> DeviceInfo {
        DeviceInfo {
            id: id.to_string(),
            device_type: DeviceType::Usb,
            vendor: vendor.to_string(),
            product: product.to_string(),
            serial: format!("SN-{}", id),
            allowed,
        }
    }

    #[test]
    fn test_device_controller_new() {
        let controller = DeviceController::new();
        assert!(controller.get_all_devices().is_empty());
        assert!(controller.alert_count() == 0);
    }

    #[test]
    fn test_check_device_allowed() {
        let mut controller = DeviceController::new();
        let device = make_device("dev001", "Kingston", "DataTraveler", true);
        let policy = controller.check_device(&device);
        assert_eq!(policy, DevicePolicy::Allowed);
    }

    #[test]
    fn test_check_device_audit() {
        let mut controller = DeviceController::new();
        let device = make_device("dev002", "UnknownVendor", "UnknownProduct", false);
        let policy = controller.check_device(&device);
        assert_eq!(policy, DevicePolicy::Audit);
    }

    #[test]
    fn test_block_device() {
        let mut controller = DeviceController::new();
        controller.block_device("EvilCorp", "BadUSB");
        let device = DeviceInfo {
            id: "dev003".to_string(),
            device_type: DeviceType::Usb,
            vendor: "EvilCorp".to_string(),
            product: "BadUSB".to_string(),
            serial: "SN-003".to_string(),
            allowed: true,
        };
        let policy = controller.check_device(&device);
        assert_eq!(policy, DevicePolicy::Blocked);
        assert!(controller.alert_count() > 0);
    }

    #[test]
    fn test_add_allowed_device() {
        let mut controller = DeviceController::new();
        controller.add_allowed_device("Kingston", "DataTraveler");
        let device = make_device("dev004", "Kingston", "DataTraveler", false);
        let policy = controller.check_device(&device);
        assert_eq!(policy, DevicePolicy::Allowed);
    }

    #[test]
    fn test_is_allowed() {
        let mut controller = DeviceController::new();
        assert!(controller.is_allowed("Kingston", "DataTraveler"));
        controller.block_device("EvilCorp", "HackRF");
        assert!(!controller.is_allowed("EvilCorp", "HackRF"));
    }

    #[test]
    fn test_device_history() {
        let mut controller = DeviceController::new();
        let d1 = make_device("d1", "A", "B", true);
        let d2 = make_device("d2", "C", "D", false);
        controller.check_device(&d1);
        controller.check_device(&d2);
        assert_eq!(controller.device_history().len(), 2);
    }

    #[test]
    fn test_block_vendor() {
        let mut controller = DeviceController::new();
        controller.block_vendor("SuspiciousCorp");
        let device = make_device("dev005", "SuspiciousCorp", "Widget", true);
        let policy = controller.check_device(&device);
        assert_eq!(policy, DevicePolicy::Blocked);
    }

    #[test]
    fn test_device_tracking() {
        let mut controller = DeviceController::new();
        let device = make_device("track001", "Logitech", "Mouse", true);
        controller.check_device(&device);
        controller.check_device(&device);
        let record = controller.get_device("track001").unwrap();
        assert_eq!(record.interaction_count, 2);
    }
}
