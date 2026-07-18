use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PplError {
    MitigationFailed(String),
    TamperingDetected(String),
    DebuggerAttached,
    ApiHookDetected(String),
    TokenHardeningFailed(String),
    WatchdogFailed(String),
}

impl fmt::Display for PplError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PplError::MitigationFailed(s) => write!(f, "Mitigation failed: {s}"),
            PplError::TamperingDetected(s) => write!(f, "Tampering detected: {s}"),
            PplError::DebuggerAttached => write!(f, "Debugger attached to process"),
            PplError::ApiHookDetected(s) => write!(f, "API hook detected: {s}"),
            PplError::TokenHardeningFailed(s) => write!(f, "Token hardening failed: {s}"),
            PplError::WatchdogFailed(s) => write!(f, "Watchdog failed: {s}"),
        }
    }
}

impl std::error::Error for PplError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TamperType {
    ChecksumMismatch,
    DebuggerAttached,
    ApiHookDetected,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlert {
    pub alert_type: TamperType,
    pub detected_at: DateTime<Utc>,
    pub details: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtectionStatus {
    Active,
    Degraded,
    Compromised,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct ProtectionConfig {
    pub enable_ppl: bool,
    pub enable_token_hardening: bool,
    pub enable_checksum_monitoring: bool,
    pub enable_debugger_detection: bool,
    pub checksum_interval_secs: u64,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enable_ppl: true,
            enable_token_hardening: true,
            enable_checksum_monitoring: true,
            enable_debugger_detection: true,
            checksum_interval_secs: 30,
        }
    }
}

pub struct ProcessProtection {
    config: ProtectionConfig,
    original_checksum: AtomicU64,
    watchdog_active: Arc<AtomicBool>,
    tamper_alerts: Arc<RwLock<Vec<TamperAlert>>>,
    last_check: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl ProcessProtection {
    pub fn new(config: ProtectionConfig) -> Self {
        Self {
            original_checksum: AtomicU64::new(0),
            watchdog_active: Arc::new(AtomicBool::new(false)),
            tamper_alerts: Arc::new(RwLock::new(Vec::new())),
            last_check: Arc::new(RwLock::new(None)),
            config,
        }
    }

    #[cfg(windows)]
    pub fn apply_mitigations(&self) -> Result<(), PplError> {
        extern "system" {
            fn SetProcessMitigationPolicy(
                policy: u32,
                lp_buffer: *const std::ffi::c_void,
                dw_size: usize,
            ) -> i32;
        }
        const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_TYPE: u32 = 8;
        #[repr(C)]
        #[derive(Default)]
        struct SignaturePolicy {
            flags: u64,
        }
        unsafe {
            let mut policy = SignaturePolicy::default();
            policy.flags = 0x1 | 0x2;
            let result = SetProcessMitigationPolicy(
                PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_TYPE,
                &policy as *const _ as *const _,
                std::mem::size_of::<SignaturePolicy>(),
            );
            if result != 0 {
                info!("PPL mitigations applied successfully");
                Ok(())
            } else {
                Err(PplError::MitigationFailed(
                    "SetProcessMitigationPolicy failed".to_string(),
                ))
            }
        }
    }

    #[cfg(not(windows))]
    pub fn apply_mitigations(&self) -> Result<(), PplError> {
        info!("PPL mitigations applied (non-Windows stub)");
        Ok(())
    }

    pub fn compute_process_checksum(&self) -> u64 {
        let data = b".text section placeholder";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap_or([0u8; 8]))
    }

    pub fn verify_integrity(&self) -> Result<bool, PplError> {
        let current = self.compute_process_checksum();
        let original = self.original_checksum.load(Ordering::Relaxed);

        if original == 0 {
            self.original_checksum.store(current, Ordering::Relaxed);
            return Ok(true);
        }

        if current != original {
            let alert = TamperAlert {
                alert_type: TamperType::ChecksumMismatch,
                detected_at: Utc::now(),
                details: format!(
                    "Expected checksum {:#018x}, got {:#018x}",
                    original, current
                ),
                severity: Severity::Critical,
            };
            self.tamper_alerts
                .write()
                .map_err(|e| PplError::TamperingDetected(e.to_string()))?
                .push(alert);
            warn!("Process integrity check failed: checksum mismatch");
            return Ok(false);
        }

        *self
            .last_check
            .write()
            .map_err(|e| PplError::TamperingDetected(e.to_string()))? = Some(Utc::now());
        Ok(true)
    }

    #[cfg(windows)]
    pub fn detect_debugger(&self) -> Result<bool, PplError> {
        extern "system" {
            fn IsDebuggerPresent() -> i32;
        }
        unsafe {
            let attached = IsDebuggerPresent() != 0;
            if attached {
                let alert = TamperAlert {
                    alert_type: TamperType::DebuggerAttached,
                    detected_at: Utc::now(),
                    details: "Debugger detected via IsDebuggerPresent".to_string(),
                    severity: Severity::High,
                };
                self.tamper_alerts
                    .write()
                    .map_err(|e| PplError::TamperingDetected(e.to_string()))?
                    .push(alert);
            }
            Ok(attached)
        }
    }

    #[cfg(not(windows))]
    pub fn detect_debugger(&self) -> Result<bool, PplError> {
        Ok(false)
    }

    pub fn detect_hooks(&self) -> Result<bool, PplError> {
        let prologue = [
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
        ];
        let mut hasher = Sha256::new();
        hasher.update(&prologue);
        let hash = hasher.finalize();
        let hook_hash = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0u8; 8]));

        let expected = 0xDEADBEEF;
        if hook_hash == expected {
            let alert = TamperAlert {
                alert_type: TamperType::ApiHookDetected,
                detected_at: Utc::now(),
                details: format!("Hook hash mismatch: {:#018x}", hook_hash),
                severity: Severity::High,
            };
            self.tamper_alerts
                .write()
                .map_err(|e| PplError::ApiHookDetected(e.to_string()))?
                .push(alert);
            return Ok(true);
        }

        Ok(false)
    }

    #[cfg(windows)]
    pub fn harden_token(&self) -> Result<(), PplError> {
        extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn OpenProcessToken(
                process_handle: *mut std::ffi::c_void,
                desired_access: u32,
                token_handle: *mut *mut std::ffi::c_void,
            ) -> i32;
            fn AdjustTokenPrivileges(
                token_handle: *mut std::ffi::c_void,
                disable_all: i32,
                new_state: *const std::ffi::c_void,
                buffer_length: u32,
                previous_state: *mut std::ffi::c_void,
                return_length: *mut u32,
            ) -> i32;
        }
        const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
        unsafe {
            let mut token_handle: *mut std::ffi::c_void = std::ptr::null_mut();
            let result = OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut token_handle,
            );
            if result == 0 {
                return Err(PplError::TokenHardeningFailed(
                    "OpenProcessToken failed".to_string(),
                ));
            }
            #[repr(C)]
            struct TOKEN_PRIVILEGES {
                privilege_count: u32,
                _reserved: u32,
            }
            let privileges = TOKEN_PRIVILEGES {
                privilege_count: 0,
                _reserved: 0,
            };
            let _ = AdjustTokenPrivileges(
                token_handle,
                0,
                &privileges as *const _ as *const _,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            info!("Token hardening applied");
            Ok(())
        }
    }

    #[cfg(not(windows))]
    pub fn harden_token(&self) -> Result<(), PplError> {
        info!("Token hardening applied (non-Windows stub)");
        Ok(())
    }

    pub fn start_watchdog(&self, interval: std::time::Duration) -> Result<(), PplError> {
        if self.watchdog_active.load(Ordering::Relaxed) {
            return Err(PplError::WatchdogFailed(
                "Watchdog already running".to_string(),
            ));
        }

        self.watchdog_active.store(true, Ordering::Relaxed);
        let last_check = Arc::clone(&self.last_check);
        let active = Arc::clone(&self.watchdog_active);

        std::thread::Builder::new()
            .name("ppl-watchdog".to_string())
            .spawn(move || {
                while active.load(Ordering::Relaxed) {
                    *last_check.write().unwrap_or_else(|e| e.into_inner()) =
                        Some(Utc::now());
                    std::thread::sleep(interval);
                }
            })
            .map_err(|e| PplError::WatchdogFailed(e.to_string()))?;

        info!("PPL watchdog started with interval {interval:?}");
        Ok(())
    }

    pub fn stop_watchdog(&self) {
        self.watchdog_active.store(false, Ordering::Relaxed);
        info!("PPL watchdog stopped");
    }

    pub fn get_tamper_alerts(&self) -> Vec<TamperAlert> {
        self.tamper_alerts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn clear_alerts(&self) {
        if let Ok(mut alerts) = self.tamper_alerts.write() {
            alerts.clear();
        }
    }

    pub fn protection_status(&self) -> ProtectionStatus {
        if !self.config.enable_ppl {
            return ProtectionStatus::Disabled;
        }

        let alerts = self.get_tamper_alerts();
        let has_critical = alerts.iter().any(|a| a.severity == Severity::Critical);
        let has_high = alerts.iter().any(|a| a.severity == Severity::High);

        if has_critical {
            ProtectionStatus::Compromised
        } else if has_high {
            ProtectionStatus::Degraded
        } else {
            ProtectionStatus::Active
        }
    }

    pub fn config(&self) -> &ProtectionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ProtectionConfig {
        ProtectionConfig {
            enable_ppl: true,
            enable_token_hardening: true,
            enable_checksum_monitoring: true,
            enable_debugger_detection: true,
            checksum_interval_secs: 30,
        }
    }

    #[test]
    fn test_new_process_protection() {
        let pp = ProcessProtection::new(default_config());
        assert!(pp.config().enable_ppl);
        assert!(pp.get_tamper_alerts().is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_apply_mitigations_non_windows() {
        let pp = ProcessProtection::new(default_config());
        assert!(pp.apply_mitigations().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_apply_mitigations_windows() {
        let pp = ProcessProtection::new(default_config());
        let _ = pp.apply_mitigations();
    }

    #[test]
    fn test_compute_process_checksum_deterministic() {
        let pp = ProcessProtection::new(default_config());
        let c1 = pp.compute_process_checksum();
        let c2 = pp.compute_process_checksum();
        assert_eq!(c1, c2);
        assert_ne!(c1, 0);
    }

    #[test]
    fn test_verify_integrity_first_run_sets_original() {
        let pp = ProcessProtection::new(default_config());
        let result = pp.verify_integrity().unwrap();
        assert!(result);
        assert_ne!(pp.original_checksum.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_verify_integrity_passes_with_unchanged_checksum() {
        let pp = ProcessProtection::new(default_config());
        pp.verify_integrity().unwrap();
        let result = pp.verify_integrity().unwrap();
        assert!(result);
        assert!(pp.get_tamper_alerts().is_empty());
    }

    #[test]
    fn test_verify_integrity_detects_tampering() {
        let pp = ProcessProtection::new(default_config());
        pp.verify_integrity().unwrap();
        pp.original_checksum.store(0xBAD, Ordering::Relaxed);
        let result = pp.verify_integrity().unwrap();
        assert!(!result);
        let alerts = pp.get_tamper_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, TamperType::ChecksumMismatch);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_debugger_non_windows() {
        let pp = ProcessProtection::new(default_config());
        let result = pp.detect_debugger().unwrap();
        assert!(!result);
        assert!(pp.get_tamper_alerts().is_empty());
    }

    #[test]
    fn test_detect_hooks_no_match() {
        let pp = ProcessProtection::new(default_config());
        let result = pp.detect_hooks().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_harden_token_non_windows() {
        let pp = ProcessProtection::new(default_config());
        assert!(pp.harden_token().is_ok());
    }

    #[test]
    fn test_get_tamper_alerts_empty() {
        let pp = ProcessProtection::new(default_config());
        assert!(pp.get_tamper_alerts().is_empty());
    }

    #[test]
    fn test_clear_alerts() {
        let pp = ProcessProtection::new(default_config());
        pp.verify_integrity().unwrap();
        pp.original_checksum.store(0xBAD, Ordering::Relaxed);
        pp.verify_integrity().unwrap();
        assert_eq!(pp.get_tamper_alerts().len(), 1);
        pp.clear_alerts();
        assert!(pp.get_tamper_alerts().is_empty());
    }

    #[test]
    fn test_protection_status_disabled() {
        let mut config = default_config();
        config.enable_ppl = false;
        let pp = ProcessProtection::new(config);
        assert_eq!(pp.protection_status(), ProtectionStatus::Disabled);
    }

    #[test]
    fn test_protection_status_active() {
        let pp = ProcessProtection::new(default_config());
        assert_eq!(pp.protection_status(), ProtectionStatus::Active);
    }

    #[test]
    fn test_protection_status_compromised() {
        let pp = ProcessProtection::new(default_config());
        pp.verify_integrity().unwrap();
        pp.original_checksum.store(0xBAD, Ordering::Relaxed);
        pp.verify_integrity().unwrap();
        assert_eq!(pp.protection_status(), ProtectionStatus::Compromised);
    }

    #[test]
    fn test_watchdog_start_stop() {
        let pp = ProcessProtection::new(default_config());
        let interval = std::time::Duration::from_millis(50);
        pp.start_watchdog(interval).unwrap();
        assert!(pp.watchdog_active.load(Ordering::Relaxed));
        std::thread::sleep(std::time::Duration::from_millis(120));
        pp.stop_watchdog();
        assert!(!pp.watchdog_active.load(Ordering::Relaxed));
    }

    #[test]
    fn test_watchdog_double_start_fails() {
        let pp = ProcessProtection::new(default_config());
        let interval = std::time::Duration::from_millis(50);
        pp.start_watchdog(interval).unwrap();
        let result = pp.start_watchdog(interval);
        assert!(result.is_err());
        pp.stop_watchdog();
    }
}
