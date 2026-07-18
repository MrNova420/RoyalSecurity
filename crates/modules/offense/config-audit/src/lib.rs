pub mod prelude;

use royalsecurity_common::types::*;
use tracing::{info, debug};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WeaknessCategory {
    Authentication,
    Authorization,
    Network,
    Encryption,
    Logging,
    Patching,
}

impl std::fmt::Display for WeaknessCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeaknessCategory::Authentication => write!(f, "Authentication"),
            WeaknessCategory::Authorization => write!(f, "Authorization"),
            WeaknessCategory::Network => write!(f, "Network"),
            WeaknessCategory::Encryption => write!(f, "Encryption"),
            WeaknessCategory::Logging => write!(f, "Logging"),
            WeaknessCategory::Patching => write!(f, "Patching"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: EventSeverity,
    pub check_fn_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub check_id: String,
    pub passed: bool,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
    pub remediation: String,
    pub severity: EventSeverity,
}

pub struct ConfigAuditor {
    checks: Vec<AuditCheck>,
    results: Vec<AuditResult>,
}

impl ConfigAuditor {
    pub fn new() -> Self {
        info!("Initializing configuration auditor");
        let mut auditor = Self {
            checks: Vec::new(),
            results: Vec::new(),
        };
        auditor.load_default_checks();
        auditor
    }

    fn load_default_checks(&mut self) {
        self.checks.extend(vec![
            AuditCheck {
                id: "AUTH-001".into(),
                name: "Password complexity enforced".into(),
                description: "Ensure password complexity requirements are configured".into(),
                severity: EventSeverity::High,
                check_fn_name: "check_authentication".into(),
            },
            AuditCheck {
                id: "AUTH-002".into(),
                name: "Account lockout configured".into(),
                description: "Ensure account lockout threshold is set to prevent brute force".into(),
                severity: EventSeverity::High,
                check_fn_name: "check_authentication".into(),
            },
            AuditCheck {
                id: "AUTH-003".into(),
                name: "Multi-factor authentication enabled".into(),
                description: "MFA should be enabled for privileged accounts".into(),
                severity: EventSeverity::Critical,
                check_fn_name: "check_authentication".into(),
            },
            AuditCheck {
                id: "AUTHZ-001".into(),
                name: "Least privilege enforced".into(),
                description: "Users should not have unnecessary administrative privileges".into(),
                severity: EventSeverity::High,
                check_fn_name: "check_authorization".into(),
            },
            AuditCheck {
                id: "AUTHZ-002".into(),
                name: "Guest account disabled".into(),
                description: "Built-in guest account should be disabled".into(),
                severity: EventSeverity::Critical,
                check_fn_name: "check_authorization".into(),
            },
            AuditCheck {
                id: "NET-001".into(),
                name: "Firewall enabled".into(),
                description: "Host firewall should be enabled and blocking unnecessary ports".into(),
                severity: EventSeverity::Critical,
                check_fn_name: "check_network".into(),
            },
            AuditCheck {
                id: "NET-002".into(),
                name: "SMBv1 disabled".into(),
                description: "SMBv1 protocol should be disabled".into(),
                severity: EventSeverity::Critical,
                check_fn_name: "check_network".into(),
            },
            AuditCheck {
                id: "NET-003".into(),
                name: "Unnecessary services disabled".into(),
                description: "Telnet, FTP, and other insecure services should be disabled".into(),
                severity: EventSeverity::High,
                check_fn_name: "check_network".into(),
            },
        ]);
        info!(count = self.checks.len(), "Loaded default audit checks");
    }

    pub fn run_audit(&mut self, config_data: &HashMap<String, String>) -> Vec<AuditResult> {
        info!("Starting full configuration audit");
        let mut results = Vec::new();

        results.extend(self.check_authentication(config_data));
        results.extend(self.check_authorization(config_data));
        results.extend(self.check_network(config_data));

        self.results = results.clone();

        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.iter().filter(|r| !r.passed).count();
        info!(
            total = results.len(),
            passed = passed,
            failed = failed,
            "Configuration audit completed"
        );

        results
    }

    pub fn check_authentication(&self, config: &HashMap<String, String>) -> Vec<AuditResult> {
        debug!("Running authentication checks");
        let mut results = Vec::new();

        let password_complexity = config.get("password_complexity");
        results.push(AuditResult {
            check_id: "AUTH-001".into(),
            passed: password_complexity.map_or(false, |v| v.eq_ignore_ascii_case("enabled") || v.eq_ignore_ascii_case("1")),
            current_value: password_complexity.cloned(),
            expected_value: Some("enabled".into()),
            remediation: "Enable password complexity requirements in security policy".into(),
            severity: EventSeverity::High,
        });

        let lockout_threshold = config.get("lockout_threshold")
            .and_then(|v| v.parse::<u32>().ok());
        results.push(AuditResult {
            check_id: "AUTH-002".into(),
            passed: lockout_threshold.map_or(false, |v| v > 0 && v <= 5),
            current_value: config.get("lockout_threshold").cloned(),
            expected_value: Some("1-5".into()),
            remediation: "Set account lockout threshold to 5 or fewer invalid attempts".into(),
            severity: EventSeverity::High,
        });

        let mfa_enabled = config.get("mfa_enabled");
        results.push(AuditResult {
            check_id: "AUTH-003".into(),
            passed: mfa_enabled.map_or(false, |v| v.eq_ignore_ascii_case("enabled") || v.eq_ignore_ascii_case("1")),
            current_value: mfa_enabled.cloned(),
            expected_value: Some("enabled".into()),
            remediation: "Enable multi-factor authentication for privileged accounts".into(),
            severity: EventSeverity::Critical,
        });

        results
    }

    pub fn check_authorization(&self, config: &HashMap<String, String>) -> Vec<AuditResult> {
        debug!("Running authorization checks");
        let mut results = Vec::new();

        let admin_count = config.get("admin_user_count")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        results.push(AuditResult {
            check_id: "AUTHZ-001".into(),
            passed: admin_count <= 3,
            current_value: Some(admin_count.to_string()),
            expected_value: Some("<=3".into()),
            remediation: "Reduce administrative privileges to minimum necessary".into(),
            severity: EventSeverity::High,
        });

        let guest_enabled = config.get("guest_account_enabled");
        results.push(AuditResult {
            check_id: "AUTHZ-002".into(),
            passed: guest_enabled.map_or(true, |v| v.eq_ignore_ascii_case("disabled") || v.eq_ignore_ascii_case("0")),
            current_value: guest_enabled.cloned(),
            expected_value: Some("disabled".into()),
            remediation: "Disable the built-in guest account".into(),
            severity: EventSeverity::Critical,
        });

        results
    }

    pub fn check_network(&self, config: &HashMap<String, String>) -> Vec<AuditResult> {
        debug!("Running network checks");
        let mut results = Vec::new();

        let firewall = config.get("firewall_enabled");
        results.push(AuditResult {
            check_id: "NET-001".into(),
            passed: firewall.map_or(false, |v| v.eq_ignore_ascii_case("enabled") || v.eq_ignore_ascii_case("1")),
            current_value: firewall.cloned(),
            expected_value: Some("enabled".into()),
            remediation: "Enable the host firewall and configure rules for necessary ports only".into(),
            severity: EventSeverity::Critical,
        });

        let smbv1 = config.get("smbv1_enabled");
        results.push(AuditResult {
            check_id: "NET-002".into(),
            passed: smbv1.map_or(true, |v| v.eq_ignore_ascii_case("disabled") || v.eq_ignore_ascii_case("0")),
            current_value: smbv1.cloned(),
            expected_value: Some("disabled".into()),
            remediation: "Disable SMBv1 protocol to prevent EternalBlue-class vulnerabilities".into(),
            severity: EventSeverity::Critical,
        });

        let telnet = config.get("telnet_enabled");
        let ftp = config.get("ftp_enabled");
        let insecure = telnet.map_or(false, |v| v.eq_ignore_ascii_case("enabled") || v.eq_ignore_ascii_case("1"))
            || ftp.map_or(false, |v| v.eq_ignore_ascii_case("enabled") || v.eq_ignore_ascii_case("1"));
        let insecure_val = if telnet.map_or(false, |v| v.eq_ignore_ascii_case("enabled")) {
            Some("telnet=enabled".into())
        } else if ftp.map_or(false, |v| v.eq_ignore_ascii_case("enabled")) {
            Some("ftp=enabled".into())
        } else {
            Some("all_disabled".into())
        };
        results.push(AuditResult {
            check_id: "NET-003".into(),
            passed: !insecure,
            current_value: insecure_val,
            expected_value: Some("all_disabled".into()),
            remediation: "Disable Telnet, FTP, and other insecure cleartext services".into(),
            severity: EventSeverity::High,
        });

        results
    }

    pub fn weakness_count(results: &[AuditResult]) -> usize {
        results.iter().filter(|r| !r.passed).count()
    }

    pub fn add_custom_check(&mut self, check: AuditCheck) {
        info!(id = %check.id, name = %check.name, "Adding custom audit check");
        self.checks.push(check);
    }
}

impl Default for ConfigAuditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> HashMap<String, String> {
        HashMap::new()
    }

    fn compliant_config() -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("password_complexity".into(), "enabled".into());
        config.insert("lockout_threshold".into(), "3".into());
        config.insert("mfa_enabled".into(), "enabled".into());
        config.insert("admin_user_count".into(), "2".into());
        config.insert("guest_account_enabled".into(), "disabled".into());
        config.insert("firewall_enabled".into(), "enabled".into());
        config.insert("smbv1_enabled".into(), "disabled".into());
        config.insert("telnet_enabled".into(), "disabled".into());
        config.insert("ftp_enabled".into(), "disabled".into());
        config
    }

    #[test]
    fn test_new_auditor_has_default_checks() {
        let auditor = ConfigAuditor::new();
        assert!(auditor.checks.len() >= 8);
        assert!(auditor.results.is_empty());
    }

    #[test]
    fn test_run_audit_empty_config() {
        let mut auditor = ConfigAuditor::new();
        let results = auditor.run_audit(&empty_config());
        assert_eq!(results.len(), 8);
        let failed = results.iter().filter(|r| !r.passed).count();
        assert!(failed >= 4, "Most mandatory checks should fail with empty config");
    }

    #[test]
    fn test_run_audit_compliant_config() {
        let mut auditor = ConfigAuditor::new();
        let results = auditor.run_audit(&compliant_config());
        let passed = results.iter().filter(|r| r.passed).count();
        assert!(passed >= 7, "Most checks should pass with compliant config");
    }

    #[test]
    fn test_check_authentication() {
        let auditor = ConfigAuditor::new();
        let mut config = HashMap::new();
        config.insert("password_complexity".into(), "enabled".into());
        config.insert("lockout_threshold".into(), "5".into());
        config.insert("mfa_enabled".into(), "disabled".into());

        let results = auditor.check_authentication(&config);
        assert_eq!(results.len(), 3);
        assert!(results[0].passed);
        assert!(results[1].passed);
        assert!(!results[2].passed);
    }

    #[test]
    fn test_check_authorization() {
        let auditor = ConfigAuditor::new();
        let mut config = HashMap::new();
        config.insert("admin_user_count".into(), "10".into());
        config.insert("guest_account_enabled".into(), "enabled".into());

        let results = auditor.check_authorization(&config);
        assert_eq!(results.len(), 2);
        assert!(!results[0].passed);
        assert!(!results[1].passed);
    }

    #[test]
    fn test_check_network() {
        let auditor = ConfigAuditor::new();
        let mut config = HashMap::new();
        config.insert("firewall_enabled".into(), "disabled".into());
        config.insert("smbv1_enabled".into(), "enabled".into());

        let results = auditor.check_network(&config);
        assert_eq!(results.len(), 3);
        assert!(!results[0].passed);
        assert!(!results[1].passed);
    }

    #[test]
    fn test_weakness_count() {
        let results = vec![
            AuditResult { check_id: "a".into(), passed: true, current_value: None, expected_value: None, remediation: String::new(), severity: EventSeverity::High },
            AuditResult { check_id: "b".into(), passed: false, current_value: None, expected_value: None, remediation: String::new(), severity: EventSeverity::Critical },
            AuditResult { check_id: "c".into(), passed: false, current_value: None, expected_value: None, remediation: String::new(), severity: EventSeverity::Medium },
        ];
        assert_eq!(ConfigAuditor::weakness_count(&results), 2);
    }

    #[test]
    fn test_add_custom_check() {
        let mut auditor = ConfigAuditor::new();
        let initial_count = auditor.checks.len();
        auditor.add_custom_check(AuditCheck {
            id: "CUSTOM-001".into(),
            name: "Custom check".into(),
            description: "A custom audit check".into(),
            severity: EventSeverity::Low,
            check_fn_name: "check_custom".into(),
        });
        assert_eq!(auditor.checks.len(), initial_count + 1);
    }

    #[test]
    fn test_weakness_category_display() {
        assert_eq!(format!("{}", WeaknessCategory::Authentication), "Authentication");
        assert_eq!(format!("{}", WeaknessCategory::Network), "Network");
        assert_eq!(format!("{}", WeaknessCategory::Encryption), "Encryption");
    }

    #[test]
    fn test_lockout_threshold_boundary() {
        let auditor = ConfigAuditor::new();
        let mut config = HashMap::new();
        config.insert("lockout_threshold".into(), "10".into());
        let results = auditor.check_authentication(&config);
        let lockout = results.iter().find(|r| r.check_id == "AUTH-002").unwrap();
        assert!(!lockout.passed, "Threshold of 10 should fail (>5)");
    }
}
