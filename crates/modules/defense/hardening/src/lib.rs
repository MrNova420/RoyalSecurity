pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info, debug};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceStandard {
    CIS,
    NIST80053,
    #[allow(non_camel_case_types)]
    DISA_STIG,
    #[allow(non_camel_case_types)]
    PCI_DSS,
    HIPAA,
    GDPR,
}

impl Default for ComplianceStandard {
    fn default() -> Self {
        ComplianceStandard::CIS
    }
}

impl std::fmt::Display for ComplianceStandard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStandard::CIS => write!(f, "CIS"),
            ComplianceStandard::NIST80053 => write!(f, "NIST 800-53"),
            #[allow(non_camel_case_types)]
            ComplianceStandard::DISA_STIG => write!(f, "DISA STIG"),
            #[allow(non_camel_case_types)]
            ComplianceStandard::PCI_DSS => write!(f, "PCI DSS"),
            ComplianceStandard::HIPAA => write!(f, "HIPAA"),
            ComplianceStandard::GDPR => write!(f, "GDPR"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardeningCategory {
    AccountPolicies,
    AuditPolicies,
    UserRights,
    SecurityOptions,
    RegistryPermissions,
    ServiceConfig,
    FirewallConfig,
    WindowsUpdate,
    BitLocker,
    WindowsDefender,
    NetworkSecurity,
    ApplicationControl,
}

impl std::fmt::Display for HardeningCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardeningCategory::AccountPolicies => write!(f, "Account Policies"),
            HardeningCategory::AuditPolicies => write!(f, "Audit Policies"),
            HardeningCategory::UserRights => write!(f, "User Rights"),
            HardeningCategory::SecurityOptions => write!(f, "Security Options"),
            HardeningCategory::RegistryPermissions => write!(f, "Registry Permissions"),
            HardeningCategory::ServiceConfig => write!(f, "Service Configuration"),
            HardeningCategory::FirewallConfig => write!(f, "Firewall Configuration"),
            HardeningCategory::WindowsUpdate => write!(f, "Windows Update"),
            HardeningCategory::BitLocker => write!(f, "BitLocker"),
            HardeningCategory::WindowsDefender => write!(f, "Windows Defender"),
            HardeningCategory::NetworkSecurity => write!(f, "Network Security"),
            HardeningCategory::ApplicationControl => write!(f, "Application Control"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckType {
    RegistryCheck {
        key: String,
        value: String,
        expected: String,
    },
    ServiceCheck {
        name: String,
        expected_status: String,
        expected_start: Option<String>,
    },
    PolicyCheck {
        policy_name: String,
        expected_value: String,
    },
    FilePermissionsCheck {
        path: String,
        required_acl: String,
    },
    CompositeCheck {
        sub_checks: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: HardeningCategory,
    pub severity: EventSeverity,
    pub enabled: bool,
    pub check_type: CheckType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningResult {
    pub check_id: String,
    pub check_name: String,
    pub passed: bool,
    pub severity: EventSeverity,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
    pub remediation: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    pub standard: ComplianceStandard,
    pub auto_remediate: bool,
    pub excluded_checks: Vec<String>,
    pub severity_filter: Option<EventSeverity>,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            standard: ComplianceStandard::CIS,
            auto_remediate: false,
            excluded_checks: Vec::new(),
            severity_filter: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryChange {
    pub key: String,
    pub value: String,
    pub new_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChange {
    pub name: String,
    pub action: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub check_id: String,
    pub description: String,
    pub registry_changes: Vec<RegistryChange>,
    pub service_changes: Vec<ServiceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub status: String,
    pub start_type: String,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub registry: HashMap<String, String>,
    pub services: HashMap<String, ServiceState>,
    pub hostname: String,
    pub os_version: String,
}

pub struct HardeningAuditor {
    checks: Vec<HardeningCheck>,
    results: Vec<HardeningResult>,
    config: HardeningConfig,
    compliance_score: f64,
}

impl HardeningAuditor {
    pub fn new() -> Self {
        info!("Initializing hardening auditor with default CIS checks");
        let checks = Self::default_checks();
        Self {
            checks,
            results: Vec::new(),
            config: HardeningConfig::default(),
            compliance_score: 0.0,
        }
    }

    pub fn with_config(config: HardeningConfig) -> Self {
        info!(standard = %config.standard, "Initializing hardening auditor with custom configuration");
        let checks = Self::default_checks();
        Self {
            checks,
            results: Vec::new(),
            config,
            compliance_score: 0.0,
        }
    }

    pub fn run_audit(
        &mut self,
        registry_state: &HashMap<String, String>,
        service_state: &HashMap<String, ServiceState>,
    ) -> Vec<HardeningResult> {
        info!("Starting hardening audit");
        let mut results = Vec::new();

        for check in &self.checks {
            if !check.enabled {
                debug!(check_id = %check.id, "Skipping disabled check");
                continue;
            }
            if self.config.excluded_checks.contains(&check.id) {
                debug!(check_id = %check.id, "Skipping excluded check");
                continue;
            }
            if let Some(min_severity) = self.config.severity_filter {
                if check.severity > min_severity {
                    debug!(check_id = %check.id, "Skipping check below severity filter");
                    continue;
                }
            }

            let result = match &check.check_type {
                CheckType::RegistryCheck { .. } => self.assess_registry_check(check, registry_state),
                CheckType::ServiceCheck { .. } => self.assess_service_check(check, service_state),
                CheckType::PolicyCheck { .. } => self.assess_policy_check(check, registry_state),
                CheckType::FilePermissionsCheck { path, .. } => {
                    debug!(check_id = %check.id, path = %path, "File permissions check not implemented in mock");
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed: false,
                        severity: check.severity,
                        current_value: None,
                        expected_value: None,
                        remediation: format!("Manual verification required for file permissions at {}", path),
                        timestamp: Utc::now(),
                    }
                }
                CheckType::CompositeCheck { sub_checks } => {
                    let all_passed = sub_checks.iter().all(|sub_id| {
                        results.iter().any(|r: &HardeningResult| r.check_id == *sub_id && r.passed)
                    });
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed: all_passed,
                        severity: check.severity,
                        current_value: if all_passed { Some("All sub-checks passed".into()) } else { Some("One or more sub-checks failed".into()) },
                        expected_value: Some("All sub-checks must pass".into()),
                        remediation: if all_passed {
                            String::new()
                        } else {
                            format!("Ensure all sub-checks [{}] pass", sub_checks.join(", "))
                        },
                        timestamp: Utc::now(),
                    }
                }
            };

            if result.passed {
                debug!(check_id = %result.check_id, "Check passed");
            } else {
                warn!(check_id = %result.check_id, severity = %result.severity, "Check failed");
            }

            results.push(result);
        }

        self.compliance_score = Self::calculate_compliance_score(&results);
        self.results = results.clone();

        info!(
            score = self.compliance_score,
            total = results.len(),
            passed = results.iter().filter(|r| r.passed).count(),
            failed = results.iter().filter(|r| !r.passed).count(),
            "Hardening audit completed"
        );

        results
    }

    pub fn check_single(&self, check_id: &str, state: &SystemState) -> Option<HardeningResult> {
        let check = self.checks.iter().find(|c| c.id == check_id)?;
        debug!(check_id = %check_id, "Running single check");

        let result = match &check.check_type {
            CheckType::RegistryCheck { .. } => self.assess_registry_check(check, &state.registry),
            CheckType::ServiceCheck { .. } => self.assess_service_check(check, &state.services),
            CheckType::PolicyCheck { .. } => self.assess_policy_check(check, &state.registry),
            CheckType::FilePermissionsCheck { path, .. } => {
                HardeningResult {
                    check_id: check.id.clone(),
                    check_name: check.name.clone(),
                    passed: false,
                    severity: check.severity,
                    current_value: None,
                    expected_value: None,
                    remediation: format!("Manual verification required for file permissions at {}", path),
                    timestamp: Utc::now(),
                }
            }
            CheckType::CompositeCheck { .. } => {
                warn!(check_id = %check_id, "Composite check cannot be run individually");
                return None;
            }
        };

        Some(result)
    }

    pub fn assess_registry_check(
        &self,
        check: &HardeningCheck,
        registry: &HashMap<String, String>,
    ) -> HardeningResult {
        if let CheckType::RegistryCheck { key, value, expected } = &check.check_type {
            let full_path = format!("{}\\{}", key, value);
            let current = registry.get(&full_path);

            match current {
                Some(actual) => {
                    let passed = actual.eq_ignore_ascii_case(expected);
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed,
                        severity: check.severity,
                        current_value: Some(actual.clone()),
                        expected_value: Some(expected.clone()),
                        remediation: if passed {
                            String::new()
                        } else {
                            format!(
                                "Set registry value {}\\{} to {} (currently: {})",
                                key, value, expected, actual
                            )
                        },
                        timestamp: Utc::now(),
                    }
                }
                None => {
                    let passed = expected.is_empty();
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed,
                        severity: check.severity,
                        current_value: None,
                        expected_value: Some(expected.clone()),
                        remediation: if passed {
                            String::new()
                        } else {
                            format!(
                                "Create registry value {}\\{} with value {}",
                                key, value, expected
                            )
                        },
                        timestamp: Utc::now(),
                    }
                }
            }
        } else {
            unreachable!("assess_registry_check called with non-RegistryCheck")
        }
    }

    pub fn assess_service_check(
        &self,
        check: &HardeningCheck,
        services: &HashMap<String, ServiceState>,
    ) -> HardeningResult {
        if let CheckType::ServiceCheck { name, expected_status, expected_start } = &check.check_type {
            let service = services.get(name);

            match service {
                Some(svc) => {
                    let status_ok = svc.status.eq_ignore_ascii_case(expected_status);
                    let start_ok = match expected_start {
                        Some(expected) => svc.start_type.eq_ignore_ascii_case(expected),
                        None => true,
                    };
                    let passed = status_ok && start_ok;

                    let current_detail = format!("status={}, start_type={}", svc.status, svc.start_type);
                    let expected_detail = match expected_start {
                        Some(es) => format!("status={}, start_type={}", expected_status, es),
                        None => format!("status={}", expected_status),
                    };

                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed,
                        severity: check.severity,
                        current_value: Some(current_detail),
                        expected_value: Some(expected_detail),
                        remediation: if passed {
                            String::new()
                        } else {
                            format!(
                                "Configure service {} to {} (currently: {})",
                                name, expected_status, svc.status
                            )
                        },
                        timestamp: Utc::now(),
                    }
                }
                None => {
                    let passed = expected_status.eq_ignore_ascii_case("Disabled")
                        || expected_status.eq_ignore_ascii_case("Stopped")
                        || expected_status.is_empty();
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed,
                        severity: check.severity,
                        current_value: Some("Service not found".into()),
                        expected_value: Some(expected_status.clone()),
                        remediation: if passed {
                            String::new()
                        } else {
                            format!("Service {} not found; expected status {}", name, expected_status)
                        },
                        timestamp: Utc::now(),
                    }
                }
            }
        } else {
            unreachable!("assess_service_check called with non-ServiceCheck")
        }
    }

    fn assess_policy_check(
        &self,
        check: &HardeningCheck,
        registry: &HashMap<String, String>,
    ) -> HardeningResult {
        if let CheckType::PolicyCheck { policy_name, expected_value } = &check.check_type {
            let current = registry.get(policy_name);
            match current {
                Some(actual) => {
                    let passed = actual.eq_ignore_ascii_case(expected_value);
                    HardeningResult {
                        check_id: check.id.clone(),
                        check_name: check.name.clone(),
                        passed,
                        severity: check.severity,
                        current_value: Some(actual.clone()),
                        expected_value: Some(expected_value.clone()),
                        remediation: if passed {
                            String::new()
                        } else {
                            format!("Set policy {} to {} (currently: {})", policy_name, expected_value, actual)
                        },
                        timestamp: Utc::now(),
                    }
                }
                None => HardeningResult {
                    check_id: check.id.clone(),
                    check_name: check.name.clone(),
                    passed: false,
                    severity: check.severity,
                    current_value: None,
                    expected_value: Some(expected_value.clone()),
                    remediation: format!("Set policy {} to {}", policy_name, expected_value),
                    timestamp: Utc::now(),
                },
            }
        } else {
            unreachable!("assess_policy_check called with non-PolicyCheck")
        }
    }

    pub fn calculate_compliance_score(results: &[HardeningResult]) -> f64 {
        if results.is_empty() {
            return 100.0;
        }

        let mut total_weight: f64 = 0.0;
        let mut passed_weight: f64 = 0.0;

        for result in results {
            let weight = match result.severity {
                EventSeverity::Critical => 4.0,
                EventSeverity::High => 3.0,
                EventSeverity::Medium => 2.0,
                EventSeverity::Low => 1.0,
                EventSeverity::Informational => 0.5,
            };
            total_weight += weight;
            if result.passed {
                passed_weight += weight;
            }
        }

        if total_weight == 0.0 {
            return 100.0;
        }

        (passed_weight / total_weight) * 100.0
    }

    pub fn get_remediation(results: &[HardeningResult]) -> Vec<RemediationAction> {
        let mut actions = Vec::new();

        for result in results {
            if result.passed {
                continue;
            }

            let mut registry_changes = Vec::new();
            let mut service_changes = Vec::new();

            // Generate remediation based on the check type context
            // In a real system, this would parse the check definition
            // Here we generate structured remediation from the result metadata
            if let Some(ref expected) = result.expected_value {
                // Attempt to infer remediation type from the check ID prefix
                if result.check_id.starts_with("HC-0") || result.check_id.starts_with("HC-0") {
                    // Registry-based checks use common key patterns
                    let key = extract_registry_key_from_remediation(&result.remediation);
                    let value = extract_registry_value_from_remediation(&result.remediation);
                    if let (Some(k), Some(v)) = (key, value) {
                        registry_changes.push(RegistryChange {
                            key: k,
                            value: v,
                            new_data: expected.clone(),
                        });
                    }

                    let svc_name = extract_service_name_from_remediation(&result.remediation);
                    if let Some(name) = svc_name {
                        service_changes.push(ServiceChange {
                            name,
                            action: "Configure".into(),
                            value: Some(expected.clone()),
                        });
                    }
                }
            }

            actions.push(RemediationAction {
                check_id: result.check_id.clone(),
                description: result.remediation.clone(),
                registry_changes,
                service_changes,
            });
        }

        info!(count = actions.len(), "Generated remediation actions");
        actions
    }

    pub fn add_check(&mut self, check: HardeningCheck) {
        info!(check_id = %check.id, name = %check.name, "Adding hardening check");
        self.checks.push(check);
    }

    pub fn remove_check(&mut self, check_id: &str) {
        let before = self.checks.len();
        self.checks.retain(|c| c.id != check_id);
        let removed = before - self.checks.len();
        if removed > 0 {
            info!(check_id = %check_id, "Removed hardening check");
        } else {
            warn!(check_id = %check_id, "Check not found for removal");
        }
    }

    pub fn compliance_score(&self) -> f64 {
        self.compliance_score
    }

    pub fn results(&self) -> &[HardeningResult] {
        &self.results
    }

    fn default_checks() -> Vec<HardeningCheck> {
        vec![
            // Account Policies
            HardeningCheck {
                id: "HC-001".into(),
                name: "Password complexity enabled".into(),
                description: "Ensure password complexity requirements are enforced to prevent weak passwords".into(),
                category: HardeningCategory::AccountPolicies,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "NoLMHash".into(),
                    expected: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-002".into(),
                name: "Account lockout threshold".into(),
                description: "Account lockout threshold should be set to 5 or fewer invalid login attempts".into(),
                category: HardeningCategory::AccountPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "LockoutBadCount".into(),
                    expected: "5".into(),
                },
            },
            HardeningCheck {
                id: "HC-003".into(),
                name: "Password history requirement".into(),
                description: "Enforce password history of 24 or more passwords to prevent password reuse".into(),
                category: HardeningCategory::AccountPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "PasswordHistorySize".into(),
                    expected: "24".into(),
                },
            },
            HardeningCheck {
                id: "HC-004".into(),
                name: "Maximum password age".into(),
                description: "Maximum password age should not exceed 90 days".into(),
                category: HardeningCategory::AccountPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "MaxPasswordAge".into(),
                    expected: "90".into(),
                },
            },
            HardeningCheck {
                id: "HC-005".into(),
                name: "Minimum password length".into(),
                description: "Minimum password length should be 14 or more characters".into(),
                category: HardeningCategory::AccountPolicies,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "MinimumPasswordLength".into(),
                    expected: "14".into(),
                },
            },

            // Audit Policies
            HardeningCheck {
                id: "HC-010".into(),
                name: "Audit logon events enabled".into(),
                description: "Enable auditing of logon events to track authentication attempts".into(),
                category: HardeningCategory::AuditPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::PolicyCheck {
                    policy_name: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects".into(),
                    expected_value: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-011".into(),
                name: "Audit object access enabled".into(),
                description: "Enable auditing of object access for tracking file and registry changes".into(),
                category: HardeningCategory::AuditPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::PolicyCheck {
                    policy_name: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy".into(),
                    expected_value: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-012".into(),
                name: "Audit privilege use enabled".into(),
                description: "Enable auditing of privilege use to detect misuse of elevated permissions".into(),
                category: HardeningCategory::AuditPolicies,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::PolicyCheck {
                    policy_name: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects".into(),
                    expected_value: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-013".into(),
                name: "Audit policy change enabled".into(),
                description: "Enable auditing of policy changes to detect security configuration modifications".into(),
                category: HardeningCategory::AuditPolicies,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::PolicyCheck {
                    policy_name: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy".into(),
                    expected_value: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-014".into(),
                name: "Audit account logon events enabled".into(),
                description: "Enable auditing of account logon events for credential validation tracking".into(),
                category: HardeningCategory::AuditPolicies,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::PolicyCheck {
                    policy_name: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects".into(),
                    expected_value: "1".into(),
                },
            },

            // Security Options
            HardeningCheck {
                id: "HC-020".into(),
                name: "UAC enabled with Always Notify".into(),
                description: "User Account Control should be enabled and set to Always Notify for maximum protection".into(),
                category: HardeningCategory::SecurityOptions,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System".into(),
                    value: "ConsentPromptBehaviorAdmin".into(),
                    expected: "2".into(),
                },
            },
            HardeningCheck {
                id: "HC-021".into(),
                name: "Guest account disabled".into(),
                description: "The built-in Guest account should be disabled to prevent unauthorized access".into(),
                category: HardeningCategory::SecurityOptions,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SAM\\SAM\\Domains\\Account".into(),
                    value: "GuestAccountDisabled".into(),
                    expected: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-022".into(),
                name: "Anonymous SID name translation disabled".into(),
                description: "Prevent anonymous translation of SID names to reduce information disclosure".into(),
                category: HardeningCategory::SecurityOptions,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "RestrictAnonymous".into(),
                    expected: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-023".into(),
                name: "Remote registry access restricted".into(),
                description: "Remote access to the registry should be restricted to prevent unauthorized modifications".into(),
                category: HardeningCategory::SecurityOptions,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg".into(),
                    value: "RemoteRegAccess".into(),
                    expected: "0".into(),
                },
            },
            HardeningCheck {
                id: "HC-024".into(),
                name: "LM hash not stored".into(),
                description: "LM hash should not be stored to prevent credential theft via SAM database".into(),
                category: HardeningCategory::SecurityOptions,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
                    value: "NoLMHash".into(),
                    expected: "1".into(),
                },
            },

            // Service Config
            HardeningCheck {
                id: "HC-030".into(),
                name: "Windows Firewall service enabled".into(),
                description: "Windows Firewall service should be running to protect against network threats".into(),
                category: HardeningCategory::ServiceConfig,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::ServiceCheck {
                    name: "MpsSvc".into(),
                    expected_status: "Running".into(),
                    expected_start: Some("Automatic".into()),
                },
            },
            HardeningCheck {
                id: "HC-031".into(),
                name: "Windows Update service enabled".into(),
                description: "Windows Update service should be running to ensure timely security patches".into(),
                category: HardeningCategory::ServiceConfig,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::ServiceCheck {
                    name: "wuauserv".into(),
                    expected_status: "Running".into(),
                    expected_start: Some("Automatic".into()),
                },
            },
            HardeningCheck {
                id: "HC-032".into(),
                name: "Remote Registry disabled".into(),
                description: "Remote Registry service should be disabled to prevent unauthorized remote registry access".into(),
                category: HardeningCategory::ServiceConfig,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::ServiceCheck {
                    name: "RemoteRegistry".into(),
                    expected_status: "Stopped".into(),
                    expected_start: Some("Disabled".into()),
                },
            },
            HardeningCheck {
                id: "HC-033".into(),
                name: "Telnet service disabled".into(),
                description: "Telnet service should be disabled as it transmits data in cleartext".into(),
                category: HardeningCategory::ServiceConfig,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::ServiceCheck {
                    name: "TlntSvr".into(),
                    expected_status: "Stopped".into(),
                    expected_start: Some("Disabled".into()),
                },
            },
            HardeningCheck {
                id: "HC-034".into(),
                name: "SNMP service disabled or restricted".into(),
                description: "SNMP service should be disabled or properly configured with community strings".into(),
                category: HardeningCategory::ServiceConfig,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::ServiceCheck {
                    name: "SNMP".into(),
                    expected_status: "Stopped".into(),
                    expected_start: Some("Disabled".into()),
                },
            },

            // Network Security
            HardeningCheck {
                id: "HC-040".into(),
                name: "SMBv1 disabled".into(),
                description: "SMBv1 protocol should be disabled due to known vulnerabilities (EternalBlue)".into(),
                category: HardeningCategory::NetworkSecurity,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".into(),
                    value: "SMB1".into(),
                    expected: "0".into(),
                },
            },
            HardeningCheck {
                id: "HC-041".into(),
                name: "NetBIOS over TCP/IP disabled".into(),
                description: "NetBIOS over TCP/IP should be disabled to reduce network attack surface".into(),
                category: HardeningCategory::NetworkSecurity,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces".into(),
                    value: "NetbiosOptions".into(),
                    expected: "2".into(),
                },
            },
            HardeningCheck {
                id: "HC-042".into(),
                name: "LLMNR disabled".into(),
                description: "Link-Local Multicast Name Resolution should be disabled to prevent poisoning attacks".into(),
                category: HardeningCategory::NetworkSecurity,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient".into(),
                    value: "EnableMulticast".into(),
                    expected: "0".into(),
                },
            },
            HardeningCheck {
                id: "HC-043".into(),
                name: "WPAD disabled".into(),
                description: "Web Proxy Auto-Discovery should be disabled to prevent proxy auto-config attacks".into(),
                category: HardeningCategory::NetworkSecurity,
                severity: EventSeverity::Medium,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad".into(),
                    value: "WpadOverride".into(),
                    expected: "1".into(),
                },
            },

            // Windows Defender
            HardeningCheck {
                id: "HC-050".into(),
                name: "Real-time protection enabled".into(),
                description: "Windows Defender real-time protection should be enabled for continuous malware detection".into(),
                category: HardeningCategory::WindowsDefender,
                severity: EventSeverity::Critical,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection".into(),
                    value: "DisableRealtimeMonitoring".into(),
                    expected: "0".into(),
                },
            },
            HardeningCheck {
                id: "HC-051".into(),
                name: "Cloud protection enabled".into(),
                description: "Windows Defender cloud-delivered protection should be enabled for enhanced threat detection".into(),
                category: HardeningCategory::WindowsDefender,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet".into(),
                    value: "SpyNetReporting".into(),
                    expected: "1".into(),
                },
            },
            HardeningCheck {
                id: "HC-052".into(),
                name: "Signature updates within 24 hours".into(),
                description: "Windows Defender signatures should be updated within the last 24 hours".into(),
                category: HardeningCategory::WindowsDefender,
                severity: EventSeverity::High,
                enabled: true,
                check_type: CheckType::RegistryCheck {
                    key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates".into(),
                    value: "SignatureUpdateInterval".into(),
                    expected: "8".into(),
                },
            },
        ]
    }
}

impl Default for HardeningAuditor {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_registry_key_from_remediation(remediation: &str) -> Option<String> {
    if remediation.contains("registry value") || remediation.contains("Set registry") {
        // Try to extract key from "Set registry value KEY\VALUE to VALUE"
        let parts: Vec<&str> = remediation.split("registry value ").collect();
        if parts.len() > 1 {
            let key_part = parts[1];
            if let Some(slash_pos) = key_part.rfind('\\') {
                return Some(key_part[..slash_pos].to_string());
            }
        }
    }
    None
}

fn extract_registry_value_from_remediation(remediation: &str) -> Option<String> {
    if remediation.contains("registry value") || remediation.contains("Set registry") {
        let parts: Vec<&str> = remediation.split("registry value ").collect();
        if parts.len() > 1 {
            let key_part = parts[1];
            if let Some(slash_pos) = key_part.rfind('\\') {
                let remainder = &key_part[slash_pos + 1..];
                if let Some(space_pos) = remainder.find(' ') {
                    return Some(remainder[..space_pos].to_string());
                }
            }
        }
    }
    None
}

fn extract_service_name_from_remediation(remediation: &str) -> Option<String> {
    if remediation.starts_with("Configure service ") {
        let parts: Vec<&str> = remediation.split_whitespace().collect();
        if parts.len() >= 3 {
            return Some(parts[2].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_check(id: &str, category: HardeningCategory, severity: EventSeverity, check_type: CheckType) -> HardeningCheck {
        HardeningCheck {
            id: id.into(),
            name: format!("Check {}", id),
            description: format!("Description for {}", id),
            category,
            severity,
            enabled: true,
            check_type,
        }
    }

    fn make_registry_check(id: &str, key: &str, value: &str, expected: &str, severity: EventSeverity) -> HardeningCheck {
        make_check(
            id,
            HardeningCategory::SecurityOptions,
            severity,
            CheckType::RegistryCheck {
                key: key.into(),
                value: value.into(),
                expected: expected.into(),
            },
        )
    }

    fn make_service_check(id: &str, name: &str, expected_status: &str, severity: EventSeverity) -> HardeningCheck {
        make_check(
            id,
            HardeningCategory::ServiceConfig,
            severity,
            CheckType::ServiceCheck {
                name: name.into(),
                expected_status: expected_status.into(),
                expected_start: None,
            },
        )
    }

    #[test]
    fn test_hardening_auditor_new_has_default_checks() {
        let auditor = HardeningAuditor::new();
        assert!(auditor.checks.len() >= 24, "Expected at least 24 default checks, got {}", auditor.checks.len());
        assert_eq!(auditor.compliance_score, 0.0);
        assert!(auditor.results.is_empty());
    }

    #[test]
    fn test_calculate_compliance_score_all_pass() {
        let results = vec![
            HardeningResult {
                check_id: "HC-001".into(),
                check_name: "Test".into(),
                passed: true,
                severity: EventSeverity::Critical,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
            HardeningResult {
                check_id: "HC-002".into(),
                check_name: "Test2".into(),
                passed: true,
                severity: EventSeverity::High,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
        ];
        let score = HardeningAuditor::calculate_compliance_score(&results);
        assert!((score - 100.0).abs() < f64::EPSILON, "All pass should yield 100.0, got {}", score);
    }

    #[test]
    fn test_calculate_compliance_score_all_fail() {
        let results = vec![
            HardeningResult {
                check_id: "HC-001".into(),
                check_name: "Test".into(),
                passed: false,
                severity: EventSeverity::Critical,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
            HardeningResult {
                check_id: "HC-002".into(),
                check_name: "Test2".into(),
                passed: false,
                severity: EventSeverity::High,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
        ];
        let score = HardeningAuditor::calculate_compliance_score(&results);
        assert!((score - 0.0).abs() < f64::EPSILON, "All fail should yield 0.0, got {}", score);
    }

    #[test]
    fn test_run_audit_compliant_state() {
        let mut auditor = HardeningAuditor::new();

        let mut registry: HashMap<String, String> = HashMap::new();
        // HC-001: NoLMHash
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash".into(), "1".into());
        // HC-020: ConsentPromptBehaviorAdmin
        registry.insert("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin".into(), "2".into());
        // HC-040: SMBv1
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1".into(), "0".into());
        // HC-042: LLMNR
        registry.insert("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast".into(), "0".into());
        // HC-050: DisableRealtimeMonitoring
        registry.insert("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring".into(), "0".into());
        // Audit policies
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects".into(), "1".into());
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy".into(), "1".into());

        let mut services: HashMap<String, ServiceState> = HashMap::new();
        services.insert("MpsSvc".into(), ServiceState { status: "Running".into(), start_type: "Automatic".into(), image_path: None });
        services.insert("wuauserv".into(), ServiceState { status: "Running".into(), start_type: "Automatic".into(), image_path: None });
        services.insert("RemoteRegistry".into(), ServiceState { status: "Stopped".into(), start_type: "Disabled".into(), image_path: None });
        services.insert("TlntSvr".into(), ServiceState { status: "Stopped".into(), start_type: "Disabled".into(), image_path: None });
        services.insert("SNMP".into(), ServiceState { status: "Stopped".into(), start_type: "Disabled".into(), image_path: None });

        let results = auditor.run_audit(&registry, &services);
        let pass_count = results.iter().filter(|r| r.passed).count();
        assert!(pass_count > 0, "Expected some checks to pass with compliant state");
        assert!(auditor.compliance_score() > 0.0, "Compliance score should be > 0");
    }

    #[test]
    fn test_run_audit_non_compliant_state() {
        let mut auditor = HardeningAuditor::new();

        let registry: HashMap<String, String> = HashMap::new();
        let services: HashMap<String, ServiceState> = HashMap::new();

        let results = auditor.run_audit(&registry, &services);
        let fail_count = results.iter().filter(|r| !r.passed).count();
        assert!(fail_count > 0, "Expected some checks to fail with empty state");
    }

    #[test]
    fn test_get_remediation_generates_actions() {
        let results = vec![
            HardeningResult {
                check_id: "HC-030".into(),
                check_name: "Firewall check".into(),
                passed: false,
                severity: EventSeverity::Critical,
                current_value: Some("Stopped".into()),
                expected_value: Some("Running".into()),
                remediation: "Configure service MpsSvc to Running (currently: Stopped)".into(),
                timestamp: Utc::now(),
            },
            HardeningResult {
                check_id: "HC-033".into(),
                check_name: "Telnet check".into(),
                passed: false,
                severity: EventSeverity::Critical,
                current_value: Some("Running".into()),
                expected_value: Some("Stopped".into()),
                remediation: "Configure service TlntSvr to Stopped (currently: Running)".into(),
                timestamp: Utc::now(),
            },
            HardeningResult {
                check_id: "HC-040".into(),
                check_name: "SMBv1 check".into(),
                passed: true,
                severity: EventSeverity::Critical,
                current_value: Some("0".into()),
                expected_value: Some("0".into()),
                remediation: String::new(),
                timestamp: Utc::now(),
            },
        ];

        let actions = HardeningAuditor::get_remediation(&results);
        assert_eq!(actions.len(), 2, "Should generate 2 remediation actions for 2 failed checks");
        assert_eq!(actions[0].check_id, "HC-030");
        assert_eq!(actions[1].check_id, "HC-033");
        assert!(!actions[0].description.is_empty());
        assert!(!actions[1].description.is_empty());
    }

    #[test]
    fn test_assess_registry_check_pass() {
        let auditor = HardeningAuditor::new();
        let check = make_registry_check("HC-TEST", "HKLM\\SOFTWARE\\Test", "Value", "1", EventSeverity::High);

        let mut registry: HashMap<String, String> = HashMap::new();
        registry.insert("HKLM\\SOFTWARE\\Test\\Value".into(), "1".into());

        let result = auditor.assess_registry_check(&check, &registry);
        assert!(result.passed);
        assert_eq!(result.current_value.as_deref(), Some("1"));
        assert_eq!(result.expected_value.as_deref(), Some("1"));
        assert!(result.remediation.is_empty());
    }

    #[test]
    fn test_assess_registry_check_fail() {
        let auditor = HardeningAuditor::new();
        let check = make_registry_check("HC-TEST", "HKLM\\SOFTWARE\\Test", "Value", "1", EventSeverity::High);

        let mut registry: HashMap<String, String> = HashMap::new();
        registry.insert("HKLM\\SOFTWARE\\Test\\Value".into(), "0".into());

        let result = auditor.assess_registry_check(&check, &registry);
        assert!(!result.passed);
        assert_eq!(result.current_value.as_deref(), Some("0"));
        assert!(!result.remediation.is_empty());
    }

    #[test]
    fn test_assess_service_check_pass() {
        let auditor = HardeningAuditor::new();
        let check = make_service_check("HC-TEST", "MpsSvc", "Running", EventSeverity::Critical);

        let mut services: HashMap<String, ServiceState> = HashMap::new();
        services.insert("MpsSvc".into(), ServiceState {
            status: "Running".into(),
            start_type: "Automatic".into(),
            image_path: None,
        });

        let result = auditor.assess_service_check(&check, &services);
        assert!(result.passed);
    }

    #[test]
    fn test_assess_service_check_fail() {
        let auditor = HardeningAuditor::new();
        let check = make_service_check("HC-TEST", "MpsSvc", "Running", EventSeverity::Critical);

        let mut services: HashMap<String, ServiceState> = HashMap::new();
        services.insert("MpsSvc".into(), ServiceState {
            status: "Stopped".into(),
            start_type: "Disabled".into(),
            image_path: None,
        });

        let result = auditor.assess_service_check(&check, &services);
        assert!(!result.passed);
    }

    #[test]
    fn test_add_check_and_remove_check() {
        let mut auditor = HardeningAuditor::new();
        let initial_count = auditor.checks.len();

        let new_check = make_check(
            "HC-999",
            HardeningCategory::ApplicationControl,
            EventSeverity::Low,
            CheckType::PolicyCheck {
                policy_name: "TestPolicy".into(),
                expected_value: "1".into(),
            },
        );

        auditor.add_check(new_check);
        assert_eq!(auditor.checks.len(), initial_count + 1);
        assert!(auditor.checks.iter().any(|c| c.id == "HC-999"));

        auditor.remove_check("HC-999");
        assert_eq!(auditor.checks.len(), initial_count);
        assert!(!auditor.checks.iter().any(|c| c.id == "HC-999"));

        // Removing non-existent check should not panic
        auditor.remove_check("HC-NONEXISTENT");
        assert_eq!(auditor.checks.len(), initial_count);
    }

    #[test]
    fn test_check_single() {
        let auditor = HardeningAuditor::new();
        let mut registry: HashMap<String, String> = HashMap::new();
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash".into(), "1".into());

        let state = SystemState {
            registry,
            services: HashMap::new(),
            hostname: "TEST-HOST".into(),
            os_version: "Windows 11".into(),
        };

        let result = auditor.check_single("HC-001", &state);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.check_id, "HC-001");
        assert!(r.passed);

        let missing = auditor.check_single("HC-NONEXISTENT", &state);
        assert!(missing.is_none());
    }

    #[test]
    fn test_check_single_service() {
        let auditor = HardeningAuditor::new();
        let mut services: HashMap<String, ServiceState> = HashMap::new();
        services.insert("TlntSvr".into(), ServiceState {
            status: "Stopped".into(),
            start_type: "Disabled".into(),
            image_path: None,
        });

        let state = SystemState {
            registry: HashMap::new(),
            services,
            hostname: "TEST-HOST".into(),
            os_version: "Windows 11".into(),
        };

        let result = auditor.check_single("HC-033", &state);
        assert!(result.is_some());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_calculate_compliance_score_empty() {
        let score = HardeningAuditor::calculate_compliance_score(&[]);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_compliance_score_weighted() {
        let results = vec![
            HardeningResult {
                check_id: "HC-001".into(),
                check_name: "Critical pass".into(),
                passed: true,
                severity: EventSeverity::Critical,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
            HardeningResult {
                check_id: "HC-002".into(),
                check_name: "Low fail".into(),
                passed: false,
                severity: EventSeverity::Low,
                current_value: None,
                expected_value: None,
                remediation: String::new(),
                timestamp: Utc::now(),
            },
        ];
        // Critical=4, Low=1; total=5, passed=4; score = (4/5)*100 = 80.0
        let score = HardeningAuditor::calculate_compliance_score(&results);
        assert!((score - 80.0).abs() < f64::EPSILON, "Expected 80.0, got {}", score);
    }

    #[test]
    fn test_with_config() {
        let config = HardeningConfig {
            standard: ComplianceStandard::DISA_STIG,
            auto_remediate: true,
            excluded_checks: vec!["HC-033".into()],
            severity_filter: Some(EventSeverity::Medium),
        };
        let auditor = HardeningAuditor::with_config(config);
        assert_eq!(auditor.config.standard, ComplianceStandard::DISA_STIG);
        assert!(auditor.config.auto_remediate);
        assert_eq!(auditor.config.excluded_checks.len(), 1);
        assert_eq!(auditor.config.severity_filter, Some(EventSeverity::Medium));
    }

    #[test]
    fn test_composite_check() {
        let mut auditor = HardeningAuditor::new();

        // Add sub-checks that pass
        let mut registry: HashMap<String, String> = HashMap::new();
        registry.insert("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash".into(), "1".into());
        registry.insert("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin".into(), "2".into());

        let mut services: HashMap<String, ServiceState> = HashMap::new();
        services.insert("MpsSvc".into(), ServiceState { status: "Running".into(), start_type: "Automatic".into(), image_path: None });

        // Add a composite check that references sub-checks
        auditor.add_check(HardeningCheck {
            id: "HC-COMPOSITE".into(),
            name: "Composite test".into(),
            description: "Composite check".into(),
            category: HardeningCategory::ApplicationControl,
            severity: EventSeverity::Low,
            enabled: true,
            check_type: CheckType::CompositeCheck {
                sub_checks: vec!["HC-001".into(), "HC-020".into()],
            },
        });

        let results = auditor.run_audit(&registry, &services);
        let composite = results.iter().find(|r| r.check_id == "HC-COMPOSITE");
        assert!(composite.is_some(), "Composite check should appear in results");
        assert!(composite.unwrap().passed, "Composite should pass when sub-checks pass");

        // Now test with a failing composite
        let mut auditor2 = HardeningAuditor::new();
        auditor2.add_check(HardeningCheck {
            id: "HC-COMPOSITE-FAIL".into(),
            name: "Composite fail".into(),
            description: "Composite check that references non-existent sub-checks".into(),
            category: HardeningCategory::ApplicationControl,
            severity: EventSeverity::Low,
            enabled: true,
            check_type: CheckType::CompositeCheck {
                sub_checks: vec!["HC-NONEXISTENT".into()],
            },
        });
        let results2 = auditor2.run_audit(&HashMap::new(), &HashMap::new());
        let composite_fail = results2.iter().find(|r| r.check_id == "HC-COMPOSITE-FAIL");
        assert!(composite_fail.is_some());
        assert!(!composite_fail.unwrap().passed, "Composite should fail when sub-checks fail");
    }

    #[test]
    fn test_assess_registry_check_missing_value() {
        let auditor = HardeningAuditor::new();
        let check = make_registry_check("HC-TEST", "HKLM\\SOFTWARE\\Test", "Missing", "1", EventSeverity::High);
        let registry: HashMap<String, String> = HashMap::new();

        let result = auditor.assess_registry_check(&check, &registry);
        assert!(!result.passed);
        assert!(result.current_value.is_none());
    }

    #[test]
    fn test_assess_service_check_missing_service() {
        let auditor = HardeningAuditor::new();
        let check = make_service_check("HC-TEST", "NonExistentSvc", "Running", EventSeverity::High);
        let services: HashMap<String, ServiceState> = HashMap::new();

        let result = auditor.assess_service_check(&check, &services);
        assert!(!result.passed);
        assert_eq!(result.current_value.as_deref(), Some("Service not found"));
    }

    #[test]
    fn test_assess_service_check_missing_service_expects_stopped() {
        let auditor = HardeningAuditor::new();
        let check = make_service_check("HC-TEST", "NonExistentSvc", "Stopped", EventSeverity::High);
        let services: HashMap<String, ServiceState> = HashMap::new();

        let result = auditor.assess_service_check(&check, &services);
        assert!(result.passed, "Missing service that is expected to be stopped should pass");
    }

    #[test]
    fn test_results_accessor() {
        let mut auditor = HardeningAuditor::new();
        assert!(auditor.results().is_empty());

        let registry: HashMap<String, String> = HashMap::new();
        let services: HashMap<String, ServiceState> = HashMap::new();
        auditor.run_audit(&registry, &services);

        assert!(!auditor.results().is_empty());
    }

    #[test]
    fn test_severity_filter_excludes_checks() {
        let config = HardeningConfig {
            severity_filter: Some(EventSeverity::Critical),
            ..Default::default()
        };
        let mut auditor = HardeningAuditor::with_config(config);

        let registry: HashMap<String, String> = HashMap::new();
        let services: HashMap<String, ServiceState> = HashMap::new();
        let results = auditor.run_audit(&registry, &services);

        for r in &results {
            assert_eq!(r.severity, EventSeverity::Critical, "Only Critical checks should be in results");
        }
    }

    #[test]
    fn test_excluded_checks() {
        let config = HardeningConfig {
            excluded_checks: vec!["HC-001".into(), "HC-002".into()],
            ..Default::default()
        };
        let mut auditor = HardeningAuditor::with_config(config);

        let registry: HashMap<String, String> = HashMap::new();
        let services: HashMap<String, ServiceState> = HashMap::new();
        let results = auditor.run_audit(&registry, &services);

        assert!(!results.iter().any(|r| r.check_id == "HC-001"), "HC-001 should be excluded");
        assert!(!results.iter().any(|r| r.check_id == "HC-002"), "HC-002 should be excluded");
    }

    #[test]
    fn test_default_config() {
        let config = HardeningConfig::default();
        assert_eq!(config.standard, ComplianceStandard::CIS);
        assert!(!config.auto_remediate);
        assert!(config.excluded_checks.is_empty());
        assert!(config.severity_filter.is_none());
    }
}
