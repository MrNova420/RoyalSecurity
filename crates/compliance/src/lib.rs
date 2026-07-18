pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlCheckType {
    RegistryCheck {
        key: String,
        value: String,
        expected: String,
    },
    ServiceCheck {
        name: String,
        expected_status: String,
    },
    PolicyCheck {
        policy: String,
        expected: String,
    },
    FileCheck {
        path: String,
        must_exist: bool,
    },
    UserCheck {
        setting: String,
        expected: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: EventSeverity,
    pub check_type: ControlCheckType,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCategory {
    pub id: String,
    pub name: String,
    pub description: String,
    pub controls: Vec<ComplianceControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub categories: Vec<ComplianceCategory>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub control_id: String,
    pub framework_id: String,
    pub passed: bool,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
    pub severity: EventSeverity,
    pub remediation: String,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework_id: String,
    pub framework_name: String,
    pub total_controls: u32,
    pub passed: u32,
    pub failed: u32,
    pub score: f64,
    pub results: Vec<ComplianceResult>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanInput {
    pub registry: HashMap<String, String>,
    pub services: HashMap<String, (String, String)>,
    pub installed_software: Vec<String>,
}

pub struct ComplianceEngine {
    frameworks: Vec<ComplianceFramework>,
    last_scan: Option<DateTime<Utc>>,
    scan_results: Vec<ComplianceResult>,
    overall_score: f64,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            frameworks: Vec::new(),
            last_scan: None,
            scan_results: Vec::new(),
            overall_score: 0.0,
        };
        engine.load_default_frameworks();
        engine
    }

    pub fn scan(&mut self, input: &ScanInput) -> Vec<ComplianceResult> {
        let mut results = Vec::new();
        let framework_ids: Vec<String> = self.frameworks.iter().map(|f| f.id.clone()).collect();
        for fid in &framework_ids {
            let mut fw_results = self.scan_framework(fid, input);
            results.append(&mut fw_results);
        }
        self.scan_results = results.clone();
        self.last_scan = Some(Utc::now());
        self.overall_score = self.compute_overall_score(&results);
        info!(
            "Compliance scan completed: {} controls checked, score: {:.1}%",
            results.len(),
            self.overall_score
        );
        results
    }

    pub fn scan_framework(
        &mut self,
        framework_id: &str,
        input: &ScanInput,
    ) -> Vec<ComplianceResult> {
        let framework = match self.frameworks.iter().find(|f| f.id == framework_id) {
            Some(fw) => fw,
            None => {
                warn!("Framework '{}' not found", framework_id);
                return Vec::new();
            }
        };

        if !framework.enabled {
            warn!("Framework '{}' is disabled", framework_id);
            return Vec::new();
        }

        let mut results = Vec::new();
        for category in &framework.categories {
            for control in &category.controls {
                let result = self.check_control(control, &framework.id, input);
                results.push(result);
            }
        }

        info!(
            "Scanned framework '{}': {} controls",
            framework_id,
            results.len()
        );

        for r in &results {
            if let Some(existing) = self
                .scan_results
                .iter_mut()
                .find(|s| s.control_id == r.control_id && s.framework_id == r.framework_id)
            {
                *existing = r.clone();
            } else {
                self.scan_results.push(r.clone());
            }
        }
        self.last_scan = Some(Utc::now());
        self.overall_score = self.compute_overall_score(&self.scan_results);

        results
    }

    pub fn check_control(
        &self,
        control: &ComplianceControl,
        framework_id: &str,
        input: &ScanInput,
    ) -> ComplianceResult {
        let (passed, current_value, expected_value) = match &control.check_type {
            ControlCheckType::RegistryCheck {
                key,
                value: _,
                expected,
            } => {
                let current = input.registry.get(key).cloned();
                let pass = current.as_deref() == Some(expected.as_str());
                (
                    pass,
                    current,
                    Some(expected.clone()),
                )
            }
            ControlCheckType::ServiceCheck {
                name,
                expected_status,
            } => {
                let current = input
                    .services
                    .get(name)
                    .map(|(status, _)| status.clone());
                let pass = current.as_deref() == Some(expected_status.as_str());
                (
                    pass,
                    current,
                    Some(expected_status.clone()),
                )
            }
            ControlCheckType::PolicyCheck { policy, expected } => {
                let found = input
                    .installed_software
                    .iter()
                    .any(|sw| sw.to_lowercase().contains(&policy.to_lowercase()));
                let current = if found {
                    Some("installed".to_string())
                } else {
                    Some("not_installed".to_string())
                };
                (
                    found && expected.to_lowercase() == "installed",
                    current,
                    Some(expected.clone()),
                )
            }
            ControlCheckType::FileCheck { path, must_exist } => {
                let found = input
                    .installed_software
                    .iter()
                    .any(|sw| sw.to_lowercase().contains(&path.to_lowercase()));
                let pass = if *must_exist { found } else { !found };
                (
                    pass,
                    Some(if found { "present".to_string() } else { "absent".to_string() }),
                    Some(if *must_exist {
                        "present".to_string()
                    } else {
                        "absent".to_string()
                    }),
                )
            }
            ControlCheckType::UserCheck { setting, expected } => {
                let current = input
                    .registry
                    .get(setting)
                    .cloned()
                    .or_else(|| {
                        input
                            .installed_software
                            .iter()
                            .find(|sw| sw.to_lowercase().contains(&setting.to_lowercase()))
                            .cloned()
                    });
                let pass = current.as_deref() == Some(expected.as_str());
                (
                    pass,
                    current,
                    Some(expected.clone()),
                )
            }
        };

        ComplianceResult {
            control_id: control.id.clone(),
            framework_id: framework_id.to_string(),
            passed,
            current_value,
            expected_value,
            severity: control.severity.clone(),
            remediation: control.remediation.clone(),
            checked_at: Utc::now(),
        }
    }

    pub fn generate_report(&self, framework_id: &str) -> Option<ComplianceReport> {
        let framework = self.frameworks.iter().find(|f| f.id == framework_id)?;
        let results: Vec<ComplianceResult> = self
            .scan_results
            .iter()
            .filter(|r| r.framework_id == framework_id)
            .cloned()
            .collect();

        let total = results.len() as u32;
        let passed = results.iter().filter(|r| r.passed).count() as u32;
        let failed = total - passed;
        let score = if total > 0 {
            (passed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Some(ComplianceReport {
            framework_id: framework.id.clone(),
            framework_name: framework.name.clone(),
            total_controls: total,
            passed,
            failed,
            score,
            results,
            generated_at: Utc::now(),
        })
    }

    pub fn add_framework(&mut self, framework: ComplianceFramework) {
        self.frameworks.push(framework);
    }

    pub fn frameworks(&self) -> &[ComplianceFramework] {
        &self.frameworks
    }

    pub fn frameworks_mut(&mut self) -> &mut Vec<ComplianceFramework> {
        &mut self.frameworks
    }

    pub fn overall_score(&self) -> f64 {
        self.overall_score
    }

    pub fn last_scan(&self) -> Option<DateTime<Utc>> {
        self.last_scan
    }

    pub fn get_failed_controls(&self, framework_id: &str) -> Vec<&ComplianceControl> {
        let failed_ids: Vec<&str> = self
            .scan_results
            .iter()
            .filter(|r| r.framework_id == framework_id && !r.passed)
            .map(|r| r.control_id.as_str())
            .collect();

        let mut controls = Vec::new();
        for framework in &self.frameworks {
            if framework.id != framework_id {
                continue;
            }
            for category in &framework.categories {
                for control in &category.controls {
                    if failed_ids.contains(&control.id.as_str()) {
                        controls.push(control);
                    }
                }
            }
        }
        controls
    }

    fn compute_overall_score(&self, results: &[ComplianceResult]) -> f64 {
        if results.is_empty() {
            return 0.0;
        }
        let passed = results.iter().filter(|r| r.passed).count() as f64;
        (passed / results.len() as f64) * 100.0
    }

    fn load_default_frameworks(&mut self) {
        self.frameworks.push(default_cis_windows10());
        self.frameworks.push(default_disa_stig_windows10());
        self.frameworks.push(default_nist_800_53());
    }
}

fn default_cis_windows10() -> ComplianceFramework {
    ComplianceFramework {
        id: "CIS-WIN10-1.0.0".to_string(),
        name: "CIS Windows 10 Benchmark".to_string(),
        version: "1.0.0".to_string(),
        enabled: true,
        categories: vec![ComplianceCategory {
            id: "CIS-WIN10-CAT1".to_string(),
            name: "Account Policies".to_string(),
            description: "Account and authentication policy controls".to_string(),
            controls: vec![
                ComplianceControl {
                    id: "CIS-1.1.1".to_string(),
                    title: "Enforce password history".to_string(),
                    description: "Ensure password history is set to 24 passwords".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::RegistryCheck {
                        key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MaxPwdHistory".to_string(),
                        value: "24".to_string(),
                        expected: "24".to_string(),
                    },
                    remediation: "Set password history to 24 in Group Policy.".to_string(),
                },
                ComplianceControl {
                    id: "CIS-1.1.2".to_string(),
                    title: "Maximum password age".to_string(),
                    description: "Ensure maximum password age is 60 days or fewer".to_string(),
                    severity: EventSeverity::Medium,
                    check_type: ControlCheckType::RegistryCheck {
                        key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MaxPasswordAge".to_string(),
                        value: "60".to_string(),
                        expected: "60".to_string(),
                    },
                    remediation: "Set maximum password age to 60 days or fewer.".to_string(),
                },
                ComplianceControl {
                    id: "CIS-1.1.3".to_string(),
                    title: "Password minimum length".to_string(),
                    description: "Ensure minimum password length is 14 characters".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::RegistryCheck {
                        key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MinPwdLen".to_string(),
                        value: "14".to_string(),
                        expected: "14".to_string(),
                    },
                    remediation: "Set minimum password length to 14 characters.".to_string(),
                },
                ComplianceControl {
                    id: "CIS-1.1.4".to_string(),
                    title: "Disable guest account".to_string(),
                    description: "Ensure Guest account is disabled".to_string(),
                    severity: EventSeverity::Critical,
                    check_type: ControlCheckType::UserCheck {
                        setting: "GuestAccount".to_string(),
                        expected: "disabled".to_string(),
                    },
                    remediation: "Disable the Guest account via Group Policy or local settings.".to_string(),
                },
                ComplianceControl {
                    id: "CIS-1.1.5".to_string(),
                    title: "Windows Defender real-time protection".to_string(),
                    description: "Ensure Windows Defender real-time protection is enabled".to_string(),
                    severity: EventSeverity::Critical,
                    check_type: ControlCheckType::ServiceCheck {
                        name: "WinDefend".to_string(),
                        expected_status: "Running".to_string(),
                    },
                    remediation: "Enable Windows Defender real-time protection.".to_string(),
                },
            ],
        }],
    }
}

fn default_disa_stig_windows10() -> ComplianceFramework {
    ComplianceFramework {
        id: "DISA-STIG-WIN10".to_string(),
        name: "DISA STIG Windows 10".to_string(),
        version: "V2R1".to_string(),
        enabled: true,
        categories: vec![ComplianceCategory {
            id: "DISA-STIG-CAT1".to_string(),
            name: "V-93000 Series".to_string(),
            description: "STIG controls for Windows 10 system configuration".to_string(),
            controls: vec![
                ComplianceControl {
                    id: "V-93001".to_string(),
                    title: "Local volumes formatted with NTFS".to_string(),
                    description: "All local volumes must be formatted with NTFS".to_string(),
                    severity: EventSeverity::Medium,
                    check_type: ControlCheckType::FileCheck {
                        path: "NTFS".to_string(),
                        must_exist: true,
                    },
                    remediation: "Format all local volumes with NTFS.".to_string(),
                },
                ComplianceControl {
                    id: "V-93002".to_string(),
                    title: "WDAC enforced mode".to_string(),
                    description: "Ensure Windows Defender Application Control is in enforced mode".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::PolicyCheck {
                        policy: "WDAC".to_string(),
                        expected: "installed".to_string(),
                    },
                    remediation: "Enable WDAC in enforced mode via Group Policy.".to_string(),
                },
                ComplianceControl {
                    id: "V-93003".to_string(),
                    title: "Remote Desktop disabled".to_string(),
                    description: "Ensure Remote Desktop is disabled if not needed".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::RegistryCheck {
                        key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections".to_string(),
                        value: "1".to_string(),
                        expected: "1".to_string(),
                    },
                    remediation: "Disable Remote Desktop via Group Policy.".to_string(),
                },
                ComplianceControl {
                    id: "V-93004".to_string(),
                    title: "SMB v1 protocol disabled".to_string(),
                    description: "Ensure SMB v1 protocol is disabled".to_string(),
                    severity: EventSeverity::Critical,
                    check_type: ControlCheckType::ServiceCheck {
                        name: "mrxsmb10".to_string(),
                        expected_status: "Stopped".to_string(),
                    },
                    remediation: "Disable SMB v1 protocol via Windows Features or Group Policy.".to_string(),
                },
                ComplianceControl {
                    id: "V-93005".to_string(),
                    title: "Windows Firewall enabled".to_string(),
                    description: "Ensure Windows Firewall is enabled on all profiles".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::ServiceCheck {
                        name: "MpsSvc".to_string(),
                        expected_status: "Running".to_string(),
                    },
                    remediation: "Enable Windows Firewall on all network profiles.".to_string(),
                },
            ],
        }],
    }
}

fn default_nist_800_53() -> ComplianceFramework {
    ComplianceFramework {
        id: "NIST-800-53".to_string(),
        name: "NIST SP 800-53".to_string(),
        version: "Rev5".to_string(),
        enabled: true,
        categories: vec![ComplianceCategory {
            id: "NIST-CAT-AC".to_string(),
            name: "Access Control".to_string(),
            description: "Access control family requirements".to_string(),
            controls: vec![
                ComplianceControl {
                    id: "AC-2".to_string(),
                    title: "Account management".to_string(),
                    description: "Manage information system accounts including establishing conditions for group membership".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::UserCheck {
                        setting: "AccountManagement".to_string(),
                        expected: "enabled".to_string(),
                    },
                    remediation: "Implement automated account management processes.".to_string(),
                },
                ComplianceControl {
                    id: "AC-6".to_string(),
                    title: "Least privilege".to_string(),
                    description: "Employ the principle of least privilege".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::PolicyCheck {
                        policy: "LeastPrivilege".to_string(),
                        expected: "installed".to_string(),
                    },
                    remediation: "Enforce least privilege through role-based access control.".to_string(),
                },
                ComplianceControl {
                    id: "AC-7".to_string(),
                    title: "Unsuccessful logon attempts".to_string(),
                    description: "Limit consecutive unsuccessful logon attempts".to_string(),
                    severity: EventSeverity::Medium,
                    check_type: ControlCheckType::RegistryCheck {
                        key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LockoutBadCount".to_string(),
                        value: "5".to_string(),
                        expected: "5".to_string(),
                    },
                    remediation: "Configure account lockout threshold to 5 invalid attempts.".to_string(),
                },
                ComplianceControl {
                    id: "AU-6".to_string(),
                    title: "Audit review and reporting".to_string(),
                    description: "Review and analyze information system audit records".to_string(),
                    severity: EventSeverity::Medium,
                    check_type: ControlCheckType::ServiceCheck {
                        name: "EventLog".to_string(),
                        expected_status: "Running".to_string(),
                    },
                    remediation: "Ensure Windows Event Log service is running.".to_string(),
                },
                ComplianceControl {
                    id: "SC-7".to_string(),
                    title: "Boundary protection".to_string(),
                    description: "Monitor and control communications at external boundaries".to_string(),
                    severity: EventSeverity::High,
                    check_type: ControlCheckType::ServiceCheck {
                        name: "MpsSvc".to_string(),
                        expected_status: "Running".to_string(),
                    },
                    remediation: "Enable and configure boundary firewall protection.".to_string(),
                },
            ],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn build_compliant_input() -> ScanInput {
        let mut registry = HashMap::new();
        registry.insert(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MaxPwdHistory".to_string(),
            "24".to_string(),
        );
        registry.insert(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MaxPasswordAge".to_string(),
            "60".to_string(),
        );
        registry.insert(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MinPwdLen".to_string(),
            "14".to_string(),
        );
        registry.insert(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LockoutBadCount".to_string(),
            "5".to_string(),
        );

        let mut services = HashMap::new();
        services.insert(
            "WinDefend".to_string(),
            ("Running".to_string(), "Auto".to_string()),
        );
        services.insert(
            "MpsSvc".to_string(),
            ("Running".to_string(), "Auto".to_string()),
        );
        services.insert(
            "mrxsmb10".to_string(),
            ("Stopped".to_string(), "Manual".to_string()),
        );
        services.insert(
            "EventLog".to_string(),
            ("Running".to_string(), "Auto".to_string()),
        );

        ScanInput {
            registry,
            services,
            installed_software: vec![
                "WDAC Application Guard".to_string(),
                "Microsoft Defender".to_string(),
            ],
        }
    }

    #[test]
    fn test_engine_new_loads_default_frameworks() {
        let engine = ComplianceEngine::new();
        assert_eq!(engine.frameworks().len(), 3);
        assert_eq!(engine.frameworks()[0].id, "CIS-WIN10-1.0.0");
        assert_eq!(engine.frameworks()[1].id, "DISA-STIG-WIN10");
        assert_eq!(engine.frameworks()[2].id, "NIST-800-53");
    }

    #[test]
    fn test_cis_framework_has_5_controls() {
        let engine = ComplianceEngine::new();
        let cis = &engine.frameworks()[0];
        let total: usize = cis.categories.iter().map(|c| c.controls.len()).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_stig_framework_has_5_controls() {
        let engine = ComplianceEngine::new();
        let stig = &engine.frameworks()[1];
        let total: usize = stig.categories.iter().map(|c| c.controls.len()).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_nist_framework_has_5_controls() {
        let engine = ComplianceEngine::new();
        let nist = &engine.frameworks()[2];
        let total: usize = nist.categories.iter().map(|c| c.controls.len()).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_registry_check_pass() {
        let input = build_compliant_input();
        let control = ComplianceControl {
            id: "TEST-REG-PASS".to_string(),
            title: "Test registry pass".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Medium,
            check_type: ControlCheckType::RegistryCheck {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MinPwdLen".to_string(),
                value: "14".to_string(),
                expected: "14".to_string(),
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(result.passed);
        assert_eq!(result.current_value.as_deref(), Some("14"));
        assert_eq!(result.expected_value.as_deref(), Some("14"));
    }

    #[test]
    fn test_registry_check_fail_missing_key() {
        let input = ScanInput::default();
        let control = ComplianceControl {
            id: "TEST-REG-FAIL".to_string(),
            title: "Test registry fail".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::High,
            check_type: ControlCheckType::RegistryCheck {
                key: "HKLM\\NonExistent".to_string(),
                value: "1".to_string(),
                expected: "1".to_string(),
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(!result.passed);
        assert!(result.current_value.is_none());
    }

    #[test]
    fn test_registry_check_fail_wrong_value() {
        let mut registry = HashMap::new();
        registry.insert("HKLM\\SomeKey".to_string(), "wrong".to_string());
        let input = ScanInput {
            registry,
            ..Default::default()
        };
        let control = ComplianceControl {
            id: "TEST-REG-WRONG".to_string(),
            title: "Test wrong value".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Medium,
            check_type: ControlCheckType::RegistryCheck {
                key: "HKLM\\SomeKey".to_string(),
                value: "wrong".to_string(),
                expected: "correct".to_string(),
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(!result.passed);
        assert_eq!(result.current_value.as_deref(), Some("wrong"));
        assert_eq!(result.expected_value.as_deref(), Some("correct"));
    }

    #[test]
    fn test_service_check_pass() {
        let input = build_compliant_input();
        let control = ComplianceControl {
            id: "TEST-SVC-PASS".to_string(),
            title: "Test service pass".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::High,
            check_type: ControlCheckType::ServiceCheck {
                name: "WinDefend".to_string(),
                expected_status: "Running".to_string(),
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(result.passed);
        assert_eq!(result.current_value.as_deref(), Some("Running"));
    }

    #[test]
    fn test_service_check_fail() {
        let mut services = HashMap::new();
        services.insert(
            "WinDefend".to_string(),
            ("Stopped".to_string(), "Manual".to_string()),
        );
        let input = ScanInput {
            services,
            ..Default::default()
        };
        let control = ComplianceControl {
            id: "TEST-SVC-FAIL".to_string(),
            title: "Test service fail".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Critical,
            check_type: ControlCheckType::ServiceCheck {
                name: "WinDefend".to_string(),
                expected_status: "Running".to_string(),
            },
            remediation: "Enable the service.".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(!result.passed);
        assert_eq!(result.current_value.as_deref(), Some("Stopped"));
    }

    #[test]
    fn test_policy_check_pass() {
        let input = build_compliant_input();
        let control = ComplianceControl {
            id: "TEST-POL-PASS".to_string(),
            title: "Test policy pass".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Medium,
            check_type: ControlCheckType::PolicyCheck {
                policy: "WDAC".to_string(),
                expected: "installed".to_string(),
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(result.passed);
    }

    #[test]
    fn test_policy_check_fail_not_installed() {
        let input = ScanInput::default();
        let control = ComplianceControl {
            id: "TEST-POL-FAIL".to_string(),
            title: "Test policy fail".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::High,
            check_type: ControlCheckType::PolicyCheck {
                policy: "WDAC".to_string(),
                expected: "installed".to_string(),
            },
            remediation: "Install required policy.".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(!result.passed);
    }

    #[test]
    fn test_file_check_exists_pass() {
        let input = build_compliant_input();
        let control = ComplianceControl {
            id: "TEST-FILE-PASS".to_string(),
            title: "Test file pass".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Low,
            check_type: ControlCheckType::FileCheck {
                path: "Defender".to_string(),
                must_exist: true,
            },
            remediation: "fix".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(result.passed);
    }

    #[test]
    fn test_user_check_pass() {
        let input = build_compliant_input();
        let mut user_registry = input.registry.clone();
        user_registry.insert("GuestAccount".to_string(), "disabled".to_string());
        let input = ScanInput {
            registry: user_registry,
            ..input
        };
        let control = ComplianceControl {
            id: "TEST-USER-PASS".to_string(),
            title: "Test user check pass".to_string(),
            description: "desc".to_string(),
            severity: EventSeverity::Critical,
            check_type: ControlCheckType::UserCheck {
                setting: "GuestAccount".to_string(),
                expected: "disabled".to_string(),
            },
            remediation: "Disable guest account.".to_string(),
        };
        let engine = ComplianceEngine::new();
        let result = engine.check_control(&control, "TEST", &input);
        assert!(result.passed);
    }

    #[test]
    fn test_scan_produces_results_for_all_frameworks() {
        let input = build_compliant_input();
        let mut engine = ComplianceEngine::new();
        let results = engine.scan(&input);
        assert_eq!(results.len(), 15);
        assert!(engine.last_scan().is_some());
        assert!(engine.overall_score() > 0.0);
    }

    #[test]
    fn test_scan_framework_unknown_returns_empty() {
        let input = build_compliant_input();
        let mut engine = ComplianceEngine::new();
        let results = engine.scan_framework("NONEXISTENT", &input);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_framework_disabled_returns_empty() {
        let input = ScanInput::default();
        let mut engine = ComplianceEngine::new();
        engine.frameworks_mut()[0].enabled = false;
        let results = engine.scan_framework("CIS-WIN10-1.0.0", &input);
        assert!(results.is_empty());
        engine.frameworks_mut()[0].enabled = true;
    }

    #[test]
    fn test_generate_report() {
        let input = build_compliant_input();
        let mut engine = ComplianceEngine::new();
        engine.scan(&input);
        let report = engine.generate_report("CIS-WIN10-1.0.0");
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.framework_id, "CIS-WIN10-1.0.0");
        assert_eq!(report.total_controls, 5);
        assert!(report.score > 0.0);
    }

    #[test]
    fn test_generate_report_no_scan() {
        let engine = ComplianceEngine::new();
        let report = engine.generate_report("CIS-WIN10-1.0.0");
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.total_controls, 0);
        assert_eq!(report.score, 0.0);
    }

    #[test]
    fn test_get_failed_controls() {
        let registry = HashMap::new();
        let input = ScanInput {
            registry,
            ..Default::default()
        };
        let mut engine = ComplianceEngine::new();
        engine.scan_framework("CIS-WIN10-1.0.0", &input);
        let failed = engine.get_failed_controls("CIS-WIN10-1.0.0");
        assert!(!failed.is_empty());
    }

    #[test]
    fn test_get_failed_controls_framework_not_found() {
        let engine = ComplianceEngine::new();
        let failed = engine.get_failed_controls("NONEXISTENT");
        assert!(failed.is_empty());
    }

    #[test]
    fn test_add_framework() {
        let mut engine = ComplianceEngine::new();
        let initial = engine.frameworks().len();
        engine.add_framework(ComplianceFramework {
            id: "CUSTOM".to_string(),
            name: "Custom Framework".to_string(),
            version: "1.0".to_string(),
            categories: Vec::new(),
            enabled: true,
        });
        assert_eq!(engine.frameworks().len(), initial + 1);
        assert_eq!(engine.frameworks().last().unwrap().id, "CUSTOM");
    }

    #[test]
    fn test_compliance_result_serialization() {
        let result = ComplianceResult {
            control_id: "T1".to_string(),
            framework_id: "F1".to_string(),
            passed: true,
            current_value: Some("ok".to_string()),
            expected_value: Some("ok".to_string()),
            severity: EventSeverity::Medium,
            remediation: "fix".to_string(),
            checked_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ComplianceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.control_id, deserialized.control_id);
        assert_eq!(result.passed, deserialized.passed);
    }

    #[test]
    fn test_overall_score_calculation() {
        let input = build_compliant_input();
        let mut engine = ComplianceEngine::new();
        engine.scan(&input);
        let score = engine.overall_score();
        assert!(score >= 0.0 && score <= 100.0);
    }
}
