use royalsecurity_common::types::*;
use tracing::warn;

pub struct CredentialProtector {
    protected_processes: Vec<String>,
    lsass_monitoring: bool,
    alert_count: u64,
    suspicious_access: Vec<LsassAccessAttempt>,
}

#[derive(Debug, Clone)]
pub struct LsassAccessAttempt {
    pub source_pid: u32,
    pub source_name: String,
    pub source_user: String,
    pub access_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct CredentialAlert {
    pub severity: EventSeverity,
    pub alert_type: String,
    pub details: String,
    pub mitre_technique: String,
}

impl CredentialProtector {
    pub fn new() -> Self {
        Self {
            protected_processes: vec![
                "lsass.exe".into(),
                "csrss.exe".into(),
                "winlogon.exe".into(),
                "services.exe".into(),
                "svchost.exe".into(),
            ],
            lsass_monitoring: true,
            alert_count: 0,
            suspicious_access: Vec::new(),
        }
    }

    pub fn check_process_access(&mut self, source_pid: u32, source_name: &str, source_user: &str, target_process: &str, access_rights: &str) -> Option<CredentialAlert> {
        if !self.lsass_monitoring {
            return None;
        }

        let target_lower = target_process.to_lowercase();

        if target_lower.contains("lsass") {
            let suspicious_rights = ["PROCESS_VM_READ", "PROCESS_QUERY_INFORMATION", "PROCESS_DUP_HANDLE", "0x0010", "0x0400", "0x0040"];
            let is_suspicious = suspicious_rights.iter().any(|r| access_rights.contains(r));

            if is_suspicious {
                let attempt = LsassAccessAttempt {
                    source_pid: source_pid,
                    source_name: source_name.to_string(),
                    source_user: source_user.to_string(),
                    access_type: access_rights.to_string(),
                    timestamp: chrono::Utc::now(),
                    blocked: true,
                };

                self.suspicious_access.push(attempt);
                self.alert_count += 1;

                warn!(
                    source = source_name,
                    pid = source_pid,
                    user = source_user,
                    access = access_rights,
                    "Suspicious LSASS access attempt blocked"
                );

                return Some(CredentialAlert {
                    severity: EventSeverity::Critical,
                    alert_type: "LSASS Access Attempt".into(),
                    details: format!(
                        "PID {} ({}) running as {} attempted {} access to LSASS. Blocked.",
                        source_pid, source_name, source_user, access_rights
                    ),
                    mitre_technique: "T1003".into(),
                });
            }
        }

        if self.protected_processes.iter().any(|p| target_lower.contains(&p.to_lowercase())) && source_user.to_uppercase() != "SYSTEM" {
            self.alert_count += 1;
            return Some(CredentialAlert {
                severity: EventSeverity::High,
                alert_type: "Protected Process Access".into(),
                details: format!(
                    "Non-SYSTEM user {} (PID {}) accessed protected process {}",
                    source_user, source_pid, target_process
                ),
                mitre_technique: "T1003".into(),
            });
        }

        None
    }

    pub fn check_token_theft(&self, pid: u32, process_name: &str) -> Option<CredentialAlert> {
        let suspicious = ["mimikatz", "sekurlsa", "procdump", "comsvcs", "tasklist", "handle"];
        let name_lower = process_name.to_lowercase();

        if suspicious.iter().any(|s| name_lower.contains(s)) {
            Some(CredentialAlert {
                severity: EventSeverity::Critical,
                alert_type: "Token Theft Tool Detected".into(),
                details: format!("Credential theft tool detected: {} (PID {})", process_name, pid),
                mitre_technique: "T1134".into(),
            })
        } else {
            None
        }
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    pub fn lsass_access_attempts(&self) -> &[LsassAccessAttempt] {
        &self.suspicious_access
    }

    pub fn protected_processes(&self) -> &[String] {
        &self.protected_processes
    }
}
