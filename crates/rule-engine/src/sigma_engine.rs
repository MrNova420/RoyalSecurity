use royalsecurity_common::types::SecurityEventEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaLogSource {
    pub process_creation: bool,
    pub network_connection: bool,
    pub file_event: bool,
    pub registry_event: bool,
}

impl Default for SigmaLogSource {
    fn default() -> Self {
        Self {
            process_creation: false,
            network_connection: false,
            file_event: false,
            registry_event: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub status: String,
    pub description: String,
    pub logsource: SigmaLogSource,
    pub detection: HashMap<String, String>,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaMatch {
    pub rule_id: String,
    pub rule_title: String,
    pub matched_fields: Vec<String>,
}

pub struct SigmaEngine {
    pub rules: Vec<SigmaRule>,
}

impl SigmaEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
        };
        for rule in Self::built_in_rules() {
            engine.rules.push(rule);
        }
        info!(count = engine.rules.len(), "Loaded built-in Sigma rules");
        engine
    }

    pub fn evaluate(&self, event: &SecurityEventEnvelope) -> Vec<SigmaMatch> {
        let mut matches = Vec::new();
        let event_map = Self::event_to_map(event);

        for rule in &self.rules {
            if let Some(m) = self.evaluate_rule(rule, &event_map) {
                matches.push(m);
            }
        }

        matches
    }

    pub fn add_rule(&mut self, rule: SigmaRule) {
        self.rules.push(rule);
    }

    fn event_to_map(event: &SecurityEventEnvelope) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("event_type".into(), format!("{:?}", event.event_type));
        map.insert("source".into(), event.source.clone());
        for (k, v) in &event.details {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            } else {
                map.insert(k.clone(), v.to_string());
            }
        }
        map
    }

    fn evaluate_rule(
        &self,
        rule: &SigmaRule,
        event_map: &HashMap<String, String>,
    ) -> Option<SigmaMatch> {
        let mut matched_fields = Vec::new();

        for (field, pattern) in &rule.detection {
            if let Some(value) = event_map.get(field) {
                if value.to_lowercase().contains(&pattern.to_lowercase()) {
                    matched_fields.push(field.clone());
                }
            }
        }

        let total_patterns = rule.detection.len();
        if total_patterns == 0 {
            return None;
        }

        let condition_match = match rule.condition.as_str() {
            "all" => matched_fields.len() == total_patterns,
            "any" => !matched_fields.is_empty(),
            _ => matched_fields.len() == total_patterns,
        };

        if condition_match {
            Some(SigmaMatch {
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                matched_fields,
            })
        } else {
            None
        }
    }

    pub fn built_in_rules() -> Vec<SigmaRule> {
        vec![
            SigmaRule {
                id: "sigma-001".into(),
                title: "Suspicious PowerShell Execution".into(),
                status: "stable".into(),
                description: "Detects suspicious PowerShell execution with encoded commands commonly used in attacks".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "powershell.exe".into());
                    m.insert("CommandLine".into(), "-enc".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-002".into(),
                title: "Suspicious PowerShell Download Cradle".into(),
                status: "stable".into(),
                description: "Detects PowerShell download cradle patterns".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "powershell.exe".into());
                    m.insert("CommandLine".into(), "DownloadString".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-003".into(),
                title: "PsExec Lateral Movement".into(),
                status: "stable".into(),
                description: "Detects PsExec usage for lateral movement across network".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "psexec".into());
                    m.insert("CommandLine".into(), "\\PSEXESVC".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-004".into(),
                title: "WMI Lateral Movement".into(),
                status: "stable".into(),
                description: "Detects WMI-based remote command execution for lateral movement".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "wmic.exe".into());
                    m.insert("CommandLine".into(), "/node:".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-005".into(),
                title: "Mimikatz Credential Dumping".into(),
                status: "stable".into(),
                description: "Detects Mimikatz execution for credential dumping".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("CommandLine".into(), "mimikatz".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-006".into(),
                title: "LSASS Memory Dump".into(),
                status: "stable".into(),
                description: "Detects tools dumping LSASS process memory for credential extraction".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("CommandLine".into(), "lsass".into());
                    m.insert("CommandLine".into(), "procdump".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-007".into(),
                title: "Suspicious Service Creation".into(),
                status: "stable".into(),
                description: "Detects creation of suspicious Windows services for persistence".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "sc.exe".into());
                    m.insert("CommandLine".into(), "create".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-008".into(),
                title: "Scheduled Task Creation".into(),
                status: "stable".into(),
                description: "Detects scheduled task creation for persistence".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "schtasks.exe".into());
                    m.insert("CommandLine".into(), "/create".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-009".into(),
                title: "Registry Run Key Modification".into(),
                status: "stable".into(),
                description: "Detects modification of registry Run keys for persistence".into(),
                logsource: SigmaLogSource { registry_event: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("TargetObject".into(), "\\Run".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-010".into(),
                title: "WMI Event Subscription Persistence".into(),
                status: "stable".into(),
                description: "Detects WMI event subscription creation for persistence".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("CommandLine".into(), "__EventFilter".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-011".into(),
                title: "UAC Bypass via Fodhelper".into(),
                status: "stable".into(),
                description: "Detects UAC bypass attempt using fodhelper.exe".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "fodhelper.exe".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-012".into(),
                title: "Process Injection via CreateRemoteThread".into(),
                status: "stable".into(),
                description: "Detects indicators of process injection via CreateRemoteThread".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("CommandLine".into(), "rundll32".into());
                    m.insert("CommandLine".into(), "comsvcs".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-013".into(),
                title: "Whoami Enumeration".into(),
                status: "stable".into(),
                description: "Detects whoami execution for system enumeration during recon".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "whoami.exe".into());
                    m
                },
                condition: "any".into(),
            },
            SigmaRule {
                id: "sigma-014".into(),
                title: "Net Group Domain Admins Enumeration".into(),
                status: "stable".into(),
                description: "Detects net group enumeration of privileged groups".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "net.exe".into());
                    m.insert("CommandLine".into(), "Domain Admins".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-015".into(),
                title: "Suspicious File Archive Creation".into(),
                status: "stable".into(),
                description: "Detects creation of archive files in temp folders before exfiltration".into(),
                logsource: SigmaLogSource { file_event: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("TargetFilename".into(), "\\Temp\\".into());
                    m.insert("TargetFilename".into(), ".zip".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-016".into(),
                title: "Data Compressed in Temp Directory".into(),
                status: "stable".into(),
                description: "Detects data compression operations in temp directories".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("CommandLine".into(), "rar.exe".into());
                    m.insert("CommandLine".into(), "\\Temp".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-017".into(),
                title: "DNS Over HTTPS Indicators".into(),
                status: "experimental".into(),
                description: "Detects DNS over HTTPS usage that may indicate C2 communication".into(),
                logsource: SigmaLogSource { network_connection: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("DestinationPort".into(), "443".into());
                    m.insert("Initiated".into(), "true".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-018".into(),
                title: "Suspicious Outbound RDP Connection".into(),
                status: "stable".into(),
                description: "Detects outbound RDP connections that may indicate lateral movement".into(),
                logsource: SigmaLogSource { network_connection: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("DestinationPort".into(), "3389".into());
                    m.insert("Initiated".into(), "true".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-019".into(),
                title: "Certutil Download Command".into(),
                status: "stable".into(),
                description: "Detects certutil usage for downloading files".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "certutil.exe".into());
                    m.insert("CommandLine".into(), "-urlcache".into());
                    m
                },
                condition: "all".into(),
            },
            SigmaRule {
                id: "sigma-020".into(),
                title: "PowerShell AMSI Bypass Attempt".into(),
                status: "stable".into(),
                description: "Detects PowerShell attempts to bypass AMSI protection".into(),
                logsource: SigmaLogSource { process_creation: true, ..Default::default() },
                detection: {
                    let mut m = HashMap::new();
                    m.insert("Image".into(), "powershell.exe".into());
                    m.insert("CommandLine".into(), "AmsiUtils".into());
                    m
                },
                condition: "all".into(),
            },
        ]
    }
}
