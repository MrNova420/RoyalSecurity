pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AsrMode {
    Block,
    AuditOnly,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AsrCategory {
    OfficeChildProcess,
    OfficeMacroExecution,
    OfficeExecutableContent,
    ScriptObfuscation,
    JsExecution,
    PsExecution,
    EmailAttachment,
    CredentialStealing,
    ProcessCreation,
    NetworkActivity,
    ExploitProtection,
    PersistenceMechanism,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrConfig {
    pub mode: AsrMode,
    pub enable_office_child_rules: bool,
    pub enable_script_rules: bool,
    pub enable_email_rules: bool,
    pub enable_network_rules: bool,
    pub excluded_processes: Vec<String>,
    pub excluded_paths: Vec<String>,
}

impl Default for AsrConfig {
    fn default() -> Self {
        Self {
            mode: AsrMode::Block,
            enable_office_child_rules: true,
            enable_script_rules: true,
            enable_email_rules: true,
            enable_network_rules: true,
            excluded_processes: Vec::new(),
            excluded_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: AsrCategory,
    pub severity: EventSeverity,
    pub enabled: bool,
    pub action: AsrMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrViolation {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub process_pid: u32,
    pub process_name: String,
    pub category: AsrCategory,
    pub severity: EventSeverity,
    pub action_taken: AsrMode,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug)]
pub struct AsrEngine {
    pub rules: Vec<AsrRule>,
    pub blocked_events: Vec<AsrViolation>,
    pub config: AsrConfig,
    pub violation_count: u64,
}

fn default_rules() -> Vec<AsrRule> {
    vec![
        AsrRule {
            id: "ASR-001".to_string(),
            name: "Block Office apps from creating child processes".to_string(),
            description: "Blocks Office applications (Word, Excel, PowerPoint, Outlook) from spawning command-line interpreters and scripting hosts".to_string(),
            category: AsrCategory::OfficeChildProcess,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-002".to_string(),
            name: "Block Office apps from creating executable content".to_string(),
            description: "Prevents Office applications from writing executable files (.exe, .dll, .ps1, .vbs, .js) to disk".to_string(),
            category: AsrCategory::OfficeExecutableContent,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-003".to_string(),
            name: "Block Office apps from injecting code".to_string(),
            description: "Detects Office applications attempting to inject code into other processes via suspicious memory allocations or child process flags".to_string(),
            category: AsrCategory::OfficeMacroExecution,
            severity: EventSeverity::Critical,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-004".to_string(),
            name: "Block JavaScript/VBScript from launching downloaded content".to_string(),
            description: "Prevents wscript.exe and cscript.exe from spawning child processes after loading downloaded scripts".to_string(),
            category: AsrCategory::JsExecution,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-005".to_string(),
            name: "Block execution of obfuscated scripts".to_string(),
            description: "Detects and blocks scripts with high entropy content, encoded commands, or Invoke-Expression patterns".to_string(),
            category: AsrCategory::ScriptObfuscation,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-006".to_string(),
            name: "Block credential stealing from LSASS".to_string(),
            description: "Blocks non-system processes from accessing lsass.exe memory for credential dumping".to_string(),
            category: AsrCategory::CredentialStealing,
            severity: EventSeverity::Critical,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-007".to_string(),
            name: "Block untrusted executables from USB".to_string(),
            description: "Prevents execution of untrusted executables originating from removable media".to_string(),
            category: AsrCategory::ProcessCreation,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-008".to_string(),
            name: "Block executable content from email".to_string(),
            description: "Blocks .exe and .scr files written from email client temporary directories".to_string(),
            category: AsrCategory::EmailAttachment,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-009".to_string(),
            name: "Block persistence via WMI".to_string(),
            description: "Detects WMI subscription creation events that enable persistence mechanisms".to_string(),
            category: AsrCategory::PersistenceMechanism,
            severity: EventSeverity::Critical,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-010".to_string(),
            name: "Block process creations from PSExec and WMI".to_string(),
            description: "Blocks processes spawned by services.exe originating from network paths (PSExec, WMI lateral movement)".to_string(),
            category: AsrCategory::NetworkActivity,
            severity: EventSeverity::High,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-011".to_string(),
            name: "Block exploit protection bypass attempts".to_string(),
            description: "Detects attempts to disable or bypass Windows exploit protection mitigations".to_string(),
            category: AsrCategory::ExploitProtection,
            severity: EventSeverity::Critical,
            enabled: true,
            action: AsrMode::Block,
        },
        AsrRule {
            id: "ASR-012".to_string(),
            name: "Block PowerShell launched from scheduled tasks".to_string(),
            description: "Blocks PowerShell execution triggered by schtasks.exe or at.exe to prevent persistence abuse".to_string(),
            category: AsrCategory::PsExecution,
            severity: EventSeverity::Medium,
            enabled: true,
            action: AsrMode::Block,
        },
    ]
}

impl AsrEngine {
    pub fn new() -> Self {
        info!("Initializing ASR engine with default rules");
        let rules = default_rules();
        let count = rules.len();
        info!(rule_count = count, "Loaded {} default ASR rules", count);
        Self {
            rules,
            blocked_events: Vec::new(),
            config: AsrConfig::default(),
            violation_count: 0,
        }
    }

    pub fn with_config(config: AsrConfig) -> Self {
        info!("Initializing ASR engine with custom configuration");
        let rules = default_rules();
        let count = rules.len();
        info!(rule_count = count, mode = ?config.mode, "Loaded {} rules with custom config", count);
        Self {
            rules,
            blocked_events: Vec::new(),
            config,
            violation_count: 0,
        }
    }

    pub fn add_rule(&mut self, rule: AsrRule) {
        info!(rule_id = rule.id, rule_name = rule.name, "Adding ASR rule");
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        let removed = self.rules.len() < before;
        if removed {
            info!(rule_id = rule_id, "Removed ASR rule");
        } else {
            warn!(rule_id = rule_id, "Attempted to remove non-existent ASR rule");
        }
        removed
    }

    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            info!(rule_id = rule_id, enabled = enabled, "Toggled ASR rule");
            true
        } else {
            warn!(rule_id = rule_id, "Attempted to toggle non-existent ASR rule");
            false
        }
    }

    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }

    pub fn get_rules(&self) -> &[AsrRule] {
        &self.rules
    }

    pub fn rules_in_category(&self, cat: AsrCategory) -> Vec<&AsrRule> {
        self.rules.iter().filter(|r| r.category == cat).collect()
    }

    fn is_process_excluded(&self, process_name: &str) -> bool {
        let lower = process_name.to_lowercase();
        self.config
            .excluded_processes
            .iter()
            .any(|p| p.to_lowercase() == lower)
    }

    fn is_path_excluded(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        self.config
            .excluded_paths
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }

    fn is_rule_active(&self, rule: &AsrRule) -> bool {
        if !rule.enabled {
            return false;
        }
        match &rule.action {
            AsrMode::Disabled => false,
            _ => {
                if matches!(self.config.mode, AsrMode::Disabled) {
                    return false;
                }
                true
            }
        }
    }

    fn effective_action(&self, rule: &AsrRule) -> AsrMode {
        match &rule.action {
            AsrMode::Disabled => AsrMode::Disabled,
            AsrMode::AuditOnly => AsrMode::AuditOnly,
            AsrMode::Block => match &self.config.mode {
                AsrMode::AuditOnly => AsrMode::AuditOnly,
                other => other.clone(),
            },
        }
    }

    fn push_violation(&mut self, violation: AsrViolation) {
        self.violation_count += 1;
        debug!(
            rule_id = violation.rule_id,
            pid = violation.process_pid,
            process = violation.process_name,
            action = ?violation.action_taken,
            "ASR violation recorded"
        );
        self.blocked_events.push(violation);
    }

    fn make_violation(
        &self,
        rule: &AsrRule,
        pid: u32,
        process_name: &str,
        description: String,
        evidence: Vec<String>,
    ) -> AsrViolation {
        let action = self.effective_action(rule);
        AsrViolation {
            id: Uuid::new_v4(),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            process_pid: pid,
            process_name: process_name.to_string(),
            category: rule.category.clone(),
            severity: rule.severity.clone(),
            action_taken: action,
            description,
            evidence,
            timestamp: Utc::now(),
        }
    }

    pub fn check_process_creation(
        &mut self,
        info: &ProcessInfo,
        parent: Option<&ProcessInfo>,
    ) -> Vec<AsrViolation> {
        if self.is_process_excluded(&info.name) {
            debug!(pid = info.pid, name = info.name, "Process excluded from ASR checks");
            return Vec::new();
        }
        if self.is_path_excluded(&info.path) {
            debug!(pid = info.pid, path = info.path, "Path excluded from ASR checks");
            return Vec::new();
        }

        let mut violations = Vec::new();
        let child_lower = info.name.to_lowercase();
        let cmd_lower = info.command_line.to_lowercase();
        let child_is_path_unc = info.path.to_lowercase().contains("\\\\");

        let active_rules: Vec<AsrRule> = self
            .rules
            .iter()
            .filter(|r| self.is_rule_active(r))
            .cloned()
            .collect();

        for rule in &active_rules {
            match &rule.category {
                AsrCategory::OfficeChildProcess => {
                    if !self.config.enable_office_child_rules {
                        continue;
                    }
                    if let Some(parent) = parent {
                        let parent_lower = parent.name.to_lowercase();
                        let office_apps = [
                            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                            "msaccess.exe", "mspub.exe", "visio.exe", "onenote.exe",
                        ];
                        let blocked_children = [
                            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                            "cscript.exe", "mshta.exe", "certutil.exe", "regsvr32.exe",
                            "rundll32.exe", "msbuild.exe", "installutil.exe",
                        ];
                        if office_apps.iter().any(|a| parent_lower == *a)
                            && blocked_children.iter().any(|c| child_lower == *c)
                        {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "Office application '{}' spawned blocked child process '{}'",
                                    parent.name, info.name
                                ),
                                vec![
                                    format!("Parent: {} (PID {})", parent.name, parent.pid),
                                    format!("Child: {} (PID {})", info.name, info.pid),
                                    format!("Child path: {}", info.path),
                                    format!("Command line: {}", info.command_line),
                                ],
                            );
                            warn!(
                                parent = parent.name,
                                child = info.name,
                                pid = info.pid,
                                "ASR: Office app spawned blocked child process"
                            );
                            violations.push(v);
                        }
                    }
                }

                AsrCategory::JsExecution => {
                    if let Some(parent) = parent {
                        let parent_lower = parent.name.to_lowercase();
                        if (parent_lower == "wscript.exe" || parent_lower == "cscript.exe")
                            && child_lower != "conhost.exe"
                        {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "Script host '{}' spawned child process '{}'",
                                    parent.name, info.name
                                ),
                                vec![
                                    format!("Script host: {} (PID {})", parent.name, parent.pid),
                                    format!("Child: {} (PID {})", info.name, info.pid),
                                    format!("Child path: {}", info.path),
                                    format!("Command line: {}", info.command_line),
                                ],
                            );
                            warn!(
                                parent = parent.name,
                                child = info.name,
                                pid = info.pid,
                                "ASR: Script host spawned child process"
                            );
                            violations.push(v);
                        }
                    }
                }

                AsrCategory::ProcessCreation => {
                    if child_lower == "cmd.exe"
                        || child_lower == "powershell.exe"
                        || child_lower == "pwsh.exe"
                    {
                        let suspicious_flags = [
                            "-enc ", "-encodedcommand ", "-e ", "/e ", "/c ",
                        ];
                        if suspicious_flags.iter().any(|f| cmd_lower.contains(f)) {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "Process '{}' launched with suspicious encoded/obfuscated command line",
                                    info.name
                                ),
                                vec![
                                    format!("Process: {} (PID {})", info.name, info.pid),
                                    format!("Command line: {}", info.command_line),
                                    format!("Path: {}", info.path),
                                ],
                            );
                            warn!(
                                pid = info.pid,
                                name = info.name,
                                "ASR: Suspicious command-line flags detected"
                            );
                            violations.push(v);
                        }
                    }
                }

                AsrCategory::CredentialStealing => {
                    let accessing_lsass = cmd_lower.contains("lsass")
                        || info.path.to_lowercase().contains("lsass");
                    if accessing_lsass && child_lower != "lsass.exe" {
                        let is_system_process =
                            info.path.to_lowercase().contains("\\windows\\system32");
                        if !is_system_process {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "Non-system process '{}' attempting to access LSASS",
                                    info.name
                                ),
                                vec![
                                    format!("Process: {} (PID {})", info.name, info.pid),
                                    format!("Path: {}", info.path),
                                    format!("Command line: {}", info.command_line),
                                    format!("User: {}", info.user),
                                ],
                            );
                            warn!(
                                pid = info.pid,
                                name = info.name,
                                "ASR: Credential stealing from LSASS detected"
                            );
                            violations.push(v);
                        }
                    }
                }

                AsrCategory::NetworkActivity => {
                    if let Some(parent) = parent {
                        let parent_lower = parent.name.to_lowercase();
                        if parent_lower == "services.exe"
                            && (child_is_path_unc || cmd_lower.contains("\\\\"))
                        {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "Process '{}' spawned by services.exe from network path (possible PSExec/WMI)",
                                    info.name
                                ),
                                vec![
                                    format!("Parent: {} (PID {})", parent.name, parent.pid),
                                    format!("Child: {} (PID {})", info.name, info.pid),
                                    format!("Child path: {}", info.path),
                                    format!("Command line: {}", info.command_line),
                                ],
                            );
                            warn!(
                                parent = parent.name,
                                child = info.name,
                                pid = info.pid,
                                "ASR: Process spawned from network path via services"
                            );
                            violations.push(v);
                        }
                    }
                }

                AsrCategory::PsExecution => {
                    if let Some(parent) = parent {
                        let parent_lower = parent.name.to_lowercase();
                        if (parent_lower == "schtasks.exe" || parent_lower == "at.exe")
                            && (child_lower == "powershell.exe" || child_lower == "pwsh.exe")
                        {
                            let v = self.make_violation(
                                rule,
                                info.pid,
                                &info.name,
                                format!(
                                    "PowerShell launched from scheduled task by '{}'",
                                    parent.name
                                ),
                                vec![
                                    format!("Task scheduler: {} (PID {})", parent.name, parent.pid),
                                    format!("PowerShell: {} (PID {})", info.name, info.pid),
                                    format!("Command line: {}", info.command_line),
                                ],
                            );
                            warn!(
                                parent = parent.name,
                                child = info.name,
                                pid = info.pid,
                                "ASR: PowerShell launched from scheduled task"
                            );
                            violations.push(v);
                        }
                    }
                }

                _ => {}
            }
        }

        for v in &violations {
            self.push_violation(v.clone());
        }
        violations
    }

    pub fn check_file_creation(
        &mut self,
        event: &FileEvent,
        process_name: &str,
    ) -> Vec<AsrViolation> {
        if self.is_process_excluded(process_name) {
            debug!(process = process_name, "Process excluded from ASR file checks");
            return Vec::new();
        }
        if self.is_path_excluded(&event.path) {
            debug!(path = event.path, "Path excluded from ASR file checks");
            return Vec::new();
        }

        let mut violations = Vec::new();
        let path_lower = event.path.to_lowercase();
        let process_lower = process_name.to_lowercase();
        let executable_exts = [
            ".exe", ".dll", ".ps1", ".vbs", ".js", ".scr", ".com", ".bat", ".cmd",
        ];
        let is_executable = executable_exts.iter().any(|ext| path_lower.ends_with(ext));

        let active_rules: Vec<AsrRule> = self
            .rules
            .iter()
            .filter(|r| self.is_rule_active(r))
            .cloned()
            .collect();

        for rule in &active_rules {
            match &rule.category {
                AsrCategory::OfficeExecutableContent => {
                    if !self.config.enable_office_child_rules {
                        continue;
                    }
                    let office_apps = [
                        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                        "msaccess.exe", "mspub.exe", "visio.exe",
                    ];
                    if office_apps.iter().any(|a| process_lower == *a) && is_executable {
                        let v = self.make_violation(
                            rule,
                            0,
                            process_name,
                            format!(
                                "Office application '{}' wrote executable content to '{}'",
                                process_name, event.path
                            ),
                            vec![
                                format!("Process: {}", process_name),
                                format!("File path: {}", event.path),
                                format!("File size: {:?}", event.size),
                                format!("SHA256: {:?}", event.hash_sha256),
                            ],
                        );
                        warn!(
                            process = process_name,
                            path = event.path,
                            "ASR: Office app wrote executable content"
                        );
                        violations.push(v);
                    }
                }

                AsrCategory::EmailAttachment => {
                    if !self.config.enable_email_rules {
                        continue;
                    }
                    let email_temp_paths = [
                        "\\appdata\\local\\temp\\outlook",
                        "\\appdata\\local\\microsoft\\windows\\inetcache",
                        "\\appdata\\local\\microsoft\\windows\\ie\\",
                        "\\content.outlook\\",
                        "\\appdata\\roaming\\microsoft\\outlook\\",
                    ];
                    let from_email_dir =
                        email_temp_paths.iter().any(|p| path_lower.contains(p));
                    let dangerous_exts = [".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1"];
                    let is_dangerous =
                        dangerous_exts.iter().any(|ext| path_lower.ends_with(ext));

                    if from_email_dir && is_dangerous {
                        let v = self.make_violation(
                            rule,
                            0,
                            process_name,
                            format!(
                                "Executable content '{}' written from email directory by '{}'",
                                event.path, process_name
                            ),
                            vec![
                                format!("Process: {}", process_name),
                                format!("File path: {}", event.path),
                                format!("File size: {:?}", event.size),
                                format!("SHA256: {:?}", event.hash_sha256),
                            ],
                        );
                        warn!(
                            process = process_name,
                            path = event.path,
                            "ASR: Executable content from email"
                        );
                        violations.push(v);
                    }
                }

                AsrCategory::ProcessCreation => {
                    if !self.config.enable_network_rules {
                        continue;
                    }
                    let usb_paths = [
                        "e:\\", "f:\\", "g:\\", "h:\\", "i:\\", "j:\\", "k:\\",
                    ];
                    let from_usb = usb_paths.iter().any(|p| path_lower.starts_with(p));
                    if from_usb && is_executable {
                        let v = self.make_violation(
                            rule,
                            0,
                            process_name,
                            format!(
                                "Untrusted executable '{}' written from removable media",
                                event.path
                            ),
                            vec![
                                format!("Process: {}", process_name),
                                format!("File path: {}", event.path),
                                format!("File size: {:?}", event.size),
                                format!("SHA256: {:?}", event.hash_sha256),
                            ],
                        );
                        warn!(
                            process = process_name,
                            path = event.path,
                            "ASR: Executable from removable media"
                        );
                        violations.push(v);
                    }
                }

                _ => {}
            }
        }

        for v in &violations {
            self.push_violation(v.clone());
        }
        violations
    }

    pub fn check_script_execution(
        &mut self,
        process_name: &str,
        script_content: Option<&str>,
        command_line: &str,
    ) -> Vec<AsrViolation> {
        if self.is_process_excluded(process_name) {
            debug!(
                process = process_name,
                "Process excluded from ASR script checks"
            );
            return Vec::new();
        }

        let mut violations = Vec::new();
        let process_lower = process_name.to_lowercase();
        let cmd_lower = command_line.to_lowercase();

        let active_rules: Vec<AsrRule> = self
            .rules
            .iter()
            .filter(|r| self.is_rule_active(r))
            .cloned()
            .collect();

        for rule in &active_rules {
            match &rule.category {
                AsrCategory::ScriptObfuscation => {
                    if !self.config.enable_script_rules {
                        continue;
                    }

                    let mut detected = false;
                    let mut evidence = Vec::new();

                    if cmd_lower.contains("-encodedcommand")
                        || cmd_lower.contains("-enc ")
                        || cmd_lower.contains("-e ")
                    {
                        detected = true;
                        evidence.push("Encoded command line parameter detected".to_string());
                        evidence.push(format!("Command line: {}", command_line));
                    }

                    if cmd_lower.contains("invoke-expression")
                        || cmd_lower.contains("iex(")
                        || cmd_lower.contains("iex ")
                        || cmd_lower.contains("invoke-expression ")
                    {
                        detected = true;
                        evidence.push("Invoke-Expression (IEX) usage detected".to_string());
                        evidence.push(format!("Command line: {}", command_line));
                    }

                    if let Some(content) = script_content {
                        let content_lower = content.to_lowercase();
                        if content_lower.contains("frombase64string")
                            || content_lower.contains("invoke-expression")
                            || content_lower.contains("[system.convert]::")
                            || content_lower.contains("iex(")
                        {
                            detected = true;
                            evidence.push("Obfuscated script content detected".to_string());
                        }

                        let entropy = calculate_shannon_entropy(content);
                        if entropy > 5.0 && content.len() > 100 {
                            detected = true;
                            evidence.push(format!("High entropy script content: {:.2}", entropy));
                            evidence.push(format!("Script length: {} chars", content.len()));
                        }
                    }

                    if detected {
                        let v = self.make_violation(
                            rule,
                            0,
                            process_name,
                            format!(
                                "Obfuscated or encoded script execution detected via '{}'",
                                process_name
                            ),
                            evidence,
                        );
                        warn!(
                            process = process_name,
                            "ASR: Obfuscated script execution detected"
                        );
                        violations.push(v);
                    }
                }

                AsrCategory::JsExecution => {
                    if process_lower == "wscript.exe" || process_lower == "cscript.exe" {
                        if let Some(content) = script_content {
                            let content_lower = content.to_lowercase();
                            let has_download = content_lower.contains("xmlhttp")
                                || content_lower.contains("wget")
                                || content_lower.contains("downloadfile")
                                || content_lower.contains("urlmon")
                                || content_lower.contains("msxml2.xmlhttp");

                            if has_download {
                                let v = self.make_violation(
                                    rule,
                                    0,
                                    process_name,
                                    format!(
                                        "Script host '{}' executing downloaded content",
                                        process_name
                                    ),
                                    vec![
                                        format!("Process: {}", process_name),
                                        format!("Command line: {}", command_line),
                                        "Script contains download/HTTP request patterns"
                                            .to_string(),
                                    ],
                                );
                                warn!(
                                    process = process_name,
                                    "ASR: Script host launching downloaded content"
                                );
                                violations.push(v);
                            }
                        }
                    }
                }

                AsrCategory::PsExecution => {
                    if process_lower == "powershell.exe" || process_lower == "pwsh.exe" {
                        let mut detected = false;
                        let mut evidence = Vec::new();

                        if cmd_lower.contains("invoke-mimikatz")
                            || cmd_lower.contains("invoke-credentialprovider")
                            || cmd_lower.contains("invoke-dcsync")
                            || cmd_lower.contains("invoke-ninjacopy")
                        {
                            detected = true;
                            evidence
                                .push("Credential theft PowerShell command detected".to_string());
                        }

                        if cmd_lower.contains("downloadstring(")
                            || cmd_lower.contains("downloadfile(")
                            || cmd_lower.contains("invoke-restmethod")
                            || cmd_lower.contains("invoke-webrequest")
                        {
                            if cmd_lower.contains("iex") || cmd_lower.contains("invoke-expression")
                            {
                                detected = true;
                                evidence
                                    .push("Download cradle with execution detected".to_string());
                            }
                        }

                        if detected {
                            let v = self.make_violation(
                                rule,
                                0,
                                process_name,
                                format!(
                                    "Suspicious PowerShell execution detected: '{}'",
                                    command_line
                                ),
                                evidence,
                            );
                            warn!(
                                process = process_name,
                                "ASR: Suspicious PowerShell execution"
                            );
                            violations.push(v);
                        }
                    }
                }

                _ => {}
            }
        }

        for v in &violations {
            self.push_violation(v.clone());
        }
        violations
    }

    pub fn check_registry_event(
        &mut self,
        event: &RegistryEvent,
        process_name: &str,
    ) -> Vec<AsrViolation> {
        if self.is_process_excluded(process_name) {
            debug!(
                process = process_name,
                "Process excluded from ASR registry checks"
            );
            return Vec::new();
        }

        let mut violations = Vec::new();
        let key_lower = event.key_path.to_lowercase();

        let active_rules: Vec<AsrRule> = self
            .rules
            .iter()
            .filter(|r| self.is_rule_active(r))
            .cloned()
            .collect();

        for rule in &active_rules {
            match &rule.category {
                AsrCategory::PersistenceMechanism => {
                    let wmi_paths = [
                        "\\software\\classes\\clsid\\",
                        "\\software\\microsoft\\wbem",
                        "\\currentcontrolset\\services\\",
                        "\\software\\microsoft\\windows\\currentversion\\wbem",
                    ];
                    let is_wmi_path = wmi_paths.iter().any(|p| key_lower.contains(p));
                    let has_wmi_value = event
                        .value_name
                        .as_ref()
                        .map(|v| {
                            let v_lower = v.to_lowercase();
                            v_lower.contains("scripttext")
                                || v_lower.contains("scriptengine")
                                || v_lower.contains("filertemplate")
                                || v_lower.contains("__filtertoconsumerbinding")
                        })
                        .unwrap_or(false);

                    if is_wmi_path && has_wmi_value {
                        let v = self.make_violation(
                            rule,
                            0,
                            process_name,
                            format!(
                                "WMI persistence mechanism detected: '{}' writing to '{}'",
                                process_name, event.key_path
                            ),
                            vec![
                                format!("Process: {}", process_name),
                                format!("Registry key: {}", event.key_path),
                                format!("Value name: {:?}", event.value_name),
                                format!("Value data: {:?}", event.value_data),
                                format!("Action: {:?}", event.action),
                            ],
                        );
                        warn!(
                            process = process_name,
                            key = event.key_path,
                            "ASR: WMI persistence detected"
                        );
                        violations.push(v);
                    }

                    let service_paths = ["\\currentcontrolset\\services\\"];
                    let is_service_path =
                        service_paths.iter().any(|p| key_lower.contains(p));
                    let modifies_image_path = event
                        .value_name
                        .as_ref()
                        .map(|v| v.to_lowercase() == "imagepath")
                        .unwrap_or(false);

                    if is_service_path && modifies_image_path {
                        if let Some(ref data) = event.value_data {
                            let data_lower = data.to_lowercase();
                            let suspicious = data_lower.contains("\\\\")
                                || data_lower.contains("cmd.exe")
                                || data_lower.contains("powershell")
                                || data_lower.contains("rundll32")
                                || data_lower.contains("regsvr32");

                            if suspicious {
                                let v = self.make_violation(
                                    rule,
                                    0,
                                    process_name,
                                    format!(
                                        "Suspicious service persistence modification by '{}'",
                                        process_name
                                    ),
                                    vec![
                                        format!("Process: {}", process_name),
                                        format!("Registry key: {}", event.key_path),
                                        format!("Image path: {}", data),
                                        format!("Action: {:?}", event.action),
                                    ],
                                );
                                warn!(
                                    process = process_name,
                                    key = event.key_path,
                                    "ASR: Suspicious service persistence"
                                );
                                violations.push(v);
                            }
                        }
                    }
                }

                AsrCategory::ExploitProtection => {
                    let exploit_prot_paths = [
                        "\\currentcontrolset\\control\\session manager\\",
                        "\\software\\microsoft\\windows nt\\currentversion\\",
                        "\\system\\currentcontrolset\\control\\lsa\\",
                    ];
                    let is_exploit_prot =
                        exploit_prot_paths.iter().any(|p| key_lower.contains(p));

                    if is_exploit_prot {
                        if let Some(ref name) = event.value_name {
                            let name_lower = name.to_lowercase();
                            let mitigations = [
                                "mitigationoptions",
                                "disabledifferentialcodecoverage",
                                "disabledynamiccodegeneration",
                            ];
                            if mitigations.iter().any(|m| name_lower.contains(m)) {
                                let v = self.make_violation(
                                    rule,
                                    0,
                                    process_name,
                                    format!(
                                        "Exploit protection modification attempted by '{}'",
                                        process_name
                                    ),
                                    vec![
                                        format!("Process: {}", process_name),
                                        format!("Registry key: {}", event.key_path),
                                        format!("Value: {}", name),
                                        format!("Data: {:?}", event.value_data),
                                    ],
                                );
                                warn!(
                                    process = process_name,
                                    key = event.key_path,
                                    "ASR: Exploit protection bypass attempt"
                                );
                                violations.push(v);
                            }
                        }
                    }
                }

                _ => {}
            }
        }

        for v in &violations {
            self.push_violation(v.clone());
        }
        violations
    }
}

fn calculate_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for byte in data.bytes() {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_office_process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 50,
            name: name.to_string(),
            path: format!(
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\{}",
                name
            ),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_engine_new_has_default_rules() {
        let engine = AsrEngine::new();
        assert!(engine.rules.len() >= 10);
        assert_eq!(engine.violation_count, 0);
        assert!(engine.blocked_events.is_empty());
        assert!(matches!(engine.config.mode, AsrMode::Block));
        assert!(engine.config.enable_office_child_rules);
        assert!(engine.config.enable_script_rules);
        assert!(engine.config.enable_email_rules);
        assert!(engine.config.enable_network_rules);
    }

    #[test]
    fn test_check_process_creation_detects_office_to_cmd() {
        let mut engine = AsrEngine::new();
        let parent = make_office_process(10, "WINWORD.EXE");
        let child = ProcessInfo {
            pid: 200,
            ppid: 10,
            name: "cmd.exe".to_string(),
            path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let violations = engine.check_process_creation(&child, Some(&parent));
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.rule_id == "ASR-001"));
        assert!(violations
            .iter()
            .any(|v| matches!(v.category, AsrCategory::OfficeChildProcess)));
        assert_eq!(engine.violation_count(), 1);
    }

    #[test]
    fn test_check_process_creation_allows_whitelisted() {
        let mut engine = AsrEngine::new();
        engine
            .config
            .excluded_processes
            .push("cmd.exe".to_string());

        let parent = make_office_process(10, "WINWORD.EXE");
        let child = ProcessInfo {
            pid: 200,
            ppid: 10,
            name: "cmd.exe".to_string(),
            path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let violations = engine.check_process_creation(&child, Some(&parent));
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_file_creation_detects_office_writing_exe() {
        let mut engine = AsrEngine::new();
        let event = FileEvent {
            path: "C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe".to_string(),
            original_path: None,
            action: FileAction::Created,
            hash_sha256: None,
            size: Some(1024),
            timestamp: Utc::now(),
        };

        let violations = engine.check_file_creation(&event, "WINWORD.EXE");
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.rule_id == "ASR-002"));
        assert!(violations
            .iter()
            .any(|v| matches!(v.category, AsrCategory::OfficeExecutableContent)));
    }

    #[test]
    fn test_check_script_execution_detects_encoded_powershell() {
        let mut engine = AsrEngine::new();
        let violations = engine.check_script_execution(
            "powershell.exe",
            None,
            "powershell.exe -encodedcommand SQBFWEFN",
        );
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.rule_id == "ASR-005"));
    }

    #[test]
    fn test_check_registry_event_detects_wmi_persistence() {
        let mut engine = AsrEngine::new();
        let event = RegistryEvent {
            key_path: "HKLM\\Software\\Classes\\CLSID\\{some-wmi-consumer}".to_string(),
            value_name: Some("ScriptText".to_string()),
            value_data: Some(
                "Set objShell = CreateObject(\"WScript.Shell\")\nobjShell.Run \"cmd.exe /c malware.exe\""
                    .to_string(),
            ),
            action: RegistryAction::Created,
            timestamp: Utc::now(),
        };

        let violations = engine.check_registry_event(&event, "wmiprvse.exe");
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.rule_id == "ASR-009"));
        assert!(violations
            .iter()
            .any(|v| matches!(v.category, AsrCategory::PersistenceMechanism)));
    }

    #[test]
    fn test_toggle_rule_disables() {
        let mut engine = AsrEngine::new();
        assert!(engine.toggle_rule("ASR-001", false));

        let parent = make_office_process(10, "WINWORD.EXE");
        let child = ProcessInfo {
            pid: 200,
            ppid: 10,
            name: "cmd.exe".to_string(),
            path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let violations = engine.check_process_creation(&child, Some(&parent));
        assert!(violations.is_empty());
        assert_eq!(engine.violation_count(), 0);
    }

    #[test]
    fn test_audit_only_mode_records_but_does_not_block() {
        let config = AsrConfig {
            mode: AsrMode::AuditOnly,
            ..AsrConfig::default()
        };
        let mut engine = AsrEngine::with_config(config);

        let parent = make_office_process(10, "WINWORD.EXE");
        let child = ProcessInfo {
            pid: 200,
            ppid: 10,
            name: "cmd.exe".to_string(),
            path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let violations = engine.check_process_creation(&child, Some(&parent));
        assert!(!violations.is_empty());
        assert!(violations
            .iter()
            .all(|v| v.action_taken == AsrMode::AuditOnly));
        assert_eq!(engine.violation_count(), 1);
    }

    #[test]
    fn test_violation_count_increments() {
        let mut engine = AsrEngine::new();
        assert_eq!(engine.violation_count(), 0);

        let parent = make_office_process(10, "EXCEL.EXE");
        let child = ProcessInfo {
            pid: 300,
            ppid: 10,
            name: "powershell.exe".to_string(),
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        engine.check_process_creation(&child, Some(&parent));
        assert_eq!(engine.violation_count(), 1);

        let parent2 = make_office_process(11, "POWERPNT.EXE");
        let child2 = ProcessInfo {
            pid: 301,
            ppid: 11,
            name: "wscript.exe".to_string(),
            path: "C:\\Windows\\System32\\wscript.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        engine.check_process_creation(&child2, Some(&parent2));
        assert_eq!(engine.violation_count(), 2);
    }

    #[test]
    fn test_rules_in_category_filter() {
        let engine = AsrEngine::new();
        let office_rules = engine.rules_in_category(AsrCategory::OfficeChildProcess);
        assert!(!office_rules.is_empty());
        assert!(office_rules
            .iter()
            .all(|r| r.category == AsrCategory::OfficeChildProcess));

        let script_rules = engine.rules_in_category(AsrCategory::ScriptObfuscation);
        assert!(!script_rules.is_empty());
        assert!(script_rules
            .iter()
            .all(|r| r.category == AsrCategory::ScriptObfuscation));

        let email_rules = engine.rules_in_category(AsrCategory::EmailAttachment);
        assert_eq!(email_rules.len(), 1);
        assert_eq!(email_rules[0].id, "ASR-008");
    }

    #[test]
    fn test_remove_rule() {
        let mut engine = AsrEngine::new();
        let initial_count = engine.rules.len();
        assert!(engine.remove_rule("ASR-001"));
        assert_eq!(engine.rules.len(), initial_count - 1);
        assert!(!engine.rules.iter().any(|r| r.id == "ASR-001"));
    }

    #[test]
    fn test_with_config_custom() {
        let config = AsrConfig {
            mode: AsrMode::Disabled,
            enable_office_child_rules: false,
            excluded_processes: vec!["notepad.exe".to_string()],
            ..AsrConfig::default()
        };
        let engine = AsrEngine::with_config(config);
        assert!(matches!(engine.config.mode, AsrMode::Disabled));
        assert!(!engine.config.enable_office_child_rules);
        assert_eq!(engine.config.excluded_processes.len(), 1);
    }

    #[test]
    fn test_disabled_mode_skips_all() {
        let config = AsrConfig {
            mode: AsrMode::Disabled,
            ..AsrConfig::default()
        };
        let mut engine = AsrEngine::with_config(config);

        let parent = make_office_process(10, "WINWORD.EXE");
        let child = ProcessInfo {
            pid: 200,
            ppid: 10,
            name: "cmd.exe".to_string(),
            path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let violations = engine.check_process_creation(&child, Some(&parent));
        assert!(violations.is_empty());
        assert_eq!(engine.violation_count(), 0);
    }

    #[test]
    fn test_check_script_high_entropy_detection() {
        let mut engine = AsrEngine::new();
        let high_entropy_script = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz\
            0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~\
            AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz\
            0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~\
            AAAAABBBBBCCCCCDDDDDEEEEE";
        let violations = engine.check_script_execution(
            "powershell.exe",
            Some(high_entropy_script),
            "powershell.exe -file script.ps1",
        );
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.rule_id == "ASR-005"));
    }

    #[test]
    fn test_shannon_entropy_calculation() {
        let uniform = "abcdefghij";
        let entropy_uniform = calculate_shannon_entropy(uniform);
        assert!(entropy_uniform > 3.0);

        let repetitive = "aaaaaaaaaa";
        let entropy_repetitive = calculate_shannon_entropy(repetitive);
        assert!((entropy_repetitive - 0.0).abs() < 0.001);

        assert!(entropy_uniform > entropy_repetitive);
    }
}
