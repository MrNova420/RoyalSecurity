use royalsecurity_common::types::*;
use std::collections::HashMap;

pub struct EdrDetector {
    process_tree: HashMap<u32, ProcessNode>,
    alert_count: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub user: String,
    pub children: Vec<u32>,
    pub suspicious_score: u32,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detected: bool,
    pub rule_name: String,
    pub severity: EventSeverity,
    pub mitre_technique: String,
    pub details: String,
}

impl EdrDetector {
    pub fn new() -> Self {
        Self {
            process_tree: HashMap::new(),
            alert_count: 0,
        }
    }

    pub fn analyze_process(&mut self, pid: u32, ppid: u32, name: &str, path: &str, command_line: &str, user: &str) -> Vec<DetectionResult> {
        let node = ProcessNode {
            pid, ppid,
            name: name.to_string(),
            path: path.to_string(),
            command_line: command_line.to_string(),
            user: user.to_string(),
            children: Vec::new(),
            suspicious_score: 0,
        };

        if let Some(parent) = self.process_tree.get_mut(&ppid) {
            parent.children.push(pid);
        }

        let mut results = Vec::new();

        // Credential access detection
        if command_line.to_lowercase().contains("lsass") || command_line.to_lowercase().contains("sekurlsa") {
            results.push(DetectionResult {
                detected: true,
                rule_name: "Credential Dumping Attempt".into(),
                severity: EventSeverity::Critical,
                mitre_technique: "T1003".into(),
                details: format!("Suspicious LSASS access from PID {} ({})", pid, name),
            });
        }

        // Process injection detection
        if command_line.to_lowercase().contains("createremotethread")
            || command_line.to_lowercase().contains("virtualallocex")
            || command_line.to_lowercase().contains("ntwritevirtualmemory") {
            results.push(DetectionResult {
                detected: true,
                rule_name: "Process Injection".into(),
                severity: EventSeverity::High,
                mitre_technique: "T1055".into(),
                details: format!("Injection indicators in PID {} ({})", pid, name),
            });
        }

        // Encoded PowerShell
        if name.to_lowercase().contains("powershell")
            && (command_line.contains("-enc ") || command_line.contains("-e ")
                || command_line.contains("FromBase64String") || command_line.contains("Invoke-Expression")) {
            results.push(DetectionResult {
                detected: true,
                rule_name: "Encoded PowerShell Execution".into(),
                severity: EventSeverity::High,
                mitre_technique: "T1059.001".into(),
                details: format!("Obfuscated PS from PID {} : {}", pid, command_line.chars().take(200).collect::<String>()),
            });
        }

        // LOLBin abuse
        let lolbins = ["mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "msbuild.exe", "installutil.exe", "msiexec.exe"];
        if lolbins.iter().any(|lb| name.to_lowercase().contains(lb)) && !command_line.is_empty() {
            results.push(DetectionResult {
                detected: true,
                rule_name: "LOLBin Execution".into(),
                severity: EventSeverity::Medium,
                mitre_technique: "T1218".into(),
                details: format!("LOLBin {} executed with args: {}", name, command_line.chars().take(200).collect::<String>()),
            });
        }

        // Suspicious user context
        if user == "SYSTEM" && !path.to_lowercase().contains("windows\\system32") && !path.to_lowercase().contains("windows\\syswow64") {
            results.push(DetectionResult {
                detected: true,
                rule_name: "Suspicious SYSTEM Execution".into(),
                severity: EventSeverity::High,
                mitre_technique: "T1055".into(),
                details: format!("Non-system binary running as SYSTEM: {} ({})", name, path),
            });
        }

        self.process_tree.insert(pid, node);
        self.alert_count += results.len() as u64;
        results
    }

    pub fn remove_process(&mut self, pid: u32) {
        self.process_tree.remove(&pid);
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    pub fn process_count(&self) -> usize {
        self.process_tree.len()
    }

    pub fn build_process_tree(&self, root_pid: u32) -> Vec<&ProcessNode> {
        let mut tree = Vec::new();
        if let Some(root) = self.process_tree.get(&root_pid) {
            tree.push(root);
            for child_pid in &root.children {
                tree.extend(self.build_process_tree(*child_pid));
            }
        }
        tree
    }
}
