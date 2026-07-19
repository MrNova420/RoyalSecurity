use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::info;

use royalsecurity_common::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub user: String,
    pub children: Vec<u32>,
    pub created_at: DateTime<Utc>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub integrity_level: Option<String>,
    pub suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeStats {
    pub total_processes: usize,
    pub active_processes: usize,
    pub terminated_processes: usize,
    pub max_depth: usize,
    pub suspicious_count: usize,
    pub root_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pid: u32,
    pub process_name: String,
    pub pattern_type: String,
    pub description: String,
    pub severity: EventSeverity,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

pub struct ProcessTreeTracker {
    nodes: DashMap<u32, ProcessNode>,
    max_tree_depth: usize,
    suspicious_parent_child: Vec<(String, String, String)>,
}

impl ProcessTreeTracker {
    pub fn new() -> Self {
        let mut suspicious_parent_child = Vec::new();
        suspicious_parent_child.push(("csrss.exe".into(), "cmd.exe".into(), "csrss spawning cmd".into()));
        suspicious_parent_child.push(("wininit.exe".into(), "cmd.exe".into(), "wininit spawning cmd".into()));
        suspicious_parent_child.push(("winlogon.exe".into(), "cmd.exe".into(), "winlogon spawning cmd".into()));
        suspicious_parent_child.push(("spoolsv.exe".into(), "cmd.exe".into(), "spoolsv spawning cmd".into()));
        suspicious_parent_child.push(("svchost.exe".into(), "powershell.exe".into(), "svchost spawning powershell".into()));
        suspicious_parent_child.push(("wmiprvse.exe".into(), "cmd.exe".into(), "wmiprvse spawning cmd".into()));
        suspicious_parent_child.push(("explorer.exe".into(), "net.exe".into(), "explorer spawning net".into()));
        suspicious_parent_child.push(("explorer.exe".into(), "net1.exe".into(), "explorer spawning net1".into()));
        suspicious_parent_child.push(("explorer.exe".into(), "whoami.exe".into(), "explorer spawning whoami".into()));
        suspicious_parent_child.push(("explorer.exe".into(), "tasklist.exe".into(), "explorer spawning tasklist".into()));
        suspicious_parent_child.push(("explorer.exe".into(), "systeminfo.exe".into(), "explorer spawning systeminfo".into()));
        suspicious_parent_child.push(("excel.exe".into(), "powershell.exe".into(), "excel spawning powershell".into()));
        suspicious_parent_child.push(("winword.exe".into(), "powershell.exe".into(), "word spawning powershell".into()));
        suspicious_parent_child.push(("outlook.exe".into(), "powershell.exe".into(), "outlook spawning powershell".into()));
        suspicious_parent_child.push(("iexplore.exe".into(), "powershell.exe".into(), "ie spawning powershell".into()));
        suspicious_parent_child.push(("msedge.exe".into(), "cmd.exe".into(), "edge spawning cmd".into()));
        suspicious_parent_child.push(("chrome.exe".into(), "cmd.exe".into(), "chrome spawning cmd".into()));

        Self {
            nodes: DashMap::new(),
            max_tree_depth: 15,
            suspicious_parent_child,
        }
    }

    pub fn on_process_created(&self, info: &ProcessInfo) -> Vec<SuspiciousPattern> {
        let mut reasons = Vec::new();
        let mut suspicious = false;

        let name_lower = info.name.to_lowercase();

        if info.ppid != 0 {
            if let Some(parent) = self.nodes.get(&info.ppid) {
                let parent_lower = parent.name.to_lowercase();

                for (p, c, desc) in &self.suspicious_parent_child {
                    if parent_lower == p.as_str().to_lowercase() && name_lower == c.as_str().to_lowercase() {
                        reasons.push(desc.clone());
                        suspicious = true;
                    }
                }

                let depth = self.calculate_depth(info.ppid) + 1;
                if depth > self.max_tree_depth {
                    reasons.push(format!("process tree depth {} exceeds max {}", depth, self.max_tree_depth));
                    suspicious = true;
                }

                let children_count = parent.children.len();
                if children_count > 10 {
                    reasons.push(format!("parent has {} children (potential fork bomb or lateral movement)", children_count));
                    suspicious = true;
                }

                if name_lower == "cmd.exe" && !parent.command_line.is_empty() && !parent.command_line.contains("/c") {
                    reasons.push("cmd.exe spawned without /c flag (possible persistence)".into());
                    suspicious = true;
                }

                if (name_lower == "powershell.exe" || name_lower == "pwsh.exe")
                    && (parent_lower == "wsmprovhost.exe" || parent_lower == "winrm.exe")
                {
                    reasons.push("PowerShell spawned via WinRM (lateral movement)".into());
                    suspicious = true;
                }

                if name_lower == "mshta.exe" {
                    reasons.push("mshta.exe execution (LOLBins abuse)".into());
                    suspicious = true;
                }

                if name_lower == "regsvr32.exe" && (parent_lower == "explorer.exe" || parent_lower == "cmd.exe") {
                    reasons.push("regsvr32.exe execution (possible DLL sideloading)".into());
                    suspicious = true;
                }

                if name_lower == "rundll32.exe" && !parent_lower.contains("setup") {
                    reasons.push("rundll32.exe execution (possible DLL injection)".into());
                    suspicious = true;
                }

                if name_lower == "certutil.exe" {
                    reasons.push("certutil.exe execution (possible file download/c2)".into());
                    suspicious = true;
                }

                if name_lower == "bitsadmin.exe" {
                    reasons.push("bitsadmin.exe execution (possible BITS abuse)".into());
                    suspicious = true;
                }

                if name_lower == "msbuild.exe" && parent_lower != "devenv.exe" {
                    reasons.push("msbuild.exe execution outside Visual Studio".into());
                    suspicious = true;
                }

                drop(parent);
            }
        }

        let node = ProcessNode {
            pid: info.pid,
            ppid: info.ppid,
            name: info.name.clone(),
            path: info.path.clone(),
            command_line: info.command_line.clone(),
            user: info.user.clone(),
            children: Vec::new(),
            created_at: info.timestamp,
            terminated_at: None,
            integrity_level: info.integrity_level.clone(),
            suspicious,
            suspicion_reasons: reasons.clone(),
        };

        if let Some(mut parent) = self.nodes.get_mut(&info.ppid) {
            parent.children.push(info.pid);
        }

        self.nodes.insert(info.pid, node);

        if suspicious {
            info!(
                pid = info.pid,
                ppid = info.ppid,
                name = %info.name,
                reasons = ?reasons,
                "Suspicious process creation detected"
            );
        }

        reasons.into_iter().map(|reason| {
            SuspiciousPattern {
                pid: info.pid,
                process_name: info.name.clone(),
                pattern_type: "suspicious_parent_child".into(),
                description: reason,
                severity: EventSeverity::High,
                mitre_tactic: Some("Execution".into()),
                mitre_technique: Some("T1059".into()),
            }
        }).collect()
    }

    pub fn on_process_terminated(&self, pid: u32) {
        if let Some(mut node) = self.nodes.get_mut(&pid) {
            node.terminated_at = Some(Utc::now());
        }
    }

    pub fn get_process_tree(&self, pid: u32) -> Vec<ProcessNode> {
        let mut tree = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.build_tree(pid, &mut tree, &mut visited);
        tree
    }

    fn build_tree(&self, pid: u32, tree: &mut Vec<ProcessNode>, visited: &mut std::collections::HashSet<u32>) {
        if visited.contains(&pid) {
            return;
        }
        visited.insert(pid);

        if let Some(node) = self.nodes.get(&pid) {
            tree.push(node.clone());
            let children: Vec<u32> = node.children.clone();
            drop(node);

            for child_pid in children {
                self.build_tree(child_pid, tree, visited);
            }
        }
    }

    fn calculate_depth(&self, pid: u32) -> usize {
        let mut depth = 0;
        let mut current = pid;
        let mut visited = std::collections::HashSet::new();

        while let Some(node) = self.nodes.get(&current) {
            if visited.contains(&current) {
                break;
            }
            visited.insert(current);
            depth += 1;

            if node.ppid == 0 || depth > self.max_tree_depth {
                break;
            }
            current = node.ppid;
        }

        depth
    }

    pub fn get_all_suspicious(&self) -> Vec<ProcessNode> {
        self.nodes.iter()
            .filter(|n| n.suspicious && n.terminated_at.is_none())
            .map(|n| n.clone())
            .collect()
    }

    pub fn stats(&self) -> ProcessTreeStats {
        let total = self.nodes.len();
        let active = self.nodes.iter().filter(|n| n.terminated_at.is_none()).count();
        let terminated = total - active;
        let suspicious = self.nodes.iter().filter(|n| n.suspicious && n.terminated_at.is_none()).count();

        let mut max_depth = 0;
        for node in self.nodes.iter() {
            if node.ppid == 0 && node.terminated_at.is_none() {
                let depth = self.calculate_depth(node.pid);
                if depth > max_depth {
                    max_depth = depth;
                }
            }
        }

        let roots = self.nodes.iter().filter(|n| n.ppid == 0 && n.terminated_at.is_none()).count();

        ProcessTreeStats {
            total_processes: total,
            active_processes: active,
            terminated_processes: terminated,
            max_depth,
            suspicious_count: suspicious,
            root_count: roots,
        }
    }

    pub fn find_by_name(&self, name: &str) -> Vec<ProcessNode> {
        let name_lower = name.to_lowercase();
        self.nodes.iter()
            .filter(|n| n.name.to_lowercase().contains(&name_lower))
            .map(|n| n.clone())
            .collect()
    }

    pub fn get_orphan_processes(&self) -> Vec<ProcessNode> {
        self.nodes.iter()
            .filter(|n| {
                n.ppid != 0
                    && n.terminated_at.is_none()
                    && !self.nodes.contains_key(&n.ppid)
            })
            .map(|n| n.clone())
            .collect()
    }

    pub fn cleanup(&self, max_age_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        self.nodes.retain(|_, node| {
            match node.terminated_at {
                Some(t) => t > cutoff,
                None => true,
            }
        });
    }

    pub fn process_event(&self, event: &SecurityEvent) -> Vec<SuspiciousPattern> {
        match event {
            SecurityEvent::Process(info) => {
                if info.ppid != 0 && self.nodes.contains_key(&info.pid) {
                    self.on_process_terminated(info.pid);
                    Vec::new()
                } else {
                    self.on_process_created(info)
                }
            }
            _ => Vec::new(),
        }
    }
}

impl Default for ProcessTreeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.into(),
            path: format!("C:\\Windows\\System32\\{}", name),
            command_line: String::new(),
            user: "SYSTEM".into(),
            hash_sha256: None,
            integrity_level: Some("System".into()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_tracker_new() {
        let tracker = ProcessTreeTracker::new();
        let stats = tracker.stats();
        assert_eq!(stats.total_processes, 0);
    }

    #[test]
    fn test_process_creation_tracking() {
        let tracker = ProcessTreeTracker::new();
        let info = make_process(100, 1, "notepad.exe");
        let patterns = tracker.on_process_created(&info);
        assert!(patterns.is_empty());
        let stats = tracker.stats();
        assert_eq!(stats.total_processes, 1);
        assert_eq!(stats.active_processes, 1);
    }

    #[test]
    fn test_parent_child_relationship() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "system"));
        tracker.on_process_created(&make_process(100, 1, "explorer.exe"));
        tracker.on_process_created(&make_process(200, 100, "cmd.exe"));

        let tree = tracker.get_process_tree(1);
        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_suspicious_parent_child_detection() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "wininit.exe"));
        let patterns = tracker.on_process_created(&make_process(100, 1, "cmd.exe"));
        assert!(!patterns.is_empty());
        assert_eq!(patterns[0].severity, EventSeverity::High);
    }

    #[test]
    fn test_suspicious_powershell_from_svchost() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "services.exe"));
        tracker.on_process_created(&make_process(100, 1, "svchost.exe"));
        let patterns = tracker.on_process_created(&make_process(200, 100, "powershell.exe"));
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_suspicious_powershell_from_office() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "explorer.exe"));
        tracker.on_process_created(&make_process(100, 1, "winword.exe"));
        let patterns = tracker.on_process_created(&make_process(200, 100, "powershell.exe"));
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_suspicious_mshta() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "explorer.exe"));
        let patterns = tracker.on_process_created(&make_process(100, 1, "mshta.exe"));
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_suspicious_certutil() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "explorer.exe"));
        let patterns = tracker.on_process_created(&make_process(100, 1, "certutil.exe"));
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_process_termination() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(100, 1, "notepad.exe"));
        tracker.on_process_terminated(100);
        let stats = tracker.stats();
        assert_eq!(stats.active_processes, 0);
        assert_eq!(stats.terminated_processes, 1);
    }

    #[test]
    fn test_get_all_suspicious() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(1, 0, "system"));
        tracker.on_process_created(&make_process(100, 1, "explorer.exe"));
        tracker.on_process_created(&make_process(200, 100, "mshta.exe"));

        let suspicious = tracker.get_all_suspicious();
        assert!(!suspicious.is_empty());
    }

    #[test]
    fn test_find_by_name() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(100, 1, "notepad.exe"));
        tracker.on_process_created(&make_process(200, 1, "notepad.exe"));

        let found = tracker.find_by_name("notepad");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_orphan_processes() {
        let tracker = ProcessTreeTracker::new();
        tracker.on_process_created(&make_process(100, 999, "orphan.exe"));
        let orphans = tracker.get_orphan_processes();
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn test_process_event_dispatch() {
        let tracker = ProcessTreeTracker::new();
        let event = SecurityEvent::Process(make_process(100, 1, "notepad.exe"));
        let patterns = tracker.process_event(&event);
        assert!(patterns.is_empty());
        assert_eq!(tracker.stats().total_processes, 1);
    }

    #[test]
    fn test_cleanup() {
        let tracker = ProcessTreeTracker::new();
        let mut info = make_process(100, 1, "old.exe");
        tracker.on_process_created(&info);
        tracker.on_process_terminated(100);

        tracker.cleanup(0);
        assert_eq!(tracker.stats().total_processes, 0);
    }
}
