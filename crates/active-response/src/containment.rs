use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainmentLevel {
    None,
    Partial,
    Full,
    Emergency,
}

impl ContainmentLevel {
    pub fn description(&self) -> &str {
        match self {
            ContainmentLevel::None => "No containment active",
            ContainmentLevel::Partial => "Block external connections, allow internal",
            ContainmentLevel::Full => "Block all connections except management IP",
            ContainmentLevel::Emergency => "Kill all non-essential processes and block everything",
        }
    }

    pub fn numeric_value(&self) -> u8 {
        match self {
            ContainmentLevel::None => 0,
            ContainmentLevel::Partial => 1,
            ContainmentLevel::Full => 2,
            ContainmentLevel::Emergency => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentState {
    pub current_level: ContainmentLevel,
    pub activated_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub management_ip: Option<String>,
    pub blocked_rules: Vec<String>,
    pub allowed_rules: Vec<String>,
    pub metadata: HashMap<String, String>,
}

pub struct ContainmentManager {
    state: ContainmentState,
    rule_prefix: String,
}

impl ContainmentManager {
    pub fn new() -> Self {
        Self {
            state: ContainmentState {
                current_level: ContainmentLevel::None,
                activated_at: None,
                deactivated_at: None,
                management_ip: None,
                blocked_rules: Vec::new(),
                allowed_rules: Vec::new(),
                metadata: HashMap::new(),
            },
            rule_prefix: "RS_Containment".to_string(),
        }
    }

    pub fn get_current_level(&self) -> &ContainmentLevel {
        &self.state.current_level
    }

    pub fn get_state(&self) -> &ContainmentState {
        &self.state
    }

    pub fn set_containment_level(
        &mut self,
        level: ContainmentLevel,
        management_ip: Option<&str>,
    ) -> Result<(), String> {
        let previous_level = self.state.current_level.clone();

        if level == previous_level {
            info!("Containment level already at {:?}", level);
            return Ok(());
        }

        if level.numeric_value() > previous_level.numeric_value() {
            info!(
                "Escalating containment from {:?} to {:?}",
                previous_level, level
            );
            self.apply_containment_level(&level, management_ip)?;
        } else {
            info!(
                "De-escalating containment from {:?} to {:?}",
                previous_level, level
            );
            self.remove_containment_level(&level)?;
        }

        self.state.current_level = level.clone();
        self.state.activated_at = Some(Utc::now());
        if let Some(mip) = management_ip {
            self.state.management_ip = Some(mip.to_string());
        }

        info!("Containment level set to {:?}", level);
        Ok(())
    }

    pub fn restore_connectivity(&mut self) -> Result<(), String> {
        info!("Restoring full connectivity - removing all containment rules");

        for rule_name in &self.state.blocked_rules {
            self.remove_firewall_rule(rule_name)?;
        }

        self.state.blocked_rules.clear();
        self.state.allowed_rules.clear();
        self.state.current_level = ContainmentLevel::None;
        self.state.deactivated_at = Some(Utc::now());

        self.enable_all_firewall_profiles()?;
        info!("Full connectivity restored");
        Ok(())
    }

    fn apply_containment_level(
        &mut self,
        level: &ContainmentLevel,
        management_ip: Option<&str>,
    ) -> Result<(), String> {
        match level {
            ContainmentLevel::None => {
                self.restore_connectivity()?;
            }
            ContainmentLevel::Partial => {
                self.apply_partial_containment()?;
            }
            ContainmentLevel::Full => {
                let mip = management_ip
                    .ok_or("Management IP required for full containment")?;
                self.apply_full_containment(mip)?;
            }
            ContainmentLevel::Emergency => {
                let mip = management_ip
                    .ok_or("Management IP required for emergency containment")?;
                self.apply_emergency_containment(mip)?;
            }
        }
        Ok(())
    }

    fn apply_partial_containment(&mut self) -> Result<(), String> {
        let rules = vec![
            ("RS_Cont_Block_Inbound_External", "in", "block", ""),
            ("RS_Cont_Block_Outbound_External", "out", "block", ""),
            ("RS_Cont_Allow_Loopback", "both", "allow", "remoteip=127.0.0.1"),
        ];

        for (name, dir, action, extra) in &rules {
            let name_arg = format!("name={}", name);
            let mut args = vec![
                "advfirewall", "firewall", "add", "rule",
                &name_arg,
                "dir", dir,
                "action", action,
            ];
            if !extra.is_empty() {
                args.push(extra);
            }
            args.push("enable=yes");

            let output = std::process::Command::new("netsh")
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to add rule {}: {}", name, e))?;

            if output.status.success() {
                self.state.blocked_rules.push(name.to_string());
                info!("Applied partial containment rule: {}", name);
            } else {
                warn!("Failed to apply rule {}: {}", name,
                    String::from_utf8_lossy(&output.stderr));
            }
        }

        Ok(())
    }

    fn apply_full_containment(&mut self, management_ip: &str) -> Result<(), String> {
        self.remove_containment_level(&ContainmentLevel::Partial)?;

        let rules = vec![
            (format!("{}_Block_All_In", self.rule_prefix), "in".to_string(), "block".to_string()),
            (format!("{}_Block_All_Out", self.rule_prefix), "out".to_string(), "block".to_string()),
        ];

        for (name, dir, action) in &rules {
            let output = std::process::Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", name),
                    "dir", dir,
                    "action", action,
                    "enable=yes",
                ])
                .output()
                .map_err(|e| format!("Failed to add rule {}: {}", name, e))?;

            if output.status.success() {
                self.state.blocked_rules.push(name.clone());
            } else {
                warn!("Failed to apply rule {}: {}", name,
                    String::from_utf8_lossy(&output.stderr));
            }
        }

        let allow_mgmt_rules = vec![
            (
                format!("{}_Allow_Mgmt_In_{}", self.rule_prefix, management_ip.replace('.', "_")),
                "in".to_string(),
                format!("remoteip={}", management_ip),
            ),
            (
                format!("{}_Allow_Mgmt_Out_{}", self.rule_prefix, management_ip.replace('.', "_")),
                "out".to_string(),
                format!("remoteip={}", management_ip),
            ),
        ];

        for (name, dir, remoteip) in &allow_mgmt_rules {
            let output = std::process::Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", name),
                    "dir", dir,
                    "action", "allow",
                    remoteip,
                    "enable=yes",
                ])
                .output()
                .map_err(|e| format!("Failed to add allow rule {}: {}", name, e))?;

            if output.status.success() {
                self.state.allowed_rules.push(name.clone());
            }
        }

        info!("Full containment applied, management IP: {}", management_ip);
        Ok(())
    }

    fn apply_emergency_containment(&mut self, management_ip: &str) -> Result<(), String> {
        self.apply_full_containment(management_ip)?;

        self.kill_non_essential_processes()?;

        info!("Emergency containment applied");
        Ok(())
    }

    fn kill_non_essential_processes(&self) -> Result<(), String> {
        let essential_processes = vec![
            "System", "svchost", "csrss", "wininit", "smss",
            "lsass", "services", "winlogon", "dwm", "conhost",
            "sihost", "ShellExperienceHost", "RuntimeBroker",
        ];

        let output = std::process::Command::new("tasklist")
            .args(&["/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| format!("Failed to list processes: {}", e))?;

        let tasklist = String::from_utf8_lossy(&output.stdout);

        for line in tasklist.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if let Some(process_name) = parts.first() {
                let clean_name = process_name.trim_matches('"').to_lowercase();

                if essential_processes.iter().any(|ep| clean_name.contains(&ep.to_lowercase())) {
                    continue;
                }

                if let Some(pid_str) = parts.get(1) {
                    let clean_pid = pid_str.trim_matches('"');
                    if let Ok(pid) = clean_pid.parse::<u32>() {
                        let kill_output = std::process::Command::new("taskkill")
                            .args(&["/F", "/PID", &pid.to_string()])
                            .output();

                        match kill_output {
                            Ok(o) if o.status.success() => {
                                info!("Killed non-essential process: {} (PID: {})", clean_name, pid);
                            }
                            _ => {
                                warn!("Could not kill process: {} (PID: {})", clean_name, pid);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn remove_containment_level(&self, level: &ContainmentLevel) -> Result<(), String> {
        match level {
            ContainmentLevel::Partial => {
                let rules_to_remove = vec![
                    "RS_Cont_Block_Inbound_External",
                    "RS_Cont_Block_Outbound_External",
                    "RS_Cont_Allow_Loopback",
                ];
                for rule in rules_to_remove {
                    self.remove_firewall_rule(rule)?;
                }
            }
            ContainmentLevel::Full | ContainmentLevel::Emergency => {
                let rules_to_remove = vec![
                    format!("{}_Block_All_In", self.rule_prefix),
                    format!("{}_Block_All_Out", self.rule_prefix),
                ];
                for rule in rules_to_remove {
                    self.remove_firewall_rule(&rule)?;
                }

                for rule in &self.state.allowed_rules {
                    self.remove_firewall_rule(rule)?;
                }
            }
            ContainmentLevel::None => {}
        }
        Ok(())
    }

    fn remove_firewall_rule(&self, rule_name: &str) -> Result<(), String> {
        let output = std::process::Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={}", rule_name),
            ])
            .output()
            .map_err(|e| format!("Failed to remove rule {}: {}", rule_name, e))?;

        if output.status.success() {
            info!("Removed firewall rule: {}", rule_name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("did not exist") {
                warn!("Failed to remove rule {}: {}", rule_name, stderr);
            }
        }
        Ok(())
    }

    fn enable_all_firewall_profiles(&self) -> Result<(), String> {
        for profile in &["DomainProfiles", "PrivateProfiles", "PublicProfiles"] {
            let output = std::process::Command::new("netsh")
                .args(&[
                    "advfirewall", "set", profile, "state", "ON",
                ])
                .output()
                .map_err(|e| format!("Failed to enable firewall profile {}: {}", profile, e))?;

            if !output.status.success() {
                warn!("Failed to enable firewall profile: {}", profile);
            }
        }
        Ok(())
    }

    pub fn get_blocked_rules(&self) -> &[String] {
        &self.state.blocked_rules
    }

    pub fn get_allowed_rules(&self) -> &[String] {
        &self.state.allowed_rules
    }
}

impl Default for ContainmentManager {
    fn default() -> Self {
        Self::new()
    }
}
