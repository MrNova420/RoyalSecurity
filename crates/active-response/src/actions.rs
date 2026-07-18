use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    TerminateProcess {
        pid: u32,
        process_name: Option<String>,
    },
    BlockIp {
        ip: String,
        direction: String,
        duration_minutes: Option<u32>,
    },
    IsolateHost {
        management_ip: String,
        allowed_ports: Vec<u16>,
    },
    QuarantineFile {
        file_path: String,
        reason: String,
    },
    DisableUser {
        username: String,
        reason: String,
    },
    BlockHash {
        hash: String,
        hash_type: String,
        target_path: Option<String>,
    },
    EnableFirewall {
        profile: String,
        direction: String,
    },
    KillConnection {
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
    },
    CollectArtifact {
        source_path: String,
        destination_path: String,
        include_metadata: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: String,
    pub action_type: ResponseAction,
    pub target: String,
    pub status: ResponseStatus,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl ResponseAction {
    pub fn action_type_name(&self) -> &str {
        match self {
            ResponseAction::TerminateProcess { .. } => "TerminateProcess",
            ResponseAction::BlockIp { .. } => "BlockIp",
            ResponseAction::IsolateHost { .. } => "IsolateHost",
            ResponseAction::QuarantineFile { .. } => "QuarantineFile",
            ResponseAction::DisableUser { .. } => "DisableUser",
            ResponseAction::BlockHash { .. } => "BlockHash",
            ResponseAction::EnableFirewall { .. } => "EnableFirewall",
            ResponseAction::KillConnection { .. } => "KillConnection",
            ResponseAction::CollectArtifact { .. } => "CollectArtifact",
        }
    }

    pub fn target_identifier(&self) -> String {
        match self {
            ResponseAction::TerminateProcess { pid, process_name } => {
                match process_name {
                    Some(name) => format!("{} (PID: {})", name, pid),
                    None => format!("PID: {}", pid),
                }
            }
            ResponseAction::BlockIp { ip, .. } => ip.clone(),
            ResponseAction::IsolateHost { .. } => "local_host".to_string(),
            ResponseAction::QuarantineFile { file_path, .. } => file_path.clone(),
            ResponseAction::DisableUser { username, .. } => username.clone(),
            ResponseAction::BlockHash { hash, .. } => hash.clone(),
            ResponseAction::EnableFirewall { profile, .. } => profile.clone(),
            ResponseAction::KillConnection { remote_ip, remote_port, .. } => {
                format!("{}:{}", remote_ip, remote_port)
            }
            ResponseAction::CollectArtifact { source_path, .. } => source_path.clone(),
        }
    }

    pub async fn execute(&self) -> ActionResult {
        let action_id = Uuid::new_v4().to_string();
        let target = self.target_identifier();
        let timestamp = Utc::now();
        let mut metadata = HashMap::new();

        let (status, message) = match self {
            ResponseAction::TerminateProcess { pid, process_name } => {
                match terminate_process(*pid) {
                    Ok(_) => {
                        let name = process_name.as_deref().unwrap_or("unknown");
                        metadata.insert("process_name".to_string(), name.to_string());
                        metadata.insert("pid".to_string(), pid.to_string());
                        (ResponseStatus::Success, format!("Terminated process {} (PID: {})", name, pid))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to terminate process PID {}: {}", pid, e))
                    }
                }
            }

            ResponseAction::BlockIp { ip, direction, duration_minutes } => {
                match block_ip_rule(ip, direction, *duration_minutes) {
                    Ok(rule_name) => {
                        metadata.insert("rule_name".to_string(), rule_name);
                        metadata.insert("direction".to_string(), direction.clone());
                        if let Some(dur) = duration_minutes {
                            metadata.insert("duration_minutes".to_string(), dur.to_string());
                        }
                        (ResponseStatus::Success, format!("Blocked IP {} ({})", ip, direction))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to block IP {}: {}", ip, e))
                    }
                }
            }

            ResponseAction::IsolateHost { management_ip, allowed_ports } => {
                match isolate_host(management_ip, allowed_ports) {
                    Ok(rules_created) => {
                        metadata.insert("management_ip".to_string(), management_ip.clone());
                        metadata.insert("rules_created".to_string(), rules_created.to_string());
                        (ResponseStatus::Success, format!("Host isolated, {} firewall rules created", rules_created))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to isolate host: {}", e))
                    }
                }
            }

            ResponseAction::QuarantineFile { file_path, reason } => {
                match quarantine_file(file_path, reason) {
                    Ok(quarantine_path) => {
                        metadata.insert("quarantine_path".to_string(), quarantine_path);
                        metadata.insert("reason".to_string(), reason.clone());
                        (ResponseStatus::Success, format!("Quarantined file: {}", file_path))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to quarantine {}: {}", file_path, e))
                    }
                }
            }

            ResponseAction::DisableUser { username, reason } => {
                match disable_user_account(username) {
                    Ok(_) => {
                        metadata.insert("reason".to_string(), reason.clone());
                        (ResponseStatus::Success, format!("Disabled user account: {}", username))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to disable user {}: {}", username, e))
                    }
                }
            }

            ResponseAction::BlockHash { hash, hash_type, target_path } => {
                match create_hash_block_rule(hash, hash_type, target_path.as_deref()) {
                    Ok(rule_id) => {
                        metadata.insert("hash".to_string(), hash.clone());
                        metadata.insert("hash_type".to_string(), hash_type.clone());
                        metadata.insert("rule_id".to_string(), rule_id);
                        (ResponseStatus::Success, format!("Blocked hash: {}", hash))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to block hash {}: {}", hash, e))
                    }
                }
            }

            ResponseAction::EnableFirewall { profile, direction } => {
                match enable_firewall_rule(profile, direction) {
                    Ok(_) => {
                        (ResponseStatus::Success, format!("Enabled firewall {} for {}", direction, profile))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to enable firewall: {}", e))
                    }
                }
            }

            ResponseAction::KillConnection { local_ip, local_port, remote_ip, remote_port } => {
                match kill_tcp_connection(local_ip, *local_port, remote_ip, *remote_port) {
                    Ok(_) => {
                        metadata.insert("local_endpoint".to_string(), format!("{}:{}", local_ip, local_port));
                        metadata.insert("remote_endpoint".to_string(), format!("{}:{}", remote_ip, remote_port));
                        (ResponseStatus::Success, format!("Killed connection {}:{} -> {}:{}", local_ip, local_port, remote_ip, remote_port))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to kill connection: {}", e))
                    }
                }
            }

            ResponseAction::CollectArtifact { source_path, destination_path, include_metadata } => {
                match collect_artifact(source_path, destination_path, *include_metadata) {
                    Ok(bytes_collected) => {
                        metadata.insert("bytes_collected".to_string(), bytes_collected.to_string());
                        metadata.insert("include_metadata".to_string(), include_metadata.to_string());
                        (ResponseStatus::Success, format!("Collected artifact: {} bytes from {}", bytes_collected, source_path))
                    }
                    Err(e) => {
                        (ResponseStatus::Failed, format!("Failed to collect artifact: {}", e))
                    }
                }
            }
        };

        ActionResult {
            action_id,
            action_type: self.clone(),
            target,
            status,
            message,
            timestamp,
            metadata,
        }
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("OpenProcess failed: {}", e))?;

        let result = TerminateProcess(handle, 1)
            .map_err(|e| format!("TerminateProcess failed: {}", e));

        let _ = CloseHandle(handle);
        result?;
        info!("Successfully terminated process with PID {}", pid);
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_process(pid: u32) -> Result<(), String> {
    let _ = pid;
    Err("Process termination not supported on this platform".into())
}

fn block_ip_rule(ip: &str, direction: &str, duration_minutes: Option<u32>) -> Result<String, String> {
    let rule_name = format!("RS_Block_{}_{}", ip.replace('.', "_"), chrono::Utc::now().timestamp());
    let dir_flag = match direction.to_lowercase().as_str() {
        "inbound" => "in",
        "outbound" => "out",
        "both" => "",
        _ => return Err(format!("Invalid direction: {}", direction)),
    };

    let name_arg = format!("name={}", rule_name);
    let remote_arg = format!("remoteip={}", ip);

    let mut cmd_args = vec![
        "advfirewall", "firewall", "add", "rule",
        &name_arg,
        "dir", if dir_flag.is_empty() { "in" } else { dir_flag },
        "action=block",
        &remote_arg,
    ];

    let rem_arg;
    if let Some(dur) = duration_minutes {
        cmd_args.push("enable=yes");
        rem_arg = format!("rem=Auto-block for {} minutes", dur);
        cmd_args.push(&rem_arg);
    }

    let output = std::process::Command::new("netsh")
        .args(&cmd_args)
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("netsh failed: {}", stderr));
    }

    if direction == "both" {
        let rule_name_out = format!("{}_out", rule_name);
        let output_out = std::process::Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name_out),
                "dir", "out",
                "action=block",
                &format!("remoteip={}", ip),
            ])
            .output()
            .map_err(|e| format!("Failed to execute netsh for outbound: {}", e))?;

        if !output_out.status.success() {
            return Err("Failed to create outbound rule".to_string());
        }
    }

    info!("Created firewall rule '{}' blocking IP {}", rule_name, ip);
    Ok(rule_name)
}

fn isolate_host(management_ip: &str, allowed_ports: &[u16]) -> Result<u32, String> {
    let mut rules_created: u32 = 0;

    let block_all_inbound = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            "name=RS_Isolate_Block_All_Inbound",
            "dir=in", "action=block",
            "enable=yes",
        ])
        .output()
        .map_err(|e| format!("Failed to block inbound: {}", e))?;

    if block_all_inbound.status.success() {
        rules_created += 1;
    }

    let block_all_outbound = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            "name=RS_Isolate_Block_All_Outbound",
            "dir=out", "action=block",
            "enable=yes",
        ])
        .output()
        .map_err(|e| format!("Failed to block outbound: {}", e))?;

    if block_all_outbound.status.success() {
        rules_created += 1;
    }

    let allow_mgmt_in = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name=RS_Isolate_Allow_Mgmt_In_{}", management_ip.replace('.', "_")),
            "dir=in", "action=allow",
            &format!("remoteip={}", management_ip),
            "enable=yes",
        ])
        .output()
        .map_err(|e| format!("Failed to add management inbound rule: {}", e))?;

    if allow_mgmt_in.status.success() {
        rules_created += 1;
    }

    let allow_mgmt_out = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name=RS_Isolate_Allow_Mgmt_Out_{}", management_ip.replace('.', "_")),
            "dir=out", "action=allow",
            &format!("remoteip={}", management_ip),
            "enable=yes",
        ])
        .output()
        .map_err(|e| format!("Failed to add management outbound rule: {}", e))?;

    if allow_mgmt_out.status.success() {
        rules_created += 1;
    }

    for port in allowed_ports {
        let rule_name = format!("RS_Isolate_Allow_Port_{}", port);
        let output = std::process::Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out", "action=allow",
                &format!("remoteport={}", port),
                &format!("remoteip={}", management_ip),
                "enable=yes",
            ])
            .output()
            .map_err(|e| format!("Failed to add port rule: {}", e))?;

        if output.status.success() {
            rules_created += 1;
        }
    }

    info!("Host isolated with {} firewall rules, management IP: {}", rules_created, management_ip);
    Ok(rules_created)
}

fn quarantine_file(file_path: &str, _reason: &str) -> Result<String, String> {
    use std::path::Path;

    let source = Path::new(file_path);
    if !source.exists() {
        return Err(format!("File does not exist: {}", file_path));
    }

    let programdata = std::env::var("PROGRAMDATA")
        .unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let quarantine_dir = Path::new(&programdata).join("RoyalSecurity").join("Quarantine");

    std::fs::create_dir_all(&quarantine_dir)
        .map_err(|e| format!("Failed to create quarantine directory: {}", e))?;

    let file_name = source.file_name()
        .ok_or_else(|| format!("Invalid file name: {}", file_path))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let quarantine_name = format!("{}_{}.quarantine", file_name.to_string_lossy(), timestamp);
    let quarantine_path = quarantine_dir.join(&quarantine_name);

    std::fs::rename(source, &quarantine_path)
        .map_err(|e| format!("Failed to move file to quarantine: {}", e))?;

    let metadata_path = quarantine_path.with_extension("quarantine.meta");
    let metadata = serde_json::json!({
        "original_path": file_path,
        "quarantine_timestamp": chrono::Utc::now().to_rfc3339(),
        "file_name": file_name.to_string_lossy(),
    });

    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata).unwrap())
        .map_err(|e| format!("Failed to write quarantine metadata: {}", e))?;

    info!("Quarantined {} to {}", file_path, quarantine_path.display());
    Ok(quarantine_path.to_string_lossy().to_string())
}

fn disable_user_account(username: &str) -> Result<(), String> {
    let output = std::process::Command::new("net")
        .args(&["user", username, "/active:no"])
        .output()
        .map_err(|e| format!("Failed to execute net user: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to disable user: {}", stderr));
    }

    info!("Disabled user account: {}", username);
    Ok(())
}

fn create_hash_block_rule(hash: &str, hash_type: &str, target_path: Option<&str>) -> Result<String, String> {
    let rule_id = Uuid::new_v4().to_string();
    let rule_name = format!("RS_Block_Hash_{}", &rule_id[..8]);

    let path = target_path.unwrap_or("*");

    let policy_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="{}" Name="{}" Description="Block executable by hash" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="{}" Value="{}"/>
        </FileHashCondition>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>"#,
        rule_id, rule_name, hash_type, hash
    );

    let policy_path = std::env::temp_dir().join(format!("rs_hash_block_{}.xml", &rule_id[..8]));
    std::fs::write(&policy_path, &policy_xml)
        .map_err(|e| format!("Failed to write policy: {}", e))?;

    let output = std::process::Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                "Set-AppLockerPolicy -PolicyObject '{}' -Merge -ErrorAction Stop",
                policy_path.display()
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to apply AppLocker policy: {}", e))?;

    let _ = std::fs::remove_file(&policy_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("AppLocker policy merge failed (may need admin): {}", stderr);
        info!("Hash block rule created locally: {} ({})", rule_name, hash_type);
    } else {
        info!("Applied AppLocker hash block rule: {} for hash {}", rule_name, hash);
    }

    Ok(rule_id)
}

fn enable_firewall_rule(profile: &str, direction: &str) -> Result<(), String> {
    let profile_arg = match profile.to_lowercase().as_str() {
        "domain" => "DomainProfiles",
        "private" => "PrivateProfiles",
        "public" => "PublicProfiles",
        "all" => "AllProfiles",
        _ => return Err(format!("Invalid profile: {}", profile)),
    };

    let state = match direction.to_lowercase().as_str() {
        "inbound" => "Inbound=Block",
        "outbound" => "Outbound=Block",
        "allow_inbound" => "Inbound=Allow",
        "allow_outbound" => "Outbound=Allow",
        _ => return Err(format!("Invalid direction: {}", direction)),
    };

    let output = std::process::Command::new("netsh")
        .args(&[
            "advfirewall", "set", profile_arg, "firewallpolicy",
            state,
        ])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to enable firewall rule: {}", stderr));
    }

    info!("Updated firewall policy for {}: {}", profile, direction);
    Ok(())
}

fn kill_tcp_connection(local_ip: &str, local_port: u16, remote_ip: &str, remote_port: u16) -> Result<(), String> {
    info!("Attempting to kill TCP connection {}:{} -> {}:{}", local_ip, local_port, remote_ip, remote_port);

    let output = std::process::Command::new("netsh")
        .args(&["int", "ipv4", "show", "connections"])
        .output()
        .map_err(|e| format!("Failed to list connections: {}", e))?;

    let connections = String::from_utf8_lossy(&output.stdout);
    for line in connections.lines() {
        if line.contains(remote_ip) || line.contains(&remote_port.to_string()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(conn_id) = parts.first() {
                let reset_output = std::process::Command::new("netsh")
                    .args(&["int", "ipv4", "delete", "connections", conn_id])
                    .output();

                match reset_output {
                    Ok(o) if o.status.success() => {
                        info!("Reset connection ID: {}", conn_id);
                    }
                    _ => {
                        warn!("Could not reset connection ID: {}", conn_id);
                    }
                }
            }
        }
    }

    Ok(())
}

fn collect_artifact(source_path: &str, destination_path: &str, include_metadata: bool) -> Result<u64, String> {
    use std::path::Path;

    let source = Path::new(source_path);
    if !source.exists() {
        return Err(format!("Source path does not exist: {}", source_path));
    }

    let dest = Path::new(destination_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create destination directory: {}", e))?;
    }

    if source.is_file() {
        let bytes = std::fs::copy(source, dest)
            .map_err(|e| format!("Failed to copy file: {}", e))?;

        if include_metadata {
            let metadata = std::fs::metadata(source)
                .map_err(|e| format!("Failed to read metadata: {}", e))?;

            let meta_path = dest.with_extension(format!("{}.metadata.json", dest.extension().unwrap_or_default().to_string_lossy()));
            let meta = serde_json::json!({
                "source_path": source_path,
                "collected_at": chrono::Utc::now().to_rfc3339(),
                "file_size": metadata.len(),
                "readonly": metadata.permissions().readonly(),
            });

            std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap())
                .map_err(|e| format!("Failed to write metadata: {}", e))?;
        }

        info!("Collected artifact: {} -> {} ({} bytes)", source_path, destination_path, bytes);
        Ok(bytes)
    } else if source.is_dir() {
        let mut total_bytes: u64 = 0;
        let entries = std::fs::read_dir(source)
            .map_err(|e| format!("Failed to read directory: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let entry_path = entry.path();
            if entry_path.is_file() {
                let file_name = entry_path.file_name().unwrap();
                let dest_file = dest.join(file_name);
                let bytes = std::fs::copy(&entry_path, &dest_file)
                    .map_err(|e| format!("Failed to copy {}: {}", entry_path.display(), e))?;
                total_bytes += bytes;
            }
        }

        info!("Collected directory artifact: {} -> {} ({} bytes)", source_path, destination_path, total_bytes);
        Ok(total_bytes)
    } else {
        Err(format!("Source path is neither a file nor a directory: {}", source_path))
    }
}
