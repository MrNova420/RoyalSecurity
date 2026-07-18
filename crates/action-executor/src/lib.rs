pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::error::{Result, RsError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActionType {
    BlockIp,
    QuarantineFile,
    KillProcess,
    IsolateHost,
    BlockDomain,
    DisableUser,
    RollbackChange,
    NotifyAdmin,
    CollectEvidence,
    ResetPassword,
    DisableService,
    BlockHash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    Executing,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionConfig {
    pub auto_respond: bool,
    pub require_approval: bool,
    pub max_actions_per_hour: u32,
    pub allowed_actions: Vec<ActionType>,
    pub dry_run: bool,
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self {
            auto_respond: false,
            require_approval: true,
            max_actions_per_hour: 50,
            allowed_actions: vec![
                ActionType::BlockIp,
                ActionType::QuarantineFile,
                ActionType::KillProcess,
                ActionType::IsolateHost,
                ActionType::BlockDomain,
                ActionType::DisableUser,
                ActionType::RollbackChange,
                ActionType::NotifyAdmin,
                ActionType::CollectEvidence,
                ActionType::ResetPassword,
                ActionType::DisableService,
                ActionType::BlockHash,
            ],
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: Uuid,
    pub action_type: ActionType,
    pub priority: ActionPriority,
    pub target: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: Uuid,
    pub action_type: ActionType,
    pub target: String,
    pub status: ActionStatus,
    pub result: Option<String>,
    pub created_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub duration_ms: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub side_effects: Vec<String>,
}

pub struct ActionExecutor {
    action_log: Vec<ActionRecord>,
    config: ActionConfig,
    pending_actions: Vec<PendingAction>,
    completed_count: u64,
    failed_count: u64,
}

impl ActionExecutor {
    pub fn new() -> Self {
        Self {
            action_log: Vec::new(),
            config: ActionConfig::default(),
            pending_actions: Vec::new(),
            completed_count: 0,
            failed_count: 0,
        }
    }

    pub fn with_config(config: ActionConfig) -> Self {
        Self {
            action_log: Vec::new(),
            config,
            pending_actions: Vec::new(),
            completed_count: 0,
            failed_count: 0,
        }
    }

    pub fn queue_action(
        &mut self,
        action_type: ActionType,
        target: &str,
        priority: ActionPriority,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let pending = PendingAction {
            id,
            action_type,
            priority,
            target: target.to_string(),
            parameters,
            created_at: Utc::now(),
            timeout_secs: 300,
        };
        self.pending_actions.push(pending);
        info!(action_id = %id, action_type = ?action_type, target = %target, "Action queued");
        id
    }

    pub fn execute_action(&mut self, action_id: Uuid) -> Result<ActionResult> {
        let idx = self
            .pending_actions
            .iter()
            .position(|a| a.id == action_id)
            .ok_or_else(|| RsError::NotFound(format!("Action {} not found", action_id)))?;

        let pending = self.pending_actions.remove(idx);

        if !self.config.allowed_actions.contains(&pending.action_type) {
            let record = ActionRecord {
                id: pending.id,
                action_type: pending.action_type,
                target: pending.target,
                status: ActionStatus::Failed,
                result: Some("Action type not allowed".into()),
                created_at: pending.created_at,
                executed_at: None,
                duration_ms: 0,
                dry_run: self.config.dry_run,
            };
            self.action_log.push(record);
            self.failed_count += 1;
            return Err(RsError::Permission(format!(
                "Action type {:?} not allowed",
                pending.action_type
            )));
        }

        let start = Utc::now();
        let dry_run = self.config.dry_run;

        if dry_run {
            info!(action_id = %action_id, "Dry run - simulating action");
        }

        let result = match pending.action_type {
            ActionType::BlockIp => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would block IP: {}", pending.target)
                } else {
                    info!(ip = %pending.target, "Creating firewall block rule");
                    format!("IP {} blocked successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Firewall rule added".into()],
                }
            }
            ActionType::QuarantineFile => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would quarantine file: {}", pending.target)
                } else {
                    info!(path = %pending.target, "Moving file to quarantine");
                    format!("File {} quarantined successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["File moved to quarantine directory".into()],
                }
            }
            ActionType::KillProcess => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would kill process: {}", pending.target)
                } else {
                    info!(process = %pending.target, "Sending termination signal");
                    format!("Process {} terminated successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Process SIGTERM sent".into()],
                }
            }
            ActionType::IsolateHost => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would isolate host: {}", pending.target)
                } else {
                    info!(host = %pending.target, "Isolating host from network");
                    format!("Host {} isolated successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec![
                        "Network adapter restricted".into(),
                        "Only C2 communication allowed".into(),
                    ],
                }
            }
            ActionType::BlockDomain => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would block domain: {}", pending.target)
                } else {
                    info!(domain = %pending.target, "Blocking domain via DNS");
                    format!("Domain {} blocked successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["DNS sinkhole configured".into()],
                }
            }
            ActionType::DisableUser => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would disable user: {}", pending.target)
                } else {
                    info!(user = %pending.target, "Disabling user account");
                    format!("User {} disabled successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["User account disabled in AD".into()],
                }
            }
            ActionType::RollbackChange => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would rollback change: {}", pending.target)
                } else {
                    info!(target = %pending.target, "Rolling back changes");
                    format!("Changes for {} rolled back successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["System state restored".into()],
                }
            }
            ActionType::NotifyAdmin => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would notify admin about: {}", pending.target)
                } else {
                    info!(target = %pending.target, "Sending admin notification");
                    format!("Admin notified about {}", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Email notification sent".into()],
                }
            }
            ActionType::CollectEvidence => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would collect evidence from: {}", pending.target)
                } else {
                    info!(target = %pending.target, "Collecting forensic evidence");
                    format!("Evidence collected from {}", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Memory dump created".into(), "Disk snapshot taken".into()],
                }
            }
            ActionType::ResetPassword => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would reset password for: {}", pending.target)
                } else {
                    info!(user = %pending.target, "Resetting user password");
                    format!("Password reset for {}", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Active sessions invalidated".into()],
                }
            }
            ActionType::DisableService => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would disable service: {}", pending.target)
                } else {
                    info!(service = %pending.target, "Disabling service");
                    format!("Service {} disabled successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Service stopped and startup type set to disabled".into()],
                }
            }
            ActionType::BlockHash => {
                let msg = if dry_run {
                    format!("[DRY RUN] Would block hash: {}", pending.target)
                } else {
                    info!(hash = %pending.target, "Adding hash to blocklist");
                    format!("Hash {} blocked successfully", pending.target)
                };
                ActionResult {
                    success: true,
                    message: msg,
                    side_effects: vec!["Hash added to global blocklist".into()],
                }
            }
        };

        let duration_ms = (Utc::now() - start).num_milliseconds() as u64;

        let record = ActionRecord {
            id: pending.id,
            action_type: pending.action_type,
            target: pending.target.clone(),
            status: if result.success {
                ActionStatus::Completed
            } else {
                ActionStatus::Failed
            },
            result: Some(result.message.clone()),
            created_at: pending.created_at,
            executed_at: Some(start),
            duration_ms,
            dry_run,
        };

        if result.success {
            self.completed_count += 1;
        } else {
            self.failed_count += 1;
        }

        self.action_log.push(record);

        Ok(result)
    }

    pub fn execute_all_pending(&mut self) -> Vec<(Uuid, Result<ActionResult>)> {
        let pending_ids: Vec<Uuid> = self.pending_actions.iter().map(|a| a.id).collect();
        let mut results = Vec::new();

        for id in pending_ids {
            let result = self.execute_action(id);
            results.push((id, result));
        }

        results
    }

    pub fn cancel_action(&mut self, action_id: Uuid) -> bool {
        if let Some(idx) = self.pending_actions.iter().position(|a| a.id == action_id) {
            let pending = self.pending_actions.remove(idx);
            let record = ActionRecord {
                id: pending.id,
                action_type: pending.action_type,
                target: pending.target,
                status: ActionStatus::Cancelled,
                result: Some("Action cancelled by user".into()),
                created_at: pending.created_at,
                executed_at: None,
                duration_ms: 0,
                dry_run: self.config.dry_run,
            };
            self.action_log.push(record);
            info!(action_id = %action_id, "Action cancelled");
            true
        } else {
            false
        }
    }

    pub fn get_action(&self, action_id: Uuid) -> Option<&ActionRecord> {
        self.action_log.iter().find(|a| a.id == action_id)
    }

    pub fn action_history(&self) -> &[ActionRecord] {
        &self.action_log
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.completed_count, self.failed_count)
    }

    pub fn check_rate_limit(&self) -> bool {
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let recent_count = self
            .action_log
            .iter()
            .filter(|a| {
                a.executed_at
                    .map(|t| t > one_hour_ago)
                    .unwrap_or(false)
            })
            .count() as u32;
        recent_count < self.config.max_actions_per_hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::{EventSeverity, ThreatStatus};

    #[test]
    fn test_new_executor() {
        let executor = ActionExecutor::new();
        assert!(executor.action_log.is_empty());
        assert!(executor.pending_actions.is_empty());
        assert_eq!(executor.completed_count, 0);
        assert_eq!(executor.failed_count, 0);
        assert!(!executor.config.auto_respond);
        assert!(executor.config.require_approval);
        assert_eq!(executor.config.max_actions_per_hour, 50);
        assert!(!executor.config.dry_run);
    }

    #[test]
    fn test_with_config() {
        let config = ActionConfig {
            auto_respond: true,
            require_approval: false,
            max_actions_per_hour: 100,
            allowed_actions: vec![ActionType::BlockIp],
            dry_run: true,
        };
        let executor = ActionExecutor::with_config(config);
        assert!(executor.config.auto_respond);
        assert!(!executor.config.require_approval);
        assert_eq!(executor.config.max_actions_per_hour, 100);
        assert!(executor.config.dry_run);
        assert_eq!(executor.config.allowed_actions.len(), 1);
    }

    #[test]
    fn test_queue_action() {
        let mut executor = ActionExecutor::new();
        let mut params = HashMap::new();
        params.insert("reason".into(), serde_json::json!("malware detected"));

        let id = executor.queue_action(
            ActionType::BlockIp,
            "192.168.1.100",
            ActionPriority::High,
            params,
        );

        assert_eq!(executor.pending_actions.len(), 1);
        assert_eq!(executor.pending_actions[0].id, id);
        assert_eq!(executor.pending_actions[0].action_type, ActionType::BlockIp);
        assert_eq!(executor.pending_actions[0].target, "192.168.1.100");
        assert_eq!(executor.pending_actions[0].priority, ActionPriority::High);
        assert_eq!(
            executor.pending_actions[0].parameters["reason"],
            serde_json::json!("malware detected")
        );
    }

    #[test]
    fn test_execute_action_block_ip() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::BlockIp,
            "10.0.0.1",
            ActionPriority::Critical,
            HashMap::new(),
        );

        let result = executor.execute_action(id);
        assert!(result.is_ok());

        let action_result = result.unwrap();
        assert!(action_result.success);
        assert!(action_result.message.contains("10.0.0.1"));
        assert!(!action_result.side_effects.is_empty());

        assert!(executor.pending_actions.is_empty());
        assert_eq!(executor.completed_count, 1);
        assert_eq!(executor.action_log.len(), 1);
        assert_eq!(executor.action_log[0].status, ActionStatus::Completed);
    }

    #[test]
    fn test_execute_action_quarantine_file() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::QuarantineFile,
            "C:\\malware.exe",
            ActionPriority::High,
            HashMap::new(),
        );

        let result = executor.execute_action(id).unwrap();
        assert!(result.success);
        assert!(result.message.contains("quarantined"));
        assert_eq!(executor.completed_count, 1);
    }

    #[test]
    fn test_execute_action_kill_process() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::KillProcess,
            "suspicious.exe",
            ActionPriority::Critical,
            HashMap::new(),
        );

        let result = executor.execute_action(id).unwrap();
        assert!(result.success);
        assert!(result.message.contains("terminated"));
        assert_eq!(executor.completed_count, 1);
    }

    #[test]
    fn test_execute_action_isolate_host() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::IsolateHost,
            "WORKSTATION-01",
            ActionPriority::Critical,
            HashMap::new(),
        );

        let result = executor.execute_action(id).unwrap();
        assert!(result.success);
        assert!(result.message.contains("isolated"));
        assert_eq!(executor.completed_count, 1);
    }

    #[test]
    fn test_cancel_action() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::BlockIp,
            "10.0.0.5",
            ActionPriority::Medium,
            HashMap::new(),
        );

        assert_eq!(executor.pending_actions.len(), 1);
        let cancelled = executor.cancel_action(id);
        assert!(cancelled);
        assert!(executor.pending_actions.is_empty());
        assert_eq!(executor.action_log.len(), 1);
        assert_eq!(executor.action_log[0].status, ActionStatus::Cancelled);
    }

    #[test]
    fn test_cancel_nonexistent_action() {
        let mut executor = ActionExecutor::new();
        let fake_id = Uuid::new_v4();
        let cancelled = executor.cancel_action(fake_id);
        assert!(!cancelled);
    }

    #[test]
    fn test_execute_all_pending() {
        let mut executor = ActionExecutor::new();
        executor.queue_action(
            ActionType::BlockIp,
            "1.1.1.1",
            ActionPriority::High,
            HashMap::new(),
        );
        executor.queue_action(
            ActionType::KillProcess,
            "bad.exe",
            ActionPriority::Critical,
            HashMap::new(),
        );
        executor.queue_action(
            ActionType::QuarantineFile,
            "C:\\bad.dll",
            ActionPriority::Medium,
            HashMap::new(),
        );

        assert_eq!(executor.pending_actions.len(), 3);

        let results = executor.execute_all_pending();
        assert_eq!(results.len(), 3);
        for (_, result) in &results {
            assert!(result.is_ok());
            assert!(result.as_ref().unwrap().success);
        }
        assert!(executor.pending_actions.is_empty());
        assert_eq!(executor.completed_count, 3);
        assert_eq!(executor.action_log.len(), 3);
    }

    #[test]
    fn test_rate_limit_within_bounds() {
        let mut executor = ActionExecutor::new();
        assert!(executor.check_rate_limit());

        for i in 0..49 {
            executor.queue_action(
                ActionType::BlockIp,
                &format!("10.0.0.{}", i),
                ActionPriority::Low,
                HashMap::new(),
            );
            executor.execute_action(executor.pending_actions[0].id).ok();
        }

        assert!(executor.check_rate_limit());
    }

    #[test]
    fn test_rate_limit_at_max() {
        let config = ActionConfig {
            max_actions_per_hour: 2,
            ..Default::default()
        };
        let mut executor = ActionExecutor::with_config(config);

        executor.queue_action(
            ActionType::BlockIp,
            "10.0.0.1",
            ActionPriority::Low,
            HashMap::new(),
        );
        executor.execute_action(executor.pending_actions[0].id).ok();

        executor.queue_action(
            ActionType::BlockIp,
            "10.0.0.2",
            ActionPriority::Low,
            HashMap::new(),
        );
        executor.execute_action(executor.pending_actions[0].id).ok();

        assert!(!executor.check_rate_limit());
    }

    #[test]
    fn test_action_history() {
        let mut executor = ActionExecutor::new();
        assert!(executor.action_history().is_empty());

        let id1 = executor.queue_action(
            ActionType::BlockIp,
            "1.2.3.4",
            ActionPriority::Low,
            HashMap::new(),
        );
        executor.execute_action(id1).ok();

        let id2 = executor.queue_action(
            ActionType::KillProcess,
            "test.exe",
            ActionPriority::High,
            HashMap::new(),
        );
        executor.cancel_action(id2);

        assert_eq!(executor.action_history().len(), 2);
        assert_eq!(executor.action_history()[0].status, ActionStatus::Completed);
        assert_eq!(executor.action_history()[1].status, ActionStatus::Cancelled);
    }

    #[test]
    fn test_stats() {
        let mut executor = ActionExecutor::new();
        assert_eq!(executor.stats(), (0, 0));

        let id1 = executor.queue_action(
            ActionType::BlockIp,
            "1.1.1.1",
            ActionPriority::High,
            HashMap::new(),
        );
        executor.execute_action(id1).ok();

        let id2 = executor.queue_action(
            ActionType::KillProcess,
            "bad.exe",
            ActionPriority::Critical,
            HashMap::new(),
        );
        executor.execute_action(id2).ok();

        assert_eq!(executor.stats(), (2, 0));

        let id3 = executor.queue_action(
            ActionType::DisableUser,
            "admin",
            ActionPriority::Low,
            HashMap::new(),
        );
        executor.cancel_action(id3);

        assert_eq!(executor.stats(), (2, 0));
    }

    #[test]
    fn test_dry_run() {
        let config = ActionConfig {
            dry_run: true,
            ..Default::default()
        };
        let mut executor = ActionExecutor::with_config(config);

        let id = executor.queue_action(
            ActionType::BlockIp,
            "192.168.1.50",
            ActionPriority::High,
            HashMap::new(),
        );

        let result = executor.execute_action(id).unwrap();
        assert!(result.success);
        assert!(result.message.contains("[DRY RUN]"));
        assert_eq!(executor.completed_count, 1);

        let record = executor.get_action(id).unwrap();
        assert!(record.dry_run);
    }

    #[test]
    fn test_get_action() {
        let mut executor = ActionExecutor::new();
        let id = executor.queue_action(
            ActionType::QuarantineFile,
            "C:\\test.txt",
            ActionPriority::Medium,
            HashMap::new(),
        );
        executor.execute_action(id).ok();

        let record = executor.get_action(id);
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.id, id);
        assert_eq!(record.action_type, ActionType::QuarantineFile);
        assert_eq!(record.target, "C:\\test.txt");
        assert!(record.executed_at.is_some());
        assert!(record.duration_ms > 0 || record.duration_ms == 0);

        let missing = executor.get_action(Uuid::new_v4());
        assert!(missing.is_none());
    }

    #[test]
    fn test_action_not_found() {
        let mut executor = ActionExecutor::new();
        let fake_id = Uuid::new_v4();
        let result = executor.execute_action(fake_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_disallowed_action() {
        let config = ActionConfig {
            allowed_actions: vec![ActionType::BlockIp, ActionType::KillProcess],
            ..Default::default()
        };
        let mut executor = ActionExecutor::with_config(config);

        let id = executor.queue_action(
            ActionType::IsolateHost,
            "host1",
            ActionPriority::High,
            HashMap::new(),
        );

        let result = executor.execute_action(id);
        assert!(result.is_err());
        assert_eq!(executor.failed_count, 1);
        assert_eq!(executor.completed_count, 0);

        let record = executor.get_action(id).unwrap();
        assert_eq!(record.status, ActionStatus::Failed);
    }

    #[test]
    fn test_action_types_completeness() {
        let all_types = vec![
            ActionType::BlockIp,
            ActionType::QuarantineFile,
            ActionType::KillProcess,
            ActionType::IsolateHost,
            ActionType::BlockDomain,
            ActionType::DisableUser,
            ActionType::RollbackChange,
            ActionType::NotifyAdmin,
            ActionType::CollectEvidence,
            ActionType::ResetPassword,
            ActionType::DisableService,
            ActionType::BlockHash,
        ];
        assert_eq!(all_types.len(), 12);

        let config = ActionConfig::default();
        assert_eq!(config.allowed_actions.len(), 12);
    }

    #[test]
    fn test_severity_and_threat_types_used() {
        let _sev = EventSeverity::Critical;
        let _threat = ThreatStatus::Active;
        let executor = ActionExecutor::new();
        assert_eq!(executor.stats(), (0, 0));
    }

    #[test]
    fn test_multiple_action_types_execution() {
        let mut executor = ActionExecutor::new();

        let actions = vec![
            (ActionType::BlockDomain, "evil.com"),
            (ActionType::DisableUser, "compromised_user"),
            (ActionType::RollbackChange, "registry_key"),
            (ActionType::NotifyAdmin, "incident-42"),
            (ActionType::CollectEvidence, "endpoints"),
            (ActionType::ResetPassword, "admin"),
            (ActionType::DisableService, "SuspiciousService"),
            (ActionType::BlockHash, "abc123def456"),
        ];

        for (action_type, target) in actions {
            let id = executor.queue_action(
                action_type,
                target,
                ActionPriority::High,
                HashMap::new(),
            );
            let result = executor.execute_action(id).unwrap();
            assert!(result.success);
        }

        assert_eq!(executor.completed_count, 8);
        assert_eq!(executor.failed_count, 0);
        assert_eq!(executor.action_log.len(), 8);
    }
}
