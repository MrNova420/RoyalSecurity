use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FleetCommand {
    ScanCommand {
        scan_type: String,
        targets: Vec<String>,
    },
    UpdateRules {
        rule_version: String,
        rule_urls: Vec<String>,
    },
    BlockIp {
        ip_address: String,
        duration_seconds: u64,
    },
    TerminateProcess {
        process_name: String,
        pid: Option<u32>,
    },
    UpdateConfig {
        config_data: serde_json::Value,
    },
    IsolateHost {
        reason: String,
    },
    CollectForensics {
        artifact_types: Vec<String>,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommandStatus {
    Pending,
    Dispatched,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub agent_id: Uuid,
    pub command_id: Uuid,
    pub command: FleetCommand,
    pub status: CommandStatus,
    pub result_data: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub dispatched_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub retry_count: u32,
}

impl CommandResult {
    pub fn new(agent_id: Uuid, command: FleetCommand) -> Self {
        Self {
            agent_id,
            command_id: Uuid::new_v4(),
            command,
            status: CommandStatus::Pending,
            result_data: None,
            error_message: None,
            created_at: Utc::now(),
            dispatched_at: None,
            completed_at: None,
            retry_count: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandDispatcher {
    commands: Arc<DashMap<Uuid, CommandResult>>,
    max_retries: u32,
}

impl CommandDispatcher {
    pub fn new() -> Self {
        Self {
            commands: Arc::new(DashMap::new()),
            max_retries: 3,
        }
    }

    pub fn send_command(&self, agent_id: Uuid, command: FleetCommand) -> Uuid {
        let result = CommandResult::new(agent_id, command);
        let command_id = result.command_id;
        self.commands.insert(command_id, result);
        command_id
    }

    pub fn get_status(&self, command_id: &Uuid) -> Option<CommandResult> {
        self.commands.get(command_id).map(|entry| entry.value().clone())
    }

    pub fn collect_results(&self) -> Vec<CommandResult> {
        self.commands
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn dispatch_command(&self, command_id: &Uuid) -> bool {
        if let Some(mut result) = self.commands.get_mut(command_id) {
            if result.status == CommandStatus::Pending {
                result.status = CommandStatus::Dispatched;
                result.dispatched_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    pub fn complete_command(&self, command_id: &Uuid, result_data: Option<serde_json::Value>) -> bool {
        if let Some(mut result) = self.commands.get_mut(command_id) {
            if result.status == CommandStatus::Dispatched {
                result.status = CommandStatus::Completed;
                result.result_data = result_data;
                result.completed_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    pub fn fail_command(&self, command_id: &Uuid, error_message: String) -> bool {
        if let Some(mut result) = self.commands.get_mut(command_id) {
            result.status = CommandStatus::Failed;
            result.error_message = Some(error_message);
            result.completed_at = Some(Utc::now());
            return true;
        }
        false
    }

    pub fn retry_command(&self, command_id: &Uuid) -> bool {
        if let Some(mut result) = self.commands.get_mut(command_id) {
            if result.status == CommandStatus::Failed && result.retry_count < self.max_retries {
                result.status = CommandStatus::Pending;
                result.retry_count += 1;
                result.error_message = None;
                result.completed_at = None;
                return true;
            }
        }
        false
    }

    pub fn get_pending_commands(&self) -> Vec<CommandResult> {
        self.commands
            .iter()
            .filter(|entry| entry.value().status == CommandStatus::Pending)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_commands_for_agent(&self, agent_id: &Uuid) -> Vec<CommandResult> {
        self.commands
            .iter()
            .filter(|entry| entry.value().agent_id == *agent_id)
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}
