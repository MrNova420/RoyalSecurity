pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlaybookTrigger {
    AlertReceived,
    ThreatDetected,
    ManualActivation,
    Schedule(String),
    EventType(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepAction {
    BlockIp(String),
    QuarantineFile(String),
    KillProcess(u32),
    SendNotification(String),
    RunCommand(String),
    Wait(u64),
    Condition {
        field: String,
        op: String,
        value: String,
    },
    CollectEvidence(String),
    CreateTicket(String),
    LogMessage(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub action: StepAction,
    pub on_success: Option<String>,
    pub on_failure: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<WorkflowStep>,
    pub enabled: bool,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub success: bool,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    pub playbook_id: String,
    pub current_step: String,
    pub started_at: DateTime<Utc>,
    pub step_results: HashMap<String, StepResult>,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub id: Uuid,
    pub playbook_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ExecutionStatus,
    pub results: Vec<StepResult>,
}

#[derive(Debug)]
pub struct SoarEngine {
    pub playbooks: HashMap<String, Playbook>,
    pub execution_log: Vec<PlaybookExecution>,
    pub active_workflows: HashMap<String, WorkflowState>,
}

impl SoarEngine {
    pub fn new() -> Self {
        info!("Initializing SOAR engine");
        Self {
            playbooks: HashMap::new(),
            execution_log: Vec::new(),
            active_workflows: HashMap::new(),
        }
    }

    pub fn create_playbook(
        &mut self,
        name: String,
        description: String,
        trigger: PlaybookTrigger,
        steps: Vec<WorkflowStep>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let playbook = Playbook {
            id: id.clone(),
            name,
            description,
            trigger,
            steps,
            enabled: true,
            version: 1,
        };
        info!("Created playbook: {}", playbook.id);
        self.playbooks.insert(id.clone(), playbook);
        id
    }

    pub fn activate_playbook(&mut self, playbook_id: &str) -> Option<String> {
        let playbook = self.playbooks.get(playbook_id)?;
        if !playbook.enabled {
            warn!("Playbook {} is disabled", playbook_id);
            return None;
        }
        if playbook.steps.is_empty() {
            warn!("Playbook {} has no steps", playbook_id);
            return None;
        }

        let execution_id = Uuid::new_v4().to_string();
        let first_step = playbook.steps[0].id.clone();

        let state = WorkflowState {
            playbook_id: playbook_id.to_string(),
            current_step: first_step,
            started_at: Utc::now(),
            step_results: HashMap::new(),
            context: HashMap::new(),
        };

        let execution = PlaybookExecution {
            id: Uuid::parse_str(&execution_id).unwrap(),
            playbook_id: playbook_id.to_string(),
            started_at: Utc::now(),
            completed_at: None,
            status: ExecutionStatus::Running,
            results: Vec::new(),
        };

        debug!("Activated playbook {} as execution {}", playbook_id, execution_id);
        self.active_workflows.insert(execution_id.clone(), state);
        self.execution_log.push(execution);

        Some(execution_id)
    }

    pub fn execute_step(&mut self, execution_id: &str, step: &WorkflowStep) -> StepResult {
        let start = Utc::now();
        let success = true;
        let message = match &step.action {
            StepAction::BlockIp(ip) => format!("Blocked IP: {}", ip),
            StepAction::QuarantineFile(path) => format!("Quarantined file: {}", path),
            StepAction::KillProcess(pid) => format!("Killed process: {}", pid),
            StepAction::SendNotification(msg) => format!("Notification sent: {}", msg),
            StepAction::RunCommand(cmd) => format!("Command executed: {}", cmd),
            StepAction::Wait(secs) => format!("Waited {} seconds", secs),
            StepAction::Condition { field, op, value } => {
                format!("Evaluated condition: {} {} {}", field, op, value)
            }
            StepAction::CollectEvidence(target) => format!("Evidence collected from: {}", target),
            StepAction::CreateTicket(desc) => format!("Ticket created: {}", desc),
            StepAction::LogMessage(msg) => format!("Logged: {}", msg),
        };

        let duration_ms = Utc::now()
            .signed_duration_since(start)
            .num_milliseconds()
            .max(0) as u64;

        let result = StepResult {
            step_id: step.id.clone(),
            success,
            message,
            duration_ms,
        };

        if let Some(state) = self.active_workflows.get_mut(execution_id) {
            state.step_results.insert(step.id.clone(), result.clone());
        }

        if let Some(exec) = self.execution_log.iter_mut().find(|e| e.id.to_string() == execution_id) {
            exec.results.push(result.clone());
        }

        result
    }

    pub fn cancel_execution(&mut self, execution_id: &str) -> bool {
        let exec = match self
            .execution_log
            .iter_mut()
            .find(|e| e.id.to_string() == execution_id)
        {
            Some(e) => e,
            None => return false,
        };

        if !matches!(exec.status, ExecutionStatus::Running) {
            return false;
        }

        exec.status = ExecutionStatus::Cancelled;
        exec.completed_at = Some(Utc::now());
        self.active_workflows.remove(execution_id);
        info!("Cancelled execution: {}", execution_id);
        true
    }

    pub fn get_playbook(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.get(id)
    }

    pub fn get_execution(&self, id: &str) -> Option<&PlaybookExecution> {
        self.execution_log.iter().find(|e| e.id.to_string() == id)
    }

    pub fn list_playbooks(&self) -> Vec<&Playbook> {
        self.playbooks.values().collect()
    }

    pub fn execution_count(&self) -> usize {
        self.execution_log.len()
    }
}

impl Default for SoarEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(id: &str, action: StepAction) -> WorkflowStep {
        WorkflowStep {
            id: id.to_string(),
            name: format!("Step {}", id),
            action,
            on_success: None,
            on_failure: None,
            timeout_secs: 30,
        }
    }

    #[test]
    fn test_new_engine_is_empty() {
        let engine = SoarEngine::new();
        assert!(engine.playbooks.is_empty());
        assert!(engine.execution_log.is_empty());
        assert!(engine.active_workflows.is_empty());
    }

    #[test]
    fn test_create_playbook() {
        let mut engine = SoarEngine::new();
        let steps = vec![
            make_step("s1", StepAction::BlockIp("10.0.0.1".into())),
            make_step("s2", StepAction::SendNotification("Alert!".into())),
        ];
        let id = engine.create_playbook(
            "IR Playbook".into(),
            "Incident response".into(),
            PlaybookTrigger::AlertReceived,
            steps,
        );
        assert!(!id.is_empty());
        let pb = engine.get_playbook(&id).unwrap();
        assert_eq!(pb.name, "IR Playbook");
        assert!(pb.enabled);
        assert_eq!(pb.version, 1);
        assert_eq!(pb.steps.len(), 2);
    }

    #[test]
    fn test_activate_playbook_returns_execution_id() {
        let mut engine = SoarEngine::new();
        let steps = vec![make_step("s1", StepAction::LogMessage("hello".into()))];
        let pb_id = engine.create_playbook(
            "Test".into(),
            "Desc".into(),
            PlaybookTrigger::ManualActivation,
            steps,
        );
        let exec_id = engine.activate_playbook(&pb_id).unwrap();
        assert!(!exec_id.is_empty());
        assert_eq!(engine.execution_count(), 1);
        assert!(engine.active_workflows.contains_key(&exec_id));
    }

    #[test]
    fn test_activate_disabled_playbook_returns_none() {
        let mut engine = SoarEngine::new();
        let steps = vec![make_step("s1", StepAction::LogMessage("x".into()))];
        let pb_id = engine.create_playbook(
            "Disabled".into(),
            "Desc".into(),
            PlaybookTrigger::ManualActivation,
            steps,
        );
        engine.playbooks.get_mut(&pb_id).unwrap().enabled = false;
        assert!(engine.activate_playbook(&pb_id).is_none());
    }

    #[test]
    fn test_activate_empty_steps_returns_none() {
        let mut engine = SoarEngine::new();
        let pb_id = engine.create_playbook(
            "Empty".into(),
            "Desc".into(),
            PlaybookTrigger::ManualActivation,
            vec![],
        );
        assert!(engine.activate_playbook(&pb_id).is_none());
    }

    #[test]
    fn test_execute_step_records_result() {
        let mut engine = SoarEngine::new();
        let steps = vec![make_step("s1", StepAction::BlockIp("1.2.3.4".into()))];
        let pb_id = engine.create_playbook(
            "T".into(),
            "D".into(),
            PlaybookTrigger::ThreatDetected,
            steps,
        );
        let exec_id = engine.activate_playbook(&pb_id).unwrap();
        let step = engine.get_playbook(&pb_id).unwrap().steps[0].clone();
        let result = engine.execute_step(&exec_id, &step);
        assert!(result.success);
        assert_eq!(result.step_id, "s1");
        assert!(result.message.contains("1.2.3.4"));
    }

    #[test]
    fn test_cancel_execution() {
        let mut engine = SoarEngine::new();
        let steps = vec![make_step("s1", StepAction::Wait(5))];
        let pb_id = engine.create_playbook(
            "W".into(),
            "D".into(),
            PlaybookTrigger::AlertReceived,
            steps,
        );
        let exec_id = engine.activate_playbook(&pb_id).unwrap();
        assert!(engine.cancel_execution(&exec_id));
        let exec = engine.get_execution(&exec_id).unwrap();
        assert!(matches!(exec.status, ExecutionStatus::Cancelled));
        assert!(exec.completed_at.is_some());
        assert!(!engine.active_workflows.contains_key(&exec_id));
    }

    #[test]
    fn test_cancel_nonexistent_execution_returns_false() {
        let mut engine = SoarEngine::new();
        assert!(!engine.cancel_execution("fake-id"));
    }

    #[test]
    fn test_list_playbooks() {
        let mut engine = SoarEngine::new();
        engine.create_playbook(
            "A".into(),
            "Desc".into(),
            PlaybookTrigger::AlertReceived,
            vec![],
        );
        engine.create_playbook(
            "B".into(),
            "Desc".into(),
            PlaybookTrigger::ManualActivation,
            vec![],
        );
        assert_eq!(engine.list_playbooks().len(), 2);
    }

    #[test]
    fn test_execution_count_increments() {
        let mut engine = SoarEngine::new();
        assert_eq!(engine.execution_count(), 0);
        let steps = vec![make_step("s1", StepAction::LogMessage("x".into()))];
        let pb_id = engine.create_playbook(
            "T".into(),
            "D".into(),
            PlaybookTrigger::ManualActivation,
            steps,
        );
        engine.activate_playbook(&pb_id);
        assert_eq!(engine.execution_count(), 1);
        engine.activate_playbook(&pb_id);
        assert_eq!(engine.execution_count(), 2);
    }

    #[test]
    fn test_various_step_actions() {
        let mut engine = SoarEngine::new();
        let actions = vec![
            StepAction::QuarantineFile("/tmp/mal.exe".into()),
            StepAction::KillProcess(1234),
            StepAction::RunCommand("netsh advfirewall set allprofiles state on".into()),
            StepAction::Condition { field: "severity".into(), op: ">=".into(), value: "high".into() },
            StepAction::CollectEvidence("/var/log/syslog".into()),
            StepAction::CreateTicket("INC-001".into()),
            StepAction::LogMessage("test log".into()),
        ];
        let steps: Vec<WorkflowStep> = actions
            .into_iter()
            .enumerate()
            .map(|(i, a)| make_step(&format!("s{}", i), a))
            .collect();
        let pb_id = engine.create_playbook(
            "Multi".into(),
            "Desc".into(),
            PlaybookTrigger::EventType("malware".into()),
            steps,
        );
        let exec_id = engine.activate_playbook(&pb_id).unwrap();
        let playbook = engine.get_playbook(&pb_id).unwrap().clone();
        for step in &playbook.steps {
            let result = engine.execute_step(&exec_id, step);
            assert!(result.success, "Step {} should succeed", step.id);
        }
        let exec = engine.get_execution(&exec_id).unwrap();
        assert_eq!(exec.results.len(), 7);
    }
}
