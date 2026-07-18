use crate::actions::{ActionResult, ResponseAction, ResponseStatus};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerType {
    AlertSeverity {
        min_severity: u8,
    },
    EventCount {
        event_type: String,
        threshold: u32,
        window_seconds: u64,
    },
    MITRETechnique {
        technique_id: String,
    },
    IOCMatch {
        ioc_type: String,
    },
    TimeWindow {
        duration_seconds: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureAction {
    Retry {
        max_retries: u32,
        delay_ms: u64,
    },
    Skip,
    Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_id: String,
    pub action: ResponseAction,
    pub delay_ms: u64,
    pub conditions: Option<HashMap<String, String>>,
    pub on_success: Option<String>,
    pub on_failure: FailureAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub triggers: Vec<TriggerType>,
    pub steps: Vec<PlaybookStep>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlaybookStatus {
    Idle,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub execution_id: String,
    pub playbook_id: String,
    pub status: PlaybookStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub step_results: Vec<(String, ActionResult)>,
    pub error: Option<String>,
}

pub struct PlaybookEngine {
    playbooks: HashMap<String, Playbook>,
    executions: HashMap<String, PlaybookExecution>,
    event_counts: HashMap<String, Vec<DateTime<Utc>>>,
}

impl PlaybookEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            playbooks: HashMap::new(),
            executions: HashMap::new(),
            event_counts: HashMap::new(),
        };
        engine.register_built_in_playbooks();
        engine
    }

    pub fn register_playbook(&mut self, playbook: Playbook) {
        info!("Registered playbook: {} ({})", playbook.name, playbook.id);
        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    pub fn get_playbook_status(&self, playbook_id: &str) -> Option<&Playbook> {
        self.playbooks.get(playbook_id)
    }

    pub fn get_execution_status(&self, execution_id: &str) -> Option<&PlaybookExecution> {
        self.executions.get(execution_id)
    }

    pub fn list_playbooks(&self) -> Vec<&Playbook> {
        self.playbooks.values().collect()
    }

    pub fn record_event(&mut self, event_type: &str) {
        self.event_counts
            .entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(Utc::now());
    }

    pub fn evaluate_triggers(&self, context: &TriggerContext) -> Vec<String> {
        let mut triggered = Vec::new();

        for (id, playbook) in &self.playbooks {
            if !playbook.enabled {
                continue;
            }

            let all_triggered = playbook.triggers.iter().all(|trigger| {
                match trigger {
                    TriggerType::AlertSeverity { min_severity } => {
                        context.severity.map_or(false, |s| s >= *min_severity)
                    }
                    TriggerType::EventCount { event_type, threshold, window_seconds } => {
                        let cutoff = Utc::now() - Duration::seconds(*window_seconds as i64);
                        if let Some(counts) = self.event_counts.get(event_type) {
                            let recent_count = counts.iter()
                                .filter(|t| **t > cutoff)
                                .count() as u32;
                            recent_count >= *threshold
                        } else {
                            false
                        }
                    }
                    TriggerType::MITRETechnique { technique_id } => {
                        context.mitre_technique.as_ref() == Some(technique_id)
                    }
                    TriggerType::IOCMatch { ioc_type } => {
                        context.ioc_types.iter().any(|t| t == ioc_type)
                    }
                    TriggerType::TimeWindow { duration_seconds } => {
                        context.event_window_seconds.map_or(false, |w| w <= *duration_seconds)
                    }
                }
            });

            if all_triggered && !playbook.triggers.is_empty() {
                triggered.push(id.clone());
            }
        }

        triggered
    }

    pub async fn execute_playbook(&mut self, playbook_id: &str, context: &TriggerContext) -> String {
        let playbook = match self.playbooks.get(playbook_id) {
            Some(p) => p.clone(),
            None => {
                error!("Playbook not found: {}", playbook_id);
                return String::new();
            }
        };

        if !playbook.enabled {
            warn!("Playbook is disabled: {}", playbook.name);
            return String::new();
        }

        let execution_id = uuid::Uuid::new_v4().to_string();
        let mut execution = PlaybookExecution {
            execution_id: execution_id.clone(),
            playbook_id: playbook_id.to_string(),
            status: PlaybookStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            step_results: Vec::new(),
            error: None,
        };

        info!("Executing playbook: {} (execution: {})", playbook.name, execution_id);

        let mut current_step_index = 0;
        let mut retries_remaining: HashMap<String, u32> = HashMap::new();

        while current_step_index < playbook.steps.len() {
            let step = &playbook.steps[current_step_index];

            if step.delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(step.delay_ms)).await;
            }

            if let Some(conditions) = &step.conditions {
                let conditions_met = conditions.iter().all(|(key, value)| {
                    match key.as_str() {
                        "severity" => {
                            context.severity.map_or(false, |s| {
                                s.to_string() == *value
                            })
                        }
                        "mitre_technique" => {
                            context.mitre_technique.as_ref() == Some(value)
                        }
                        _ => true,
                    }
                });

                if !conditions_met {
                    info!("Step {} conditions not met, skipping", step.step_id);
                    current_step_index += 1;
                    continue;
                }
            }

            let result = step.action.execute().await;
            let step_id = step.step_id.clone();
            execution.step_results.push((step_id.clone(), result.clone()));

            match result.status {
                ResponseStatus::Success => {
                    info!("Step {} completed successfully", step_id);
                    if let Some(next_step_id) = &step.on_success {
                        if let Some(idx) = playbook.steps.iter().position(|s| s.step_id == *next_step_id) {
                            current_step_index = idx;
                            continue;
                        }
                    }
                    current_step_index += 1;
                }
                ResponseStatus::Failed => {
                    error!("Step {} failed: {}", step_id, result.message);
                    match &step.on_failure {
                        FailureAction::Retry { max_retries, delay_ms } => {
                            let retries = retries_remaining.entry(step_id.clone()).or_insert(0);
                            *retries += 1;
                            if *retries <= *max_retries {
                                warn!("Retrying step {} ({}/{})", step_id, retries, max_retries);
                                tokio::time::sleep(tokio::time::Duration::from_millis(*delay_ms)).await;
                                continue;
                            } else {
                                error!("Step {} exceeded max retries", step_id);
                                execution.status = PlaybookStatus::Failed;
                                execution.error = Some(format!("Step {} failed after {} retries", step_id, max_retries));
                                break;
                            }
                        }
                        FailureAction::Skip => {
                            warn!("Skipping failed step {}", step_id);
                            current_step_index += 1;
                        }
                        FailureAction::Abort => {
                            error!("Aborting playbook due to step {} failure", step_id);
                            execution.status = PlaybookStatus::Failed;
                            execution.error = Some(format!("Aborted at step {}: {}", step_id, result.message));
                            break;
                        }
                    }
                }
                ResponseStatus::Skipped => {
                    info!("Step {} skipped", step_id);
                    current_step_index += 1;
                }
            }
        }

        if execution.status == PlaybookStatus::Running {
            execution.status = PlaybookStatus::Completed;
        }
        execution.completed_at = Some(Utc::now());

        let final_status = execution.status.clone();
        info!(
            "Playbook execution {} completed with status: {:?}",
            execution_id, final_status
        );

        self.executions.insert(execution_id.clone(), execution);
        execution_id
    }

    fn register_built_in_playbooks(&mut self) {
        self.register_playbook(Playbook {
            id: "ransomware-response".to_string(),
            name: "Ransomware Response".to_string(),
            description: "Detects mass file operations indicative of ransomware and automatically isolates the host, collects artifacts, and blocks the malicious hash".to_string(),
            triggers: vec![
                TriggerType::EventCount {
                    event_type: "file_modify".to_string(),
                    threshold: 100,
                    window_seconds: 60,
                },
                TriggerType::MITRETechnique {
                    technique_id: "T1486".to_string(),
                },
            ],
            steps: vec![
                PlaybookStep {
                    step_id: "isolate_host".to_string(),
                    action: ResponseAction::IsolateHost {
                        management_ip: "10.0.0.1".to_string(),
                        allowed_ports: vec![3389, 445],
                    },
                    delay_ms: 0,
                    conditions: None,
                    on_success: Some("collect_artifacts".to_string()),
                    on_failure: FailureAction::Retry {
                        max_retries: 2,
                        delay_ms: 1000,
                    },
                },
                PlaybookStep {
                    step_id: "collect_artifacts".to_string(),
                    action: ResponseAction::CollectArtifact {
                        source_path: "C:\\Windows\\System32\\config\\SYSTEM".to_string(),
                        destination_path: "C:\\ProgramData\\RoyalSecurity\\Artifacts\\ransomware_".to_string(),
                        include_metadata: true,
                    },
                    delay_ms: 2000,
                    conditions: None,
                    on_success: Some("block_hash".to_string()),
                    on_failure: FailureAction::Skip,
                },
                PlaybookStep {
                    step_id: "block_hash".to_string(),
                    action: ResponseAction::BlockHash {
                        hash: String::new(),
                        hash_type: "SHA256".to_string(),
                        target_path: None,
                    },
                    delay_ms: 1000,
                    conditions: None,
                    on_success: None,
                    on_failure: FailureAction::Skip,
                },
            ],
            enabled: true,
        });

        self.register_playbook(Playbook {
            id: "c2-communication".to_string(),
            name: "C2 Communication".to_string(),
            description: "Detects command and control beaconing, blocks the C2 IP, kills active connections, and collects network artifacts".to_string(),
            triggers: vec![
                TriggerType::EventCount {
                    event_type: "network_beacon".to_string(),
                    threshold: 10,
                    window_seconds: 300,
                },
                TriggerType::IOCMatch {
                    ioc_type: "c2_ip".to_string(),
                },
            ],
            steps: vec![
                PlaybookStep {
                    step_id: "block_c2_ip".to_string(),
                    action: ResponseAction::BlockIp {
                        ip: String::new(),
                        direction: "both".to_string(),
                        duration_minutes: Some(1440),
                    },
                    delay_ms: 0,
                    conditions: None,
                    on_success: Some("kill_connections".to_string()),
                    on_failure: FailureAction::Abort,
                },
                PlaybookStep {
                    step_id: "kill_connections".to_string(),
                    action: ResponseAction::KillConnection {
                        local_ip: "0.0.0.0".to_string(),
                        local_port: 0,
                        remote_ip: String::new(),
                        remote_port: 0,
                    },
                    delay_ms: 500,
                    conditions: None,
                    on_success: Some("collect_network_artifacts".to_string()),
                    on_failure: FailureAction::Skip,
                },
                PlaybookStep {
                    step_id: "collect_network_artifacts".to_string(),
                    action: ResponseAction::CollectArtifact {
                        source_path: "C:\\Windows\\System32\\LogFiles\\WMI\\etw*.etl".to_string(),
                        destination_path: "C:\\ProgramData\\RoyalSecurity\\Artifacts\\network_".to_string(),
                        include_metadata: true,
                    },
                    delay_ms: 1000,
                    conditions: None,
                    on_success: None,
                    on_failure: FailureAction::Skip,
                },
            ],
            enabled: true,
        });

        self.register_playbook(Playbook {
            id: "credential-theft".to_string(),
            name: "Credential Theft".to_string(),
            description: "Detects LSASS access attempts, terminates the malicious process, disables the compromised user, and alerts the SOC".to_string(),
            triggers: vec![
                TriggerType::MITRETechnique {
                    technique_id: "T1003".to_string(),
                },
                TriggerType::AlertSeverity {
                    min_severity: 8,
                },
            ],
            steps: vec![
                PlaybookStep {
                    step_id: "terminate_process".to_string(),
                    action: ResponseAction::TerminateProcess {
                        pid: 0,
                        process_name: None,
                    },
                    delay_ms: 0,
                    conditions: None,
                    on_success: Some("disable_user".to_string()),
                    on_failure: FailureAction::Retry {
                        max_retries: 3,
                        delay_ms: 500,
                    },
                },
                PlaybookStep {
                    step_id: "disable_user".to_string(),
                    action: ResponseAction::DisableUser {
                        username: String::new(),
                        reason: "Suspected credential theft - LSASS access detected".to_string(),
                    },
                    delay_ms: 1000,
                    conditions: Some({
                        let mut m = HashMap::new();
                        m.insert("severity".to_string(), "critical".to_string());
                        m
                    }),
                    on_success: None,
                    on_failure: FailureAction::Skip,
                },
            ],
            enabled: true,
        });

        self.register_playbook(Playbook {
            id: "privilege-escalation".to_string(),
            name: "Privilege Escalation".to_string(),
            description: "Detects UAC bypass attempts, blocks the executable, and creates an audit trail entry".to_string(),
            triggers: vec![
                TriggerType::MITRETechnique {
                    technique_id: "T1548".to_string(),
                },
                TriggerType::AlertSeverity {
                    min_severity: 7,
                },
            ],
            steps: vec![
                PlaybookStep {
                    step_id: "block_executable".to_string(),
                    action: ResponseAction::BlockHash {
                        hash: String::new(),
                        hash_type: "SHA256".to_string(),
                        target_path: None,
                    },
                    delay_ms: 0,
                    conditions: None,
                    on_success: Some("collect_evidence".to_string()),
                    on_failure: FailureAction::Skip,
                },
                PlaybookStep {
                    step_id: "collect_evidence".to_string(),
                    action: ResponseAction::CollectArtifact {
                        source_path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx".to_string(),
                        destination_path: "C:\\ProgramData\\RoyalSecurity\\Artifacts\\priv_esc_".to_string(),
                        include_metadata: true,
                    },
                    delay_ms: 500,
                    conditions: None,
                    on_success: None,
                    on_failure: FailureAction::Skip,
                },
            ],
            enabled: true,
        });
    }
}

#[derive(Debug, Clone, Default)]
pub struct TriggerContext {
    pub severity: Option<u8>,
    pub mitre_technique: Option<String>,
    pub ioc_types: Vec<String>,
    pub event_window_seconds: Option<u64>,
    pub metadata: HashMap<String, String>,
}
