use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    AgentCountThreshold {
        operator: String,
        value: usize,
    },
    AlertSeverity {
        severity: String,
    },
    EventType {
        event_type: String,
    },
    TimeWindow {
        duration_minutes: u64,
    },
    AgentTag {
        tag: String,
    },
    AgentOs {
        os: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    IsolateHost {
        reason: String,
    },
    BlockIp {
        ip_address: String,
        duration_seconds: u64,
    },
    UpdateRules {
        rule_version: String,
    },
    TriggerScan {
        scan_type: String,
    },
    SendNotification {
        message: String,
        channels: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub targets: PolicyTargets,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
    pub schedule: Option<PolicySchedule>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyTargets {
    AgentIds(Vec<Uuid>),
    Tags(Vec<String>),
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySchedule {
    pub interval_minutes: u64,
    pub last_executed: Option<DateTime<Utc>>,
}

impl Policy {
    pub fn new(name: String, description: String, targets: PolicyTargets) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            targets,
            conditions: Vec::new(),
            actions: Vec::new(),
            schedule: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn add_condition(&mut self, condition: Condition) {
        self.conditions.push(condition);
        self.updated_at = Utc::now();
    }

    pub fn add_action(&mut self, action: Action) {
        self.actions.push(action);
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Arc<DashMap<Uuid, Policy>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(DashMap::new()),
        }
    }

    pub fn add_policy(&self, policy: Policy) -> Uuid {
        let id = policy.id;
        self.policies.insert(id, policy);
        id
    }

    pub fn remove_policy(&self, policy_id: &Uuid) -> Option<Policy> {
        self.policies.remove(policy_id).map(|(_, policy)| policy)
    }

    pub fn list_policies(&self) -> Vec<Policy> {
        self.policies
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_policy(&self, policy_id: &Uuid) -> Option<Policy> {
        self.policies.get(policy_id).map(|entry| entry.value().clone())
    }

    pub fn enable_policy(&self, policy_id: &Uuid) -> bool {
        if let Some(mut policy) = self.policies.get_mut(policy_id) {
            policy.enabled = true;
            policy.updated_at = Utc::now();
            return true;
        }
        false
    }

    pub fn disable_policy(&self, policy_id: &Uuid) -> bool {
        if let Some(mut policy) = self.policies.get_mut(policy_id) {
            policy.enabled = false;
            policy.updated_at = Utc::now();
            return true;
        }
        false
    }

    pub fn evaluate_policies(&self, context: &EvaluationContext) -> Vec<PolicyAction> {
        let mut triggered_actions = Vec::new();

        for entry in self.policies.iter() {
            let policy = entry.value();
            if !policy.enabled {
                continue;
            }

            if self.evaluate_conditions(&policy.conditions, context) {
                for action in &policy.actions {
                    triggered_actions.push(PolicyAction {
                        policy_id: policy.id,
                        policy_name: policy.name.clone(),
                        action: action.clone(),
                    });
                }
            }
        }

        triggered_actions
    }

    fn evaluate_conditions(&self, conditions: &[Condition], context: &EvaluationContext) -> bool {
        if conditions.is_empty() {
            return true;
        }

        conditions.iter().all(|condition| {
            match condition {
                Condition::AgentCountThreshold { operator, value } => {
                    let count = context.online_agent_count;
                    match operator.as_str() {
                        "gt" => count > *value,
                        "gte" => count >= *value,
                        "lt" => count < *value,
                        "lte" => count <= *value,
                        "eq" => count == *value,
                        _ => false,
                    }
                }
                Condition::AlertSeverity { severity } => {
                    context.current_severity == *severity
                }
                Condition::EventType { event_type } => {
                    context.event_type == *event_type
                }
                Condition::TimeWindow { duration_minutes } => {
                    if let Some(last_executed) = context.last_policy_execution {
                        let now = Utc::now();
                        let duration = now.signed_duration_since(last_executed);
                        duration.num_minutes() as u64 >= *duration_minutes
                    } else {
                        true
                    }
                }
                Condition::AgentTag { tag } => {
                    context.agent_tags.contains(tag)
                }
                Condition::AgentOs { os } => {
                    context.agent_os == *os
                }
            }
        })
    }

    pub fn apply_policy(&self, policy_id: &Uuid, context: &EvaluationContext) -> Option<Vec<Action>> {
        if let Some(policy) = self.policies.get(policy_id) {
            if policy.enabled && self.evaluate_conditions(&policy.conditions, context) {
                return Some(policy.actions.clone());
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub online_agent_count: usize,
    pub current_severity: String,
    pub event_type: String,
    pub last_policy_execution: Option<DateTime<Utc>>,
    pub agent_tags: Vec<String>,
    pub agent_os: String,
}

#[derive(Debug, Clone)]
pub struct PolicyAction {
    pub policy_id: Uuid,
    pub policy_name: String,
    pub action: Action,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}
