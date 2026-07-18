use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::agent::AgentInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub agent_ids: Vec<Uuid>,
    pub parent_group: Option<Uuid>,
    pub policies: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Group {
    pub fn new(name: String, description: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            agent_ids: Vec::new(),
            parent_group: None,
            policies: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutoGroupRule {
    ByOs {
        os_pattern: String,
    },
    ByHostname {
        hostname_pattern: String,
    },
    ByIpRange {
        ip_prefix: String,
    },
    ByTag {
        tag: String,
    },
}

#[derive(Debug, Clone)]
pub struct GroupManager {
    groups: Arc<DashMap<Uuid, Group>>,
    auto_group_rules: Arc<DashMap<Uuid, Vec<AutoGroupRule>>>,
}

impl GroupManager {
    pub fn new() -> Self {
        Self {
            groups: Arc::new(DashMap::new()),
            auto_group_rules: Arc::new(DashMap::new()),
        }
    }

    pub fn create_group(&self, name: String, description: String) -> Uuid {
        let group = Group::new(name, description);
        let id = group.id;
        self.groups.insert(id, group);
        id
    }

    pub fn delete_group(&self, group_id: &Uuid) -> Option<Group> {
        self.groups.remove(group_id).map(|(_, group)| group)
    }

    pub fn add_agent_to_group(&self, group_id: &Uuid, agent_id: Uuid) -> bool {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            if !group.agent_ids.contains(&agent_id) {
                group.agent_ids.push(agent_id);
                group.updated_at = Utc::now();
            }
            true
        } else {
            false
        }
    }

    pub fn remove_agent_from_group(&self, group_id: &Uuid, agent_id: &Uuid) -> bool {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            group.agent_ids.retain(|id| id != agent_id);
            group.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn list_groups(&self) -> Vec<Group> {
        self.groups
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_group_agents(&self, group_id: &Uuid) -> Vec<Uuid> {
        if let Some(group) = self.groups.get(group_id) {
            group.agent_ids.clone()
        } else {
            Vec::new()
        }
    }

    pub fn get_group(&self, group_id: &Uuid) -> Option<Group> {
        self.groups.get(group_id).map(|entry| entry.value().clone())
    }

    pub fn add_policy_to_group(&self, group_id: &Uuid, policy_id: Uuid) -> bool {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            if !group.policies.contains(&policy_id) {
                group.policies.push(policy_id);
                group.updated_at = Utc::now();
            }
            true
        } else {
            false
        }
    }

    pub fn remove_policy_from_group(&self, group_id: &Uuid, policy_id: &Uuid) -> bool {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            group.policies.retain(|id| id != policy_id);
            group.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn set_parent_group(&self, group_id: &Uuid, parent_group_id: Option<Uuid>) -> bool {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            group.parent_group = parent_group_id;
            group.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn add_auto_group_rule(&self, group_id: &Uuid, rule: AutoGroupRule) -> bool {
        if let Some(mut rules) = self.auto_group_rules.get_mut(group_id) {
            rules.push(rule);
            true
        } else {
            self.auto_group_rules.insert(*group_id, vec![rule]);
            true
        }
    }

    pub fn apply_auto_grouping(&self, agents: &[AgentInfo]) -> Vec<(Uuid, Vec<Uuid>)> {
        let mut group_assignments = Vec::new();

        for entry in self.auto_group_rules.iter() {
            let group_id = *entry.key();
            let rules = entry.value();
            let mut matching_agents = Vec::new();

            for agent in agents {
                let matches = rules.iter().any(|rule| {
                    match rule {
                        AutoGroupRule::ByOs { os_pattern } => {
                            agent.os.to_lowercase().contains(&os_pattern.to_lowercase())
                        }
                        AutoGroupRule::ByHostname { hostname_pattern } => {
                            agent.hostname.to_lowercase().contains(&hostname_pattern.to_lowercase())
                        }
                        AutoGroupRule::ByIpRange { ip_prefix } => {
                            agent.ip.starts_with(ip_prefix)
                        }
                        AutoGroupRule::ByTag { tag } => {
                            agent.tags.contains(tag)
                        }
                    }
                });

                if matches {
                    matching_agents.push(agent.id);
                }
            }

            if !matching_agents.is_empty() {
                if let Some(mut group) = self.groups.get_mut(&group_id) {
                    for agent_id in &matching_agents {
                        if !group.agent_ids.contains(agent_id) {
                            group.agent_ids.push(*agent_id);
                        }
                    }
                    group.updated_at = Utc::now();
                }
                group_assignments.push((group_id, matching_agents));
            }
        }

        group_assignments
    }
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}
