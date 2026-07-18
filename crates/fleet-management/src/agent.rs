use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Online,
    Offline,
    Updating,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: Uuid,
    pub hostname: String,
    pub os: String,
    pub ip: String,
    pub version: String,
    pub status: AgentStatus,
    pub last_seen: DateTime<Utc>,
    pub registered_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

impl AgentInfo {
    pub fn new(hostname: String, os: String, ip: String, version: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            hostname,
            os,
            ip,
            version,
            status: AgentStatus::Online,
            last_seen: now,
            registered_at: now,
            tags: Vec::new(),
        }
    }

    pub fn is_stale(&self) -> bool {
        let now = Utc::now();
        let duration = now.signed_duration_since(self.last_seen);
        duration.num_minutes() > 5
    }
}

#[derive(Debug, Clone)]
pub struct AgentRegistry {
    agents: Arc<DashMap<Uuid, AgentInfo>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(DashMap::new()),
        }
    }

    pub fn register_agent(&self, mut agent: AgentInfo) -> Uuid {
        let id = agent.id;
        agent.status = AgentStatus::Online;
        agent.last_seen = Utc::now();
        self.agents.insert(id, agent);
        id
    }

    pub fn unregister_agent(&self, agent_id: &Uuid) -> Option<AgentInfo> {
        self.agents.remove(agent_id).map(|(_, agent)| agent)
    }

    pub fn heartbeat(&self, agent_id: &Uuid) -> bool {
        if let Some(mut agent) = self.agents.get_mut(agent_id) {
            agent.last_seen = Utc::now();
            agent.status = AgentStatus::Online;
            true
        } else {
            false
        }
    }

    pub fn get_agent(&self, agent_id: &Uuid) -> Option<AgentInfo> {
        self.agents.get(agent_id).map(|agent| agent.clone())
    }

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        self.agents.iter().map(|entry| entry.value().clone()).collect()
    }

    pub fn get_online_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|entry| entry.value().status == AgentStatus::Online)
            .count()
    }

    pub fn detect_stale_agents(&self) -> Vec<Uuid> {
        let mut stale_ids = Vec::new();
        for entry in self.agents.iter() {
            if entry.value().is_stale() {
                let mut agent = entry.value().clone();
                agent.status = AgentStatus::Offline;
                stale_ids.push(*entry.key());
            }
        }
        for id in &stale_ids {
            if let Some(mut agent) = self.agents.get_mut(id) {
                agent.status = AgentStatus::Offline;
            }
        }
        stale_ids
    }

    pub fn add_tag(&self, agent_id: &Uuid, tag: String) -> bool {
        if let Some(mut agent) = self.agents.get_mut(agent_id) {
            if !agent.tags.contains(&tag) {
                agent.tags.push(tag);
            }
            true
        } else {
            false
        }
    }

    pub fn remove_tag(&self, agent_id: &Uuid, tag: &str) -> bool {
        if let Some(mut agent) = self.agents.get_mut(agent_id) {
            agent.tags.retain(|t| t != tag);
            true
        } else {
            false
        }
    }

    pub fn get_agents_by_tag(&self, tag: &str) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter(|entry| entry.value().tags.contains(&tag.to_string()))
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_agents_by_os(&self, os: &str) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter(|entry| entry.value().os == os)
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}
