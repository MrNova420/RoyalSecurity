use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::agent::AgentRegistry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStats {
    pub total_agents: usize,
    pub online_agents: usize,
    pub offline_agents: usize,
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub avg_compliance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_id: Uuid,
    pub hostname: String,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub event_rate: f64,
    pub last_error: Option<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTimeline {
    pub timestamp: DateTime<Utc>,
    pub online_count: usize,
    pub alert_count: usize,
    pub events_processed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHealth {
    pub stats: FleetStats,
    pub agent_health: Vec<AgentHealth>,
    pub timeline: Vec<FleetTimeline>,
}

#[derive(Debug, Clone)]
pub struct MonitoringService {
    agent_health: Arc<dashmap::DashMap<Uuid, AgentHealth>>,
    timeline: Arc<RwLock<Vec<FleetTimeline>>>,
    total_alerts: Arc<RwLock<usize>>,
    critical_alerts: Arc<RwLock<usize>>,
    compliance_scores: Arc<RwLock<Vec<f64>>>,
}

impl MonitoringService {
    pub fn new() -> Self {
        Self {
            agent_health: Arc::new(dashmap::DashMap::new()),
            timeline: Arc::new(RwLock::new(Vec::new())),
            total_alerts: Arc::new(RwLock::new(0)),
            critical_alerts: Arc::new(RwLock::new(0)),
            compliance_scores: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_fleet_stats(&self, agent_registry: &AgentRegistry) -> FleetStats {
        let agents = agent_registry.list_agents();
        let total_agents = agents.len();
        let online_agents = agent_registry.get_online_count();
        let offline_agents = total_agents - online_agents;

        let total_alerts = *self.total_alerts.read().await;
        let critical_alerts = *self.critical_alerts.read().await;

        let compliance_scores = self.compliance_scores.read().await;
        let avg_compliance_score = if compliance_scores.is_empty() {
            100.0
        } else {
            compliance_scores.iter().sum::<f64>() / compliance_scores.len() as f64
        };

        FleetStats {
            total_agents,
            online_agents,
            offline_agents,
            total_alerts,
            critical_alerts,
            avg_compliance_score,
        }
    }

    pub fn get_agent_health(&self, agent_id: &Uuid) -> Option<AgentHealth> {
        self.agent_health.get(agent_id).map(|entry| entry.value().clone())
    }

    pub fn update_agent_health(&self, health: AgentHealth) {
        self.agent_health.insert(health.agent_id, health);
    }

    pub async fn get_fleet_timeline(&self) -> Vec<FleetTimeline> {
        self.timeline.read().await.clone()
    }

    pub async fn add_timeline_entry(&self, entry: FleetTimeline) {
        let mut timeline = self.timeline.write().await;
        timeline.push(entry);
        if timeline.len() > 1000 {
            timeline.remove(0);
        }
    }

    pub async fn increment_alerts(&self, critical: bool) {
        let mut total = self.total_alerts.write().await;
        *total += 1;
        if critical {
            let mut critical = self.critical_alerts.write().await;
            *critical += 1;
        }
    }

    pub async fn add_compliance_score(&self, score: f64) {
        let mut scores = self.compliance_scores.write().await;
        scores.push(score);
        if scores.len() > 100 {
            scores.remove(0);
        }
    }

    pub async fn get_fleet_health(&self, agent_registry: &AgentRegistry) -> FleetHealth {
        let stats = self.get_fleet_stats(agent_registry).await;
        let agent_health = self.agent_health.iter().map(|entry| entry.value().clone()).collect();
        let timeline = self.get_fleet_timeline().await;

        FleetHealth {
            stats,
            agent_health,
            timeline,
        }
    }

    pub fn get_all_agent_health(&self) -> Vec<AgentHealth> {
        self.agent_health.iter().map(|entry| entry.value().clone()).collect()
    }
}

impl Default for MonitoringService {
    fn default() -> Self {
        Self::new()
    }
}
