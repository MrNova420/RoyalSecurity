pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityThreatType {
    TokenManipulation,
    SidHistoryInjection,
    CredentialDump,
    PasswordSpray,
    PassTheHash,
    PassTheTicket,
    Kerberoasting,
    UnconstrainedDelegation,
}

impl std::fmt::Display for IdentityThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityThreatType::TokenManipulation => write!(f, "Token Manipulation"),
            IdentityThreatType::SidHistoryInjection => write!(f, "SID History Injection"),
            IdentityThreatType::CredentialDump => write!(f, "Credential Dump"),
            IdentityThreatType::PasswordSpray => write!(f, "Password Spray"),
            IdentityThreatType::PassTheHash => write!(f, "Pass-the-Hash"),
            IdentityThreatType::PassTheTicket => write!(f, "Pass-the-Ticket"),
            IdentityThreatType::Kerberoasting => write!(f, "Kerberoasting"),
            IdentityThreatType::UnconstrainedDelegation => write!(f, "Unconstrained Delegation"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEvent {
    pub user: String,
    pub event_type: IdentityThreatType,
    pub source_ip: Option<String>,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityThreat {
    pub id: Uuid,
    pub user: String,
    pub threat_type: IdentityThreatType,
    pub severity: EventSeverity,
    pub description: String,
    pub mitre_technique: String,
    pub source_ip: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct ItdrEngine {
    user_baselines: HashMap<String, UserBaseline>,
    threats: Vec<IdentityThreat>,
    threat_count: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UserBaseline {
    pub known_sids: Vec<String>,
    pub known_tokens: Vec<String>,
    pub login_count: u64,
    pub last_login: Option<DateTime<Utc>>,
}

impl ItdrEngine {
    pub fn new() -> Self {
        info!("Initializing Identity Threat Detection and Response engine");
        Self {
            user_baselines: HashMap::new(),
            threats: Vec::new(),
            threat_count: 0,
        }
    }

    pub fn analyze_identity_event(&mut self, event: &IdentityEvent) -> Vec<IdentityThreat> {
        let mut threats = Vec::new();

        let baseline = self
            .user_baselines
            .entry(event.user.clone())
            .or_insert_with(UserBaseline::default);

        baseline.login_count += 1;

        match event.event_type {
            IdentityThreatType::TokenManipulation => {
                warn!(
                    user = %event.user,
                    source_ip = ?event.source_ip,
                    "Token manipulation detected"
                );
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::TokenManipulation,
                    severity: EventSeverity::Critical,
                    description: format!(
                        "Token manipulation detected for user {} - {}", event.user, event.details
                    ),
                    mitre_technique: "T1134".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::SidHistoryInjection => {
                warn!(
                    user = %event.user,
                    "SID history injection detected"
                );
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::SidHistoryInjection,
                    severity: EventSeverity::Critical,
                    description: format!(
                        "SID history injection for user {}: {}", event.user, event.details
                    ),
                    mitre_technique: "T1134.005".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::CredentialDump => {
                warn!(user = %event.user, "Credential dump attempt detected");
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::CredentialDump,
                    severity: EventSeverity::Critical,
                    description: format!(
                        "Credential dump detected for user {}", event.user
                    ),
                    mitre_technique: "T1003".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::PasswordSpray => {
                warn!(
                    source_ip = ?event.source_ip,
                    "Password spray attack detected"
                );
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::PasswordSpray,
                    severity: EventSeverity::High,
                    description: format!(
                        "Password spray attack targeting user {}", event.user
                    ),
                    mitre_technique: "T1110.003".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::PassTheHash => {
                warn!(user = %event.user, "Pass-the-Hash detected");
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::PassTheHash,
                    severity: EventSeverity::Critical,
                    description: format!(
                        "Pass-the-Hash attack using user {}'s credentials", event.user
                    ),
                    mitre_technique: "T1550.002".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::PassTheTicket => {
                warn!(user = %event.user, "Pass-the-Ticket detected");
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::PassTheTicket,
                    severity: EventSeverity::Critical,
                    description: format!(
                        "Pass-the-Ticket attack using user {}'s Kerberos ticket", event.user
                    ),
                    mitre_technique: "T1550.003".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::Kerberoasting => {
                warn!(user = %event.user, "Kerberoasting attempt detected");
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::Kerberoasting,
                    severity: EventSeverity::High,
                    description: format!(
                        "Kerberoasting attack by user {} requesting multiple SPN tickets", event.user
                    ),
                    mitre_technique: "T1558.003".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
            IdentityThreatType::UnconstrainedDelegation => {
                warn!(
                    user = %event.user,
                    "Unconstrained delegation configuration detected"
                );
                let threat = IdentityThreat {
                    id: Uuid::new_v4(),
                    user: event.user.clone(),
                    threat_type: IdentityThreatType::UnconstrainedDelegation,
                    severity: EventSeverity::Medium,
                    description: format!(
                        "Unconstrained delegation configured: {}", event.details
                    ),
                    mitre_technique: "T1558".to_string(),
                    source_ip: event.source_ip.clone(),
                    timestamp: Utc::now(),
                };
                threats.push(threat);
            }
        }

        self.threat_count += threats.len() as u64;
        for t in &threats {
            self.threats.push(t.clone());
        }

        threats
    }

    pub fn detect_token_manipulation(
        &mut self,
        user: &str,
        source_token: &str,
        target_token: &str,
    ) -> Vec<IdentityThreat> {
        if source_token != target_token {
            warn!(
                user = user,
                source = source_token,
                target = target_token,
                "Token mismatch indicates manipulation"
            );
            let event = IdentityEvent {
                user: user.to_string(),
                event_type: IdentityThreatType::TokenManipulation,
                source_ip: None,
                details: format!(
                    "Source token {} differs from target token {}",
                    source_token, target_token
                ),
                timestamp: Utc::now(),
            };
            self.analyze_identity_event(&event)
        } else {
            Vec::new()
        }
    }

    pub fn detect_sid_history(
        &mut self,
        user: &str,
        added_sids: &[String],
    ) -> Vec<IdentityThreat> {
        if added_sids.is_empty() {
            return Vec::new();
        }

        let baseline = self
            .user_baselines
            .entry(user.to_string())
            .or_insert_with(UserBaseline::default);

        let mut new_sids: Vec<String> = added_sids
            .iter()
            .filter(|sid| !baseline.known_sids.contains(sid))
            .cloned()
            .collect();

        if new_sids.is_empty() {
            return Vec::new();
        }

        baseline.known_sids.append(&mut new_sids.clone());

        let event = IdentityEvent {
            user: user.to_string(),
            event_type: IdentityThreatType::SidHistoryInjection,
            source_ip: None,
            details: format!("New SIDs added: {:?}", new_sids),
            timestamp: Utc::now(),
        };
        self.analyze_identity_event(&event)
    }

    pub fn threat_count(&self) -> u64 {
        self.threat_count
    }

    pub fn threats(&self) -> &[IdentityThreat] {
        &self.threats
    }
}

impl Default for ItdrEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(user: &str, threat_type: IdentityThreatType) -> IdentityEvent {
        IdentityEvent {
            user: user.to_string(),
            event_type: threat_type,
            source_ip: Some("10.0.0.100".to_string()),
            details: "Test event".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_itdr_engine_new() {
        let engine = ItdrEngine::new();
        assert_eq!(engine.threat_count(), 0);
        assert!(engine.threats().is_empty());
    }

    #[test]
    fn test_analyze_token_manipulation() {
        let mut engine = ItdrEngine::new();
        let event = make_event("admin", IdentityThreatType::TokenManipulation);
        let threats = engine.analyze_identity_event(&event);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, IdentityThreatType::TokenManipulation);
        assert_eq!(threats[0].severity, EventSeverity::Critical);
        assert_eq!(threats[0].mitre_technique, "T1134");
        assert_eq!(engine.threat_count(), 1);
    }

    #[test]
    fn test_analyze_sid_history_injection() {
        let mut engine = ItdrEngine::new();
        let event = make_event("admin", IdentityThreatType::SidHistoryInjection);
        let threats = engine.analyze_identity_event(&event);
        assert_eq!(threats.len(), 1);
        assert_eq!(
            threats[0].threat_type,
            IdentityThreatType::SidHistoryInjection
        );
    }

    #[test]
    fn test_analyze_kerberoasting() {
        let mut engine = ItdrEngine::new();
        let event = make_event("svc_account", IdentityThreatType::Kerberoasting);
        let threats = engine.analyze_identity_event(&event);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, EventSeverity::High);
        assert_eq!(threats[0].mitre_technique, "T1558.003");
    }

    #[test]
    fn test_detect_token_manipulation_different_tokens() {
        let mut engine = ItdrEngine::new();
        let threats = engine.detect_token_manipulation("admin", "token_a", "token_b");
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, IdentityThreatType::TokenManipulation);
    }

    #[test]
    fn test_detect_token_manipulation_same_tokens() {
        let mut engine = ItdrEngine::new();
        let threats = engine.detect_token_manipulation("admin", "token_a", "token_a");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_detect_sid_history_new_sids() {
        let mut engine = ItdrEngine::new();
        let sids = vec!["S-1-5-21-1234567890-1234567890-1234567890-500".to_string()];
        let threats = engine.detect_sid_history("admin", &sids);
        assert_eq!(threats.len(), 1);
    }

    #[test]
    fn test_detect_sid_history_known_sids_no_alert() {
        let mut engine = ItdrEngine::new();
        let sids = vec!["S-1-5-21-1234567890-1234567890-1234567890-500".to_string()];
        engine.detect_sid_history("admin", &sids);
        let threats2 = engine.detect_sid_history("admin", &sids);
        assert!(threats2.is_empty());
    }

    #[test]
    fn test_detect_sid_history_empty() {
        let mut engine = ItdrEngine::new();
        let threats = engine.detect_sid_history("admin", &[]);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_threat_count_accumulates() {
        let mut engine = ItdrEngine::new();
        let e1 = make_event("user1", IdentityThreatType::CredentialDump);
        let e2 = make_event("user2", IdentityThreatType::PassTheHash);
        engine.analyze_identity_event(&e1);
        engine.analyze_identity_event(&e2);
        assert_eq!(engine.threat_count(), 2);
    }

    #[test]
    fn test_password_spray_severity() {
        let mut engine = ItdrEngine::new();
        let event = make_event("user", IdentityThreatType::PasswordSpray);
        let threats = engine.analyze_identity_event(&event);
        assert_eq!(threats[0].severity, EventSeverity::High);
        assert_eq!(threats[0].mitre_technique, "T1110.003");
    }
}
