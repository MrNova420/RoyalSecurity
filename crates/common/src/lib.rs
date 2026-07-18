pub mod error;
pub mod types;
pub mod mitre;
pub mod constants;
pub mod prelude;

#[cfg(test)]
mod tests {
    use crate::types::*;
    use crate::mitre::*;
    use crate::constants::*;

    #[test]
    fn test_event_severity_display() {
        assert_eq!(format!("{}", EventSeverity::Critical), "Critical");
        assert_eq!(format!("{}", EventSeverity::High), "High");
        assert_eq!(format!("{}", EventSeverity::Medium), "Medium");
        assert_eq!(format!("{}", EventSeverity::Low), "Low");
        assert_eq!(format!("{}", EventSeverity::Informational), "Informational");
    }

    #[test]
    fn test_event_type_count() {
        let variants: Vec<_> = <EventType as strum::IntoEnumIterator>::iter().collect();
        assert!(variants.len() >= 50, "Should have at least 50 event types, got {}", variants.len());
    }

    #[test]
    fn test_mitre_tactics_count() {
        let tactics: Vec<_> = <Tactic as strum::IntoEnumIterator>::iter().collect();
        assert_eq!(tactics.len(), 14, "Should have exactly 14 MITRE tactics");
    }

    #[test]
    fn test_mitre_techniques_lookup() {
        let initial_access = get_techniques_for_tactic(Tactic::InitialAccess);
        assert!(!initial_access.is_empty(), "InitialAccess should have techniques");
        
        let execution = get_techniques_for_tactic(Tactic::Execution);
        assert!(!execution.is_empty(), "Execution should have techniques");
    }

    #[test]
    fn test_classify_event_to_technique() {
        let process_event = EventType::ProcessCreated;
        let techniques = classify_event_to_technique(&process_event);
        assert!(!techniques.is_empty(), "ProcessCreated should map to techniques");
    }

    #[test]
    fn test_constants() {
        assert_eq!(APP_NAME, "RoyalSecurity");
        assert_eq!(SERVICE_NAME, "RoyalSecurityAgent");
        assert!(MAX_MEMORY_MB >= 80);
        assert!(MAX_EVENTS_PER_SECOND >= 100_000);
    }

    #[test]
    fn test_security_event_default() {
        let event = SecurityEventEnvelope::default();
        assert_eq!(event.severity, EventSeverity::Informational);
    }

    #[test]
    fn test_module_health_default() {
        let health = ModuleHealth::default();
        assert_eq!(health.status, ModuleStatus::Uninitialized);
        assert_eq!(health.events_processed, 0);
    }

    #[test]
    fn test_process_info_creation() {
        let proc = ProcessInfo {
            pid: 1234,
            ppid: 567,
            name: "test.exe".into(),
            path: "C:\\test.exe".into(),
            command_line: "test.exe --flag".into(),
            user: "SYSTEM".into(),
            hash_sha256: None,
            integrity_level: Some("High".into()),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.name, "test.exe");
    }

    #[test]
    fn test_file_action_variants() {
        assert!(format!("{}", FileAction::Created).contains("Created"));
        assert!(format!("{}", FileAction::Deleted).contains("Deleted"));
    }

    #[test]
    fn test_threat_status_variants() {
        let statuses = vec![
            ThreatStatus::Active,
            ThreatStatus::Investigating,
            ThreatStatus::Contained,
            ThreatStatus::Eradicated,
            ThreatStatus::Recovered,
            ThreatStatus::FalsePositive,
        ];
        assert_eq!(statuses.len(), 6);
    }
}
