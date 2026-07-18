use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::TriageReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub description: String,
    pub details: Vec<(String, String)>,
}

pub fn build_timeline(report: &TriageReport) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for event in &report.evtx_events {
        if let Some(ts) = event.timestamp {
            let mut details = event.data_fields.clone();
            details.push(("Channel".to_string(), event.channel.clone()));
            details.push(("Provider".to_string(), event.provider.clone()));
            details.push(("EventID".to_string(), event.event_id.to_string()));

            events.push(TimelineEvent {
                timestamp: ts,
                source: "EVTX".to_string(),
                event_type: determine_event_type(event.event_id, &event.channel),
                description: format!("Event ID {} from {}", event.event_id, event.channel),
                details,
            });
        }
    }

    for entry in &report.mft_entries {
        if let Some(ts) = entry.created {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "MFT".to_string(),
                event_type: "FileCreated".to_string(),
                description: format!("MFT entry {} created: {}", entry.entry_number, entry.file_name),
                details: vec![
                    ("EntryNumber".to_string(), entry.entry_number.to_string()),
                    ("FileName".to_string(), entry.file_name.clone()),
                    ("IsDirectory".to_string(), entry.is_directory.to_string()),
                ],
            });
        }

        if let Some(ts) = entry.modified {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "MFT".to_string(),
                event_type: "FileModified".to_string(),
                description: format!("MFT entry {} modified: {}", entry.entry_number, entry.file_name),
                details: vec![
                    ("EntryNumber".to_string(), entry.entry_number.to_string()),
                    ("FileName".to_string(), entry.file_name.clone()),
                    ("FileSize".to_string(), entry.file_size.to_string()),
                ],
            });
        }
    }

    for pf in &report.prefetch_files {
        if let Some(ts) = pf.last_run_time {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "Prefetch".to_string(),
                event_type: "ProgramExecution".to_string(),
                description: format!("{} executed ({} times)", pf.executable_name, pf.run_count),
                details: vec![
                    ("Executable".to_string(), pf.executable_name.clone()),
                    ("RunCount".to_string(), pf.run_count.to_string()),
                    ("Version".to_string(), pf.version.to_string()),
                    ("VolumeName".to_string(), pf.volume_name.clone()),
                ],
            });
        }
    }

    for entry in &report.registry_keys {
        if let Some(ts) = entry.last_written {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "Registry".to_string(),
                event_type: "RegistryModified".to_string(),
                description: format!("Registry key modified: {}", entry.key_path),
                details: vec![
                    ("KeyPath".to_string(), entry.key_path.clone()),
                    ("HiveName".to_string(), entry.hive_name.clone()),
                    ("Values".to_string(), entry.values.len().to_string()),
                ],
            });
        }
    }

    for entry in &report.shimcache_entries {
        if let Some(ts) = entry.last_modified {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "Shimcache".to_string(),
                event_type: "ProgramExecution".to_string(),
                description: format!("Shimcache: {}", entry.executable_path),
                details: vec![
                    ("Path".to_string(), entry.executable_path.clone()),
                    ("Flags".to_string(), entry.flags.to_string()),
                ],
            });
        }
    }

    for entry in &report.amcache_entries {
        if let Some(ts) = entry.install_date {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "Amcache".to_string(),
                event_type: "ProgramInstallation".to_string(),
                description: format!("Amcache: {} v{}", entry.program_name, entry.version),
                details: vec![
                    ("ProgramName".to_string(), entry.program_name.clone()),
                    ("Version".to_string(), entry.version.clone()),
                    ("Publisher".to_string(), entry.publisher.clone()),
                    ("SHA1".to_string(), entry.sha1.clone()),
                ],
            });
        }
    }

    for entry in &report.lnk_files {
        if let Some(ts) = entry.access_time {
            events.push(TimelineEvent {
                timestamp: ts,
                source: "LNK".to_string(),
                event_type: "FileAccess".to_string(),
                description: format!("LNK: {} -> {}", entry.local_base_path.as_deref().unwrap_or("?"), entry.target_path),
                details: vec![
                    ("OriginalPath".to_string(), entry.local_base_path.clone().unwrap_or_default()),
                    ("TargetPath".to_string(), entry.target_path.clone()),
                ],
            });
        }
    }

    for entry in &report.usn_entries {
        let ts = entry.timestamp;
        events.push(TimelineEvent {
            timestamp: ts,
            source: "USN".to_string(),
            event_type: format!("{:?}", entry.reason),
            description: format!("USN: {} ({:?})", entry.file_name, entry.reason),
            details: vec![
                ("FileName".to_string(), entry.file_name.clone()),
                ("FileReference".to_string(), entry.file_reference_number.to_string()),
                ("ParentReference".to_string(), entry.parent_file_reference_number.to_string()),
                ("Reason".to_string(), format!("{:?}", entry.reason)),
            ],
        });
    }

    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    events
}

fn determine_event_type(event_id: u32, channel: &str) -> String {
    match event_id {
        4624 | 4625 | 4634 | 4647 | 4648 => "Authentication".to_string(),
        4688 | 4689 => "ProcessCreation".to_string(),
        4697 | 4698 => "ServiceInstallation".to_string(),
        4699 | 4700 | 4701 | 4702 => "ScheduledTask".to_string(),
        4720 | 4722 | 4723 | 4724 | 4725 | 4726 | 4728 | 4732 | 4756 => "AccountManagement".to_string(),
        4768 | 4769 | 4770 => "KerberosAuth".to_string(),
        5140 | 5145 => "NetworkShare".to_string(),
        1100 | 1101 | 1102 => "AuditLog".to_string(),
        _ => {
            if channel.contains("Sysmon") {
                "Sysmon".to_string()
            } else if channel.contains("PowerShell") {
                "PowerShell".to_string()
            } else if channel.contains("TaskScheduler") {
                "TaskScheduler".to_string()
            } else {
                "Other".to_string()
            }
        }
    }
}

fn determine_usn_event_type(reason_code: u32) -> String {
    if reason_code & 0x00000001 != 0 { "FileCreated".to_string() }
    else if reason_code & 0x00000002 != 0 { "FileDeleted".to_string() }
    else if reason_code & 0x00000004 != 0 { "FileRenamed".to_string() }
    else if reason_code & 0x00000008 != 0 { "FileModified".to_string() }
    else if reason_code & 0x00000010 != 0 { "SecurityChange".to_string() }
    else { "OtherChange".to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TriageReport;
    use chrono::TimeZone;

    fn make_test_report() -> TriageReport {
        TriageReport {
            hostname: "TEST-PC".to_string(),
            collected_at: Utc::now(),
            evtx_events: Vec::new(),
            mft_entries: Vec::new(),
            prefetch_files: Vec::new(),
            registry_keys: Vec::new(),
            shimcache_entries: Vec::new(),
            amcache_entries: Vec::new(),
            srum_entries: Vec::new(),
            lnk_files: Vec::new(),
            usn_entries: Vec::new(),
            timeline: Vec::new(),
        }
    }

    #[test]
    fn test_build_timeline_empty() {
        let report = make_test_report();
        let timeline = build_timeline(&report);
        assert!(timeline.is_empty());
    }

    #[test]
    fn test_determine_event_type_auth() {
        assert_eq!(determine_event_type(4624, "Security"), "Authentication");
        assert_eq!(determine_event_type(4625, "Security"), "Authentication");
    }

    #[test]
    fn test_determine_event_type_process() {
        assert_eq!(determine_event_type(4688, "Security"), "ProcessCreation");
    }

    #[test]
    fn test_determine_event_type_sysmon() {
        assert_eq!(determine_event_type(1, "Microsoft-Windows-Sysmon/Operational"), "Sysmon");
    }

    #[test]
    fn test_determine_usn_event_type() {
        assert_eq!(determine_usn_event_type(0x01), "FileCreated");
        assert_eq!(determine_usn_event_type(0x02), "FileDeleted");
        assert_eq!(determine_usn_event_type(0x04), "FileRenamed");
        assert_eq!(determine_usn_event_type(0x08), "FileModified");
    }

    #[test]
    fn test_timeline_event_serialization() {
        let event = TimelineEvent {
            timestamp: Utc::now(),
            source: "EVTX".to_string(),
            event_type: "Authentication".to_string(),
            description: "Test event".to_string(),
            details: vec![("Key".to_string(), "Value".to_string())],
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("EVTX"));
        assert!(json.contains("Authentication"));
    }

    #[test]
    fn test_build_timeline_with_evtx() {
        let mut report = make_test_report();
        report.evtx_events.push(crate::evtx::EvtxEvent {
            event_id: 4624,
            timestamp: Some(Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap()),
            channel: "Security".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            level: 0,
            message: String::new(),
            data_fields: vec![],
            record_id: 12345,
        });
        let timeline = build_timeline(&report);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].source, "EVTX");
        assert_eq!(timeline[0].event_type, "Authentication");
    }
}
