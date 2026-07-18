use royalsecurity_common::types::*;
use std::collections::HashMap;
use tracing::info;

pub struct PersistenceDetector {
    baseline: HashMap<String, PersistenceEntry>,
    checks: Vec<PersistenceCheck>,
}

#[derive(Debug, Clone)]
pub struct PersistenceEntry {
    pub location: String,
    pub entry_type: PersistenceType,
    pub value: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PersistenceType {
    RunKey,
    RunOnceKey,
    Service,
    ScheduledTask,
    WmiSubscription,
    StartupFolder,
    AppInitDlls,
    ImageFileExecution,
    WinlogonHelper,
    COMObject,
    FolderRedirection,
    ProtocolHandler,
}

#[derive(Debug, Clone)]
pub struct PersistenceCheck {
    pub name: String,
    pub persistence_type: PersistenceType,
    pub location: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct PersistenceAlert {
    pub persistence_type: PersistenceType,
    pub location: String,
    pub value: String,
    pub severity: EventSeverity,
    pub details: String,
}

impl PersistenceDetector {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
            checks: Self::default_checks(),
        }
    }

    fn default_checks() -> Vec<PersistenceCheck> {
        vec![
            PersistenceCheck {
                name: "Run Key HKLM".into(),
                persistence_type: PersistenceType::RunKey,
                location: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                description: "System-wide Run key".into(),
            },
            PersistenceCheck {
                name: "Run Key HKCU".into(),
                persistence_type: PersistenceType::RunKey,
                location: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                description: "User Run key".into(),
            },
            PersistenceCheck {
                name: "RunOnce Key HKLM".into(),
                persistence_type: PersistenceType::RunOnceKey,
                location: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                description: "System RunOnce key".into(),
            },
            PersistenceCheck {
                name: "Services".into(),
                persistence_type: PersistenceType::Service,
                location: "HKLM\\SYSTEM\\CurrentControlSet\\Services".into(),
                description: "Windows services".into(),
            },
            PersistenceCheck {
                name: "Scheduled Tasks".into(),
                persistence_type: PersistenceType::ScheduledTask,
                location: "C:\\Windows\\System32\\Tasks".into(),
                description: "Scheduled tasks".into(),
            },
            PersistenceCheck {
                name: "WMI Subscriptions".into(),
                persistence_type: PersistenceType::WmiSubscription,
                location: "root\\subscription".into(),
                description: "WMI event subscriptions".into(),
            },
            PersistenceCheck {
                name: "Startup Folder HKLM".into(),
                persistence_type: PersistenceType::StartupFolder,
                location: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".into(),
                description: "All-users startup folder".into(),
            },
            PersistenceCheck {
                name: "Startup Folder HKCU".into(),
                persistence_type: PersistenceType::StartupFolder,
                location: "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".into(),
                description: "User startup folder".into(),
            },
            PersistenceCheck {
                name: "AppInit DLLs".into(),
                persistence_type: PersistenceType::AppInitDlls,
                location: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows".into(),
                description: "AppInit DLLs loading".into(),
            },
            PersistenceCheck {
                name: "Image File Execution Options".into(),
                persistence_type: PersistenceType::ImageFileExecution,
                location: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options".into(),
                description: "Debugger hijacking via IFEO".into(),
            },
            PersistenceCheck {
                name: "Winlogon Helpers".into(),
                persistence_type: PersistenceType::WinlogonHelper,
                location: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon".into(),
                description: "Winlogon notification packages".into(),
            },
            PersistenceCheck {
                name: "COM Objects".into(),
                persistence_type: PersistenceType::COMObject,
                location: "HKLM\\SOFTWARE\\Classes\\CLSID".into(),
                description: "COM server registrations".into(),
            },
        ]
    }

    pub fn record_entry(&mut self, location: &str, entry_type: PersistenceType, value: &str) -> Option<PersistenceAlert> {
        let key = format!("{}:{}", location, value);

        if self.baseline.contains_key(&key) {
            return None;
        }

        let entry = PersistenceEntry {
            location: location.to_string(),
            entry_type: entry_type.clone(),
            value: value.to_string(),
            first_seen: chrono::Utc::now(),
        };

        self.baseline.insert(key, entry);

        let severity = match &entry_type {
            PersistenceType::RunKey | PersistenceType::RunOnceKey => EventSeverity::Medium,
            PersistenceType::Service => EventSeverity::Medium,
            PersistenceType::ScheduledTask => EventSeverity::Medium,
            PersistenceType::WmiSubscription => EventSeverity::High,
            PersistenceType::AppInitDlls | PersistenceType::ImageFileExecution => EventSeverity::High,
            PersistenceType::WinlogonHelper => EventSeverity::Critical,
            PersistenceType::COMObject => EventSeverity::Medium,
            _ => EventSeverity::Low,
        };

        info!(
            persistence_type = ?entry_type,
            location = location,
            value = value,
            "New persistence entry detected"
        );

        Some(PersistenceAlert {
            persistence_type: entry_type,
            location: location.to_string(),
            value: value.to_string(),
            severity,
            details: format!("New persistence entry: {} at {}", value, location),
        })
    }

    pub fn checks(&self) -> &[PersistenceCheck] {
        &self.checks
    }

    pub fn baseline_count(&self) -> usize {
        self.baseline.len()
    }

    pub fn get_entries_by_type(&self, ptype: &PersistenceType) -> Vec<&PersistenceEntry> {
        self.baseline.values().filter(|e| &e.entry_type == ptype).collect()
    }
}
