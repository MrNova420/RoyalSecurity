pub mod evtx;
pub mod mft;
pub mod prefetch;
pub mod registry;
pub mod shimcache;
pub mod amcache;
pub mod srum;
pub mod timeline;
pub mod lnk;
pub mod usn;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("Buffer too small: need {needed}, have {have}")]
    BufferTooSmall { needed: usize, have: usize },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ForensicError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub hostname: String,
    pub collected_at: DateTime<Utc>,
    pub evtx_events: Vec<evtx::EvtxEvent>,
    pub mft_entries: Vec<mft::MftEntry>,
    pub prefetch_files: Vec<prefetch::PrefetchEntry>,
    pub registry_keys: Vec<registry::RegistryEntry>,
    pub shimcache_entries: Vec<shimcache::ShimcacheEntry>,
    pub amcache_entries: Vec<amcache::AmcacheEntry>,
    pub srum_entries: Vec<srum::SrumEntry>,
    pub lnk_files: Vec<lnk::LnkEntry>,
    pub usn_entries: Vec<usn::UsnEntry>,
    pub timeline: Vec<timeline::TimelineEvent>,
}

pub async fn triage_system() -> Result<TriageReport> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_string());

    let mut report = TriageReport {
        hostname,
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
    };

    let evtx_paths = vec![
        r"C:\Windows\System32\winevt\Logs\Security.evtx",
        r"C:\Windows\System32\winevt\Logs\System.evtx",
        r"C:\Windows\System32\winevt\Logs\Application.evtx",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
    ];

    for path in &evtx_paths {
        match tokio::fs::read(path).await {
            Ok(data) => match evtx::parse_evtx(&data) {
                Ok(events) => report.evtx_events.extend(events),
                Err(e) => tracing::warn!("Failed to parse {}: {}", path, e),
            },
            Err(e) => tracing::warn!("Failed to read {}: {}", path, e),
        }
    }

    match tokio::fs::read(r"C:\").await {
        Ok(data) => match mft::parse_mft(&data) {
            Ok(entries) => report.mft_entries = entries,
            Err(e) => tracing::warn!("Failed to parse MFT: {}", e),
        },
        Err(e) => tracing::warn!("Failed to read MFT: {}", e),
    }

    let prefetch_dir = r"C:\Windows\Prefetch";
    if let Ok(mut entries) = tokio::fs::read_dir(prefetch_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                if name.to_uppercase().ends_with(".PF") {
                    match tokio::fs::read(entry.path()).await {
                        Ok(data) => match prefetch::parse_prefetch(&data) {
                            Ok(pf) => report.prefetch_files.push(pf),
                            Err(e) => tracing::warn!("Failed to parse {}: {}", name, e),
                        },
                        Err(e) => tracing::warn!("Failed to read {}: {}", name, e),
                    }
                }
            }
        }
    }

    let registry_paths = vec![
        (r"C:\Windows\System32\config\SAM", "HKLM\\SAM"),
        (r"C:\Windows\System32\config\SOFTWARE", "HKLM\\SOFTWARE"),
        (r"C:\Windows\System32\config\SYSTEM", "HKLM\\SYSTEM"),
        (r"C:\Windows\System32\config\SECURITY", "HKLM\\SECURITY"),
    ];

    for (path, hive_name) in &registry_paths {
        match tokio::fs::read(path).await {
            Ok(data) => match registry::parse_registry_hive(&data, hive_name) {
                Ok(entries) => report.registry_keys.extend(entries),
                Err(e) => tracing::warn!("Failed to parse {}: {}", hive_name, e),
            },
            Err(e) => tracing::warn!("Failed to read {}: {}", path, e),
        }
    }

    if let Ok(data) = tokio::fs::read(r"C:\Windows\System32\config\SYSTEM").await {
        match shimcache::parse_shimcache(&data) {
            Ok(entries) => report.shimcache_entries = entries,
            Err(e) => tracing::warn!("Failed to parse shimcache: {}", e),
        }
    }

    match tokio::fs::read(r"C:\Windows\appcompat\Programs\Amcache.hve").await {
        Ok(data) => match amcache::parse_amcache(&data) {
            Ok(entries) => report.amcache_entries = entries,
            Err(e) => tracing::warn!("Failed to parse amcache: {}", e),
        },
        Err(e) => tracing::warn!("Failed to read amcache: {}", e),
    }

    match tokio::fs::read(r"C:\Windows\System32\sru\SRUDB.dat").await {
        Ok(data) => match srum::parse_srum(&data) {
            Ok(entries) => report.srum_entries = entries,
            Err(e) => tracing::warn!("Failed to parse SRUM: {}", e),
        },
        Err(e) => tracing::warn!("Failed to read SRUM: {}", e),
    }

    let user_profile_dirs = match std::fs::read_dir(r"C:\Users") {
        Ok(dirs) => dirs,
        Err(e) => {
            tracing::warn!("Failed to read Users directory: {}", e);
            return Ok(report);
        }
    };

    for profile in user_profile_dirs.flatten() {
        let profile_path = profile.path();
        let lnk_dir = profile_path.join(r"AppData\Roaming\Microsoft\Windows\Recent");
        if let Ok(mut lnk_entries) = tokio::fs::read_dir(&lnk_dir).await {
            while let Ok(Some(entry)) = lnk_entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.to_uppercase().ends_with(".LNK") {
                        if let Ok(data) = tokio::fs::read(entry.path()).await {
                            match lnk::parse_lnk(&data) {
                                Ok(lnk) => report.lnk_files.push(lnk),
                                Err(e) => tracing::warn!("Failed to parse LNK {}: {}", name, e),
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(data) = tokio::fs::read(r"C:\").await {
        match usn::parse_usn_journal(&data) {
            Ok(entries) => report.usn_entries = entries,
            Err(e) => tracing::warn!("Failed to parse USN Journal: {}", e),
        }
    }

    report.timeline = timeline::build_timeline(&report);

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triage_report_serialization() {
        let report = TriageReport {
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
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: TriageReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, "TEST-PC");
    }

    #[test]
    fn test_forensic_error_display() {
        let err = ForensicError::InvalidMagic;
        assert_eq!(err.to_string(), "Invalid magic bytes");
    }

    #[test]
    fn test_buffer_too_small_error() {
        let err = ForensicError::BufferTooSmall { needed: 100, have: 50 };
        assert!(err.to_string().contains("100"));
    }

    #[test]
    fn test_triage_report_default_empty() {
        let report = TriageReport {
            hostname: String::new(),
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
        };
        assert!(report.evtx_events.is_empty());
        assert!(report.timeline.is_empty());
    }

    #[test]
    fn test_forensic_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = ForensicError::from(io_err);
        assert!(matches!(err, ForensicError::Io(_)));
    }
}
