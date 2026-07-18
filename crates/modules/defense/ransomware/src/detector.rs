use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{Utc, Duration};
use tracing::warn;

pub struct RansomwareDetector {
    file_modifications: HashMap<String, Vec<FileModEntry>>,
    _entropy_tracker: HashMap<String, f64>,
    config: RansomwareConfig,
    alert_count: u64,
    protected_dirs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RansomwareConfig {
    pub high_mod_rate_threshold: usize,
    pub entropy_threshold: f64,
    pub mass_rename_threshold: usize,
    pub monitoring_window_secs: i64,
    pub auto_quarantine: bool,
    pub auto_rollback: bool,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            high_mod_rate_threshold: 50,
            entropy_threshold: 7.5,
            mass_rename_threshold: 20,
            monitoring_window_secs: 60,
            auto_quarantine: true,
            auto_rollback: true,
        }
    }
}

#[derive(Debug, Clone)]
struct FileModEntry {
    path: String,
    timestamp: chrono::DateTime<Utc>,
    action: FileAction,
}

#[derive(Debug, Clone)]
pub struct RansomwareAlert {
    pub severity: EventSeverity,
    pub rule_name: String,
    pub details: String,
    pub affected_files: Vec<String>,
    pub mitre_technique: String,
}

impl RansomwareDetector {
    pub fn new() -> Self {
        Self {
            file_modifications: HashMap::new(),
            _entropy_tracker: HashMap::new(),
            config: RansomwareConfig::default(),
            alert_count: 0,
            protected_dirs: vec![
                "C:\\Users".into(),
                "C:\\ProgramData".into(),
                "D:\\".into(),
            ],
        }
    }

    pub fn with_config(config: RansomwareConfig) -> Self {
        let mut detector = Self::new();
        detector.config = config;
        detector
    }

    pub fn analyze_file_event(&mut self, path: &str, action: FileAction) -> Option<RansomwareAlert> {
        let now = Utc::now();
        let user_dir = self.extract_user_dir(path);

        self.file_modifications
            .entry(user_dir.clone())
            .or_insert_with(Vec::new)
            .push(FileModEntry {
                path: path.to_string(),
                timestamp: now,
                action,
            });

        // Clean old entries
        let window = Duration::seconds(self.config.monitoring_window_secs);
        if let Some(entries) = self.file_modifications.get_mut(&user_dir) {
            entries.retain(|e| e.timestamp > now - window);
        }

        self.detect_mass_modification(&user_dir)
            .or_else(|| self.detect_mass_rename(&user_dir))
    }

    fn detect_mass_modification(&mut self, user_dir: &str) -> Option<RansomwareAlert> {
        let count = self.file_modifications.get(user_dir)?.len();
        if count >= self.config.high_mod_rate_threshold {
            self.alert_count += 1;
            let affected: Vec<String> = self.file_modifications[user_dir]
                .iter()
                .map(|e| e.path.clone())
                .collect();

            warn!(
                dir = user_dir,
                count = count,
                "Mass file modification detected - possible ransomware"
            );

            Some(RansomwareAlert {
                severity: EventSeverity::Critical,
                rule_name: "Mass File Modification".into(),
                details: format!(
                    "{} files modified in {} within {}s (threshold: {})",
                    count, user_dir, self.config.monitoring_window_secs, self.config.high_mod_rate_threshold
                ),
                affected_files: affected.into_iter().take(50).collect(),
                mitre_technique: "T1486".into(),
            })
        } else {
            None
        }
    }

    fn detect_mass_rename(&mut self, user_dir: &str) -> Option<RansomwareAlert> {
        let entries = self.file_modifications.get(user_dir)?;
        let renames: usize = entries.iter().filter(|e| matches!(e.action, FileAction::Renamed)).count();

        if renames >= self.config.mass_rename_threshold {
            self.alert_count += 1;
            let affected: Vec<String> = entries
                .iter()
                .filter(|e| matches!(e.action, FileAction::Renamed))
                .map(|e| e.path.clone())
                .collect();

            warn!(
                dir = user_dir,
                renames = renames,
                "Mass file rename detected - possible ransomware"
            );

            Some(RansomwareAlert {
                severity: EventSeverity::Critical,
                rule_name: "Mass File Rename".into(),
                details: format!(
                    "{} files renamed in {} (threshold: {})",
                    renames, user_dir, self.config.mass_rename_threshold
                ),
                affected_files: affected.into_iter().take(50).collect(),
                mitre_technique: "T1486".into(),
            })
        } else {
            None
        }
    }

    fn extract_user_dir(&self, path: &str) -> String {
        let path_lower = path.to_lowercase();
        for prefix in &self.protected_dirs {
            if path_lower.starts_with(&prefix.to_lowercase()) {
                let parts: Vec<&str> = path.split('\\').collect();
                if parts.len() >= 4 {
                    return parts[0..3].join("\\");
                }
                return prefix.clone();
            }
        }
        path.to_string()
    }

    pub fn check_ransomware_extension(&self, path: &str) -> bool {
        let ransomware_exts = [
            ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
            ".ryk", ".ryuk", ".wannacry", ".wncry", ".locky",
            ".cerber", ".zepto", ".thor", ".aesir", ".zzzzz",
            ".zzzz", ".ecc", ".ezz", ".aaa", ".abc",
            ".xyz", ".ttt", ".vvv", ".xxx", ".crypted",
        ];
        let path_lower = path.to_lowercase();
        ransomware_exts.iter().any(|ext| path_lower.ends_with(ext))
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    pub fn stats(&self) -> RansomwareStats {
        RansomwareStats {
            monitored_dirs: self.protected_dirs.len(),
            active_modifications: self.file_modifications.values().map(|v| v.len()).sum(),
            alert_count: self.alert_count,
            auto_quarantine: self.config.auto_quarantine,
            auto_rollback: self.config.auto_rollback,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RansomwareStats {
    pub monitored_dirs: usize,
    pub active_modifications: usize,
    pub alert_count: u64,
    pub auto_quarantine: bool,
    pub auto_rollback: bool,
}
