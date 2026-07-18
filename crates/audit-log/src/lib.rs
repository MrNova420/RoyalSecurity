pub mod prelude;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_RING_CAPACITY: usize = 100_000;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1_000;
const DEFAULT_BATCH_SIZE: usize = 512;
const GENESIS_HASH: &str =
    "6077d5207b21675f61b21b69332739b32c875e3c2b73c3c279d2e7b52c8f1e9a";

// ─── Severity ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AuditSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }
}

// ─── AuditEntry ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: AuditSeverity,
    pub source: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub entry_hash: String,
    pub previous_hash: String,
}

// ─── Config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub max_entries: usize,
    pub wal_path: Option<PathBuf>,
    pub flush_interval_ms: u64,
    pub batch_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_RING_CAPACITY,
            wal_path: None,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

// ─── Filter ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub severity: Option<AuditSeverity>,
    pub source: Option<String>,
    pub search_text: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ─── Chain Integrity ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIntegrity {
    pub valid: bool,
    pub total_entries: usize,
    pub broken_at: Option<usize>,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
}

// ─── Stats ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_entries: usize,
    pub total_appended: u64,
    pub by_severity: HashMap<String, usize>,
    pub by_type: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
}

// ─── Core ────────────────────────────────────────────────────────────

pub struct AuditLog {
    entries: Vec<Option<AuditEntry>>,
    head: usize,
    len: usize,
    capacity: usize,
    last_hash: String,
    next_id: u64,
    total_appended: u64,
    config: AuditConfig,
    wal: Option<Arc<RwLock<WalWriter>>>,
}

struct WalWriter {
    file: Option<fs::File>,
}

impl WalWriter {
    fn open(path: &Path) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        Self { file }
    }

    fn append_entry(&mut self, entry: &AuditEntry) {
        if let Some(ref mut file) = self.file {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(file, "{}", line);
                let _ = file.flush();
            }
        }
    }

    fn flush(&mut self) {
        if let Some(ref mut file) = self.file {
            let _ = file.flush();
        }
    }

}

impl AuditLog {
    pub fn new() -> Self {
        Self::with_config(AuditConfig::default())
    }

    pub fn with_config(config: AuditConfig) -> Self {
        let wal = config.wal_path.as_ref().map(|p| {
            Arc::new(RwLock::new(WalWriter::open(p)))
        });

        let capacity = config.max_entries;
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);

        Self {
            entries,
            head: 0,
            len: 0,
            capacity,
            last_hash: GENESIS_HASH.to_string(),
            next_id: 1,
            total_appended: 0,
            config,
            wal,
        }
    }

    fn compute_hash(&self, entry: &AuditEntry) -> String {
        let metadata_json = serde_json::to_string(&entry.metadata).unwrap_or_default();
        let input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            entry.previous_hash, entry.id, entry.timestamp, entry.event_type,
            entry.severity.as_str(), entry.source, entry.message, metadata_json
        );
        let mut hasher = Sha3_256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn append(
        &mut self,
        event_type: &str,
        severity: AuditSeverity,
        source: &str,
        message: &str,
        metadata: HashMap<String, String>,
    ) -> AuditEntry {
        let id = self.next_id;
        self.next_id += 1;

        let timestamp = Utc::now();
        let previous_hash = self.last_hash.clone();

        let mut entry = AuditEntry {
            id,
            timestamp,
            event_type: event_type.to_string(),
            severity,
            source: source.to_string(),
            message: message.to_string(),
            metadata,
            entry_hash: String::new(),
            previous_hash,
        };

        entry.entry_hash = self.compute_hash(&entry);
        self.last_hash = entry.entry_hash.clone();

        let idx = self.head % self.capacity;
        self.entries[idx] = Some(entry.clone());

        if self.len < self.capacity {
            self.len += 1;
        }
        self.head += 1;
        self.total_appended += 1;

        if let Some(ref wal) = self.wal {
            wal.write().append_entry(&entry);
        }

        tracing::debug!(
            id,
            event_type = %entry.event_type,
            severity = %entry.severity,
            "Audit entry appended"
        );

        entry
    }

    pub fn flush(&self) {
        if let Some(ref wal) = self.wal {
            wal.write().flush();
        }
    }

    pub fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        let snapshot: Vec<AuditEntry> = {
            let mut result = Vec::with_capacity(self.len);
            for i in 0..self.len {
                let slot = (self.head + self.capacity - self.len + i) % self.capacity;
                if let Some(ref entry) = self.entries[slot] {
                    result.push(entry.clone());
                }
            }
            result
        };

        snapshot
            .into_iter()
            .filter(|e| {
                if let Some(ref start) = filter.start_time {
                    if e.timestamp < *start {
                        return false;
                    }
                }
                if let Some(ref end) = filter.end_time {
                    if e.timestamp > *end {
                        return false;
                    }
                }
                if let Some(ref et) = filter.event_type {
                    if e.event_type != *et {
                        return false;
                    }
                }
                if let Some(ref sev) = filter.severity {
                    if e.severity != *sev {
                        return false;
                    }
                }
                if let Some(ref src) = filter.source {
                    if e.source != *src {
                        return false;
                    }
                }
                if let Some(ref text) = filter.search_text {
                    let needle = text.to_lowercase();
                    if !e.message.to_lowercase().contains(&needle)
                        && !e.event_type.to_lowercase().contains(&needle)
                        && !e.source.to_lowercase().contains(&needle)
                        && !e.metadata.values().any(|v| v.to_lowercase().contains(&needle))
                    {
                        return false;
                    }
                }
                true
            })
            .skip(filter.offset.unwrap_or(0))
            .take(filter.limit.unwrap_or(usize::MAX))
            .collect()
    }

    pub fn verify_chain(&self) -> ChainIntegrity {
        if self.len == 0 {
            return ChainIntegrity {
                valid: true,
                total_entries: 0,
                broken_at: None,
                expected_hash: None,
                actual_hash: None,
            };
        }

        let mut prev_hash = GENESIS_HASH.to_string();

        for i in 0..self.len {
            let slot = (self.head + self.capacity - self.len + i) % self.capacity;
            if let Some(ref entry) = self.entries[slot] {
                if entry.previous_hash != prev_hash {
                    let mut candidate = entry.clone();
                    candidate.previous_hash = prev_hash.clone();
                    let expected = self.compute_hash(&candidate);
                    return ChainIntegrity {
                        valid: false,
                        total_entries: self.len,
                        broken_at: Some(i),
                        expected_hash: Some(expected),
                        actual_hash: Some(entry.entry_hash.clone()),
                    };
                }

                let recomputed = self.compute_hash(entry);
                if recomputed != entry.entry_hash {
                    return ChainIntegrity {
                        valid: false,
                        total_entries: self.len,
                        broken_at: Some(i),
                        expected_hash: Some(recomputed),
                        actual_hash: Some(entry.entry_hash.clone()),
                    };
                }

                prev_hash = entry.entry_hash.clone();
            }
        }

        ChainIntegrity {
            valid: true,
            total_entries: self.len,
            broken_at: None,
            expected_hash: None,
            actual_hash: None,
        }
    }

    pub fn get_entry(&self, sequence: usize) -> Option<AuditEntry> {
        if sequence >= self.len {
            return None;
        }
        let slot = (self.head + self.capacity - self.len + sequence) % self.capacity;
        self.entries[slot].clone()
    }

    pub fn last_entry(&self) -> Option<AuditEntry> {
        if self.len == 0 {
            return None;
        }
        let slot = (self.head + self.capacity - 1) % self.capacity;
        self.entries[slot].clone()
    }

    pub fn entry_count(&self) -> usize {
        self.len
    }

    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    pub fn total_appended(&self) -> u64 {
        self.total_appended
    }

    pub fn export_json(&self) -> Result<String> {
        let entries = self.ordered_entries();
        serde_json::to_string_pretty(&entries).map_err(|e| RsError::Audit(e.to_string()))
    }

    pub fn export_csv(&self) -> Result<String> {
        let entries = self.ordered_entries();
        let mut out = String::with_capacity(entries.len() * 200);
        out.push_str("id,timestamp,event_type,severity,source,message,entry_hash,previous_hash\n");
        for entry in &entries {
            let meta_json = serde_json::to_string(&entry.metadata)
                .map_err(|e| RsError::Audit(e.to_string()))?;
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},\"{}\"\n",
                entry.id,
                entry.timestamp.to_rfc3339(),
                csv_escape(&entry.event_type),
                entry.severity.as_str(),
                csv_escape(&entry.source),
                csv_escape(&entry.message),
                entry.entry_hash,
                entry.previous_hash,
                meta_json,
            ));
        }
        Ok(out)
    }

    pub fn import_json(&mut self, json: &str) -> Result<usize> {
        let imported: Vec<AuditEntry> =
            serde_json::from_str(json).map_err(|e| RsError::Audit(e.to_string()))?;
        let count = imported.len();

        for entry in imported {
            if self.len >= self.capacity {
                break;
            }
            let idx = self.head % self.capacity;
            self.entries[idx] = Some(entry.clone());
            self.last_hash = entry.entry_hash.clone();
            self.next_id = self.next_id.max(entry.id + 1);
            if self.len < self.capacity {
                self.len += 1;
            }
            self.head += 1;
            self.total_appended += 1;

            if let Some(ref wal) = self.wal {
                wal.write().append_entry(&entry);
            }
        }

        tracing::info!(count, "Audit entries imported");
        Ok(count)
    }

    pub fn get_stats(&self) -> AuditStats {
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();

        for i in 0..self.len {
            let slot = (self.head + self.capacity - self.len + i) % self.capacity;
            if let Some(ref entry) = self.entries[slot] {
                *by_severity
                    .entry(entry.severity.as_str().to_string())
                    .or_insert(0) += 1;
                *by_type
                    .entry(entry.event_type.clone())
                    .or_insert(0) += 1;
                *by_source
                    .entry(entry.source.clone())
                    .or_insert(0) += 1;
            }
        }

        AuditStats {
            total_entries: self.len,
            total_appended: self.total_appended,
            by_severity,
            by_type,
            by_source,
        }
    }

    fn ordered_entries(&self) -> Vec<AuditEntry> {
        let mut result = Vec::with_capacity(self.len);
        for i in 0..self.len {
            let slot = (self.head + self.capacity - self.len + i) % self.capacity;
            if let Some(ref entry) = self.entries[slot] {
                result.push(entry.clone());
            }
        }
        result
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(k: &str, v: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(k.to_string(), v.to_string());
        m
    }

    #[test]
    fn test_new_log_is_empty() {
        let log = AuditLog::new();
        assert_eq!(log.entry_count(), 0);
        assert!(log.last_entry().is_none());
        assert_eq!(log.last_hash, GENESIS_HASH);
    }

    #[test]
    fn test_append_creates_entry_with_hash() {
        let mut log = AuditLog::new();
        let entry = log.append(
            "login",
            AuditSeverity::High,
            "auth-service",
            "User logged in",
            meta("user", "alice"),
        );
        assert_eq!(entry.id, 1);
        assert_eq!(entry.event_type, "login");
        assert_eq!(entry.severity, AuditSeverity::High);
        assert_eq!(entry.source, "auth-service");
        assert!(!entry.entry_hash.is_empty());
        assert_eq!(entry.previous_hash, GENESIS_HASH);
    }

    #[test]
    fn test_chain_builds_correctly() {
        let mut log = AuditLog::new();
        let e1 = log.append("a1", AuditSeverity::Info, "s", "m1", meta("k", "v"));
        let e2 = log.append("a2", AuditSeverity::Low, "s", "m2", meta("k", "v"));
        let e3 = log.append("a3", AuditSeverity::Medium, "s", "m3", meta("k", "v"));

        assert_eq!(e1.previous_hash, GENESIS_HASH);
        assert_eq!(e2.previous_hash, e1.entry_hash);
        assert_eq!(e3.previous_hash, e2.entry_hash);
        assert_ne!(e1.entry_hash, e2.entry_hash);
        assert_ne!(e2.entry_hash, e3.entry_hash);
    }

    #[test]
    fn test_verify_chain_passes_on_valid_log() {
        let mut log = AuditLog::new();
        for i in 0..25 {
            log.append(
                &format!("event_{}", i),
                AuditSeverity::Info,
                "test",
                &format!("message {}", i),
                meta("idx", &i.to_string()),
            );
        }
        let result = log.verify_chain();
        assert!(result.valid);
        assert_eq!(result.total_entries, 25);
        assert!(result.broken_at.is_none());
    }

    #[test]
    fn test_verify_chain_on_empty_log() {
        let log = AuditLog::new();
        let result = log.verify_chain();
        assert!(result.valid);
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_query_by_event_type() {
        let mut log = AuditLog::new();
        log.append("login", AuditSeverity::Info, "s", "m", meta("k", "v"));
        log.append("logout", AuditSeverity::Info, "s", "m", meta("k", "v"));
        log.append("login", AuditSeverity::Info, "s", "m", meta("k", "v"));

        let filter = AuditFilter {
            event_type: Some("login".into()),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.event_type == "login"));
    }

    #[test]
    fn test_query_by_severity() {
        let mut log = AuditLog::new();
        log.append("a", AuditSeverity::Critical, "s", "m", meta("k", "v"));
        log.append("a", AuditSeverity::Low, "s", "m", meta("k", "v"));
        log.append("a", AuditSeverity::Critical, "s", "m", meta("k", "v"));

        let filter = AuditFilter {
            severity: Some(AuditSeverity::Critical),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|e| e.severity == AuditSeverity::Critical));
    }

    #[test]
    fn test_query_by_source() {
        let mut log = AuditLog::new();
        log.append("a", AuditSeverity::Info, "svc-a", "m", meta("k", "v"));
        log.append("a", AuditSeverity::Info, "svc-b", "m", meta("k", "v"));
        log.append("a", AuditSeverity::Info, "svc-a", "m", meta("k", "v"));

        let filter = AuditFilter {
            source: Some("svc-a".into()),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_search_text() {
        let mut log = AuditLog::new();
        log.append("a", AuditSeverity::Info, "s", "failed login attempt", meta("k", "v"));
        log.append("b", AuditSeverity::Info, "s", "successful operation", meta("k", "v"));
        log.append("c", AuditSeverity::Info, "s", "failed to connect", meta("k", "v"));

        let filter = AuditFilter {
            search_text: Some("failed".into()),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_limit_and_offset() {
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.append(
                &format!("event_{}", i),
                AuditSeverity::Info,
                "s",
                "m",
                meta("k", "v"),
            );
        }

        let filter = AuditFilter {
            limit: Some(3),
            offset: Some(2),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].id, 3);
        assert_eq!(results[1].id, 4);
        assert_eq!(results[2].id, 5);
    }

    #[test]
    fn test_ring_buffer_overwrites_old_entries() {
        let config = AuditConfig {
            max_entries: 5,
            ..Default::default()
        };
        let mut log = AuditLog::with_config(config);

        for i in 0..8 {
            log.append(
                &format!("event_{}", i),
                AuditSeverity::Info,
                "s",
                "m",
                meta("k", &i.to_string()),
            );
        }

        assert_eq!(log.entry_count(), 5);
        assert_eq!(log.total_appended(), 8);
        let first = log.get_entry(0).unwrap();
        assert_eq!(first.event_type, "event_3");
    }

    #[test]
    fn test_get_entry_by_sequence() {
        let mut log = AuditLog::new();
        log.append("first", AuditSeverity::Info, "s", "m", meta("k", "v"));
        log.append("second", AuditSeverity::Info, "s", "m", meta("k", "v"));

        assert_eq!(log.get_entry(0).unwrap().event_type, "first");
        assert_eq!(log.get_entry(1).unwrap().event_type, "second");
        assert!(log.get_entry(2).is_none());
    }

    #[test]
    fn test_last_entry() {
        let mut log = AuditLog::new();
        assert!(log.last_entry().is_none());

        log.append("first", AuditSeverity::Info, "s", "m", meta("k", "v"));
        assert_eq!(log.last_entry().unwrap().event_type, "first");

        log.append("second", AuditSeverity::Info, "s", "m", meta("k", "v"));
        assert_eq!(log.last_entry().unwrap().event_type, "second");
    }

    #[test]
    fn test_unique_hashes_per_entry() {
        let mut log = AuditLog::new();
        let mut hashes = std::collections::HashSet::new();

        for i in 0..20 {
            let entry = log.append(
                &format!("event_{}", i),
                AuditSeverity::Info,
                "test",
                &format!("msg {}", i),
                meta("i", &i.to_string()),
            );
            assert!(
                hashes.insert(entry.entry_hash.clone()),
                "Duplicate hash: {}",
                entry.entry_hash
            );
        }
    }

    #[test]
    fn test_hash_includes_previous_hash() {
        let mut log = AuditLog::new();
        let e1 = log.append("a", AuditSeverity::Info, "s", "m", meta("k", "v"));
        let e2 = log.append("a", AuditSeverity::Info, "s", "m", meta("k", "v"));

        assert_eq!(e2.previous_hash, e1.entry_hash);
    }

    #[test]
    fn test_import_export_json_roundtrip() {
        let mut log = AuditLog::new();
        log.append("a1", AuditSeverity::High, "s1", "msg1", meta("k", "v1"));
        log.append("a2", AuditSeverity::Low, "s2", "msg2", meta("k", "v2"));

        let json = log.export_json().unwrap();
        assert!(json.contains("a1"));
        assert!(json.contains("a2"));

        let mut log2 = AuditLog::new();
        let imported = log2.import_json(&json).unwrap();
        assert_eq!(imported, 2);
        assert_eq!(log2.entry_count(), 2);
        assert_eq!(log2.get_entry(0).unwrap().event_type, "a1");
        assert_eq!(log2.get_entry(1).unwrap().event_type, "a2");
    }

    #[test]
    fn test_export_csv() {
        let mut log = AuditLog::new();
        log.append("event_a", AuditSeverity::Critical, "svc", "msg", meta("k", "v"));

        let csv = log.export_csv().unwrap();
        assert!(csv.contains("event_a"));
        assert!(csv.contains("Critical"));
        assert!(csv.contains("svc"));
    }

    #[test]
    fn test_get_stats() {
        let mut log = AuditLog::new();
        log.append("login", AuditSeverity::High, "auth", "msg1", meta("k", "v"));
        log.append("login", AuditSeverity::Critical, "auth", "msg2", meta("k", "v"));
        log.append("logout", AuditSeverity::Low, "auth", "msg3", meta("k", "v"));

        let stats = log.get_stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.by_type.get("login"), Some(&2));
        assert_eq!(stats.by_type.get("logout"), Some(&1));
        assert_eq!(stats.by_severity.get("High"), Some(&1));
        assert_eq!(stats.by_severity.get("Critical"), Some(&1));
        assert_eq!(stats.by_source.get("auth"), Some(&3));
    }

    #[test]
    fn test_import_json_rejects_invalid() {
        let mut log = AuditLog::new();
        let result = log.import_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_total_appended_counter() {
        let mut log = AuditLog::new();
        assert_eq!(log.total_appended(), 0);

        for i in 0..100 {
            log.append(
                &format!("e{}", i),
                AuditSeverity::Info,
                "s",
                "m",
                meta("k", "v"),
            );
        }
        assert_eq!(log.total_appended(), 100);
        assert_eq!(log.entry_count(), 100);
    }

    #[test]
    fn test_verify_chain_detects_tampered_entry() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(
                &format!("event_{}", i),
                AuditSeverity::Info,
                "s",
                "m",
                meta("k", "v"),
            );
        }

        let mut result = log.verify_chain();
        assert!(result.valid);

        {
            let slot = (log.head + log.capacity - log.len + 2) % log.capacity;
            if let Some(ref mut entry) = log.entries[slot] {
                entry.message = "TAMPERED".to_string();
            }
        }

        result = log.verify_chain();
        assert!(!result.valid);
        assert_eq!(result.broken_at, Some(2));
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", AuditSeverity::Critical), "Critical");
        assert_eq!(format!("{}", AuditSeverity::High), "High");
        assert_eq!(format!("{}", AuditSeverity::Medium), "Medium");
        assert_eq!(format!("{}", AuditSeverity::Low), "Low");
        assert_eq!(format!("{}", AuditSeverity::Info), "Info");
    }
}
