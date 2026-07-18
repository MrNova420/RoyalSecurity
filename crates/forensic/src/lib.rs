pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaseStatus {
    Open,
    Investigating,
    Closed,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    MftEntry,
    PrefetchFile,
    RegistryHive,
    EventLog,
    PcapCapture,
    MemoryDump,
    DiskImage,
    LogFile,
    Amcache,
    ShimCache,
    SRUM,
    JumpList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum EventSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicCase {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub status: CaseStatus,
    pub evidence_count: u32,
    pub analyst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: Uuid,
    pub case_id: String,
    pub source: String,
    pub evidence_type: EvidenceType,
    pub hash_sha256: String,
    pub collected_at: DateTime<Utc>,
    pub description: String,
    pub chain_of_custody: Vec<CustodyEntry>,
    #[serde(skip)]
    raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub handler: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub description: String,
    pub severity: EventSeverity,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    pub file_name: String,
    pub parent_dir: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub file_size: u64,
    pub attributes: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run: DateTime<Utc>,
    pub file_refs: Vec<String>,
    pub volume_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub value_type: String,
    pub last_modified: DateTime<Utc>,
}

pub struct ForensicEngine {
    pub cases: HashMap<String, ForensicCase>,
    pub evidence_store: Vec<EvidenceItem>,
    pub timeline: Vec<TimelineEntry>,
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

impl ForensicEngine {
    pub fn new() -> Self {
        Self {
            cases: HashMap::new(),
            evidence_store: Vec::new(),
            timeline: Vec::new(),
        }
    }

    pub fn create_case(&mut self, name: &str, description: &str, analyst: &str) -> String {
        let case_id = Uuid::new_v4().to_string();
        let case = ForensicCase {
            id: case_id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            created_at: Utc::now(),
            status: CaseStatus::Open,
            evidence_count: 0,
            analyst: analyst.to_string(),
        };
        info!(case_id = %case_id, name = %name, "Created forensic case");
        self.cases.insert(case_id.clone(), case);
        case_id
    }

    pub fn close_case(&mut self, case_id: &str) -> bool {
        if let Some(case) = self.cases.get_mut(case_id) {
            case.status = CaseStatus::Closed;
            info!(case_id = %case_id, "Closed forensic case");
            true
        } else {
            false
        }
    }

    pub fn add_evidence(
        &mut self,
        case_id: &str,
        source: &str,
        evidence_type: EvidenceType,
        data: &[u8],
    ) -> Uuid {
        let hash = compute_sha256(data);
        let evidence_id = Uuid::new_v4();
        let item = EvidenceItem {
            id: evidence_id,
            case_id: case_id.to_string(),
            source: source.to_string(),
            evidence_type,
            hash_sha256: hash.clone(),
            collected_at: Utc::now(),
            description: String::new(),
            chain_of_custody: vec![CustodyEntry {
                handler: "system".to_string(),
                action: "collected".to_string(),
                timestamp: Utc::now(),
                notes: format!("Initial collection from {}", source),
            }],
            raw_data: data.to_vec(),
        };
        if let Some(case) = self.cases.get_mut(case_id) {
            case.evidence_count += 1;
        }
        info!(
            evidence_id = %evidence_id,
            case_id = %case_id,
            hash = %hash,
            "Added evidence item"
        );
        self.evidence_store.push(item);
        evidence_id
    }

    pub fn collect_mft_entry(&mut self, entry: MftEntry) -> Uuid {
        let serialized = serde_json::to_vec(&entry).unwrap_or_default();
        let evidence_id = self.add_evidence("", "MFT", EvidenceType::MftEntry, &serialized);
        let severity = if entry.is_directory {
            EventSeverity::Informational
        } else {
            EventSeverity::Low
        };
        self.timeline.push(TimelineEntry {
            timestamp: entry.created,
            source: "MFT".to_string(),
            event_type: "file_record".to_string(),
            description: format!("MFT entry: {} in {}", entry.file_name, entry.parent_dir),
            severity,
            artifacts: vec![entry.file_name.clone()],
        });
        evidence_id
    }

    pub fn collect_prefetch(&mut self, entry: PrefetchEntry) -> Uuid {
        let serialized = serde_json::to_vec(&entry).unwrap_or_default();
        let evidence_id = self.add_evidence("", "Prefetch", EvidenceType::PrefetchFile, &serialized);
        self.timeline.push(TimelineEntry {
            timestamp: entry.last_run,
            source: "Prefetch".to_string(),
            event_type: "prefetch_execution".to_string(),
            description: format!(
                "Prefetch: {} ran {} times",
                entry.executable_name, entry.run_count
            ),
            severity: EventSeverity::Medium,
            artifacts: vec![entry.executable_name.clone()],
        });
        evidence_id
    }

    pub fn collect_registry(&mut self, entry: RegistryEntry) -> Uuid {
        let serialized = serde_json::to_vec(&entry).unwrap_or_default();
        let evidence_id =
            self.add_evidence("", "Registry", EvidenceType::RegistryHive, &serialized);
        self.timeline.push(TimelineEntry {
            timestamp: entry.last_modified,
            source: "Registry".to_string(),
            event_type: "registry_change".to_string(),
            description: format!(
                "Registry: {}\\{} = {}",
                entry.key_path, entry.value_name, entry.value_data
            ),
            severity: EventSeverity::Low,
            artifacts: vec![entry.key_path.clone()],
        });
        evidence_id
    }

    pub fn add_timeline_entry(&mut self, entry: TimelineEntry) {
        self.timeline.push(entry);
    }

    pub fn build_timeline(&self, case_id: &str) -> Vec<&TimelineEntry> {
        let mut indexed: Vec<(usize, &TimelineEntry)> = self
            .timeline
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                self.evidence_store
                    .iter()
                    .any(|ev| ev.case_id == case_id && ev.source == e.source)
                    || self.cases.contains_key(case_id)
            })
            .collect();
        indexed.sort_by(|a, b| a.1.timestamp.cmp(&b.1.timestamp));
        indexed.into_iter().map(|(_, e)| e).collect()
    }

    pub fn search_timeline(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        query: &str,
    ) -> Vec<&TimelineEntry> {
        let q = query.to_lowercase();
        let mut results: Vec<&TimelineEntry> = self
            .timeline
            .iter()
            .filter(|e| {
                e.timestamp >= start
                    && e.timestamp <= end
                    && (e.description.to_lowercase().contains(&q)
                        || e.event_type.to_lowercase().contains(&q))
            })
            .collect();
        results.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        results
    }

    pub fn get_evidence(&self, evidence_id: Uuid) -> Option<&EvidenceItem> {
        self.evidence_store.iter().find(|e| e.id == evidence_id)
    }

    pub fn verify_evidence_integrity(&self, evidence_id: Uuid) -> bool {
        if let Some(item) = self.get_evidence(evidence_id) {
            let recomputed = compute_sha256(&item.raw_data);
            recomputed == item.hash_sha256
        } else {
            false
        }
    }

    pub fn get_case(&self, case_id: &str) -> Option<&ForensicCase> {
        self.cases.get(case_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn test_new_engine() {
        let engine = ForensicEngine::new();
        assert!(engine.cases.is_empty());
        assert!(engine.evidence_store.is_empty());
        assert!(engine.timeline.is_empty());
    }

    #[test]
    fn test_create_case() {
        let mut engine = ForensicEngine::new();
        let id = engine.create_case("Test Case", "Description", "analyst1");
        assert!(!id.is_empty());
        assert_eq!(engine.cases.len(), 1);
        let case = engine.get_case(&id).unwrap();
        assert_eq!(case.name, "Test Case");
        assert_eq!(case.status, CaseStatus::Open);
        assert_eq!(case.analyst, "analyst1");
    }

    #[test]
    fn test_close_case() {
        let mut engine = ForensicEngine::new();
        let id = engine.create_case("Case", "Desc", "analyst");
        assert!(engine.close_case(&id));
        assert_eq!(engine.get_case(&id).unwrap().status, CaseStatus::Closed);
    }

    #[test]
    fn test_close_nonexistent_case() {
        let mut engine = ForensicEngine::new();
        assert!(!engine.close_case("nonexistent"));
    }

    #[test]
    fn test_add_evidence() {
        let mut engine = ForensicEngine::new();
        let case_id = engine.create_case("Case", "Desc", "analyst");
        let data = b"forensic evidence payload";
        let evidence_id =
            engine.add_evidence(&case_id, "disk.raw", EvidenceType::DiskImage, data);
        assert_eq!(engine.evidence_store.len(), 1);
        assert_eq!(engine.get_case(&case_id).unwrap().evidence_count, 1);
        let item = engine.get_evidence(evidence_id).unwrap();
        assert_eq!(item.evidence_type, EvidenceType::DiskImage);
        assert_eq!(item.hash_sha256.len(), 64);
        assert_eq!(item.chain_of_custody.len(), 1);
    }

    #[test]
    fn test_collect_mft_entry() {
        let mut engine = ForensicEngine::new();
        let entry = MftEntry {
            file_name: "evil.exe".to_string(),
            parent_dir: "C:\\Users\\victim".to_string(),
            created: ts(2025, 1, 15, 10, 30),
            modified: ts(2025, 1, 15, 11, 0),
            mft_modified: ts(2025, 1, 15, 11, 0),
            accessed: ts(2025, 1, 15, 11, 5),
            file_size: 102400,
            attributes: 0x20,
            is_directory: false,
        };
        let id = engine.collect_mft_entry(entry);
        assert!(engine.get_evidence(id).is_some());
        assert_eq!(engine.timeline.len(), 1);
        assert_eq!(engine.timeline[0].event_type, "file_record");
    }

    #[test]
    fn test_collect_prefetch() {
        let mut engine = ForensicEngine::new();
        let entry = PrefetchEntry {
            executable_name: "CMD.EXE".to_string(),
            run_count: 42,
            last_run: ts(2025, 3, 10, 14, 0),
            file_refs: vec!["file1.dll".to_string()],
            volume_refs: vec!["C:\\WINDOWS".to_string()],
        };
        let id = engine.collect_prefetch(entry);
        assert!(engine.get_evidence(id).is_some());
        assert_eq!(engine.timeline.len(), 1);
        assert!(engine.timeline[0].description.contains("42"));
    }

    #[test]
    fn test_build_timeline_sorted() {
        let mut engine = ForensicEngine::new();
        let case_id = engine.create_case("Case", "Desc", "analyst");

        engine.add_timeline_entry(TimelineEntry {
            timestamp: ts(2025, 1, 15, 12, 0),
            source: "A".to_string(),
            event_type: "type_a".to_string(),
            description: "later event".to_string(),
            severity: EventSeverity::Low,
            artifacts: vec![],
        });
        engine.add_timeline_entry(TimelineEntry {
            timestamp: ts(2025, 1, 15, 10, 0),
            source: "B".to_string(),
            event_type: "type_b".to_string(),
            description: "earlier event".to_string(),
            severity: EventSeverity::High,
            artifacts: vec![],
        });

        let sorted = engine.build_timeline(&case_id);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].description, "earlier event");
        assert_eq!(sorted[1].description, "later event");
    }

    #[test]
    fn test_search_timeline() {
        let mut engine = ForensicEngine::new();
        engine.add_timeline_entry(TimelineEntry {
            timestamp: ts(2025, 6, 1, 8, 0),
            source: "S".to_string(),
            event_type: "login".to_string(),
            description: "User login success".to_string(),
            severity: EventSeverity::Informational,
            artifacts: vec![],
        });
        engine.add_timeline_entry(TimelineEntry {
            timestamp: ts(2025, 6, 1, 9, 0),
            source: "S".to_string(),
            event_type: "process".to_string(),
            description: "Process spawned cmd.exe".to_string(),
            severity: EventSeverity::Medium,
            artifacts: vec![],
        });
        engine.add_timeline_entry(TimelineEntry {
            timestamp: ts(2025, 6, 2, 8, 0),
            source: "S".to_string(),
            event_type: "login".to_string(),
            description: "User login failure".to_string(),
            severity: EventSeverity::High,
            artifacts: vec![],
        });

        let results =
            engine.search_timeline(ts(2025, 6, 1, 0, 0), ts(2025, 6, 1, 23, 59), "login");
        assert_eq!(results.len(), 1);
        assert!(results[0].description.contains("success"));

        let all_day = engine.search_timeline(ts(2025, 6, 1, 0, 0), ts(2025, 6, 1, 23, 59), "");
        assert_eq!(all_day.len(), 2);
    }

    #[test]
    fn test_verify_evidence_integrity() {
        let mut engine = ForensicEngine::new();
        let case_id = engine.create_case("Case", "Desc", "analyst");
        let data = b"original evidence data";
        let id = engine.add_evidence(&case_id, "source", EvidenceType::LogFile, data);
        assert!(engine.verify_evidence_integrity(id));
    }

    #[test]
    fn test_verify_evidence_nonexistent() {
        let engine = ForensicEngine::new();
        assert!(!engine.verify_evidence_integrity(Uuid::new_v4()));
    }

    #[test]
    fn test_collect_registry() {
        let mut engine = ForensicEngine::new();
        let entry = RegistryEntry {
            hive: "NTUSER.DAT".to_string(),
            key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            value_name: "Malware".to_string(),
            value_data: "C:\\Users\\victim\\evil.exe".to_string(),
            value_type: "REG_SZ".to_string(),
            last_modified: ts(2025, 4, 1, 9, 0),
        };
        let id = engine.collect_registry(entry);
        assert!(engine.get_evidence(id).is_some());
        assert_eq!(engine.timeline.len(), 1);
        assert_eq!(engine.timeline[0].event_type, "registry_change");
    }

    #[test]
    fn test_get_case_none() {
        let engine = ForensicEngine::new();
        assert!(engine.get_case("nope").is_none());
    }
}
