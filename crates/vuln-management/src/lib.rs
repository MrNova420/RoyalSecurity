pub mod cve;
pub mod cvss;
pub mod patch;
pub mod report;
pub mod scanner;
mod tests;

pub use cve::{CveDatabase, CveEntry};
pub use cvss::{CvssScore, SeverityRating};
pub use patch::{InstalledPatch, MissingPatch, PatchAssessment};
pub use report::{Finding, VulnReport};
pub use scanner::{VulnScanner, ScanTarget, ScanResult};

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub target: ScanTarget,
    pub results: Vec<ScanResult>,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScanSession {
    pub fn new(target: ScanTarget) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: None,
            target,
            results: Vec::new(),
            status: ScanStatus::Pending,
        }
    }

    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
        self.status = ScanStatus::Completed;
    }
}
