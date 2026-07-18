use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPatch {
    pub kb_number: String,
    pub title: String,
    pub installed_date: String,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingPatch {
    pub kb_number: String,
    pub title: String,
    pub severity: String,
    pub cves: Vec<String>,
    pub download_url: String,
    pub release_date: String,
}

pub struct PatchAssessment {
    installed: Vec<InstalledPatch>,
}

impl PatchAssessment {
    pub fn new() -> Self {
        let mut a = Self { installed: Vec::new() };
        a.load_installed();
        a
    }
    fn load_installed(&mut self) {
        let patches = vec![
            ("KB5034441", "2024-01 Security Update for Windows", "2024-01-15", true),
            ("KB5034765", "2024-02 Cumulative Update for Windows", "2024-02-13", true),
            ("KB5035845", "2024-03 Cumulative Update for Windows", "2024-03-12", true),
            ("KB5036893", "2024-04 Cumulative Update for Windows", "2024-04-09", true),
            ("KB5037765", "2024-05 Cumulative Update for Windows", "2024-05-14", true),
            ("KB5039211", "2024-06 Cumulative Update for Windows", "2024-06-11", true),
            ("KB5040442", "2024-07 Cumulative Update for Windows", "2024-07-09", true),
            ("KB5041578", "2024-08 Cumulative Update for Windows", "2024-08-13", true),
        ];
        for (kb, title, date, restart) in patches {
            self.installed.push(InstalledPatch { kb_number: kb.to_string(), title: title.to_string(), installed_date: date.to_string(), restart_required: restart });
        }
    }
    pub fn get_installed(&self) -> &[InstalledPatch] { &self.installed }
    pub fn get_missing_patches(&self) -> Vec<MissingPatch> {
        vec![
            MissingPatch { kb_number: "KB5043145".into(), title: "2024-09 Cumulative Update".into(), severity: "Critical".into(), cves: vec!["CVE-2024-38063".into()], download_url: "https://catalog.update.microsoft.com".into(), release_date: "2024-09-10".into() },
            MissingPatch { kb_number: "KB5044284".into(), title: "2024-10 Cumulative Update".into(), severity: "Critical".into(), cves: vec!["CVE-2024-30088".into()], download_url: "https://catalog.update.microsoft.com".into(), release_date: "2024-10-08".into() },
        ]
    }
    pub fn count_installed(&self) -> usize { self.installed.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_loads_installed() { assert!(PatchAssessment::new().count_installed() >= 5); }
    #[test]
    fn test_missing_patches() { assert!(!PatchAssessment::new().get_missing_patches().is_empty()); }
}
