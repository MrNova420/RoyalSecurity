use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub published: String,
    pub affected_software: Vec<String>,
    pub exploit_available: bool,
    pub kev_listed: bool,
    pub references: Vec<String>,
}

pub struct CveDatabase {
    entries: Vec<CveEntry>,
}

impl CveDatabase {
    pub fn new() -> Self {
        let mut db = Self { entries: Vec::new() };
        db.load_builtin();
        db
    }
    fn load_builtin(&mut self) {
        let cves = vec![
            ("CVE-2017-0144", "EternalBlue SMB RCE", "Critical", 9.8, vec!["Microsoft Windows SMB".into()], true, true),
            ("CVE-2017-0145", "EternalRomance SMB RCE", "Critical", 9.8, vec!["Microsoft Windows SMB".into()], true, true),
            ("CVE-2019-0708", "BlueKeep RDP RCE", "Critical", 9.8, vec!["Microsoft Windows RDP".into()], true, true),
            ("CVE-2020-1472", "Zerologon Netlogon Elevation of Privilege", "Critical", 10.0, vec!["Windows Server".into()], true, true),
            ("CVE-2021-1675", "PrintNightmare Print Spooler RCE", "Critical", 8.8, vec!["Windows Print Spooler".into()], true, true),
            ("CVE-2021-34527", "PrintNightmare Print Spooler RCE", "Critical", 8.8, vec!["Windows Print Spooler".into()], true, true),
            ("CVE-2021-44228", "Log4Shell Apache Log4j RCE", "Critical", 10.0, vec!["Apache Log4j".into()], true, true),
            ("CVE-2022-30190", "Follina MSDT RCE", "Critical", 7.8, vec!["Microsoft MSDT".into()], true, true),
            ("CVE-2023-21746", "LocalPotato Windows NTLM EoP", "High", 7.8, vec!["Windows NTLM".into()], true, false),
            ("CVE-2023-23397", "Microsoft Outlook Elevation of Privilege", "Critical", 9.8, vec!["Microsoft Outlook".into()], true, true),
            ("CVE-2023-36884", "Microsoft Office RCE", "High", 8.3, vec!["Microsoft Office".into()], true, true),
            ("CVE-2024-21412", "Internet Shortcut Files Security Bypass", "High", 7.5, vec!["Microsoft Windows".into()], true, true),
            ("CVE-2024-30088", "Windows Kernel Elevation of Privilege", "High", 7.0, vec!["Microsoft Windows".into()], true, true),
            ("CVE-2024-38063", "Windows TCP/IP RCE", "Critical", 9.8, vec!["Microsoft Windows TCP/IP".into()], true, true),
            ("CVE-2023-46604", "Apache ActiveMQ RCE", "Critical", 10.0, vec!["Apache ActiveMQ".into()], true, true),
            ("CVE-2023-4966", "Citrix Bleed Information Disclosure", "Critical", 9.4, vec!["Citrix NetScaler".into()], true, true),
            ("CVE-2023-22515", "Atlassian Confluence Privilege Escalation", "Critical", 10.0, vec!["Atlassian Confluence".into()], true, true),
            ("CVE-2022-40684", "FortiOS Authentication Bypass", "Critical", 9.8, vec!["FortiOS".into()], true, true),
            ("CVE-2022-42475", "FortiOS Heap-based Buffer Overflow", "Critical", 9.8, vec!["FortiOS".into()], true, true),
            ("CVE-2023-27997", "FortiOS Out-of-Bound Write", "Critical", 9.8, vec!["FortiOS SSL VPN".into()], true, true),
            ("CVE-2021-34481", "Windows Print Spooler EoP", "Critical", 7.8, vec!["Windows Print Spooler".into()], true, true),
            ("CVE-2021-36934", "HiveNightmare SAM Privilege Escalation", "High", 7.8, vec!["Windows SAM".into()], true, true),
            ("CVE-2022-21999", "Windows Print Spooler EoP", "High", 7.8, vec!["Windows Print Spooler".into()], true, false),
            ("CVE-2023-21768", "Windows Ancillary Function Driver EoP", "High", 7.8, vec!["Windows AFD".into()], true, false),
            ("CVE-2024-20656", "Visual Studio Elevation of Privilege", "High", 7.8, vec!["Visual Studio".into()], false, false),
        ];
        for (id, desc, sev, cvss, affected, exploit, kev) in cves {
            self.entries.push(CveEntry {
                id: id.to_string(), description: desc.to_string(), severity: sev.to_string(),
                cvss_score: cvss, published: "2020-2024".to_string(), affected_software: affected,
                exploit_available: exploit, kev_listed: kev, references: vec![],
            });
        }
    }
    pub fn lookup_cve(&self, id: &str) -> Option<&CveEntry> { self.entries.iter().find(|e| e.id == id) }
    pub fn search_cves(&self, query: &str) -> Vec<&CveEntry> {
        let q = query.to_lowercase();
        self.entries.iter().filter(|e| e.id.to_lowercase().contains(&q) || e.description.to_lowercase().contains(&q)).collect()
    }
    pub fn get_critical_cves(&self) -> Vec<&CveEntry> { self.entries.iter().filter(|e| e.severity == "Critical").collect() }
    pub fn count(&self) -> usize { self.entries.len() }
    pub fn get_cves_for_software(&self, name: &str, _version: &str) -> Vec<CveEntry> {
        self.entries.iter().filter(|e| {
            e.affected_software.iter().any(|s| s.to_lowercase().contains(&name.to_lowercase()))
        }).cloned().collect()
    }
    pub fn get_cves_for_network_service(&self, service_name: &str, _version: Option<&str>) -> Vec<CveEntry> {
        self.entries.iter().filter(|e| {
            e.affected_software.iter().any(|s| s.to_lowercase().contains(&service_name.to_lowercase()))
        }).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_database_loads() { assert!(CveDatabase::new().count() >= 20); }
    #[test]
    fn test_lookup_cve() { let db = CveDatabase::new(); assert!(db.lookup_cve("CVE-2017-0144").is_some()); }
    #[test]
    fn test_search_cves() { let db = CveDatabase::new(); assert!(!db.search_cves("bluekeep").is_empty()); }
    #[test]
    fn test_critical_cves() { let db = CveDatabase::new(); assert!(db.get_critical_cves().len() >= 10); }
}
