use serde::{Deserialize, Serialize};
use crate::cve::CveEntry;
use crate::cvss::severity_from_score;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub affected_asset: String,
    pub remediation: String,
    pub cvss_score: f64,
    pub exploit_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub scan_id: String,
    pub scan_time: String,
    pub hostname: String,
    pub total_vulns: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub findings: Vec<Finding>,
    pub risk_score: f64,
    pub summary: String,
}

impl VulnReport {
    pub fn new(hostname: &str) -> Self {
        Self {
            scan_id: uuid::Uuid::new_v4().to_string(),
            scan_time: chrono::Utc::now().to_rfc3339(),
            hostname: hostname.to_string(),
            total_vulns: 0, critical: 0, high: 0, medium: 0, low: 0,
            findings: Vec::new(), risk_score: 0.0, summary: String::new(),
        }
    }
    pub fn add_finding(&mut self, finding: Finding) {
        match finding.severity.as_str() {
            "Critical" => self.critical += 1,
            "High" => self.high += 1,
            "Medium" => self.medium += 1,
            _ => self.low += 1,
        }
        self.findings.push(finding);
        self.total_vulns = self.findings.len();
        self.risk_score = (self.critical as f64 * 10.0 + self.high as f64 * 7.0 + self.medium as f64 * 4.0 + self.low as f64 * 1.0) / (self.total_vulns as f64).max(1.0);
        self.summary = format!("{} findings: {} critical, {} high, {} medium, {} low. Risk score: {:.1}",
            self.total_vulns, self.critical, self.high, self.medium, self.low, self.risk_score);
    }
    pub fn from_cves(hostname: &str, cves: &[&CveEntry]) -> Self {
        let mut report = Self::new(hostname);
        for cve in cves {
            report.add_finding(Finding {
                cve_id: cve.id.clone(), severity: cve.severity.clone(), description: cve.description.clone(),
                affected_asset: hostname.to_string(), remediation: format!("Apply patch for {}", cve.id),
                cvss_score: cve.cvss_score, exploit_available: cve.exploit_available,
            });
        }
        report
    }
    pub fn export_json(&self) -> String { serde_json::to_string_pretty(self).unwrap_or_default() }
    pub fn export_csv(&self) -> String {
        let mut csv = "CVE_ID,Severity,CVSS,Description,Remediation,Exploit_Available\n".to_string();
        for f in &self.findings {
            csv += &format!("{},{},{},{},{},{}\n", f.cve_id, f.severity, f.cvss_score, f.description, f.remediation, f.exploit_available);
        }
        csv
    }
    pub fn export_html(&self) -> String {
        format!("<html><head><title>Vulnerability Report - {}</title></head><body><h1>Vulnerability Report</h1><h2>Host: {}</h2><p>{}</p><table border='1'><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>{}</table></body></html>",
            self.hostname, self.hostname, self.summary,
            self.findings.iter().map(|f| format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", f.cve_id, f.severity, f.cvss_score, f.description)).collect::<Vec<_>>().join(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_empty_report() { let r = VulnReport::new("test"); assert_eq!(r.total_vulns, 0); }
    #[test]
    fn test_add_finding() {
        let mut r = VulnReport::new("test");
        r.add_finding(Finding { cve_id: "CVE-2024-0001".into(), severity: "Critical".into(), description: "test".into(), affected_asset: "test".into(), remediation: "patch".into(), cvss_score: 9.8, exploit_available: true });
        assert_eq!(r.critical, 1);
        assert_eq!(r.total_vulns, 1);
    }
    #[test]
    fn test_export_json() { let r = VulnReport::new("test"); assert!(r.export_json().contains("scan_id")); }
    #[test]
    fn test_export_csv() { let r = VulnReport::new("test"); assert!(r.export_csv().contains("CVE_ID")); }
    #[test]
    fn test_export_html() { let r = VulnReport::new("test"); assert!(r.export_html().contains("<html>")); }
}
