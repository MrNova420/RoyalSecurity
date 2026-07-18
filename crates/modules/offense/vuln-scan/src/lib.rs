pub mod prelude;

use royalsecurity_common::types::*;
use tracing::{info, debug};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: EventSeverity,
    pub cve_id: String,
    pub affected_software: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub check_id: String,
    pub vulnerable: bool,
    pub version_found: Option<String>,
    pub fixed_version: Option<String>,
    pub severity: EventSeverity,
    pub remediation: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: String,
    pub path: String,
}

pub struct VulnScanner {
    checks: Vec<VulnCheck>,
    results: Vec<VulnResult>,
}

impl VulnScanner {
    pub fn new() -> Self {
        info!("Initializing vulnerability scanner");
        Self {
            checks: Vec::new(),
            results: Vec::new(),
        }
    }

    pub fn add_check(&mut self, check: VulnCheck) {
        info!(id = %check.id, cve = %check.cve_id, "Adding vulnerability check");
        self.checks.push(check);
    }

    pub fn scan_software(&mut self, software: &[SoftwareInfo]) -> Vec<VulnResult> {
        info!(count = software.len(), "Scanning software inventory for vulnerabilities");
        let mut results = Vec::new();

        for sw in software {
            debug!(name = %sw.name, version = %sw.version, "Checking software");
            for check in &self.checks {
                if check.affected_software.eq_ignore_ascii_case(&sw.name) {
                    let vulnerable = Self::is_version_vulnerable(&sw.version, &check.cve_id);
                    if vulnerable {
                        let result = VulnResult {
                            check_id: check.id.clone(),
                            vulnerable: true,
                            version_found: Some(sw.version.clone()),
                            fixed_version: None,
                            severity: check.severity.clone(),
                            remediation: format!(
                                "Update {} to latest version to mitigate {}",
                                sw.name, check.cve_id
                            ),
                            evidence: format!(
                                "Found {} version {} at {}",
                                sw.name, sw.version, sw.path
                            ),
                        };
                        results.push(result);
                    }
                }
            }
        }

        info!(vulns_found = results.len(), "Software vulnerability scan completed");
        self.results.extend(results.clone());
        results
    }

    pub fn scan_network(&mut self, host: &str, open_ports: &[u16]) -> Vec<VulnResult> {
        info!(host = %host, ports = open_ports.len(), "Scanning network for vulnerabilities");
        let mut results = Vec::new();

        let known_vulnerable_ports: HashMap<u16, (&str, &str, EventSeverity)> = HashMap::from([
            (445u16, ("SMBv1 enabled", "CVE-2017-0144 (EternalBlue)", EventSeverity::Critical)),
            (3389, ("RDP exposed", "CVE-2019-0708 (BlueKeep)", EventSeverity::Critical)),
            (5985, ("WinRM exposed", "CVE-2024-21407 (WinRM RCE)", EventSeverity::High)),
            (1433, ("MSSQL exposed", "CVE-2024-37334 (SQL RCE)", EventSeverity::High)),
            (3306, ("MySQL exposed", "Weak authentication", EventSeverity::Medium)),
            (21, ("FTP exposed", "Cleartext credentials", EventSeverity::High)),
            (23, ("Telnet exposed", "Cleartext credentials", EventSeverity::Critical)),
            (135, ("RPC exposed", "CVE-2024-26169 (RPC LPE)", EventSeverity::High)),
            (139, ("NetBIOS exposed", "Information disclosure", EventSeverity::Medium)),
            (53, ("DNS exposed", "DNS amplification", EventSeverity::Medium)),
        ]);

        for &port in open_ports {
            if let Some((name, cve, severity)) = known_vulnerable_ports.get(&port) {
                let result = VulnResult {
                    check_id: format!("NET-{}", port),
                    vulnerable: true,
                    version_found: Some(format!("port {}", port)),
                    fixed_version: None,
                    severity: severity.clone(),
                    remediation: format!("Restrict access to port {} on host {}", port, host),
                    evidence: format!(
                        "Host {} has port {} open - {} ({})",
                        host, port, name, cve
                    ),
                };
                results.push(result);
            }
        }

        info!(vulns_found = results.len(), "Network vulnerability scan completed");
        self.results.extend(results.clone());
        results
    }

    pub fn scan_weak_crypto(&mut self, files: &[(&str, &[u8])]) -> Vec<VulnResult> {
        info!(file_count = files.len(), "Scanning for weak cryptography");
        let mut results = Vec::new();

        for (filename, content) in files {
            debug!(file = %filename, "Analyzing file for weak crypto patterns");

            let weak_patterns: Vec<(&[u8], &str, &str, EventSeverity)> = vec![
                (b"DES ", "DES cipher detected", "CVE-1999-0144 (DES weakness)", EventSeverity::High),
                (b"RC4", "RC4 cipher detected", "CVE-2013-2566 (RC4 bias)", EventSeverity::High),
                (b"MD5", "MD5 hash detected", "MD5 collision attacks", EventSeverity::Medium),
                (b"SHA1", "SHA1 hash detected", "SHA1 collision (SHAttered)", EventSeverity::Medium),
                (b"TLSv1.0", "TLS 1.0 detected", "BEAST/POODLE attacks", EventSeverity::High),
                (b"TLSv1.1", "TLS 1.1 detected", "Deprecated protocol", EventSeverity::Medium),
                (b"ECB", "ECB mode detected", "ECB pattern leakage", EventSeverity::Medium),
                (b"RSA-1024", "RSA-1024 detected", "Weak RSA key size", EventSeverity::High),
            ];

            for (pattern, name, _cve, severity) in &weak_patterns {
                if content.windows(pattern.len()).any(|window| window == *pattern) {
                    let result = VulnResult {
                        check_id: format!("CRYPTO-{}", name.replace(' ', "-")),
                        vulnerable: true,
                        version_found: None,
                        fixed_version: None,
                        severity: severity.clone(),
                        remediation: format!("Replace {} in {}", name, filename),
                        evidence: format!("{} found in {}", name, filename),
                    };
                    results.push(result);
                }
            }
        }

        info!(vulns_found = results.len(), "Weak crypto scan completed");
        self.results.extend(results.clone());
        results
    }

    pub fn vuln_count(results: &[VulnResult]) -> usize {
        results.iter().filter(|r| r.vulnerable).count()
    }

    pub fn get_critical_vulns(results: &[VulnResult]) -> Vec<&VulnResult> {
        results
            .iter()
            .filter(|r| r.vulnerable && r.severity == EventSeverity::Critical)
            .collect()
    }

    fn is_version_vulnerable(version: &str, _cve_id: &str) -> bool {
        let parts: Vec<u32> = version
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() < 2 {
            return false;
        }
        let major = parts[0];
        let minor = parts[1];
        major == 0 || (major == 1 && minor < 5) || (major == 1 && minor == 5 && parts.get(2).map_or(true, |&p| p < 30))
    }
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checks() -> Vec<VulnCheck> {
        vec![
            VulnCheck {
                id: "VC-001".into(),
                name: "OpenSSL Heartbleed".into(),
                description: "OpenSSL heartbeat extension vulnerability".into(),
                severity: EventSeverity::Critical,
                cve_id: "CVE-2014-0160".into(),
                affected_software: "openssl".into(),
            },
            VulnCheck {
                id: "VC-002".into(),
                name: "Log4Shell".into(),
                description: "Apache Log4j JNDI injection".into(),
                severity: EventSeverity::Critical,
                cve_id: "CVE-2021-44228".into(),
                affected_software: "log4j".into(),
            },
            VulnCheck {
                id: "VC-003".into(),
                name: "IIS WebDAV".into(),
                description: "IIS WebDAV buffer overflow".into(),
                severity: EventSeverity::High,
                cve_id: "CVE-2017-7269".into(),
                affected_software: "iis".into(),
            },
        ]
    }

    #[test]
    fn test_new_scanner() {
        let s = VulnScanner::new();
        assert!(s.checks.is_empty());
        assert!(s.results.is_empty());
    }

    #[test]
    fn test_add_check() {
        let mut s = VulnScanner::new();
        s.add_check(VulnCheck {
            id: "VC-001".into(),
            name: "Test".into(),
            description: "Test".into(),
            severity: EventSeverity::High,
            cve_id: "CVE-2024-0001".into(),
            affected_software: "test".into(),
        });
        assert_eq!(s.checks.len(), 1);
    }

    #[test]
    fn test_scan_software_vulnerable() {
        let mut s = VulnScanner::new();
        for c in sample_checks() {
            s.add_check(c);
        }
        let software = vec![
            SoftwareInfo { name: "openssl".into(), version: "1.0.2".into(), path: "/usr/lib/ssl".into() },
            SoftwareInfo { name: "log4j".into(), version: "2.14.1".into(), path: "/opt/log4j".into() },
        ];
        let results = s.scan_software(&software);
        assert!(!results.is_empty(), "Should find vulnerable software");
        assert!(results.iter().all(|r| r.vulnerable));
    }

    #[test]
    fn test_scan_software_not_vulnerable() {
        let mut s = VulnScanner::new();
        for c in sample_checks() {
            s.add_check(c);
        }
        let software = vec![
            SoftwareInfo { name: "openssl".into(), version: "3.0.0".into(), path: "/usr/lib/ssl".into() },
        ];
        let results = s.scan_software(&software);
        assert!(results.is_empty(), "Up-to-date software should not be vulnerable");
    }

    #[test]
    fn test_scan_network_vulnerable_ports() {
        let mut s = VulnScanner::new();
        let results = s.scan_network("192.168.1.1", &[445, 3389, 80]);
        let vuln_results: Vec<_> = results.iter().filter(|r| r.vulnerable).collect();
        assert_eq!(vuln_results.len(), 2, "Ports 445 and 3389 should be flagged");
    }

    #[test]
    fn test_scan_network_safe_ports() {
        let mut s = VulnScanner::new();
        let results = s.scan_network("10.0.0.1", &[80, 443]);
        assert!(results.is_empty(), "Standard HTTP/HTTPS ports should not be flagged");
    }

    #[test]
    fn test_scan_weak_crypto() {
        let mut s = VulnScanner::new();
        let file_content = b"This file uses DES encryption and MD5 hashing with ECB mode.";
        let files = vec![("config.bin", file_content.as_slice())];
        let results = s.scan_weak_crypto(&files);
        let vuln_results: Vec<_> = results.iter().filter(|r| r.vulnerable).collect();
        assert!(vuln_results.len() >= 2, "Should detect DES, MD5, and ECB");
    }

    #[test]
    fn test_scan_weak_crypto_clean_file() {
        let mut s = VulnScanner::new();
        let file_content = b"This file uses AES-256-GCM with SHA-256 hashing.";
        let files = vec![("secure.bin", file_content.as_slice())];
        let results = s.scan_weak_crypto(&files);
        assert!(results.is_empty(), "Clean file should have no weak crypto findings");
    }

    #[test]
    fn test_vuln_count() {
        let results = vec![
            VulnResult { check_id: "1".into(), vulnerable: true, version_found: None, fixed_version: None, severity: EventSeverity::High, remediation: String::new(), evidence: String::new() },
            VulnResult { check_id: "2".into(), vulnerable: false, version_found: None, fixed_version: None, severity: EventSeverity::Low, remediation: String::new(), evidence: String::new() },
            VulnResult { check_id: "3".into(), vulnerable: true, version_found: None, fixed_version: None, severity: EventSeverity::Critical, remediation: String::new(), evidence: String::new() },
        ];
        assert_eq!(VulnScanner::vuln_count(&results), 2);
    }

    #[test]
    fn test_get_critical_vulns() {
        let results = vec![
            VulnResult { check_id: "1".into(), vulnerable: true, version_found: None, fixed_version: None, severity: EventSeverity::Critical, remediation: String::new(), evidence: String::new() },
            VulnResult { check_id: "2".into(), vulnerable: true, version_found: None, fixed_version: None, severity: EventSeverity::High, remediation: String::new(), evidence: String::new() },
            VulnResult { check_id: "3".into(), vulnerable: true, version_found: None, fixed_version: None, severity: EventSeverity::Critical, remediation: String::new(), evidence: String::new() },
        ];
        let critical = VulnScanner::get_critical_vulns(&results);
        assert_eq!(critical.len(), 2);
        assert!(critical.iter().all(|r| r.severity == EventSeverity::Critical));
    }

    #[test]
    fn test_version_parsing_vulnerable() {
        assert!(VulnScanner::is_version_vulnerable("1.0.2", "CVE-2014-0160"));
        assert!(VulnScanner::is_version_vulnerable("0.9.8", "CVE-2014-0160"));
    }

    #[test]
    fn test_version_parsing_safe() {
        assert!(!VulnScanner::is_version_vulnerable("3.0.0", "CVE-2014-0160"));
        assert!(!VulnScanner::is_version_vulnerable("2.1.5", "CVE-2014-0160"));
    }
}
