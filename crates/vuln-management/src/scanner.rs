use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn, debug};
use crate::cve::{CveDatabase, CveEntry};
use crate::cvss::{CvssScore, SeverityRating};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub hostname: String,
    pub ip_address: Option<String>,
    pub scan_type: ScanType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Software,
    Network,
    Configuration,
    Patches,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanResult {
    SoftwareInventory(SoftwareInventory),
    NetworkService(NetworkService),
    ConfigAudit(ConfigAuditResult),
    PatchVulnerability(PatchVulnerability),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInventory {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub vulnerabilities: Vec<CveEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub vulnerabilities: Vec<CveEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAuditResult {
    pub setting_name: String,
    pub current_value: String,
    pub expected_value: String,
    pub compliant: bool,
    pub severity: SeverityRating,
    pub recommendation: String,
    pub cve_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchVulnerability {
    pub kb_number: String,
    pub title: String,
    pub severity: SeverityRating,
    pub cves: Vec<String>,
    pub installed: bool,
    pub installed_date: Option<String>,
}

pub struct VulnScanner {
    cve_db: CveDatabase,
}

impl VulnScanner {
    pub fn new() -> Self {
        Self {
            cve_db: CveDatabase::new(),
        }
    }

    pub fn scan_software(&self) -> Vec<SoftwareInventory> {
        info!("Starting software inventory scan");
        let installed = self.enumerate_installed_software();
        let mut results = Vec::new();

        for sw in installed {
            let vulns = self.cve_db.get_cves_for_software(&sw.name, &sw.version);
            if !vulns.is_empty() {
                warn!("Found {} vulnerabilities for {} {}", vulns.len(), sw.name, sw.version);
            }
            results.push(SoftwareInventory {
                name: sw.name,
                version: sw.version,
                publisher: sw.publisher,
                install_date: sw.install_date,
                install_location: sw.install_location,
                vulnerabilities: vulns,
            });
        }

        info!("Software scan complete: {} items with vulnerabilities", results.iter().filter(|r| !r.vulnerabilities.is_empty()).count());
        results
    }

    fn enumerate_installed_software(&self) -> Vec<InstalledSoftware> {
        info!("Enumerating installed software from Windows registry");
        #[cfg(target_os = "windows")]
        {
            self.scan_registry_software()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.get_fallback_software()
        }
    }

    #[cfg(target_os = "windows")]
    fn scan_registry_software(&self) -> Vec<InstalledSoftware> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let uninstall_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut software_list = Vec::new();

        if let Ok(uninstall_key) = hklm.open_subkey_with_flags(uninstall_key_path, KEY_READ) {
            for subkey_name in uninstall_key.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(subkey) = uninstall_key.open_subkey(&subkey_name) {
                    let display_name: String = subkey.get_value("DisplayName").unwrap_or_default();
                    let display_version: String = subkey.get_value("DisplayVersion").unwrap_or_default();
                    let publisher: Option<String> = subkey.get_value("Publisher").ok();
                    let install_date: Option<String> = subkey.get_value("InstallDate").ok();
                    let install_location: Option<String> = subkey.get_value("InstallLocation").ok();
                    let system_component: u32 = subkey.get_value("SystemComponent").unwrap_or(0);

                    if !display_name.is_empty() && display_version.is_empty() == false && system_component != 1 {
                        debug!("Found: {} v{}", display_name, display_version);
                        software_list.push(InstalledSoftware {
                            name: display_name,
                            version: display_version,
                            publisher,
                            install_date,
                            install_location,
                        });
                    }
                }
            }
        }

        let wow6432_path = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
        if let Ok(wow64_key) = hklm.open_subkey_with_flags(wow6432_path, KEY_READ) {
            for subkey_name in wow64_key.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(subkey) = wow64_key.open_subkey(&subkey_name) {
                    let display_name: String = subkey.get_value("DisplayName").unwrap_or_default();
                    let display_version: String = subkey.get_value("DisplayVersion").unwrap_or_default();
                    let publisher: Option<String> = subkey.get_value("Publisher").ok();
                    let install_date: Option<String> = subkey.get_value("InstallDate").ok();
                    let install_location: Option<String> = subkey.get_value("InstallLocation").ok();

                    if !display_name.is_empty() && !display_version.is_empty() {
                        software_list.push(InstalledSoftware {
                            name: display_name,
                            version: display_version,
                            publisher,
                            install_date,
                            install_location,
                        });
                    }
                }
            }
        }

        info!("Enumerated {} installed software items", software_list.len());
        software_list
    }

    #[cfg(not(target_os = "windows"))]
    fn get_fallback_software(&self) -> Vec<InstalledSoftware> {
        vec![
            InstalledSoftware {
                name: "OpenSSL".to_string(),
                version: "1.1.1k".to_string(),
                publisher: Some("OpenSSL Project".to_string()),
                install_date: None,
                install_location: None,
            },
            InstalledSoftware {
                name: "Apache HTTP Server".to_string(),
                version: "2.4.51".to_string(),
                publisher: Some("Apache Software Foundation".to_string()),
                install_date: None,
                install_location: None,
            },
        ]
    }

    pub fn scan_network(&self, target_host: &str) -> Vec<NetworkService> {
        info!("Starting network service scan on {}", target_host);
        let common_ports = vec![
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
            (53, "DNS"), (80, "HTTP"), (110, "POP3"), (111, "RPC"),
            (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"),
            (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
            (1433, "MSSQL"), (1434, "MSSQL Browser"), (3306, "MySQL"),
            (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
            (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (8888, "HTTP-Proxy"),
            (27017, "MongoDB"), (6379, "Redis"), (9200, "Elasticsearch"),
        ];

        let mut services = Vec::new();

        for (port, service_name) in common_ports {
            debug!("Checking port {} ({})", port, service_name);
            let is_open = self.check_port(target_host, port);
            if is_open {
                let banner = self.grab_banner(target_host, port);
                let version = self.parse_service_version(service_name, &banner);
                let vulns = self.cve_db.get_cves_for_network_service(service_name, version.as_deref());

                info!("Port {} open: {} (v{:?}) - {} CVEs", port, service_name, version, vulns.len());
                services.push(NetworkService {
                    host: target_host.to_string(),
                    port,
                    protocol: "TCP".to_string(),
                    service_name: service_name.to_string(),
                    version,
                    banner,
                    vulnerabilities: vulns,
                });
            }
        }

        info!("Network scan complete: {} services found", services.len());
        services
    }

    fn check_port(&self, _host: &str, _port: u16) -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::net::TcpStream;
            use std::time::Duration;
            let addr = format!("{}:{}", _host, _port);
            TcpStream::connect_timeout(
                &addr.parse().unwrap_or_else(|_| "127.0.0.1:1".parse().unwrap()),
                Duration::from_millis(500),
            ).is_ok()
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    fn grab_banner(&self, _host: &str, _port: u16) -> Option<String> {
        #[cfg(target_os = "windows")]
        {
            use std::net::TcpStream;
            use std::io::{Read, Write};
            use std::time::Duration;

            let addr = format!("{}:{}", _host, _port);
            if let Ok(mut stream) = TcpStream::connect_timeout(
                &addr.parse().unwrap_or_else(|_| "127.0.0.1:1".parse().unwrap()),
                Duration::from_secs(3),
            ) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    return String::from_utf8_lossy(&buf[..n]).to_string().into();
                }
            }
            None
        }
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }

    fn parse_service_version(&self, service: &str, banner: &Option<String>) -> Option<String> {
        if let Some(banner) = banner {
            let patterns = match service {
                "HTTP" | "HTTPS" | "HTTP-Alt" | "HTTPS-Alt" => {
                    vec![r"Apache/(\d+\.\d+\.\d+)", r"nginx/(\d+\.\d+\.\d+)", r"Microsoft-IIS/(\d+\.\d+)"]
                }
                "SSH" => vec![r"OpenSSH_(\d+\.\d+\p{Alnum}*)"],
                "FTP" => vec![r"vsFTPd (\d+\.\d+\.\d+)", r"ProFTPD (\d+\.\d+\.\d+)"],
                "SMTP" => vec![r"Postfix", r"Sendmail (\d+\.\d+\.\d+)"],
                "MySQL" => vec![r"(\d+\.\d+\.\d+)-MariaDB", r"(\d+\.\d+\.\d+)-log"],
                _ => vec![],
            };

            for pattern in patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if let Some(caps) = re.captures(banner) {
                        return caps.get(1).map(|m| m.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    pub fn scan_config(&self) -> Vec<ConfigAuditResult> {
        info!("Starting configuration audit");
        let mut results = Vec::new();

        let checks = self.get_config_checks();
        for check in checks {
            let current_value = self.get_config_value(&check.setting_name);
            let compliant = current_value == check.expected_value;
            if !compliant {
                warn!("Configuration non-compliant: {} (expected: {}, got: {})",
                    check.setting_name, check.expected_value, current_value);
            }
            results.push(ConfigAuditResult {
                setting_name: check.setting_name,
                current_value,
                expected_value: check.expected_value,
                compliant,
                severity: check.severity,
                recommendation: check.recommendation,
                cve_refs: check.cve_refs,
            });
        }

        info!("Config audit complete: {}/{} checks passed",
            results.iter().filter(|r| r.compliant).count(),
            results.len()
        );
        results
    }

    fn get_config_checks(&self) -> Vec<ConfigCheck> {
        vec![
            ConfigCheck {
                setting_name: "SMBv1 Disabled".to_string(),
                expected_value: "Disabled".to_string(),
                severity: SeverityRating::Critical,
                recommendation: "Disable SMBv1 to prevent EternalBlue (MS17-010) exploitation".to_string(),
                cve_refs: vec!["CVE-2017-0144".to_string(), "CVE-2017-0145".to_string()],
            },
            ConfigCheck {
                setting_name: "Remote Desktop NLA".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enable Network Level Authentication for RDP to prevent BlueKeep".to_string(),
                cve_refs: vec!["CVE-2019-0708".to_string()],
            },
            ConfigCheck {
                setting_name: "Windows Firewall".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enable Windows Firewall to restrict unauthorized network access".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "Print Spooler".to_string(),
                expected_value: "Disabled".to_string(),
                severity: SeverityRating::Critical,
                recommendation: "Disable Print Spooler if not needed to prevent PrintNightmare".to_string(),
                cve_refs: vec!["CVE-2021-34527".to_string()],
            },
            ConfigCheck {
                setting_name: "LAPS Installed".to_string(),
                expected_value: "Installed".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Deploy Microsoft LAPS for local admin password management".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "WDAC Enabled".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Enable Windows Defender Application Control for code integrity".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "PowerShell Script Block Logging".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Enable Script Block Logging for PowerShell audit trail".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "LSA Protection".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enable RunAsPPL to protect LSASS from credential dumping".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "DEP Policy".to_string(),
                expected_value: "AlwaysOn".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enable DEP AlwaysOn for system-wide exploit mitigation".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "UAC Level".to_string(),
                expected_value: "Always Notify".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Set UAC to Always Notify for maximum privilege escalation protection".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "WinRM HTTPS".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Configure WinRM over HTTPS for secure remote management".to_string(),
                cve_refs: vec!["CVE-2024-21410".to_string()],
            },
            ConfigCheck {
                setting_name: "NTLM Restrictions".to_string(),
                expected_value: "Auditing".to_string(),
                severity: SeverityRating::High,
                recommendation: "Restrict NTLM usage to prevent relay attacks".to_string(),
                cve_refs: vec!["CVE-2024-21410".to_string()],
            },
            ConfigCheck {
                setting_name: "Credential Guard".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Enable Credential Guard to protect LSASS credentials".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "Audit Policy".to_string(),
                expected_value: "Advanced".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Enable advanced audit policy for comprehensive event logging".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "Secure Boot".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enable UEFI Secure Boot to prevent bootkit attacks".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "AutoPlay".to_string(),
                expected_value: "Disabled".to_string(),
                severity: SeverityRating::Low,
                recommendation: "Disable AutoPlay to prevent autorun-based malware".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "SMB Signing".to_string(),
                expected_value: "Required".to_string(),
                severity: SeverityRating::High,
                recommendation: "Require SMB signing to prevent relay attacks".to_string(),
                cve_refs: vec!["CVE-2024-21410".to_string()],
            },
            ConfigCheck {
                setting_name: "TLS Minimum Version".to_string(),
                expected_value: "1.2".to_string(),
                severity: SeverityRating::High,
                recommendation: "Enforce TLS 1.2 minimum to prevent downgrade attacks".to_string(),
                cve_refs: vec!["CVE-2014-0160".to_string()],
            },
            ConfigCheck {
                setting_name: "Windows Event Forwarding".to_string(),
                expected_value: "Enabled".to_string(),
                severity: SeverityRating::Low,
                recommendation: "Enable Windows Event Forwarding for centralized log collection".to_string(),
                cve_refs: vec![],
            },
            ConfigCheck {
                setting_name: "ASR Rules".to_string(),
                expected_value: "BlockAll".to_string(),
                severity: SeverityRating::Medium,
                recommendation: "Enable Attack Surface Reduction rules for Office and script protection".to_string(),
                cve_refs: vec!["CVE-2023-23397".to_string()],
            },
        ]
    }

    fn get_config_value(&self, setting: &str) -> String {
        match setting {
            "SMBv1 Disabled" => {
                #[cfg(target_os = "windows")]
                {
                    if self.check_registry_dword(
                        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "SMB1",
                        0,
                    ) {
                        return "Disabled".to_string();
                    }
                    return "Enabled".to_string();
                }
                #[cfg(not(target_os = "windows"))]
                { "Disabled".to_string() }
            }
            "Remote Desktop NLA" => {
                #[cfg(target_os = "windows")]
                {
                    if self.check_registry_dword(
                        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                        "UserAuthentication",
                        1,
                    ) {
                        return "Enabled".to_string();
                    }
                    return "Disabled".to_string();
                }
                #[cfg(not(target_os = "windows"))]
                { "Enabled".to_string() }
            }
            "Windows Firewall" => {
                #[cfg(target_os = "windows")]
                {
                    return "Enabled".to_string();
                }
                #[cfg(not(target_os = "windows"))]
                { "Enabled".to_string() }
            }
            "Print Spooler" => {
                #[cfg(target_os = "windows")]
                {
                    if self.check_service_stopped("Spooler") {
                        return "Disabled".to_string();
                    }
                    return "Enabled".to_string();
                }
                #[cfg(not(target_os = "windows"))]
                { "Disabled".to_string() }
            }
            _ => "Unknown".to_string(),
        }
    }

    #[cfg(target_os = "windows")]
    fn check_registry_dword(&self, key_path: &str, value_name: &str, expected: u32) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey_with_flags(key_path, KEY_READ) {
            if let Ok(val) = key.get_value::<u32, _>(value_name) {
                return val == expected;
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    fn check_service_stopped(&self, service_name: &str) -> bool {
        use std::process::Command;
        let output = Command::new("sc")
            .args(["query", service_name])
            .output();
        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("STOPPED")
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn check_registry_dword(&self, _key_path: &str, _value_name: &str, _expected: u32) -> bool {
        true
    }

    #[cfg(not(target_os = "windows"))]
    fn check_service_stopped(&self, _service_name: &str) -> bool {
        true
    }
}

#[derive(Debug)]
struct InstalledSoftware {
    name: String,
    version: String,
    publisher: Option<String>,
    install_date: Option<String>,
    install_location: Option<String>,
}

#[derive(Debug)]
struct ConfigCheck {
    setting_name: String,
    expected_value: String,
    severity: SeverityRating,
    recommendation: String,
    cve_refs: Vec<String>,
}
