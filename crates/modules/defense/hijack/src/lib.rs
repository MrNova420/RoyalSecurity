pub mod prelude;

use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HijackType {
    SearchOrder,
    SideLoading,
    KnownVulnerable,
    PhantomDll,
}

impl std::fmt::Display for HijackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HijackType::SearchOrder => write!(f, "Search Order Hijack"),
            HijackType::SideLoading => write!(f, "DLL Side-Loading"),
            HijackType::KnownVulnerable => write!(f, "Known Vulnerable DLL"),
            HijackType::PhantomDll => write!(f, "Phantom DLL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HijackInfo {
    pub process_name: String,
    pub dll_name: String,
    pub expected_path: String,
    pub actual_path: String,
    pub hijack_type: HijackType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HijackDetection {
    pub id: Uuid,
    pub info: HijackInfo,
    pub severity: EventSeverity,
    pub description: String,
}

pub struct HijackDetector {
    known_vulnerable: HashMap<String, String>,
    system_dll_paths: Vec<String>,
    detections: Vec<HijackDetection>,
    detection_count: u64,
}

impl HijackDetector {
    pub fn new() -> Self {
        info!("Initializing DLL hijack detector");
        let mut detector = Self {
            known_vulnerable: HashMap::new(),
            system_dll_paths: Vec::new(),
            detections: Vec::new(),
            detection_count: 0,
        };
        detector.load_defaults();
        detector
    }

    fn load_defaults(&mut self) {
        self.system_dll_paths = vec![
            "C:\\Windows\\System32".to_string(),
            "C:\\Windows\\SysWOW64".to_string(),
        ];

        self.known_vulnerable
            .insert("version.dll".to_string(), "10.0.19041".to_string());
        self.known_vulnerable
            .insert("dbghelp.dll".to_string(), "10.0.19041".to_string());
        self.known_vulnerable
            .insert("winhttp.dll".to_string(), "10.0.19041".to_string());
    }

    pub fn check_dll_load(
        &mut self,
        process: &str,
        dll: &str,
        loaded_from: &str,
    ) -> Option<HijackDetection> {
        let dll_lower = dll.to_lowercase();
        let loaded_lower = loaded_from.to_lowercase();

        if let Some(fixed_version) = self.known_vulnerable.get(&dll_lower) {
            if !loaded_lower.contains(&fixed_version.replace('.', ""))
                && !loaded_lower.contains("system32")
                && !loaded_lower.contains("syswow64")
            {
                let detection = HijackDetection {
                    id: Uuid::new_v4(),
                    info: HijackInfo {
                        process_name: process.to_string(),
                        dll_name: dll.to_string(),
                        expected_path: format!("C:\\Windows\\System32\\{}", dll),
                        actual_path: loaded_from.to_string(),
                        hijack_type: HijackType::KnownVulnerable,
                    },
                    severity: EventSeverity::High,
                    description: format!(
                        "Known vulnerable DLL {} loaded from non-system path by {}",
                        dll, process
                    ),
                };
                warn!(
                    process = process,
                    dll = dll,
                    path = loaded_from,
                    "Known vulnerable DLL loaded from non-standard path"
                );
                self.detection_count += 1;
                self.detections.push(detection.clone());
                return Some(detection);
            }
        }

        let is_system_path = self
            .system_dll_paths
            .iter()
            .any(|p| loaded_lower.contains(&p.to_lowercase()));

        let known_side_loads = ["dbghelp.dll", "version.dll", "winhttp.dll", "cryptsp.dll"];
        let in_app_dir = loaded_lower.contains("\\app\\")
            || loaded_lower.contains("\\program files")
            || loaded_lower.contains("\\temp\\")
            || loaded_lower.contains("\\downloads\\");

        if known_side_loads.contains(&dll_lower.as_str()) && in_app_dir && !is_system_path {
            let detection = HijackDetection {
                id: Uuid::new_v4(),
                info: HijackInfo {
                    process_name: process.to_string(),
                    dll_name: dll.to_string(),
                    expected_path: format!("C:\\Windows\\System32\\{}", dll),
                    actual_path: loaded_from.to_string(),
                    hijack_type: HijackType::SideLoading,
                },
                severity: EventSeverity::High,
                description: format!(
                    "Potential DLL side-loading: {} loaded from application directory by {}",
                    dll, process
                ),
            };
            warn!(
                process = process,
                dll = dll,
                path = loaded_from,
                "Potential DLL side-loading detected"
            );
            self.detection_count += 1;
            self.detections.push(detection.clone());
            return Some(detection);
        }

        if !is_system_path && loaded_lower.contains(&dll_lower) {
            let detection = HijackDetection {
                id: Uuid::new_v4(),
                info: HijackInfo {
                    process_name: process.to_string(),
                    dll_name: dll.to_string(),
                    expected_path: format!("C:\\Windows\\System32\\{}", dll),
                    actual_path: loaded_from.to_string(),
                    hijack_type: HijackType::SearchOrder,
                },
                severity: EventSeverity::Medium,
                description: format!(
                    "DLL {} loaded from non-system directory by {} - possible search order hijack",
                    dll, process
                ),
            };
            warn!(
                process = process,
                dll = dll,
                path = loaded_from,
                "DLL loaded from non-system path"
            );
            self.detection_count += 1;
            self.detections.push(detection.clone());
            return Some(detection);
        }

        None
    }

    pub fn add_known_vulnerable(&mut self, dll_name: &str, fixed_version: &str) {
        info!(
            dll = dll_name,
            version = fixed_version,
            "Adding known vulnerable DLL"
        );
        self.known_vulnerable
            .insert(dll_name.to_lowercase(), fixed_version.to_string());
    }

    pub fn get_vulnerable_dlls(&self) -> &HashMap<String, String> {
        &self.known_vulnerable
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn detections(&self) -> &[HijackDetection] {
        &self.detections
    }
}

impl Default for HijackDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hijack_detector_new() {
        let detector = HijackDetector::new();
        assert!(detector.detection_count() == 0);
        assert!(!detector.known_vulnerable.is_empty());
    }

    #[test]
    fn test_check_dll_load_system32_is_clean() {
        let mut detector = HijackDetector::new();
        let result = detector.check_dll_load(
            "app.exe",
            "kernel32.dll",
            "C:\\Windows\\System32\\kernel32.dll",
        );
        assert!(result.is_none());
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_check_dll_load_search_order_hijack() {
        let mut detector = HijackDetector::new();
        let result = detector.check_dll_load(
            "app.exe",
            "custom.dll",
            "C:\\Users\\user\\Downloads\\custom.dll",
        );
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.info.hijack_type, HijackType::SearchOrder);
        assert_eq!(detection.severity, EventSeverity::Medium);
    }

    #[test]
    fn test_check_dll_known_vulnerable() {
        let mut detector = HijackDetector::new();
        let result = detector.check_dll_load(
            "malware.exe",
            "version.dll",
            "C:\\Users\\user\\AppData\\version.dll",
        );
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.info.hijack_type, HijackType::KnownVulnerable);
        assert_eq!(detection.severity, EventSeverity::High);
    }

    #[test]
    fn test_add_known_vulnerable() {
        let mut detector = HijackDetector::new();
        assert!(!detector.known_vulnerable.contains_key("evil.dll"));
        detector.add_known_vulnerable("evil.dll", "1.0.0");
        assert!(detector.known_vulnerable.contains_key("evil.dll"));
        assert_eq!(
            detector.known_vulnerable.get("evil.dll").unwrap(),
            "1.0.0"
        );
    }

    #[test]
    fn test_get_vulnerable_dlls() {
        let detector = HijackDetector::new();
        let vulns = detector.get_vulnerable_dlls();
        assert!(vulns.contains_key("version.dll"));
        assert!(vulns.contains_key("dbghelp.dll"));
    }

    #[test]
    fn test_detection_count_increments() {
        let mut detector = HijackDetector::new();
        detector.check_dll_load("app.exe", "evil.dll", "C:\\Temp\\evil.dll");
        assert_eq!(detector.detection_count(), 1);
        detector.check_dll_load("app2.exe", "bad.dll", "C:\\Downloads\\bad.dll");
        assert_eq!(detector.detection_count(), 2);
    }

    #[test]
    fn test_detections_stored() {
        let mut detector = HijackDetector::new();
        detector.check_dll_load("app.exe", "evil.dll", "C:\\Temp\\evil.dll");
        assert_eq!(detector.detections().len(), 1);
    }

    #[test]
    fn test_side_loading_detection() {
        let mut detector = HijackDetector::new();
        let result = detector.check_dll_load(
            "slack.exe",
            "cryptsp.dll",
            "C:\\Program Files\\Slack\\cryptsp.dll",
        );
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.info.hijack_type, HijackType::SideLoading);
    }
}
