pub mod detector;
pub mod rollback;

pub use royalsecurity_core as core;
pub use royalsecurity_common as common;
pub use detector::*;
pub use rollback::*;

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::*;

    #[test]
    fn test_detector_new() {
        let detector = RansomwareDetector::new();
        assert_eq!(detector.alert_count(), 0);
    }

    #[test]
    fn test_mass_modification_detection() {
        let config = RansomwareConfig {
            high_mod_rate_threshold: 5,
            monitoring_window_secs: 60,
            ..Default::default()
        };
        let mut detector = RansomwareDetector::with_config(config);

        for i in 0..10 {
            detector.analyze_file_event(&format!("C:\\Users\\test\\file{}.txt", i), FileAction::Modified);
        }

        assert!(detector.alert_count() > 0, "Should detect mass modification");
    }

    #[test]
    fn test_mass_rename_detection() {
        let config = RansomwareConfig {
            mass_rename_threshold: 3,
            monitoring_window_secs: 60,
            ..Default::default()
        };
        let mut detector = RansomwareDetector::with_config(config);

        for i in 0..5 {
            detector.analyze_file_event(&format!("C:\\Users\\doc{}.txt", i), FileAction::Renamed);
        }

        assert!(detector.alert_count() > 0, "Should detect mass rename");
    }

    #[test]
    fn test_ransomware_extension_detection() {
        let detector = RansomwareDetector::new();
        assert!(detector.check_ransomware_extension("file.locked"));
        assert!(detector.check_ransomware_extension("file.encrypted"));
        assert!(detector.check_ransomware_extension("file.ryuk"));
        assert!(!detector.check_ransomware_extension("file.txt"));
        assert!(!detector.check_ransomware_extension("file.pdf"));
    }

    #[test]
    fn test_rollback_engine() {
        let mut engine = RollbackEngine::new();
        let id = engine.create_snapshot("test").unwrap();
        assert!(!id.is_empty());
        assert_eq!(engine.snapshots().len(), 1);
    }

    #[test]
    fn test_rollback_nonexistent_snapshot() {
        let engine = RollbackEngine::new();
        let result = engine.rollback_file("test.txt", "nonexistent-id");
        assert!(result.is_err());
    }
}
