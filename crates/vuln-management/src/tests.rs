use super::*;
use crate::scanner::ScanType;

fn localhost_target() -> ScanTarget {
    ScanTarget {
        hostname: "localhost".into(),
        ip_address: Some("127.0.0.1".into()),
        scan_type: ScanType::Full,
    }
}

#[test]
fn test_scan_session_new() {
    let session = ScanSession::new(localhost_target());
    assert_eq!(session.status, ScanStatus::Pending);
    assert!(session.results.is_empty());
}

#[test]
fn test_scan_session_complete() {
    let mut session = ScanSession::new(localhost_target());
    session.complete();
    assert_eq!(session.status, ScanStatus::Completed);
    assert!(session.completed_at.is_some());
}

#[test]
fn test_cve_database_count() {
    let db = CveDatabase::new();
    assert!(db.count() >= 20);
}

#[test]
fn test_cvss_calculation() {
    let v = cvss::CvssVector { attack_vector:"N".into(), attack_complexity:"L".into(), privileges_required:"N".into(), user_interaction:"N".into(), scope:"C".into(), confidentiality:"H".into(), integrity:"H".into(), availability:"H".into() };
    let s = CvssScore::calculate_v3(&v);
    assert!(s.base_score >= 9.0);
}

#[test]
fn test_severity_rating() {
    let db = CveDatabase::new();
    let cve = db.lookup_cve("CVE-2020-1472").unwrap();
    assert_eq!(cve.severity, "Critical");
    assert!(cve.cvss_score >= 9.0);
}

#[test]
fn test_patch_assessment() {
    let pa = patch::PatchAssessment::new();
    assert!(pa.count_installed() >= 5);
    assert!(!pa.get_missing_patches().is_empty());
}

#[test]
fn test_vuln_report_new() {
    let r = report::VulnReport::new("testhost");
    assert_eq!(r.total_vulns, 0);
    assert_eq!(r.hostname, "testhost");
}

#[test]
fn test_vuln_report_export() {
    let r = report::VulnReport::new("test");
    assert!(r.export_json().contains("scan_id"));
    assert!(r.export_csv().contains("CVE_ID"));
    assert!(r.export_html().contains("<html>"));
}

#[test]
fn test_cve_search() {
    let db = CveDatabase::new();
    let results = db.search_cves("eternalblue");
    assert!(!results.is_empty());
}

#[test]
fn test_cve_lookup() {
    let db = CveDatabase::new();
    assert!(db.lookup_cve("CVE-2017-0144").is_some());
    assert!(db.lookup_cve("CVE-9999-9999").is_none());
}
