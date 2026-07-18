use super::techniques::*;
use super::detections::*;
use super::coverage::*;

#[test]
fn test_technique_database_not_empty() {
    let db = TechniqueDatabase::new();
    assert!(db.techniques.len() >= 80, "Expected >= 80 techniques, got {}", db.techniques.len());
}

#[test]
fn test_get_technique_by_id() {
    let db = TechniqueDatabase::new();
    let t = db.get_technique("T1059");
    assert!(t.is_some());
    assert_eq!(t.unwrap().name, "Command and Scripting Interpreter");
}

#[test]
fn test_get_techniques_by_tactic() {
    let db = TechniqueDatabase::new();
    let tactics = db.get_techniques_by_tactic("TA0002");
    assert!(!tactics.is_empty());
}

#[test]
fn test_search_techniques() {
    let db = TechniqueDatabase::new();
    let results = db.search_techniques("phishing");
    assert!(!results.is_empty());
}

#[test]
fn test_all_tactics_represented() {
    let db = TechniqueDatabase::new();
    let tactics: std::collections::HashSet<String> = db.techniques.iter()
        .flat_map(|t| t.tactics.iter().cloned())
        .collect();
    assert!(tactics.len() >= 10, "Expected >= 10 tactics, got {}", tactics.len());
}

#[test]
fn test_detection_mapper_loads() {
    let mapper = DetectionMapper::new();
    assert!(mapper.get_all_mappings().len() >= 40);
}

#[test]
fn test_coverage_analyzer() {
    let a = CoverageAnalyzer::new();
    let r = a.calculate_coverage();
    assert!(r.total_techniques >= 40);
}

#[test]
fn test_navigator_layer_export() {
    let a = CoverageAnalyzer::new();
    let r = a.calculate_coverage();
    let layer = a.generate_navigator_layer(&r);
    let json = serde_json::to_string_pretty(&layer).unwrap();
    assert!(json.contains("RoyalSecurity"));
}
