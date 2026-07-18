use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_percent: f64,
    pub uncovered_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_percent: f64,
    pub by_tactic: HashMap<String, TacticCoverage>,
    pub gaps: Vec<GapItem>,
    pub priority_gaps: Vec<GapItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapItem {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic_id: String,
    pub priority: String,
    pub threat_frequency: f64,
    pub detection_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorLayer {
    pub name: String,
    pub versions: NavigatorVersions,
    pub domain: String,
    pub description: String,
    pub filters: Vec<serde_json::Value>,
    pub layout: NavigatorLayout,
    pub gradient: GradientConfig,
    pub colorings: Vec<serde_json::Value>,
    pub legendItems: Vec<serde_json::Value>,
    pub showDisabled: bool,
    pub metadata: Vec<serde_json::Value>,
    pub techniques: Vec<NavigatorTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorVersions { pub attack: String, pub navigator: String, pub minor: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorLayout { #[serde(rename="layout")] pub layout: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientConfig { pub colors: Vec<String>, pub min_value: f64, pub max_value: f64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorTechnique {
    pub technique_id: String,
    pub tactic: String,
    pub color: String,
    pub score: f64,
    pub enabled: bool,
    pub comment: String,
}

pub struct CoverageAnalyzer {
    techniques: Vec<(String, String, String)>,
    covered: HashMap<String, Vec<String>>,
}

impl CoverageAnalyzer {
    pub fn new() -> Self {
        let techniques = vec![
            ("TA0001", "Initial Access", "T1189"),
            ("TA0001", "Initial Access", "T1190"),
            ("TA0001", "Initial Access", "T1133"),
            ("TA0001", "Initial Access", "T1200"),
            ("TA0001", "Initial Access", "T1566"),
            ("TA0001", "Initial Access", "T1195"),
            ("TA0001", "Initial Access", "T1199"),
            ("TA0001", "Initial Access", "T1078"),
            ("TA0002", "Execution", "T1059"),
            ("TA0002", "Execution", "T1059.001"),
            ("TA0002", "Execution", "T1047"),
            ("TA0002", "Execution", "T1203"),
            ("TA0002", "Execution", "T1204"),
            ("TA0002", "Execution", "T1053.005"),
            ("TA0002", "Execution", "T1072"),
            ("TA0003", "Persistence", "T1547.001"),
            ("TA0003", "Persistence", "T1136"),
            ("TA0003", "Persistence", "T1543.003"),
            ("TA0003", "Persistence", "T1546.003"),
            ("TA0003", "Persistence", "T1505.003"),
            ("TA0004", "Privilege Escalation", "T1548.002"),
            ("TA0004", "Privilege Escalation", "T1134"),
            ("TA0004", "Privilege Escalation", "T1055"),
            ("TA0005", "Defense Evasion", "T1562.001"),
            ("TA0005", "Defense Evasion", "T1140"),
            ("TA0005", "Defense Evasion", "T1070.001"),
            ("TA0005", "Defense Evasion", "T1027"),
            ("TA0005", "Defense Evasion", "T1218"),
            ("TA0005", "Defense Evasion", "T1562.001"),
            ("TA0006", "Credential Access", "T1003.001"),
            ("TA0006", "Credential Access", "T1110"),
            ("TA0006", "Credential Access", "T1558.003"),
            ("TA0006", "Credential Access", "T1555"),
            ("TA0007", "Discovery", "T1087"),
            ("TA0007", "Discovery", "T1082"),
            ("TA0007", "Discovery", "T1016"),
            ("TA0007", "Discovery", "T1033"),
            ("TA0007", "Discovery", "T1083"),
            ("TA0008", "Lateral Movement", "T1021.002"),
            ("TA0008", "Lateral Movement", "T1570"),
            ("TA0008", "Lateral Movement", "T1021.001"),
            ("TA0009", "Collection", "T1560.001"),
            ("TA0009", "Collection", "T1119"),
            ("TA0009", "Collection", "T1114"),
            ("TA0010", "Exfiltration", "T1041"),
            ("TA0010", "Exfiltration", "T1567.002"),
            ("TA0011", "Command and Control", "T1071.001"),
            ("TA0011", "Command and Control", "T1105"),
            ("TA0011", "Command and Control", "T1573.002"),
            ("TA0040", "Impact", "T1486"),
            ("TA0040", "Impact", "T1490"),
            ("TA0040", "Impact", "T1489"),
        ];
        Self { techniques: techniques.into_iter().map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string())).collect(), covered: HashMap::new() }
    }

    pub fn set_covered(&mut self, technique_id: &str, rule_ids: Vec<String>) {
        self.covered.insert(technique_id.to_string(), rule_ids);
    }

    pub fn calculate_coverage(&self) -> CoverageReport {
        let total = self.techniques.len();
        let covered_count = self.techniques.iter()
            .filter(|(_, _, tid)| self.covered.contains_key(tid))
            .count();
        let coverage_percent = if total > 0 { (covered_count as f64 / total as f64) * 100.0 } else { 0.0 };
        let mut by_tactic: HashMap<String, TacticCoverage> = HashMap::new();
        for (tactic_id, tactic_name, technique_id) in &self.techniques {
            let entry = by_tactic.entry(tactic_id.clone()).or_insert_with(|| TacticCoverage {
                tactic_id: tactic_id.clone(),
                tactic_name: tactic_name.clone(),
                total_techniques: 0,
                covered_techniques: 0,
                coverage_percent: 0.0,
                uncovered_techniques: Vec::new(),
            });
            entry.total_techniques += 1;
            if self.covered.contains_key(technique_id) {
                entry.covered_techniques += 1;
            } else {
                entry.uncovered_techniques.push(technique_id.clone());
            }
        }
        for entry in by_tactic.values_mut() {
            entry.coverage_percent = if entry.total_techniques > 0 {
                (entry.covered_techniques as f64 / entry.total_techniques as f64) * 100.0
            } else { 0.0 };
        }
        let gaps: Vec<GapItem> = self.techniques.iter()
            .filter(|(_, _, tid)| !self.covered.contains_key(tid))
            .map(|(tac_id, _, tid)| GapItem {
                technique_id: tid.clone(),
                technique_name: format!("Technique {}", tid),
                tactic_id: tac_id.clone(),
                priority: "High".to_string(),
                threat_frequency: 0.5,
                detection_confidence: 0.0,
            }).collect();
        let mut priority_gaps = gaps.clone();
        priority_gaps.sort_by(|a, b| b.threat_frequency.partial_cmp(&a.threat_frequency).unwrap_or(std::cmp::Ordering::Equal));
        CoverageReport { total_techniques: total, covered_techniques: covered_count, coverage_percent, by_tactic, gaps, priority_gaps }
    }

    pub fn generate_navigator_layer(&self, report: &CoverageReport) -> NavigatorLayer {
        let mut techniques = Vec::new();
        for (tac_id, tac_name, tid) in &self.techniques {
            let (color, score) = if self.covered.contains_key(tid) {
                ("#4CAF50".to_string(), 1.0)
            } else {
                ("#F44336".to_string(), 0.0)
            };
            techniques.push(NavigatorTechnique {
                technique_id: tid.clone(),
                tactic: tac_name.clone(),
                color,
                score,
                enabled: true,
                comment: if self.covered.contains_key(tid) { "Detected".to_string() } else { "Not covered".to_string() },
            });
        }
        NavigatorLayer {
            name: "RoyalSecurity Coverage".to_string(),
            versions: NavigatorVersions { attack: "15.1".to_string(), navigator: "4.8.2".to_string(), minor: "1".to_string() },
            domain: "enterprise-attack".to_string(),
            description: format!("RoyalSecurity detection coverage ({:.1}%)", report.coverage_percent),
            filters: vec![],
            layout: NavigatorLayout { layout: "side-by-side".to_string() },
            gradient: GradientConfig { colors: vec!["#F44336".to_string(), "#FF9800".to_string(), "#4CAF50".to_string()], min_value: 0.0, max_value: 1.0 },
            colorings: vec![],
            legendItems: vec![],
            showDisabled: false,
            metadata: vec![],
            techniques,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_analyzer_technique_count() {
        let a = CoverageAnalyzer::new();
        assert!(a.techniques.len() >= 40);
    }
    #[test]
    fn test_full_coverage() {
        let mut a = CoverageAnalyzer::new();
        for (_, _, tid) in &a.techniques.clone() {
            a.set_covered(tid, vec!["rule1".to_string()]);
        }
        let r = a.calculate_coverage();
        assert_eq!(r.covered_techniques, r.total_techniques);
        assert!((r.coverage_percent - 100.0).abs() < 0.1);
    }
    #[test]
    fn test_partial_coverage() {
        let a = CoverageAnalyzer::new();
        let r = a.calculate_coverage();
        assert!(r.coverage_percent < 50.0);
        assert!(!r.gaps.is_empty());
    }
    #[test]
    fn test_navigator_layer() {
        let a = CoverageAnalyzer::new();
        let r = a.calculate_coverage();
        let layer = a.generate_navigator_layer(&r);
        assert_eq!(layer.name, "RoyalSecurity Coverage");
        assert_eq!(layer.techniques.len(), a.techniques.len());
    }
    #[test]
    fn test_tactic_coverage() {
        let a = CoverageAnalyzer::new();
        let r = a.calculate_coverage();
        assert!(r.by_tactic.contains_key("TA0001"));
        assert!(r.by_tactic.contains_key("TA0002"));
    }
}
