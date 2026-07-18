use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMapping {
    pub rule_id: String,
    pub rule_type: String,
    pub technique_ids: Vec<String>,
    pub confidence: f64,
    pub tactic_ids: Vec<String>,
}

pub struct DetectionMapper {
    mappings: Vec<DetectionMapping>,
}

impl DetectionMapper {
    pub fn new() -> Self {
        let mut mapper = Self { mappings: Vec::new() };
        mapper.load_builtin_mappings();
        mapper
    }

    fn load_builtin_mappings(&mut self) {
        let yara_mappings: Vec<(&str, &str, Vec<&str>, Vec<&str>, f64)> = vec![
            ("yara-001", "Emotet", vec!["T1059.001", "T1053.005"], vec!["TA0002", "TA0003"], 0.85),
            ("yara-002", "TrickBot", vec!["T1059.001", "T1071.001"], vec!["TA0002", "TA0011"], 0.85),
            ("yara-003", "Ryuk", vec!["T1486", "T1490"], vec!["TA0040"], 0.90),
            ("yara-004", "Conti", vec!["T1486", "T1560.001"], vec!["TA0040", "TA0009"], 0.90),
            ("yara-005", "LockBit", vec!["T1486", "T1070.001"], vec!["TA0040", "TA0005"], 0.90),
            ("yara-006", "CobaltStrike", vec!["T1059.001", "T1071.001", "T1573.002"], vec!["TA0002", "TA0011", "TA0001"], 0.95),
            ("yara-007", "Mimikatz", vec!["T1003.001", "T1558.003"], vec!["TA0006"], 0.95),
            ("yara-008", "QakBot", vec!["T1059.001", "T1053.005"], vec!["TA0002", "TA0003"], 0.85),
            ("yara-009", "IcedID", vec!["T1059.001", "T1071.001"], vec!["TA0002", "TA0011"], 0.85),
            ("yara-010", "Dridex", vec!["T1059.001", "T1185"], vec!["TA0002", "TA0001"], 0.85),
            ("yara-011", "Formbook", vec!["T1056.001", "T1055"], vec!["TA0006", "TA0005"], 0.85),
            ("yara-012", "DLLInjection", vec!["T1055.001"], vec!["TA0005"], 0.80),
            ("yara-013", "ProcessHollowing", vec!["T1055.012"], vec!["TA0005"], 0.85),
            ("yara-014", "APCInjection", vec!["T1055.004"], vec!["TA0005"], 0.80),
            ("yara-015", "CredentialDump", vec!["T1003.001"], vec!["TA0006"], 0.90),
            ("yara-016", "LSASSAccess", vec!["T1003.001"], vec!["TA0006"], 0.90),
            ("yara-017", "RegistryPersistence", vec!["T1547.001"], vec!["TA0003"], 0.80),
            ("yara-018", "ScheduledTask", vec!["T1053.005"], vec!["TA0003", "TA0002"], 0.75),
            ("yara-019", "ServiceInstall", vec!["T1543.003"], vec!["TA0003"], 0.75),
            ("yara-020", "WMIExecution", vec!["T1047"], vec!["TA0002"], 0.80),
            ("yara-021", "PowerShellEmpire", vec!["T1059.001", "T1105"], vec!["TA0002", "TA0011"], 0.90),
            ("yara-022", "Metasploit", vec!["T1059.001", "T1055"], vec!["TA0002", "TA0005"], 0.90),
            ("yara-023", "Shellcode", vec!["T1055"], vec!["TA0005"], 0.80),
            ("yara-024", "RansomwareNote", vec!["T1486"], vec!["TA0040"], 0.95),
            ("yara-025", "DataExfil", vec!["T1041", "T1567.002"], vec!["TA0010"], 0.80),
            ("yara-026", "C2Beacon", vec!["T1071.001", "T1573"], vec!["TA0011"], 0.85),
            ("yara-027", "DNSOverHTTPS", vec!["T1071.004", "T1573.002"], vec!["TA0011"], 0.80),
            ("yara-028", "Keylogger", vec!["T1056.001"], vec!["TA0009"], 0.90),
            ("yara-029", "RAT", vec!["T1219", "T1071.001"], vec!["TA0011"], 0.85),
            ("yara-030", "BankingTrojan", vec!["T1056.001", "T1185"], vec!["TA0006", "TA0001"], 0.85),
        ];
        for (id, name, techniques, tactics, conf) in yara_mappings {
            self.mappings.push(DetectionMapping {
                rule_id: id.to_string(),
                rule_type: "yara".to_string(),
                technique_ids: techniques.iter().map(|s| s.to_string()).collect(),
                confidence: conf,
                tactic_ids: tactics.iter().map(|s| s.to_string()).collect(),
            });
        }
        let sigma_mappings: Vec<(&str, Vec<&str>, Vec<&str>, f64)> = vec![
            ("sigma-001", vec!["T1059.001"], vec!["TA0002"], 0.85),
            ("sigma-002", vec!["T1021.002", "T1570"], vec!["TA0008"], 0.80),
            ("sigma-003", vec!["T1047"], vec!["TA0002"], 0.80),
            ("sigma-004", vec!["T1003.001"], vec!["TA0006"], 0.95),
            ("sigma-005", vec!["T1003.001"], vec!["TA0006"], 0.90),
            ("sigma-006", vec!["T1543.003"], vec!["TA0003"], 0.80),
            ("sigma-007", vec!["T1053.005"], vec!["TA0003"], 0.80),
            ("sigma-008", vec!["T1547.001"], vec!["TA0003"], 0.80),
            ("sigma-009", vec!["T1546.003"], vec!["TA0003"], 0.85),
            ("sigma-010", vec!["T1548.002"], vec!["TA0004", "TA0005"], 0.85),
            ("sigma-011", vec!["T1055"], vec!["TA0005"], 0.85),
            ("sigma-012", vec!["T1033"], vec!["TA0007"], 0.70),
            ("sigma-013", vec!["T1069.002"], vec!["TA0007"], 0.70),
            ("sigma-014", vec!["T1560.001"], vec!["TA0009"], 0.80),
            ("sigma-015", vec!["T1071.004"], vec!["TA0011"], 0.75),
            ("sigma-016", vec!["T1021.001"], vec!["TA0008"], 0.80),
            ("sigma-017", vec!["T1105"], vec!["TA0011"], 0.80),
            ("sigma-018", vec!["T1562.001"], vec!["TA0005"], 0.90),
            ("sigma-019", vec!["T1070.001"], vec!["TA0005"], 0.80),
            ("sigma-020", vec!["T1112"], vec!["TA0005"], 0.75),
        ];
        for (id, techniques, tactics, conf) in sigma_mappings {
            self.mappings.push(DetectionMapping {
                rule_id: id.to_string(),
                rule_type: "sigma".to_string(),
                technique_ids: techniques.iter().map(|s| s.to_string()).collect(),
                confidence: conf,
                tactic_ids: tactics.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    pub fn map_event_to_techniques(&self, event_type: &str) -> Vec<&DetectionMapping> {
        self.mappings.iter().filter(|m| {
            event_type.to_lowercase().contains(&m.rule_type)
                || event_type.to_lowercase().contains(&m.rule_id)
        }).collect()
    }

    pub fn get_mappings_for_technique(&self, technique_id: &str) -> Vec<&DetectionMapping> {
        self.mappings.iter().filter(|m| m.technique_ids.iter().any(|t| t == technique_id)).collect()
    }

    pub fn get_all_mappings(&self) -> &[DetectionMapping] { &self.mappings }

    pub fn count_by_type(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for m in &self.mappings {
            *counts.entry(m.rule_type.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn get_uncovered_techniques(&self, all_techniques: &[String]) -> Vec<String> {
        let covered: std::collections::HashSet<String> = self.mappings.iter()
            .flat_map(|m| m.technique_ids.iter().cloned())
            .collect();
        all_techniques.iter().filter(|t| !covered.contains(*t)).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mapper_builtin_count() {
        let mapper = DetectionMapper::new();
        assert!(mapper.mappings.len() >= 40);
    }
    #[test]
    fn test_count_by_type() {
        let mapper = DetectionMapper::new();
        let counts = mapper.count_by_type();
        assert!(counts.get("yara").unwrap_or(&0) >= &25);
        assert!(counts.get("sigma").unwrap_or(&0) >= &15);
    }
    #[test]
    fn test_get_mappings_for_technique() {
        let mapper = DetectionMapper::new();
        let maps = mapper.get_mappings_for_technique("T1486");
        assert!(!maps.is_empty());
    }
    #[test]
    fn test_uncovered_techniques() {
        let mapper = DetectionMapper::new();
        let all = vec!["T9999".to_string(), "T1486".to_string()];
        let uncovered = mapper.get_uncovered_techniques(&all);
        assert!(uncovered.contains(&"T9999".to_string()));
        assert!(!uncovered.contains(&"T1486".to_string()));
    }
}
