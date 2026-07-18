pub mod sigma;
pub mod dsl;
pub mod engine;
pub mod yara_engine;
pub mod sigma_engine;

pub use royalsecurity_core as core;
pub use royalsecurity_common as common;
pub use sigma::*;
pub use dsl::*;
pub use engine::*;
pub use yara_engine::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::SigmaRule;
    use crate::engine::RuleEngine;
    use royalsecurity_common::types::*;
    use std::collections::HashMap;

    #[test]
    fn test_sigma_rule_parse() {
        let yaml = r#"
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: A test rule
detection:
    condition: selection
    EventID: 1
    Image|endswith: '\cmd.exe'
level: high
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.level, Some("high".into()));
        assert_eq!(rule.detection.condition, "selection");
    }

    #[test]
    fn test_sigma_rule_compile() {
        let yaml = r#"
title: Suspicious Process
id: test-001
detection:
    condition: selection
    CommandLine|contains: 'mimikatz'
level: critical
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let compiled = rule.compile().unwrap();
        assert_eq!(compiled.title, "Suspicious Process");
        assert_eq!(compiled.level, "critical");
        assert!(!compiled.patterns.is_empty());
    }

    #[test]
    fn test_sigma_field_modifiers() {
        let yaml = r#"
title: Modifier Test
detection:
    condition: selection
    Image|endswith: '\powershell.exe'
    CommandLine|contains|lowercase: 'bypass'
level: medium
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let compiled = rule.compile().unwrap();
        assert!(compiled.patterns.iter().any(|p| p.field == "Image"));
        assert!(compiled.patterns.iter().any(|p| p.field == "CommandLine"));
    }

    #[test]
    fn test_rule_engine_evaluate() {
        let mut engine = RuleEngine::new();
        
        let yaml = r#"
title: Detect PowerShell
id: test-ps-001
detection:
    condition: selection
    source: 'etw'
    event_type: 'ProcessCreated'
level: medium
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let compiled = rule.compile().unwrap();
        engine.add_sigma_rule(compiled);
        
        let envelope = SecurityEventEnvelope {
            severity: EventSeverity::Medium,
            event_type: EventType::ProcessCreated,
            source: "etw".into(),
            raw: None,
            details: HashMap::new(),
            ..Default::default()
        };
        
        let matches = engine.evaluate_event(&envelope);
        assert!(!matches.is_empty(), "Should match PowerShell rule");
        assert_eq!(matches[0].rule_title, "Detect PowerShell");
    }

    #[test]
    fn test_rule_engine_no_match() {
        let mut engine = RuleEngine::new();
        
        let yaml = r#"
title: Detect Network
id: test-net-001
detection:
    condition: selection
    source: 'wfp'
level: low
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let compiled = rule.compile().unwrap();
        engine.add_sigma_rule(compiled);
        
        let envelope = SecurityEventEnvelope {
            source: "etw".into(),
            ..Default::default()
        };
        
        let matches = engine.evaluate_event(&envelope);
        assert!(matches.is_empty(), "Should not match with wrong source");
    }

    #[test]
    fn test_dsl_rule_parse() {
        let json = r#"{
            "name": "test-dsl",
            "description": "Test DSL rule",
            "severity": "high",
            "conditions": [],
            "action": {"Alert": {"severity": "high", "message": "test"}}
        }"#;
        let rule = dsl::DslRule::parse(json).unwrap();
        assert_eq!(rule.name, "test-dsl");
        assert_eq!(rule.severity, "high");
    }

    #[test]
    fn test_pattern_operators() {
        let yaml = r#"
title: Operator Test
detection:
    condition: selection
    Path|startswith: 'C:\Users'
    Name|endswith: '.exe'
    Size|gte: 1000
level: low
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let compiled = rule.compile().unwrap();
        
        let path_pattern = compiled.patterns.iter().find(|p| p.field == "Path").unwrap();
        assert_eq!(path_pattern.operator, sigma::PatternOperator::StartsWith);
        
        let name_pattern = compiled.patterns.iter().find(|p| p.field == "Name").unwrap();
        assert_eq!(name_pattern.operator, sigma::PatternOperator::EndsWith);
        
        let size_pattern = compiled.patterns.iter().find(|p| p.field == "Size").unwrap();
        assert_eq!(size_pattern.operator, sigma::PatternOperator::Gte);
    }
}
