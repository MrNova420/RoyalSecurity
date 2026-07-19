use crate::sigma::{CompiledSigmaRule, PatternOperator};
use crate::dsl::DslRule;
use royalsecurity_common::types::SecurityEventEnvelope;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::info;

pub struct RuleEngine {
    sigma_rules: Vec<CompiledSigmaRule>,
    dsl_rules: Vec<DslRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub matched_fields: Vec<String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            sigma_rules: Vec::new(),
            dsl_rules: Vec::new(),
        }
    }

    pub fn add_sigma_rule(&mut self, rule: CompiledSigmaRule) {
        info!(rule_id = %rule.id, title = %rule.title, "Added Sigma rule");
        self.sigma_rules.push(rule);
    }

    pub fn remove_sigma_rule(&mut self, rule_id: &str) -> bool {
        let before = self.sigma_rules.len();
        self.sigma_rules.retain(|r| r.id != rule_id);
        let removed = self.sigma_rules.len() < before;
        if removed {
            info!(rule_id = %rule_id, "Removed Sigma rule");
        }
        removed
    }

    pub fn add_dsl_rule(&mut self, rule: DslRule) {
        info!(name = %rule.name, "Added DSL rule");
        self.dsl_rules.push(rule);
    }

    pub fn evaluate_event(&self, event: &SecurityEventEnvelope) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let event_map = self.event_to_map(event);

        for rule in &self.sigma_rules {
            if let Some(m) = self.evaluate_sigma_rule(rule, &event_map) {
                matches.push(m);
            }
        }

        for rule in &self.dsl_rules {
            if let Some(m) = self.evaluate_dsl_rule(rule, &event_map) {
                matches.push(m);
            }
        }

        matches
    }

    fn event_to_map(&self, event: &SecurityEventEnvelope) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("event_id".into(), event.id.to_string());
        map.insert("severity".into(), format!("{:?}", event.severity));
        map.insert("event_type".into(), format!("{:?}", event.event_type));
        map.insert("source".into(), event.source.clone());
        map.insert("timestamp".into(), event.timestamp.to_rfc3339());
        if let Some(raw) = &event.raw {
            map.insert("raw".into(), raw.clone());
        }
        for (k, v) in &event.details {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            } else {
                map.insert(k.clone(), v.to_string());
            }
        }
        map
    }

    fn evaluate_sigma_rule(
        &self,
        rule: &CompiledSigmaRule,
        event_data: &HashMap<String, String>,
    ) -> Option<RuleMatch> {
        let mut matched_fields = Vec::new();

        for pattern in &rule.patterns {
            let value = match event_data.get(&pattern.field) {
                Some(v) => v,
                None => {
                    if pattern.operator == PatternOperator::Exists {
                        let final_match = if pattern.negated { false } else { false };
                        if !final_match {
                            return None;
                        }
                    }
                    continue;
                }
            };

            let matched = match pattern.operator {
                PatternOperator::Contains => value.contains(&pattern.value),
                PatternOperator::StartsWith => value.starts_with(&pattern.value),
                PatternOperator::EndsWith => value.ends_with(&pattern.value),
                PatternOperator::Equals => value == &pattern.value,
                PatternOperator::Regex => {
                    regex::Regex::new(&pattern.value)
                        .map(|r| r.is_match(value))
                        .unwrap_or(false)
                }
                PatternOperator::Gt => {
                    value
                        .parse::<f64>()
                        .ok()
                        .zip(pattern.value.parse::<f64>().ok())
                        .map(|(v, t)| v > t)
                        .unwrap_or(false)
                }
                PatternOperator::Lt => {
                    value
                        .parse::<f64>()
                        .ok()
                        .zip(pattern.value.parse::<f64>().ok())
                        .map(|(v, t)| v < t)
                        .unwrap_or(false)
                }
                PatternOperator::Gte => {
                    value
                        .parse::<f64>()
                        .ok()
                        .zip(pattern.value.parse::<f64>().ok())
                        .map(|(v, t)| v >= t)
                        .unwrap_or(false)
                }
                PatternOperator::Lte => {
                    value
                        .parse::<f64>()
                        .ok()
                        .zip(pattern.value.parse::<f64>().ok())
                        .map(|(v, t)| v <= t)
                        .unwrap_or(false)
                }
                PatternOperator::Exists => true,
            };

            let final_match = if pattern.negated { !matched } else { matched };
            if final_match {
                matched_fields.push(pattern.field.clone());
            } else {
                return None;
            }
        }

        if !matched_fields.is_empty() {
            Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                severity: rule.level.clone(),
                matched_fields,
            })
        } else {
            None
        }
    }

    fn evaluate_dsl_rule(
        &self,
        rule: &DslRule,
        event_data: &HashMap<String, String>,
    ) -> Option<RuleMatch> {
        let all_match = rule
            .conditions
            .iter()
            .all(|c| DslRule::evaluate_condition(c, event_data));

        if all_match {
            Some(RuleMatch {
                rule_id: rule.name.clone(),
                rule_title: rule.description.clone(),
                severity: rule.severity.clone(),
                matched_fields: event_data.keys().cloned().collect(),
            })
        } else {
            None
        }
    }

    pub fn rule_count(&self) -> usize {
        self.sigma_rules.len() + self.dsl_rules.len()
    }

    pub fn sigma_rule_count(&self) -> usize {
        self.sigma_rules.len()
    }

    pub fn dsl_rule_count(&self) -> usize {
        self.dsl_rules.len()
    }
}
