use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DslRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub conditions: Vec<DslCondition>,
    pub action: DslAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DslCondition {
    EventMatches { field: String, pattern: String },
    FieldEquals { field: String, value: String },
    FieldContains { field: String, value: String },
    FieldRegex { field: String, regex: String },
    FieldGreaterThan { field: String, threshold: f64 },
    FieldLessThan { field: String, threshold: f64 },
    TimeRange { seconds: u64 },
    Threshold { count: usize, window_secs: u64 },
    CompoundAll(Vec<DslCondition>),
    CompoundAny(Vec<DslCondition>),
    CompoundNot(Box<DslCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DslAction {
    Alert { severity: String, message: String },
    Block,
    Quarantine,
    TerminateProcess,
    Isolate,
    Custom(String),
}

impl DslRule {
    pub fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rule: DslRule = serde_json::from_str(input)?;
        Ok(rule)
    }

    pub fn evaluate_condition(
        condition: &DslCondition,
        event_data: &std::collections::HashMap<String, String>,
    ) -> bool {
        match condition {
            DslCondition::EventMatches { field, pattern } => {
                if let Some(value) = event_data.get(field) {
                    value.contains(pattern.as_str())
                } else {
                    false
                }
            }
            DslCondition::FieldEquals { field, value } => {
                event_data.get(field).map(|v| v == value).unwrap_or(false)
            }
            DslCondition::FieldContains { field, value } => {
                event_data.get(field).map(|v| v.contains(value.as_str())).unwrap_or(false)
            }
            DslCondition::FieldRegex { field, regex } => {
                if let Some(value) = event_data.get(field) {
                    regex::Regex::new(regex)
                        .map(|r| r.is_match(value))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            DslCondition::FieldGreaterThan { field, threshold } => {
                event_data
                    .get(field)
                    .and_then(|v| v.parse::<f64>().ok())
                    .map(|v| v > *threshold)
                    .unwrap_or(false)
            }
            DslCondition::FieldLessThan { field, threshold } => {
                event_data
                    .get(field)
                    .and_then(|v| v.parse::<f64>().ok())
                    .map(|v| v < *threshold)
                    .unwrap_or(false)
            }
            DslCondition::TimeRange { .. } => true,
            DslCondition::Threshold { .. } => true,
            DslCondition::CompoundAll(conditions) => {
                conditions.iter().all(|c| Self::evaluate_condition(c, event_data))
            }
            DslCondition::CompoundAny(conditions) => {
                conditions.iter().any(|c| Self::evaluate_condition(c, event_data))
            }
            DslCondition::CompoundNot(inner) => {
                !Self::evaluate_condition(inner, event_data)
            }
        }
    }
}
